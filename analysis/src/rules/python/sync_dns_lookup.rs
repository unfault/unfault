//! Rule B18: Sync DNS lookups detection
//!
//! Detects synchronous DNS lookups that can block the event loop in async code.
//! DNS resolution can take significant time (network latency, DNS server delays)
//! and should be done asynchronously in async contexts.
//!
//! ## What it detects
//!
//! - `socket.gethostbyname()` - Synchronous hostname resolution
//! - `socket.gethostbyname_ex()` - Extended synchronous hostname resolution
//! - `socket.gethostbyaddr()` - Synchronous reverse DNS lookup
//! - `socket.getaddrinfo()` - Synchronous address info lookup
//! - `socket.getnameinfo()` - Synchronous name info lookup
//! - `socket.getfqdn()` - Synchronous fully qualified domain name lookup
//!
//! ## Why it matters
//!
//! - DNS lookups can take 50-500ms or more
//! - Blocks the entire event loop during resolution
//! - Can cause cascading timeouts in async applications
//! - Network issues can cause DNS to hang for seconds
//!
//! ## Recommended fixes
//!
//! - Use `asyncio.get_event_loop().getaddrinfo()` for async DNS
//! - Use `aiodns` library for async DNS resolution
//! - Use `socket.getaddrinfo()` in a thread pool via `run_in_executor()`

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::timeout;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::{ImportInsertionType, PyCallSite, PyFileSemantics, PyImport};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule for detecting synchronous DNS lookups
#[derive(Debug)]
pub struct PythonSyncDnsLookupRule;

impl PythonSyncDnsLookupRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonSyncDnsLookupRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Synchronous DNS lookup patterns
#[derive(Debug, Clone)]
struct SyncDnsLookup {
    /// Function name being called
    function_name: String,
    /// The type of DNS lookup
    lookup_type: DnsLookupType,
    /// Line number (1-based)
    line: u32,
    /// Column number (1-based)
    column: u32,
    /// Whether this is in an async context
    in_async_context: bool,
    /// Start byte offset for the call
    start_byte: usize,
    /// End byte offset for the call
    end_byte: usize,
    /// The original call arguments
    args_repr: String,
}

/// DNS lookup function types
#[derive(Debug, Clone, Copy)]
enum DnsLookupType {
    /// socket.gethostbyname()
    GetHostByName,
    /// socket.gethostbyname_ex()
    GetHostByNameEx,
    /// socket.gethostbyaddr()
    GetHostByAddr,
    /// socket.getaddrinfo()
    GetAddrInfo,
    /// socket.getnameinfo()
    GetNameInfo,
    /// socket.getfqdn()
    GetFqdn,
}

impl DnsLookupType {
    fn description(&self) -> &'static str {
        match self {
            DnsLookupType::GetHostByName => "gethostbyname() performs synchronous DNS lookup",
            DnsLookupType::GetHostByNameEx => "gethostbyname_ex() performs synchronous DNS lookup",
            DnsLookupType::GetHostByAddr => "gethostbyaddr() performs synchronous reverse DNS",
            DnsLookupType::GetAddrInfo => "getaddrinfo() performs synchronous address resolution",
            DnsLookupType::GetNameInfo => "getnameinfo() performs synchronous name resolution",
            DnsLookupType::GetFqdn => "getfqdn() performs synchronous FQDN lookup",
        }
    }

    fn async_alternative(&self) -> &'static str {
        match self {
            DnsLookupType::GetHostByName
            | DnsLookupType::GetHostByNameEx
            | DnsLookupType::GetAddrInfo => {
                "Use `await loop.getaddrinfo()` or `aiodns` for async DNS resolution"
            }
            DnsLookupType::GetHostByAddr | DnsLookupType::GetNameInfo => {
                "Use `await loop.getnameinfo()` or `aiodns` for async reverse DNS"
            }
            DnsLookupType::GetFqdn => {
                "Use `await loop.getaddrinfo()` with AI_CANONNAME flag for async FQDN lookup"
            }
        }
    }
}

#[async_trait]
impl Rule for PythonSyncDnsLookupRule {
    fn id(&self) -> &'static str {
        "python.sync_dns_lookup"
    }

    fn name(&self) -> &'static str {
        "Synchronous DNS lookup blocks event loop"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(timeout())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                #[allow(unreachable_patterns)]
                _ => continue,
            };

            // Check if socket module is imported
            let has_socket_import = py.imports.iter().any(|imp| {
                imp.module == "socket"
                    || imp.module.starts_with("socket.")
                    || imp.names.iter().any(|n| is_dns_function(n))
            });

            if !has_socket_import {
                continue;
            }

            // Use stdlib_import since we're adding "import asyncio"
            let import_line = py.import_insertion_line_for(ImportInsertionType::stdlib_import());

            // Check all calls for DNS lookups
            for call in &py.calls {
                if let Some(lookup) = detect_dns_lookup(call, py) {
                    findings.push(create_finding(
                        self.id(),
                        &lookup,
                        *file_id,
                        &py.path,
                        &py.imports,
                        import_line,
                    ));
                }
            }
        }

        findings
    }
}

/// Check if a function name is a DNS lookup function
fn is_dns_function(name: &str) -> bool {
    matches!(
        name,
        "gethostbyname"
            | "gethostbyname_ex"
            | "gethostbyaddr"
            | "getaddrinfo"
            | "getnameinfo"
            | "getfqdn"
    )
}

/// Detect if a call is a synchronous DNS lookup
fn detect_dns_lookup(call: &PyCallSite, py: &PyFileSemantics) -> Option<SyncDnsLookup> {
    let callee = &call.function_call.callee_expr;

    // Check for socket.function() or direct function() calls
    let dns_function = if callee.starts_with("socket.") {
        callee.strip_prefix("socket.")
    } else if is_dns_function(callee) && has_direct_import(py, callee) {
        Some(callee.as_str())
    } else {
        None
    }?;

    let lookup_type = match dns_function {
        "gethostbyname" => DnsLookupType::GetHostByName,
        "gethostbyname_ex" => DnsLookupType::GetHostByNameEx,
        "gethostbyaddr" => DnsLookupType::GetHostByAddr,
        "getaddrinfo" => DnsLookupType::GetAddrInfo,
        "getnameinfo" => DnsLookupType::GetNameInfo,
        "getfqdn" => DnsLookupType::GetFqdn,
        _ => return None,
    };

    // Check if we're in an async context
    let in_async_context = py.functions.iter().any(|f| {
        f.is_async
            && call.function_call.location.line >= f.location.range.start_line
            && call.function_call.location.line <= f.location.range.end_line
    });

    Some(SyncDnsLookup {
        function_name: dns_function.to_string(),
        lookup_type,
        line: call.function_call.location.line,
        column: call.function_call.location.column,
        in_async_context,
        start_byte: call.start_byte,
        end_byte: call.end_byte,
        args_repr: call.args_repr.clone(),
    })
}

/// Check if a function is directly imported
fn has_direct_import(py: &PyFileSemantics, func_name: &str) -> bool {
    py.imports
        .iter()
        .any(|imp| imp.module == "socket" && imp.names.iter().any(|n| n == func_name || n == "*"))
}

fn create_finding(
    rule_id: &str,
    lookup: &SyncDnsLookup,
    file_id: FileId,
    file_path: &str,
    imports: &[PyImport],
    import_insertion_line: u32,
) -> RuleFinding {
    let title = if lookup.in_async_context {
        format!(
            "{} in async context blocks event loop",
            lookup.lookup_type.description()
        )
    } else {
        format!(
            "{} - consider async alternatives",
            lookup.lookup_type.description()
        )
    };

    let description = if lookup.in_async_context {
        format!(
            "The synchronous DNS lookup '{}' is called inside an async function. \
             This will block the entire event loop during DNS resolution, which can \
             take 50-500ms or more. {}",
            lookup.function_name,
            lookup.lookup_type.async_alternative()
        )
    } else {
        format!(
            "The synchronous DNS lookup '{}' may block if called from async context. \
             Consider using async alternatives if this code may be called from async functions. {}",
            lookup.function_name,
            lookup.lookup_type.async_alternative()
        )
    };

    let patch = generate_async_dns_patch(lookup, file_id, imports, import_insertion_line);

    let fix_preview = format!(
        r#"# Before (blocking DNS):
ip = socket.{func}(hostname)

# After (async DNS):
import asyncio
loop = asyncio.get_event_loop()
result = await loop.getaddrinfo(hostname, None)

# Or use aiodns for more features:
import aiodns
resolver = aiodns.DNSResolver()
result = await resolver.query(hostname, 'A')"#,
        func = lookup.function_name
    );

    let severity = if lookup.in_async_context {
        Severity::High
    } else {
        Severity::Medium
    };

    let confidence = if lookup.in_async_context { 0.90 } else { 0.85 };

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::PerformanceSmell,
        severity,
        confidence,
        dimension: Dimension::Performance,
        file_id,
        file_path: file_path.to_string(),
        line: Some(lookup.line),
        column: Some(lookup.column),
        end_line: None,
        end_column: None,
        byte_range: None,
        patch: Some(patch),
        fix_preview: Some(fix_preview),
        tags: vec![
            "python".into(),
            "performance".into(),
            "dns".into(),
            "blocking".into(),
            "async".into(),
        ],
    }
}

/// Check if asyncio is already imported
fn has_asyncio_import(imports: &[PyImport]) -> bool {
    imports
        .iter()
        .any(|imp| imp.module == "asyncio" || imp.names.iter().any(|n| n == "asyncio"))
}

fn generate_async_dns_patch(
    lookup: &SyncDnsLookup,
    file_id: FileId,
    imports: &[PyImport],
    import_insertion_line: u32,
) -> FilePatch {
    let mut hunks = Vec::new();

    // If in async context and we have byte offsets, use ReplaceBytes for direct code fix
    if lookup.in_async_context && lookup.start_byte > 0 && lookup.end_byte > lookup.start_byte {
        // Only add asyncio import if not already present
        if !has_asyncio_import(imports) {
            hunks.push(PatchHunk {
                range: PatchRange::InsertBeforeLine {
                    line: import_insertion_line,
                },
                replacement: "import asyncio\n".to_string(),
            });
        }

        // Generate async replacement using asyncio.get_event_loop()
        let args_trimmed = lookup.args_repr.trim_matches(|c| c == '(' || c == ')');

        let replacement = match lookup.lookup_type {
            DnsLookupType::GetHostByName => {
                // socket.gethostbyname(hostname) -> (await asyncio.get_event_loop().getaddrinfo(hostname, None))[0][4][0]
                format!(
                    "(await asyncio.get_event_loop().getaddrinfo({}, None))[0][4][0]",
                    args_trimmed
                )
            }
            DnsLookupType::GetHostByNameEx => {
                // Keep original args structure for extended info
                format!(
                    "await asyncio.get_event_loop().getaddrinfo({})",
                    args_trimmed
                )
            }
            DnsLookupType::GetAddrInfo => {
                // socket.getaddrinfo(host, port, ...) -> await asyncio.get_event_loop().getaddrinfo(host, port, ...)
                format!(
                    "await asyncio.get_event_loop().getaddrinfo({})",
                    args_trimmed
                )
            }
            DnsLookupType::GetHostByAddr | DnsLookupType::GetNameInfo => {
                // socket.getnameinfo/gethostbyaddr -> await loop.getnameinfo(...)
                format!(
                    "await asyncio.get_event_loop().getnameinfo({})",
                    args_trimmed
                )
            }
            DnsLookupType::GetFqdn => {
                // socket.getfqdn() -> more complex, use run_in_executor
                format!(
                    "await asyncio.get_event_loop().run_in_executor(None, socket.getfqdn{})",
                    if args_trimmed.is_empty() { "" } else { ", " }
                )
            }
        };

        hunks.push(PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: lookup.start_byte,
                end: lookup.end_byte,
            },
            replacement,
        });
    } else {
        // Fallback: not in async context or no byte offsets - use comment-based patch
        if !has_asyncio_import(imports) {
            hunks.push(PatchHunk {
                range: PatchRange::InsertBeforeLine {
                    line: import_insertion_line,
                },
                replacement: "import asyncio\n".to_string(),
            });
        }

        // Generate the async replacement suggestion as a comment
        let replacement = match lookup.lookup_type {
            DnsLookupType::GetHostByName
            | DnsLookupType::GetHostByNameEx
            | DnsLookupType::GetAddrInfo => {
                format!(
                    "# Fix: Replace socket.{} with async DNS:\n\
                     # loop = asyncio.get_event_loop()\n\
                     # result = await loop.getaddrinfo(hostname, port)\n",
                    lookup.function_name
                )
            }
            DnsLookupType::GetHostByAddr | DnsLookupType::GetNameInfo => {
                format!(
                    "# Fix: Replace socket.{} with async reverse DNS:\n\
                     # loop = asyncio.get_event_loop()\n\
                     # result = await loop.getnameinfo(sockaddr, flags)\n",
                    lookup.function_name
                )
            }
            DnsLookupType::GetFqdn => {
                format!(
                    "# Fix: Replace socket.{} with async FQDN lookup:\n\
                     # loop = asyncio.get_event_loop()\n\
                     # result = await loop.getaddrinfo(hostname, None, flags=socket.AI_CANONNAME)\n",
                    lookup.function_name
                )
            }
        };

        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: lookup.line },
            replacement,
        });
    }

    FilePatch { file_id, hunks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::python::build_python_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_python_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonSyncDnsLookupRule::new();
        assert_eq!(rule.id(), "python.sync_dns_lookup");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonSyncDnsLookupRule::new();
        assert!(rule.name().contains("DNS"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonSyncDnsLookupRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonSyncDnsLookupRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonSyncDnsLookupRule::default();
        assert_eq!(rule.id(), "python.sync_dns_lookup");
    }

    #[tokio::test]
    async fn detects_gethostbyname_in_async() {
        let source = r#"
import socket
import asyncio

async def resolve_host(hostname):
    ip = socket.gethostbyname(hostname)
    return ip
"#;
        let (file_id, sem) = parse_and_build_semantics(source);
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect gethostbyname in async");
        assert!(findings[0].title.contains("gethostbyname"));
        assert!(findings[0].title.contains("async context"));
    }

    #[tokio::test]
    async fn detects_getaddrinfo_in_async() {
        let source = r#"
import socket

async def get_address_info(host, port):
    info = socket.getaddrinfo(host, port)
    return info
"#;
        let (file_id, sem) = parse_and_build_semantics(source);
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect getaddrinfo in async");
        assert!(findings[0].title.contains("getaddrinfo"));
    }

    #[tokio::test]
    async fn detects_gethostbyaddr_reverse_dns() {
        let source = r#"
import socket

async def reverse_lookup(ip):
    hostname = socket.gethostbyaddr(ip)
    return hostname
"#;
        let (file_id, sem) = parse_and_build_semantics(source);
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect gethostbyaddr");
        assert!(findings[0].title.contains("gethostbyaddr"));
    }

    #[tokio::test]
    async fn detects_getfqdn() {
        let source = r#"
import socket

async def get_fqdn():
    fqdn = socket.getfqdn()
    return fqdn
"#;
        let (file_id, sem) = parse_and_build_semantics(source);
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect getfqdn");
        assert!(findings[0].title.contains("getfqdn"));
    }

    #[tokio::test]
    async fn detects_getnameinfo() {
        let source = r#"
import socket

async def get_name_info(sockaddr):
    name = socket.getnameinfo(sockaddr, 0)
    return name
"#;
        let (file_id, sem) = parse_and_build_semantics(source);
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect getnameinfo");
        assert!(findings[0].title.contains("getnameinfo"));
    }

    #[tokio::test]
    async fn detects_direct_import() {
        let source = r#"
from socket import gethostbyname

async def resolve(host):
    return gethostbyname(host)
"#;
        let (file_id, sem) = parse_and_build_semantics(source);
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect direct import");
    }

    #[tokio::test]
    async fn no_finding_without_socket_import() {
        let source = r#"
async def resolve(host):
    # No socket import, so this shouldn't be detected
    return gethostbyname(host)
"#;
        let (file_id, sem) = parse_and_build_semantics(source);
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(
            findings.is_empty(),
            "Should not detect without socket import"
        );
    }

    #[tokio::test]
    async fn detects_in_sync_context_with_lower_severity() {
        let source = r#"
import socket

def resolve_host(hostname):
    ip = socket.gethostbyname(hostname)
    return ip
"#;
        let (file_id, sem) = parse_and_build_semantics(source);
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect in sync context");
        // Should have lower severity since not in async context
        assert!(matches!(findings[0].severity, Severity::Medium));
        assert!(!findings[0].title.contains("async context"));
    }

    #[tokio::test]
    async fn higher_severity_in_async_context() {
        let source = r#"
import socket

async def resolve_host(hostname):
    ip = socket.gethostbyname(hostname)
    return ip
"#;
        let (file_id, sem) = parse_and_build_semantics(source);
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect in async context");
        // Should have higher severity in async context
        assert!(matches!(findings[0].severity, Severity::High));
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let (file_id, sem) = parse_and_build_semantics("");
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[], None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let source = r#"
import socket

async def resolve(host):
    return socket.gethostbyname(host)
"#;
        let (file_id, sem) = parse_and_build_semantics(source);
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty());
        let finding = &findings[0];
        assert_eq!(finding.rule_id, "python.sync_dns_lookup");
        assert!(matches!(finding.kind, FindingKind::PerformanceSmell));
        assert_eq!(finding.dimension, Dimension::Performance);
        assert!(finding.confidence > 0.8);
        assert!(finding.patch.is_some());
        assert!(finding.fix_preview.is_some());
        assert!(finding.tags.contains(&"dns".to_string()));
    }

    #[tokio::test]
    async fn generates_patch_for_async_context() {
        let source = r#"
import socket

async def resolve(host):
    return socket.gethostbyname(host)
"#;
        let (file_id, sem) = parse_and_build_semantics(source);
        let rule = PythonSyncDnsLookupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty());
        let patch = findings[0].patch.as_ref().unwrap();
        assert!(!patch.hunks.is_empty());
    }

    #[test]
    fn dns_lookup_type_descriptions_are_meaningful() {
        let types = [
            DnsLookupType::GetHostByName,
            DnsLookupType::GetHostByNameEx,
            DnsLookupType::GetHostByAddr,
            DnsLookupType::GetAddrInfo,
            DnsLookupType::GetNameInfo,
            DnsLookupType::GetFqdn,
        ];

        for lookup_type in types {
            let desc = lookup_type.description();
            assert!(!desc.is_empty());
            assert!(desc.contains("DNS") || desc.contains("synchronous"));

            let alt = lookup_type.async_alternative();
            assert!(!alt.is_empty());
            assert!(alt.contains("async") || alt.contains("await") || alt.contains("aiodns"));
        }
    }

    #[test]
    fn is_dns_function_identifies_all_functions() {
        assert!(is_dns_function("gethostbyname"));
        assert!(is_dns_function("gethostbyname_ex"));
        assert!(is_dns_function("gethostbyaddr"));
        assert!(is_dns_function("getaddrinfo"));
        assert!(is_dns_function("getnameinfo"));
        assert!(is_dns_function("getfqdn"));
        assert!(!is_dns_function("connect"));
        assert!(!is_dns_function("socket"));
    }
}
