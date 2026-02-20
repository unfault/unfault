//! Rule: Synchronous DNS lookup in async context detection
//!
//! Detects blocking DNS operations inside async functions that can block
//! the async runtime's worker threads.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! async fn connect_to_host(host: &str) {
//!     let addrs = std::net::ToSocketAddrs::to_socket_addrs(&(host, 80));  // Blocking!
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! async fn connect_to_host(host: &str) {
//!     let addrs = tokio::net::lookup_host((host, 80)).await?;
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects synchronous DNS lookups in async code.
///
/// DNS resolution can take hundreds of milliseconds when resolvers
/// are slow or unresponsive. Blocking the async worker thread
/// starves other tasks of execution time.
#[derive(Debug, Default)]
pub struct RustSyncDnsLookupRule;

impl RustSyncDnsLookupRule {
    pub fn new() -> Self {
        Self
    }
}

/// Patterns that indicate blocking DNS operations
const BLOCKING_DNS_PATTERNS: &[(&str, &str)] = &[
    ("std::net::ToSocketAddrs", "tokio::net::lookup_host"),
    ("to_socket_addrs", "tokio::net::lookup_host"),
    ("std::net::lookup_host", "tokio::net::lookup_host"),
    ("gethostbyname", "tokio::net::lookup_host"),
    ("getaddrinfo", "tokio::net::lookup_host"),
    ("dns_lookup::", "trust_dns_resolver or tokio::net::lookup_host"),
    ("resolve_host", "async resolution"),
];

/// Patterns that indicate async-safe DNS operations
const ASYNC_DNS_PATTERNS: &[&str] = &[
    "tokio::net::lookup_host",
    "async_std::net::resolve",
    "trust_dns_resolver",
    "hickory_resolver",
    "hyper::client",
    "reqwest::",
    "spawn_blocking",
];

#[async_trait]
impl Rule for RustSyncDnsLookupRule {
    fn id(&self) -> &'static str {
        "rust.sync_dns_lookup"
    }

    fn name(&self) -> &'static str {
        "Synchronous DNS lookup in async code blocks runtime"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let rust = match sem.as_ref() {
                SourceSemantics::Rust(r) => r,
                _ => continue,
            };

            // Check calls in async functions for blocking DNS
            for call in &rust.calls {
                if !call.in_async {
                    continue;
                }

                let callee = &call.function_call.callee_expr;

                // Check if this is a blocking DNS pattern
                let blocking_match = BLOCKING_DNS_PATTERNS
                    .iter()
                    .find(|(pattern, _)| callee.contains(pattern));

                if let Some((pattern, alternative)) = blocking_match {
                    // Check if there's async DNS or spawn_blocking in context
                    let func_name = call.function_name.clone().unwrap_or_default();
                    let is_properly_wrapped = rust.calls.iter().any(|c| {
                        c.function_name.as_deref() == Some(&func_name)
                            && ASYNC_DNS_PATTERNS.iter().any(|p| c.function_call.callee_expr.contains(p))
                    });

                    if is_properly_wrapped {
                        continue;
                    }

                    let line = call.function_call.location.line;

                    let title = format!(
                        "Blocking DNS lookup '{}' in async function",
                        pattern
                    );

                    let description = format!(
                        "The DNS call '{}' at line {} is a blocking operation that can \
                        stall the async runtime's worker thread.\n\n\
                        **Why this is problematic:**\n\
                        - DNS resolution can take hundreds of milliseconds\n\
                        - Slow/unreachable DNS servers cause long blocking\n\
                        - Blocks all tasks scheduled on this worker thread\n\
                        - Can cause cascading timeouts and failures\n\n\
                        **Recommended fix:**\n\
                        Use `{}` instead.",
                        callee, line, alternative
                    );

                    let fix_preview = format!(
                        r#"// Before (blocking):
async fn connect(host: &str) {{
    let addrs = {pattern}(&(host, 80)).unwrap();
}}

// After (async):
async fn connect(host: &str) {{
    let addrs = tokio::net::lookup_host((host, 80)).await?;
}}"#,
                        pattern = pattern
                    );

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line },
                            replacement: format!(
                                "// TODO: Replace blocking DNS with: {}\n",
                                alternative
                            ),
                        }],
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::High,
                        confidence: 0.85,
                        dimension: Dimension::Performance,
                        file_id: *file_id,
                        file_path: rust.path.clone(),
                        line: Some(line),
                        column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "rust".into(),
                            "async".into(),
                            "dns".into(),
                            "blocking".into(),
                            "performance".into(),
                        ],
                    });
                }
            }

            // Also check use imports for std::net DNS functions
            for use_stmt in &rust.uses {
                if use_stmt.path.contains("std::net::ToSocketAddrs") {
                    // Check if the file has async functions
                    let has_async = rust.functions.iter().any(|f| f.is_async);
                    
                    if has_async {
                        let line = use_stmt.location.range.start_line + 1;

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Import of blocking DNS trait in async codebase".to_string(),
                            description: Some(format!(
                                "The import of `{}` at line {} provides blocking DNS resolution. \
                                In async code, prefer `tokio::net::lookup_host` or similar.",
                                use_stmt.path, line
                            )),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::Low,
                            confidence: 0.60,
                            dimension: Dimension::Performance,
                            file_id: *file_id,
                            file_path: rust.path.clone(),
                            line: Some(line),
                            column: Some(use_stmt.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: None,
                            fix_preview: None,
                            tags: vec![
                                "rust".into(),
                                "async".into(),
                                "dns".into(),
                                "import".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::rust::parse_rust_file;
    use crate::semantics::rust::build_rust_semantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "async_code.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_rust_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Rust(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = RustSyncDnsLookupRule::new();
        assert_eq!(rule.id(), "rust.sync_dns_lookup");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustSyncDnsLookupRule::new();
        assert!(rule.name().contains("DNS"));
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = RustSyncDnsLookupRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn blocking_dns_patterns_are_valid() {
        for (pattern, alt) in BLOCKING_DNS_PATTERNS {
            assert!(!pattern.is_empty());
            assert!(!alt.is_empty());
        }
    }

    #[test]
    fn async_dns_patterns_are_valid() {
        for pattern in ASYNC_DNS_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[tokio::test]
    async fn no_finding_for_sync_functions() {
        let rule = RustSyncDnsLookupRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn sync_fn() {
    let addrs = "localhost:8080".to_socket_addrs();
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}