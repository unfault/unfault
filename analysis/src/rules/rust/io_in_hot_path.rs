//! Rule: I/O operation in hot path detection
//!
//! Detects file I/O, network calls, or database queries inside loops
//! or frequently-called functions that can cause severe performance issues.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! fn process_items(items: &[Item]) {
//!     for item in items {
//!         let config = std::fs::read_to_string("config.json")?;  // I/O in loop!
//!         process(item, &config);
//!     }
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! fn process_items(items: &[Item]) {
//!     let config = std::fs::read_to_string("config.json")?;  // I/O before loop
//!     for item in items {
//!         process(item, &config);
//!     }
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects I/O operations in hot paths.
///
/// I/O operations (file, network, database) in loops or hot paths
/// cause severe performance degradation due to latency overhead.
#[derive(Debug, Default)]
pub struct RustIoInHotPathRule;

impl RustIoInHotPathRule {
    pub fn new() -> Self {
        Self
    }
}

/// Patterns indicating I/O operations
const IO_PATTERNS: &[(&str, &str)] = &[
    // File I/O
    ("std::fs::read", "file read"),
    ("std::fs::write", "file write"),
    ("std::fs::read_to_string", "file read"),
    ("std::fs::read_dir", "directory listing"),
    ("std::fs::metadata", "file metadata"),
    ("std::fs::copy", "file copy"),
    ("std::fs::create_dir", "directory creation"),
    ("File::open", "file open"),
    ("File::create", "file create"),
    (".read(", "read operation"),
    (".write(", "write operation"),
    (".read_to_end(", "read all"),
    (".read_to_string(", "read to string"),
    // Network I/O
    ("TcpStream::connect", "TCP connect"),
    ("UdpSocket::bind", "UDP bind"),
    ("reqwest::get", "HTTP request"),
    ("reqwest::Client", "HTTP request"),
    (".send().await", "HTTP send"),
    ("client.get(", "HTTP GET"),
    ("http_client.get(", "HTTP GET"),
    // Database I/O
    ("sqlx::query", "database query"),
    (".fetch_one(", "database fetch"),
    (".fetch_all(", "database fetch"),
    (".execute(", "database execute"),
    ("diesel::", "database operation"),
    // Other I/O
    ("Command::new", "process spawn"),
    ("std::io::stdin", "stdin read"),
    ("std::io::stdout", "stdout write"),
];

/// Patterns indicating caching/optimization is in place
const CACHED_PATTERNS: &[&str] = &[
    "cache",
    "Cache",
    "cached",
    "memoize",
    "lazy_static",
    "OnceCell",
    "OnceLock",
    "Lazy",
];

#[async_trait]
impl Rule for RustIoInHotPathRule {
    fn id(&self) -> &'static str {
        "rust.io_in_hot_path"
    }

    fn name(&self) -> &'static str {
        "I/O operation in hot path causes performance degradation"
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

            // Check for I/O operations in loops
            for call in &rust.calls {
                if !call.in_loop {
                    continue;
                }

                let callee = &call.function_call.callee_expr;

                // Skip calls on string literals (false positives from documentation/examples)
                // This includes regular strings ("...") and raw strings (r#"..."#, r"...")
                if callee.starts_with('"')
                    || callee.starts_with("r#\"")
                    || callee.starts_with("r\"")
                {
                    continue;
                }

                // Find matching I/O pattern
                let io_match = IO_PATTERNS
                    .iter()
                    .find(|(pattern, _)| callee.contains(pattern));

                if let Some((pattern, io_type)) = io_match {
                    // Check if caching is used in the function
                    let func_name = call.function_name.clone().unwrap_or_default();
                    let has_caching = rust.calls.iter().any(|c| {
                        c.function_name.as_deref() == Some(&func_name)
                            && CACHED_PATTERNS
                                .iter()
                                .any(|p| c.function_call.callee_expr.contains(p))
                    }) || rust
                        .uses
                        .iter()
                        .any(|u| CACHED_PATTERNS.iter().any(|p| u.path.contains(p)));

                    if has_caching {
                        continue;
                    }

                    let line = call.function_call.location.line;

                    let title = format!("I/O in hot path: {} inside loop", io_type);

                    let description = format!(
                        "The {} operation '{}' at line {} is inside a loop.\n\n\
                        **Performance impact:**\n\
                        - Each iteration incurs I/O latency (ms to seconds)\n\
                        - 1000 iterations = 1000x the latency overhead\n\
                        - Blocks the thread/task during each operation\n\
                        - Can exhaust file descriptors or connections\n\n\
                        **Solutions:**\n\
                        1. Move I/O outside the loop and cache results\n\
                        2. Use batch operations (e.g., read multiple files at once)\n\
                        3. Pre-fetch data before entering the loop\n\
                        4. Use caching (OnceCell, lazy_static, or manual cache)",
                        io_type, pattern, line
                    );

                    let fix_preview = format!(
                        r#"// Before (I/O in loop):
for item in items {{
    let data = {pattern}(...);  // I/O each iteration
    process(item, &data);
}}

// After (I/O before loop):
let data = {pattern}(...);  // Single I/O call
for item in items {{
    process(item, &data);
}}"#,
                        pattern = pattern.replace("std::fs::", "fs::")
                    );

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line },
                            replacement: format!(
                                "// TODO: Move {} outside loop or add caching\n",
                                io_type
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
                            "io".into(),
                            "performance".into(),
                            "loop".into(),
                            "hot-path".into(),
                        ],
                    });
                }
            }

            // Also flag multiple I/O calls in the same function (potential batching opportunity)
            // Limit to 100 functions max to bound memory usage
            const MAX_FUNCTION_FINDINGS: usize = 100;
            let functions_with_many_io: Vec<_> = rust
                .functions
                .iter()
                .filter(|f| !f.is_test)
                .filter_map(|f| {
                    let io_count = rust
                        .calls
                        .iter()
                        .filter(|c| {
                            c.function_name.as_deref() == Some(&f.name)
                                // Skip string literals (including raw strings)
                                && !c.function_call.callee_expr.starts_with('"')
                                && !c.function_call.callee_expr.starts_with("r#\"")
                                && !c.function_call.callee_expr.starts_with("r\"")
                                && IO_PATTERNS.iter().any(|(p, _)| c.function_call.callee_expr.contains(p))
                        })
                        .count();

                    if io_count > 3 {
                        Some((f.name.clone(), f.location.range.start_line + 1, io_count))
                    } else {
                        None
                    }
                })
                .take(MAX_FUNCTION_FINDINGS)
                .collect();

            for (func_name, line, io_count) in functions_with_many_io {
                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!("Function '{}' has {} I/O operations", func_name, io_count),
                    description: Some(format!(
                        "Function '{}' at line {} contains {} I/O operations.\n\
                        Consider batching, caching, or parallelizing these operations.",
                        func_name, line, io_count
                    )),
                    kind: FindingKind::PerformanceSmell,
                    severity: Severity::Medium,
                    confidence: 0.65,
                    dimension: Dimension::Performance,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: None,
                    fix_preview: None,
                    tags: vec!["rust".into(), "io".into(), "performance".into()],
                });
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
    use crate::semantics::SourceSemantics;
    use crate::semantics::rust::build_rust_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "io_code.rs".to_string(),
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
        let rule = RustIoInHotPathRule::new();
        assert_eq!(rule.id(), "rust.io_in_hot_path");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustIoInHotPathRule::new();
        assert!(rule.name().contains("I/O"));
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = RustIoInHotPathRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn io_patterns_are_valid() {
        for (pattern, desc) in IO_PATTERNS {
            assert!(!pattern.is_empty());
            assert!(!desc.is_empty());
        }
    }

    #[test]
    fn cached_patterns_are_valid() {
        for pattern in CACHED_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[tokio::test]
    async fn no_finding_for_io_outside_loop() {
        let rule = RustIoInHotPathRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process_items() {
    let config = std::fs::read_to_string("config.json").unwrap();
    // No loop here
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        // No loop = no hot path finding
        let hot_path_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("inside loop"))
            .collect();
        assert!(hot_path_findings.is_empty());
    }
}
