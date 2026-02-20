//! Rule: Unbounded concurrency detection
//!
//! Detects spawning many async tasks without limiting concurrency,
//! which can lead to resource exhaustion.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! async fn process_all(items: Vec<Item>) {
//!     let handles: Vec<_> = items
//!         .into_iter()
//!         .map(|item| tokio::spawn(process_item(item)))
//!         .collect();
//!     futures::future::join_all(handles).await;
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! async fn process_all(items: Vec<Item>) {
//!     let semaphore = Arc::new(Semaphore::new(10));
//!     let handles: Vec<_> = items
//!         .into_iter()
//!         .map(|item| {
//!             let permit = semaphore.clone();
//!             tokio::spawn(async move {
//!                 let _permit = permit.acquire().await?;
//!                 process_item(item).await
//!             })
//!         })
//!         .collect();
//!     futures::future::join_all(handles).await;
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

/// Rule that detects unbounded concurrency patterns.
///
/// Spawning unlimited concurrent tasks can exhaust system resources
/// like file descriptors, memory, and network connections.
#[derive(Debug, Default)]
pub struct RustUnboundedConcurrencyRule;

impl RustUnboundedConcurrencyRule {
    pub fn new() -> Self {
        Self
    }
}

/// Patterns indicating concurrency limiting is applied
const CONCURRENCY_LIMIT_PATTERNS: &[&str] = &[
    "Semaphore",
    "semaphore",
    "ConcurrencyLimit",
    "concurrency_limit",
    "buffer_unordered(",
    "buffered(",
    "FuturesUnordered",
    "StreamExt::buffer",
    "tokio::sync::Semaphore",
];

/// Patterns indicating unbounded spawn in a loop/iterator
const UNBOUNDED_SPAWN_PATTERNS: &[&str] = &[
    ".map(|", // Iterator map potentially spawning
    "for_each(",
    "join_all(",
    "try_join_all(",
];

#[async_trait]
impl Rule for RustUnboundedConcurrencyRule {
    fn id(&self) -> &'static str {
        "rust.unbounded_concurrency"
    }

    fn name(&self) -> &'static str {
        "Unbounded concurrency can exhaust system resources"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::unbounded_resource())
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

            // Check if Semaphore is imported
            let has_semaphore_import = rust.uses.iter().any(|u| {
                CONCURRENCY_LIMIT_PATTERNS.iter().any(|p| u.path.contains(p))
            });

            // Look for spawn calls that appear in loop/iterator context
            for spawn_call in &rust.async_info.spawn_calls {
                let expr = &spawn_call.spawned_expr;
                let func_name = spawn_call.function_name.clone().unwrap_or_default();

                // Check if this spawn is part of an iterator chain
                let in_iterator_context = UNBOUNDED_SPAWN_PATTERNS
                    .iter()
                    .any(|p| expr.contains(p));

                // Check if the function uses any concurrency limiting
                let func_has_limiting = has_semaphore_import
                    || rust.calls.iter().any(|c| {
                        c.function_name.as_deref() == Some(&func_name)
                            && CONCURRENCY_LIMIT_PATTERNS.iter().any(|p| c.function_call.callee_expr.contains(p))
                    });

                // Count spawns in this function
                let spawns_in_func = rust
                    .async_info
                    .spawn_calls
                    .iter()
                    .filter(|s| s.function_name.as_deref() == Some(&func_name))
                    .count();

                // Flag if: multiple spawns or in iterator context, without semaphore
                if (spawns_in_func > 1 || in_iterator_context) && !func_has_limiting {
                    let line = spawn_call.location.range.start_line;

                    findings.push(create_finding(
                        self.id(),
                        &func_name,
                        line,
                        spawn_call.location.range.start_col,
                        spawns_in_func,
                        *file_id,
                        &rust.path,
                    ));
                    
                    // Only report once per function
                    break;
                }
            }

            // Also check for join_all/try_join_all without semaphore
            for call in &rust.calls {
                if call.function_call.callee_expr.contains("join_all") || call.function_call.callee_expr.contains("try_join_all") {
                    let func_name = call.function_name.clone().unwrap_or_default();

                    let func_has_limiting = has_semaphore_import
                        || rust.calls.iter().any(|c| {
                            c.function_name.as_deref() == Some(&func_name)
                                && CONCURRENCY_LIMIT_PATTERNS.iter().any(|p| c.function_call.callee_expr.contains(p))
                        });

                    if !func_has_limiting {
                        let line = call.function_call.location.line;

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: format!(
                                "Unbounded {} may exhaust resources",
                                if call.function_call.callee_expr.contains("try_join_all") {
                                    "try_join_all"
                                } else {
                                    "join_all"
                                }
                            ),
                            description: Some(format!(
                                "The call to `{}` at line {} runs all futures concurrently \
                                without limiting parallelism.\n\n\
                                **Why this is risky:**\n\
                                - Can spawn thousands of concurrent operations\n\
                                - Exhausts file descriptors and connections\n\
                                - May overwhelm downstream services\n\
                                - Can cause OOM under high load\n\n\
                                **Recommended fix:**\n\
                                Use `futures::stream::iter(...).buffer_unordered(N)` or \
                                a semaphore to limit concurrency.",
                                call.function_call.callee_expr, line
                            )),
                            kind: FindingKind::BehaviorThreat,
                            severity: Severity::High,
                            confidence: 0.80,
                            dimension: Dimension::Scalability,
                            file_id: *file_id,
                            file_path: rust.path.clone(),
                            line: Some(line),
                            column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line },
                                    replacement: "// TODO: Limit concurrency with buffer_unordered or Semaphore\n".to_string(),
                                }],
                            }),
                            fix_preview: Some(
                                "// Use buffer_unordered to limit concurrency:\n\
                                use futures::stream::{self, StreamExt};\n\
                                \n\
                                stream::iter(items)\n\
                                    .map(|item| async move { process(item).await })\n\
                                    .buffer_unordered(10)  // Max 10 concurrent\n\
                                    .collect::<Vec<_>>()\n\
                                    .await;".to_string()
                            ),
                            tags: vec![
                                "rust".into(),
                                "async".into(),
                                "concurrency".into(),
                                "resource-exhaustion".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }
}

fn create_finding(
    rule_id: &str,
    func_name: &str,
    line: u32,
    column: u32,
    spawn_count: usize,
    file_id: FileId,
    file_path: &str,
) -> RuleFinding {
    let title = format!(
        "Unbounded task spawning in '{}' ({} spawns without semaphore)",
        func_name, spawn_count
    );

    let description = format!(
        "Function '{}' spawns {} concurrent tasks without limiting parallelism.\n\n\
        **Why this is risky:**\n\
        - Can spawn thousands of concurrent operations\n\
        - Exhausts file descriptors and connections\n\
        - May overwhelm downstream services\n\
        - Can cause OOM under high load\n\n\
        **Recommended fix:**\n\
        Use `tokio::sync::Semaphore` to limit concurrent tasks:\n\
        ```rust\n\
        let semaphore = Arc::new(Semaphore::new(10));\n\
        let permit = semaphore.clone().acquire_owned().await?;\n\
        tokio::spawn(async move {{\n\
            let _permit = permit;  // Released when dropped\n\
            // ... task work\n\
        }});\n\
        ```",
        func_name, spawn_count
    );

    let fix_preview = format!(
        r#"// Before (unbounded):
for item in items {{
    tokio::spawn(process(item));
}}

// After (limited to 10 concurrent):
use tokio::sync::Semaphore;
let semaphore = Arc::new(Semaphore::new(10));
for item in items {{
    let permit = semaphore.clone().acquire_owned().await?;
    tokio::spawn(async move {{
        let _permit = permit;
        process(item).await
    }});
}}"#
    );

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::BehaviorThreat,
        severity: Severity::High,
        confidence: 0.75,
        dimension: Dimension::Scalability,
        file_id,
        file_path: file_path.to_string(),
        line: Some(line),
        column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
        patch: Some(FilePatch {
            file_id,
            hunks: vec![
                PatchHunk {
                    range: PatchRange::InsertBeforeLine { line: 1 },
                    replacement: "use tokio::sync::Semaphore;\nuse std::sync::Arc;\n".to_string(),
                },
                PatchHunk {
                    range: PatchRange::InsertBeforeLine { line },
                    replacement: "// TODO: Add Semaphore to limit concurrent spawns\n".to_string(),
                },
            ],
        }),
        fix_preview: Some(fix_preview),
        tags: vec![
            "rust".into(),
            "async".into(),
            "concurrency".into(),
            "spawn".into(),
            "resource-exhaustion".into(),
        ],
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
        let rule = RustUnboundedConcurrencyRule::new();
        assert_eq!(rule.id(), "rust.unbounded_concurrency");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustUnboundedConcurrencyRule::new();
        assert!(rule.name().contains("concurrency"));
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = RustUnboundedConcurrencyRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn concurrency_limit_patterns_are_valid() {
        for pattern in CONCURRENCY_LIMIT_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[test]
    fn unbounded_spawn_patterns_are_valid() {
        for pattern in UNBOUNDED_SPAWN_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[tokio::test]
    async fn no_finding_for_sync_code() {
        let rule = RustUnboundedConcurrencyRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn sync_fn() {
    for i in 0..10 {
        process(i);
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}