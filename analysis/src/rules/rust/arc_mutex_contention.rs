//! Rule: Arc<Mutex> contention in hot paths
//!
//! Detects `Arc<Mutex<T>>` patterns that may cause contention issues,
//! especially when used in async contexts or frequently accessed paths.
//!
//! # Examples
//!
//! Potentially problematic:
//! ```rust,ignore
//! async fn handle_request(state: Arc<Mutex<State>>) {
//!     let guard = state.lock().unwrap();  // Blocks the task!
//!     // ...
//! }
//! ```
//!
//! Better alternatives:
//! ```rust,ignore
//! // Use tokio::sync::Mutex for async
//! async fn handle_request(state: Arc<tokio::sync::Mutex<State>>) {
//!     let guard = state.lock().await;
//!     // ...
//! }
//!
//! // Or use RwLock for read-heavy workloads
//! async fn handle_request(state: Arc<RwLock<State>>) {
//!     let guard = state.read().await;
//!     // ...
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

/// Rule that detects potentially problematic Arc<Mutex<T>> usage patterns.
///
/// While Arc<Mutex<T>> is valid, using std::sync::Mutex in async code
/// can cause thread pool starvation and contention issues.
#[derive(Debug, Default)]
pub struct RustArcMutexContentionRule;

impl RustArcMutexContentionRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustArcMutexContentionRule {
    fn id(&self) -> &'static str {
        "rust.arc_mutex_contention"
    }

    fn name(&self) -> &'static str {
        "Arc<Mutex> used in async context"
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

            // Check if this file uses async (tokio or async-std)
            let uses_async = rust.async_info.uses_tokio
                || rust.async_info.uses_async_std
                || rust.async_info.async_fn_count > 0;

            if !uses_async {
                continue;
            }

            // Look for Arc<Mutex<...>> patterns in function parameters and statics
            for func in &rust.functions {
                if func.is_test {
                    continue;
                }

                // Check parameters for Arc<Mutex<...>>
                for param in &func.params {
                    if is_arc_std_mutex(&param.param_type) {
                        let line = func.location.range.start_line + 1;

                        // Higher severity if the function is async
                        let severity = if func.is_async {
                            Severity::High
                        } else {
                            Severity::Medium
                        };

                        let title = format!(
                            "std::sync::Mutex used in {} function '{}'",
                            if func.is_async { "async" } else { "sync" },
                            func.name
                        );

                        let description = format!(
                            "The function '{}' accepts `Arc<Mutex<T>>` with std::sync::Mutex.\n\n\
                             **Why this matters:**\n\
                             - std::sync::Mutex::lock() blocks the current thread\n\
                             - In async contexts, this blocks the entire tokio worker thread\n\
                             - Can cause thread pool starvation under load\n\
                             - Other tasks on the same thread can't make progress\n\n\
                             **Recommendations:**\n\
                             - Use `tokio::sync::Mutex` for async code (allows .await)\n\
                             - Use `tokio::sync::RwLock` for read-heavy workloads\n\
                             - Use `parking_lot::Mutex` for better performance in sync code\n\
                             - Consider lock-free alternatives like `dashmap` for concurrent maps",
                            func.name
                        );

                        let fix_preview = if func.is_async {
                            format!(
                                "// Replace std::sync::Mutex with tokio::sync::Mutex:\n\
                                 async fn {}(..., state: Arc<tokio::sync::Mutex<T>>) {{\n    \
                                     let guard = state.lock().await;  // Non-blocking!\n\
                                 }}",
                                func.name
                            )
                        } else {
                            format!(
                                "// Consider using parking_lot::Mutex for better performance:\n\
                                 fn {}(..., state: Arc<parking_lot::Mutex<T>>) {{\n    \
                                     let guard = state.lock();  // No .unwrap() needed\n\
                                 }}",
                                func.name
                            )
                        };

                        let patch = FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: if func.is_async {
                                    "// TODO: Consider using tokio::sync::Mutex for async code"
                                        .to_string()
                                } else {
                                    "// TODO: Consider using parking_lot::Mutex or tokio::sync::Mutex".to_string()
                                },
                            }],
                        };

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::PerformanceSmell,
                            severity,
                            confidence: 0.85,
                            dimension: Dimension::Performance,
                            file_id: *file_id,
                            file_path: rust.path.clone(),
                            line: Some(line),
                            column: None,
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(fix_preview),
                            tags: vec![
                                "rust".into(),
                                "performance".into(),
                                "async".into(),
                                "mutex".into(),
                                "concurrency".into(),
                            ],
                        });
                    }
                }
            }

            // Also check static/const declarations for Arc<Mutex<...>>
            for static_decl in &rust.statics {
                if is_arc_std_mutex(&static_decl.decl_type) {
                    let line = static_decl.location.range.start_line + 1;

                    let title = format!(
                        "Global Arc<Mutex<T>> may cause contention: {}",
                        static_decl.name
                    );

                    let description = format!(
                        "The static '{}' uses `Arc<Mutex<T>>` with std::sync::Mutex.\n\n\
                         **Why this matters:**\n\
                         - Global mutexes are accessed from many places\n\
                         - High contention under concurrent access\n\
                         - Can become a bottleneck in async code\n\n\
                         **Consider:**\n\
                         - Using `OnceCell` or `OnceLock` for initialization\n\
                         - Using `RwLock` if reads are more common than writes\n\
                         - Using lock-free data structures\n\
                         - Avoiding global mutable state",
                        static_decl.name
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::Medium,
                        confidence: 0.70,
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
                        tags: vec![
                            "rust".into(),
                            "performance".into(),
                            "mutex".into(),
                            "global-state".into(),
                        ],
                    });
                }
            }
        }

        findings
    }
}

/// Check if a type is Arc<Mutex<...>> using std::sync::Mutex
fn is_arc_std_mutex(type_str: &str) -> bool {
    let cleaned = type_str.replace(' ', "");

    // Check for Arc<Mutex<...>> but not Arc<tokio::sync::Mutex<...>>
    if cleaned.contains("Arc<Mutex<") {
        // Make sure it's not tokio or parking_lot mutex
        !cleaned.contains("tokio::sync::Mutex")
            && !cleaned.contains("parking_lot::Mutex")
            && !cleaned.contains("async_std::sync::Mutex")
    } else {
        false
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
            path: "mutex_code.rs".to_string(),
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
        let rule = RustArcMutexContentionRule::new();
        assert_eq!(rule.id(), "rust.arc_mutex_contention");
    }

    #[test]
    fn rule_name_mentions_mutex() {
        let rule = RustArcMutexContentionRule::new();
        assert!(rule.name().to_lowercase().contains("mutex"));
    }

    #[test]
    fn is_arc_std_mutex_detects_basic() {
        assert!(is_arc_std_mutex("Arc<Mutex<Data>>"));
        assert!(is_arc_std_mutex("Arc<Mutex<Vec<String>>>"));
    }

    #[test]
    fn is_arc_std_mutex_skips_tokio() {
        assert!(!is_arc_std_mutex("Arc<tokio::sync::Mutex<Data>>"));
        assert!(!is_arc_std_mutex("Arc<parking_lot::Mutex<Data>>"));
    }

    #[test]
    fn is_arc_std_mutex_skips_non_mutex() {
        assert!(!is_arc_std_mutex("Arc<RwLock<Data>>"));
        assert!(!is_arc_std_mutex("Arc<Data>"));
        assert!(!is_arc_std_mutex("Mutex<Data>"));
    }

    #[tokio::test]
    async fn detects_arc_mutex_in_async_function() {
        let rule = RustArcMutexContentionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::sync::{Arc, Mutex};
use tokio;

async fn handle(state: Arc<Mutex<Data>>) {
    let guard = state.lock().unwrap();
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "rust.arc_mutex_contention"),
            "Should detect Arc<Mutex> in async code"
        );
    }

    #[tokio::test]
    async fn skips_non_async_code_without_tokio() {
        let rule = RustArcMutexContentionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::sync::{Arc, Mutex};

fn handle(state: Arc<Mutex<Data>>) {
    let guard = state.lock().unwrap();
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should skip because no async context
        assert!(findings.is_empty(), "Should skip non-async code");
    }

    #[tokio::test]
    async fn finding_has_correct_severity_for_async() {
        let rule = RustArcMutexContentionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::sync::{Arc, Mutex};
use tokio;

async fn handle(state: Arc<Mutex<Data>>) {
    let guard = state.lock().unwrap();
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        for finding in &findings {
            if finding.rule_id == "rust.arc_mutex_contention" {
                assert_eq!(
                    finding.severity,
                    Severity::High,
                    "Async functions should have High severity"
                );
                assert_eq!(finding.dimension, Dimension::Performance);
            }
        }
    }
}
