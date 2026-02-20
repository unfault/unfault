//! Rule: Uncancelled async tasks detection
//!
//! Detects spawned tasks that are not properly cancelled on shutdown,
//! which can lead to resource leaks and incomplete work.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! async fn run_server() {
//!     let handle = tokio::spawn(background_work());
//!     // Server stops, but background_work keeps running
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! async fn run_server() {
//!     let handle = tokio::spawn(background_work());
//!     // On shutdown:
//!     handle.abort();  // Or use CancellationToken
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::semantics::rust::RustFileSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Check if CancellationToken is already imported
fn has_cancellation_token_import(rust: &RustFileSemantics) -> bool {
    rust.uses.iter().any(|u| {
        u.path.contains("CancellationToken") || u.path.contains("tokio_util::sync::CancellationToken")
    })
}

/// Rule that detects spawned tasks without proper cancellation handling.
///
/// Tasks that aren't cancelled on shutdown can:
/// - Continue accessing resources that have been cleaned up
/// - Prevent graceful shutdown from completing
/// - Leak resources and cause memory growth
#[derive(Debug, Default)]
pub struct RustUncancelledTasksRule;

impl RustUncancelledTasksRule {
    pub fn new() -> Self {
        Self
    }
}

/// Patterns that indicate proper cancellation handling
const CANCELLATION_PATTERNS: &[&str] = &[
    ".abort()",
    "abort_handle",
    "AbortHandle",
    "CancellationToken",
    "cancellation_token",
    "shutdown_signal",
    "shutdown_rx",
    "ctrl_c",
    "signal::ctrl_c",
    "tokio::signal",
    "JoinSet",
    ".abort_all()",
];

#[async_trait]
impl Rule for RustUncancelledTasksRule {
    fn id(&self) -> &'static str {
        "rust.uncancelled_tasks"
    }

    fn name(&self) -> &'static str {
        "Spawned tasks not properly cancelled on shutdown"
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

            // Check if file has any cancellation patterns
            let has_cancellation = rust.calls.iter().any(|c| {
                CANCELLATION_PATTERNS.iter().any(|p| c.function_call.callee_expr.contains(p))
            }) || rust.uses.iter().any(|u| {
                CANCELLATION_PATTERNS.iter().any(|p| u.path.contains(p))
            });

            // Check spawn calls
            for spawn_call in &rust.async_info.spawn_calls {
                // Skip spawns in test functions
                let func_name = spawn_call.function_name.clone().unwrap_or_default();
                let in_test = rust.functions.iter().any(|f| {
                    f.name == func_name && (f.is_test || f.has_test_attribute)
                });

                if in_test {
                    continue;
                }

                // Check if handle is captured (at least basic tracking)
                if !spawn_call.handle_captured {
                    // Fire-and-forget spawn without even capturing the handle
                    let line = spawn_call.location.range.start_line;

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Fire-and-forget spawn without handle capture".to_string(),
                        description: Some(format!(
                            "The spawn at line {} doesn't capture its JoinHandle, \
                            making it impossible to cancel or await completion.\n\n\
                            **Issues:**\n\
                            - Cannot cancel the task on shutdown\n\
                            - Cannot detect if task panicked\n\
                            - Cannot wait for task completion\n\n\
                            **Recommended:** Capture handles and manage task lifecycle.",
                            line
                        )),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.80,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: rust.path.clone(),
                        line: Some(line),
                        column: Some(spawn_call.location.range.start_col),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(create_handle_capture_patch(line, *file_id)),
                        fix_preview: Some(create_handle_fix_preview()),
                        tags: vec![
                            "rust".into(),
                            "async".into(),
                            "spawn".into(),
                            "cancellation".into(),
                        ],
                    });
                } else if !has_cancellation {
                    // Handle captured but no cancellation logic found in file
                    let line = spawn_call.location.range.start_line;

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: format!(
                            "Spawned task in '{}' lacks cancellation handling",
                            func_name
                        ),
                        description: Some(format!(
                            "The spawn at line {} captures its handle but the file has no \
                            visible cancellation logic.\n\n\
                            **Why this matters:**\n\
                            - Tasks may outlive their useful lifetime\n\
                            - Shutdown handlers won't stop this task\n\
                            - Background work continues after service \"stops\"\n\n\
                            **Recommended patterns:**\n\
                            - Use `CancellationToken` for cooperative cancellation\n\
                            - Use `JoinSet` for managing multiple tasks\n\
                            - Call `handle.abort()` in shutdown handlers",
                            line
                        )),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Low,
                        confidence: 0.65,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: rust.path.clone(),
                        line: Some(line),
                        column: Some(spawn_call.location.range.start_col),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(create_cancellation_patch(line, *file_id, rust)),
                        fix_preview: Some(create_cancellation_fix_preview()),
                        tags: vec![
                            "rust".into(),
                            "async".into(),
                            "spawn".into(),
                            "cancellation".into(),
                            "shutdown".into(),
                        ],
                    });
                }
            }
        }

        findings
    }
}

fn create_handle_capture_patch(line: u32, file_id: FileId) -> FilePatch {
    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement: "// TODO: Capture spawn handle for cancellation\n\
                         // let handle = ".to_string(),
        }],
    }
}

fn create_handle_fix_preview() -> String {
    r#"// Before (fire-and-forget):
tokio::spawn(background_work());

// After (tracked task):
let handle = tokio::spawn(background_work());
// Store handle for later cancellation

// On shutdown:
handle.abort();
// Or: handle.await.unwrap();"#.to_string()
}

fn create_cancellation_patch(line: u32, file_id: FileId, rust: &RustFileSemantics) -> FilePatch {
    let mut hunks = Vec::new();
    
    // Only add import if not already present
    if !has_cancellation_token_import(rust) {
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: 1 },
            replacement: "use tokio_util::sync::CancellationToken;\n".to_string(),
        });
    }
    
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line },
        replacement: "// TODO: Add cancellation support to this spawn\n".to_string(),
    });
    
    FilePatch { file_id, hunks }
}

fn create_cancellation_fix_preview() -> String {
    r#"use tokio_util::sync::CancellationToken;

// Create token
let cancel_token = CancellationToken::new();
let token = cancel_token.clone();

// Spawn with cancellation
let handle = tokio::spawn(async move {
    tokio::select! {
        _ = token.cancelled() => {
            // Cleanup on cancellation
        }
        result = actual_work() => {
            result
        }
    }
});

// On shutdown:
cancel_token.cancel();
handle.await.ok();"#.to_string()
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
        let rule = RustUncancelledTasksRule::new();
        assert_eq!(rule.id(), "rust.uncancelled_tasks");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustUncancelledTasksRule::new();
        assert!(rule.name().contains("cancel"));
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = RustUncancelledTasksRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn cancellation_patterns_are_valid() {
        for pattern in CANCELLATION_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[tokio::test]
    async fn no_finding_for_sync_code() {
        let rule = RustUncancelledTasksRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn sync_fn() {
    let x = 1 + 2;
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}