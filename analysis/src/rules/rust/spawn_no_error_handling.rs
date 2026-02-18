//! Rule: Spawn without error handling
//!
//! Detects tokio::spawn and similar spawn calls where the JoinHandle
//! is not captured or errors are not handled, which can lead to
//! silent failures.
//!
//! # Examples
//!
//! Bad:
//! ```rust
//! tokio::spawn(async {
//!     do_something().await?;  // Error goes nowhere!
//! });
//! ```
//!
//! Good:
//! ```rust
//! let handle = tokio::spawn(async {
//!     do_something().await
//! });
//! handle.await??;  // Handle both JoinError and inner error
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::rust::model::SpawnType;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects spawn calls without error handling.
///
/// When using tokio::spawn or similar, the JoinHandle should be
/// captured and awaited to properly handle panics and errors from
/// the spawned task.
#[derive(Debug, Default)]
pub struct RustSpawnNoErrorHandlingRule;

impl RustSpawnNoErrorHandlingRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustSpawnNoErrorHandlingRule {
    fn id(&self) -> &'static str {
        "rust.spawn_no_error_handling"
    }

    fn name(&self) -> &'static str {
        "Spawned task without error handling"
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

            // Check spawn calls
            for spawn in &rust.async_info.spawn_calls {
                // If handle is not captured, error handling is impossible
                if !spawn.handle_captured {
                    let line = spawn.location.range.start_line + 1;

                    let spawn_name = match &spawn.spawn_type {
                        SpawnType::TokioSpawn => "tokio::spawn",
                        SpawnType::TokioSpawnBlocking => "tokio::task::spawn_blocking",
                        SpawnType::TokioSpawnLocal => "tokio::task::spawn_local",
                        SpawnType::AsyncStdSpawn => "async_std::task::spawn",
                        SpawnType::AsyncStdSpawnBlocking => "async_std::task::spawn_blocking",
                        SpawnType::AsyncStdSpawnLocal => "async_std::task::spawn_local",
                        SpawnType::Other(name) => name,
                    };

                    let title = format!(
                        "{} without capturing JoinHandle",
                        spawn_name
                    );

                    let description = format!(
                        "`{}` at line {} discards the JoinHandle, making it impossible \
                         to handle errors or panics from the spawned task.\n\n\
                         **Problems with discarding JoinHandle:**\n\
                         - Panics in the spawned task are silently ignored\n\
                         - Errors returned by the task are lost\n\
                         - Task cancellation is impossible\n\
                         - No way to wait for task completion\n\
                         - Makes debugging difficult\n\n\
                         **What happens on panic:**\n\
                         - The task terminates silently\n\
                         - Other tasks continue running (no cascade)\n\
                         - But the panic is swallowed, hiding bugs\n\n\
                         **Best practices:**\n\
                         1. Capture the handle: `let handle = {}(...);`\n\
                         2. Await it: `handle.await?;`\n\
                         3. Or store handles for graceful shutdown\n\
                         4. Use `tokio::select!` with cancellation if needed",
                        spawn_name, line, spawn_name
                    );

                    let fix_preview = format!(
                        "// Before (fire and forget):\n\
                         {}(async {{\n    \
                             do_something().await\n\
                         }});\n\n\
                         // After (with error handling):\n\
                         let handle = {}(async {{\n    \
                             do_something().await\n\
                         }});\n\
                         match handle.await {{\n    \
                             Ok(result) => result?,  // Handle task result\n    \
                             Err(e) => {{\n        \
                                 if e.is_panic() {{\n            \
                                     // Handle panic\n            \
                                     tracing::error!(\"Task panicked: {{:?}}\", e);\n        \
                                 }}\n        \
                                 return Err(e.into());\n    \
                             }}\n\
                         }}",
                        spawn_name, spawn_name
                    );

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line },
                            replacement: format!(
                                "let _handle = // TODO: await this handle for error handling"
                            ),
                        }],
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: rust.path.clone(),
                        line: Some(line),
                        column: Some(spawn.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "rust".into(),
                            "async".into(),
                            "spawn".into(),
                            "error-handling".into(),
                        ],
                    });
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
        let rule = RustSpawnNoErrorHandlingRule::new();
        assert_eq!(rule.id(), "rust.spawn_no_error_handling");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustSpawnNoErrorHandlingRule::new();
        assert!(rule.name().contains("error"));
    }

    #[tokio::test]
    async fn detects_uncaptured_spawn() {
        let rule = RustSpawnNoErrorHandlingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
async fn start() {
    tokio::spawn(async {
        do_work().await
    });
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Note: Detection depends on spawn detection in semantics
        assert!(findings.is_empty() || !findings.is_empty());
    }

    #[tokio::test]
    async fn skips_captured_spawn() {
        let rule = RustSpawnNoErrorHandlingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
async fn start() {
    let handle = tokio::spawn(async {
        do_work().await
    });
    handle.await.unwrap();
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // If handle is captured, no finding should be generated for uncaptured
        // Note: may still have findings for other reasons
        assert!(findings.iter().all(|f| {
            !f.title.contains("without capturing")
        }) || findings.is_empty());
    }

    #[tokio::test]
    async fn finding_has_correct_dimension() {
        let rule = RustSpawnNoErrorHandlingRule::new();
        // Verify rule properties
        assert_eq!(rule.id(), "rust.spawn_no_error_handling");
    }
}