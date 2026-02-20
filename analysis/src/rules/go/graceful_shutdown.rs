//! Rule: Go Missing Graceful Shutdown
//!
//! Detects HTTP servers without graceful shutdown handling.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::graceful_shutdown;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects HTTP servers without graceful shutdown.
#[derive(Debug, Default)]
pub struct GoMissingGracefulShutdownRule;

impl GoMissingGracefulShutdownRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoMissingGracefulShutdownRule {
    fn id(&self) -> &'static str {
        "go.missing_graceful_shutdown"
    }

    fn name(&self) -> &'static str {
        "Go Missing Graceful Shutdown"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(graceful_shutdown())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go_sem = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Look for http.ListenAndServe without shutdown handling
            let has_listen_and_serve = go_sem.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("ListenAndServe")
                    || c.function_call.callee_expr.contains("http.ListenAndServe")
            });

            if !has_listen_and_serve {
                continue;
            }

            // Check for graceful shutdown patterns
            let has_shutdown = go_sem.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("Shutdown")
                    || c.function_call.callee_expr.contains("server.Shutdown")
            });

            let has_signal_handling = go_sem.imports.iter().any(|i| i.path.contains("os/signal"));

            if has_shutdown && has_signal_handling {
                continue;
            }

            // Find the ListenAndServe call
            for call in &go_sem.calls {
                if call.function_call.callee_expr.contains("ListenAndServe") {
                    let line = call.function_call.location.line;

                    let title = format!("HTTP server at line {} lacks graceful shutdown", line);

                    let description = format!(
                        "The HTTP server at line {} does not implement graceful shutdown. \
                         Without graceful shutdown, in-flight requests may be terminated \
                         abruptly during deployments or restarts, causing errors for users. \
                         Add signal handling and call server.Shutdown() for clean termination.",
                        line
                    );

                    let patch = generate_shutdown_patch(*file_id, line);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.80,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go_sem.path.clone(),
                        line: Some(line),
                        column: Some(1),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(
                            "// Add graceful shutdown with signal handling".to_string(),
                        ),
                        tags: vec![
                            "go".into(),
                            "graceful-shutdown".into(),
                            "reliability".into(),
                            "http".into(),
                        ],
                    });
                    break;
                }
            }
        }

        findings
    }
}

fn generate_shutdown_patch(file_id: FileId, line: u32) -> FilePatch {
    let replacement = r#"// Add graceful shutdown:
// srv := &http.Server{Addr: ":8080", Handler: handler}
// go func() {
//     if err := srv.ListenAndServe(); err != http.ErrServerClosed {
//         log.Fatal(err)
//     }
// }()
// quit := make(chan os.Signal, 1)
// signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
// <-quit
// ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
// defer cancel()
// srv.Shutdown(ctx)
"#
    .to_string();

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_has_correct_metadata() {
        let rule = GoMissingGracefulShutdownRule::new();
        assert_eq!(rule.id(), "go.missing_graceful_shutdown");
    }
}
