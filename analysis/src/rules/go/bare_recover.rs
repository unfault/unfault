//! Rule: Bare recover in Go
//!
//! Detects recover() calls without proper handling.

use async_trait::async_trait;
use std::sync::Arc;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects improper recover() usage.
#[derive(Debug, Default)]
pub struct GoBareRecoverRule;

impl GoBareRecoverRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoBareRecoverRule {
    fn id(&self) -> &'static str {
        "go.bare_recover"
    }

    fn name(&self) -> &'static str {
        "Bare recover without logging"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(error_handling_in_handler())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Check defers for recover() calls
            for defer_stmt in &go.defers {
                if defer_stmt.call_text.contains("recover()") {
                    // Check if there's logging/handling after recover
                    let has_proper_handling = defer_stmt.call_text.contains("log.")
                        || defer_stmt.call_text.contains("slog.")
                        || defer_stmt.call_text.contains("zap.")
                        || defer_stmt.call_text.contains("logrus.")
                        || defer_stmt.call_text.contains("fmt.Print")
                        || defer_stmt.call_text.contains("Error(")
                        || defer_stmt.call_text.contains("debug.Stack()")
                        || defer_stmt.call_text.contains("runtime.Stack");

                    // Check for empty recover handling
                    let is_bare_recover = !has_proper_handling
                        && (
                            defer_stmt.call_text.contains("recover()")
                                && defer_stmt.call_text.len() < 50
                            // Short block likely just recover()
                        );

                    if is_bare_recover {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Bare recover() without error handling".to_string(),
                            description: Some(
                                "recover() without logging or handling silently swallows panics, \
                                 making debugging extremely difficult. Always log the recovered \
                                 panic value and stack trace."
                                    .to_string(),
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.85,
                            dimension: Dimension::Observability,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(defer_stmt.line),
                            column: Some(defer_stmt.column),
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine {
                                        line: defer_stmt.line,
                                    },
                                    replacement: "defer func() {
    if r := recover(); r != nil {
        // Log the panic and stack trace
        log.Printf(\"panic recovered: %v\\n%s\", r, debug.Stack())
        // Optionally re-panic or return error
        // panic(r) 
    }
}()"
                                    .to_string(),
                                }],
                            }),
                            fix_preview: Some("Add panic logging with stack trace".to_string()),
                            tags: vec!["go".into(), "error-handling".into(), "panic".into()],
                        });
                    }

                    // Check for recover that doesn't check return value
                    if defer_stmt.call_text.contains("recover()")
                        && !defer_stmt.call_text.contains("if ")
                        && !defer_stmt.call_text.contains(":=")
                    {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "recover() return value not checked".to_string(),
                            description: Some(
                                "recover() returns nil if no panic occurred. Check the return \
                                 value to determine if a panic actually happened before \
                                 handling it."
                                    .to_string(),
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Medium,
                            confidence: 0.80,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(defer_stmt.line),
                            column: Some(defer_stmt.column),
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine {
                                        line: defer_stmt.line,
                                    },
                                    replacement: "// Check recover() return value:
// if r := recover(); r != nil {
//     // Handle panic
// }"
                                        .to_string(),
                                }],
                            }),
                            fix_preview: Some("Check recover() return value".to_string()),
                            tags: vec!["go".into(), "error-handling".into(), "panic".into()],
                        });
                    }
                }
            }

            // Check functions for missing panic recovery in handlers
            // Note: GoFunction doesn't have is_http_handler, so we detect by signature
            for func in &go.functions {
                // Check if this looks like an HTTP handler by checking params
                let is_handler = func.params.iter().any(|p| {
                    p.param_type.contains("http.ResponseWriter")
                        || p.param_type.contains("*gin.Context")
                        || p.param_type.contains("echo.Context")
                        || p.param_type.contains("*fiber.Ctx")
                });

                if is_handler || func.name.contains("Handler") {
                    // HTTP handlers should have panic recovery
                    let has_recover = go.defers.iter().any(|d| {
                        d.function_name.as_deref() == Some(&func.name)
                            && d.call_text.contains("recover()")
                    });

                    if !has_recover {
                        let line = func.location.range.start_line + 1; // Convert 0-based to 1-based
                        let column = func.location.range.start_col + 1;

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: format!("HTTP handler '{}' without panic recovery", func.name),
                            description: Some(
                                "HTTP handlers should recover from panics to prevent the \
                                 entire server from crashing. Add a deferred recover() \
                                 that logs the panic and returns a 500 error."
                                    .to_string(),
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Medium,
                            confidence: 0.70,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: Some(column),
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertAfterLine { line },
                                    replacement: "\tdefer func() {
\t\tif r := recover(); r != nil {
\t\t\tlog.Printf(\"panic in handler: %v\\n%s\", r, debug.Stack())
\t\t\thttp.Error(w, \"Internal Server Error\", http.StatusInternalServerError)
\t\t}
\t}()"
                                        .to_string(),
                                }],
                            }),
                            fix_preview: Some("Add panic recovery to handler".to_string()),
                            tags: vec!["go".into(), "http".into(), "panic".into()],
                        });
                        break; // One finding per file for this pattern
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

    #[test]
    fn test_rule_metadata() {
        let rule = GoBareRecoverRule::new();
        assert_eq!(rule.id(), "go.bare_recover");
        assert!(!rule.name().is_empty());
    }
}
