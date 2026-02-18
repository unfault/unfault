//! Rule: Echo Missing Middleware
//!
//! Detects Echo applications without essential security middleware.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects Echo applications without essential middleware.
#[derive(Debug, Default)]
pub struct EchoMissingMiddlewareRule;

impl EchoMissingMiddlewareRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for EchoMissingMiddlewareRule {
    fn id(&self) -> &'static str {
        "go.echo.missing_middleware"
    }

    fn name(&self) -> &'static str {
        "Echo Missing Security Middleware"
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

            // Check if Echo is imported
            let has_echo = go_sem.imports.iter().any(|imp| {
                imp.path.contains("github.com/labstack/echo")
            });

            if !has_echo {
                continue;
            }

            // Check for Echo server creation
            let has_echo_new = go_sem.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("echo.New")
            });

            if !has_echo_new {
                continue;
            }

            // Check for essential middleware
            let has_recover = go_sem.calls.iter().any(|c| {
                c.function_call.callee_expr.contains(".Use") && go_sem.calls.iter().any(|c2| {
                    c2.function_call.callee_expr.contains("middleware.Recover")
                })
            });

            let has_logger = go_sem.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("middleware.Logger")
            });

            let has_request_id = go_sem.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("middleware.RequestID")
            });

            let mut missing = Vec::new();
            if !has_recover {
                missing.push("Recover");
            }
            if !has_logger {
                missing.push("Logger");
            }
            if !has_request_id {
                missing.push("RequestID");
            }

            if !missing.is_empty() {
                let title = format!(
                    "Echo server missing middleware: {}",
                    missing.join(", ")
                );

                let description = format!(
                    "Echo server is missing essential middleware: {}. \
                     The Recover middleware prevents panics from crashing the server. \
                     Logger middleware provides request logging for observability. \
                     RequestID middleware adds correlation IDs for distributed tracing.",
                    missing.join(", ")
                );

                let patch = generate_middleware_patch(*file_id);

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::High,
                    confidence: 0.90,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: go_sem.path.clone(),
                    line: Some(1),
                    column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("// Add essential Echo middleware".to_string()),
                    tags: vec![
                        "go".into(),
                        "echo".into(),
                        "middleware".into(),
                        "security".into(),
                    ],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(error_handling_in_handler())
    }
}

fn generate_middleware_patch(file_id: FileId) -> FilePatch {
    let replacement = r#"// Add essential Echo middleware:
// e := echo.New()
// e.Use(middleware.Recover())
// e.Use(middleware.Logger())
// e.Use(middleware.RequestID())
"#.to_string();

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line: 1 },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_has_correct_metadata() {
        let rule = EchoMissingMiddlewareRule::new();
        assert_eq!(rule.id(), "go.echo.missing_middleware");
    }
}