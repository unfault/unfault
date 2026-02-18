//! Rule: Echo Request Validation
//!
//! Detects Echo handlers that use request binding without validation.

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

/// Rule that detects Echo handlers without input validation.
#[derive(Debug, Default)]
pub struct EchoRequestValidationRule;

impl EchoRequestValidationRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for EchoRequestValidationRule {
    fn id(&self) -> &'static str {
        "go.echo.request_validation"
    }

    fn name(&self) -> &'static str {
        "Echo Request Validation Missing"
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

            // Check for validator import
            let has_validator = go_sem.imports.iter().any(|imp| {
                imp.path.contains("validator")
                    || imp.path.contains("go-playground/validator")
            });

            // Look for Bind calls without subsequent Validate
            for call in &go_sem.calls {
                if call.function_call.callee_expr.contains(".Bind") || call.function_call.callee_expr.ends_with("Bind") {
                    let bind_line = call.function_call.location.line;

                    // Check if there's a Validate call nearby (within 10 lines)
                    let has_validation = go_sem.calls.iter().any(|c| {
                        let validate_line = c.function_call.location.line;
                        (c.function_call.callee_expr.contains("Validate") || c.function_call.callee_expr.contains(".Struct"))
                            && validate_line > bind_line
                            && validate_line <= bind_line + 10
                    });

                    if !has_validation {
                        let line = call.function_call.location.line;

                        let title = format!(
                            "Echo Bind() at line {} lacks validation",
                            line
                        );

                        let description = format!(
                            "Echo Bind() at line {} lacks validation. Use go-playground/validator \
                             to validate input before processing. Unvalidated input can lead to \
                             security vulnerabilities and unexpected behavior.",
                            line
                        );

                        let patch = generate_validation_patch(*file_id, line, has_validator);

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.85,
                            dimension: Dimension::Security,
                            file_id: *file_id,
                            file_path: go_sem.path.clone(),
                            line: Some(line),
                            column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some("// Add validation after binding".to_string()),
                            tags: vec![
                                "go".into(),
                                "echo".into(),
                                "validation".into(),
                                "security".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(error_handling_in_handler())
    }
}

fn generate_validation_patch(file_id: FileId, line: u32, has_validator: bool) -> FilePatch {
    let replacement = if has_validator {
        r#"    // Add validation after binding:
    // if err := validate.Struct(req); err != nil {
    //     return echo.NewHTTPError(http.StatusBadRequest, err.Error())
    // }
"#.to_string()
    } else {
        r#"    // Add go-playground/validator:
    // import "github.com/go-playground/validator/v10"
    // var validate = validator.New()
    //
    // if err := validate.Struct(req); err != nil {
    //     return echo.NewHTTPError(http.StatusBadRequest, err.Error())
    // }
"#.to_string()
    };

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertAfterLine { line },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_has_correct_metadata() {
        let rule = EchoRequestValidationRule::new();
        assert_eq!(rule.id(), "go.echo.request_validation");
    }
}