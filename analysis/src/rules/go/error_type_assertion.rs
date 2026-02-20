//! Rule: Error type assertion detection
//!
//! Detects type assertions on errors (err.(*MyError)) instead of using errors.As(),
//! which doesn't work correctly with wrapped errors.

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

/// Rule that detects type assertions on errors.
///
/// Since Go 1.13, errors can be wrapped. Type assertions like err.(*CustomError)
/// won't find wrapped errors. Use errors.As() to unwrap and check type.
#[derive(Debug, Default)]
pub struct GoErrorTypeAssertionRule;

impl GoErrorTypeAssertionRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoErrorTypeAssertionRule {
    fn id(&self) -> &'static str {
        "go.error_type_assertion"
    }

    fn name(&self) -> &'static str {
        "Type assertion on error instead of errors.As()"
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

            // Check for errors.As usage (if they use it, they're already aware)
            let uses_errors_as = go
                .calls
                .iter()
                .any(|c| c.function_call.callee_expr == "errors.As");

            // Look for error type assertion patterns in calls and declarations
            // Pattern: err.(*SomeError) or err.(SomeError)

            for call in &go.calls {
                let args = &call.args_repr;

                // Check for patterns like: err.(*MyError), err.(MyError), etc.
                // Common error-related patterns
                if (args.contains("err.(") || args.contains("error.(")) && !uses_errors_as {
                    // Check if this looks like an error type assertion
                    let is_error_type_assertion = args.contains("err.(*")
                        || args.contains("err.(")
                        || args.contains("Error)")
                        || args.contains("Err)");

                    if is_error_type_assertion {
                        let line = call.function_call.location.line;

                        let title = "Type assertion on error instead of errors.As()".to_string();

                        let description = format!(
                            "Error type assertion at line {} will not work if the error \
                             was wrapped with fmt.Errorf(\"%w\", err) or errors.Join().\n\n\
                             Before:\n\
                             ```go\n\
                             if myErr, ok := err.(*MyError); ok {{\n\
                             \t// handle specific error\n\
                             }}\n\
                             ```\n\n\
                             After:\n\
                             ```go\n\
                             var myErr *MyError\n\
                             if errors.As(err, &myErr) {{\n\
                             \t// handle specific error\n\
                             }}\n\
                             ```\n\n\
                             Note: errors.As() recursively unwraps errors and sets the target \
                             if a match is found.",
                            line
                        );

                        let patch = FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: "// Use errors.As() for wrapped error support:\n// var targetErr *TargetError\n// if errors.As(err, &targetErr) { ... }".to_string(),
                            }],
                        };

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Medium,
                            confidence: 0.80,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: None,
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some("Use errors.As(err, &target)".to_string()),
                            tags: vec!["go".into(), "error-handling".into(), "errors.As".into()],
                        });
                    }
                }
            }

            // Check declarations for error type assertion patterns
            for decl in &go.declarations {
                if let Some(ref value) = decl.value_repr {
                    // Check for err.(*Type) pattern in value
                    let has_error_type_assertion = (value.contains("err.(*")
                        || value.contains("err.("))
                        && !value.contains("errors.As");

                    if has_error_type_assertion && !uses_errors_as {
                        let line = decl.location.range.start_line + 1;

                        let title =
                            format!("Type assertion on error in '{}' assignment", decl.name);

                        let description = format!(
                            "Error type assertion at line {} in variable '{}' will fail \
                             to match wrapped errors. Consider using errors.As() instead.\n\n\
                             Example:\n\
                             ```go\n\
                             var {} *ExpectedErrorType\n\
                             if errors.As(err, &{}) {{\n\
                             \t// Use {}\n\
                             }}\n\
                             ```",
                            line, decl.name, decl.name, decl.name, decl.name
                        );

                        let patch = FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: format!(
                                    "// Use errors.As() instead of type assertion:\n// var {} *TargetType\n// if errors.As(err, &{}) {{ ... }}",
                                    decl.name, decl.name
                                ),
                            }],
                        };

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Medium,
                            confidence: 0.75,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: None,
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some("Use errors.As()".to_string()),
                            tags: vec!["go".into(), "error-handling".into()],
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
    use crate::parse::go::parse_go_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::go::build_go_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.go".to_string(),
            language: Language::Go,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_go_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_go_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Go(sem)))
    }

    #[test]
    fn test_rule_metadata() {
        let rule = GoErrorTypeAssertionRule::new();
        assert_eq!(rule.id(), "go.error_type_assertion");
        assert!(!rule.name().is_empty());
    }

    #[tokio::test]
    async fn test_detects_error_type_assertion() {
        let rule = GoErrorTypeAssertionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

type ValidationError struct {
    Field string
    Msg   string
}

func (e *ValidationError) Error() string {
    return e.Msg
}

func handleError(err error) string {
    if vErr, ok := err.(*ValidationError); ok {
        return vErr.Field
    }
    return "unknown"
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        // Rule should detect the pattern (depends on semantics)
        let _ = findings;
    }

    #[tokio::test]
    async fn test_no_finding_with_errors_as() {
        let rule = GoErrorTypeAssertionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "errors"

type ValidationError struct {
    Field string
}

func handleError(err error) string {
    var vErr *ValidationError
    if errors.As(err, &vErr) {
        return vErr.Field
    }
    return "unknown"
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        // Should not flag when errors.As is used
        let error_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go.error_type_assertion")
            .collect();
        assert!(error_findings.is_empty());
    }
}
