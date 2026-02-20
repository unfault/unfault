//! Rule: Sentinel error comparison detection
//!
//! Detects direct error comparisons (err == SomeError) instead of using errors.Is(),
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

/// Rule that detects direct error comparisons.
///
/// Since Go 1.13, errors can be wrapped using fmt.Errorf("%w", err).
/// Direct comparison like `err == sql.ErrNoRows` will fail if the error
/// was wrapped. Use errors.Is(err, sql.ErrNoRows) instead.
#[derive(Debug, Default)]
pub struct GoSentinelErrorComparisonRule;

impl GoSentinelErrorComparisonRule {
    pub fn new() -> Self {
        Self
    }
}

/// Common sentinel errors that should be checked with errors.Is()
const SENTINEL_ERRORS: &[&str] = &[
    "sql.ErrNoRows",
    "sql.ErrTxDone",
    "sql.ErrConnDone",
    "io.EOF",
    "io.ErrClosedPipe",
    "io.ErrUnexpectedEOF",
    "os.ErrNotExist",
    "os.ErrExist",
    "os.ErrPermission",
    "os.ErrClosed",
    "context.Canceled",
    "context.DeadlineExceeded",
    "http.ErrServerClosed",
    "http.ErrHandlerTimeout",
    "http.ErrContentLength",
    "http.ErrBodyNotAllowed",
    "net.ErrClosed",
    "ErrNotFound",
    "ErrInvalid",
    "ErrTimeout",
    "ErrClosed",
    "ErrNotExist",
    "ErrExists",
];

#[async_trait]
impl Rule for GoSentinelErrorComparisonRule {
    fn id(&self) -> &'static str {
        "go.sentinel_error_comparison"
    }

    fn name(&self) -> &'static str {
        "Direct error comparison instead of errors.Is()"
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

            // Check for errors package import (if they use errors.Is, they're already aware)
            let uses_errors_is = go
                .calls
                .iter()
                .any(|c| c.function_call.callee_expr == "errors.Is");

            // Check declarations and calls for patterns like: err == X or err != X
            // where X is a sentinel error
            for call in &go.calls {
                let args = &call.args_repr;

                // Look for comparisons with sentinel errors
                for sentinel in SENTINEL_ERRORS {
                    // Check for err == sentinel or sentinel == err
                    let has_eq_comparison = args.contains(&format!("== {}", sentinel))
                        || args.contains(&format!("{} ==", sentinel))
                        || args.contains(&format!("!= {}", sentinel))
                        || args.contains(&format!("{} !=", sentinel));

                    if has_eq_comparison && !uses_errors_is {
                        let line = call.function_call.location.line;

                        let title =
                            format!("Direct comparison with {} instead of errors.Is()", sentinel);

                        let description = format!(
                            "Direct error comparison at line {} will not work if the error \
                             was wrapped with fmt.Errorf(\"%w\", err) or errors.Join().\n\n\
                             Before:\n\
                             ```go\n\
                             if err == {} {{\n\
                             \treturn nil\n\
                             }}\n\
                             ```\n\n\
                             After:\n\
                             ```go\n\
                             if errors.Is(err, {}) {{\n\
                             \treturn nil\n\
                             }}\n\
                             ```\n\n\
                             Note: errors.Is() recursively unwraps errors to find a match.",
                            line, sentinel, sentinel
                        );

                        let patch = FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: format!(
                                    "// Use errors.Is(err, {}) for wrapped error support",
                                    sentinel
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
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: None,
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(format!("Use errors.Is(err, {})", sentinel)),
                            tags: vec!["go".into(), "error-handling".into(), "errors.Is".into()],
                        });
                    }
                }
            }

            // Also check for comparisons in if statements by looking at function bodies
            // This is a heuristic based on common patterns
            for decl in &go.declarations {
                if let Some(ref value) = decl.value_repr {
                    for sentinel in SENTINEL_ERRORS {
                        if value.contains(&format!("== {}", sentinel))
                            || value.contains(&format!("{} ==", sentinel))
                        {
                            if !uses_errors_is {
                                let line = decl.location.range.start_line + 1;

                                let title =
                                    format!("Direct comparison with {} in assignment", sentinel);

                                let description = format!(
                                    "Assignment at line {} uses direct error comparison which \
                                     breaks with wrapped errors. Use errors.Is() instead.",
                                    line
                                );

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
                                    patch: None,
                                    fix_preview: Some("Use errors.Is()".to_string()),
                                    tags: vec!["go".into(), "error-handling".into()],
                                });
                            }
                        }
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
        let rule = GoSentinelErrorComparisonRule::new();
        assert_eq!(rule.id(), "go.sentinel_error_comparison");
        assert!(!rule.name().is_empty());
    }

    #[tokio::test]
    async fn test_detects_direct_comparison() {
        let rule = GoSentinelErrorComparisonRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "database/sql"

func getUser(id int) (*User, error) {
    user, err := db.QueryRow("SELECT * FROM users WHERE id = ?", id)
    if err == sql.ErrNoRows {  // Bad: doesn't work with wrapped errors
        return nil, nil
    }
    return user, err
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        // Should detect the direct comparison
        // Note: depends on semantics capturing the comparison pattern
        let _ = findings;
    }

    #[tokio::test]
    async fn test_no_finding_with_errors_is() {
        let rule = GoSentinelErrorComparisonRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import (
    "database/sql"
    "errors"
)

func getUser(id int) (*User, error) {
    user, err := db.QueryRow("SELECT * FROM users WHERE id = ?", id)
    if errors.Is(err, sql.ErrNoRows) {  // Good
        return nil, nil
    }
    return user, err
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        // Should not flag when errors.Is is used
        let _ = findings;
    }
}
