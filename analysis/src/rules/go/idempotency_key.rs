//! Rule: Idempotency key in Go
//!
//! Detects POST/PUT/DELETE endpoints without idempotency key handling.

use async_trait::async_trait;
use std::sync::Arc;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::idempotency_key;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects missing idempotency key handling.
#[derive(Debug, Default)]
pub struct GoIdempotencyKeyRule;

impl GoIdempotencyKeyRule {
    pub fn new() -> Self {
        Self
    }

    /// Check if a function looks like an HTTP handler based on its parameters
    fn is_http_handler(func: &crate::semantics::go::model::GoFunction) -> bool {
        func.params.iter().any(|p| {
            p.param_type.contains("http.ResponseWriter")
                || p.param_type.contains("*gin.Context")
                || p.param_type.contains("echo.Context")
                || p.param_type.contains("*fiber.Ctx")
        })
    }

    /// Check if function name suggests a mutating operation
    fn is_mutating_function(name: &str) -> bool {
        let lower = name.to_lowercase();
        // Check for read-only prefixes that should NOT be considered mutating
        let is_read_only = lower.starts_with("get")
            || lower.starts_with("list")
            || lower.starts_with("fetch")
            || lower.starts_with("find")
            || lower.starts_with("search")
            || lower.starts_with("query")
            || lower.starts_with("read");

        if is_read_only {
            return false;
        }

        lower.contains("create")
            || lower.contains("post")
            || lower.contains("update")
            || lower.contains("put")
            || lower.contains("delete")
            || lower.contains("payment")
            || lower.contains("order")
            || lower.contains("transfer")
            || lower.contains("submit")
    }
}

#[async_trait]
impl Rule for GoIdempotencyKeyRule {
    fn id(&self) -> &'static str {
        "go.idempotency_key"
    }

    fn name(&self) -> &'static str {
        "Missing idempotency key handling"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(idempotency_key())
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

            // Check for idempotency handling patterns in calls
            let has_idempotency = go.calls.iter().any(|c| {
                let callee = c.function_call.callee_expr.to_lowercase();
                callee.contains("idempotency") || callee.contains("idempotent")
            });

            if has_idempotency {
                continue; // File already has idempotency handling
            }

            // Check for mutating calls that suggest state modification
            let has_mutating_calls = go.calls.iter().any(|c| {
                let callee = &c.function_call.callee_expr;
                callee.ends_with(".Create")
                    || callee.ends_with(".Insert")
                    || callee.ends_with(".Update")
                    || callee.ends_with(".Delete")
                    || callee.ends_with(".Exec")
                    || callee.starts_with("http.Post")
                    || callee.contains("SendMessage")
            });

            for func in &go.functions {
                if !Self::is_http_handler(func) {
                    continue;
                }

                let is_mutating = Self::is_mutating_function(&func.name);

                if is_mutating && has_mutating_calls {
                    let line = func.location.range.start_line + 1;
                    let column = func.location.range.start_col + 1;

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: format!("Mutating endpoint '{}' without idempotency key", func.name),
                        description: Some(
                            "Mutating operations should support idempotency keys to safely \
                             handle retries. Accept an 'X-Idempotency-Key' header and track \
                             processed keys to prevent duplicate operations."
                                .to_string(),
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.70,
                        dimension: Dimension::Reliability,
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
                                replacement: "\t// Extract idempotency key from request
\tidempotencyKey := r.Header.Get(\"X-Idempotency-Key\")
\tif idempotencyKey == \"\" {
\t\thttp.Error(w, \"X-Idempotency-Key header required\", http.StatusBadRequest)
\t\treturn
\t}
\t
\t// Check if operation was already processed
\tif result, exists := idempotencyStore.Get(idempotencyKey); exists {
\t\t// Return cached result
\t\tjson.NewEncoder(w).Encode(result)
\t\treturn
\t}
\t
\t// After successful operation:
\t// idempotencyStore.Set(idempotencyKey, result, 24*time.Hour)"
                                    .to_string(),
                            }],
                        }),
                        fix_preview: Some("Add idempotency key handling".to_string()),
                        tags: vec!["go".into(), "idempotency".into(), "reliability".into()],
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
    use crate::parse::ast::{AstLocation, TextRange};
    use crate::semantics::go::model::GoFunction;

    #[test]
    fn test_rule_metadata() {
        let rule = GoIdempotencyKeyRule::new();
        assert_eq!(rule.id(), "go.idempotency_key");
        assert!(!rule.name().is_empty());
    }

    #[test]
    fn test_is_http_handler() {
        let func = GoFunction {
            name: "CreateUser".to_string(),
            params: vec![
                crate::semantics::go::model::GoParam {
                    name: "w".to_string(),
                    param_type: "http.ResponseWriter".to_string(),
                },
                crate::semantics::go::model::GoParam {
                    name: "r".to_string(),
                    param_type: "*http.Request".to_string(),
                },
            ],
            return_types: vec![],
            returns_error: false,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 0,
                },
            },
        };
        assert!(GoIdempotencyKeyRule::is_http_handler(&func));
    }

    #[test]
    fn test_is_mutating_function() {
        assert!(GoIdempotencyKeyRule::is_mutating_function("CreateUser"));
        assert!(GoIdempotencyKeyRule::is_mutating_function("updateProfile"));
        assert!(GoIdempotencyKeyRule::is_mutating_function("DeleteOrder"));
        assert!(GoIdempotencyKeyRule::is_mutating_function("SubmitPayment"));
        assert!(!GoIdempotencyKeyRule::is_mutating_function("GetUser"));
        assert!(!GoIdempotencyKeyRule::is_mutating_function("ListOrders"));
    }
}
