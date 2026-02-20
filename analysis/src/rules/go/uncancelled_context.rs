//! Rule: Uncancelled context in Go
//!
//! Detects context.WithCancel/WithTimeout where cancel function is not called.

use async_trait::async_trait;
use std::sync::Arc;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::timeout;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects uncancelled contexts.
#[derive(Debug, Default)]
pub struct GoUncancelledContextRule;

impl GoUncancelledContextRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoUncancelledContextRule {
    fn id(&self) -> &'static str {
        "go.uncancelled_context"
    }

    fn name(&self) -> &'static str {
        "Uncancelled context"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(timeout())
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

            // Check for context usages
            for ctx_usage in &go.context_usages {
                // Flag context.TODO() in handlers
                if ctx_usage.context_type == "TODO" && ctx_usage.in_handler {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "context.TODO() used in handler".to_string(),
                        description: Some(
                            "context.TODO() should not be used in production handlers. \
                             Use r.Context() for HTTP handlers or pass context from caller.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.90,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(ctx_usage.line),
                        column: Some(ctx_usage.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line: ctx_usage.line },
                                replacement: "// Use r.Context() for HTTP handlers or c.Request.Context() for Gin".to_string(),
                            }],
                        }),
                        fix_preview: Some("Replace with request context".to_string()),
                        tags: vec!["go".into(), "context".into()],
                    });
                }

                // Flag context.Background() in handlers (should use request context)
                if ctx_usage.context_type == "Background" && ctx_usage.in_handler {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "context.Background() in request handler".to_string(),
                        description: Some(
                            "Using context.Background() in a request handler loses request \
                             scoping and cancellation. Use r.Context() or propagate from caller."
                                .to_string(),
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(ctx_usage.line),
                        column: Some(ctx_usage.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine {
                                    line: ctx_usage.line,
                                },
                                replacement: "// Use request context: ctx := r.Context()"
                                    .to_string(),
                            }],
                        }),
                        fix_preview: Some("Use request context".to_string()),
                        tags: vec!["go".into(), "context".into()],
                    });
                }
            }

            // Check for defers that should have cancel calls
            let has_with_cancel = go.context_usages.iter().any(|c| {
                c.context_type == "WithCancel"
                    || c.context_type == "WithTimeout"
                    || c.context_type == "WithDeadline"
            });

            if has_with_cancel {
                let has_defer_cancel = go.defers.iter().any(|d| d.call_text.contains("cancel"));

                if !has_defer_cancel {
                    // Find the first WithCancel/WithTimeout
                    if let Some(ctx_usage) = go.context_usages.iter().find(|c| {
                        c.context_type == "WithCancel"
                            || c.context_type == "WithTimeout"
                            || c.context_type == "WithDeadline"
                    }) {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: format!(
                                "context.{}() without defer cancel()",
                                ctx_usage.context_type
                            ),
                            description: Some(
                                "Context created with WithCancel/WithTimeout/WithDeadline must \
                                 have its cancel function called. Use defer cancel() immediately \
                                 after creating the context to prevent resource leaks."
                                    .to_string(),
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.90,
                            dimension: Dimension::Reliability,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(ctx_usage.line),
                            column: Some(ctx_usage.column),
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertAfterLine {
                                        line: ctx_usage.line,
                                    },
                                    replacement: "defer cancel()".to_string(),
                                }],
                            }),
                            fix_preview: Some("Add defer cancel()".to_string()),
                            tags: vec!["go".into(), "context".into(), "resource-leak".into()],
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

    #[test]
    fn test_rule_metadata() {
        let rule = GoUncancelledContextRule::new();
        assert_eq!(rule.id(), "go.uncancelled_context");
        assert!(!rule.name().is_empty());
    }
}
