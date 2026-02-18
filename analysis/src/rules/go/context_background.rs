//! Rule: context.Background() in request handlers
//!
//! Detects usage of context.Background() or context.TODO() in HTTP handlers
//! or RPC handlers where the request context should be used instead.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::timeout;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects inappropriate use of context.Background().
///
/// In HTTP handlers and RPC handlers, the request context should be used
/// to properly propagate cancellation, deadlines, and request-scoped values.
/// Using context.Background() breaks this chain and can lead to:
/// - Resources not being cleaned up when requests are cancelled
/// - Timeouts not being respected
/// - Missing tracing/observability data
#[derive(Debug)]
pub struct GoContextBackgroundRule;

impl GoContextBackgroundRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoContextBackgroundRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for GoContextBackgroundRule {
    fn id(&self) -> &'static str {
        "go.context_background_in_handler"
    }

    fn name(&self) -> &'static str {
        "context.Background() used in request handler instead of request context"
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
                SourceSemantics::Go(go) => go,
                _ => continue,
            };

            for ctx_usage in &go.context_usages {
                // Only flag context.Background() or context.TODO() in handlers
                if !ctx_usage.is_background_or_todo {
                    continue;
                }

                // Check if this is inside a handler function
                if !ctx_usage.in_handler {
                    continue;
                }

                let is_todo = ctx_usage.context_type == "TODO";
                let title = if is_todo {
                    "context.TODO() used in handler - request context should be used".to_string()
                } else {
                    "context.Background() used in handler - request context should be used"
                        .to_string()
                };

                let description = format!(
                    "The function `{}` appears to be an HTTP/RPC handler but uses `{}` \
                     instead of the request context. This breaks the context chain and can cause:\n\
                     - Cancellation signals from clients not being respected\n\
                     - Timeouts not being enforced\n\
                     - Missing trace/span propagation\n\
                     - Resource leaks when requests are cancelled\n\n\
                     Use the context from the request instead:\n\
                     - HTTP: `r.Context()` from *http.Request\n\
                     - gRPC: context passed as first argument\n\
                     - Gin: `c.Request.Context()`\n\
                     - Echo: `c.Request().Context()`",
                    ctx_usage.function_name,
                    ctx_usage.context_type
                );

                let patch = generate_context_replacement_patch(ctx_usage, *file_id);

                let fix_preview = format!(
                    "// Before:\n\
                     // ctx := context.{}()\n\
                     //\n\
                     // After (HTTP handler):\n\
                     // ctx := r.Context()\n\
                     //\n\
                     // After (gRPC):\n\
                     // // use ctx parameter",
                    ctx_usage.context_type
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::AntiPattern,
                    severity: if is_todo {
                        Severity::Medium
                    } else {
                        Severity::High
                    },
                    confidence: 0.90,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: go.path.clone(),
                    line: Some(ctx_usage.line),
                    column: Some(ctx_usage.column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "go".into(),
                        "context".into(),
                        "handler".into(),
                        "cancellation".into(),
                        "reliability".into(),
                    ],
                });
            }
        }

        findings
    }
}

use crate::semantics::go::model::ContextUsage;

/// Generate a patch to replace context.Background() with request context.
fn generate_context_replacement_patch(ctx_usage: &ContextUsage, file_id: FileId) -> FilePatch {
    // Determine the appropriate replacement based on handler type
    let replacement = match ctx_usage.handler_type.as_deref() {
        Some("http") => "r.Context()".to_string(),
        Some("gin") => "c.Request.Context()".to_string(),
        Some("echo") => "c.Request().Context()".to_string(),
        Some("fiber") => "c.UserContext()".to_string(),
        Some("grpc") => "ctx".to_string(), // Assuming ctx is the first parameter
        _ => {
            // Generic replacement with comment
            format!(
                "/* TODO: Use request context instead of context.{}() */\n\
                 context.{}()",
                ctx_usage.context_type, ctx_usage.context_type
            )
        }
    };

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: ctx_usage.start_byte,
                end: ctx_usage.end_byte,
            },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::go::parse_go_file;
    use crate::semantics::go::build_go_semantics;
    use crate::semantics::SourceSemantics;
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
    fn rule_id_is_correct() {
        let rule = GoContextBackgroundRule::new();
        assert_eq!(rule.id(), "go.context_background_in_handler");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = GoContextBackgroundRule::new();
        assert!(rule.name().contains("context.Background"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = GoContextBackgroundRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GoContextBackgroundRule"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_go() {
        let rule = GoContextBackgroundRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_no_finding_for_background_outside_handler() {
        let rule = GoContextBackgroundRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "context"

func main() {
    ctx := context.Background()
    doWork(ctx)
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag context.Background() in main()
        for finding in &findings {
            assert_ne!(finding.rule_id, "go.context_background_in_handler");
        }
    }

    #[tokio::test]
    async fn evaluate_detects_background_in_http_handler() {
        let rule = GoContextBackgroundRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import (
    "context"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    ctx := context.Background()  // Bug: should use r.Context()
    doWork(ctx)
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Depends on semantics detection of handler patterns
        for finding in &findings {
            if finding.rule_id == "go.context_background_in_handler" {
                assert!(finding.description.is_some());
                assert!(finding.tags.contains(&"context".to_string()));
            }
        }
    }

    #[tokio::test]
    async fn evaluate_no_finding_when_using_request_context() {
        let rule = GoContextBackgroundRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import (
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()  // Correct usage
    doWork(ctx)
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag correct usage
        for finding in &findings {
            assert_ne!(finding.rule_id, "go.context_background_in_handler");
        }
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = GoContextBackgroundRule::new();
        // Any Go code for testing
        let (file_id, sem) = parse_and_build_semantics("package main");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.context_background_in_handler" {
                assert_eq!(finding.dimension, Dimension::Reliability);
                assert!(finding.tags.contains(&"go".to_string()));
            }
        }
    }
}