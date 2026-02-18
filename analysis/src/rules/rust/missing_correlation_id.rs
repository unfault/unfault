//! Rule: Missing correlation ID in request handling.
//!
//! HTTP handlers should propagate or generate correlation IDs for tracing
//! requests across distributed systems.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{
    Benefit, DecisionLevel, FindingApplicability, FindingKind, InvestmentLevel, LifecycleStage,
    Severity,
};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects missing correlation ID handling.
#[derive(Debug, Default)]
pub struct RustMissingCorrelationIdRule;

impl RustMissingCorrelationIdRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustMissingCorrelationIdRule {
    fn id(&self) -> &'static str {
        "rust.missing_correlation_id"
    }

    fn name(&self) -> &'static str {
        "HTTP handlers without correlation ID propagation"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Medium,
            min_stage: LifecycleStage::Product,
            decision_level: DecisionLevel::ApiContract,
            benefits: vec![Benefit::Operability],
            prerequisites: vec![
                "Decide on header names and propagation rules across services".to_string(),
                "Ensure logs include the chosen correlation identifiers".to_string(),
            ],
            notes: Some(
                "Optional for demos; becomes valuable once multiple services or async workflows exist.".to_string(),
            ),
        })
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

            // Check if correlation ID handling exists
            let has_correlation_id = rust.uses.iter().any(|u| {
                u.path.contains("correlation")
                    || u.path.contains("request_id")
                    || u.path.contains("trace_id")
                    || u.path.contains("x-request-id")
            }) || rust.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("correlation_id")
                    || c.function_call.callee_expr.contains("request_id")
                    || c.function_call.callee_expr.contains("trace_id")
            });

            if has_correlation_id {
                continue;
            }

            // Check if this is an HTTP framework file
            let is_http_handler = rust.uses.iter().any(|u| {
                u.path.contains("axum") || u.path.contains("actix") || u.path.contains("warp")
            });

            if !is_http_handler {
                continue;
            }

            // Look for handler functions
            for func in &rust.functions {
                if !func.is_async {
                    continue;
                }

                if func.is_test {
                    continue;
                }

                // Check if function is likely a handler (has common handler patterns)
                let is_handler = func.name.contains("handler")
                    || func.name.contains("endpoint")
                    || func.name.contains("route")
                    || func.name.starts_with("get_")
                    || func.name.starts_with("post_")
                    || func.name.starts_with("put_")
                    || func.name.starts_with("delete_")
                    || func.name.starts_with("create_")
                    || func.name.starts_with("update_")
                    || func.name.starts_with("list_");

                if !is_handler {
                    continue;
                }

                let line = func.location.range.start_line + 1;

                let title = format!(
                    "Handler '{}' doesn't propagate correlation ID",
                    func.name
                );

                let description = format!(
                    "The HTTP handler '{}' at line {} doesn't extract or propagate a correlation ID.\n\n\
                     **Why this matters:**\n\
                     - Cannot trace requests across services\n\
                     - Difficult to debug distributed issues\n\
                     - Logs from different services cannot be correlated\n\
                     - Missing observability in production\n\n\
                     **Recommendations:**\n\
                     - Extract X-Request-ID header from incoming requests\n\
                     - Generate a new ID if not present (using uuid)\n\
                     - Propagate to downstream services\n\
                     - Include in all log entries\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use axum::{{extract::Request, middleware::Next, response::Response}};\n\
                     use uuid::Uuid;\n\
                     \n\
                     pub async fn correlation_id_middleware(\n    \
                         mut request: Request,\n    \
                         next: Next,\n\
                     ) -> Response {{\n    \
                         let correlation_id = request\n        \
                             .headers()\n        \
                             .get(\"x-request-id\")\n        \
                             .and_then(|v| v.to_str().ok())\n        \
                             .map(|s| s.to_string())\n        \
                             .unwrap_or_else(|| Uuid::new_v4().to_string());\n\
                         \n    \
                         request.extensions_mut().insert(correlation_id);\n    \
                         next.run(request).await\n\
                     }}\n\
                     ```",
                    func.name,
                    line
                );

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Extract and propagate correlation ID (X-Request-ID)".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::AntiPattern,
                    severity: Severity::Medium,
                    confidence: 0.65,
                    dimension: Dimension::Observability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("let correlation_id = req.headers().get(\"x-request-id\")...".to_string()),
                    tags: vec![
                        "rust".into(),
                        "correlation-id".into(),
                        "observability".into(),
                        "http".into(),
                    ],
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_id_is_correct() {
        let rule = RustMissingCorrelationIdRule::new();
        assert_eq!(rule.id(), "rust.missing_correlation_id");
    }

    #[test]
    fn rule_name_mentions_correlation() {
        let rule = RustMissingCorrelationIdRule::new();
        assert!(rule.name().contains("correlation"));
    }
}
