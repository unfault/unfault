//! Rule: Go Missing Correlation ID
//!
//! Detects HTTP handlers without X-Request-ID/correlation ID handling.

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

/// Rule that detects missing correlation ID handling in Go HTTP handlers.
#[derive(Debug, Default)]
pub struct GoMissingCorrelationIdRule;

impl GoMissingCorrelationIdRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoMissingCorrelationIdRule {
    fn id(&self) -> &'static str {
        "go.missing_correlation_id"
    }

    fn name(&self) -> &'static str {
        "Go Missing Correlation ID"
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
            let go_sem = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Check if there are HTTP handlers
            let has_http_handler = go_sem.functions.iter().any(|f| {
                f.params.iter().any(|p| 
                    p.param_type.contains("http.ResponseWriter") || p.param_type.contains("*http.Request")
                )
            }) || go_sem.imports.iter().any(|i| i.path.contains("net/http"));

            if !has_http_handler {
                continue;
            }

            // Check for correlation ID patterns
            let has_correlation_id = go_sem.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("X-Request-ID")
                    || c.function_call.callee_expr.contains("X-Correlation-ID")
                    || c.args_repr.contains("X-Request-ID")
                    || c.args_repr.contains("X-Correlation-ID")
                    || c.args_repr.contains("request_id")
                    || c.args_repr.contains("correlation_id")
            });

            if has_correlation_id {
                continue;
            }

            let title = "HTTP handlers without correlation ID tracking".to_string();

            let description = "This file contains HTTP handlers but does not appear to track \
                correlation IDs (X-Request-ID/X-Correlation-ID). Correlation IDs are essential \
                for tracing requests across services, debugging distributed systems, and \
                correlating logs from different services handling the same request.".to_string();

            let patch = generate_correlation_id_patch(*file_id);

            findings.push(RuleFinding {
                rule_id: self.id().to_string(),
                title,
                description: Some(description),
                kind: FindingKind::AntiPattern,
                severity: Severity::Medium,
                confidence: 0.75,
                dimension: Dimension::Observability,
                file_id: *file_id,
                file_path: go_sem.path.clone(),
                line: Some(1),
                column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                patch: Some(patch),
                fix_preview: Some("// Add correlation ID middleware".to_string()),
                tags: vec![
                    "go".into(),
                    "correlation-id".into(),
                    "observability".into(),
                    "tracing".into(),
                ],
            });
        }

        findings
    }
}

fn generate_correlation_id_patch(file_id: FileId) -> FilePatch {
    let replacement = r#"// Add correlation ID middleware:
// func correlationIDMiddleware(next http.Handler) http.Handler {
//     return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//         requestID := r.Header.Get("X-Request-ID")
//         if requestID == "" {
//             requestID = uuid.New().String()
//         }
//         ctx := context.WithValue(r.Context(), "request_id", requestID)
//         w.Header().Set("X-Request-ID", requestID)
//         next.ServeHTTP(w, r.WithContext(ctx))
//     })
// }
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
        let rule = GoMissingCorrelationIdRule::new();
        assert_eq!(rule.id(), "go.missing_correlation_id");
    }
}
