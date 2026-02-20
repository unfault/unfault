//! Rule: Go Missing Tracing
//!
//! Detects HTTP handlers without OpenTelemetry tracing.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::tracing;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects missing OpenTelemetry tracing in Go HTTP handlers.
#[derive(Debug, Default)]
pub struct GoMissingTracingRule;

impl GoMissingTracingRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoMissingTracingRule {
    fn id(&self) -> &'static str {
        "go.missing_tracing"
    }

    fn name(&self) -> &'static str {
        "Go Missing Tracing"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(tracing())
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

            // Check for OpenTelemetry imports
            let has_otel = go_sem.imports.iter().any(|imp| {
                imp.path.contains("go.opentelemetry.io/otel")
                    || imp.path.contains("github.com/opentracing/opentracing-go")
            });

            if has_otel {
                continue;
            }

            // Check if there are HTTP handlers (functions with http.ResponseWriter)
            let has_http_handler = go_sem.functions.iter().any(|f| {
                f.params.iter().any(|p| {
                    p.param_type.contains("http.ResponseWriter")
                        || p.param_type.contains("*http.Request")
                })
            });

            if has_http_handler {
                let title = "HTTP handlers without OpenTelemetry tracing".to_string();

                let description =
                    "This file contains HTTP handlers but does not use OpenTelemetry \
                    for distributed tracing. Tracing is essential for observability in \
                    production systems, enabling you to trace requests across services, \
                    identify bottlenecks, and debug issues in distributed architectures."
                        .to_string();

                let patch = generate_tracing_patch(*file_id);

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::AntiPattern,
                    severity: Severity::Medium,
                    confidence: 0.80,
                    dimension: Dimension::Observability,
                    file_id: *file_id,
                    file_path: go_sem.path.clone(),
                    line: Some(1),
                    column: Some(1),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("// Add OpenTelemetry tracing".to_string()),
                    tags: vec![
                        "go".into(),
                        "tracing".into(),
                        "observability".into(),
                        "opentelemetry".into(),
                    ],
                });
            }
        }

        findings
    }
}

fn generate_tracing_patch(file_id: FileId) -> FilePatch {
    let replacement = r#"// Add OpenTelemetry tracing:
// import "go.opentelemetry.io/otel"
// import "go.opentelemetry.io/otel/trace"
//
// func handler(w http.ResponseWriter, r *http.Request) {
//     ctx, span := otel.Tracer("service-name").Start(r.Context(), "handler-name")
//     defer span.End()
//     // ... handler logic using ctx
// }
"#
    .to_string();

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
        let rule = GoMissingTracingRule::new();
        assert_eq!(rule.id(), "go.missing_tracing");
    }
}
