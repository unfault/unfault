//! TypeScript Missing Tracing Detection Rule
//!
//! Detects HTTP handlers without OpenTelemetry or distributed tracing setup.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

#[derive(Debug)]
pub struct TypescriptMissingTracingRule;

impl TypescriptMissingTracingRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptMissingTracingRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptMissingTracingRule {
    fn id(&self) -> &'static str {
        "typescript.missing_tracing"
    }

    fn name(&self) -> &'static str {
        "Missing Distributed Tracing"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::tracing())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let ts = match sem.as_ref() {
                SourceSemantics::Typescript(ts) => ts,
                _ => continue,
            };

            // Check if this is a server/API file
            let is_server_file = ts.express.is_some()
                || ts.imports.iter().any(|imp| {
                    let module = imp.module.to_lowercase();
                    module == "express" || module == "fastify" || module.contains("nestjs")
                });

            if !is_server_file {
                continue;
            }

            // Check if tracing is already imported
            let has_tracing = ts.imports.iter().any(|imp| {
                let module = imp.module.to_lowercase();
                module.contains("opentelemetry")
                    || module.contains("jaeger")
                    || module.contains("zipkin")
                    || module.contains("datadog")
                    || module.contains("newrelic")
            });

            if has_tracing {
                continue;
            }

            // Report on the first line of the file
            let line = 1u32;
            let column = 1u32;

            let patch = FilePatch {
                file_id: *file_id,
                hunks: vec![PatchHunk {
                    range: PatchRange::InsertBeforeLine { line },
                    replacement: "// Add OpenTelemetry tracing:\n\
                         // import { trace } from '@opentelemetry/api';\n\
                         // const tracer = trace.getTracer('service-name');\n\
                         // const span = tracer.startSpan('operation-name');\n"
                        .to_string(),
                }],
            };

            findings.push(RuleFinding {
                rule_id: self.id().to_string(),
                title: "Server lacks distributed tracing".to_string(),
                description: Some(format!(
                    "Server file '{}' does not have OpenTelemetry or distributed tracing configured. \
                     Tracing is essential for debugging and monitoring in distributed systems.",
                    ts.path
                )),
                kind: FindingKind::AntiPattern,
                severity: Severity::Low,
                confidence: 0.6,
                dimension: Dimension::Observability,
                file_id: *file_id,
                file_path: ts.path.clone(),
                line: Some(line),
                column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                patch: Some(patch),
                fix_preview: Some("Add OpenTelemetry tracing".to_string()),
                tags: vec!["observability".into(), "tracing".into(), "opentelemetry".into()],
            });
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptMissingTracingRule::new();
        assert_eq!(rule.id(), "typescript.missing_tracing");
    }
}
