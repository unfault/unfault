//! Rule: Missing Tracing (OpenTelemetry)
//!
//! Detects services that don't have distributed tracing instrumentation.
//! Distributed tracing provides visibility into request flow across services.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::tracing;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};

/// Rule that detects missing distributed tracing instrumentation.
#[derive(Debug, Default)]
pub struct PythonMissingTracingRule;

impl PythonMissingTracingRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for PythonMissingTracingRule {
    fn id(&self) -> &'static str {
        "python.missing_tracing"
    }

    fn name(&self) -> &'static str {
        "Missing Distributed Tracing"
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

        // Collect all files to check for tracing setup
        let mut has_tracing_setup = false;

        for (_file_id, sem) in semantics {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => continue,
            };

            // Check if this file has tracing setup
            let has_otel = py.imports.iter().any(|imp| {
                imp.module.starts_with("opentelemetry") || imp.module == "opentelemetry"
            });

            let has_other_tracing = py.imports.iter().any(|imp| {
                imp.module == "ddtrace"
                    || imp.module.starts_with("ddtrace.")
                    || imp.module == "jaeger_client"
                    || imp.module == "newrelic"
            });

            if has_otel || has_other_tracing {
                has_tracing_setup = true;
                break;
            }
        }

        // If no tracing setup found, check for FastAPI apps
        if !has_tracing_setup {
            for (file_id, sem) in semantics {
                let py = match sem.as_ref() {
                    SourceSemantics::Python(py) => py,
                    _ => continue,
                };

                if let Some(ref fastapi) = py.fastapi {
                    // Get app info from the first app in the file
                    let (app_var_name, app_line) = fastapi.apps.first()
                        .map(|a| (a.var_name.clone(), a.location.range.start_line + 1))
                        .unwrap_or_else(|| ("app".to_string(), 1));
                    
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "FastAPI app without distributed tracing".to_string(),
                        description: Some(
                            "This FastAPI application doesn't have OpenTelemetry or other distributed tracing \
                             instrumentation. Distributed tracing provides visibility into request flow, \
                             latency breakdown, and dependency relationships across services. \
                             Consider adding OpenTelemetry auto-instrumentation."
                                .to_string(),
                        ),
                        kind: FindingKind::AntiPattern,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        dimension: Dimension::Observability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(app_line),
                        column: Some(0),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_fastapi_tracing_fix(&app_var_name)),
                        tags: vec!["tracing".to_string(), "opentelemetry".to_string(), "observability".to_string()],
                    });
                }
            }
        }

        findings
    }
}

fn generate_fastapi_tracing_fix(app_var: &str) -> String {
    format!(
        r#"Add OpenTelemetry instrumentation:

# Add to requirements.txt or pyproject.toml:
# opentelemetry-api
# opentelemetry-sdk
# opentelemetry-instrumentation-fastapi
# opentelemetry-exporter-otlp

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

# Set up tracing
trace.set_tracer_provider(TracerProvider())
tracer_provider = trace.get_tracer_provider()
otlp_exporter = OTLPSpanExporter(endpoint="http://localhost:4317")
tracer_provider.add_span_processor(BatchSpanProcessor(otlp_exporter))

# Instrument FastAPI
FastAPIInstrumentor.instrument_app({app_var})"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = PythonMissingTracingRule::new();
        assert_eq!(rule.id(), "python.missing_tracing");
    }

    #[test]
    fn test_rule_name() {
        let rule = PythonMissingTracingRule::new();
        assert_eq!(rule.name(), "Missing Distributed Tracing");
    }
}