//! TypeScript Missing Correlation ID Detection Rule

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

#[derive(Debug)]
pub struct TypescriptMissingCorrelationIdRule;

impl TypescriptMissingCorrelationIdRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptMissingCorrelationIdRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptMissingCorrelationIdRule {
    fn id(&self) -> &'static str {
        "typescript.missing_correlation_id"
    }

    fn name(&self) -> &'static str {
        "Missing Correlation ID"
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
            let ts = match sem.as_ref() {
                SourceSemantics::Typescript(ts) => ts,
                _ => continue,
            };

            // Check if this is a server/API file
            let is_server_file = ts.express.is_some()
                || ts.imports.iter().any(|imp| {
                    let module = imp.module.to_lowercase();
                    module == "express" || module == "fastify" || module == "@nestjs/common"
                });

            if !is_server_file {
                continue;
            }

            // Check for correlation ID handling
            let has_correlation = ts.imports.iter().any(|imp| {
                imp.module.contains("correlation") || imp.module.contains("cls-hooked")
            });

            if has_correlation {
                continue;
            }

            // Check for HTTP calls that should propagate correlation IDs
            for http_call in &ts.http_calls {
                let line = http_call.location.range.start_line + 1;
                let column = http_call.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// Add correlation ID header:\n// headers: { 'X-Correlation-ID': correlationId }\n".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "HTTP call without correlation ID".to_string(),
                    description: Some(format!(
                        "HTTP call at line {} does not propagate correlation ID.",
                        line
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
                    fix_preview: Some("Add correlation ID header".to_string()),
                    tags: vec!["observability".into(), "correlation-id".into()],
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
    fn test_rule_id() {
        let rule = TypescriptMissingCorrelationIdRule::new();
        assert_eq!(rule.id(), "typescript.missing_correlation_id");
    }
}
