//! TypeScript HTTP Retry Detection Rule
//!
//! Detects HTTP calls without proper retry logic.

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
pub struct TypescriptHttpMissingRetryRule;

impl TypescriptHttpMissingRetryRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptHttpMissingRetryRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptHttpMissingRetryRule {
    fn id(&self) -> &'static str {
        "typescript.http.missing_retry"
    }

    fn name(&self) -> &'static str {
        "HTTP Call Without Retry Logic"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Medium,
            min_stage: LifecycleStage::Product,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Reliability],
            prerequisites: vec![
                "Only retry idempotent operations (or add idempotency keys)".to_string(),
                "Define which failures are retryable and apply backoff + max attempts".to_string(),
            ],
            notes: Some("Retries can increase load during outages; tune carefully and measure.".to_string()),
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

            // Check if retry library is imported
            let has_retry = ts.imports.iter().any(|imp| {
                let module = imp.module.to_lowercase();
                module.contains("retry")
                    || module.contains("axios-retry")
                    || module.contains("got")
                    || module.contains("ky")
            });

            if has_retry {
                continue;
            }

            // Check HTTP calls
            for http_call in &ts.http_calls {
                let line = http_call.location.range.start_line + 1;
                let column = http_call.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// Add retry logic for resilience:\n\
                             // import retry from 'async-retry';\n\
                             // const result = await retry(async () => {\n\
                             //   return await fetch(url);\n\
                             // }, { retries: 3 });\n"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!("HTTP {} call without retry logic", http_call.method),
                    description: Some(format!(
                        "HTTP {} call at line {} has no retry logic configured. \
                         Network failures are common; add retry with exponential backoff.",
                        http_call.method, line
                    )),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Low,
                    confidence: 0.5,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Add retry logic with exponential backoff".to_string()),
                    tags: vec!["http".into(), "retry".into(), "resilience".into()],
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
        let rule = TypescriptHttpMissingRetryRule::new();
        assert_eq!(rule.id(), "typescript.http.missing_retry");
    }
}
