//! TypeScript Unbounded Retry Detection Rule
//!
//! Detects retry loops without proper limits or backoff.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

#[derive(Debug)]
pub struct TypescriptUnboundedRetryRule;

impl TypescriptUnboundedRetryRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptUnboundedRetryRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptUnboundedRetryRule {
    fn id(&self) -> &'static str {
        "typescript.unbounded_retry"
    }

    fn name(&self) -> &'static str {
        "Unbounded Retry Loop"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::retry())
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

            // Check for retry patterns without limits
            for call in &ts.calls {
                let callee_lower = call.callee.to_lowercase();
                
                // Look for retry-related patterns
                let is_retry_pattern = callee_lower.contains("retry")
                    || callee_lower.contains("attempt")
                    || (call.in_loop && is_http_or_db_call(&callee_lower));

                if !is_retry_pattern {
                    continue;
                }

                // Check for limiting patterns
                let args_text = call.args.iter()
                    .map(|a| a.value_repr.to_lowercase())
                    .collect::<Vec<_>>()
                    .join(" ");
                
                let has_limit = args_text.contains("maxretries")
                    || args_text.contains("max_retries")
                    || args_text.contains("attempts")
                    || args_text.contains("limit")
                    || args_text.contains("backoff");

                if has_limit {
                    continue;
                }

                let line = call.location.range.start_line + 1;
                let column = call.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// Add retry limits with exponential backoff:\n\
                             // import { retry } from 'async-retry';\n\
                             // await retry(fn, { retries: 3, factor: 2 });\n"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "Unbounded retry without limits".to_string(),
                    description: Some(format!(
                        "Retry pattern at line {} lacks proper limits or backoff. \
                         Unbounded retries can cause cascading failures and resource exhaustion.",
                        line
                    )),
                    kind: FindingKind::ReliabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.6,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Add maxRetries and exponential backoff".to_string()),
                    tags: vec!["reliability".into(), "retry".into(), "resilience".into()],
                });
            }
        }

        findings
    }
}

fn is_http_or_db_call(callee: &str) -> bool {
    callee.contains("fetch")
        || callee.contains("axios")
        || callee.contains("http")
        || callee.contains("query")
        || callee.contains("request")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptUnboundedRetryRule::new();
        assert_eq!(rule.id(), "typescript.unbounded_retry");
    }
}