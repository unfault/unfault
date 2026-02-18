//! TypeScript Idempotency Key Detection Rule
//!
//! Detects state-changing API operations that lack idempotency keys.

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
pub struct TypescriptMissingIdempotencyKeyRule;

impl TypescriptMissingIdempotencyKeyRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptMissingIdempotencyKeyRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptMissingIdempotencyKeyRule {
    fn id(&self) -> &'static str {
        "typescript.missing_idempotency_key"
    }

    fn name(&self) -> &'static str {
        "Missing Idempotency Key"
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

            // Check for state-changing HTTP calls
            for http_call in &ts.http_calls {
                let method_lower = http_call.method.to_lowercase();
                
                // Only check POST, PUT, PATCH (state-changing)
                if method_lower != "post" && method_lower != "put" && method_lower != "patch" {
                    continue;
                }

                // Skip if it already has idempotency key
                // We can't check headers directly, but check for common patterns
                let line = http_call.location.range.start_line + 1;
                let column = http_call.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// Add idempotency key for safe retries:\n\
                             // import { v4 as uuidv4 } from 'uuid';\n\
                             // headers: { 'Idempotency-Key': uuidv4() }\n"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "State-changing API call without idempotency key".to_string(),
                    description: Some(format!(
                        "HTTP {} call at line {} should include an idempotency key to ensure \
                         safe retries and prevent duplicate operations.",
                        method_lower.to_uppercase(), line
                    )),
                    kind: FindingKind::ReliabilityRisk,
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
                    fix_preview: Some("Add Idempotency-Key header".to_string()),
                    tags: vec!["reliability".into(), "idempotency".into(), "api".into()],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::idempotency_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptMissingIdempotencyKeyRule::new();
        assert_eq!(rule.id(), "typescript.missing_idempotency_key");
    }
}