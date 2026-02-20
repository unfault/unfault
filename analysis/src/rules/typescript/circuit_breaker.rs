//! TypeScript Circuit Breaker Detection Rule
//!
//! Detects HTTP calls that lack circuit breaker patterns for resilience.

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
pub struct TypescriptMissingCircuitBreakerRule;

impl TypescriptMissingCircuitBreakerRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptMissingCircuitBreakerRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptMissingCircuitBreakerRule {
    fn id(&self) -> &'static str {
        "typescript.missing_circuit_breaker"
    }

    fn name(&self) -> &'static str {
        "Missing Circuit Breaker Pattern"
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

            // Check if circuit breaker libraries are imported
            let has_circuit_breaker = ts.imports.iter().any(|imp| {
                let module_lower = imp.module.to_lowercase();
                module_lower.contains("opossum")
                    || module_lower.contains("cockatiel")
                    || module_lower.contains("circuit-breaker")
                    || module_lower.contains("brakes")
            });

            if has_circuit_breaker {
                continue;
            }

            // Find external HTTP calls that should have circuit breakers
            for http_call in &ts.http_calls {
                // Skip internal/localhost calls
                if let Some(ref url) = http_call.url {
                    if url.contains("localhost") || url.contains("127.0.0.1") {
                        continue;
                    }
                }

                let line = http_call.location.range.start_line + 1;
                let column = http_call.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// Consider wrapping with circuit breaker:\n\
                             // import CircuitBreaker from 'opossum';\n\
                             // const breaker = new CircuitBreaker(asyncFn, { timeout: 3000 });\n"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "HTTP call without circuit breaker".to_string(),
                    description: Some(format!(
                        "External HTTP call '{}' at line {} lacks circuit breaker protection. \
                         Circuit breakers prevent cascading failures when external services are unavailable.",
                        http_call.method, line
                    )),
                    kind: FindingKind::ReliabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.7,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Wrap HTTP call with circuit breaker pattern".to_string()),
                    tags: vec![
                        "resilience".into(),
                        "circuit-breaker".into(),
                        "fault-tolerance".into(),
                    ],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::circuit_breaker())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptMissingCircuitBreakerRule::new();
        assert_eq!(rule.id(), "typescript.missing_circuit_breaker");
    }

    #[test]
    fn test_rule_name() {
        let rule = TypescriptMissingCircuitBreakerRule::new();
        assert!(rule.name().contains("Circuit Breaker"));
    }
}
