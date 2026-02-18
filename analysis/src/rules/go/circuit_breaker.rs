//! Rule: Go Missing Circuit Breaker
//!
//! Detects HTTP client calls without circuit breaker pattern for fault tolerance.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::circuit_breaker;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects missing circuit breaker pattern for external HTTP calls.
#[derive(Debug, Default)]
pub struct GoMissingCircuitBreakerRule;

impl GoMissingCircuitBreakerRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoMissingCircuitBreakerRule {
    fn id(&self) -> &'static str {
        "go.missing_circuit_breaker"
    }

    fn name(&self) -> &'static str {
        "Go Missing Circuit Breaker"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(circuit_breaker())
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

            // Check for circuit breaker library usage
            let has_circuit_breaker = go_sem.imports.iter().any(|imp| {
                imp.path.contains("github.com/sony/gobreaker")
                    || imp.path.contains("github.com/afex/hystrix-go")
                    || imp.path.contains("github.com/rubyist/circuitbreaker")
            });

            if has_circuit_breaker {
                continue;
            }

            // Look for HTTP client calls
            for call in &go_sem.http_calls {
                let line = call.location.range.start_line + 1;
                
                let title = format!(
                    "HTTP client call at line {} lacks circuit breaker",
                    line
                );

                let description = format!(
                    "HTTP client call at line {} does not use a circuit breaker pattern. \
                     Circuit breakers prevent cascading failures by stopping requests to \
                     failing services, allowing them to recover. Use gobreaker or hystrix-go \
                     for fault tolerance in production systems.",
                    line
                );

                let patch = generate_circuit_breaker_patch(*file_id, line);

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.75,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: go_sem.path.clone(),
                    line: Some(line),
                    column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("// Use gobreaker for circuit breaker pattern".to_string()),
                    tags: vec![
                        "go".into(),
                        "circuit-breaker".into(),
                        "resilience".into(),
                        "reliability".into(),
                    ],
                });
            }
        }

        findings
    }
}

fn generate_circuit_breaker_patch(file_id: FileId, line: u32) -> FilePatch {
    let replacement = r#"// Add circuit breaker for fault tolerance:
// import "github.com/sony/gobreaker"
// var cb *gobreaker.CircuitBreaker
// cb = gobreaker.NewCircuitBreaker(gobreaker.Settings{
//     Name:        "HTTP",
//     MaxRequests: 3,
//     Interval:    10 * time.Second,
//     Timeout:     30 * time.Second,
// })
// result, err := cb.Execute(func() (interface{}, error) {
//     return http.Get(url)
// })
"#.to_string();

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_has_correct_metadata() {
        let rule = GoMissingCircuitBreakerRule::new();
        assert_eq!(rule.id(), "go.missing_circuit_breaker");
    }
}