//! Rule: Missing circuit breaker pattern for HTTP/external calls.
//!
//! HTTP calls to external services should be wrapped with a circuit breaker
//! to prevent cascading failures when the external service is down.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{Benefit, DecisionLevel, FindingApplicability, FindingKind, InvestmentLevel, LifecycleStage, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects HTTP calls without circuit breaker protection.
#[derive(Debug, Default)]
pub struct RustMissingCircuitBreakerRule;

impl RustMissingCircuitBreakerRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustMissingCircuitBreakerRule {
    fn id(&self) -> &'static str {
        "rust.missing_circuit_breaker"
    }

    fn name(&self) -> &'static str {
        "HTTP calls without circuit breaker protection"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::High,
            min_stage: LifecycleStage::Production,
            decision_level: DecisionLevel::Architecture,
            benefits: vec![Benefit::Reliability, Benefit::Operability],
            prerequisites: vec![
                "Choose a circuit breaker library/pattern".to_string(),
                "Define fallback behavior and error semantics".to_string(),
                "Tune thresholds based on real traffic".to_string(),
            ],
            notes: Some(
                "Typically unnecessary for small demos; most useful with real traffic and external dependencies."
                    .to_string(),
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
            let rust = match sem.as_ref() {
                SourceSemantics::Rust(r) => r,
                _ => continue,
            };

            // Check if circuit breaker is used
            let uses_circuit_breaker = rust.uses.iter().any(|u| {
                u.path.contains("failsafe")
                    || u.path.contains("circuit_breaker")
                    || u.path.contains("CircuitBreaker")
                    || u.path.contains("recloser")
            });

            if uses_circuit_breaker {
                continue;
            }

            // Look for HTTP client calls to external services.
            // We need to be specific to avoid false positives like HeaderMap.get().
            let http_calls: Vec<_> = rust
                .calls
                .iter()
                .filter(|c| {
                    let callee = &c.function_call.callee_expr;
                    // reqwest client calls (most common)
                    callee.contains("reqwest::Client")
                        || callee.contains("reqwest::client")
                        || callee.contains("Client::new")
                        || callee.contains("Client::builder")
                        // surf client calls
                        || callee.contains("surf::Client")
                        // hyper client calls
                        || callee.contains("hyper::Client")
                        || callee.contains("hyper::client")
                        // Match .send() and .execute() on known clients (after .get/.post but only on client objects)
                        || (callee.contains(".send(") && callee.contains("client"))
                        || (callee.contains(".execute(") && callee.contains("client"))
                })
                .collect();

            if http_calls.is_empty() {
                continue;
            }

            // Check if there are multiple HTTP calls (suggests external service communication)
            if http_calls.len() < 2 {
                continue;
            }

            // Find the first HTTP call as the location for the finding
            if let Some(first_call) = http_calls.first() {
                let line = first_call.function_call.location.line;

                let title = "HTTP calls without circuit breaker protection".to_string();

                let description = format!(
                    "Multiple HTTP calls found starting at line {} without circuit breaker \
                     protection.\n\n\
                     **Why this matters:**\n\
                     - External service failures can cascade to your application\n\
                     - Slow responses can exhaust connection pools\n\
                     - Repeated failures waste resources on doomed requests\n\
                     - No automatic recovery when services come back\n\n\
                     **Recommendations:**\n\
                     - Use the `failsafe-rs` or `recloser` crate\n\
                     - Configure failure threshold and recovery time\n\
                     - Implement fallback behavior for open circuit\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use failsafe::{{Config, CircuitBreaker}};\n\
                     use std::time::Duration;\n\
                     \n\
                     let circuit_breaker = Config::new()\n    \
                         .failure_threshold(3)\n    \
                         .success_threshold(2)\n    \
                         .failure_timeout(Duration::from_secs(30))\n    \
                         .build();\n\
                     \n\
                     let result = circuit_breaker.call(|| {{\n    \
                         client.get(url).send().await\n\
                     }}).await;\n\
                     ```",
                    line
                );

                let fix_preview = 
                    "use failsafe::{Config, CircuitBreaker};\n\n\
                     let circuit_breaker = Config::new()\n    \
                         .failure_threshold(3)\n    \
                         .success_threshold(2)\n    \
                         .failure_timeout(Duration::from_secs(30))\n    \
                         .build();\n\n\
                     let response = circuit_breaker.call(|| async {\n    \
                         client.get(url).send().await\n\
                     }).await?;".to_string();

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Add circuit breaker - use failsafe or recloser crate".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::ReliabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.70,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "circuit-breaker".into(),
                        "resilience".into(),
                        "http".into(),
                    ],
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
    fn rule_id_is_correct() {
        let rule = RustMissingCircuitBreakerRule::new();
        assert_eq!(rule.id(), "rust.missing_circuit_breaker");
    }

    #[test]
    fn rule_name_mentions_circuit_breaker() {
        let rule = RustMissingCircuitBreakerRule::new();
        assert!(rule.name().contains("circuit breaker"));
    }
}
