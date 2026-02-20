//! Rule: Unbounded retry loops without limits.
//!
//! Retry loops should have a maximum retry count or timeout to prevent
//! infinite retry storms.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects retry loops without proper bounds.
#[derive(Debug, Default)]
pub struct RustUnboundedRetryRule;

impl RustUnboundedRetryRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustUnboundedRetryRule {
    fn id(&self) -> &'static str {
        "rust.unbounded_retry"
    }

    fn name(&self) -> &'static str {
        "Retry loop without maximum attempts or timeout"
    }

    fn applicability(&self) -> Option<crate::types::finding::FindingApplicability> {
        Some(crate::rules::applicability_defaults::retry())
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

            // Check for proper retry library usage
            let uses_retry_crate = rust.uses.iter().any(|u| {
                u.path.contains("backoff")
                    || u.path.contains("retry")
                    || u.path.contains("tokio_retry")
            });

            if uses_retry_crate {
                continue;
            }

            // Look for loop patterns with retry-like behavior
            for mac in &rust.macro_invocations {
                if mac.name != "loop" && !mac.args.contains("loop") {
                    continue;
                }

                // Check if it's a retry loop (contains await, error handling)
                let has_await_in_loop = rust.calls.iter().any(|c| {
                    c.function_call.callee_expr.contains(".await")
                        && c.function_call.location.line > mac.location.range.start_line
                });

                if !has_await_in_loop {
                    continue;
                }

                let line = mac.location.range.start_line + 1;

                let title = "Potential unbounded retry loop".to_string();

                let description = format!(
                    "A loop at line {} appears to be a retry loop but may not have proper bounds.\n\n\
                     **Why this matters:**\n\
                     - Infinite retries can overwhelm failing services\n\
                     - Resource exhaustion from accumulated retry attempts\n\
                     - No exponential backoff causes thundering herd\n\
                     - Difficult to diagnose stuck requests\n\n\
                     **Recommendations:**\n\
                     - Use the `backoff` or `tokio-retry` crate\n\
                     - Implement exponential backoff with jitter\n\
                     - Set maximum retry count or timeout\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use backoff::ExponentialBackoff;\n\
                     use backoff::future::retry;\n\
                     \n\
                     let result = retry(ExponentialBackoff::default(), || async {{\n    \
                         client.request().await.map_err(backoff::Error::transient)\n\
                     }}).await?;\n\
                     ```",
                    line
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::ReliabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.60,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line },
                            replacement: "// TODO: Use backoff crate for bounded retries"
                                .to_string(),
                        }],
                    }),
                    fix_preview: Some("use backoff::ExponentialBackoff;".to_string()),
                    tags: vec!["rust".into(), "retry".into(), "resilience".into()],
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
        let rule = RustUnboundedRetryRule::new();
        assert_eq!(rule.id(), "rust.unbounded_retry");
    }
}
