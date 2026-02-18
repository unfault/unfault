//! Rule: Go Unbounded Retry
//!
//! Detects retry loops without maximum attempts or exponential backoff.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unbounded retry loops in Go code.
#[derive(Debug, Default)]
pub struct GoUnboundedRetryRule;

impl GoUnboundedRetryRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoUnboundedRetryRule {
    fn id(&self) -> &'static str {
        "go.unbounded_retry"
    }

    fn name(&self) -> &'static str {
        "Go Unbounded Retry"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(unbounded_resource())
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

            // Check for retry library imports
            let has_retry_lib = go_sem.imports.iter().any(|imp| {
                imp.path.contains("github.com/avast/retry-go")
                    || imp.path.contains("github.com/cenkalti/backoff")
            });

            if has_retry_lib {
                continue;
            }

            // Look for retry patterns in loops
            for call in &go_sem.calls {
                if !call.in_loop {
                    continue;
                }

                // Check for HTTP calls or other potentially retried operations
                let is_retryable_call = call.function_call.callee_expr.contains("http.")
                    || call.function_call.callee_expr.contains(".Do")
                    || call.function_call.callee_expr.contains(".Get")
                    || call.function_call.callee_expr.contains(".Post")
                    || call.function_call.callee_expr.contains(".Execute");

                if is_retryable_call {
                    let line = call.function_call.location.line;

                    let title = format!(
                        "Potential unbounded retry loop at line {}",
                        line
                    );

                    let description = format!(
                        "The call to `{}` at line {} appears to be in a retry loop without \
                         proper bounds or exponential backoff. Unbounded retries can cause \
                         cascading failures, resource exhaustion, and denial of service. \
                         Use a retry library with max attempts and exponential backoff.",
                        call.function_call.callee_expr, line
                    );

                    let patch = generate_retry_patch(*file_id, line);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::High,
                        confidence: 0.70,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go_sem.path.clone(),
                        line: Some(line),
                        column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("// Use retry-go with exponential backoff".to_string()),
                        tags: vec![
                            "go".into(),
                            "retry".into(),
                            "reliability".into(),
                            "resilience".into(),
                        ],
                    });
                }
            }
        }

        findings
    }
}

fn generate_retry_patch(file_id: FileId, line: u32) -> FilePatch {
    let replacement = r#"// Use retry-go with exponential backoff:
// import "github.com/avast/retry-go"
//
// err := retry.Do(
//     func() error {
//         return doOperation()
//     },
//     retry.Attempts(3),
//     retry.Delay(100*time.Millisecond),
//     retry.DelayType(retry.BackOffDelay),
//     retry.MaxJitter(100*time.Millisecond),
// )
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
        let rule = GoUnboundedRetryRule::new();
        assert_eq!(rule.id(), "go.unbounded_retry");
    }
}