//! Rule: HTTP retry in Go
//!
//! Detects HTTP clients without retry logic for transient failures.

use async_trait::async_trait;
use std::sync::Arc;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::retry;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects HTTP clients without retry logic.
#[derive(Debug, Default)]
pub struct GoHttpRetryRule;

impl GoHttpRetryRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoHttpRetryRule {
    fn id(&self) -> &'static str {
        "go.http_retry"
    }

    fn name(&self) -> &'static str {
        "HTTP client without retry"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(retry())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Check for retry library imports
            let has_retry_lib = go.imports.iter().any(|imp| {
                imp.path.contains("hashicorp/go-retryablehttp")
                    || imp.path.contains("avast/retry-go")
                    || imp.path.contains("cenkalti/backoff")
                    || imp.path.contains("sethvargo/go-retry")
            });

            if has_retry_lib {
                continue; // Project uses retry library
            }

            // Check HTTP calls
            for http_call in &go.http_calls {
                // Get line/column from location
                let call_line = http_call.location.range.start_line + 1; // Convert 0-based to 1-based
                let call_column = http_call.location.range.start_col + 1;

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!("HTTP {} call without retry logic", http_call.method_name),
                    description: Some(
                        "HTTP calls can fail due to transient network issues. \
                         Implement retry logic with exponential backoff for resilience. \
                         Consider using hashicorp/go-retryablehttp or cenkalti/backoff."
                            .to_string(),
                    ),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.75,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: go.path.clone(),
                    line: Some(call_line),
                    column: Some(call_column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line: call_line },
                            replacement: format!(
                                "// Add retry logic for transient failures:
// Option 1: Use go-retryablehttp
// import retryablehttp \"github.com/hashicorp/go-retryablehttp\"
// client := retryablehttp.NewClient()
// client.RetryMax = 3
// client.RetryWaitMin = 1 * time.Second
// client.RetryWaitMax = 30 * time.Second

// Option 2: Manual retry with backoff
// for attempt := 0; attempt < maxRetries; attempt++ {{
//     resp, err := http.{}(url)
//     if err == nil && resp.StatusCode < 500 {{
//         break
//     }}
//     time.Sleep(time.Duration(attempt+1) * time.Second)
// }}",
                                http_call.method_name
                            ),
                        }],
                    }),
                    fix_preview: Some("Add retry with backoff".to_string()),
                    tags: vec![
                        "go".into(),
                        "http".into(),
                        "retry".into(),
                        "resilience".into(),
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
    fn test_rule_metadata() {
        let rule = GoHttpRetryRule::new();
        assert_eq!(rule.id(), "go.http_retry");
        assert!(!rule.name().is_empty());
    }
}
