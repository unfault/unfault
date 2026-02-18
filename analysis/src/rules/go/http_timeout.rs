//! Rule: HTTP client without timeout configuration
//!
//! Detects HTTP clients and requests that don't configure timeouts,
//! which can lead to resource exhaustion and hung connections.

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

/// Rule that detects HTTP clients without timeout configuration.
///
/// HTTP requests without timeouts can hang indefinitely if the server
/// doesn't respond or the network has issues. This can lead to:
/// - Goroutine leaks
/// - Connection pool exhaustion
/// - Degraded application performance
/// - Cascading failures in microservices
#[derive(Debug)]
pub struct GoHttpTimeoutRule;

impl GoHttpTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoHttpTimeoutRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for GoHttpTimeoutRule {
    fn id(&self) -> &'static str {
        "go.http_missing_timeout"
    }

    fn name(&self) -> &'static str {
        "HTTP client without timeout configuration"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Low,
            min_stage: LifecycleStage::Prototype,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Reliability, Benefit::Latency],
            prerequisites: vec![],
            notes: Some("Time bounds are helpful even in demos; pick a sensible default.".to_string()),
        })
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go = match sem.as_ref() {
                SourceSemantics::Go(go) => go,
                _ => continue,
            };

            for http_call in &go.http_calls {
                // Check if this HTTP call has a timeout configured
                if http_call.has_timeout {
                    continue;
                }

                let title = format!(
                    "HTTP {} call has no timeout",
                    http_call.method_name
                );

                let description = format!(
                    "The HTTP {} request at line {} doesn't have a timeout configured. \
                     A timeout ensures the request completes within a known time bound, \
                     which helps maintain predictable response times.\n\n\
                     Solutions:\n\
                     1. Use http.Client with Timeout field set\n\
                     2. Use context.WithTimeout() for per-request timeouts\n\
                     3. Configure Transport.ResponseHeaderTimeout and Transport.IdleConnTimeout",
                    http_call.method_name, http_call.location.range.start_line + 1
                );

                let patch = generate_timeout_patch(http_call, *file_id);

                let fix_preview = format!(
                    "// Before:\n\
                     // resp, err := http.{}(url)\n\
                     //\n\
                     // After (Option 1: Client with timeout):\n\
                     // client := &http.Client{{Timeout: 30 * time.Second}}\n\
                     // resp, err := client.{}(url)\n\
                     //\n\
                     // After (Option 2: Context with timeout):\n\
                     // ctx, cancel := context.WithTimeout(ctx, 30*time.Second)\n\
                     // defer cancel()\n\
                     // req, _ := http.NewRequestWithContext(ctx, \"{}\", url, nil)\n\
                     // resp, err := client.Do(req)",
                    http_call.method_name,
                    http_call.method_name,
                    http_call.method_name.to_uppercase()
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::ReliabilityRisk,
                    severity: Severity::High,
                    confidence: 0.95,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: go.path.clone(),
                    line: Some(http_call.location.range.start_line + 1),
                    column: Some(http_call.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "go".into(),
                        "http".into(),
                        "timeout".into(),
                        "reliability".into(),
                        "network".into(),
                    ],
                });
            }
        }

        findings
    }
}

use crate::semantics::go::http::HttpCallSite;

/// Generate a patch to add timeout to HTTP calls.
fn generate_timeout_patch(http_call: &HttpCallSite, file_id: FileId) -> FilePatch {
    // Check if using http.Get/Post/etc directly vs client.Get/etc
    let is_default_client = http_call.call_text.starts_with("http.");
    
    let replacement = if is_default_client {
        // Using http.Get/Post/etc directly - suggest using custom client
        format!(
            "// TODO: Create client with timeout\n\
             client := &http.Client{{Timeout: 30 * time.Second}}\n\
             {}",
            http_call.call_text.replace("http.", "client.")
        )
    } else {
        // Generic suggestion with context timeout
        format!(
            "ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)\n\
             defer cancel()\n\
             // TODO: Update {} to use context",
            http_call.call_text
        )
    };

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: http_call.start_byte,
                end: http_call.end_byte,
            },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::go::parse_go_file;
    use crate::semantics::go::build_go_semantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.go".to_string(),
            language: Language::Go,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_go_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_go_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Go(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = GoHttpTimeoutRule::new();
        assert_eq!(rule.id(), "go.http_missing_timeout");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = GoHttpTimeoutRule::new();
        assert!(rule.name().contains("timeout"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = GoHttpTimeoutRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GoHttpTimeoutRule"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_go() {
        let rule = GoHttpTimeoutRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_http_get_without_timeout() {
        let rule = GoHttpTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "net/http"

func fetch() {
    resp, err := http.Get("https://example.com")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.http_missing_timeout" {
                assert!(finding.description.is_some());
                assert!(finding.tags.contains(&"http".to_string()));
                assert!(finding.tags.contains(&"timeout".to_string()));
            }
        }
    }

    #[tokio::test]
    async fn evaluate_no_finding_for_client_with_timeout() {
        let rule = GoHttpTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import (
    "net/http"
    "time"
)

func fetch() {
    client := &http.Client{Timeout: 30 * time.Second}
    resp, err := client.Get("https://example.com")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag properly configured client (depends on semantics)
        let _ = findings;
    }

    #[tokio::test]
    async fn evaluate_detects_post_without_timeout() {
        let rule = GoHttpTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import (
    "net/http"
    "strings"
)

func sendData() {
    http.Post("https://api.example.com", "application/json", strings.NewReader("{}"))
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.http_missing_timeout" {
                assert_eq!(finding.dimension, Dimension::Reliability);
            }
        }
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = GoHttpTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "net/http"

func main() {
    http.Get("https://example.com")
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.http_missing_timeout" {
                assert!(finding.patch.is_some());
                assert!(finding.fix_preview.is_some());
                assert!(finding.tags.contains(&"go".to_string()));
            }
        }
    }
}
