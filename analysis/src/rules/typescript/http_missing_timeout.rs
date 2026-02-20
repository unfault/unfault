//! Rule: HTTP calls without timeout
//!
//! Detects HTTP client calls that don't have timeout configuration,
//! which can cause requests to hang indefinitely and exhaust resources.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::typescript::model::is_server_side_code;
use crate::types::context::Dimension;
use crate::types::finding::{
    Benefit, DecisionLevel, FindingApplicability, FindingKind, InvestmentLevel, LifecycleStage,
    Severity,
};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects HTTP calls without timeout configuration.
///
/// HTTP calls without timeouts can hang indefinitely, exhausting connection
/// pools and causing cascading failures in distributed systems.
#[derive(Debug)]
pub struct TypescriptHttpMissingTimeoutRule;

impl TypescriptHttpMissingTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptHttpMissingTimeoutRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptHttpMissingTimeoutRule {
    fn id(&self) -> &'static str {
        "typescript.http_missing_timeout"
    }

    fn name(&self) -> &'static str {
        "HTTP call without timeout"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Low,
            min_stage: LifecycleStage::Prototype,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Reliability, Benefit::Latency],
            prerequisites: vec![],
            notes: Some(
                "Time bounds are helpful even in demos; pick a sensible default.".to_string(),
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
            let ts = match sem.as_ref() {
                SourceSemantics::Typescript(ts) => ts,
                _ => continue,
            };

            // Skip client-side code - this rule only applies to server-side TypeScript
            // where connection pool exhaustion and cascading failures are concerns
            if !is_server_side_code(ts) {
                continue;
            }

            for http_call in &ts.http_calls {
                // Skip if timeout is already configured
                if http_call.has_timeout {
                    continue;
                }

                let client_name = format!("{:?}", http_call.client_kind);
                let title = format!(
                    "HTTP {} call without timeout configuration",
                    http_call.method
                );

                let description = if let Some(ref fn_name) = http_call.function_name {
                    format!(
                        "The HTTP `{}` call in function `{}` doesn't have a timeout configured. \
                         A timeout ensures the request completes within a known time bound, \
                         which helps maintain predictable response times for your service. \
                         Add a timeout configuration appropriate for your use case (e.g., 30 seconds for API calls).",
                        http_call.method, fn_name
                    )
                } else {
                    format!(
                        "The HTTP `{}` call using {} doesn't have a timeout configured. \
                         A timeout ensures the request completes within a known time bound, \
                         which helps maintain predictable response times for your service. \
                         Add a timeout configuration appropriate for your use case.",
                        http_call.method, client_name
                    )
                };

                let (patch, fix_preview) = generate_timeout_patch(http_call, *file_id);

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::High,
                    confidence: 0.95,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(http_call.location.range.start_line + 1),
                    column: Some(http_call.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "typescript".into(),
                        "http".into(),
                        "timeout".into(),
                        "stability".into(),
                        "reliability".into(),
                    ],
                });
            }
        }

        findings
    }
}

fn generate_timeout_patch(
    http_call: &crate::semantics::typescript::http::HttpCallSite,
    file_id: FileId,
) -> (FilePatch, String) {
    use crate::semantics::typescript::http::HttpClientKind;

    let fix_preview = match http_call.client_kind {
        HttpClientKind::Fetch => {
            "// Add AbortController for timeout:\nconst controller = new AbortController();\nconst timeoutId = setTimeout(() => controller.abort(), 30000);\nfetch(url, { signal: controller.signal });".to_string()
        }
        HttpClientKind::Axios => {
            "axios.get(url, { timeout: 30000 });".to_string()
        }
        HttpClientKind::Got => {
            "got(url, { timeout: { request: 30000 } });".to_string()
        }
        HttpClientKind::Ky => {
            "ky(url, { timeout: 30000 });".to_string()
        }
        _ => {
            "// Add timeout option to HTTP request".to_string()
        }
    };

    let patch = FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine {
                line: http_call.location.range.start_line + 1,
            },
            replacement: "// TODO: Add timeout configuration\n".to_string(),
        }],
    };

    (patch, fix_preview)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::typescript::parse_typescript_file;
    use crate::semantics::typescript::build_typescript_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.ts".to_string(),
            language: Language::Typescript,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_typescript_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_typescript_semantics(&parsed).expect("semantics should succeed");
        (file_id, Arc::new(SourceSemantics::Typescript(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = TypescriptHttpMissingTimeoutRule::new();
        assert_eq!(rule.id(), "typescript.http_missing_timeout");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = TypescriptHttpMissingTimeoutRule::new();
        assert!(rule.name().contains("timeout"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_typescript() {
        let rule = TypescriptHttpMissingTimeoutRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_fetch_without_timeout_in_server_code() {
        let rule = TypescriptHttpMissingTimeoutRule::new();
        // Server-side code with express import
        let src = r#"
import express from 'express';

async function fetchData() {
    return fetch('https://api.example.com');
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("timeout"));
    }

    #[tokio::test]
    async fn evaluate_ignores_fetch_in_client_side_code() {
        let rule = TypescriptHttpMissingTimeoutRule::new();
        // Pure client-side code with no server indicators
        let src = r#"
async function fetchData() {
    return fetch('https://api.example.com');
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "Client-side code should not trigger this rule"
        );
    }

    #[tokio::test]
    async fn evaluate_ignores_fetch_with_signal_in_server_code() {
        let rule = TypescriptHttpMissingTimeoutRule::new();
        let src = r#"
import express from 'express';

fetch('https://api.example.com', { signal: controller.signal });
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_axios_with_timeout_in_server_code() {
        let rule = TypescriptHttpMissingTimeoutRule::new();
        let src = r#"
import * as fs from 'fs';

axios.get('https://api.example.com', { timeout: 30000 });
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_axios_without_timeout_in_server_code() {
        let rule = TypescriptHttpMissingTimeoutRule::new();
        let src = r#"
import { createServer } from 'http';

axios.get('https://api.example.com');
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_detects_with_node_prefix_import() {
        let rule = TypescriptHttpMissingTimeoutRule::new();
        // Use node:http to indicate server-side code
        // Note: node:path, node:fs, etc. are NOT server-side indicators
        // as they're commonly used in CLI tools and VS Code extensions
        let src = r#"
import { createServer } from 'node:http';

fetch('https://api.example.com');
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1, "node:http indicates server-side code");
    }

    #[tokio::test]
    async fn evaluate_detects_with_nestjs_import() {
        let rule = TypescriptHttpMissingTimeoutRule::new();
        let src = r#"
import { Controller } from '@nestjs/common';

fetch('https://api.example.com');
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(
            findings.len(),
            1,
            "NestJS imports indicate server-side code"
        );
    }
}
