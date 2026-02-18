//! TypeScript Rate Limiting Detection Rule
//!
//! Detects API endpoints that lack rate limiting.

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
pub struct TypescriptMissingRateLimitingRule;

impl TypescriptMissingRateLimitingRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptMissingRateLimitingRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptMissingRateLimitingRule {
    fn id(&self) -> &'static str {
        "typescript.missing_rate_limiting"
    }

    fn name(&self) -> &'static str {
        "Missing Rate Limiting"
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

            // Check for server/API code
            let is_server = ts.express.is_some()
                || ts.imports.iter().any(|imp| {
                    let m = imp.module.to_lowercase();
                    m.contains("express") || m.contains("fastify") || m.contains("nestjs")
                });

            if !is_server {
                continue;
            }

            // Check if rate limiting is configured
            let has_rate_limiting = ts.imports.iter().any(|imp| {
                let m = imp.module.to_lowercase();
                m.contains("rate-limit")
                    || m.contains("ratelimit")
                    || m.contains("limiter")
                    || m.contains("express-rate-limit")
            });

            if has_rate_limiting {
                continue;
            }

            // Report on first line
            let line = 1u32;
            let column = 1u32;

            let patch = FilePatch {
                file_id: *file_id,
                hunks: vec![PatchHunk {
                    range: PatchRange::InsertBeforeLine { line },
                    replacement: "// Add rate limiting to protect against abuse:\n\
                         // import rateLimit from 'express-rate-limit';\n\
                         // const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });\n\
                         // app.use(limiter);\n"
                        .to_string(),
                }],
            };

            findings.push(RuleFinding {
                rule_id: self.id().to_string(),
                title: "API server without rate limiting".to_string(),
                description: Some(
                    "This server file does not have rate limiting configured. \
                     Without rate limiting, the API is vulnerable to abuse and DDoS attacks."
                        .to_string(),
                ),
                kind: FindingKind::SecurityVulnerability,
                severity: Severity::Medium,
                confidence: 0.6,
                dimension: Dimension::Security,
                file_id: *file_id,
                file_path: ts.path.clone(),
                line: Some(line),
                column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                patch: Some(patch),
                fix_preview: Some("Add express-rate-limit middleware".to_string()),
                tags: vec!["security".into(), "rate-limiting".into(), "api".into()],
            });
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::missing_rate_limiting())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptMissingRateLimitingRule::new();
        assert_eq!(rule.id(), "typescript.missing_rate_limiting");
    }
}