//! TypeScript Missing Structured Logging Detection Rule
//!
//! Detects usage of console.log instead of structured logging libraries
//! in server-side TypeScript/Node.js code.
//!
//! Note: This rule only applies to server-side code. Client-side (browser)
//! code is excluded since console.log is acceptable there.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::typescript::model::is_server_side_code;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects console.log usage instead of structured logging.
///
/// This rule only applies to server-side TypeScript/Node.js code.
/// Client-side browser code is excluded.
#[derive(Debug)]
pub struct TypescriptMissingStructuredLoggingRule;

impl TypescriptMissingStructuredLoggingRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptMissingStructuredLoggingRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptMissingStructuredLoggingRule {
    fn id(&self) -> &'static str {
        "typescript.missing_structured_logging"
    }

    fn name(&self) -> &'static str {
        "Missing Structured Logging"
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

            // Skip test files
            if ts.path.contains("test") || ts.path.contains("spec") {
                continue;
            }

            // Skip client-side code - console.log is acceptable in browser code
            if !is_server_side_code(ts) {
                continue;
            }

            // Check if structured logging is already imported
            let has_structured_logger = ts.imports.iter().any(|imp| {
                let module = imp.module.to_lowercase();
                module.contains("winston")
                    || module.contains("pino")
                    || module.contains("bunyan")
                    || module.contains("log4js")
                    || module.contains("loglevel")
            });

            if has_structured_logger {
                continue;
            }

            // Find console.log/warn/error calls
            for call in &ts.calls {
                let callee_lower = call.callee.to_lowercase();
                
                if !callee_lower.starts_with("console.") {
                    continue;
                }

                let line = call.location.range.start_line + 1;
                let column = call.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// Use structured logging instead of console:\n\
                             // import pino from 'pino';\n\
                             // const logger = pino({ level: 'info' });\n\
                             // logger.info({ event: 'action' }, 'Message');\n"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "Using console instead of structured logger".to_string(),
                    description: Some(format!(
                        "Console logging at line {} should be replaced with structured logging. \
                         Structured logs are easier to search, filter, and analyze in production.",
                        line
                    )),
                    kind: FindingKind::AntiPattern,
                    severity: Severity::Low,
                    confidence: 0.8,
                    dimension: Dimension::Observability,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Replace with pino/winston structured logger".to_string()),
                    tags: vec!["observability".into(), "logging".into()],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::structured_logging())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::typescript::parse_typescript_file;
    use crate::semantics::typescript::build_typescript_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(path: &str, source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: path.to_string(),
            language: Language::Typescript,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_typescript_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_typescript_semantics(&parsed).unwrap();
        (file_id, Arc::new(SourceSemantics::Typescript(sem)))
    }

    #[test]
    fn test_rule_id() {
        let rule = TypescriptMissingStructuredLoggingRule::new();
        assert_eq!(rule.id(), "typescript.missing_structured_logging");
    }

    #[tokio::test]
    async fn evaluate_detects_console_in_server_code() {
        let rule = TypescriptMissingStructuredLoggingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "app.ts",
            r#"
import express from 'express';

function process() {
    console.log('Processing');
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_ignores_client_side_code() {
        let rule = TypescriptMissingStructuredLoggingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "browser.ts",
            r#"
function showMessage() {
    console.log('Hello');
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Client-side code should not require structured logging");
    }

    #[tokio::test]
    async fn evaluate_ignores_when_logger_imported() {
        let rule = TypescriptMissingStructuredLoggingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "app.ts",
            r#"
import express from 'express';
import pino from 'pino';

console.log('backup log');
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not flag when structured logger is imported");
    }
}