//! Rule: Console statements in production code
//!
//! Detects `console.log`, `console.error`, etc. which should be replaced with
//! structured logging in server-side production code.
//!
//! Note: This rule only applies to server-side TypeScript/Node.js code.
//! Client-side (browser) code is excluded since console.log is acceptable there.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::typescript::model::is_server_side_code;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects console statements in server-side production code.
///
/// Console statements don't provide structured logging, may leak sensitive
/// information, and can't be easily filtered or leveled.
///
/// This rule only applies to server-side code (Node.js). Client-side browser
/// code is excluded since console.log is acceptable for debugging there.
#[derive(Debug)]
pub struct TypescriptConsoleInProductionRule;

impl TypescriptConsoleInProductionRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptConsoleInProductionRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptConsoleInProductionRule {
    fn id(&self) -> &'static str {
        "typescript.console_in_production"
    }

    fn name(&self) -> &'static str {
        "Console statements should be replaced with structured logging"
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
            if ts.path.contains(".test.") || ts.path.contains(".spec.") {
                continue;
            }

            // Skip client-side code - console.log is acceptable in browser code
            if !is_server_side_code(ts) {
                continue;
            }

            for call in &ts.calls {
                // Check for console.* calls
                if call.callee.starts_with("console.") {
                    let method = call.callee.strip_prefix("console.").unwrap_or("log");
                    let logger_method = match method {
                        "error" => "error",
                        "warn" => "warn",
                        "info" => "info",
                        "debug" => "debug",
                        _ => "info",
                    };

                    let title = format!(
                        "Use structured logging instead of {} in production",
                        call.callee
                    );

                    let description = format!(
                        "The {} call should be replaced with a structured logger. \
                         Console statements don't provide structured logging for aggregation, \
                         may leak sensitive information, and can't be easily filtered or leveled.",
                        call.callee
                    );

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::ReplaceBytes {
                                start: call.start_byte,
                                end: call.end_byte,
                            },
                            replacement: format!("logger.{}{}", logger_method, call.args_repr),
                        }],
                    };

                    let fix_preview = format!(
                        "// Before:\n{}\n// After:\nlogger.{}{}",
                        call.callee, logger_method, call.args_repr
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::AntiPattern,
                        severity: Severity::Medium,
                        confidence: 0.9,
                        dimension: Dimension::Observability,
                        file_id: *file_id,
                        file_path: ts.path.clone(),
                        line: Some(call.location.range.start_line + 1),
                        column: Some(call.location.range.start_col + 1),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "typescript".into(),
                            "logging".into(),
                            "observability".into(),
                            "anti-pattern".into(),
                        ],
                    });
                }
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
    fn rule_id_is_correct() {
        let rule = TypescriptConsoleInProductionRule::new();
        assert_eq!(rule.id(), "typescript.console_in_production");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = TypescriptConsoleInProductionRule::new();
        assert!(rule.name().contains("Console"));
    }

    #[tokio::test]
    async fn evaluate_detects_console_log_in_server_code() {
        let rule = TypescriptConsoleInProductionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "app.ts",
            r#"
import express from 'express';

function process() {
    console.log('Processing data');
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("console.log"));
    }

    #[tokio::test]
    async fn evaluate_detects_console_error_in_server_code() {
        let rule = TypescriptConsoleInProductionRule::new();
        // Use an HTTP-related import to indicate server-side code
        // Note: fs, path, crypto are NOT server-side indicators as they're used in CLI tools, VS Code extensions, etc.
        let (file_id, sem) = parse_and_build_semantics(
            "app.ts",
            r#"
import { createServer } from 'http';

function handleError() {
    console.error('Error occurred');
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_ignores_test_files() {
        let rule = TypescriptConsoleInProductionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "app.test.ts",
            r#"
import express from 'express';
console.log('test output');
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_client_side_code() {
        let rule = TypescriptConsoleInProductionRule::new();
        // Pure client-side code with no server indicators
        let (file_id, sem) = parse_and_build_semantics(
            "browser-app.ts",
            r#"
function showMessage() {
    console.log('Hello from browser');
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "Client-side code should not trigger console warnings"
        );
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_typescript() {
        let rule = TypescriptConsoleInProductionRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_vscode_extensions() {
        let rule = TypescriptConsoleInProductionRule::new();
        // VS Code extension - console.log is standard practice for extensions
        let (file_id, sem) = parse_and_build_semantics(
            "extension.ts",
            r#"
import * as vscode from 'vscode';

function log(message: string): void {
    console.log(`[Extension] ${message}`);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "VS Code extensions should not trigger console warnings"
        );
    }
}
