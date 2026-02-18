//! Rule: Go Missing Structured Logging
//!
//! Detects usage of fmt.Println/log.Print instead of structured logging (zerolog/zap/slog).

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::structured_logging;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects missing structured logging in Go code.
#[derive(Debug, Default)]
pub struct GoMissingStructuredLoggingRule;

impl GoMissingStructuredLoggingRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoMissingStructuredLoggingRule {
    fn id(&self) -> &'static str {
        "go.missing_structured_logging"
    }

    fn name(&self) -> &'static str {
        "Go Missing Structured Logging"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(structured_logging())
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

            // Check for structured logging libraries
            let has_structured_logging = go_sem.imports.iter().any(|imp| {
                imp.path.contains("github.com/rs/zerolog")
                    || imp.path.contains("go.uber.org/zap")
                    || imp.path.contains("log/slog")
                    || imp.path.contains("github.com/sirupsen/logrus")
            });

            if has_structured_logging {
                continue;
            }

            // Look for unstructured logging calls
            for call in &go_sem.calls {
                let is_unstructured = call.function_call.callee_expr.contains("fmt.Print")
                    || call.function_call.callee_expr.contains("fmt.Println")
                    || call.function_call.callee_expr.contains("fmt.Printf")
                    || call.function_call.callee_expr.contains("log.Print")
                    || call.function_call.callee_expr.contains("log.Println")
                    || call.function_call.callee_expr.contains("log.Printf")
                    || call.function_call.callee_expr.contains("log.Fatal")
                    || call.function_call.callee_expr.contains("log.Panic");

                if is_unstructured {
                    let line = call.function_call.location.line;
                    
                    let title = format!(
                        "Unstructured logging call `{}` detected",
                        call.function_call.callee_expr
                    );

                    let description = format!(
                        "The call to `{}` at line {} uses unstructured logging. \
                         In production systems, structured logging (e.g., zerolog, zap, slog) \
                         provides better observability with key-value pairs, log levels, \
                         and JSON output for log aggregation systems.",
                        call.function_call.callee_expr, line
                    );

                    let patch = generate_structured_logging_patch(*file_id, line);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::AntiPattern,
                        severity: Severity::Low,
                        confidence: 0.85,
                        dimension: Dimension::Observability,
                        file_id: *file_id,
                        file_path: go_sem.path.clone(),
                        line: Some(line),
                        column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("// Use structured logging:\n// log.Info().Str(\"key\", value).Msg(\"message\")".to_string()),
                        tags: vec![
                            "go".into(),
                            "logging".into(),
                            "observability".into(),
                        ],
                    });
                }
            }
        }

        findings
    }
}

fn generate_structured_logging_patch(file_id: FileId, line: u32) -> FilePatch {
    let replacement = r#"// Replace with structured logging:
    // import "github.com/rs/zerolog/log"
    // log.Info().Str("key", "value").Msg("your message")"#.to_string();

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
        let rule = GoMissingStructuredLoggingRule::new();
        assert_eq!(rule.id(), "go.missing_structured_logging");
    }
}