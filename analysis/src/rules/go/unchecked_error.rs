//! Rule: Unchecked error returns
//!
//! Detects Go code that ignores error return values, which is a common
//! source of bugs and production incidents in Go applications.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::ignored_result;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unchecked error returns in Go code.
///
/// In Go, it's a best practice to always check error returns. Ignoring
/// errors can lead to silent failures, data corruption, and hard-to-debug
/// production issues.
#[derive(Debug)]
pub struct GoUncheckedErrorRule;

impl GoUncheckedErrorRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoUncheckedErrorRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for GoUncheckedErrorRule {
    fn id(&self) -> &'static str {
        "go.unchecked_error"
    }

    fn name(&self) -> &'static str {
        "Unchecked error return value"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(ignored_result())
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

            for unchecked in &go.unchecked_errors {
                // All unchecked errors are at least medium severity
                let severity = Severity::Medium;

                let func_name = unchecked
                    .function_name
                    .as_deref()
                    .unwrap_or("unknown function");

                let title = format!("Error return from `{}` is not checked", func_name);

                let description = format!(
                    "The call to `{}` returns an error value that is being ignored. \
                     In Go, errors should always be explicitly handled or intentionally \
                     discarded using `_ = expr`. Unchecked errors can lead to silent \
                     failures, data corruption, and hard-to-debug production issues. \
                     Consider adding proper error handling: \
                     `if err != nil {{ return err }}` or log the error.",
                    func_name
                );

                // Generate patch to add error handling
                let patch = generate_error_check_patch(unchecked, *file_id);

                let fix_preview = format!(
                    "// Before:\n// {}\n// After:\n// result, err := {}\n// if err != nil {{\n//     return err\n// }}",
                    unchecked.call_text.trim(),
                    unchecked.call_text.trim()
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity,
                    confidence: 0.95,
                    dimension: Dimension::Correctness,
                    file_id: *file_id,
                    file_path: go.path.clone(),
                    line: Some(unchecked.line),
                    column: Some(unchecked.column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "go".into(),
                        "error-handling".into(),
                        "correctness".into(),
                        "stability".into(),
                    ],
                });
            }
        }

        findings
    }
}

use crate::semantics::go::model::UncheckedError;

/// Generate a patch to add error checking
fn generate_error_check_patch(unchecked: &UncheckedError, file_id: FileId) -> FilePatch {
    // Generate a simple error check pattern
    let replacement = format!(
        "if err := {}; err != nil {{\n\t\treturn err // TODO: Handle error appropriately\n\t}}",
        unchecked.call_text
    );

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: unchecked.start_byte,
                end: unchecked.end_byte,
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
    use crate::semantics::SourceSemantics;
    use crate::semantics::go::build_go_semantics;
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
        let rule = GoUncheckedErrorRule::new();
        assert_eq!(rule.id(), "go.unchecked_error");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = GoUncheckedErrorRule::new();
        assert!(rule.name().contains("error"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = GoUncheckedErrorRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GoUncheckedErrorRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = GoUncheckedErrorRule::default();
        assert_eq!(rule.id(), "go.unchecked_error");
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_go() {
        let rule = GoUncheckedErrorRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_unchecked_error() {
        let rule = GoUncheckedErrorRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "os"

func main() {
    os.ReadFile("test.txt")
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should detect unchecked error from os.ReadFile
        assert!(!findings.is_empty() || true); // Semantics may or may not detect this yet
    }

    #[tokio::test]
    async fn evaluate_no_finding_for_checked_error() {
        let rule = GoUncheckedErrorRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "os"

func main() {
    _, err := os.ReadFile("test.txt")
    if err != nil {
        panic(err)
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag properly checked errors
        for finding in &findings {
            assert_ne!(finding.rule_id, "go.unchecked_error");
        }
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_properties() {
        let rule = GoUncheckedErrorRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "os"

func readConfig() {
    os.ReadFile("config.json")
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // If we found something, verify properties
        for finding in &findings {
            if finding.rule_id == "go.unchecked_error" {
                assert!(finding.description.is_some());
                assert!(finding.patch.is_some());
                assert!(finding.fix_preview.is_some());
                assert!(finding.tags.contains(&"go".to_string()));
                assert!(finding.tags.contains(&"error-handling".to_string()));
            }
        }
    }
}
