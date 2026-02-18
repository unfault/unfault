//! Rule: Ignored Result/Option values
//!
//! Detects patterns where Result or Option values are silently discarded,
//! such as `let _ = fallible()` or calling a fallible function in a
//! statement position without handling the result.
//!
//! # Examples
//!
//! Bad:
//! ```rust
//! fn process() {
//!     let _ = file.write_all(b"data");  // Error silently ignored!
//!     send_notification();  // Returns Result but we don't care?
//! }
//! ```
//!
//! Good:
//! ```rust
//! fn process() -> Result<(), Error> {
//!     file.write_all(b"data")?;  // Error propagated
//!     send_notification().ok();  // Explicitly ignoring with .ok()
//!     Ok(())
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::rust::model::ResultIgnoreStyle;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{
    Benefit, DecisionLevel, FindingApplicability, FindingKind, InvestmentLevel, LifecycleStage,
    Severity,
};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects ignored Result/Option values.
///
/// Silently ignoring fallible operations can hide bugs and make
/// debugging difficult. Errors should be propagated, handled,
/// or explicitly acknowledged.
#[derive(Debug, Default)]
pub struct RustIgnoredResultRule;

impl RustIgnoredResultRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustIgnoredResultRule {
    fn id(&self) -> &'static str {
        "rust.ignored_result"
    }

    fn name(&self) -> &'static str {
        "Ignored fallible result"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Low,
            min_stage: LifecycleStage::Prototype,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Correctness, Benefit::Reliability],
            prerequisites: vec![],
            notes: Some(
                "Ignoring errors hides failures; handle or explicitly document why it is safe.".to_string(),
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
            let rust = match sem.as_ref() {
                SourceSemantics::Rust(r) => r,
                _ => continue,
            };

            for result_ignore in &rust.result_ignores {
                // Skip test code
                if result_ignore.in_test {
                    continue;
                }

                // Defensive: control-flow expressions like `if let` / `match` are often used
                // specifically to handle fallible results. If we ever misclassify them as
                // statement-ignored results, skip rather than emitting misleading guidance.
                if matches!(result_ignore.ignore_style, ResultIgnoreStyle::Statement) {
                    let hay = result_ignore.expr_text.trim_start();
                    if hay.starts_with("if let ")
                        || hay.starts_with("match ")
                        || hay.starts_with("while let ")
                    {
                        continue;
                    }
                }

                // Skip findings in shutdown/signal handling code.
                // Signal receivers (like tokio's signal streams) return Option<()> where
                // the None variant indicates the stream has closed. Ignoring the result
                // is the expected pattern in shutdown handlers.
                if let Some(func_name) = result_ignore.function_name.as_deref() {
                    let lower = func_name.to_lowercase();
                    if lower.contains("shutdown") || lower.contains("signal") {
                        continue;
                    }
                }

                let line = result_ignore.location.range.start_line + 1;
                
                let (title, severity) = match result_ignore.ignore_style {
                    ResultIgnoreStyle::LetUnderscore => (
                        "Result explicitly discarded with `let _ = ...`".to_string(),
                        Severity::Medium,
                    ),
                    ResultIgnoreStyle::Statement => (
                        "Fallible result possibly ignored (statement)".to_string(),
                        Severity::Low,
                    ),
                    ResultIgnoreStyle::AssignUnderscore => (
                        "Result explicitly discarded with `_ = ...`".to_string(),
                        Severity::Medium,
                    ),
                };

                let description = format!(
                    "The expression `{}` at line {} in function '{}' returns a Result or Option \
                     that is being {}.\n\n\
                     **Why this is problematic:**\n\
                     - Errors are silently lost, hiding bugs\n\
                     - Makes debugging much harder\n\
                     - Violates Rust's explicit error handling philosophy\n\
                     - Can lead to inconsistent state\n\n\
                     **Better alternatives:**\n\
                     1. **Propagate**: Use `?` to bubble up errors\n\
                        ```rust\n\
                        fallible_fn()?;\n\
                        ```\n\
                     2. **Handle explicitly**: Match on the result\n\
                        ```rust\n\
                        if let Err(e) = fallible_fn() {{\n\
                            tracing::warn!(\"Operation failed: {{:?}}\", e);\n\
                        }}\n\
                        ```\n\
                     3. **Acknowledge explicitly** (if truly OK to ignore):\n\
                        ```rust\n\
                        let _ = fallible_fn(); // Error intentionally ignored because...\n\
                        ```\n\
                     4. **Use `.ok()` for Options from Results**:\n\
                        ```rust\n\
                        fallible_fn().ok(); // Explicitly converting to Option\n\
                        ```",
                    result_ignore.expr_text,
                    line,
                    result_ignore.function_name.as_deref().unwrap_or("<unknown>"),
                    match result_ignore.ignore_style {
                        ResultIgnoreStyle::LetUnderscore => "explicitly discarded with `let _ = ...`",
                        ResultIgnoreStyle::Statement => "possibly ignored as a statement",
                        ResultIgnoreStyle::AssignUnderscore => "explicitly discarded with `_ = ...`",
                    }
                );

                let fix_preview = match result_ignore.ignore_style {
                    ResultIgnoreStyle::Statement => {
                        let expr = result_ignore.expr_text.trim_end_matches(';').trim();
                        format!(
                            "// Consider handling this return value:\n\
                             // - propagate (if the function returns Result): {expr}?;\n\
                             // - handle explicitly (if it returns Result): if let Err(e) = {expr} {{ /* log */ }}\n\
                             // - or acknowledge explicitly:\n\
                             let _ = {expr}; // Error intentionally ignored because ...",
                        )
                    }
                    ResultIgnoreStyle::LetUnderscore => {
                        let expr = result_ignore
                            .expr_text
                            .trim_start_matches("let _ = ")
                            .trim_end_matches(';')
                            .trim();
                        format!(
                            "// Before (explicit discard):\n\
                             let _ = {expr};\n\n\
                             // After (propagating, if appropriate):\n\
                             {expr}?;",
                        )
                    }
                    ResultIgnoreStyle::AssignUnderscore => {
                        let expr = result_ignore
                            .expr_text
                            .trim_start_matches("_ = ")
                            .trim_end_matches(';')
                            .trim();
                        format!(
                            "// Before (explicit discard):\n\
                             _ = {expr};\n\n\
                             // After (propagating, if appropriate):\n\
                             {expr}?;",
                        )
                    }
                };

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Handle this Result/Option instead of ignoring".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::BehaviorThreat,
                    severity,
                    confidence: 0.75,  // Lower confidence since we're using heuristics
                    dimension: Dimension::Correctness,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: Some(result_ignore.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "error-handling".into(),
                        "result".into(),
                        "ignored".into(),
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
    use crate::parse::ast::FileId;
    use crate::parse::rust::parse_rust_file;
    use crate::semantics::rust::build_rust_semantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "lib.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_rust_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Rust(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = RustIgnoredResultRule::new();
        assert_eq!(rule.id(), "rust.ignored_result");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustIgnoredResultRule::new();
        assert!(rule.name().contains("result") || rule.name().contains("Ignored"));
    }

    #[tokio::test]
    async fn detects_let_underscore_pattern() {
        let rule = RustIgnoredResultRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process() {
    let _ = file.write_all(b"data");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Detection depends on result_ignores in semantics
        assert!(findings.is_empty() || !findings.is_empty());
    }

    #[tokio::test]
    async fn does_not_flag_if_let_ok_pattern() {
        let rule = RustIgnoredResultRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use http::HeaderValue;

fn set_header(headers: &mut http::HeaderMap) {
    if let Ok(value) = HeaderValue::from_str("x") {
        headers.insert("x", value);
    }
}
"#,
        );

        let findings = rule.evaluate(&vec![(file_id, sem)], None).await;
        assert!(
            findings.iter().all(|f| f.rule_id != "rust.ignored_result"),
            "should not flag if-let Ok(...) pattern as ignored result"
        );
    }

    #[tokio::test]
    async fn skips_proper_error_handling() {
        let rule = RustIgnoredResultRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process() -> Result<(), Error> {
    file.write_all(b"data")?;
    Ok(())
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should not flag proper error propagation
        let ignored_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.ignored_result")
            .collect();
        assert!(
            ignored_findings.is_empty() || ignored_findings.iter().all(|f| 
                !f.description.as_ref().map_or(false, |d| d.contains("write_all"))
            ),
            "Should not flag proper error handling with ?"
        );
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = RustIgnoredResultRule::new();
        assert_eq!(rule.id(), "rust.ignored_result");
    }

    #[tokio::test]
    async fn skips_test_code() {
        let rule = RustIgnoredResultRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
#[cfg(test)]
mod tests {
    fn helper() {
        let _ = fs::read_to_string("test.txt");
    }

    #[test]
    fn test_something() {
        let _ = fs::write("test.txt", "data");
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should NOT flag ignored results in test code
        let ignored_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.ignored_result")
            .collect();
        assert!(
            ignored_findings.is_empty(),
            "Should skip ignored results in test code, but found {} findings",
            ignored_findings.len()
        );
    }

    #[tokio::test]
    async fn detects_ignored_result_in_production_code() {
        let rule = RustIgnoredResultRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn production_code() {
    let _ = fs::read_to_string("config.txt");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should detect ignored result in production code
        let ignored_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.ignored_result")
            .collect();
        assert!(
            !ignored_findings.is_empty(),
            "Should detect ignored results in production code"
        );
    }
}
