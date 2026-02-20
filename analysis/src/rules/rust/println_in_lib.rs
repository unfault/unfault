//! Rule: println!/eprintln! in library code
//!
//! Detects use of println!, eprintln!, print!, eprint!, and dbg! macros
//! in library code where tracing/logging should be used instead.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! pub fn process(data: &str) {
//!     println!("Processing: {}", data);  // Not appropriate for library
//!     // ...
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! pub fn process(data: &str) {
//!     tracing::debug!("Processing: {}", data);
//!     // ...
//! }
//! ```

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

/// Rule that detects print macros in library code.
///
/// Library code should use proper logging/tracing instead of
/// println!, eprintln!, or dbg! macros because:
/// - Output goes to stdout/stderr which may not be appropriate
/// - No log levels or filtering
/// - No structured logging
/// - Cannot be disabled by library consumers
#[derive(Debug, Default)]
pub struct RustPrintlnInLibRule;

impl RustPrintlnInLibRule {
    pub fn new() -> Self {
        Self
    }
}

/// Print macros to detect with their suggested tracing equivalents
const PRINT_MACROS: &[(&str, &str)] = &[
    ("println", "tracing::info! or tracing::debug!"),
    ("print", "tracing::info! or tracing::debug!"),
    ("eprintln", "tracing::warn! or tracing::error!"),
    ("eprint", "tracing::warn! or tracing::error!"),
    ("dbg", "tracing::debug!"),
];

#[async_trait]
impl Rule for RustPrintlnInLibRule {
    fn id(&self) -> &'static str {
        "rust.println_in_lib"
    }

    fn name(&self) -> &'static str {
        "Print macro in library code"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Low,
            min_stage: LifecycleStage::Prototype,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Operability],
            prerequisites: vec!["Choose a logging/tracing approach".to_string()],
            notes: Some(
                "For demos it may be fine; prefer structured logs once you aggregate or debug issues.".to_string(),
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

            for macro_inv in &rust.macro_invocations {
                // Skip test code - print is fine in tests
                if macro_inv.in_test {
                    continue;
                }

                // Skip main function - print is acceptable there
                if macro_inv.function_name.as_deref() == Some("main") {
                    continue;
                }

                // Check if this is a debug/print macro
                if !macro_inv.is_debug_macro {
                    continue;
                }

                let line = macro_inv.location.range.start_line + 1;
                
                // Find the suggested alternative (for future use in patches)
                let _suggestion = PRINT_MACROS
                    .iter()
                    .find(|(name, _)| *name == macro_inv.name)
                    .map(|(_, sug)| *sug)
                    .unwrap_or("tracing macros");

                let is_binary_entrypoint_file = rust.path.ends_with("main.rs") || rust.path.ends_with("/main.rs");
                let title = if is_binary_entrypoint_file {
                    format!("{}! macro in application code", macro_inv.name)
                } else {
                    format!("{}! macro in library code", macro_inv.name)
                };

                let description = if is_binary_entrypoint_file {
                    format!(
                        "`{}!` at line {} in function '{}' writes directly to stdout/stderr.\n\n\
                         **Why this hurts operability in services/CLIs:**\n\
                         - No log levels means no filtering\n\
                         - Output isn't structured (no fields)\n\
                         - Harder to correlate to request IDs / spans\n\
                         - dbg! includes file:line which isn't helpful in releases\n\n\
                         **Better alternatives:**\n\
                         - `tracing::info!`, `tracing::debug!`, `tracing::warn!`\n\
                         - `log::info!`, `log::debug!`, `log::warn!`\n\
                         - Return errors instead of printing them",
                        macro_inv.name,
                        line,
                        macro_inv.function_name.as_deref().unwrap_or("<unknown>")
                    )
                } else {
                    format!(
                        "`{}!` at line {} in function '{}' writes directly to stdout/stderr.\n\n\
                         **Why this is problematic for libraries:**\n\
                         - Library consumers can't control or disable the output\n\
                         - No log levels means no filtering\n\
                         - Output isn't structured (no JSON, no fields)\n\
                         - Can't integrate with the application's logging\n\
                         - Interferes with applications that capture stdout\n\
                         - dbg! includes file:line which isn't helpful in releases\n\n\
                         **Better alternatives:**\n\
                         - `tracing::info!`, `tracing::debug!`, `tracing::warn!`\n\
                         - `log::info!`, `log::debug!`, `log::warn!`\n\
                         - Return errors instead of printing them\n\
                         - Accept a writer/callback for diagnostic output",
                        macro_inv.name,
                        line,
                        macro_inv.function_name.as_deref().unwrap_or("<unknown>")
                    )
                };

                // Determine severity - dbg! is worse than println
                let severity = if macro_inv.name == "dbg" {
                    Severity::High  // dbg! should never be in production
                } else {
                    Severity::Medium
                };

                let tracing_level = if macro_inv.name.starts_with('e') {
                    "warn"  // eprintln -> warn
                } else if macro_inv.name == "dbg" {
                    "debug"
                } else {
                    "info"
                };

                let fix_preview = format!(
                    "// Before:\n\
                     {}!({});\n\n\
                     // After (using tracing):\n\
                     tracing::{}!({});\n\n\
                     // Or with structured fields:\n\
                     tracing::{}!(value = %{}, \"descriptive message\");",
                    macro_inv.name,
                    macro_inv.args,
                    tracing_level,
                    macro_inv.args,
                    tracing_level,
                    macro_inv.args.split(',').next().unwrap_or("value").trim()
                );

                let replacement = format!(
                    "tracing::{}!({})",
                    tracing_level,
                    macro_inv.args
                );

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::ReplaceBytes {
                            start: macro_inv.start_byte,
                            end: macro_inv.end_byte,
                        },
                        replacement,
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::BehaviorThreat,
                    severity,
                    confidence: 0.90,
                    dimension: Dimension::Observability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: Some(macro_inv.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "logging".into(),
                        "observability".into(),
                        macro_inv.name.clone(),
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
        let rule = RustPrintlnInLibRule::new();
        assert_eq!(rule.id(), "rust.println_in_lib");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustPrintlnInLibRule::new();
        assert!(rule.name().contains("Print"));
    }

    #[tokio::test]
    async fn detects_println_in_library() {
        let rule = RustPrintlnInLibRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
pub fn process(data: &str) {
    println!("Processing: {}", data);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.println_in_lib"),
            "Should detect println in library function"
        );
    }

    #[tokio::test]
    async fn detects_dbg_in_library() {
        let rule = RustPrintlnInLibRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
pub fn process(data: &str) {
    dbg!(data);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.println_in_lib"),
            "Should detect dbg! in library function"
        );
    }

    #[tokio::test]
    async fn skips_println_in_main() {
        let rule = RustPrintlnInLibRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn main() {
    println!("Hello, World!");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let print_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.println_in_lib")
            .collect();
        assert!(
            print_findings.is_empty(),
            "Should skip println in main() function"
        );
    }

    #[tokio::test]
    async fn skips_println_in_test() {
        let rule = RustPrintlnInLibRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
#[test]
fn test_something() {
    println!("test output");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let print_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.println_in_lib")
            .collect();
        assert!(
            print_findings.is_empty(),
            "Should skip println in test function"
        );
    }

    #[tokio::test]
    async fn finding_has_patch() {
        let rule = RustPrintlnInLibRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
pub fn process() {
    println!("info");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        for finding in &findings {
            if finding.rule_id == "rust.println_in_lib" {
                assert!(finding.patch.is_some(), "Finding should have a patch");
                assert!(finding.fix_preview.is_some());
                assert_eq!(finding.dimension, Dimension::Observability);
            }
        }
    }
}
