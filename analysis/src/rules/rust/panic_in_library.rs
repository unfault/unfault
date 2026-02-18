//! Rule: Panic in library code detection
//!
//! Detects panic!() macro and related panicking functions in library code
//! (non-main, non-test). Libraries should return Result/Option instead.
//!
//! # Examples
//!
//! Bad:
//! ```rust
//! pub fn parse(input: &str) -> Config {
//!     if input.is_empty() {
//!         panic!("input cannot be empty");  // Will crash the application
//!     }
//!     // ...
//! }
//! ```
//!
//! Good:
//! ```rust
//! pub fn parse(input: &str) -> Result<Config, ParseError> {
//!     if input.is_empty() {
//!         return Err(ParseError::EmptyInput);
//!     }
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
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects panic usage in library code.
///
/// Library code should return errors through Result/Option instead of
/// panicking. Panics take away error handling decisions from callers
/// and can crash the entire application.
#[derive(Debug, Default)]
pub struct RustPanicInLibraryRule;

impl RustPanicInLibraryRule {
    pub fn new() -> Self {
        Self
    }
}

/// Panic macros to detect
const PANIC_MACROS: &[&str] = &[
    "panic",
    "unreachable",
    "unimplemented",
    "todo",
];

#[async_trait]
impl Rule for RustPanicInLibraryRule {
    fn id(&self) -> &'static str {
        "rust.panic_in_library"
    }

    fn name(&self) -> &'static str {
        "Panic in library code"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
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

            // Look for panic macros in non-test, non-main code
            for macro_inv in &rust.macro_invocations {
                // Skip test code
                if macro_inv.in_test {
                    continue;
                }

                // Skip if in main function
                if macro_inv.function_name.as_deref() == Some("main") {
                    continue;
                }

                // Check if this is a panic macro
                let is_panic_macro = PANIC_MACROS.contains(&macro_inv.name.as_str());
                if !is_panic_macro {
                    continue;
                }

                let line = macro_inv.location.range.start_line + 1;
                
                // Different severity for different macros
                let (severity, message) = match macro_inv.name.as_str() {
                    "panic" => (
                        Severity::High,
                        "panic!() will crash the application. Return Result/Option instead.",
                    ),
                    "unreachable" => (
                        Severity::Medium,
                        "unreachable!() indicates a logic error. Consider using Result to handle this case.",
                    ),
                    "unimplemented" | "todo" => (
                        Severity::Medium,
                        "unimplemented!/todo! will panic at runtime. These should not be in production code.",
                    ),
                    _ => (
                        Severity::Medium,
                        "This macro may panic at runtime.",
                    ),
                };

                let title = format!(
                    "{}!() in library code may crash application",
                    macro_inv.name
                );

                let description = format!(
                    "{}!() at line {} in function '{}' will panic if reached.\n\n\
                     {}\n\n\
                     **Why this is problematic:**\n\
                     - Panics are unrecoverable in most Rust code\n\
                     - Callers have no opportunity to handle the error\n\
                     - In async code, panics can crash the entire runtime\n\
                     - Library code should be defensive and return errors\n\n\
                     **Suggested alternatives:**\n\
                     - Return `Result<T, E>` with a descriptive error type\n\
                     - Return `Option<T>` for optional values\n\
                     - Use `debug_assert!()` for invariants (only panics in debug builds)\n\
                     - Document panic conditions if truly unavoidable",
                    macro_inv.name,
                    line,
                    macro_inv.function_name.as_deref().unwrap_or("<unknown>"),
                    message
                );

                let fix_preview = match macro_inv.name.as_str() {
                    "panic" => format!(
                        "// Before:\n\
                         {}!({});\n\n\
                         // After:\n\
                         return Err(Error::new({}));",
                        macro_inv.name, macro_inv.args, macro_inv.args
                    ),
                    "unreachable" => format!(
                        "// Before:\n\
                         {}!({});\n\n\
                         // After (if truly unreachable):\n\
                         unsafe {{ std::hint::unreachable_unchecked() }}\n\n\
                         // Or better, handle the case:\n\
                         return Err(Error::UnexpectedState);",
                        macro_inv.name, macro_inv.args
                    ),
                    _ => format!(
                        "// Before:\n\
                         {}!({});\n\n\
                         // After:\n\
                         return Err(Error::NotImplemented);",
                        macro_inv.name, macro_inv.args
                    ),
                };

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: format!(
                            "// TODO: Return error instead of panicking\n\
                             // return Err(Error::new({}))",
                            macro_inv.args
                        ),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity,
                    confidence: 0.90,
                    dimension: Dimension::Stability,
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
                        "panic".into(),
                        "error-handling".into(),
                        "stability".into(),
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
        let rule = RustPanicInLibraryRule::new();
        assert_eq!(rule.id(), "rust.panic_in_library");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustPanicInLibraryRule::new();
        assert!(rule.name().contains("Panic"));
    }

    #[tokio::test]
    async fn detects_panic_in_library_function() {
        let rule = RustPanicInLibraryRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
pub fn process(x: i32) -> i32 {
    if x < 0 {
        panic!("x must be positive");
    }
    x * 2
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.panic_in_library"),
            "Should detect panic in library function"
        );
    }

    #[tokio::test]
    async fn detects_todo_macro() {
        let rule = RustPanicInLibraryRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
pub fn process() -> String {
    todo!("implement this")
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.panic_in_library"),
            "Should detect todo! macro"
        );
    }

    #[tokio::test]
    async fn detects_unimplemented_macro() {
        let rule = RustPanicInLibraryRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
pub fn process() {
    unimplemented!()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.panic_in_library"),
            "Should detect unimplemented! macro"
        );
    }

    #[tokio::test]
    async fn skips_panic_in_main() {
        let rule = RustPanicInLibraryRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn main() {
    panic!("fatal error");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let panic_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.panic_in_library")
            .collect();
        assert!(
            panic_findings.is_empty(),
            "Should skip panic in main() function"
        );
    }

    #[tokio::test]
    async fn skips_panic_in_test() {
        let rule = RustPanicInLibraryRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
#[test]
fn test_something() {
    panic!("test panic");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let panic_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.panic_in_library")
            .collect();
        assert!(
            panic_findings.is_empty(),
            "Should skip panic in test function"
        );
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = RustPanicInLibraryRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
pub fn process() {
    panic!("error");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        for finding in &findings {
            if finding.rule_id == "rust.panic_in_library" {
                assert!(finding.patch.is_some());
                assert!(finding.fix_preview.is_some());
                assert!(finding.tags.contains(&"rust".to_string()));
                assert!(finding.tags.contains(&"panic".to_string()));
                assert_eq!(finding.dimension, Dimension::Stability);
            }
        }
    }
}