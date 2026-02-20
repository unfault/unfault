//! Rule: Functions without tracing instrumentation
//!
//! Detects public functions that lack tracing instrumentation,
//! which is important for observability in production systems.
//!
//! # Examples
//!
//! Missing instrumentation:
//! ```rust,ignore
//! pub async fn handle_request(req: Request) -> Response {
//!     // No tracing!
//!     process(req).await
//! }
//! ```
//!
//! Good (with tracing):
//! ```rust,ignore
//! #[tracing::instrument]
//! pub async fn handle_request(req: Request) -> Response {
//!     tracing::info!("Processing request");
//!     process(req).await
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::rust::model::Visibility;
use crate::types::context::Dimension;
use crate::types::finding::{FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects public functions without tracing instrumentation.
///
/// Tracing is essential for observability in production systems,
/// allowing developers to trace request flows and debug issues.
#[derive(Debug, Default)]
pub struct RustMissingTracingRule;

impl RustMissingTracingRule {
    pub fn new() -> Self {
        Self
    }
}

/// Check if a file uses the tracing crate
fn uses_tracing(rust: &crate::semantics::rust::model::RustFileSemantics) -> bool {
    rust.uses.iter().any(|u| u.path.contains("tracing"))
}

/// Check if function has tracing attribute
fn has_tracing_attribute(attributes: &[String]) -> bool {
    attributes.iter().any(|attr| {
        attr.contains("instrument")
            || attr.contains("tracing::instrument")
            || attr.contains("tracing_instrument")
    })
}

/// Check if function body contains tracing calls
fn has_tracing_calls(
    func_name: &str,
    rust: &crate::semantics::rust::model::RustFileSemantics,
) -> bool {
    rust.macro_invocations.iter().any(|m| {
        m.function_name.as_deref() == Some(func_name)
            && (m.name.starts_with("tracing::")
                || m.name == "info"
                || m.name == "debug"
                || m.name == "warn"
                || m.name == "error"
                || m.name == "trace"
                || m.name == "span"
                || m.name == "info_span"
                || m.name == "debug_span"
                || m.name == "warn_span"
                || m.name == "error_span")
    })
}

#[async_trait]
impl Rule for RustMissingTracingRule {
    fn id(&self) -> &'static str {
        "rust.missing_tracing"
    }

    fn name(&self) -> &'static str {
        "Public function without tracing instrumentation"
    }

    fn applicability(&self) -> Option<crate::types::finding::FindingApplicability> {
        Some(crate::rules::applicability_defaults::tracing())
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

            // Only check files that use tracing (it's opt-in)
            if !uses_tracing(rust) {
                continue;
            }

            for func in &rust.functions {
                // Skip tests
                if func.is_test {
                    continue;
                }

                // Skip main (usually has its own setup)
                if func.is_main {
                    continue;
                }

                // Only check public functions
                if !matches!(func.visibility, Visibility::Pub | Visibility::PubCrate) {
                    continue;
                }

                // Skip if has #[instrument] attribute
                if has_tracing_attribute(&func.attributes) {
                    continue;
                }

                // Skip if has tracing calls in body
                if has_tracing_calls(&func.name, rust) {
                    continue;
                }

                // Skip very short functions (getters, etc.)
                // TODO: Could add line count check

                let line = func.location.range.start_line + 1;

                // Higher severity for async functions (usually handlers)
                let severity = if func.is_async {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                let title = format!(
                    "Public {} function '{}' has no tracing",
                    if func.is_async { "async" } else { "sync" },
                    func.name
                );

                let description = format!(
                    "The public function '{}' at line {} has no tracing instrumentation.\n\n\
                     **Why this matters:**\n\
                     - Hard to trace request flow through the system\n\
                     - Difficult to debug production issues\n\
                     - Missing performance metrics\n\
                     - Incomplete distributed traces\n\n\
                     **Recommendations:**\n\
                     - Add `#[tracing::instrument]` attribute to the function\n\
                     - Or add explicit `tracing::info!()` / `tracing::debug!()` calls\n\
                     - Consider using spans for async work\n\n\
                     **Example:**\n\
                     ```rust\n\
                     #[tracing::instrument(skip(pool), err)]\n\
                     pub async fn get_user(id: i32, pool: &PgPool) -> Result<User> {{\n    \
                         tracing::debug!(\"Fetching user\");\n    \
                         // ...\n\
                     }}\n\
                     ```",
                    func.name, line
                );

                let fix_preview = format!(
                    "#[tracing::instrument]\n\
                     pub {}fn {}(...) {{\n    \
                         // function body\n\
                     }}",
                    if func.is_async { "async " } else { "" },
                    func.name
                );

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "#[tracing::instrument]".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::AntiPattern,
                    severity,
                    confidence: 0.70,
                    dimension: Dimension::Observability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec!["rust".into(), "observability".into(), "tracing".into()],
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
    use crate::semantics::SourceSemantics;
    use crate::semantics::rust::build_rust_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "tracing_code.rs".to_string(),
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
        let rule = RustMissingTracingRule::new();
        assert_eq!(rule.id(), "rust.missing_tracing");
    }

    #[test]
    fn rule_name_mentions_tracing() {
        let rule = RustMissingTracingRule::new();
        assert!(rule.name().to_lowercase().contains("tracing"));
    }

    #[tokio::test]
    async fn skips_files_without_tracing_import() {
        let rule = RustMissingTracingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
pub fn handle_request() {
    println!("hello");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let tracing_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.missing_tracing")
            .collect();
        assert!(
            tracing_findings.is_empty(),
            "Should skip files without tracing import"
        );
    }

    #[tokio::test]
    async fn detects_public_function_without_tracing() {
        let rule = RustMissingTracingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use tracing;

pub fn handle_request() {
    println!("hello");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.missing_tracing"),
            "Should detect public function without tracing"
        );
    }

    #[tokio::test]
    async fn skips_private_functions() {
        let rule = RustMissingTracingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use tracing;

fn private_helper() {
    println!("hello");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let tracing_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.missing_tracing")
            .collect();
        assert!(tracing_findings.is_empty(), "Should skip private functions");
    }

    #[tokio::test]
    async fn skips_test_functions() {
        let rule = RustMissingTracingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use tracing;

#[test]
pub fn test_something() {
    assert!(true);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let tracing_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.missing_tracing")
            .collect();
        assert!(tracing_findings.is_empty(), "Should skip test functions");
    }

    #[tokio::test]
    async fn finding_has_observability_dimension() {
        let rule = RustMissingTracingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use tracing;

pub fn handle_request() {
    println!("hello");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        for finding in &findings {
            if finding.rule_id == "rust.missing_tracing" {
                assert_eq!(finding.dimension, Dimension::Observability);
                assert!(finding.patch.is_some());
            }
        }
    }
}
