//! Rule: Missing structured logging detection
//!
//! Detects usage of unstructured logging (print!, log!) instead of
//! structured logging with tracing spans and fields.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! fn process_order(order_id: u64) {
//!     log::info!("Processing order {}", order_id);  // Unstructured
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! #[tracing::instrument]
//! fn process_order(order_id: u64) {
//!     tracing::info!(order_id, "Processing order");  // Structured
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
use crate::types::finding::{FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects missing structured logging.
///
/// Unstructured logs are difficult to search, filter, and aggregate.
/// Structured logging with tracing enables powerful observability.
#[derive(Debug, Default)]
pub struct RustMissingStructuredLoggingRule;

impl RustMissingStructuredLoggingRule {
    pub fn new() -> Self {
        Self
    }
}

/// Patterns indicating unstructured logging
const UNSTRUCTURED_LOG_PATTERNS: &[&str] = &[
    "println!",
    "print!",
    "eprintln!",
    "eprint!",
    "log::info!",
    "log::debug!",
    "log::warn!",
    "log::error!",
    "log::trace!",
    "info!",
    "debug!",
    "warn!",
    "error!",
    "trace!",
];

/// Patterns indicating structured logging is in use
const STRUCTURED_LOG_PATTERNS: &[&str] = &[
    "tracing::",
    "#[instrument]",
    "#[tracing::instrument]",
    "tracing::info!",
    "tracing::debug!",
    "tracing::warn!",
    "tracing::error!",
    "tracing::trace!",
    "slog::",
    "structured_logger",
];

#[async_trait]
impl Rule for RustMissingStructuredLoggingRule {
    fn id(&self) -> &'static str {
        "rust.missing_structured_logging"
    }

    fn name(&self) -> &'static str {
        "Missing structured logging prevents effective observability"
    }

    fn applicability(&self) -> Option<crate::types::finding::FindingApplicability> {
        Some(crate::rules::applicability_defaults::structured_logging())
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

            // Check if structured logging is already used in the file
            let uses_structured = rust.uses.iter().any(|u| {
                STRUCTURED_LOG_PATTERNS.iter().any(|p| u.path.contains(p))
            }) || rust.macro_invocations.iter().any(|m| {
                STRUCTURED_LOG_PATTERNS.iter().any(|p| m.name.contains(p))
            });

            // If already using tracing, check for mixed usage
            if uses_structured {
                // Look for unstructured logs mixed with tracing
                for macro_inv in &rust.macro_invocations {
                    if macro_inv.in_test {
                        continue;
                    }

                    // Check for log:: macros (mixed with tracing)
                    if macro_inv.name.starts_with("log::")
                        || (["info", "debug", "warn", "error", "trace"]
                            .contains(&macro_inv.name.as_str())
                            && !macro_inv.name.contains("tracing"))
                    {
                        let line = macro_inv.location.range.start_line + 1;

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: format!(
                                "Mixed logging: '{}' used alongside tracing",
                                macro_inv.name
                            ),
                            description: Some(format!(
                                "The log macro '{}' at line {} is used alongside tracing.\n\
                                Mixing log frameworks can cause:\n\
                                - Inconsistent log formatting\n\
                                - Missing span context in log:: calls\n\
                                - Confusion in log aggregation systems\n\n\
                                Use `tracing::{}` instead for consistency.",
                                macro_inv.name, line,
                                macro_inv.name.replace("log::", "")
                            )),
                            kind: FindingKind::AntiPattern,
                            severity: Severity::Low,
                            confidence: 0.80,
                            dimension: Dimension::Observability,
                            file_id: *file_id,
                            file_path: rust.path.clone(),
                            line: Some(line),
                            column: Some(macro_inv.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::ReplaceBytes {
                                        start: macro_inv.start_byte,
                                        end: macro_inv.end_byte,
                                    },
                                    replacement: format!(
                                        "tracing::{}!({})",
                                        macro_inv.name.replace("log::", ""),
                                        macro_inv.args
                                    ),
                                }],
                            }),
                            fix_preview: None,
                            tags: vec![
                                "rust".into(),
                                "logging".into(),
                                "observability".into(),
                            ],
                        });
                    }
                }
            } else {
                // Not using tracing at all - check for any logging
                let has_logging = rust.macro_invocations.iter().any(|m| {
                    !m.in_test && UNSTRUCTURED_LOG_PATTERNS.iter().any(|p| m.name == *p || m.name.starts_with(p))
                });

                if has_logging {
                    // File-level finding to suggest tracing adoption
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "File uses unstructured logging instead of tracing".to_string(),
                        description: Some(
                            "This file uses log macros without tracing instrumentation.\n\n\
                            **Why structured logging matters:**\n\
                            - Searchable fields: `order_id=123` vs parsing \"order 123\"\n\
                            - Automatic span context propagation\n\
                            - Better support in log aggregation (Datadog, Loki, etc.)\n\
                            - Consistent JSON output for log pipelines\n\n\
                            **Migration path:**\n\
                            1. Add `tracing` and `tracing-subscriber` dependencies\n\
                            2. Replace `log::info!(\"msg {}\", val)` with `tracing::info!(val, \"msg\")`\n\
                            3. Add `#[tracing::instrument]` to functions".to_string()
                        ),
                        kind: FindingKind::AntiPattern,
                        severity: Severity::Low,
                        confidence: 0.70,
                        dimension: Dimension::Observability,
                        file_id: *file_id,
                        file_path: rust.path.clone(),
                        line: Some(1),
                        column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line: 1 },
                                replacement: "use tracing::{info, debug, warn, error, instrument};\n".to_string(),
                            }],
                        }),
                        fix_preview: Some(
                            r#"// Add to Cargo.toml:
tracing = "0.1"
tracing-subscriber = "0.3"

// Replace:
log::info!("Processing order {}", order_id);

// With:
tracing::info!(order_id, "Processing order");

// Add to functions:
#[tracing::instrument]
fn process_order(order_id: u64) {
    // logs automatically include function context
}"#.to_string()
                        ),
                        tags: vec![
                            "rust".into(),
                            "logging".into(),
                            "tracing".into(),
                            "observability".into(),
                        ],
                    });
                }
            }

            // Check for printf-style formatting in any log (even tracing)
            for macro_inv in &rust.macro_invocations {
                if macro_inv.in_test {
                    continue;
                }

                // Check for format string interpolation in log args
                if macro_inv.args.contains("{}") && 
                   (macro_inv.name.contains("info") || 
                    macro_inv.name.contains("debug") ||
                    macro_inv.name.contains("warn") ||
                    macro_inv.name.contains("error"))
                {
                    // This is fine for message, but check if values should be fields
                    let has_potential_fields = macro_inv.args.contains("user")
                        || macro_inv.args.contains("id")
                        || macro_inv.args.contains("request")
                        || macro_inv.args.contains("order")
                        || macro_inv.args.contains("error")
                        || macro_inv.args.contains("count");

                    if has_potential_fields && !macro_inv.args.contains(" = ") {
                        let line = macro_inv.location.range.start_line + 1;

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Log with interpolation could use structured fields".to_string(),
                            description: Some(format!(
                                "The log at line {} uses format interpolation. Consider using \
                                structured fields for better searchability:\n\n\
                                `tracing::info!(user_id, \"Message\")` instead of \
                                `tracing::info!(\"Message {{}}\", user_id)`",
                                line
                            )),
                            kind: FindingKind::AntiPattern,
                            severity: Severity::Low,
                            confidence: 0.60,
                            dimension: Dimension::Observability,
                            file_id: *file_id,
                            file_path: rust.path.clone(),
                            line: Some(line),
                            column: Some(macro_inv.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: None,
                            fix_preview: None,
                            tags: vec![
                                "rust".into(),
                                "logging".into(),
                                "structured".into(),
                            ],
                        });
                    }
                }
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
            path: "logging_code.rs".to_string(),
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
        let rule = RustMissingStructuredLoggingRule::new();
        assert_eq!(rule.id(), "rust.missing_structured_logging");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustMissingStructuredLoggingRule::new();
        assert!(rule.name().contains("logging"));
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = RustMissingStructuredLoggingRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn unstructured_log_patterns_are_valid() {
        for pattern in UNSTRUCTURED_LOG_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[test]
    fn structured_log_patterns_are_valid() {
        for pattern in STRUCTURED_LOG_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[tokio::test]
    async fn no_finding_for_code_without_logging() {
        let rule = RustMissingStructuredLoggingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn compute(x: i32) -> i32 {
    x + 1
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}
