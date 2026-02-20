//! Rule: Naive datetime without timezone detection
//!
//! Detects usage of chrono's NaiveDateTime or time's PrimitiveDateTime
//! without timezone awareness, which can cause subtle bugs.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! use chrono::NaiveDateTime;
//!
//! fn get_timestamp() -> NaiveDateTime {
//!     chrono::Utc::now().naive_utc()  // Losing timezone info
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! use chrono::{DateTime, Utc};
//!
//! fn get_timestamp() -> DateTime<Utc> {
//!     chrono::Utc::now()  // Timezone-aware
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

/// Rule that detects naive datetime usage.
///
/// Naive datetimes (without timezone) cause subtle bugs when:
/// - Servers are in different timezones
/// - Daylight saving time transitions occur
/// - Data is stored/retrieved from databases
#[derive(Debug, Default)]
pub struct RustNaiveDatetimeRule;

impl RustNaiveDatetimeRule {
    pub fn new() -> Self {
        Self
    }
}

/// Patterns indicating naive datetime usage
const NAIVE_DATETIME_PATTERNS: &[(&str, &str)] = &[
    ("NaiveDateTime", "DateTime<Utc>"),
    ("NaiveDate", "Date (with timezone context)"),
    ("NaiveTime", "Time (with timezone context)"),
    (".naive_utc()", "keep as DateTime<Utc>"),
    (".naive_local()", "keep as DateTime<Local> or DateTime<Utc>"),
    ("PrimitiveDateTime", "OffsetDateTime"),
    ("chrono::Local::now().naive_local()", "chrono::Utc::now()"),
];

/// Safe timezone-aware patterns
const SAFE_DATETIME_PATTERNS: &[&str] = &[
    "DateTime<Utc>",
    "DateTime<FixedOffset>",
    "DateTime<Local>",
    "OffsetDateTime",
    "Utc::now()",
    "chrono::Utc",
    "time::OffsetDateTime",
];

#[async_trait]
impl Rule for RustNaiveDatetimeRule {
    fn id(&self) -> &'static str {
        "rust.naive_datetime"
    }

    fn name(&self) -> &'static str {
        "Naive datetime without timezone can cause subtle bugs"
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

            // Check imports for naive datetime types
            for use_stmt in &rust.uses {
                let path = &use_stmt.path;

                for (pattern, alternative) in NAIVE_DATETIME_PATTERNS {
                    if path.contains(pattern) {
                        let line = use_stmt.location.range.start_line + 1;

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: format!("Import of naive datetime type: {}", pattern),
                            description: Some(format!(
                                "The import `{}` at line {} brings in a naive datetime type \
                                without timezone information.\n\n\
                                **Why this is problematic:**\n\
                                - Ambiguous in distributed systems\n\
                                - Incorrect across server timezones\n\
                                - DST bugs twice per year\n\
                                - Database storage issues\n\n\
                                **Recommendation:** Use `{}` instead.",
                                path, line, alternative
                            )),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Medium,
                            confidence: 0.80,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: rust.path.clone(),
                            line: Some(line),
                            column: Some(use_stmt.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: None,
                            fix_preview: Some(format!(
                                "// Replace:\n\
                                use chrono::{};\n\n\
                                // With:\n\
                                use chrono::{{DateTime, Utc}};",
                                pattern
                            )),
                            tags: vec![
                                "rust".into(),
                                "datetime".into(),
                                "timezone".into(),
                                "correctness".into(),
                            ],
                        });
                        break;
                    }
                }
            }

            // Check function signatures for naive return types
            for func in &rust.functions {
                if let Some(ref return_type) = func.return_type {
                    for (pattern, alternative) in NAIVE_DATETIME_PATTERNS {
                        if return_type.contains(pattern) {
                            let line = func.location.range.start_line + 1;

                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: format!(
                                    "Function '{}' returns naive datetime type",
                                    func.name
                                ),
                                description: Some(format!(
                                    "Function '{}' at line {} returns `{}` which lacks timezone info.\n\n\
                                    **Recommendation:** Return `{}` to ensure timezone awareness.",
                                    func.name, line, pattern, alternative
                                )),
                                kind: FindingKind::StabilityRisk,
                                severity: Severity::Medium,
                                confidence: 0.85,
                                dimension: Dimension::Correctness,
                                file_id: *file_id,
                                file_path: rust.path.clone(),
                                line: Some(line),
                                column: Some(func.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                                patch: None,
                                fix_preview: Some(format!(
                                    "// Before:\n\
                                    fn {}(...) -> {}\n\n\
                                    // After:\n\
                                    fn {}(...) -> DateTime<Utc>",
                                    func.name, return_type, func.name
                                )),
                                tags: vec![
                                    "rust".into(),
                                    "datetime".into(),
                                    "timezone".into(),
                                    "api".into(),
                                ],
                            });
                            break;
                        }
                    }
                }
            }

            // Check calls for naive datetime conversions
            for call in &rust.calls {
                let callee = &call.function_call.callee_expr;

                for (pattern, alternative) in NAIVE_DATETIME_PATTERNS {
                    if callee.contains(pattern) {
                        // Skip if file also uses safe patterns
                        let uses_safe = rust.calls.iter().any(|c| {
                            SAFE_DATETIME_PATTERNS.iter().any(|p| c.function_call.callee_expr.contains(p))
                        }) || rust.uses.iter().any(|u| {
                            SAFE_DATETIME_PATTERNS.iter().any(|p| u.path.contains(p))
                        });

                        // Lower severity if also using safe patterns
                        let severity = if uses_safe {
                            Severity::Low
                        } else {
                            Severity::Medium
                        };

                        let line = call.function_call.location.line;

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: format!("Naive datetime conversion: {}", pattern),
                            description: Some(format!(
                                "The call at line {} uses `{}` which strips timezone information.\n\n\
                                **Recommendation:** {}",
                                line, pattern, alternative
                            )),
                            kind: FindingKind::StabilityRisk,
                            severity,
                            confidence: 0.75,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: rust.path.clone(),
                            line: Some(line),
                            column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line },
                                    replacement: format!(
                                        "// TODO: Consider using timezone-aware datetime instead of {}\n",
                                        pattern
                                    ),
                                }],
                            }),
                            fix_preview: Some(format!(
                                "// Instead of:\n\
                                let dt = now.{};\n\n\
                                // Keep timezone:\n\
                                let dt = chrono::Utc::now();",
                                pattern
                            )),
                            tags: vec![
                                "rust".into(),
                                "datetime".into(),
                                "timezone".into(),
                            ],
                        });
                        break;
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
            path: "datetime_code.rs".to_string(),
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
        let rule = RustNaiveDatetimeRule::new();
        assert_eq!(rule.id(), "rust.naive_datetime");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustNaiveDatetimeRule::new();
        assert!(rule.name().contains("datetime"));
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = RustNaiveDatetimeRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn naive_datetime_patterns_are_valid() {
        for (pattern, alt) in NAIVE_DATETIME_PATTERNS {
            assert!(!pattern.is_empty());
            assert!(!alt.is_empty());
        }
    }

    #[test]
    fn safe_datetime_patterns_are_valid() {
        for pattern in SAFE_DATETIME_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[tokio::test]
    async fn no_finding_for_timezone_aware_code() {
        let rule = RustNaiveDatetimeRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use chrono::{DateTime, Utc};

fn get_timestamp() -> DateTime<Utc> {
    Utc::now()
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        
        // Should not flag timezone-aware datetime usage
        let naive_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.naive_datetime")
            .collect();
        assert!(naive_findings.is_empty());
    }
}