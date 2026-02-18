//! Rule B19: Naive datetime handling
//!
//! Detects usage of naive datetime objects (without timezone information)
//! which can lead to subtle bugs in scheduling, logging, and data corruption.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::{ImportInsertionType, PyImport};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Check if timezone is already imported from datetime
fn has_timezone_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| {
        // Check for `from datetime import timezone`
        (imp.module == "datetime" && imp.names.iter().any(|n| n == "timezone"))
            // Check for `import datetime` (can use datetime.timezone)
            || imp.module == "datetime" && imp.names.is_empty()
    })
}

/// Rule that detects naive datetime usage in Python code.
///
/// Naive datetime objects (without timezone information) can lead to:
/// - Silent data corruption when crossing timezone boundaries
/// - Scheduling bugs in distributed systems
/// - Incorrect timestamps in logs and databases
/// - DST-related issues
#[derive(Debug)]
pub struct PythonNaiveDatetimeRule;

impl PythonNaiveDatetimeRule {
    pub fn new() -> Self {
        Self
    }

    /// Check if a call is a naive datetime constructor
    fn is_naive_datetime_call(callee: &str, args: &[crate::semantics::python::model::PyCallArg]) -> Option<NaiveDatetimePattern> {
        match callee {
            // datetime.now() without timezone
            "datetime.now" | "datetime.datetime.now" => {
                // Check if tz argument is provided
                let has_tz = args.iter().any(|arg| {
                    arg.name.as_deref() == Some("tz") ||
                    arg.value_repr.contains("timezone") ||
                    arg.value_repr.contains("pytz") ||
                    arg.value_repr.contains("zoneinfo") ||
                    // Python 3.11+ datetime.UTC constant
                    arg.value_repr == "UTC" ||
                    arg.value_repr == "datetime.UTC"
                });
                if !has_tz {
                    Some(NaiveDatetimePattern::DatetimeNow)
                } else {
                    None
                }
            }
            // datetime.utcnow() - deprecated and always naive
            "datetime.utcnow" | "datetime.datetime.utcnow" => {
                Some(NaiveDatetimePattern::DatetimeUtcnow)
            }
            // datetime.today() - always naive
            "datetime.today" | "datetime.datetime.today" => {
                Some(NaiveDatetimePattern::DatetimeToday)
            }
            // date.today() is fine for dates, but datetime.today() is problematic
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum NaiveDatetimePattern {
    DatetimeNow,
    DatetimeUtcnow,
    DatetimeToday,
}

impl NaiveDatetimePattern {
    fn description(&self) -> &'static str {
        match self {
            NaiveDatetimePattern::DatetimeNow => "datetime.now() without timezone",
            NaiveDatetimePattern::DatetimeUtcnow => "datetime.utcnow() (deprecated)",
            NaiveDatetimePattern::DatetimeToday => "datetime.today() without timezone",
        }
    }

    fn fix_suggestion(&self) -> &'static str {
        match self {
            NaiveDatetimePattern::DatetimeNow => "datetime.now(timezone.utc)",
            NaiveDatetimePattern::DatetimeUtcnow => "datetime.now(timezone.utc)",
            NaiveDatetimePattern::DatetimeToday => "datetime.now(timezone.utc)",
        }
    }

    /// Generate the actual replacement code for the call expression
    fn generate_replacement(&self, callee: &str) -> String {
        match self {
            NaiveDatetimePattern::DatetimeNow => {
                // datetime.now() -> datetime.now(timezone.utc)
                // datetime.datetime.now() -> datetime.datetime.now(timezone.utc)
                if callee.starts_with("datetime.datetime") {
                    "datetime.datetime.now(timezone.utc)".to_string()
                } else {
                    "datetime.now(timezone.utc)".to_string()
                }
            }
            NaiveDatetimePattern::DatetimeUtcnow => {
                // datetime.utcnow() -> datetime.now(timezone.utc)
                // datetime.datetime.utcnow() -> datetime.datetime.now(timezone.utc)
                if callee.starts_with("datetime.datetime") {
                    "datetime.datetime.now(timezone.utc)".to_string()
                } else {
                    "datetime.now(timezone.utc)".to_string()
                }
            }
            NaiveDatetimePattern::DatetimeToday => {
                // datetime.today() -> datetime.now(timezone.utc)
                // datetime.datetime.today() -> datetime.datetime.now(timezone.utc)
                if callee.starts_with("datetime.datetime") {
                    "datetime.datetime.now(timezone.utc)".to_string()
                } else {
                    "datetime.now(timezone.utc)".to_string()
                }
            }
        }
    }
}

impl Default for PythonNaiveDatetimeRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonNaiveDatetimeRule {
    fn id(&self) -> &'static str {
        "python.naive_datetime"
    }

    fn name(&self) -> &'static str {
        "Datetime objects should include timezone information"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(error_handling_in_handler())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => continue,
            };

            // Use stdlib_from_import line for `from datetime import timezone`
            let import_line = py.import_insertion_line_for(ImportInsertionType::stdlib_from_import());
            
            // Check call sites for naive datetime patterns
            for call in &py.calls {
                if let Some(pattern) = Self::is_naive_datetime_call(&call.function_call.callee_expr, &call.args) {
                    let location = &call.function_call.location;

                    // Generate the actual replacement code
                    let replacement = pattern.generate_replacement(&call.function_call.callee_expr);

                    // Generate a proper patch with:
                    // 1. Import at the top of the file (only if not already imported)
                    // 2. Actual code replacement using byte positions
                    let mut hunks = Vec::new();
                    
                    // Only add import if timezone is not already imported
                    if !has_timezone_import(&py.imports) {
                        hunks.push(PatchHunk {
                            range: PatchRange::InsertBeforeLine { line: import_line },
                            replacement: "from datetime import timezone  # Added by unfault\n".to_string(),
                        });
                    }
                    
                    // Always add the replacement hunk
                    hunks.push(PatchHunk {
                        range: PatchRange::ReplaceBytes {
                            start: call.start_byte,
                            end: call.end_byte,
                        },
                        replacement: replacement.clone(),
                    });
                    
                    let file_patch = FilePatch {
                        file_id: *file_id,
                        hunks,
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: format!("Naive datetime: {}", pattern.description()),
                        description: Some(format!(
                            "The call `{}` creates a naive datetime object without timezone information.\n\n\
                             Naive datetimes can cause:\n\
                             - Silent data corruption when crossing timezone boundaries\n\
                             - Scheduling bugs in distributed systems\n\
                             - Incorrect timestamps in logs and databases\n\
                             - DST (Daylight Saving Time) related issues\n\n\
                             Use timezone-aware datetimes instead:\n\
                             ```python\n\
                             from datetime import datetime, timezone\n\
                             \n\
                             # Instead of: datetime.now()\n\
                             # Use:\n\
                             datetime.now(timezone.utc)\n\
                             \n\
                             # Or for local time with timezone:\n\
                             from zoneinfo import ZoneInfo\n\
                             datetime.now(ZoneInfo(\"America/New_York\"))\n\
                             ```",
                            call.function_call.callee_expr
                        )),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::Medium,
                        confidence: 0.9,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(location.line + 1),
                        column: Some(location.column + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(file_patch),
                        fix_preview: Some(format!(
                            "# Before:\n#   {}()\n# After:\n#   {}",
                            call.function_call.callee_expr, replacement
                        )),
                        tags: vec![
                            "python".into(),
                            "datetime".into(),
                            "timezone".into(),
                            "correctness".into(),
                        ],
                    });
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
    use crate::parse::python::parse_python_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let sem = PyFileSemantics::from_parsed(&parsed);
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonNaiveDatetimeRule::new();
        assert_eq!(rule.id(), "python.naive_datetime");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonNaiveDatetimeRule::new();
        assert!(rule.name().contains("timezone"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonNaiveDatetimeRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonNaiveDatetimeRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonNaiveDatetimeRule::default();
        assert_eq!(rule.id(), "python.naive_datetime");
    }

    // ==================== Finding Tests ====================

    #[tokio::test]
    async fn detects_datetime_now_without_tz() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
from datetime import datetime
now = datetime.now()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("datetime.now()"));
    }

    #[tokio::test]
    async fn detects_datetime_utcnow() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
from datetime import datetime
now = datetime.utcnow()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("utcnow"));
    }

    #[tokio::test]
    async fn detects_datetime_today() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
from datetime import datetime
today = datetime.today()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("today"));
    }

    // ==================== No Finding Tests ====================

    #[tokio::test]
    async fn no_finding_for_datetime_now_with_tz() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
from datetime import datetime, timezone
now = datetime.now(tz=timezone.utc)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_for_datetime_now_with_timezone_arg() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
from datetime import datetime, timezone
now = datetime.now(timezone.utc)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_for_datetime_now_with_utc_constant() {
        let rule = PythonNaiveDatetimeRule::new();
        // Python 3.11+ datetime.UTC constant
        let src = r#"
from datetime import UTC, datetime, timedelta
expires_at = datetime.now(UTC) + timedelta(seconds=600)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "datetime.now(UTC) should not trigger naive datetime warning");
    }

    #[tokio::test]
    async fn no_finding_for_date_today() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
from datetime import date
today = date.today()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_for_unrelated_now_function() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
def now():
    return "current time"

result = now()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Finding Properties Tests ====================

    #[tokio::test]
    async fn finding_has_correct_rule_id() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
from datetime import datetime
now = datetime.now()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "python.naive_datetime");
    }

    #[tokio::test]
    async fn finding_has_medium_severity() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
from datetime import datetime
now = datetime.now()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[tokio::test]
    async fn finding_has_patch() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
from datetime import datetime
now = datetime.now()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn finding_has_fix_preview() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
from datetime import datetime
now = datetime.now()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].fix_preview.is_some());
        let preview = findings[0].fix_preview.as_ref().unwrap();
        assert!(preview.contains("timezone.utc"));
    }

    // ==================== Multiple Findings Tests ====================

    #[tokio::test]
    async fn detects_multiple_naive_datetimes() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
from datetime import datetime
now = datetime.now()
utc = datetime.utcnow()
today = datetime.today()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 3);
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = "";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_file_without_datetime() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = r#"
def hello():
    print("Hello, World!")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Patch Application Tests ====================

    #[tokio::test]
    async fn patch_actually_replaces_datetime_now() {
        use crate::types::patch::apply_file_patch;
        
        let rule = PythonNaiveDatetimeRule::new();
        let src = "from datetime import datetime\nnow = datetime.now()\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        
        let patch = findings[0].patch.as_ref().unwrap();
        let patched = apply_file_patch(src, patch);
        
        // The patch should add import and replace the call
        assert!(patched.contains("from datetime import timezone"));
        assert!(patched.contains("datetime.now(timezone.utc)"));
        assert!(!patched.contains("datetime.now()"));
    }

    #[tokio::test]
    async fn patch_actually_replaces_datetime_utcnow() {
        use crate::types::patch::apply_file_patch;
        
        let rule = PythonNaiveDatetimeRule::new();
        let src = "from datetime import datetime\nutc = datetime.utcnow()\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        
        let patch = findings[0].patch.as_ref().unwrap();
        let patched = apply_file_patch(src, patch);
        
        // The patch should add import and replace the deprecated call
        assert!(patched.contains("from datetime import timezone"));
        assert!(patched.contains("datetime.now(timezone.utc)"));
        assert!(!patched.contains("datetime.utcnow()"));
    }

    #[tokio::test]
    async fn patch_actually_replaces_datetime_today() {
        use crate::types::patch::apply_file_patch;
        
        let rule = PythonNaiveDatetimeRule::new();
        let src = "from datetime import datetime\ntd = datetime.today()\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        
        let patch = findings[0].patch.as_ref().unwrap();
        let patched = apply_file_patch(src, patch);
        
        // The patch should add import and replace the call
        assert!(patched.contains("from datetime import timezone"));
        assert!(patched.contains("datetime.now(timezone.utc)"));
        assert!(!patched.contains("datetime.today()"));
    }

    #[tokio::test]
    async fn patch_uses_replace_bytes_not_insert() {
        let rule = PythonNaiveDatetimeRule::new();
        let src = "from datetime import datetime\nnow = datetime.now()\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        
        let patch = findings[0].patch.as_ref().unwrap();
        
        // Verify that one hunk is ReplaceBytes (the actual fix)
        let has_replace_bytes = patch.hunks.iter().any(|h| {
            matches!(h.range, crate::types::patch::PatchRange::ReplaceBytes { .. })
        });
        assert!(has_replace_bytes, "Patch should use ReplaceBytes for actual code replacement");
    }
}