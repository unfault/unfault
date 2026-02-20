//! Rule B7: Bare `except:` blocks
//!
//! Detects Python `except:` clauses without an exception type. Specifying
//! exception types makes error handling intent explicit and preserves Python's
//! interrupt and exit signals.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::BareExceptClause;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects bare `except:` blocks in Python code.
///
/// Bare except blocks catch all exceptions including `KeyboardInterrupt`,
/// `SystemExit`, and `GeneratorExit`. Specifying exception types makes
/// error handling intent explicit and preserves Python's control signals.
#[derive(Debug)]
pub struct PythonBareExceptRule;

impl PythonBareExceptRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonBareExceptRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonBareExceptRule {
    fn id(&self) -> &'static str {
        "python.bare_except"
    }

    fn name(&self) -> &'static str {
        "Bare `except:` blocks catch all exceptions including system exits"
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

            // Use the bare_excepts from the semantic model
            for bare_except in &py.bare_excepts {
                let title = "Bare `except:` block catches all exceptions".to_string();

                let description = if let Some(ref fn_name) = bare_except.function_name {
                    format!(
                        "The bare `except:` clause in function `{}` catches all exceptions, \
                         including `KeyboardInterrupt`, `SystemExit`, and `GeneratorExit`. \
                         Specifying exception types makes error handling intent explicit and \
                         preserves Python's control signals. Consider catching `Exception` or more specific types.",
                        fn_name
                    )
                } else {
                    "This bare `except:` clause catches all exceptions, \
                     including `KeyboardInterrupt`, `SystemExit`, and `GeneratorExit`. \
                     Specifying exception types makes error handling intent explicit and \
                     preserves Python's control signals. Consider catching `Exception` or more specific types."
                        .to_string()
                };

                // Generate the patch to replace `except:` with `except Exception:`
                let (patched_text, patch) = generate_bare_except_patch(bare_except, *file_id);

                let fix_preview = format!(
                    "# Before:\n#   {}\n# After:\n#   {}",
                    bare_except.text.trim(),
                    patched_text.trim()
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::AntiPattern,
                    severity: Severity::Medium,
                    confidence: 1.0, // This is a definite pattern match
                    dimension: Dimension::Correctness,
                    file_id: *file_id,
                    file_path: py.path.clone(),
                    line: Some(bare_except.line),
                    column: Some(bare_except.column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "python".into(),
                        "exception-handling".into(),
                        "correctness".into(),
                        "anti-pattern".into(),
                    ],
                });
            }
        }

        findings
    }
}

/// Generate a patch to replace `except:` with `except Exception:`
fn generate_bare_except_patch(
    bare_except: &BareExceptClause,
    file_id: FileId,
) -> (String, FilePatch) {
    // The fix is to replace `except:` with `except Exception:`
    let original = &bare_except.text;
    let patched = if original.trim() == "except:" {
        original.replace("except:", "except Exception:")
    } else {
        // Handle cases like "except:  # comment"
        original.replacen("except:", "except Exception:", 1)
    };

    let patch = FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: bare_except.except_keyword_start,
                end: bare_except.except_keyword_end,
            },
            replacement: "except Exception".to_string(),
        }],
    };

    (patched, patch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    // ==================== Helper Functions ====================

    /// Parse source and extract bare except clauses from the semantic model
    fn parse_and_find_bare_excepts(source: &str) -> Vec<BareExceptClause> {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let sem = PyFileSemantics::from_parsed(&parsed);

        sem.bare_excepts
    }

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
        let rule = PythonBareExceptRule::new();
        assert_eq!(rule.id(), "python.bare_except");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonBareExceptRule::new();
        assert!(rule.name().contains("except"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonBareExceptRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonBareExceptRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonBareExceptRule::default();
        assert_eq!(rule.id(), "python.bare_except");
    }

    // ==================== Bare Except Detection Tests ====================

    #[test]
    fn detects_simple_bare_except() {
        let src = r#"
try:
    risky()
except:
    pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert_eq!(results.len(), 1);
        assert!(results[0].text.contains("except:"));
    }

    #[test]
    fn does_not_flag_except_with_type() {
        let src = r#"
try:
    risky()
except ValueError:
    pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert!(results.is_empty());
    }

    #[test]
    fn does_not_flag_except_exception() {
        let src = r#"
try:
    risky()
except Exception:
    pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert!(results.is_empty());
    }

    #[test]
    fn does_not_flag_except_with_alias() {
        let src = r#"
try:
    risky()
except ValueError as e:
    print(e)
"#;
        let results = parse_and_find_bare_excepts(src);
        assert!(results.is_empty());
    }

    #[test]
    fn does_not_flag_except_with_tuple() {
        let src = r#"
try:
    risky()
except (ValueError, TypeError):
    pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert!(results.is_empty());
    }

    #[test]
    fn does_not_flag_except_with_attribute() {
        let src = r#"
try:
    risky()
except module.CustomError:
    pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert!(results.is_empty());
    }

    #[test]
    fn detects_bare_except_in_function() {
        let src = r#"
def my_function():
    try:
        risky()
    except:
        pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].function_name, Some("my_function".to_string()));
    }

    #[test]
    fn detects_multiple_bare_excepts() {
        let src = r#"
try:
    risky1()
except:
    pass

try:
    risky2()
except:
    pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn detects_bare_except_among_typed_excepts() {
        let src = r#"
try:
    risky()
except ValueError:
    handle_value_error()
except:
    handle_other()
"#;
        let results = parse_and_find_bare_excepts(src);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn detects_nested_bare_except() {
        let src = r#"
try:
    try:
        risky()
    except:
        pass
except ValueError:
    pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn reports_correct_line_number() {
        let src = r#"
try:
    risky()
except:
    pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert_eq!(results.len(), 1);
        // The except: is on line 4 (1-indexed)
        assert_eq!(results[0].line, 4);
    }

    #[test]
    fn handles_try_else_finally() {
        let src = r#"
try:
    risky()
except:
    handle_error()
else:
    success()
finally:
    cleanup()
"#;
        let results = parse_and_find_bare_excepts(src);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn handles_async_function() {
        let src = r#"
async def async_func():
    try:
        await risky()
    except:
        pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].function_name, Some("async_func".to_string()));
    }

    #[test]
    fn handles_class_method() {
        let src = r#"
class MyClass:
    def method(self):
        try:
            risky()
        except:
            pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].function_name, Some("method".to_string()));
    }

    #[test]
    fn handles_empty_file() {
        let src = "";
        let results = parse_and_find_bare_excepts(src);
        assert!(results.is_empty());
    }

    #[test]
    fn handles_file_without_try_except() {
        let src = r#"
def hello():
    print("Hello, World!")
"#;
        let results = parse_and_find_bare_excepts(src);
        assert!(results.is_empty());
    }

    // ==================== Rule Evaluate Tests ====================

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_python() {
        let rule = PythonBareExceptRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_code_without_bare_except() {
        let rule = PythonBareExceptRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
try:
    risky()
except ValueError:
    pass
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_bare_except() {
        let rule = PythonBareExceptRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
try:
    risky()
except:
    pass
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "python.bare_except");
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_properties() {
        let rule = PythonBareExceptRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
def my_func():
    try:
        risky()
    except:
        pass
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);

        let finding = &findings[0];
        assert_eq!(finding.rule_id, "python.bare_except");
        assert!(finding.description.as_ref().unwrap().contains("my_func"));
        assert!(finding.patch.is_some());
        assert!(finding.fix_preview.is_some());
        assert!(
            finding
                .fix_preview
                .as_ref()
                .unwrap()
                .contains("except Exception:")
        );
        assert!(finding.tags.contains(&"python".to_string()));
        assert!(finding.tags.contains(&"exception-handling".to_string()));
    }

    // ==================== Finding Properties Tests ====================

    #[test]
    fn bare_except_info_has_correct_fields() {
        let src = r#"
def test():
    try:
        risky()
    except:
        pass
"#;
        let results = parse_and_find_bare_excepts(src);
        assert_eq!(results.len(), 1);

        let info = &results[0];
        assert!(info.line > 0);
        assert!(info.column > 0);
        assert!(!info.text.is_empty());
        assert!(info.function_name.is_some());
        assert!(info.start_byte < info.end_byte);
    }
}
