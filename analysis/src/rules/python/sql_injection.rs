//! Rule B13: Non-parameterized SQL queries
//!
//! Detects SQL queries that use string interpolation (f-strings, .format(), %)
//! instead of parameterized queries. Parameterized queries provide type safety
//! and proper escaping for query parameters.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::sql_injection;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects non-parameterized SQL queries in Python code.
///
/// SQL queries that use string interpolation (f-strings, .format(), or %)
/// bypass the database's parameter handling. This rule detects such patterns
/// and suggests using parameterized queries for proper type safety and escaping.
#[derive(Debug)]
pub struct PythonSqlInjectionRule;

impl PythonSqlInjectionRule {
    pub fn new() -> Self {
        Self
    }

    /// Check if a string looks like a SQL query
    fn is_sql_query(s: &str) -> bool {
        let upper = s.to_uppercase();
        upper.contains("SELECT ")
            || upper.contains("INSERT ")
            || upper.contains("UPDATE ")
            || upper.contains("DELETE ")
            || upper.contains("DROP ")
            || upper.contains("CREATE ")
            || upper.contains("ALTER ")
            || upper.contains("TRUNCATE ")
            || upper.contains("EXEC ")
            || upper.contains("EXECUTE ")
    }

    /// Check if a string uses f-string interpolation
    fn is_fstring(s: &str) -> bool {
        s.starts_with("f\"") || s.starts_with("f'") || s.starts_with("F\"") || s.starts_with("F'")
    }

    /// Check if a string uses .format() method
    fn uses_format_method(s: &str) -> bool {
        s.contains(".format(")
    }

    /// Check if a string uses % formatting
    fn uses_percent_formatting(s: &str) -> bool {
        // Look for patterns like "... %s ..." % or "... %(name)s ..." %
        s.contains(" % ") || s.ends_with(" %")
    }
}

impl Default for PythonSqlInjectionRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonSqlInjectionRule {
    fn id(&self) -> &'static str {
        "python.sql_injection"
    }

    fn name(&self) -> &'static str {
        "SQL queries should use parameterized queries instead of string interpolation"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(sql_injection())
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

            // Check assignments for SQL queries with string interpolation
            for assignment in &py.assignments {
                let value = &assignment.value_repr;
                
                // Check if it looks like a SQL query
                if !Self::is_sql_query(value) {
                    continue;
                }

                // Check for dangerous patterns
                let (is_dangerous, pattern_type) = if Self::is_fstring(value) {
                    (true, "f-string")
                } else if Self::uses_format_method(value) {
                    (true, ".format()")
                } else if Self::uses_percent_formatting(value) {
                    (true, "% formatting")
                } else {
                    (false, "")
                };

                if is_dangerous {
                    let location = &assignment.location;
                    
                    // Generate a fix suggestion
                    let sql_template = Self::extract_sql_template(value);
                    let fix_suggestion = format!(
                        "# Use parameterized query instead:\n\
                         # cursor.execute(\"{}\", (param1, param2, ...))",
                        sql_template
                    );

                    // Generate a proper patch with semantically sound hunks:
                    // 1. The parameterized query template as a comment after the problematic line
                    let file_patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![
                            // Hunk 1: Add a comment showing the safe pattern after the problematic line
                            PatchHunk {
                                range: PatchRange::InsertAfterLine {
                                    line: location.range.start_line,
                                },
                                replacement: format!(
                                    "# FIXME: SQL injection risk! Replace with parameterized query:\n\
                                     # {} = \"{}\"\n\
                                     # cursor.execute({}, (param1, param2, ...))\n",
                                    assignment.target,
                                    sql_template,
                                    assignment.target
                                ),
                            },
                        ],
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: format!(
                            "SQL query uses {} interpolation in `{}`",
                            pattern_type, assignment.target
                        ),
                        description: Some(format!(
                            "The SQL query in `{}` uses {} for string interpolation. \
                             Parameterized queries provide proper type safety and escaping.\n\n\
                             With parameterized queries:\n\
                             - Parameters are properly typed and escaped by the database driver\n\
                             - Query structure is separated from data values\n\
                             - The database can cache and optimize query plans\n\n\
                             Use parameterized queries (also called prepared statements) instead.",
                            assignment.target, pattern_type
                        )),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::Critical,
                        confidence: 0.9,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(location.range.start_line + 1),
                        column: Some(location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(file_patch),
                        fix_preview: Some(fix_suggestion),
                        tags: vec![
                            "python".into(),
                            "security".into(),
                            "sql-injection".into(),
                            "correctness".into(),
                        ],
                    });
                }
            }

            // Also check call sites for execute() calls with interpolated strings
            for call in &py.calls {
                // Look for cursor.execute(), connection.execute(), etc.
                if !call.function_call.callee_expr.ends_with(".execute") && !call.function_call.callee_expr.ends_with(".executemany") {
                    continue;
                }

                // Check the first argument (the SQL query)
                if let Some(first_arg) = call.args.first() {
                    let value = &first_arg.value_repr;
                    
                    if !Self::is_sql_query(value) {
                        continue;
                    }

                    let (is_dangerous, pattern_type) = if Self::is_fstring(value) {
                        (true, "f-string")
                    } else if Self::uses_format_method(value) {
                        (true, ".format()")
                    } else if Self::uses_percent_formatting(value) {
                        (true, "% formatting")
                    } else {
                        (false, "")
                    };

                    if is_dangerous {
                        let location = &call.function_call.location;

                        // Extract the cursor/connection variable name
                        let cursor_var = call.function_call.callee_expr
                            .trim_end_matches(".execute")
                            .trim_end_matches(".executemany");

                        // Generate actual fix using ReplaceBytes for f-strings
                        let file_patch = if Self::is_fstring(value) {
                            // Transform f-string to parameterized query
                            let (sql_template, params) = Self::transform_fstring_to_parameterized(value);
                            let patched_call = format!(
                                "{}.execute(\"{}\", ({}))",
                                cursor_var,
                                sql_template,
                                params
                            );
                            
                            FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::ReplaceBytes {
                                        start: call.start_byte,
                                        end: call.end_byte,
                                    },
                                    replacement: patched_call,
                                }],
                            }
                        } else {
                            // For .format() and % - add comment guidance (more complex transformation)
                            FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertAfterLine {
                                        line: location.line as u32,
                                    },
                                    replacement: format!(
                                        "# FIXME: SQL injection risk! Use parameterized query:\n\
                                         # {}.execute(\"SELECT ... WHERE col = %s\", (value,))\n",
                                        cursor_var
                                    ),
                                }],
                            }
                        };

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: format!(
                                "SQL execute() call uses {} interpolation",
                                pattern_type
                            ),
                            description: Some(format!(
                                "The `{}` call uses {} for SQL string interpolation. \
                                 Parameterized queries provide proper type safety and escaping.\n\n\
                                 Instead of:\n\
                                 ```python\n\
                                 cursor.execute(f\"SELECT * FROM users WHERE id = {{user_id}}\")\n\
                                 ```\n\n\
                                 Use:\n\
                                 ```python\n\
                                 cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n\
                                 ```",
                                call.function_call.callee_expr, pattern_type
                            )),
                            kind: FindingKind::BehaviorThreat,
                            severity: Severity::Critical,
                            confidence: 0.95,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(location.line),
                            column: Some(location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(file_patch),
                            fix_preview: Some(
                                "# Use parameterized query:\n\
                                 # cursor.execute(\"SELECT ... WHERE id = %s\", (param,))".to_string()
                            ),
                            tags: vec![
                                "python".into(),
                                "security".into(),
                                "sql-injection".into(),
                                "correctness".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }
}

impl PythonSqlInjectionRule {
    /// Extract a SQL template from an interpolated string (for fix suggestions)
    fn extract_sql_template(s: &str) -> String {
        // Simple extraction - replace {var} with %s
        let mut result = s.to_string();
        
        // Remove f-string prefix
        if result.starts_with("f\"") || result.starts_with("F\"") {
            result = result[2..].to_string();
        } else if result.starts_with("f'") || result.starts_with("F'") {
            result = result[2..].to_string();
        }
        
        // Remove trailing quote
        if result.ends_with('"') || result.ends_with('\'') {
            result.pop();
        }
        
        // Replace {var} patterns with %s
        let mut output = String::new();
        let mut in_brace = false;
        for ch in result.chars() {
            if ch == '{' {
                in_brace = true;
                output.push_str("%s");
            } else if ch == '}' {
                in_brace = false;
            } else if !in_brace {
                output.push(ch);
            }
        }
        
        output
    }
    
    /// Transform an f-string SQL query to a parameterized query.
    /// Returns (sql_template, params_tuple_str)
    /// e.g., f"SELECT * FROM users WHERE id = {user_id} AND name = {name}"
    /// -> ("SELECT * FROM users WHERE id = %s AND name = %s", "user_id, name,")
    fn transform_fstring_to_parameterized(s: &str) -> (String, String) {
        let mut result = s.to_string();
        
        // Remove f-string prefix
        if result.starts_with("f\"") || result.starts_with("F\"") {
            result = result[2..].to_string();
        } else if result.starts_with("f'") || result.starts_with("F'") {
            result = result[2..].to_string();
        }
        
        // Remove trailing quote
        if result.ends_with('"') || result.ends_with('\'') {
            result.pop();
        }
        
        // Extract variable names and build template
        let mut sql_template = String::new();
        let mut params = Vec::new();
        let mut in_brace = false;
        let mut current_var = String::new();
        
        for ch in result.chars() {
            if ch == '{' {
                in_brace = true;
                current_var.clear();
                sql_template.push_str("%s");
            } else if ch == '}' {
                in_brace = false;
                // Trim any format spec (e.g., {var:.2f} -> var)
                let var_name = current_var.split(':').next().unwrap_or(&current_var).trim();
                if !var_name.is_empty() {
                    params.push(var_name.to_string());
                }
            } else if in_brace {
                current_var.push(ch);
            } else {
                sql_template.push(ch);
            }
        }
        
        // Build params tuple string
        // For single param, need trailing comma: (param,)
        // For multiple params: (param1, param2,)
        let params_str = if params.is_empty() {
            "".to_string()
        } else {
            format!("{},", params.join(", "))
        };
        
        (sql_template, params_str)
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
        let rule = PythonSqlInjectionRule::new();
        assert_eq!(rule.id(), "python.sql_injection");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonSqlInjectionRule::new();
        assert!(rule.name().contains("SQL"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonSqlInjectionRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonSqlInjectionRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonSqlInjectionRule::default();
        assert_eq!(rule.id(), "python.sql_injection");
    }

    // ==================== SQL Detection Tests ====================

    #[test]
    fn detects_select_query() {
        assert!(PythonSqlInjectionRule::is_sql_query("SELECT * FROM users"));
    }

    #[test]
    fn detects_insert_query() {
        assert!(PythonSqlInjectionRule::is_sql_query("INSERT INTO users VALUES (1, 'name')"));
    }

    #[test]
    fn detects_update_query() {
        assert!(PythonSqlInjectionRule::is_sql_query("UPDATE users SET name = 'test'"));
    }

    #[test]
    fn detects_delete_query() {
        assert!(PythonSqlInjectionRule::is_sql_query("DELETE FROM users WHERE id = 1"));
    }

    #[test]
    fn does_not_detect_non_sql() {
        assert!(!PythonSqlInjectionRule::is_sql_query("Hello world"));
    }

    // ==================== Interpolation Detection Tests ====================

    #[test]
    fn detects_fstring() {
        assert!(PythonSqlInjectionRule::is_fstring("f\"SELECT * FROM users\""));
        assert!(PythonSqlInjectionRule::is_fstring("f'SELECT * FROM users'"));
        assert!(PythonSqlInjectionRule::is_fstring("F\"SELECT * FROM users\""));
    }

    #[test]
    fn does_not_detect_regular_string_as_fstring() {
        assert!(!PythonSqlInjectionRule::is_fstring("\"SELECT * FROM users\""));
    }

    #[test]
    fn detects_format_method() {
        assert!(PythonSqlInjectionRule::uses_format_method("\"SELECT * FROM users WHERE id = {}\".format(user_id)"));
    }

    #[test]
    fn detects_percent_formatting() {
        assert!(PythonSqlInjectionRule::uses_percent_formatting("\"SELECT * FROM users WHERE id = %s\" % user_id"));
    }

    // ==================== Finding Tests ====================

    #[tokio::test]
    async fn detects_fstring_sql_in_assignment() {
        let rule = PythonSqlInjectionRule::new();
        let src = r#"query = f"SELECT * FROM users WHERE id = {user_id}""#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("f-string"));
    }

    #[tokio::test]
    async fn detects_format_sql_in_assignment() {
        let rule = PythonSqlInjectionRule::new();
        let src = r#"query = "SELECT * FROM users WHERE id = {}".format(user_id)"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains(".format()"));
    }

    // ==================== No Finding Tests ====================

    #[tokio::test]
    async fn no_finding_for_parameterized_query() {
        let rule = PythonSqlInjectionRule::new();
        let src = r#"query = "SELECT * FROM users WHERE id = %s""#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_for_non_sql_fstring() {
        let rule = PythonSqlInjectionRule::new();
        let src = r#"message = f"Hello {name}""#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_for_static_sql() {
        let rule = PythonSqlInjectionRule::new();
        let src = r#"query = "SELECT * FROM users""#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Finding Properties Tests ====================

    #[tokio::test]
    async fn finding_has_correct_rule_id() {
        let rule = PythonSqlInjectionRule::new();
        let src = r#"query = f"SELECT * FROM users WHERE id = {user_id}""#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "python.sql_injection");
    }

    #[tokio::test]
    async fn finding_has_critical_severity() {
        let rule = PythonSqlInjectionRule::new();
        let src = r#"query = f"SELECT * FROM users WHERE id = {user_id}""#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    #[tokio::test]
    async fn finding_has_patch() {
        let rule = PythonSqlInjectionRule::new();
        let src = r#"query = f"SELECT * FROM users WHERE id = {user_id}""#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn finding_has_fix_preview() {
        let rule = PythonSqlInjectionRule::new();
        let src = r#"query = f"SELECT * FROM users WHERE id = {user_id}""#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].fix_preview.is_some());
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = PythonSqlInjectionRule::new();
        let src = "";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_file_without_sql() {
        let rule = PythonSqlInjectionRule::new();
        let src = r#"
def hello():
    print("Hello, World!")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Template Extraction Tests ====================

    #[test]
    fn extract_sql_template_from_fstring() {
        let template = PythonSqlInjectionRule::extract_sql_template(
            "f\"SELECT * FROM users WHERE id = {user_id}\""
        );
        assert_eq!(template, "SELECT * FROM users WHERE id = %s");
    }

    #[test]
    fn extract_sql_template_with_multiple_vars() {
        let template = PythonSqlInjectionRule::extract_sql_template(
            "f\"SELECT * FROM users WHERE id = {id} AND name = {name}\""
        );
        assert_eq!(template, "SELECT * FROM users WHERE id = %s AND name = %s");
    }
}