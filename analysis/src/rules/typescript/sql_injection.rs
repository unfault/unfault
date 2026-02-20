//! TypeScript SQL Injection Detection Rule
//!
//! Detects potential SQL injection vulnerabilities where user input
//! is directly concatenated into SQL queries.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

#[derive(Debug)]
pub struct TypescriptSqlInjectionRule;

impl TypescriptSqlInjectionRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptSqlInjectionRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptSqlInjectionRule {
    fn id(&self) -> &'static str {
        "typescript.sql_injection"
    }

    fn name(&self) -> &'static str {
        "SQL Injection Vulnerability"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let ts = match sem.as_ref() {
                SourceSemantics::Typescript(ts) => ts,
                _ => continue,
            };

            // Check all function calls for SQL-related methods with string concatenation
            for call in &ts.calls {
                let callee_lower = call.callee.to_lowercase();

                // Detect SQL query methods
                let is_sql_method = callee_lower.contains("query")
                    || callee_lower.contains("execute")
                    || callee_lower.contains("raw")
                    || callee_lower == "sql"
                    || callee_lower.ends_with(".$queryraw")
                    || callee_lower.ends_with(".$executeraw");

                if !is_sql_method {
                    continue;
                }

                // Check if any argument contains string concatenation or template variables
                for arg in &call.args {
                    let arg_value = &arg.value_repr;
                    let arg_lower = arg_value.to_lowercase();

                    // Detect string concatenation patterns
                    let has_concatenation = arg_value.contains('+')
                        || (arg_value.contains('$') && arg_value.contains('{'))
                        || arg_value.contains("req.")
                        || arg_value.contains("params.")
                        || arg_value.contains("body.")
                        || arg_value.contains("query.");

                    // Check for SQL keywords to confirm it's a SQL query
                    let has_sql_keywords = arg_lower.contains("select")
                        || arg_lower.contains("insert")
                        || arg_lower.contains("update")
                        || arg_lower.contains("delete")
                        || arg_lower.contains("where");

                    if has_concatenation && has_sql_keywords {
                        let line = call.location.range.start_line + 1;
                        let column = call.location.range.start_col + 1;

                        let patch = FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: "// Use parameterized queries to prevent SQL injection\n\
                                     // Example: query('SELECT * FROM users WHERE id = $1', [userId])\n"
                                    .to_string(),
                            }],
                        };

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Potential SQL injection vulnerability".to_string(),
                            description: Some(format!(
                                "SQL query uses string concatenation with potentially user-controlled input. \
                                 Use parameterized queries to prevent SQL injection attacks. \
                                 Found in call to '{}' at line {}.",
                                call.callee, line
                            )),
                            kind: FindingKind::SecurityVulnerability,
                            severity: Severity::Critical,
                            confidence: 0.8,
                            dimension: Dimension::Security,
                            file_id: *file_id,
                            file_path: ts.path.clone(),
                            line: Some(line),
                            column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(
                                "Use parameterized query with placeholders ($1, ?, etc.)".to_string(),
                            ),
                            tags: vec![
                                "security".into(),
                                "sql-injection".into(),
                                "owasp-a03".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::sql_injection())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptSqlInjectionRule::new();
        assert_eq!(rule.id(), "typescript.sql_injection");
    }

    #[test]
    fn test_rule_name() {
        let rule = TypescriptSqlInjectionRule::new();
        assert!(rule.name().contains("SQL Injection"));
    }
}
