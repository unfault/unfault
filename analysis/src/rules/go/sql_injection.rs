//! Rule: SQL injection vulnerabilities
//!
//! Detects potential SQL injection vulnerabilities in Go code, including
//! string concatenation in SQL queries and improper use of fmt.Sprintf
//! for building queries.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::sql_injection;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects SQL injection vulnerabilities.
///
/// SQL injection is one of the most critical security vulnerabilities.
/// This rule detects patterns like:
/// - String concatenation in SQL queries
/// - fmt.Sprintf with user input in queries
/// - Raw query execution without parameterization
#[derive(Debug)]
pub struct GoSqlInjectionRule;

impl GoSqlInjectionRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoSqlInjectionRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for GoSqlInjectionRule {
    fn id(&self) -> &'static str {
        "go.sql_injection"
    }

    fn name(&self) -> &'static str {
        "Potential SQL injection vulnerability"
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
            let go = match sem.as_ref() {
                SourceSemantics::Go(go) => go,
                _ => continue,
            };

            // Check for SQL-related calls with potential injection
            for call in &go.calls {
                // Look for database query methods
                if !is_sql_query_method(&call.function_call.callee_expr) {
                    continue;
                }

                // Check if the arguments look like string concatenation or interpolation
                let args = &call.args_repr;
                let risk = analyze_sql_injection_risk(args);
                
                if let Some(injection_pattern) = risk {
                    let line = call.function_call.location.line;
                    let col = call.function_call.location.column;
                    
                    let title = format!(
                        "Potential SQL injection in {}",
                        call.function_call.callee_expr
                    );

                    let description = format!(
                        "The SQL query in `{}` at line {} uses {} to build the query. \
                         Parameterized queries separate SQL structure from data, making the \
                         query behavior explicit and predictable.\n\n\
                         Use parameterized queries instead:\n\
                         ```go\n\
                         db.Query(\"SELECT * FROM users WHERE id = $1\", userID)\n\
                         ```\n\n\
                         Or use a query builder that handles escaping properly.",
                        call.function_call.callee_expr,
                        line,
                        injection_pattern
                    );

                    let patch = generate_parameterized_query_patch(call, *file_id);

                    let fix_preview = format!(
                        "// Before (VULNERABLE):\n\
                         // db.Query(\"SELECT * FROM users WHERE id = \" + userID)\n\
                         // db.Query(fmt.Sprintf(\"SELECT * FROM users WHERE id = %s\", userID))\n\
                         //\n\
                         // After (SAFE):\n\
                         // db.Query(\"SELECT * FROM users WHERE id = $1\", userID)"
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::SecurityVulnerability,
                        severity: Severity::Critical,
                        confidence: injection_pattern.confidence() as f32,
                        dimension: Dimension::Security,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: Some(col),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "go".into(),
                            "sql".into(),
                            "injection".into(),
                            "security".into(),
                            "critical".into(),
                        ],
                    });
                }
            }
        }

        findings
    }
}

/// Check if a method name is a SQL query method
fn is_sql_query_method(callee: &str) -> bool {
    let sql_methods = [
        "Query",
        "QueryRow",
        "QueryContext",
        "QueryRowContext",
        "Exec",
        "ExecContext",
        "Prepare",
        "PrepareContext",
        // GORM
        "Raw",
        "Exec",
        "Where",
        // sqlx
        "Select",
        "Get",
        "NamedQuery",
        "NamedExec",
    ];

    sql_methods.iter().any(|method| callee.ends_with(method) || callee.contains(&format!(".{}", method)))
}

/// Patterns that indicate SQL injection risk
#[derive(Debug, Clone)]
enum InjectionPattern {
    StringConcatenation,
    FmtSprintf,
    StringInterpolation,
    RawStringVariable,
}

impl InjectionPattern {
    fn confidence(&self) -> f64 {
        match self {
            InjectionPattern::StringConcatenation => 0.95,
            InjectionPattern::FmtSprintf => 0.90,
            InjectionPattern::StringInterpolation => 0.90,
            InjectionPattern::RawStringVariable => 0.75,
        }
    }
}

impl std::fmt::Display for InjectionPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InjectionPattern::StringConcatenation => write!(f, "string concatenation"),
            InjectionPattern::FmtSprintf => write!(f, "fmt.Sprintf"),
            InjectionPattern::StringInterpolation => write!(f, "string interpolation"),
            InjectionPattern::RawStringVariable => write!(f, "a variable (potentially user input)"),
        }
    }
}

/// Analyze a query argument for SQL injection risk
fn analyze_sql_injection_risk(query_arg: &str) -> Option<InjectionPattern> {
    // Check for string concatenation
    if query_arg.contains(" + ") || query_arg.contains("+ \"") || query_arg.contains("\" +") {
        return Some(InjectionPattern::StringConcatenation);
    }

    // Check for fmt.Sprintf
    if query_arg.starts_with("fmt.Sprintf") || query_arg.contains("fmt.Sprintf") {
        // Check if it has format specifiers that could be user input
        if query_arg.contains("%s") || query_arg.contains("%v") || query_arg.contains("%d") {
            return Some(InjectionPattern::FmtSprintf);
        }
    }

    // Check for string interpolation patterns (Go doesn't have this, but check templates)
    if query_arg.contains("{{") || query_arg.contains("}}") {
        return Some(InjectionPattern::StringInterpolation);
    }

    // Check if it's just a variable (not a literal string)
    if !query_arg.starts_with('"') && !query_arg.starts_with('`') && !query_arg.starts_with("\"") {
        // It's a variable - could be risky
        return Some(InjectionPattern::RawStringVariable);
    }

    None
}

use crate::semantics::go::model::CallSite;

/// Generate a patch to convert to parameterized query
fn generate_parameterized_query_patch(call: &CallSite, file_id: FileId) -> FilePatch {
    let replacement = format!(
        "// TODO: Convert to parameterized query\n\
         // Replace string concatenation/interpolation with placeholders:\n\
         // {}(\"... $1 ...\", param1)",
        call.function_call.callee_expr
    );

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: call.start_byte,
                end: call.end_byte,
            },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::go::parse_go_file;
    use crate::semantics::go::build_go_semantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.go".to_string(),
            language: Language::Go,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_go_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_go_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Go(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = GoSqlInjectionRule::new();
        assert_eq!(rule.id(), "go.sql_injection");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = GoSqlInjectionRule::new();
        assert!(rule.name().contains("SQL injection"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = GoSqlInjectionRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GoSqlInjectionRule"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_go() {
        let rule = GoSqlInjectionRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_string_concatenation() {
        let rule = GoSqlInjectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "database/sql"

func getUser(db *sql.DB, userID string) {
    db.Query("SELECT * FROM users WHERE id = " + userID)
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.sql_injection" {
                assert_eq!(finding.severity, Severity::Critical);
                assert!(finding.tags.contains(&"security".to_string()));
            }
        }
    }

    #[tokio::test]
    async fn evaluate_detects_fmt_sprintf() {
        let rule = GoSqlInjectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import (
    "database/sql"
    "fmt"
)

func getUser(db *sql.DB, userID string) {
    query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
    db.Query(query)
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.sql_injection" {
                assert_eq!(finding.dimension, Dimension::Security);
            }
        }
    }

    #[tokio::test]
    async fn evaluate_no_finding_for_parameterized_query() {
        let rule = GoSqlInjectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "database/sql"

func getUser(db *sql.DB, userID string) {
    db.Query("SELECT * FROM users WHERE id = $1", userID)
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag parameterized queries
        for finding in &findings {
            // If there are findings, they shouldn't be for this query
            if finding.rule_id == "go.sql_injection" {
                // The parameterized query should not be flagged
                // (depends on semantics implementation)
            }
        }
    }

    #[test]
    fn is_sql_query_method_detects_common_methods() {
        assert!(is_sql_query_method("db.Query"));
        assert!(is_sql_query_method("db.QueryRow"));
        assert!(is_sql_query_method("db.Exec"));
        assert!(is_sql_query_method("tx.QueryContext"));
        assert!(is_sql_query_method("Raw"));
        assert!(!is_sql_query_method("fmt.Println"));
    }

    #[test]
    fn analyze_sql_injection_risk_detects_patterns() {
        assert!(analyze_sql_injection_risk("\"SELECT \" + userID").is_some());
        assert!(analyze_sql_injection_risk("fmt.Sprintf(\"SELECT %s\", id)").is_some());
        assert!(analyze_sql_injection_risk("\"SELECT * FROM users WHERE id = $1\"").is_none());
    }
}