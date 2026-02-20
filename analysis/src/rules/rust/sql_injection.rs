//! Rule: SQL Injection via string interpolation
//!
//! Detects SQL queries built using string formatting or concatenation,
//! which are vulnerable to SQL injection attacks.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! let query = format!("SELECT * FROM users WHERE id = {}", user_id);
//! let query = "SELECT * FROM users WHERE name = '".to_string() + &name + "'";
//! ```
//!
//! Good:
//! ```rust,ignore
//! // Use parameterized queries with sqlx
//! sqlx::query("SELECT * FROM users WHERE id = $1")
//!     .bind(user_id)
//!     .fetch_one(&pool)
//!     .await?;
//!
//! // Or use diesel's type-safe queries
//! users.filter(id.eq(user_id)).first(&conn)?;
//! ```

use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use regex::Regex;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// SQL statement patterns compiled once at startup.
/// Uses structural patterns that require context to avoid matching English words
/// like "update the documentation" or "select your option".
static SQL_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        // SELECT ... FROM (the FROM is required to avoid "select an option")
        r"(?i)\bSELECT\s+.+\s+FROM\b",
        // SELECT * (common pattern)
        r"(?i)\bSELECT\s+\*",
        // SELECT with specific column syntax
        r"(?i)\bSELECT\s+\w+\s*,",
        // INSERT INTO (INTO is required)
        r"(?i)\bINSERT\s+INTO\b",
        // UPDATE ... SET (SET is required to avoid "update the docs")
        r"(?i)\bUPDATE\s+\w+\s+SET\b",
        // UPDATE with table name followed by SET
        r"(?i)\bUPDATE\s+`?\w+`?\s+SET\b",
        // DELETE FROM (FROM is required)
        r"(?i)\bDELETE\s+FROM\b",
        // DROP TABLE/DATABASE/INDEX
        r"(?i)\bDROP\s+(TABLE|DATABASE|INDEX|SCHEMA)\b",
        // CREATE TABLE/DATABASE/INDEX
        r"(?i)\bCREATE\s+(TABLE|DATABASE|INDEX|SCHEMA)\b",
        // ALTER TABLE
        r"(?i)\bALTER\s+TABLE\b",
        // TRUNCATE TABLE
        r"(?i)\bTRUNCATE\s+(TABLE\s+)?\w+",
        // WHERE clause (common in dynamic queries)
        r"(?i)\bWHERE\s+\w+\s*=",
    ]
    .into_iter()
    .map(|p| Regex::new(p).expect("SQL pattern is valid regex"))
    .collect()
});

/// Rule that detects SQL injection vulnerabilities in Rust code.
///
/// Looks for SQL statement patterns combined with string formatting/concatenation.
/// Uses structural patterns to avoid false positives from English words like "update".
#[derive(Debug, Default)]
pub struct RustSqlInjectionRule;

impl RustSqlInjectionRule {
    pub fn new() -> Self {
        Self
    }

    /// Check if text contains SQL statement patterns (not just isolated keywords)
    fn contains_sql(&self, text: &str) -> bool {
        SQL_PATTERNS.iter().any(|p| p.is_match(text))
    }

    /// Check if the format string is safe (contains parameterized query indicators
    /// or is clearly documentation/examples rather than actual SQL building).
    fn is_safe_format_string(&self, text: &str) -> bool {
        // If the string contains parameterized query placeholders, it's likely
        // showing a safe example rather than building an unsafe query
        if text.contains("$1") || text.contains("$2") || text.contains("$3") {
            return true;
        }

        // Named parameters indicate safe patterns
        if text.contains(":name") || text.contains(":id") || text.contains(":value") {
            return true;
        }

        // If SQL appears within an escaped string literal (documentation/examples),
        // it's not actual SQL being built. Look for patterns like \"SELECT
        if text.contains("\\\"SELECT")
            || text.contains("\\\"INSERT")
            || text.contains("\\\"UPDATE")
            || text.contains("\\\"DELETE")
        {
            return true;
        }

        // Common documentation patterns
        if text.contains("Example:")
            || text.contains("Instead of:")
            || text.contains("// Use:")
            || text.contains("Safe alternative")
        {
            return true;
        }

        false
    }

    /// Check if text uses format! with SQL
    fn is_format_sql(&self, text: &str) -> bool {
        if text.contains("format!") && self.contains_sql(text) {
            // Check for common safe patterns
            !text.contains("$1")
                && !text.contains("$2")
                && !text.contains(":name")
                && !text.contains(":id")
        } else {
            false
        }
    }

    /// Check if text uses string concatenation with SQL
    fn is_concat_sql(&self, text: &str) -> bool {
        (text.contains(" + &") || text.contains("+ \"")) && self.contains_sql(text)
    }
}

#[async_trait]
impl Rule for RustSqlInjectionRule {
    fn id(&self) -> &'static str {
        "rust.sql_injection"
    }

    fn name(&self) -> &'static str {
        "Potential SQL injection vulnerability"
    }

    fn applicability(&self) -> Option<crate::types::finding::FindingApplicability> {
        Some(crate::rules::applicability_defaults::sql_injection())
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

            // Check macro invocations for format! with SQL
            for macro_inv in &rust.macro_invocations {
                if macro_inv.name != "format" {
                    continue;
                }

                if macro_inv.in_test {
                    continue;
                }

                // Check if the format string contains SQL
                if !self.contains_sql(&macro_inv.args) {
                    continue;
                }

                // Check for format placeholders that might be user input
                if !macro_inv.args.contains("{}") && !macro_inv.args.contains("{:") {
                    continue;
                }

                // Skip safe format strings (documentation, examples, parameterized queries)
                if self.is_safe_format_string(&macro_inv.args) {
                    continue;
                }

                let line = macro_inv.location.range.start_line + 1;

                let title = "SQL query built with format!() - potential SQL injection".to_string();

                let description = format!(
                    "A SQL query is built using `format!()` at line {} in function '{}'.\n\n\
                     **Why this is dangerous:**\n\
                     - User input can include SQL metacharacters\n\
                     - Attackers can inject arbitrary SQL commands\n\
                     - Can lead to data theft, modification, or deletion\n\
                     - May allow authentication bypass\n\n\
                     **Safe alternatives:**\n\
                     - Use parameterized queries with sqlx: `sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(id)`\n\
                     - Use diesel's type-safe query builder\n\
                     - Use sea-orm's entity-based queries\n\n\
                     **Example fix:**\n\
                     ```rust\n\
                     // Instead of:\n\
                     // let q = format!(\"SELECT * FROM users WHERE id = {{}}\", id);\n\
                     \n\
                     // Use:\n\
                     sqlx::query(\"SELECT * FROM users WHERE id = $1\")\n    \
                         .bind(id)\n    \
                         .fetch_one(&pool)\n    \
                         .await?;\n\
                     ```",
                    line,
                    macro_inv.function_name.as_deref().unwrap_or("<unknown>")
                );

                let fix_preview = "// Use parameterized queries instead of format!:\n\
                     sqlx::query(\"SELECT * FROM table WHERE col = $1\")\n    \
                         .bind(value)\n    \
                         .fetch_one(&pool)\n    \
                         .await?;"
                    .to_string();

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// SECURITY: Replace format!() with parameterized query"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::SecurityVulnerability,
                    severity: Severity::Critical,
                    confidence: 0.85,
                    dimension: Dimension::Security,
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
                        "security".into(),
                        "sql-injection".into(),
                        "owasp".into(),
                    ],
                });
            }

            // Also check call sites for raw SQL execution
            for call in &rust.calls {
                // Look for patterns like client.execute() with format! or string concat
                let callee_lower = call.function_call.callee_expr.to_lowercase();

                if !(callee_lower.contains(".execute(")
                    || callee_lower.contains(".query(")
                    || callee_lower.contains("raw_sql(")
                    || callee_lower.contains("sql("))
                {
                    continue;
                }

                // Check if there's a format! or concat in the call
                if !self.is_format_sql(&call.function_call.callee_expr)
                    && !self.is_concat_sql(&call.function_call.callee_expr)
                {
                    continue;
                }

                let line = call.function_call.location.line;

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "Raw SQL execution with string interpolation".to_string(),
                    description: Some(format!(
                        "A raw SQL call uses string interpolation at line {}.\n\
                         Use parameterized queries instead.",
                        line
                    )),
                    kind: FindingKind::SecurityVulnerability,
                    severity: Severity::Critical,
                    confidence: 0.90,
                    dimension: Dimension::Security,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: None,
                    fix_preview: None,
                    tags: vec!["rust".into(), "security".into(), "sql-injection".into()],
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
            path: "sql_code.rs".to_string(),
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
        let rule = RustSqlInjectionRule::new();
        assert_eq!(rule.id(), "rust.sql_injection");
    }

    #[test]
    fn rule_name_mentions_sql() {
        let rule = RustSqlInjectionRule::new();
        assert!(rule.name().to_lowercase().contains("sql"));
    }

    #[test]
    fn contains_sql_detects_keywords() {
        let rule = RustSqlInjectionRule::new();
        assert!(rule.contains_sql("SELECT * FROM users"));
        assert!(rule.contains_sql("INSERT INTO users"));
        assert!(rule.contains_sql("UPDATE users SET"));
        assert!(rule.contains_sql("DELETE FROM users"));
        assert!(rule.contains_sql("select id from users"));
    }

    #[test]
    fn contains_sql_skips_non_sql() {
        let rule = RustSqlInjectionRule::new();
        assert!(!rule.contains_sql("hello world"));
        assert!(!rule.contains_sql("format!(\"test {}\", x)"));
    }

    #[test]
    fn contains_sql_skips_english_update() {
        // Regression test: "update the endpoint" is English, not SQL
        let rule = RustSqlInjectionRule::new();
        assert!(
            !rule.contains_sql("# Then update the {} {} endpoint to use it:"),
            "English phrase 'update the' should not match SQL UPDATE"
        );
        assert!(
            !rule.contains_sql("Please update the documentation"),
            "English phrase should not match"
        );
        assert!(
            !rule.contains_sql("select your preferred option"),
            "English phrase should not match SQL SELECT"
        );
        assert!(
            !rule.contains_sql("delete the file when done"),
            "English phrase should not match SQL DELETE"
        );
    }

    #[test]
    fn contains_sql_detects_real_sql_update() {
        // Ensure real SQL UPDATE statements are still detected
        let rule = RustSqlInjectionRule::new();
        assert!(
            rule.contains_sql("UPDATE users SET name = 'test'"),
            "Real SQL UPDATE should match"
        );
        assert!(
            rule.contains_sql("update users set email = 'x'"),
            "Lowercase SQL UPDATE should match"
        );
    }

    // ==================== is_safe_format_string tests ====================

    #[test]
    fn safe_format_string_with_parameterized_placeholders() {
        let rule = RustSqlInjectionRule::new();
        // Strings containing parameterized query placeholders are safe (documentation/examples)
        assert!(
            rule.is_safe_format_string("Use sqlx::query(\"SELECT * FROM users WHERE id = $1\")"),
            "$1 placeholder indicates safe parameterized query example"
        );
        assert!(
            rule.is_safe_format_string("Example: INSERT INTO users VALUES ($1, $2, $3)"),
            "$1, $2, $3 placeholders indicate safe example"
        );
    }

    #[test]
    fn safe_format_string_with_named_parameters() {
        let rule = RustSqlInjectionRule::new();
        assert!(
            rule.is_safe_format_string("Use named params: WHERE id = :id"),
            ":id named parameter indicates safe pattern"
        );
        assert!(
            rule.is_safe_format_string("SELECT * FROM users WHERE name = :name"),
            ":name named parameter indicates safe pattern"
        );
        assert!(
            rule.is_safe_format_string("INSERT INTO t (v) VALUES (:value)"),
            ":value named parameter indicates safe pattern"
        );
    }

    #[test]
    fn safe_format_string_with_escaped_sql() {
        let rule = RustSqlInjectionRule::new();
        // SQL within escaped quotes is documentation, not actual SQL
        assert!(
            rule.is_safe_format_string(r#"sqlx::query(\"SELECT * FROM users\")"#),
            "Escaped SELECT indicates documentation"
        );
        assert!(
            rule.is_safe_format_string(r#"conn.execute(\"INSERT INTO logs\")"#),
            "Escaped INSERT indicates documentation"
        );
        assert!(
            rule.is_safe_format_string(r#"Format: \"UPDATE users SET name = 'x'\""#),
            "Escaped UPDATE indicates documentation"
        );
        assert!(
            rule.is_safe_format_string(r#"Run: \"DELETE FROM cache\""#),
            "Escaped DELETE indicates documentation"
        );
    }

    #[test]
    fn safe_format_string_with_documentation_markers() {
        let rule = RustSqlInjectionRule::new();
        assert!(
            rule.is_safe_format_string("Example: SELECT * FROM users"),
            "'Example:' indicates documentation"
        );
        assert!(
            rule.is_safe_format_string("Instead of: format!(\"SELECT...\")"),
            "'Instead of:' indicates documentation"
        );
        assert!(
            rule.is_safe_format_string("// Use: parameterized queries"),
            "'// Use:' indicates documentation"
        );
        assert!(
            rule.is_safe_format_string("Safe alternative: sqlx::query"),
            "'Safe alternative' indicates documentation"
        );
    }

    #[test]
    fn unsafe_format_string_without_safety_indicators() {
        let rule = RustSqlInjectionRule::new();
        // These should NOT be considered safe
        assert!(
            !rule.is_safe_format_string("SELECT * FROM users WHERE id = {}"),
            "Raw format placeholder without safety indicators is unsafe"
        );
        assert!(
            !rule.is_safe_format_string("Building query for user {}"),
            "Simple interpolation without SQL safety indicators"
        );
    }

    #[tokio::test]
    async fn detects_format_with_select() {
        let rule = RustSqlInjectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn get_user(id: i32) {
    let query = format!("SELECT * FROM users WHERE id = {}", id);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.sql_injection"),
            "Should detect format! with SQL"
        );
    }

    #[tokio::test]
    async fn skips_format_without_sql() {
        let rule = RustSqlInjectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn greet(name: &str) {
    let msg = format!("Hello, {}!", name);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let sql_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.sql_injection")
            .collect();
        assert!(
            sql_findings.is_empty(),
            "Should not flag format! without SQL"
        );
    }

    #[tokio::test]
    async fn finding_has_critical_severity() {
        let rule = RustSqlInjectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn get_user(id: i32) {
    let query = format!("SELECT * FROM users WHERE id = {}", id);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        for finding in &findings {
            if finding.rule_id == "rust.sql_injection" {
                assert_eq!(finding.severity, Severity::Critical);
                assert_eq!(finding.dimension, Dimension::Security);
            }
        }
    }

    #[tokio::test]
    async fn skips_test_functions() {
        let rule = RustSqlInjectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
#[test]
fn test_query() {
    let query = format!("SELECT * FROM users WHERE id = {}", 1);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let sql_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.sql_injection")
            .collect();
        assert!(sql_findings.is_empty(), "Should skip test functions");
    }

    #[tokio::test]
    async fn skips_format_with_parameterized_examples() {
        // Regression test: format! that contains SQL examples with $1 placeholders
        // should NOT be flagged (this is documentation, not actual SQL injection)
        let rule = RustSqlInjectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn build_error_message(line: u32) {
    let desc = format!(
        "Error at line {}.\n\
         Use: sqlx::query(\"SELECT * FROM users WHERE id = $1\").bind(id)",
        line
    );
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let sql_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.sql_injection")
            .collect();
        assert!(
            sql_findings.is_empty(),
            "Should not flag format! containing SQL documentation with $1 placeholders"
        );
    }

    #[tokio::test]
    async fn skips_format_with_documentation_markers() {
        // Regression test: format! with "Example:" or "Instead of:" markers
        let rule = RustSqlInjectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn build_help_text(func_name: &str) {
    let help = format!(
        "Example: Use SELECT * FROM table instead of raw queries in {}",
        func_name
    );
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let sql_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.sql_injection")
            .collect();
        assert!(
            sql_findings.is_empty(),
            "Should not flag format! containing 'Example:' documentation marker"
        );
    }

    #[tokio::test]
    async fn still_detects_actual_sql_injection() {
        // Ensure we still catch actual SQL injection even with similar patterns
        let rule = RustSqlInjectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn dangerous_query(user_input: &str) {
    let query = format!("SELECT * FROM users WHERE name = '{}'", user_input);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.sql_injection"),
            "Should still detect actual SQL injection vulnerabilities"
        );
    }
}
