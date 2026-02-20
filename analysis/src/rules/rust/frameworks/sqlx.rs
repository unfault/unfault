//! SQLx database rules for detecting production-readiness issues.
//!
//! SQLx is a popular async database library for Rust. These rules detect common
//! issues that can affect reliability and performance.

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

// ================== Missing Pool Timeout Rule ==================

/// Rule that detects SQLx connection pools without timeout configuration.
///
/// Connection pools should have acquire timeouts to prevent indefinite blocking
/// when the pool is exhausted or the database is slow.
#[derive(Debug, Default)]
pub struct SqlxMissingPoolTimeoutRule;

impl SqlxMissingPoolTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

/// Check if a file uses SQLx
fn uses_sqlx(rust: &crate::semantics::rust::model::RustFileSemantics) -> bool {
    rust.uses.iter().any(|u| u.path.contains("sqlx"))
}

#[async_trait]
impl Rule for SqlxMissingPoolTimeoutRule {
    fn id(&self) -> &'static str {
        "rust.sqlx.missing_pool_timeout"
    }

    fn name(&self) -> &'static str {
        "SQLx connection pool without timeout configuration"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
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

            // Only check files that use SQLx
            if !uses_sqlx(rust) {
                continue;
            }

            // Look for pool creation patterns
            for call in &rust.calls {
                let is_pool_creation = call.function_call.callee_expr.contains("PgPoolOptions")
                    || call.function_call.callee_expr.contains("MySqlPoolOptions")
                    || call.function_call.callee_expr.contains("SqlitePoolOptions")
                    || call.function_call.callee_expr.contains("Pool::connect")
                    || call.function_call.callee_expr.contains("PoolOptions");

                if !is_pool_creation {
                    continue;
                }

                let line = call.function_call.location.line;

                // Check if timeout configuration is present nearby
                let has_acquire_timeout = rust.calls.iter().any(|c| {
                    c.function_call.callee_expr.contains("acquire_timeout")
                        && (c.function_call.location.line as i64
                            - call.function_call.location.line as i64)
                            .abs()
                            < 10
                });

                if has_acquire_timeout {
                    continue;
                }

                let title = "SQLx connection pool without acquire timeout".to_string();

                let description = format!(
                    "A SQLx connection pool is created at line {} without an acquire timeout.\n\n\
                     **Why this matters:**\n\
                     - Requests can block indefinitely waiting for connections\n\
                     - Pool exhaustion can cascade across the application\n\
                     - No way to fail fast when database is overloaded\n\
                     - Difficult to diagnose connection pool issues\n\n\
                     **Recommendations:**\n\
                     - Set `acquire_timeout` on the pool options\n\
                     - Use a reasonable timeout (e.g., 5-10 seconds)\n\
                     - Configure `max_connections` appropriately\n\
                     - Consider setting `idle_timeout` and `max_lifetime`\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use sqlx::postgres::PgPoolOptions;\n\
                     use std::time::Duration;\n\
                     \n\
                     let pool = PgPoolOptions::new()\n    \
                         .max_connections(5)\n    \
                         .acquire_timeout(Duration::from_secs(5))\n    \
                         .idle_timeout(Duration::from_secs(300))\n    \
                         .max_lifetime(Duration::from_secs(3600))\n    \
                         .connect(&database_url)\n    \
                         .await?;\n\
                     ```",
                    line
                );

                let fix_preview = "use sqlx::postgres::PgPoolOptions;\n\
                     use std::time::Duration;\n\n\
                     let pool = PgPoolOptions::new()\n    \
                         .max_connections(5)\n    \
                         .acquire_timeout(Duration::from_secs(5))\n    \
                         .idle_timeout(Duration::from_secs(300))\n    \
                         .connect(&database_url)\n    \
                         .await?;"
                    .to_string();

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Add acquire_timeout to pool configuration"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::ReliabilityRisk,
                    severity: Severity::High,
                    confidence: 0.80,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "sqlx".into(),
                        "database".into(),
                        "timeout".into(),
                    ],
                });
            }
        }

        findings
    }
}

// ================== Query Without Timeout Rule ==================

/// Rule that detects SQLx queries without timeout configuration.
///
/// Database queries should have timeouts to prevent slow queries from
/// blocking the application indefinitely.
#[derive(Debug, Default)]
pub struct SqlxQueryWithoutTimeoutRule;

impl SqlxQueryWithoutTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for SqlxQueryWithoutTimeoutRule {
    fn id(&self) -> &'static str {
        "rust.sqlx.query_without_timeout"
    }

    fn name(&self) -> &'static str {
        "SQLx query without timeout"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
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

            // Only check files that use SQLx
            if !uses_sqlx(rust) {
                continue;
            }

            // Check if tokio timeout is available
            let uses_tokio_timeout = rust
                .uses
                .iter()
                .any(|u| u.path.contains("tokio::time::timeout") || u.path.contains("timeout"));

            // Look for query execution patterns
            for call in &rust.calls {
                let is_query = call.function_call.callee_expr.contains("query(")
                    || call.function_call.callee_expr.contains("query_as")
                    || call.function_call.callee_expr.contains("query_scalar")
                    || call.function_call.callee_expr.contains("fetch_one")
                    || call.function_call.callee_expr.contains("fetch_all")
                    || call.function_call.callee_expr.contains("fetch_optional")
                    || call.function_call.callee_expr.contains("execute");

                if !is_query {
                    continue;
                }

                // Skip if it appears to be wrapped in a timeout
                // Check surrounding context for timeout usage
                let has_timeout_wrapper = rust.calls.iter().any(|c| {
                    c.function_call.callee_expr.contains("timeout")
                        && (c.function_call.location.line <= call.function_call.location.line)
                        && (c.function_call.location.line >= call.function_call.location.line)
                });

                if has_timeout_wrapper || uses_tokio_timeout {
                    continue;
                }

                let line = call.function_call.location.line;

                let title = format!("SQLx query at line {} may run indefinitely", line);

                let description = format!(
                    "A database query at line {} doesn't appear to have a timeout.\n\n\
                     **Why this matters:**\n\
                     - Slow queries can block request handlers indefinitely\n\
                     - Database locks can cause cascading failures\n\
                     - Resource exhaustion from accumulated slow queries\n\
                     - Poor user experience with unresponsive endpoints\n\n\
                     **Recommendations:**\n\
                     - Wrap queries with `tokio::time::timeout`\n\
                     - Use database-level statement timeout as fallback\n\
                     - Set appropriate timeout based on expected query time\n\
                     - Log slow queries for optimization\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use tokio::time::{{timeout, Duration}};\n\
                     \n\
                     let result = timeout(\n    \
                         Duration::from_secs(5),\n    \
                         sqlx::query(\"SELECT * FROM users\")\n        \
                             .fetch_all(&pool)\n\
                     )\n\
                     .await\n\
                     .map_err(|_| QueryTimeoutError)?;\n\
                     ```",
                    line
                );

                let fix_preview = "use tokio::time::{timeout, Duration};\n\n\
                     let result = timeout(\n    \
                         Duration::from_secs(5),\n    \
                         sqlx::query_as::<_, User>(\"SELECT * FROM users\")\n        \
                             .fetch_all(&pool)\n\
                     )\n\
                     .await\n\
                     .map_err(|_| AppError::QueryTimeout)??;"
                    .to_string();

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Wrap query with tokio::time::timeout".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::ReliabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.70,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "sqlx".into(),
                        "database".into(),
                        "timeout".into(),
                    ],
                });
            }
        }

        findings
    }
}

// ================== Missing Transaction Handling Rule ==================

/// Rule that detects SQLx database operations that should be in a transaction.
///
/// Multiple related database operations should be wrapped in a transaction
/// to ensure atomicity and consistency.
#[derive(Debug, Default)]
pub struct SqlxMissingTransactionRule;

impl SqlxMissingTransactionRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for SqlxMissingTransactionRule {
    fn id(&self) -> &'static str {
        "rust.sqlx.missing_transaction"
    }

    fn name(&self) -> &'static str {
        "Multiple SQLx operations without transaction"
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

            // Only check files that use SQLx
            if !uses_sqlx(rust) {
                continue;
            }

            // Check for transaction usage
            let uses_transactions = rust.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("begin()")
                    || c.function_call.callee_expr.contains("transaction")
            });

            if uses_transactions {
                continue;
            }

            // Look for functions with multiple writes
            for func in &rust.functions {
                if func.is_test {
                    continue;
                }

                // Count write operations in the function
                let writes_in_func: Vec<_> = rust
                    .calls
                    .iter()
                    .filter(|c| {
                        c.function_name.as_deref() == Some(&func.name)
                            && (c.function_call.callee_expr.contains("INSERT")
                                || c.function_call.callee_expr.contains("UPDATE")
                                || c.function_call.callee_expr.contains("DELETE")
                                || c.function_call.callee_expr.contains("execute"))
                    })
                    .collect();

                // Only flag if there are multiple write operations
                if writes_in_func.len() < 2 {
                    continue;
                }

                let line = func.location.range.start_line + 1;

                let title = format!(
                    "Function '{}' has {} database writes without a transaction",
                    func.name,
                    writes_in_func.len()
                );

                let description = format!(
                    "The function '{}' at line {} performs {} database write operations \
                     without wrapping them in a transaction.\n\n\
                     **Why this matters:**\n\
                     - Partial failures leave database in inconsistent state\n\
                     - No atomicity guarantees for related changes\n\
                     - Race conditions with concurrent operations\n\
                     - Difficult to roll back on errors\n\n\
                     **Recommendations:**\n\
                     - Wrap related operations in a transaction\n\
                     - Use `pool.begin()` to start a transaction\n\
                     - Call `.commit()` on success\n\
                     - Transactions auto-rollback on drop if not committed\n\n\
                     **Example:**\n\
                     ```rust\n\
                     let mut tx = pool.begin().await?;\n\
                     \n\
                     sqlx::query(\"INSERT INTO ...\")\n    \
                         .execute(&mut *tx)\n    \
                         .await?;\n\
                     \n\
                     sqlx::query(\"UPDATE ...\")\n    \
                         .execute(&mut *tx)\n    \
                         .await?;\n\
                     \n\
                     tx.commit().await?;\n\
                     ```",
                    func.name,
                    line,
                    writes_in_func.len()
                );

                let fix_preview = "let mut tx = pool.begin().await?;\n\n\
                     // ... database operations using &mut *tx ...\n\n\
                     tx.commit().await?;"
                    .to_string();

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line: line + 1 },
                        replacement: "    // TODO: Wrap database operations in a transaction - use pool.begin()".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::High,
                    confidence: 0.75,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "sqlx".into(),
                        "database".into(),
                        "transaction".into(),
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
    use crate::semantics::SourceSemantics;
    use crate::semantics::rust::build_rust_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "db.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_rust_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Rust(sem)))
    }

    #[test]
    fn pool_timeout_rule_id_is_correct() {
        let rule = SqlxMissingPoolTimeoutRule::new();
        assert_eq!(rule.id(), "rust.sqlx.missing_pool_timeout");
    }

    #[test]
    fn query_timeout_rule_id_is_correct() {
        let rule = SqlxQueryWithoutTimeoutRule::new();
        assert_eq!(rule.id(), "rust.sqlx.query_without_timeout");
    }

    #[test]
    fn transaction_rule_id_is_correct() {
        let rule = SqlxMissingTransactionRule::new();
        assert_eq!(rule.id(), "rust.sqlx.missing_transaction");
    }

    #[tokio::test]
    async fn skips_non_sqlx_files() {
        let rule = SqlxMissingPoolTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn main() {
    println!("Hello");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should skip non-SQLx files");
    }

    #[tokio::test]
    async fn detects_missing_pool_timeout() {
        let rule = SqlxMissingPoolTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use sqlx::postgres::PgPoolOptions;

async fn create_pool() -> sqlx::Pool<sqlx::Postgres> {
    PgPoolOptions::new()
        .max_connections(5)
        .connect("postgres://localhost/test")
        .await
        .unwrap()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "rust.sqlx.missing_pool_timeout"),
            "Should detect missing pool timeout"
        );
    }

    #[tokio::test]
    async fn skips_pool_with_timeout() {
        let rule = SqlxMissingPoolTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

async fn create_pool() -> sqlx::Pool<sqlx::Postgres> {
    PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect("postgres://localhost/test")
        .await
        .unwrap()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let pool_timeout_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.sqlx.missing_pool_timeout")
            .collect();
        assert!(
            pool_timeout_findings.is_empty(),
            "Should not flag pool with acquire_timeout"
        );
    }
}
