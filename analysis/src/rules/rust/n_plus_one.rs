//! Rule: N+1 query pattern detection
//!
//! Detects database queries executed inside loops that can lead to
//! severe performance degradation.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! for user_id in user_ids {
//!     let orders = sqlx::query!("SELECT * FROM orders WHERE user_id = ?", user_id)
//!         .fetch_all(&pool).await?;
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! let orders = sqlx::query!("SELECT * FROM orders WHERE user_id = ANY(?)", &user_ids)
//!     .fetch_all(&pool).await?;
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

/// Rule that detects N+1 query patterns.
///
/// Executing a query per item in a collection causes N+1 database
/// round-trips, severely impacting performance and database load.
#[derive(Debug, Default)]
pub struct RustNPlusOneRule;

impl RustNPlusOneRule {
    pub fn new() -> Self {
        Self
    }
}

/// Database query patterns to detect
const QUERY_PATTERNS: &[&str] = &[
    // SQLx
    "sqlx::query",
    "sqlx::query_as",
    "sqlx::query!",
    "sqlx::query_as!",
    ".fetch_one(",
    ".fetch_all(",
    ".fetch_optional(",
    ".fetch(",
    ".execute(",
    // Diesel
    "diesel::select",
    "diesel::insert_into",
    "diesel::update",
    "diesel::delete",
    ".load(",
    ".get_result(",
    ".first(&",  // Diesel's first takes a connection: .first(&conn) - not slice .first()
    // SeaORM
    "Entity::find",
    ".find_by_id(",
    // General
    "query(",
    "query_one(",
    "query_opt(",
];

/// Patterns that suggest batching is already used
const BATCH_PATTERNS: &[&str] = &[
    "ANY(",
    "IN (",
    "IN(",
    "= ANY",
    "WHERE id IN",
    "batch",
    "bulk",
    "multi_get",
    "find_many",
    "fetch_all_by",
];

#[async_trait]
impl Rule for RustNPlusOneRule {
    fn id(&self) -> &'static str {
        "rust.n_plus_one"
    }

    fn name(&self) -> &'static str {
        "N+1 query pattern causes severe performance degradation"
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

            // Find queries executed in loops
            for call in &rust.calls {
                // Must be in a loop
                if !call.in_loop {
                    continue;
                }

                let callee = &call.function_call.callee_expr;

                // Helper to check if callee is a string literal (regular or raw)
                let is_string_literal = callee.starts_with('"')
                    || callee.starts_with("r#\"")
                    || callee.starts_with("r\"");

                // Check if this is a database query pattern using the actual method name
                // to avoid false positives from string literals containing query-like text.
                // For method calls, check the method_name field; for function calls, check the callee.
                let is_query = if let Some(method) = &call.method_name {
                    // Method call: check if the method name matches a query pattern (e.g., "fetch_one")
                    QUERY_PATTERNS.iter().any(|p| {
                        let pattern = p.trim_start_matches('.');
                        let pattern = pattern.trim_end_matches('(');
                        method == pattern
                    }) || QUERY_PATTERNS.iter().any(|p| callee.contains(p) && !is_string_literal)
                } else {
                    // Function call: check the callee text, but skip if it starts with a string literal
                    !is_string_literal && QUERY_PATTERNS.iter().any(|p| callee.contains(p))
                };

                if !is_query {
                    continue;
                }

                // Check if it might be a batch query
                let is_batch = BATCH_PATTERNS.iter().any(|p| callee.contains(p) && !is_string_literal);

                if is_batch {
                    continue;
                }

                let line = call.function_call.location.line;
                let func_name = call.function_name.clone().unwrap_or_else(|| "function".to_string());

                let title = format!(
                    "N+1 query pattern: database call in loop in '{}'",
                    func_name
                );

                let description = format!(
                    "The database query at line {} is executed inside a loop, \
                    causing N+1 database round-trips.\n\n\
                    **Performance Impact:**\n\
                    - For N items, executes N+1 queries (1 for main + N in loop)\n\
                    - Each query has network latency overhead\n\
                    - Database connection pool exhaustion under load\n\
                    - Linear scaling: 100 items = 100 queries\n\n\
                    **Solution patterns:**\n\
                    1. **Batch query:** Fetch all IDs in one `WHERE id IN (...)` query\n\
                    2. **Join/eager loading:** Use SQL JOIN to fetch related data\n\
                    3. **Prefetch:** Load all needed data before the loop",
                    line
                );

                let fix_preview = r#"// Before (N+1):
for user_id in user_ids {
    let orders = sqlx::query!("SELECT * FROM orders WHERE user_id = ?", user_id)
        .fetch_all(&pool).await?;
}

// After (batch query):
let orders = sqlx::query!(
    "SELECT * FROM orders WHERE user_id = ANY($1)",
    &user_ids
).fetch_all(&pool).await?;

// Group by user_id in application code:
let orders_by_user: HashMap<_, Vec<_>> = orders
    .into_iter()
    .into_group_map_by(|o| o.user_id);"#.to_string();

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: N+1 query - refactor to batch query with WHERE id IN (...)\n".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::PerformanceSmell,
                    severity: Severity::High,
                    confidence: 0.85,
                    dimension: Dimension::Performance,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "database".into(),
                        "n+1".into(),
                        "performance".into(),
                        "loop".into(),
                    ],
                });
            }

            // Also check for fetch inside for_each or map
            for call in &rust.calls {
                let callee = &call.function_call.callee_expr;

                // Skip calls on string literals (false positives from documentation/examples)
                // This includes regular strings ("...") and raw strings (r#"..."#, r"...")
                if callee.starts_with('"') || callee.starts_with("r#\"") || callee.starts_with("r\"") {
                    continue;
                }

                // Check for iterator patterns that might hide N+1
                if (callee.contains(".map(") || callee.contains(".for_each("))
                    && QUERY_PATTERNS.iter().any(|p| callee.contains(p))
                {
                    let line = call.function_call.location.line;

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Potential N+1 query in iterator".to_string(),
                        description: Some(format!(
                            "The pattern at line {} may execute a query per item in an iterator.\n\
                            Consider pre-fetching data or using batch queries.",
                            line
                        )),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::Medium,
                        confidence: 0.70,
                        dimension: Dimension::Performance,
                        file_id: *file_id,
                        file_path: rust.path.clone(),
                        line: Some(line),
                        column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: None,
                        tags: vec![
                            "rust".into(),
                            "database".into(),
                            "n+1".into(),
                            "iterator".into(),
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
    use crate::parse::rust::parse_rust_file;
    use crate::semantics::rust::build_rust_semantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "db_code.rs".to_string(),
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
        let rule = RustNPlusOneRule::new();
        assert_eq!(rule.id(), "rust.n_plus_one");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustNPlusOneRule::new();
        assert!(rule.name().contains("N+1"));
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = RustNPlusOneRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn query_patterns_are_valid() {
        for pattern in QUERY_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[test]
    fn batch_patterns_are_valid() {
        for pattern in BATCH_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[tokio::test]
    async fn no_finding_for_non_loop_query() {
        let rule = RustNPlusOneRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
async fn get_user(pool: &Pool, id: i64) {
    let user = sqlx::query!("SELECT * FROM users WHERE id = ?", id)
        .fetch_one(pool).await;
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        
        // No loop = no N+1
        let n_plus_one_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.n_plus_one")
            .collect();
        assert!(n_plus_one_findings.is_empty() || n_plus_one_findings.iter().all(|f| f.confidence < 0.8));
    }

    #[tokio::test]
    async fn no_finding_for_string_literal_containing_query_patterns() {
        // Regression test: string literals containing database query patterns
        // (like example code or documentation) should NOT trigger N+1 findings
        let rule = RustNPlusOneRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn generate_error_message(line: u32) {
    for i in 0..10 {
        // This string literal contains .fetch_one() pattern but should NOT be flagged
        let fix_preview =
            "// Use parameterized queries instead of format!:\n\
             sqlx::query(\"SELECT * FROM table WHERE col = $1\")\n    \
                 .bind(value)\n    \
                 .fetch_one(&pool)\n    \
                 .await?;".to_string();
        println!("{}", fix_preview);
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        
        let n_plus_one_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.n_plus_one")
            .collect();
        
        assert!(
            n_plus_one_findings.is_empty(),
            "String literals containing query patterns should NOT trigger N+1 findings. Found: {:?}",
            n_plus_one_findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn no_finding_for_slice_first_in_loop() {
        // Regression test: Vec/slice .first() method should NOT trigger N+1 findings
        // Only Diesel's .first(&conn) should be detected (takes a connection parameter)
        let rule = RustNPlusOneRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
struct App {
    var_name: String,
}

struct FastApi {
    apps: Vec<App>,
}

fn process_routes(fastapi: &FastApi) {
    for i in 0..10 {
        // This is slice .first() - NOT a database query
        let app_var_name = fastapi
            .apps
            .first()
            .map(|a| a.var_name.clone());
        println!("{:?}", app_var_name);
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        let n_plus_one_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.n_plus_one")
            .collect();

        assert!(
            n_plus_one_findings.is_empty(),
            "Slice/Vec .first() should NOT trigger N+1 findings. Found: {:?}",
            n_plus_one_findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}