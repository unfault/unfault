//! Rule: Transaction boundary in Go
//!
//! Detects database transactions that span too long or aren't properly committed/rolled back.

use std::sync::Arc;
use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::transaction_boundary;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects transaction boundary issues.
#[derive(Debug, Default)]
pub struct GoTransactionBoundaryRule;

impl GoTransactionBoundaryRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoTransactionBoundaryRule {
    fn id(&self) -> &'static str {
        "go.transaction_boundary"
    }

    fn name(&self) -> &'static str {
        "Transaction boundary issues"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(transaction_boundary())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Check for database imports
            let uses_db = go.imports.iter().any(|imp| {
                imp.path.contains("database/sql") ||
                imp.path.contains("gorm") ||
                imp.path.contains("sqlx") ||
                imp.path.contains("pgx")
            });

            if !uses_db {
                continue;
            }

            // Look for transaction-related calls
            let mut has_begin = false;
            let mut has_commit = false;
            let mut has_rollback = false;
            let mut has_defer_rollback = false;
            let mut has_http_call = false;
            let mut begin_call_location = None;

            for call in &go.calls {
                let callee = &call.function_call.callee_expr;
                
                if callee.ends_with(".Begin") || callee.ends_with(".BeginTx") || callee.contains("Transaction") {
                    has_begin = true;
                    begin_call_location = Some(&call.function_call.location);
                }
                if callee.ends_with(".Commit") {
                    has_commit = true;
                }
                if callee.ends_with(".Rollback") {
                    has_rollback = true;
                }
                
                // Check for HTTP calls
                if callee.starts_with("http.") && 
                   (callee.contains("Get") || callee.contains("Post") || callee.contains("Do")) {
                    has_http_call = true;
                }
            }

            // Check defers for rollback
            for defer_stmt in &go.defers {
                if defer_stmt.call_text.contains("Rollback") {
                    has_defer_rollback = true;
                }
            }

            // Report findings based on transaction patterns
            if has_begin {
                if let Some(loc) = begin_call_location {
                    let line = loc.line + 1;
                    let _column = loc.column + 1;

                    // Transaction without defer rollback
                    if !has_defer_rollback {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Transaction without defer rollback".to_string(),
                            description: Some(
                                "Database transactions should have 'defer tx.Rollback()' \
                                 immediately after Begin to ensure cleanup on panic or \
                                 early return. Rollback after Commit is a no-op.".to_string()
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.85,
                            dimension: Dimension::Reliability,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertAfterLine { line },
                                    replacement: 
"\tdefer tx.Rollback() // Safe: no-op if Commit() succeeds".to_string(),
                                }],
                            }),
                            fix_preview: Some("Add defer tx.Rollback()".to_string()),
                            tags: vec!["go".into(), "database".into(), "transaction".into()],
                        });
                    }

                    // Transaction without commit (missing success path)
                    if !has_commit && has_rollback {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Transaction never committed".to_string(),
                            description: Some(
                                "Transaction is started but never committed. Ensure \
                                 tx.Commit() is called on the success path.".to_string()
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.80,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line },
                                    replacement: "// Add tx.Commit() at the end of successful operations".to_string(),
                                }],
                            }),
                            fix_preview: Some("Add tx.Commit()".to_string()),
                            tags: vec!["go".into(), "database".into(), "transaction".into()],
                        });
                    }

                    // Check for HTTP calls within transaction context
                    if has_http_call {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "HTTP call within database transaction context".to_string(),
                            description: Some(
                                "HTTP calls within a transaction hold database connections \
                                 and can cause connection pool exhaustion if the HTTP call \
                                 is slow. Move HTTP calls outside the transaction.".to_string()
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.75,
                            dimension: Dimension::Scalability,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line },
                                    replacement: "// Move HTTP calls outside the transaction to avoid holding connections".to_string(),
                                }],
                            }),
                            fix_preview: Some("Move HTTP calls outside transaction".to_string()),
                            tags: vec!["go".into(), "database".into(), "transaction".into(), "performance".into()],
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

    #[test]
    fn test_rule_metadata() {
        let rule = GoTransactionBoundaryRule::new();
        assert_eq!(rule.id(), "go.transaction_boundary");
        assert!(!rule.name().is_empty());
    }
}