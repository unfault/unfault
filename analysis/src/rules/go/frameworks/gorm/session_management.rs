//! Rule: GORM Session/Transaction Management
//!
//! Detects improper GORM session and transaction management patterns.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::transaction_boundary;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::go::GoFileSemantics;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects improper GORM session/transaction management.
///
/// Issues detected:
/// - Multiple write operations without explicit transaction
/// - Transaction without proper commit/rollback handling
/// - Missing rollback in error paths
#[derive(Debug, Default)]
pub struct GormSessionManagementRule;

impl GormSessionManagementRule {
    pub fn new() -> Self {
        Self
    }
}

/// Session management issue.
#[derive(Debug, Clone)]
struct SessionIssue {
    line: u32,
    issue_type: SessionIssueType,
}

#[derive(Debug, Clone)]
enum SessionIssueType {
    MultipleWritesNoTransaction,
    TransactionNoRollback,
}

#[async_trait]
impl Rule for GormSessionManagementRule {
    fn id(&self) -> &'static str {
        "go.gorm.improper_session"
    }

    fn name(&self) -> &'static str {
        "GORM Improper Session Management"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go_sem = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Check if GORM is imported
            let has_gorm = go_sem.imports.iter().any(|imp| {
                imp.path.contains("gorm.io/gorm")
                    || imp.path.contains("github.com/jinzhu/gorm")
            });

            if !has_gorm {
                continue;
            }

            // Analyze functions for session issues
            if let Some(issue) = analyze_for_session_issues(go_sem) {
                findings.push(create_finding(*file_id, go_sem, issue, self));
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(transaction_boundary())
    }
}

/// Analyze a file for session management issues.
fn analyze_for_session_issues(sem: &GoFileSemantics) -> Option<SessionIssue> {
    // Count write operations
    let mut write_count = 0;
    let mut has_transaction = false;
    let mut has_begin = false;
    let mut has_rollback = false;
    let mut first_write_line = None;

    for call in &sem.calls {
        // Check for write operations
        if is_write_operation(&call.function_call.callee_expr) {
            write_count += 1;
            if first_write_line.is_none() {
                first_write_line = Some(call.function_call.location.line);
            }
        }

        // Check for transaction handling
        if call.function_call.callee_expr.contains("Begin") || call.function_call.callee_expr.contains(".Transaction(") {
            has_transaction = true;
            has_begin = true;
        }
        if call.function_call.callee_expr.contains("Rollback") {
            has_rollback = true;
        }
        if call.function_call.callee_expr.contains("Commit") {
            has_transaction = true;
        }
    }

    // Multiple writes without transaction
    if write_count > 1 && !has_transaction {
        return Some(SessionIssue {
            line: first_write_line.unwrap_or(1),
            issue_type: SessionIssueType::MultipleWritesNoTransaction,
        });
    }

    // Transaction without rollback
    if has_begin && !has_rollback {
        return Some(SessionIssue {
            line: first_write_line.unwrap_or(1),
            issue_type: SessionIssueType::TransactionNoRollback,
        });
    }

    None
}

/// Check if a call is a write operation.
fn is_write_operation(callee: &str) -> bool {
    callee.contains(".Create(")
        || callee.contains(".Save(")
        || callee.contains(".Update(")
        || callee.contains(".Updates(")
        || callee.contains(".Delete(")
        || callee.contains(".Exec(")
        || callee.ends_with(".Create")
        || callee.ends_with(".Save")
        || callee.ends_with(".Update")
        || callee.ends_with(".Delete")
}

/// Create a finding from a session issue.
fn create_finding(
    file_id: FileId,
    sem: &GoFileSemantics,
    issue: SessionIssue,
    rule: &GormSessionManagementRule,
) -> RuleFinding {
    let (title, description, patch_text) = match issue.issue_type {
        SessionIssueType::MultipleWritesNoTransaction => {
            let title = format!(
                "Multiple GORM writes without transaction at line {}",
                issue.line
            );
            let desc = format!(
                "Multiple GORM write operations starting at line {} without explicit transaction. \
                 Wrap in db.Transaction() for atomicity. Without transactions, partial writes \
                 can occur if an error happens mid-operation.",
                issue.line
            );
            let patch = r#"// Wrap multiple write operations in a transaction:
// err := db.Transaction(func(tx *gorm.DB) error {
//     if err := tx.Create(&record1).Error; err != nil {
//         return err
//     }
//     if err := tx.Create(&record2).Error; err != nil {
//         return err
//     }
//     return nil
// })
"#;
            (title, desc, patch)
        }
        SessionIssueType::TransactionNoRollback => {
            let title = format!(
                "GORM transaction missing rollback at line {}",
                issue.line
            );
            let desc = format!(
                "GORM transaction at line {} may be missing rollback on error. \
                 Ensure proper rollback handling to avoid leaving connections in \
                 an inconsistent state.",
                issue.line
            );
            let patch = r#"// Ensure proper transaction handling:
// tx := db.Begin()
// defer func() {
//     if r := recover(); r != nil {
//         tx.Rollback()
//     }
// }()
// if err := tx.Create(&record).Error; err != nil {
//     tx.Rollback()
//     return err
// }
// return tx.Commit().Error
"#;
            (title, desc, patch)
        }
    };

    let patch = FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line: issue.line },
            replacement: patch_text.to_string(),
        }],
    };

    RuleFinding {
        rule_id: rule.id().to_string(),
        title,
        description: Some(description),
        kind: FindingKind::StabilityRisk,
        severity: Severity::Medium,
        confidence: 0.80,
        dimension: Dimension::Reliability,
        file_id,
        file_path: sem.path.clone(),
        line: Some(issue.line),
        column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
        patch: Some(patch),
        fix_preview: Some("// Use db.Transaction() for atomicity".to_string()),
        tags: vec![
            "go".into(),
            "gorm".into(),
            "transaction".into(),
            "database".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_write_detects_create() {
        assert!(is_write_operation("db.Create"));
        assert!(is_write_operation("db.Save"));
        assert!(is_write_operation("db.Update"));
        assert!(is_write_operation("db.Delete"));
    }

    #[test]
    fn is_write_ignores_read() {
        assert!(!is_write_operation("db.Find"));
        assert!(!is_write_operation("db.First"));
        assert!(!is_write_operation("db.Where"));
    }

    #[test]
    fn rule_has_correct_metadata() {
        let rule = GormSessionManagementRule::new();
        assert_eq!(rule.id(), "go.gorm.improper_session");
        assert_eq!(rule.name(), "GORM Improper Session Management");
    }
}