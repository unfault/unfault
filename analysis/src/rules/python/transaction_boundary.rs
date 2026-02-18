use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule: Missing Transaction Boundary
///
/// Detects multiple database writes without transaction wrapping.
/// Without transactions, partial updates can occur if something fails midway.
#[derive(Debug)]
pub struct PythonMissingTransactionBoundaryRule;

impl PythonMissingTransactionBoundaryRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonMissingTransactionBoundaryRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonMissingTransactionBoundaryRule {
    fn id(&self) -> &'static str {
        "python.db.missing_transaction_boundary"
    }

    fn name(&self) -> &'static str {
        "Detects multiple database writes without transaction wrapping to ensure data consistency."
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

            // Check for ORM imports (SQLAlchemy, Django)
            let has_orm = py.imports.iter().any(|imp| {
                imp.module.contains("sqlalchemy")
                    || imp.module.contains("django")
                    || imp.names.iter().any(|n| n == "Session" || n == "transaction")
            });

            if !has_orm {
                continue;
            }

            // Count database write operations in file-level calls
            let db_writes: Vec<_> = py.calls.iter().filter(|call| {
                is_db_write_operation(&call.function_call.callee_expr)
            }).collect();

            if db_writes.len() < 2 {
                continue;
            }

            // Check if transaction handling is present
            let has_transaction = py.calls.iter().any(|call| {
                call.function_call.callee_expr.contains("begin")
                    || call.function_call.callee_expr.contains("transaction")
                    || call.function_call.callee_expr.contains("atomic")
                    || call.function_call.callee_expr.contains("commit")
            }) || py.imports.iter().any(|imp| {
                imp.names.iter().any(|n| n == "transaction" || n == "atomic")
            });

            if has_transaction {
                continue;
            }

            let title = format!(
                "File has {} database writes without transaction boundary",
                db_writes.len()
            );

            let description = format!(
                "This file performs {count} database write operations \
                 without wrapping them in a transaction. If any operation fails midway, \
                 the database will be left in an inconsistent state with partial updates. \
                 Use a transaction context manager to ensure atomicity.",
                count = db_writes.len(),
            );

            let fix_preview = generate_fix_preview();

            // Generate patch
            let patch = generate_transaction_patch(
                *file_id,
                py.module_docstring_end_line.map(|l| l + 1).unwrap_or(1),
            );

            findings.push(RuleFinding {
                rule_id: self.id().to_string(),
                title,
                description: Some(description),
                kind: FindingKind::BehaviorThreat,
                severity: Severity::High,
                confidence: 0.80,
                dimension: Dimension::Correctness,
                file_id: *file_id,
                file_path: py.path.clone(),
                line: Some(db_writes.first().map(|c| c.function_call.location.line + 1).unwrap_or(1)),
                column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                patch: Some(patch),
                fix_preview: Some(fix_preview),
                tags: vec![
                    "python".into(),
                    "database".into(),
                    "transaction".into(),
                    "data-consistency".into(),
                    "atomicity".into(),
                ],
            });
        }

        findings
    }
}

/// Check if a call is a database write operation.
fn is_db_write_operation(callee: &str) -> bool {
    let write_patterns = [
        ".add",
        ".insert",
        ".update",
        ".delete",
        ".save",
        ".create",
        ".bulk_create",
        ".bulk_update",
        ".execute",
        ".flush",
    ];

    write_patterns.iter().any(|pattern| callee.contains(pattern))
}

/// Generate transaction patch with actual imports and context manager wrapper.
fn generate_transaction_patch(file_id: FileId, import_line: u32) -> FilePatch {
    let mut hunks = Vec::new();

    // Add transaction contextmanager import and helper
    let import_str = r#"from contextlib import contextmanager
from sqlalchemy.orm import Session

@contextmanager
def transaction_scope(session: Session):
    """Provide a transactional scope around a series of operations."""
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise

"#;
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: import_line },
        replacement: import_str.to_string(),
    });

    FilePatch { file_id, hunks }
}

/// Generate a fix preview showing how to add transaction boundaries.
fn generate_fix_preview() -> String {
    r#"# SQLAlchemy: Use session context manager
from sqlalchemy.orm import Session

def create_order(db: Session):
    with db.begin():  # Transaction starts here
        db.add(order)
        db.add(payment)
        db.add(audit_log)
        # All succeed or all fail - no partial updates

# Alternative: Use session.begin_nested() for savepoints
def create_order_with_savepoint(db: Session):
    with db.begin():
        db.add(order)
        try:
            with db.begin_nested():  # Savepoint
                db.add(risky_operation)
        except Exception:
            pass  # Savepoint rolled back, outer transaction continues
        db.add(audit_log)

# Django: Use transaction.atomic decorator
from django.db import transaction

@transaction.atomic
def create_order_django():
    Order.objects.create(...)
    Payment.objects.create(...)
    AuditLog.objects.create(...)
    # All succeed or all fail

# Django: Use transaction.atomic context manager
def create_order_django_context():
    with transaction.atomic():
        order = Order.objects.create(...)
        payment = Payment.objects.create(...)
        # Atomic block ensures consistency

# FastAPI with SQLAlchemy dependency
from fastapi import Depends
from sqlalchemy.orm import Session

@app.post("/orders")
def create_order(db: Session = Depends(get_db)):
    with db.begin():
        order = Order(...)
        db.add(order)
        payment = Payment(order_id=order.id, ...)
        db.add(payment)
    return {"order_id": order.id}"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::python::parse_python_file;
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
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed)
            .expect("framework analysis should succeed");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonMissingTransactionBoundaryRule::new();
        assert_eq!(rule.id(), "python.db.missing_transaction_boundary");
    }

    #[test]
    fn rule_name_mentions_transaction() {
        let rule = PythonMissingTransactionBoundaryRule::new();
        assert!(rule.name().contains("transaction"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_db_code() {
        let rule = PythonMissingTransactionBoundaryRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn is_db_write_operation_detects_add() {
        assert!(is_db_write_operation("db.add"));
    }

    #[test]
    fn is_db_write_operation_detects_insert() {
        assert!(is_db_write_operation("table.insert"));
    }

    #[test]
    fn is_db_write_operation_detects_update() {
        assert!(is_db_write_operation("User.update"));
    }

    #[test]
    fn is_db_write_operation_detects_delete() {
        assert!(is_db_write_operation("db.delete"));
    }

    #[test]
    fn is_db_write_operation_ignores_read() {
        assert!(!is_db_write_operation("db.query"));
    }
}