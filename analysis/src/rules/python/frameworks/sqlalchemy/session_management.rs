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

/// Rule: SQLAlchemy Session Not Properly Closed
///
/// Detects SQLAlchemy sessions that are created but may not be properly
/// closed, leading to connection leaks and database connection exhaustion.
#[derive(Debug)]
pub struct SqlAlchemySessionManagementRule;

impl SqlAlchemySessionManagementRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SqlAlchemySessionManagementRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for SqlAlchemySessionManagementRule {
    fn id(&self) -> &'static str {
        "python.sqlalchemy.session_not_closed"
    }

    fn name(&self) -> &'static str {
        "Detects SQLAlchemy sessions that may not be properly closed, causing connection leaks."
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

            // Check for SQLAlchemy imports
            let has_sqlalchemy = py.imports.iter().any(|imp| {
                imp.module.contains("sqlalchemy")
                    || imp.names.iter().any(|n| n == "Session" || n == "sessionmaker" || n == "create_engine")
            });

            if !has_sqlalchemy {
                continue;
            }

            // Look for Session() calls without context manager
            for call in &py.calls {
                let is_session_creation = call.function_call.callee_expr == "Session"
                    || call.function_call.callee_expr.ends_with(".Session")
                    || call.function_call.callee_expr == "sessionmaker"
                    || call.function_call.callee_expr.ends_with("()"); // scoped_session()() pattern

                if !is_session_creation {
                    continue;
                }

                // Check if it's used with a context manager (with statement)
                // We can't easily detect this from calls alone, so we check assignments
                let is_in_with_context = py.assignments.iter().any(|a| {
                    a.value_repr.contains(&call.function_call.callee_expr) && 
                    (a.value_repr.contains("with") || a.target.starts_with("_"))
                });

                // Check if there's a corresponding close() call
                let has_close_call = py.calls.iter().any(|c| {
                    c.function_call.callee_expr.ends_with(".close") || c.function_call.callee_expr.ends_with(".remove")
                });

                // Check for try/finally pattern
                let has_finally_cleanup = py.calls.iter().any(|c| {
                    c.function_call.callee_expr.contains("close") || c.function_call.callee_expr.contains("remove")
                });

                if !is_in_with_context && !has_close_call && !has_finally_cleanup {
                    let title = "SQLAlchemy session may not be properly closed".to_string();

                    let description = 
                        "A SQLAlchemy Session is created but there's no visible close() call \
                         or context manager usage. Unclosed sessions can lead to connection \
                         leaks, exhausting the database connection pool. Use a context manager \
                         (with statement) or ensure sessions are closed in a finally block.".to_string();

                    let fix_preview = generate_fix_preview();

                    let patch = generate_session_patch(
                        *file_id,
                        call.function_call.location.line,
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.70,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "python".into(),
                            "sqlalchemy".into(),
                            "session".into(),
                            "connection-leak".into(),
                            "stability".into(),
                        ],
                    });
                }
            }

            // Also check for engine.connect() without context manager
            for call in &py.calls {
                if call.function_call.callee_expr.ends_with(".connect") || call.function_call.callee_expr.ends_with(".begin") {
                    // Check if there's a corresponding close
                    let has_close = py.calls.iter().any(|c| {
                        c.function_call.callee_expr.ends_with(".close") || c.function_call.callee_expr.ends_with(".commit") || c.function_call.callee_expr.ends_with(".rollback")
                    });

                    if !has_close {
                        let title = "Database connection may not be properly closed".to_string();

                        let description = 
                            "A database connection is opened but may not be properly closed. \
                             Use a context manager to ensure connections are always returned \
                             to the pool.".to_string();

                        let fix_preview = generate_connection_fix_preview();

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Medium,
                            confidence: 0.65,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: None,
                            fix_preview: Some(fix_preview),
                            tags: vec![
                                "python".into(),
                                "sqlalchemy".into(),
                                "connection".into(),
                                "connection-leak".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::unbounded_resource())
    }
}

/// Generate patch for session management.
fn generate_session_patch(file_id: FileId, line: u32) -> FilePatch {
    let hunks = vec![PatchHunk {
        range: PatchRange::InsertBeforeLine { line },
        replacement: "# TODO: Use context manager for session management:\n# with Session() as session:\n#     # your code here\n".to_string(),
    }];

    FilePatch { file_id, hunks }
}

/// Generate a fix preview for session management.
fn generate_fix_preview() -> String {
    r#"# Always use context managers for SQLAlchemy sessions

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

engine = create_engine("postgresql://user:pass@localhost/db")

# Option 1: Use Session as context manager (SQLAlchemy 1.4+)
with Session(engine) as session:
    result = session.query(User).all()
    # Session is automatically closed when exiting the with block

# Option 2: Use sessionmaker with context manager
SessionLocal = sessionmaker(bind=engine)

with SessionLocal() as session:
    user = session.query(User).first()
    session.commit()  # Commit if needed
# Session automatically closed

# Option 3: Manual management with try/finally (not recommended)
session = Session(engine)
try:
    result = session.query(User).all()
    session.commit()
except Exception:
    session.rollback()
    raise
finally:
    session.close()  # Always close!

# Option 4: For FastAPI/Flask, use dependency injection
from fastapi import Depends

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/users")
def get_users(db: Session = Depends(get_db)):
    return db.query(User).all()

# Option 5: Use scoped_session for thread-local sessions
from sqlalchemy.orm import scoped_session

Session = scoped_session(sessionmaker(bind=engine))
# Call Session.remove() at the end of each request"#.to_string()
}

/// Generate a fix preview for connection management.
fn generate_connection_fix_preview() -> String {
    r#"# Always use context managers for database connections

from sqlalchemy import create_engine

engine = create_engine("postgresql://user:pass@localhost/db")

# Option 1: Use connection as context manager
with engine.connect() as connection:
    result = connection.execute(text("SELECT * FROM users"))
    # Connection automatically returned to pool

# Option 2: Use begin() for automatic transaction management
with engine.begin() as connection:
    connection.execute(text("INSERT INTO users VALUES (...)"))
    # Automatically commits on success, rolls back on exception

# Option 3: Manual management (not recommended)
connection = engine.connect()
try:
    result = connection.execute(text("SELECT 1"))
finally:
    connection.close()  # Always close!"#.to_string()
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
        let rule = SqlAlchemySessionManagementRule::new();
        assert_eq!(rule.id(), "python.sqlalchemy.session_not_closed");
    }

    #[test]
    fn rule_name_mentions_session() {
        let rule = SqlAlchemySessionManagementRule::new();
        assert!(rule.name().contains("session"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_sqlalchemy_code() {
        let rule = SqlAlchemySessionManagementRule::new();
        let src = r#"
session = get_session()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_has_medium_severity() {
        let rule = SqlAlchemySessionManagementRule::new();
        assert_eq!(rule.id(), "python.sqlalchemy.session_not_closed");
    }

    #[tokio::test]
    async fn fix_preview_contains_context_manager() {
        let preview = generate_fix_preview();
        assert!(preview.contains("with Session"));
        assert!(preview.contains("context manager"));
    }
}