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

/// Rule: SQLAlchemy Missing Query Timeout
///
/// Detects SQLAlchemy queries without timeout configuration, which can lead
/// to queries running indefinitely and blocking resources.
#[derive(Debug)]
pub struct SqlAlchemyQueryTimeoutRule;

impl SqlAlchemyQueryTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SqlAlchemyQueryTimeoutRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for SqlAlchemyQueryTimeoutRule {
    fn id(&self) -> &'static str {
        "python.sqlalchemy.missing_query_timeout"
    }

    fn name(&self) -> &'static str {
        "Detects SQLAlchemy engines and queries without timeout configuration."
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
                    || imp.names.iter().any(|n| {
                        n == "create_engine"
                            || n == "create_async_engine"
                            || n == "Session"
                            || n == "sessionmaker"
                    })
            });

            if !has_sqlalchemy {
                continue;
            }

            // Look for create_engine calls without connect_args timeout
            for call in &py.calls {
                let is_engine_creation = call.function_call.callee_expr == "create_engine"
                    || call.function_call.callee_expr.ends_with(".create_engine")
                    || call.function_call.callee_expr == "create_async_engine"
                    || call.function_call.callee_expr.ends_with(".create_async_engine");

                if is_engine_creation {
                    let args = &call.args_repr;

                    // Check for timeout configuration
                    let has_connect_args = args.contains("connect_args");
                    let has_execution_options = args.contains("execution_options");
                    let has_timeout_in_url = args.contains("connect_timeout")
                        || args.contains("timeout");

                    if !has_connect_args && !has_execution_options && !has_timeout_in_url {
                        let title = "SQLAlchemy engine missing query/connection timeout".to_string();

                        let description = 
                            "SQLAlchemy engine is created without timeout configuration. \
                             Queries can run indefinitely, blocking connections and causing \
                             resource exhaustion. Configure connect_args with timeout settings \
                             or use execution_options for statement timeouts.".to_string();

                        let fix_preview = generate_engine_timeout_fix_preview();

                        let patch = generate_timeout_patch(
                            *file_id,
                            call.function_call.location.line,
                            Some(call.start_byte),
                            Some(call.end_byte),
                            &call.function_call.callee_expr,
                            &call.args_repr,
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
                                "timeout".into(),
                                "query".into(),
                            ],
                        });
                    }
                }
            }

            // Look for raw execute() calls without timeout
            for call in &py.calls {
                let is_execute = call.function_call.callee_expr.ends_with(".execute")
                    || call.function_call.callee_expr.ends_with(".exec")
                    || call.function_call.callee_expr.ends_with(".scalar")
                    || call.function_call.callee_expr.ends_with(".scalars");

                if is_execute {
                    let args = &call.args_repr;

                    // Check if execution_options with timeout is used
                    let has_timeout = args.contains("timeout")
                        || args.contains("execution_options");

                    // Check if this is likely a SQLAlchemy call
                    let is_likely_sqlalchemy = call.function_call.callee_expr.contains("session")
                        || call.function_call.callee_expr.contains("connection")
                        || call.function_call.callee_expr.contains("engine")
                        || call.function_call.callee_expr.contains("conn")
                        || call.function_call.callee_expr.contains("db");

                    if !has_timeout && is_likely_sqlalchemy {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "SQLAlchemy query without timeout".to_string(),
                            description: Some(
                                "Database query is executed without a timeout. Long-running \
                                 queries can block connections and cause cascading failures. \
                                 Use execution_options(timeout=...) or configure statement \
                                 timeout at the engine level.".to_string()
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Low,
                            confidence: 0.60,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: None,
                            fix_preview: Some(generate_query_timeout_fix_preview()),
                            tags: vec![
                                "python".into(),
                                "sqlalchemy".into(),
                                "timeout".into(),
                                "query".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
    }
}

/// Generate patch for missing timeout configuration.
/// If we have byte positions, we can generate an actual code fix.
fn generate_timeout_patch(
    file_id: FileId,
    line: u32,
    start_byte: Option<usize>,
    end_byte: Option<usize>,
    callee: &str,
    args: &str,
) -> FilePatch {
    // If we have byte positions, generate actual replacement
    if let (Some(start), Some(end)) = (start_byte, end_byte) {
        // Parse existing args and add timeout configuration
        let args_inner = args.trim().trim_start_matches('(').trim_end_matches(')');
        
        let timeout_config = "connect_args={'connect_timeout': 10}";
        
        let new_call = if args_inner.is_empty() {
            format!("{}({})", callee, timeout_config)
        } else {
            format!("{}({}, {})", callee, args_inner, timeout_config)
        };
        
        return FilePatch {
            file_id,
            hunks: vec![PatchHunk {
                range: PatchRange::ReplaceBytes { start, end },
                replacement: new_call,
            }],
        };
    }
    
    // Fallback to comment patch
    let hunks = vec![PatchHunk {
        range: PatchRange::InsertBeforeLine { line },
        replacement: "# TODO: Add timeout configuration to create_engine:\n# connect_args={'connect_timeout': 10, 'options': '-c statement_timeout=30000'}\n".to_string(),
    }];

    FilePatch { file_id, hunks }
}

/// Generate fix preview for engine timeout configuration.
fn generate_engine_timeout_fix_preview() -> String {
    r#"# Configure SQLAlchemy engine with timeouts

from sqlalchemy import create_engine

# PostgreSQL with connection and statement timeout
engine = create_engine(
    "postgresql://user:pass@localhost/db",
    connect_args={
        'connect_timeout': 10,  # Connection timeout in seconds
        'options': '-c statement_timeout=30000'  # Query timeout in milliseconds
    }
)

# MySQL with timeouts
engine = create_engine(
    "mysql+pymysql://user:pass@localhost/db",
    connect_args={
        'connect_timeout': 10,
        'read_timeout': 30,
        'write_timeout': 30,
    }
)

# SQLite with timeout
engine = create_engine(
    "sqlite:///test.db",
    connect_args={'timeout': 30}
)

# Using execution_options for statement timeout
engine = create_engine(
    "postgresql://user:pass@localhost/db",
    execution_options={
        'timeout': 30  # Statement timeout
    }
)

# Async engine with timeout
from sqlalchemy.ext.asyncio import create_async_engine

async_engine = create_async_engine(
    "postgresql+asyncpg://user:pass@localhost/db",
    connect_args={
        'timeout': 10,
        'command_timeout': 30,
    }
)

# Environment-based configuration
import os

engine = create_engine(
    os.environ["DATABASE_URL"],
    connect_args={
        'connect_timeout': int(os.environ.get('DB_CONNECT_TIMEOUT', 10)),
        'options': f'-c statement_timeout={os.environ.get("DB_STATEMENT_TIMEOUT", 30000)}'
    }
)"#.to_string()
}

/// Generate fix preview for query timeout.
fn generate_query_timeout_fix_preview() -> String {
    r#"# Add timeout to SQLAlchemy queries

from sqlalchemy import text
from sqlalchemy.orm import Session

# Option 1: Use execution_options on the query
with Session(engine) as session:
    result = session.execute(
        text("SELECT * FROM large_table"),
        execution_options={'timeout': 30}
    )

# Option 2: Set timeout on the connection
with engine.connect() as conn:
    conn = conn.execution_options(timeout=30)
    result = conn.execute(text("SELECT * FROM large_table"))

# Option 3: Configure at session level
Session = sessionmaker(
    bind=engine,
    execution_options={'timeout': 30}
)

# Option 4: Use context manager with timeout
import asyncio

async def query_with_timeout():
    async with asyncio.timeout(30):
        async with async_session() as session:
            result = await session.execute(text("SELECT ..."))

# Option 5: Database-level timeout (PostgreSQL)
with engine.connect() as conn:
    conn.execute(text("SET statement_timeout = '30s'"))
    result = conn.execute(text("SELECT * FROM large_table"))

# For critical queries, always set explicit timeouts
# to prevent runaway queries from blocking resources"#.to_string()
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
        let rule = SqlAlchemyQueryTimeoutRule::new();
        assert_eq!(rule.id(), "python.sqlalchemy.missing_query_timeout");
    }

    #[test]
    fn rule_name_mentions_timeout() {
        let rule = SqlAlchemyQueryTimeoutRule::new();
        assert!(rule.name().contains("timeout"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_sqlalchemy_code() {
        let rule = SqlAlchemyQueryTimeoutRule::new();
        let src = r#"
engine = create_engine("sqlite:///test.db")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_configured_timeout() {
        let rule = SqlAlchemyQueryTimeoutRule::new();
        let src = r#"
from sqlalchemy import create_engine

engine = create_engine(
    "postgresql://localhost/db",
    connect_args={'connect_timeout': 10}
)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn fix_preview_contains_timeout_examples() {
        let preview = generate_engine_timeout_fix_preview();
        assert!(preview.contains("connect_timeout"));
        assert!(preview.contains("statement_timeout"));
    }
}