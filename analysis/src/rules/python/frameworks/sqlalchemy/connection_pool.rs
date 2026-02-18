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

/// Rule: SQLAlchemy Missing Connection Pool Configuration
///
/// Detects SQLAlchemy engine creation without proper connection pool
/// configuration, which can lead to connection exhaustion or poor performance.
#[derive(Debug)]
pub struct SqlAlchemyConnectionPoolRule;

impl SqlAlchemyConnectionPoolRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SqlAlchemyConnectionPoolRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for SqlAlchemyConnectionPoolRule {
    fn id(&self) -> &'static str {
        "python.sqlalchemy.missing_connection_pool_config"
    }

    fn name(&self) -> &'static str {
        "Detects SQLAlchemy engines without proper connection pool configuration."
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
                    || imp.names.iter().any(|n| n == "create_engine" || n == "create_async_engine")
            });

            if !has_sqlalchemy {
                continue;
            }

            // Look for create_engine calls
            for call in &py.calls {
                let is_engine_creation = call.function_call.callee_expr == "create_engine"
                    || call.function_call.callee_expr.ends_with(".create_engine")
                    || call.function_call.callee_expr == "create_async_engine"
                    || call.function_call.callee_expr.ends_with(".create_async_engine");

                if !is_engine_creation {
                    continue;
                }

                let args = &call.args_repr;

                // Check for pool configuration parameters
                let has_pool_size = args.contains("pool_size");
                let has_max_overflow = args.contains("max_overflow");
                let has_pool_timeout = args.contains("pool_timeout");
                let has_pool_recycle = args.contains("pool_recycle");
                let has_pool_pre_ping = args.contains("pool_pre_ping");
                let has_poolclass = args.contains("poolclass");

                // Check if NullPool is used (disables pooling)
                let uses_null_pool = args.contains("NullPool");

                if uses_null_pool {
                    // NullPool is intentional - no pooling
                    continue;
                }

                // Check for missing critical pool settings
                let mut missing_settings = Vec::new();

                if !has_pool_size && !has_poolclass {
                    missing_settings.push("pool_size");
                }
                if !has_max_overflow && !has_poolclass {
                    missing_settings.push("max_overflow");
                }
                if !has_pool_recycle {
                    missing_settings.push("pool_recycle");
                }
                if !has_pool_pre_ping {
                    missing_settings.push("pool_pre_ping");
                }

                if !missing_settings.is_empty() {
                    let severity = if missing_settings.contains(&"pool_recycle") {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };

                    let title = format!(
                        "SQLAlchemy engine missing pool configuration: {}",
                        missing_settings.join(", ")
                    );

                    let description = 
                        "SQLAlchemy engine is created without explicit connection pool \
                         configuration. This can lead to connection exhaustion under load, \
                         stale connections, or poor performance. Configure pool_size, \
                         max_overflow, pool_recycle, and pool_pre_ping for production.".to_string();

                    let fix_preview = generate_pool_config_fix_preview();

                    let patch = generate_pool_config_patch(
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
                        severity,
                        confidence: 0.75,
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
                            "connection-pool".into(),
                            "performance".into(),
                        ],
                    });
                }

                // Check for pool_timeout
                if !has_pool_timeout && (has_pool_size || has_max_overflow) {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "SQLAlchemy engine missing pool_timeout".to_string(),
                        description: Some(
                            "Connection pool is configured but pool_timeout is not set. \
                             Without a timeout, requests may wait indefinitely for a \
                             connection. Set pool_timeout to fail fast under load.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Low,
                        confidence: 0.70,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_pool_timeout_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "sqlalchemy".into(),
                            "connection-pool".into(),
                            "timeout".into(),
                        ],
                    });
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::unbounded_resource())
    }
}

/// Generate patch for missing pool configuration.
/// If we have byte positions, we can generate an actual code fix.
fn generate_pool_config_patch(
    file_id: FileId,
    line: u32,
    start_byte: Option<usize>,
    end_byte: Option<usize>,
    callee: &str,
    args: &str,
) -> FilePatch {
    // If we have byte positions, generate actual replacement
    if let (Some(start), Some(end)) = (start_byte, end_byte) {
        // Parse existing args and add pool configuration
        let args_inner = args.trim().trim_start_matches('(').trim_end_matches(')');
        
        let pool_config = "pool_size=5, max_overflow=10, pool_recycle=3600, pool_pre_ping=True";
        
        let new_call = if args_inner.is_empty() {
            format!("{}({})", callee, pool_config)
        } else {
            format!("{}({}, {})", callee, args_inner, pool_config)
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
        replacement: "# TODO: Add connection pool configuration to create_engine:\n# pool_size=5, max_overflow=10, pool_recycle=3600, pool_pre_ping=True\n".to_string(),
    }];

    FilePatch { file_id, hunks }
}

/// Generate fix preview for pool configuration.
fn generate_pool_config_fix_preview() -> String {
    r#"# Configure SQLAlchemy connection pool for production

from sqlalchemy import create_engine

# Recommended production configuration
engine = create_engine(
    "postgresql://user:pass@localhost/db",
    
    # Pool size settings
    pool_size=5,          # Number of connections to keep open
    max_overflow=10,      # Additional connections allowed under load
    
    # Connection health settings
    pool_recycle=3600,    # Recycle connections after 1 hour (prevents stale connections)
    pool_pre_ping=True,   # Test connections before use (handles disconnects)
    
    # Timeout settings
    pool_timeout=30,      # Seconds to wait for a connection
    
    # Optional: Connection validation
    pool_use_lifo=True,   # Use LIFO to keep connections fresh
)

# For async SQLAlchemy:
from sqlalchemy.ext.asyncio import create_async_engine

async_engine = create_async_engine(
    "postgresql+asyncpg://user:pass@localhost/db",
    pool_size=5,
    max_overflow=10,
    pool_recycle=3600,
    pool_pre_ping=True,
)

# For serverless/Lambda, disable pooling:
from sqlalchemy.pool import NullPool

engine = create_engine(
    "postgresql://user:pass@localhost/db",
    poolclass=NullPool,  # No connection pooling
)

# Environment-based configuration:
import os

engine = create_engine(
    os.environ["DATABASE_URL"],
    pool_size=int(os.environ.get("DB_POOL_SIZE", 5)),
    max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", 10)),
    pool_recycle=int(os.environ.get("DB_POOL_RECYCLE", 3600)),
    pool_pre_ping=True,
)"#.to_string()
}

/// Generate fix preview for pool timeout.
fn generate_pool_timeout_fix_preview() -> String {
    r#"# Configure pool_timeout to fail fast under load

engine = create_engine(
    "postgresql://user:pass@localhost/db",
    pool_size=5,
    max_overflow=10,
    pool_timeout=30,  # Wait max 30 seconds for a connection
)

# Without pool_timeout, requests wait indefinitely when pool is exhausted
# This can cause cascading failures in your application

# For high-traffic applications, consider:
# - Lower pool_timeout (10-30 seconds)
# - Higher pool_size and max_overflow
# - Connection pooler like PgBouncer"#.to_string()
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
        let rule = SqlAlchemyConnectionPoolRule::new();
        assert_eq!(rule.id(), "python.sqlalchemy.missing_connection_pool_config");
    }

    #[test]
    fn rule_name_mentions_connection_pool() {
        let rule = SqlAlchemyConnectionPoolRule::new();
        assert!(rule.name().contains("connection pool"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_sqlalchemy_code() {
        let rule = SqlAlchemyConnectionPoolRule::new();
        let src = r#"
engine = create_engine("sqlite:///test.db")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_configured_pool() {
        let rule = SqlAlchemyConnectionPoolRule::new();
        let src = r#"
from sqlalchemy import create_engine

engine = create_engine(
    "postgresql://localhost/db",
    pool_size=5,
    max_overflow=10,
    pool_recycle=3600,
    pool_pre_ping=True,
    pool_timeout=30
)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn fix_preview_contains_pool_settings() {
        let preview = generate_pool_config_fix_preview();
        assert!(preview.contains("pool_size"));
        assert!(preview.contains("max_overflow"));
        assert!(preview.contains("pool_recycle"));
        assert!(preview.contains("pool_pre_ping"));
    }
}