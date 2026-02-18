//! Rule: Redis Connection Pool Configuration
//!
//! Detects Redis clients without proper connection pool configuration.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects Redis clients without connection pool configuration.
#[derive(Debug, Default)]
pub struct RedisConnectionPoolRule;

impl RedisConnectionPoolRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RedisConnectionPoolRule {
    fn id(&self) -> &'static str {
        "go.redis.connection_pool"
    }

    fn name(&self) -> &'static str {
        "Redis Connection Pool Configuration"
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

            // Check if go-redis is imported
            let has_redis = go_sem.imports.iter().any(|imp| {
                imp.path.contains("github.com/redis/go-redis")
                    || imp.path.contains("github.com/go-redis/redis")
            });

            if !has_redis {
                continue;
            }

            // Look for redis.NewClient calls
            for call in &go_sem.calls {
                let is_new_client = call.function_call.callee_expr.contains("redis.NewClient")
                    || call.function_call.callee_expr.contains("redis.NewClusterClient")
                    || call.function_call.callee_expr == "NewClient"
                    || call.function_call.callee_expr == "NewClusterClient";

                if !is_new_client {
                    continue;
                }

                // Check if Options has PoolSize configured
                let has_pool_config = call.args_repr.contains("PoolSize")
                    || call.args_repr.contains("MinIdleConns")
                    || call.args_repr.contains("MaxRetries");

                if !has_pool_config {
                    let line = call.function_call.location.line;

                    let title = format!(
                        "Redis client at line {} lacks connection pool configuration",
                        line
                    );

                    let description = format!(
                        "Redis client at line {} lacks connection pool configuration. \
                         Set PoolSize, MinIdleConns, and MaxRetries for production use. \
                         Without proper pool configuration, the application may create \
                         excessive connections or struggle with connection management \
                         under load.",
                        line
                    );

                    let patch = generate_pool_patch(*file_id, line);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.80,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go_sem.path.clone(),
                        line: Some(line),
                        column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("// Configure Redis connection pool".to_string()),
                        tags: vec![
                            "go".into(),
                            "redis".into(),
                            "connection-pool".into(),
                            "configuration".into(),
                        ],
                    });
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(unbounded_resource())
    }
}

fn generate_pool_patch(file_id: FileId, line: u32) -> FilePatch {
    let replacement = r#"// Configure Redis connection pool:
// rdb := redis.NewClient(&redis.Options{
//     Addr:         "localhost:6379",
//     PoolSize:     10,              // Max connections
//     MinIdleConns: 5,               // Warm connections
//     MaxRetries:   3,               // Retry failed operations
//     DialTimeout:  5 * time.Second,
//     ReadTimeout:  3 * time.Second,
//     WriteTimeout: 3 * time.Second,
//     PoolTimeout:  4 * time.Second,
// })
"#.to_string();

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_has_correct_metadata() {
        let rule = RedisConnectionPoolRule::new();
        assert_eq!(rule.id(), "go.redis.connection_pool");
    }
}