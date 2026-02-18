//! Rule: Redis Missing TTL
//!
//! Detects Redis SET operations without TTL, which can lead to unbounded memory growth.

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

/// Rule that detects Redis SET operations without TTL.
#[derive(Debug, Default)]
pub struct RedisMissingTtlRule;

impl RedisMissingTtlRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RedisMissingTtlRule {
    fn id(&self) -> &'static str {
        "go.redis.missing_ttl"
    }

    fn name(&self) -> &'static str {
        "Redis Missing TTL"
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

            // Look for Set calls without TTL (third argument is 0 or missing)
            for call in &go_sem.calls {
                let is_set_without_ttl = (call.function_call.callee_expr.contains(".Set") || call.function_call.callee_expr.ends_with("Set"))
                    && (call.args_repr.ends_with(", 0)")
                        || call.args_repr.ends_with(", 0, )")
                        || call.args_repr.contains(", 0)"));

                // Also check for HSet, MSet without expiration
                let is_hset = call.function_call.callee_expr.contains(".HSet") || call.function_call.callee_expr.ends_with("HSet");
                let is_mset = call.function_call.callee_expr.contains(".MSet") || call.function_call.callee_expr.ends_with("MSet");

                if is_set_without_ttl || is_hset || is_mset {
                    let line = call.function_call.location.line;

                    // For HSet/MSet, check if there's an Expire call nearby
                    if is_hset || is_mset {
                        let has_expire = go_sem.calls.iter().any(|c| {
                            let expire_line = c.function_call.location.line;
                            (c.function_call.callee_expr.contains("Expire") || c.function_call.callee_expr.contains("ExpireAt"))
                                && expire_line > call.function_call.location.line
                                && expire_line <= call.function_call.location.line + 5
                        });

                        if has_expire {
                            continue;
                        }
                    }

                    let op_name = call.function_call.callee_expr.split('.').last().unwrap_or("operation");

                    let title = format!(
                        "Redis {} at line {} has no TTL",
                        op_name,
                        line
                    );

                    let description = format!(
                        "Redis {} at line {} has no TTL. Set an expiration to prevent \
                         unbounded memory growth. Keys without TTL accumulate indefinitely \
                         and can cause Redis to run out of memory.",
                        op_name,
                        line
                    );

                    let patch = generate_ttl_patch(*file_id, line, &call.function_call.callee_expr);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::High,
                        confidence: 0.85,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go_sem.path.clone(),
                        line: Some(line),
                        column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("// Add TTL to Redis operation".to_string()),
                        tags: vec![
                            "go".into(),
                            "redis".into(),
                            "ttl".into(),
                            "memory".into(),
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

fn generate_ttl_patch(file_id: FileId, line: u32, callee: &str) -> FilePatch {
    let replacement = if callee.contains("Set") && !callee.contains("HSet") && !callee.contains("MSet") {
        r#"// Add TTL to Set operation:
// err := rdb.Set(ctx, key, value, 24*time.Hour).Err()  // Use appropriate TTL
"#.to_string()
    } else {
        r#"// Add TTL after operation:
// rdb.Expire(ctx, key, 24*time.Hour)  // Set appropriate TTL
"#.to_string()
    };

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertAfterLine { line },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_has_correct_metadata() {
        let rule = RedisMissingTtlRule::new();
        assert_eq!(rule.id(), "go.redis.missing_ttl");
    }
}