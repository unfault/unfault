//! Rule: Unbounded cache without eviction.
//!
//! Caches should have size limits or TTL to prevent memory exhaustion.

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

/// Rule that detects unbounded caches.
#[derive(Debug, Default)]
pub struct RustUnboundedCacheRule;

impl RustUnboundedCacheRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustUnboundedCacheRule {
    fn id(&self) -> &'static str {
        "rust.unbounded_cache"
    }

    fn name(&self) -> &'static str {
        "Cache without size limit or eviction policy"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::unbounded_resource())
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

            // Check for proper cache crates
            let uses_cache_crate = rust.uses.iter().any(|u| {
                u.path.contains("moka")
                    || u.path.contains("cached")
                    || u.path.contains("lru")
                    || u.path.contains("quick_cache")
            });

            if uses_cache_crate {
                continue;
            }

            // Look for patterns that suggest caching
            for stat in &rust.statics {
                // Check if the type suggests a cache
                let type_str = &stat.decl_type;
                let is_cache_pattern = type_str.contains("HashMap")
                    || type_str.contains("BTreeMap")
                    || type_str.contains("HashSet");

                if !is_cache_pattern {
                    continue;
                }

                // Check if name suggests caching
                let name_lower = stat.name.to_lowercase();
                let is_cache_name = name_lower.contains("cache")
                    || name_lower.contains("memo")
                    || name_lower.contains("store")
                    || name_lower.contains("registry");

                if !is_cache_name {
                    continue;
                }

                let line = stat.location.range.start_line + 1;

                let title = format!("Unbounded cache '{}'", stat.name);

                let description = format!(
                    "The static cache '{}' at line {} uses a HashMap/Map without size limits.\n\n\
                     **Why this matters:**\n\
                     - Memory grows unboundedly over time\n\
                     - No eviction of stale entries\n\
                     - Can cause OOM in long-running services\n\
                     - Memory pressure affects other services\n\n\
                     **Recommendations:**\n\
                     - Use `moka` for high-performance bounded caches\n\
                     - Use `lru` for simple LRU caches\n\
                     - Use `cached` crate with TTL support\n\
                     - Implement size limits and eviction\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use moka::sync::Cache;\n\
                     use std::time::Duration;\n\
                     \n\
                     let cache: Cache<String, Value> = Cache::builder()\n    \
                         .max_capacity(10_000)\n    \
                         .time_to_live(Duration::from_secs(300))\n    \
                         .build();\n\
                     ```",
                    stat.name,
                    line
                );

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Replace with bounded cache (moka, lru, or cached crate)".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::ResourceLeak,
                    severity: Severity::Medium,
                    confidence: 0.75,
                    dimension: Dimension::Scalability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("use moka::sync::Cache;\nlet cache: Cache<K, V> = Cache::builder().max_capacity(10_000).build();".to_string()),
                    tags: vec![
                        "rust".into(),
                        "cache".into(),
                        "memory".into(),
                        "scalability".into(),
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

    #[test]
    fn rule_id_is_correct() {
        let rule = RustUnboundedCacheRule::new();
        assert_eq!(rule.id(), "rust.unbounded_cache");
    }
}