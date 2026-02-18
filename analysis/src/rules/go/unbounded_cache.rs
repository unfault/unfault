//! Rule: Unbounded cache in Go
//!
//! Detects in-memory caches without size limits or TTL.

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

/// Rule that detects unbounded caches.
#[derive(Debug, Default)]
pub struct GoUnboundedCacheRule;

impl GoUnboundedCacheRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoUnboundedCacheRule {
    fn id(&self) -> &'static str {
        "go.unbounded_cache"
    }

    fn name(&self) -> &'static str {
        "Unbounded cache"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(unbounded_resource())
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

            // Check for cache library imports with proper config
            let has_bounded_cache_lib = go.imports.iter().any(|imp| {
                imp.path.contains("patrickmn/go-cache") ||
                imp.path.contains("hashicorp/golang-lru") ||
                imp.path.contains("bluele/gcache") ||
                imp.path.contains("dgraph-io/ristretto") ||
                imp.path.contains("allegro/bigcache")
            });

            // Check for sync.Map being used as cache
            for decl in &go.declarations {
                let decl_type = decl.decl_type.as_deref().unwrap_or("");
                if decl_type.contains("sync.Map") {
                    // Check if it seems to be used as a cache
                    let is_cache_like = decl.name.to_lowercase().contains("cache") ||
                                       decl.name.to_lowercase().contains("store") ||
                                       decl.name.to_lowercase().contains("memo");
                    
                    if is_cache_like {
                        let line = decl.location.range.start_line + 1;
                        let column = decl.location.range.start_col + 1;
                        
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: format!("sync.Map '{}' used as unbounded cache", decl.name),
                            description: Some(
                                "sync.Map has no size limit or TTL, leading to memory exhaustion \
                                 over time. Use a proper cache library like hashicorp/golang-lru \
                                 or dgraph-io/ristretto with size limits and eviction.".to_string()
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.80,
                            dimension: Dimension::Scalability,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line },
                                    replacement: 
"// Replace sync.Map with a bounded cache:
// import lru \"github.com/hashicorp/golang-lru/v2\"
// cache, _ := lru.New[string, Value](1000) // Max 1000 entries
// 
// Or use ristretto for better performance:
// import \"github.com/dgraph-io/ristretto\"
// cache, _ := ristretto.NewCache(&ristretto.Config{
//     NumCounters: 1e7,
//     MaxCost:     1 << 30, // 1GB
//     BufferItems: 64,
// })".to_string(),
                                }],
                            }),
                            fix_preview: Some("Use bounded cache library".to_string()),
                            tags: vec!["go".into(), "cache".into(), "memory".into()],
                        });
                    }
                }
            }

            // Check for map being used as cache without bounds
            for decl in &go.declarations {
                let decl_type = decl.decl_type.as_deref().unwrap_or("");
                if decl_type.starts_with("map[") {
                    let is_cache_like = decl.name.to_lowercase().contains("cache") ||
                                       decl.name.to_lowercase().contains("memo");
                    
                    if is_cache_like && !has_bounded_cache_lib {
                        let line = decl.location.range.start_line + 1;
                        let column = decl.location.range.start_col + 1;
                        
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: format!("map '{}' used as unbounded cache", decl.name),
                            description: Some(
                                "Using a plain map as cache without size limits or eviction \
                                 will cause memory to grow unbounded. Use a proper cache \
                                 library with LRU eviction and TTL support.".to_string()
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.75,
                            dimension: Dimension::Scalability,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line },
                                    replacement: 
"// Replace plain map with bounded cache:
// import \"github.com/patrickmn/go-cache\"
// cache := cache.New(5*time.Minute, 10*time.Minute) // TTL + cleanup interval".to_string(),
                                }],
                            }),
                            fix_preview: Some("Use cache with TTL".to_string()),
                            tags: vec!["go".into(), "cache".into(), "memory".into()],
                        });
                    }
                }
            }

            // Check for cache.New with NoExpiration via calls
            for call in &go.calls {
                if call.function_call.callee_expr.contains("cache.New") && call.args_repr.contains("NoExpiration") {
                    let line = call.function_call.location.line;
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Cache with NoExpiration".to_string(),
                        description: Some(
                            "Using cache.NoExpiration means entries never expire, leading \
                             to unbounded memory growth. Set a reasonable TTL for cache \
                             entries.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.90,
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
                                replacement: "// Set a reasonable TTL instead of NoExpiration:\n// cache.New(5*time.Minute, 10*time.Minute)".to_string(),
                            }],
                        }),
                        fix_preview: Some("Set cache TTL".to_string()),
                        tags: vec!["go".into(), "cache".into(), "ttl".into()],
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

    #[test]
    fn test_rule_metadata() {
        let rule = GoUnboundedCacheRule::new();
        assert_eq!(rule.id(), "go.unbounded_cache");
        assert!(!rule.name().is_empty());
    }
}