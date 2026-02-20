//! TypeScript Unbounded Cache Detection Rule
//!
//! Detects in-memory caches without size limits or TTL.

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

#[derive(Debug)]
pub struct TypescriptUnboundedCacheRule;

impl TypescriptUnboundedCacheRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptUnboundedCacheRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptUnboundedCacheRule {
    fn id(&self) -> &'static str {
        "typescript.unbounded_cache"
    }

    fn name(&self) -> &'static str {
        "Unbounded In-Memory Cache"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let ts = match sem.as_ref() {
                SourceSemantics::Typescript(ts) => ts,
                _ => continue,
            };

            // Check for Map/object used as cache without limits
            for var in &ts.variables {
                let value_lower = var.value_repr.to_lowercase();

                // Detect cache-like patterns
                let is_cache_like = var.name.to_lowercase().contains("cache")
                    || var.name.to_lowercase().contains("memo")
                    || value_lower.contains("new map()")
                    || value_lower == "{}";

                if !is_cache_like {
                    continue;
                }

                // Check if it's already a bounded cache library
                let has_bounds = value_lower.contains("lru")
                    || value_lower.contains("ttl")
                    || value_lower.contains("maxsize")
                    || value_lower.contains("max_size");

                if has_bounds {
                    continue;
                }

                // Check if cleanup methods (.delete, .clear) are called on this variable
                // This indicates bounded usage (e.g., debounce patterns where entries are removed)
                let has_cleanup = ts.calls.iter().any(|call| {
                    let callee_lower = call.callee.to_lowercase();
                    // Match patterns like "varName.delete" or "varName.clear"
                    callee_lower == format!("{}.delete", var.name.to_lowercase())
                        || callee_lower == format!("{}.clear", var.name.to_lowercase())
                });

                if has_cleanup {
                    continue;
                }

                let line = var.location.range.start_line + 1;
                let column = var.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// Use bounded cache with TTL:\n\
                             // import { LRUCache } from 'lru-cache';\n\
                             // const cache = new LRUCache({ max: 500, ttl: 1000 * 60 * 5 });\n"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "Unbounded in-memory cache".to_string(),
                    description: Some(format!(
                        "Cache '{}' at line {} has no size limit or TTL. \
                         Unbounded caches can cause memory exhaustion.",
                        var.name, line
                    )),
                    kind: FindingKind::ResourceLeak,
                    severity: Severity::Medium,
                    confidence: 0.6,
                    dimension: Dimension::Performance,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Use LRU cache with max size and TTL".to_string()),
                    tags: vec!["performance".into(), "memory".into(), "cache".into()],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::unbounded_resource())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::typescript::parse_typescript_file;
    use crate::semantics::typescript::model::TsFileSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.ts".to_string(),
            language: Language::Typescript,
            content: source.to_string(),
        };
        let parsed = parse_typescript_file(FileId(1), &sf).expect("parsing should succeed");
        let mut sem = TsFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed).ok();
        (FileId(1), Arc::new(SourceSemantics::Typescript(sem)))
    }

    #[test]
    fn test_rule_id() {
        let rule = TypescriptUnboundedCacheRule::new();
        assert_eq!(rule.id(), "typescript.unbounded_cache");
    }

    #[tokio::test]
    async fn test_detects_unbounded_map() {
        let source = r#"
const myCache: Map<string, number> = new Map();

function getValue(key: string): number | undefined {
    return myCache.get(key);
}

function setValue(key: string, value: number): void {
    myCache.set(key, value);
}
"#;
        let rule = TypescriptUnboundedCacheRule::new();
        let (file_id, sem) = parse_and_build_semantics(source);
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        // Should detect the unbounded Map (no .delete or .clear calls)
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Unbounded"));
    }

    #[tokio::test]
    async fn test_no_finding_when_cleanup_present() {
        // This mimics the debounceTimers pattern from extension.ts
        let source = r#"
const debounceTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

function debounce(key: string) {
    const existing = debounceTimers.get(key);
    if (existing) {
        clearTimeout(existing);
    }
    const timer = setTimeout(() => {
        debounceTimers.delete(key);
        doWork();
    }, 500);
    debounceTimers.set(key, timer);
}
"#;
        let rule = TypescriptUnboundedCacheRule::new();
        let (file_id, sem) = parse_and_build_semantics(source);
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        // Should NOT detect because .delete is called
        assert_eq!(findings.len(), 0, "Should not flag Map with cleanup logic");
    }

    #[tokio::test]
    async fn test_no_finding_when_clear_present() {
        let source = r#"
const cache: Map<string, any> = new Map();

function clearCache(): void {
    cache.clear();
}
"#;
        let rule = TypescriptUnboundedCacheRule::new();
        let (file_id, sem) = parse_and_build_semantics(source);
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        // Should NOT detect because .clear is called
        assert_eq!(findings.len(), 0, "Should not flag Map with .clear() call");
    }
}
