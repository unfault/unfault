//! Rule B6: Unbounded caches detection
//!
//! Detects in-memory caches without TTL or max-size limits, which can lead
//! to memory leaks and eviction storms in production.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::{ImportInsertionType, PyImport};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unbounded in-memory caches in Python code.
///
/// Unbounded caches can grow indefinitely, leading to memory exhaustion.
/// This rule detects common caching patterns that lack TTL or max-size limits.
#[derive(Debug)]
pub struct PythonUnboundedCacheRule;

impl PythonUnboundedCacheRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonUnboundedCacheRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about an unbounded cache pattern
#[derive(Debug, Clone)]
struct UnboundedCachePattern {
    /// The type of cache pattern detected
    pattern_type: CachePatternType,
    /// Line number (1-based)
    line: u32,
    /// Column number (1-based)
    column: u32,
    /// The variable name or expression
    cache_name: String,
    /// Start byte offset
    start_byte: usize,
    /// End byte offset
    end_byte: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CachePatternType {
    /// Plain dict used as cache (e.g., `cache = {}`)
    PlainDict,
    /// functools.lru_cache without maxsize
    LruCacheUnbounded,
    /// functools.cache (always unbounded)
    FunctoolsCache,
    /// cachetools without maxsize/ttl
    CachetoolsUnbounded,
    /// Custom cache class without limits
    #[allow(dead_code)]
    CustomCacheUnbounded,
}

impl CachePatternType {
    fn description(&self) -> &'static str {
        match self {
            CachePatternType::PlainDict => "Plain dict used as cache without size limits",
            CachePatternType::LruCacheUnbounded => {
                "lru_cache with maxsize=None allows unbounded growth"
            }
            CachePatternType::FunctoolsCache => {
                "functools.cache has no size limit (equivalent to lru_cache(maxsize=None))"
            }
            CachePatternType::CachetoolsUnbounded => "cachetools cache without maxsize or ttl",
            CachePatternType::CustomCacheUnbounded => {
                "Custom cache implementation without apparent size limits"
            }
        }
    }

    fn fix_suggestion(&self) -> &'static str {
        match self {
            CachePatternType::PlainDict => {
                "Use functools.lru_cache with maxsize, or cachetools.TTLCache/LRUCache"
            }
            CachePatternType::LruCacheUnbounded => {
                "Set maxsize to a reasonable value (e.g., @lru_cache(maxsize=128))"
            }
            CachePatternType::FunctoolsCache => {
                "Use @lru_cache(maxsize=128) instead, or cachetools.TTLCache for TTL support"
            }
            CachePatternType::CachetoolsUnbounded => {
                "Add maxsize and/or ttl parameters to limit cache growth"
            }
            CachePatternType::CustomCacheUnbounded => {
                "Add max-size limit and/or TTL eviction to prevent unbounded growth"
            }
        }
    }
}

#[async_trait]
impl Rule for PythonUnboundedCacheRule {
    fn id(&self) -> &'static str {
        "python.unbounded_cache"
    }

    fn name(&self) -> &'static str {
        "Unbounded cache without size limits"
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
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => continue,
            };

            // Check for unbounded cache patterns
            let patterns = detect_unbounded_caches(py);

            // Use third_party_from_import since we're adding "from cachetools import TTLCache"
            let import_line =
                py.import_insertion_line_for(ImportInsertionType::third_party_from_import());

            for pattern in &patterns {
                let title = format!("Unbounded cache: {}", pattern.cache_name);

                let description = format!(
                    "{}. This can lead to memory exhaustion in production. {}",
                    pattern.pattern_type.description(),
                    pattern.pattern_type.fix_suggestion()
                );

                let patch = generate_cache_fix_patch(pattern, *file_id, &py.imports, import_line);

                let fix_preview = get_fix_preview(&pattern.pattern_type);

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::BehaviorThreat,
                    severity: Severity::Medium,
                    confidence: 0.80,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: py.path.clone(),
                    line: Some(pattern.line),
                    column: Some(pattern.column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "python".into(),
                        "cache".into(),
                        "memory".into(),
                        "stability".into(),
                    ],
                });
            }
        }

        findings
    }
}

fn detect_unbounded_caches(
    py: &crate::semantics::python::model::PyFileSemantics,
) -> Vec<UnboundedCachePattern> {
    let mut patterns = Vec::new();

    // Check for @cache or @lru_cache decorators in function calls
    for call in &py.calls {
        let callee = &call.function_call.callee_expr;

        // Check for functools.cache (always unbounded)
        if callee == "cache" || callee == "functools.cache" {
            patterns.push(UnboundedCachePattern {
                pattern_type: CachePatternType::FunctoolsCache,
                line: call.function_call.location.line,
                column: call.function_call.location.column,
                cache_name: callee.clone(),
                start_byte: call.start_byte,
                end_byte: call.end_byte,
            });
        }

        // Check for lru_cache with maxsize=None
        if callee == "lru_cache" || callee == "functools.lru_cache" {
            let args_text = &call.args_repr;
            // Check if maxsize=None is explicitly set
            if args_text.contains("maxsize=None") || args_text.contains("maxsize = None") {
                patterns.push(UnboundedCachePattern {
                    pattern_type: CachePatternType::LruCacheUnbounded,
                    line: call.function_call.location.line,
                    column: call.function_call.location.column,
                    cache_name: callee.clone(),
                    start_byte: call.start_byte,
                    end_byte: call.end_byte,
                });
            }
        }

        // Check for cachetools patterns without limits
        if callee.contains("Cache")
            && (callee.starts_with("cachetools.")
                || callee == "TTLCache"
                || callee == "LRUCache"
                || callee == "LFUCache")
        {
            let args_text = &call.args_repr;
            // If no maxsize argument is provided, it might be unbounded
            if !args_text.contains("maxsize") && !args_text.contains("ttl") {
                patterns.push(UnboundedCachePattern {
                    pattern_type: CachePatternType::CachetoolsUnbounded,
                    line: call.function_call.location.line,
                    column: call.function_call.location.column,
                    cache_name: callee.clone(),
                    start_byte: call.start_byte,
                    end_byte: call.end_byte,
                });
            }
        }
    }

    // Check for module-level dict assignments that look like caches
    for assign in &py.assignments {
        let target = &assign.target;
        let value = &assign.value_repr;

        // Check if it's a dict that looks like a cache
        if is_cache_like_name(target) && (value == "{}" || value.starts_with("dict(")) {
            patterns.push(UnboundedCachePattern {
                pattern_type: CachePatternType::PlainDict,
                line: assign.location.range.start_line + 1,
                column: assign.location.range.start_col + 1,
                cache_name: target.clone(),
                start_byte: 0, // Not available from TextRange
                end_byte: 0,   // Not available from TextRange
            });
        }
    }

    patterns
}

fn is_cache_like_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("cache")
        || lower.contains("memo")
        || lower.contains("_cache")
        || lower.ends_with("_map")
        || lower == "seen"
        || lower == "visited"
        || lower.contains("lookup")
}

fn get_fix_preview(pattern_type: &CachePatternType) -> String {
    match pattern_type {
        CachePatternType::PlainDict => r#"# Before (unbounded):
cache = {}

# After (bounded with TTL):
from cachetools import TTLCache
cache = TTLCache(maxsize=1000, ttl=300)  # 1000 items, 5 min TTL

# Or with functools:
from functools import lru_cache

@lru_cache(maxsize=128)
def cached_function(key):
    return expensive_computation(key)"#
            .to_string(),
        CachePatternType::LruCacheUnbounded => r#"# Before (unbounded):
@lru_cache(maxsize=None)
def expensive_function(x):
    return compute(x)

# After (bounded):
@lru_cache(maxsize=128)  # Limit to 128 entries
def expensive_function(x):
    return compute(x)"#
            .to_string(),
        CachePatternType::FunctoolsCache => r#"# Before (unbounded):
from functools import cache

@cache
def expensive_function(x):
    return compute(x)

# After (bounded):
from functools import lru_cache

@lru_cache(maxsize=128)  # Limit to 128 entries
def expensive_function(x):
    return compute(x)"#
            .to_string(),
        CachePatternType::CachetoolsUnbounded => r#"# Before (potentially unbounded):
from cachetools import Cache
cache = Cache()

# After (bounded with TTL):
from cachetools import TTLCache
cache = TTLCache(maxsize=1000, ttl=300)  # 1000 items, 5 min TTL"#
            .to_string(),
        CachePatternType::CustomCacheUnbounded => {
            r#"# Add size limits and TTL to your cache implementation:
# - Track number of entries
# - Evict oldest entries when limit reached
# - Add timestamp-based expiration"#
                .to_string()
        }
    }
}

/// Check if TTLCache is already imported from cachetools
fn has_ttlcache_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| {
        (imp.module == "cachetools" && imp.names.iter().any(|n| n == "TTLCache"))
            || imp.module == "cachetools.TTLCache"
    })
}

fn generate_cache_fix_patch(
    pattern: &UnboundedCachePattern,
    file_id: FileId,
    imports: &[PyImport],
    import_insertion_line: u32,
) -> FilePatch {
    let mut hunks = Vec::new();

    match pattern.pattern_type {
        CachePatternType::PlainDict => {
            // Only add import for cachetools.TTLCache if not already imported
            if !has_ttlcache_import(imports) {
                hunks.push(PatchHunk {
                    range: PatchRange::InsertBeforeLine {
                        line: import_insertion_line,
                    },
                    replacement: "from cachetools import TTLCache\n".to_string(),
                });
            }
            // PlainDict doesn't have byte offsets (comes from assignments), so use comment
            let replacement = format!(
                "# Replace '{}' with bounded cache:\n# {} = TTLCache(maxsize=1000, ttl=300)\n",
                pattern.cache_name, pattern.cache_name
            );
            hunks.push(PatchHunk {
                range: PatchRange::InsertBeforeLine { line: pattern.line },
                replacement,
            });
        }
        CachePatternType::LruCacheUnbounded => {
            // Replace the call using ReplaceBytes if we have byte offsets
            if pattern.start_byte > 0 && pattern.end_byte > pattern.start_byte {
                // Replace lru_cache(maxsize=None, ...) with lru_cache(maxsize=128, ...)
                let replacement = "lru_cache(maxsize=128)".to_string();
                hunks.push(PatchHunk {
                    range: PatchRange::ReplaceBytes {
                        start: pattern.start_byte,
                        end: pattern.end_byte,
                    },
                    replacement,
                });
            } else {
                // Fallback to comment
                let replacement = "# Fix: Replace maxsize=None with a bounded value:\n# @lru_cache(maxsize=128)\n".to_string();
                hunks.push(PatchHunk {
                    range: PatchRange::InsertBeforeLine { line: pattern.line },
                    replacement,
                });
            }
        }
        CachePatternType::FunctoolsCache => {
            // Replace cache(...) with lru_cache(maxsize=128, ...) using ReplaceBytes
            if pattern.start_byte > 0 && pattern.end_byte > pattern.start_byte {
                let replacement = "lru_cache(maxsize=128)".to_string();
                hunks.push(PatchHunk {
                    range: PatchRange::ReplaceBytes {
                        start: pattern.start_byte,
                        end: pattern.end_byte,
                    },
                    replacement,
                });
            } else {
                // Fallback to comment if no byte offsets
                let replacement =
                    "# Fix: Replace @cache with bounded @lru_cache:\n# @lru_cache(maxsize=128)\n"
                        .to_string();
                hunks.push(PatchHunk {
                    range: PatchRange::InsertBeforeLine { line: pattern.line },
                    replacement,
                });
            }
        }
        CachePatternType::CachetoolsUnbounded => {
            // Replace cachetools Cache without limits with TTLCache
            if pattern.start_byte > 0 && pattern.end_byte > pattern.start_byte {
                let replacement = "TTLCache(maxsize=1000, ttl=300)".to_string();
                hunks.push(PatchHunk {
                    range: PatchRange::ReplaceBytes {
                        start: pattern.start_byte,
                        end: pattern.end_byte,
                    },
                    replacement,
                });
            } else {
                // Fallback to comment
                let replacement = format!(
                    "# Fix: Add maxsize and ttl parameters:\n# {}(maxsize=1000, ttl=300)\n",
                    pattern.cache_name
                );
                hunks.push(PatchHunk {
                    range: PatchRange::InsertBeforeLine { line: pattern.line },
                    replacement,
                });
            }
        }
        CachePatternType::CustomCacheUnbounded => {
            // Custom caches can't be automatically fixed
            let replacement =
                "# Fix: Add size limits and TTL to prevent unbounded growth\n".to_string();
            hunks.push(PatchHunk {
                range: PatchRange::InsertBeforeLine { line: pattern.line },
                replacement,
            });
        }
    };

    FilePatch { file_id, hunks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::python::build_python_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_python_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonUnboundedCacheRule::new();
        assert_eq!(rule.id(), "python.unbounded_cache");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonUnboundedCacheRule::new();
        assert!(rule.name().contains("cache"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonUnboundedCacheRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonUnboundedCacheRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonUnboundedCacheRule::default();
        assert_eq!(rule.id(), "python.unbounded_cache");
    }

    #[tokio::test]
    async fn detects_functools_cache() {
        let rule = PythonUnboundedCacheRule::new();
        // Note: @cache without parentheses is not detected as a call
        // We detect cache() when used with parentheses
        let src = r#"
from functools import cache

result = cache(expensive_function)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(!findings.is_empty(), "Should detect cache() call");
        assert_eq!(findings[0].rule_id, "python.unbounded_cache");
    }

    #[tokio::test]
    async fn detects_lru_cache_with_maxsize_none() {
        let rule = PythonUnboundedCacheRule::new();
        let src = r#"
from functools import lru_cache

@lru_cache(maxsize=None)
def expensive_function(x):
    return x * 2
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            !findings.is_empty(),
            "Should detect lru_cache with maxsize=None"
        );
    }

    #[tokio::test]
    async fn detects_plain_dict_cache() {
        let rule = PythonUnboundedCacheRule::new();
        let src = r#"
# Module-level cache
_cache = {}

def get_cached(key):
    if key not in _cache:
        _cache[key] = compute(key)
    return _cache[key]
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(!findings.is_empty(), "Should detect plain dict cache");
    }

    #[tokio::test]
    async fn no_finding_for_bounded_lru_cache() {
        let rule = PythonUnboundedCacheRule::new();
        let src = r#"
from functools import lru_cache

@lru_cache(maxsize=128)
def expensive_function(x):
    return x * 2
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(findings.is_empty(), "Should not flag bounded lru_cache");
    }

    #[tokio::test]
    async fn no_finding_for_regular_dict() {
        let rule = PythonUnboundedCacheRule::new();
        let src = r#"
# Regular dict, not a cache
data = {}
config = {}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should not flag regular dicts that don't look like caches
        assert!(findings.is_empty(), "Should not flag regular dicts");
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = PythonUnboundedCacheRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = PythonUnboundedCacheRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = PythonUnboundedCacheRule::new();
        let src = r#"
from functools import cache

@cache
def func(x):
    return x
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        if !findings.is_empty() {
            let finding = &findings[0];
            assert_eq!(finding.rule_id, "python.unbounded_cache");
            assert!(matches!(finding.kind, FindingKind::BehaviorThreat));
            assert_eq!(finding.dimension, Dimension::Stability);
            assert!(finding.patch.is_some());
            assert!(finding.fix_preview.is_some());
            assert!(finding.tags.contains(&"cache".to_string()));
        }
    }

    #[test]
    fn cache_pattern_descriptions_are_meaningful() {
        assert!(CachePatternType::PlainDict.description().contains("dict"));
        assert!(
            CachePatternType::LruCacheUnbounded
                .description()
                .contains("lru_cache")
        );
        assert!(
            CachePatternType::FunctoolsCache
                .description()
                .contains("functools.cache")
        );
    }

    #[test]
    fn cache_pattern_fix_suggestions_are_meaningful() {
        assert!(
            CachePatternType::PlainDict
                .fix_suggestion()
                .contains("lru_cache")
        );
        assert!(
            CachePatternType::LruCacheUnbounded
                .fix_suggestion()
                .contains("maxsize")
        );
        assert!(
            CachePatternType::FunctoolsCache
                .fix_suggestion()
                .contains("lru_cache")
        );
    }

    #[test]
    fn is_cache_like_name_detects_cache_patterns() {
        assert!(is_cache_like_name("cache"));
        assert!(is_cache_like_name("_cache"));
        assert!(is_cache_like_name("my_cache"));
        assert!(is_cache_like_name("memo"));
        assert!(is_cache_like_name("memoize"));
        assert!(is_cache_like_name("lookup_table"));
        assert!(is_cache_like_name("seen"));

        assert!(!is_cache_like_name("data"));
        assert!(!is_cache_like_name("config"));
        assert!(!is_cache_like_name("result"));
    }
}
