use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::PyCallSite;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule: Redis/Cache Missing TTL
///
/// Detects Redis SET operations and cache writes without TTL (Time To Live),
/// which can lead to unbounded memory growth.
#[derive(Debug)]
pub struct RedisMissingTtlRule;

impl RedisMissingTtlRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RedisMissingTtlRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for RedisMissingTtlRule {
    fn id(&self) -> &'static str {
        "python.redis.missing_ttl"
    }

    fn name(&self) -> &'static str {
        "Detects Redis/cache operations without TTL that can cause unbounded memory growth."
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

            // Check for Redis imports
            let has_redis = py.imports.iter().any(|imp| {
                imp.module == "redis"
                    || imp.module.starts_with("redis.")
                    || imp.module == "aioredis"
                    || imp.names.iter().any(|n| n == "Redis" || n == "StrictRedis")
            });

            // Check for cache imports (Django cache, Flask-Caching, etc.)
            let has_cache = py.imports.iter().any(|imp| {
                imp.module.contains("cache")
                    || imp.names.iter().any(|n| n.to_lowercase().contains("cache"))
            });

            if !has_redis && !has_cache {
                continue;
            }

            // Look for Redis SET operations without TTL
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;
                let args = &call.args_repr;

                // Check for redis.set without ex/px/exat/pxat
                if (callee.ends_with(".set") || callee.ends_with(".SET"))
                    && !callee.contains("setex")
                    && !callee.contains("psetex")
                {
                    let has_ttl = args.contains("ex=")
                        || args.contains("px=")
                        || args.contains("exat=")
                        || args.contains("pxat=")
                        || args.contains("expire")
                        || args.contains("ttl");

                    if !has_ttl {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Redis SET without TTL".to_string(),
                            description: Some(
                                "Redis SET operation without TTL (ex/px parameter). Keys without \
                                 expiration can accumulate indefinitely, causing memory exhaustion. \
                                 Always set a TTL for cache entries.".to_string()
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Medium,
                            confidence: 0.85,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(generate_set_ttl_patch(*file_id, call)),
                            fix_preview: Some(generate_redis_ttl_fix_preview()),
                            tags: vec![
                                "python".into(),
                                "redis".into(),
                                "cache".into(),
                                "ttl".into(),
                            ],
                        });
                    }
                }

                // Check for hset without expiration
                if callee.ends_with(".hset") || callee.ends_with(".hmset") {
                    // hset doesn't have built-in TTL, need separate expire call
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Redis HSET without expiration".to_string(),
                        description: Some(
                            "Redis HSET operation detected. Hash keys don't have built-in TTL \
                             support. Call EXPIRE separately or use a different data structure \
                             with TTL support."
                                .to_string(),
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
                        fix_preview: Some(generate_hash_ttl_fix_preview()),
                        tags: vec!["python".into(), "redis".into(), "hash".into(), "ttl".into()],
                    });
                }

                // Check for Django cache.set without timeout
                if callee.ends_with("cache.set") || callee.ends_with(".cache_set") {
                    let has_timeout = args.contains("timeout")
                        || args.contains("expire")
                        || args.split(',').count() >= 3; // cache.set(key, value, timeout)

                    if !has_timeout {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Django cache.set without timeout".to_string(),
                            description: Some(
                                "Django cache.set() without explicit timeout. While Django has \
                                 a default timeout, it's best practice to set explicit timeouts \
                                 for cache entries."
                                    .to_string(),
                            ),
                            kind: FindingKind::AntiPattern,
                            severity: Severity::Low,
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
                            fix_preview: Some(generate_django_cache_fix_preview()),
                            tags: vec![
                                "python".into(),
                                "django".into(),
                                "cache".into(),
                                "ttl".into(),
                            ],
                        });
                    }
                }

                // Check for Flask-Caching set without timeout
                if callee.contains("cache") && callee.ends_with(".set") {
                    let has_timeout = args.contains("timeout") || args.split(',').count() >= 3;

                    if !has_timeout && !callee.contains("redis") {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Cache set without timeout".to_string(),
                            description: Some(
                                "Cache set operation without explicit timeout. Always specify \
                                 a timeout to prevent unbounded cache growth."
                                    .to_string(),
                            ),
                            kind: FindingKind::AntiPattern,
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
                            fix_preview: Some(generate_flask_cache_fix_preview()),
                            tags: vec![
                                "python".into(),
                                "flask".into(),
                                "cache".into(),
                                "ttl".into(),
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

/// Generate patch for Redis SET with TTL.
/// Transforms: `redis.set(key, value)` → `redis.set(key, value, ex=3600)`
fn generate_set_ttl_patch(file_id: FileId, call: &PyCallSite) -> FilePatch {
    let args_trimmed = call.args_repr.trim_matches(|c| c == '(' || c == ')');

    // Add ex=3600 (1 hour TTL) to the SET call
    let replacement = if args_trimmed.is_empty() || args_trimmed.trim().is_empty() {
        format!("{}(ex=3600)", call.function_call.callee_expr)
    } else {
        format!(
            "{}({}, ex=3600)",
            call.function_call.callee_expr, args_trimmed
        )
    };

    let hunks = vec![PatchHunk {
        range: PatchRange::ReplaceBytes {
            start: call.start_byte,
            end: call.end_byte,
        },
        replacement,
    }];

    FilePatch { file_id, hunks }
}

/// Generate fix preview for Redis TTL.
fn generate_redis_ttl_fix_preview() -> String {
    r#"# Always set TTL for Redis keys

import redis

r = redis.Redis()

# Bad: No TTL - key lives forever
r.set("key", "value")

# Good: Set TTL in seconds (ex)
r.set("key", "value", ex=3600)  # Expires in 1 hour

# Good: Set TTL in milliseconds (px)
r.set("key", "value", px=60000)  # Expires in 60 seconds

# Good: Set absolute expiration time (exat)
import time
r.set("key", "value", exat=int(time.time()) + 3600)

# Good: Use SETEX for atomic set with expiration
r.setex("key", 3600, "value")  # Expires in 1 hour

# Good: Use pipeline for multiple operations
pipe = r.pipeline()
pipe.set("key", "value")
pipe.expire("key", 3600)
pipe.execute()

# For async redis (aioredis):
import aioredis

async def set_with_ttl():
    r = await aioredis.from_url("redis://localhost")
    await r.set("key", "value", ex=3600)

# Environment-based TTL:
import os
DEFAULT_TTL = int(os.environ.get("REDIS_DEFAULT_TTL", 3600))
r.set("key", "value", ex=DEFAULT_TTL)"#
        .to_string()
}

/// Generate fix preview for Redis hash TTL.
fn generate_hash_ttl_fix_preview() -> String {
    r#"# Set expiration for Redis hashes

import redis

r = redis.Redis()

# Hashes don't have built-in TTL in HSET
# You must call EXPIRE separately

# Option 1: Use pipeline for atomic operation
pipe = r.pipeline()
pipe.hset("hash_key", "field", "value")
pipe.expire("hash_key", 3600)  # Expire entire hash in 1 hour
pipe.execute()

# Option 2: Use Lua script for atomicity
lua_script = """
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
redis.call('EXPIRE', KEYS[1], ARGV[3])
return 1
"""
hset_with_ttl = r.register_script(lua_script)
hset_with_ttl(keys=["hash_key"], args=["field", "value", 3600])

# Option 3: Consider using regular keys with JSON
import json
data = {"field1": "value1", "field2": "value2"}
r.set("key", json.dumps(data), ex=3600)

# Option 4: Use sorted sets with timestamps for auto-cleanup
import time
r.zadd("data_set", {json.dumps(data): time.time()})
# Periodically clean old entries:
r.zremrangebyscore("data_set", 0, time.time() - 3600)"#
        .to_string()
}

/// Generate fix preview for Django cache.
fn generate_django_cache_fix_preview() -> String {
    r#"# Set explicit timeout for Django cache

from django.core.cache import cache

# Bad: Uses default timeout (may be None = forever)
cache.set("key", "value")

# Good: Explicit timeout in seconds
cache.set("key", "value", timeout=3600)  # 1 hour

# Good: Use None for default timeout (from settings)
cache.set("key", "value", timeout=None)  # Uses TIMEOUT from settings

# Good: Set version for cache invalidation
cache.set("key", "value", timeout=3600, version=2)

# Configure default timeout in settings.py:
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.redis.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'TIMEOUT': 3600,  # Default timeout: 1 hour
        'OPTIONS': {
            'MAX_ENTRIES': 10000,  # Limit cache size
        }
    }
}

# Use cache decorators with timeout:
from django.views.decorators.cache import cache_page

@cache_page(60 * 15)  # Cache for 15 minutes
def my_view(request):
    pass

# For template fragment caching:
# {% cache 3600 sidebar request.user.id %}
#     ... expensive template fragment ...
# {% endcache %}"#
        .to_string()
}

/// Generate fix preview for Flask cache.
fn generate_flask_cache_fix_preview() -> String {
    r#"# Set explicit timeout for Flask-Caching

from flask import Flask
from flask_caching import Cache

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'redis'})

# Bad: No timeout specified
cache.set("key", "value")

# Good: Explicit timeout
cache.set("key", "value", timeout=3600)  # 1 hour

# Good: Use decorator with timeout
@cache.cached(timeout=300)  # 5 minutes
def get_data():
    return expensive_operation()

# Good: Memoize with timeout
@cache.memoize(timeout=300)
def get_user(user_id):
    return User.query.get(user_id)

# Configure default timeout:
app.config['CACHE_DEFAULT_TIMEOUT'] = 3600

# Full configuration example:
app.config.from_mapping({
    'CACHE_TYPE': 'redis',
    'CACHE_REDIS_URL': 'redis://localhost:6379/0',
    'CACHE_DEFAULT_TIMEOUT': 3600,
    'CACHE_KEY_PREFIX': 'myapp_',
})

# Clear specific cached values:
cache.delete("key")
cache.delete_memoized(get_user, user_id)

# Clear all cache:
cache.clear()"#
        .to_string()
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
        let rule = RedisMissingTtlRule::new();
        assert_eq!(rule.id(), "python.redis.missing_ttl");
    }

    #[test]
    fn rule_name_mentions_ttl() {
        let rule = RedisMissingTtlRule::new();
        assert!(rule.name().contains("TTL"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_redis_code() {
        let rule = RedisMissingTtlRule::new();
        let src = r#"
def set_value():
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn fix_preview_contains_ttl_examples() {
        let preview = generate_redis_ttl_fix_preview();
        assert!(preview.contains("ex="));
        assert!(preview.contains("setex"));
    }

    // ==================== Patch Application Tests ====================

    #[tokio::test]
    async fn detects_redis_set_without_ttl() {
        let rule = RedisMissingTtlRule::new();
        let src = r#"
import redis

r = redis.Redis()
r.set("key", "value")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty(), "Should detect Redis SET without TTL");
    }

    #[tokio::test]
    async fn no_finding_when_ex_present() {
        let rule = RedisMissingTtlRule::new();
        let src = r#"
import redis

r = redis.Redis()
r.set("key", "value", ex=3600)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag SET with ex= parameter
        let set_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("Redis SET"))
            .collect();
        assert!(
            set_findings.is_empty(),
            "Should not flag Redis SET with TTL"
        );
    }

    #[tokio::test]
    async fn patch_adds_ex_parameter() {
        use crate::types::patch::apply_file_patch;

        let rule = RedisMissingTtlRule::new();
        let src = "import redis\nr = redis.Redis()\nr.set(\"key\", \"value\")\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let set_finding = findings
            .iter()
            .find(|f| f.title.contains("Redis SET"))
            .expect("Should have a Redis SET finding");

        let patch = set_finding
            .patch
            .as_ref()
            .expect("Finding should have a patch");
        let patched = apply_file_patch(src, patch);

        assert!(
            patched.contains("ex=3600"),
            "Patched code should contain ex=3600"
        );
        assert!(
            patched.contains("r.set(\"key\", \"value\", ex=3600)"),
            "SET call should have TTL added"
        );
    }

    #[tokio::test]
    async fn patch_uses_replace_bytes() {
        let rule = RedisMissingTtlRule::new();
        let src = "import redis\nr = redis.Redis()\nr.set(\"key\", \"value\")\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let set_finding = findings
            .iter()
            .find(|f| f.title.contains("Redis SET"))
            .expect("Should have a Redis SET finding");

        let patch = set_finding
            .patch
            .as_ref()
            .expect("Finding should have a patch");

        let has_replace_bytes = patch
            .hunks
            .iter()
            .any(|h| matches!(h.range, PatchRange::ReplaceBytes { .. }));
        assert!(
            has_replace_bytes,
            "Patch should use ReplaceBytes for actual code replacement"
        );
    }
}
