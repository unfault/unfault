use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};

/// Rule: Redis Unbounded Keys
///
/// Detects Redis key patterns that could lead to unbounded key growth,
/// such as using user input directly in keys or timestamp-based keys.
#[derive(Debug)]
pub struct RedisUnboundedKeysRule;

impl RedisUnboundedKeysRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RedisUnboundedKeysRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for RedisUnboundedKeysRule {
    fn id(&self) -> &'static str {
        "python.redis.unbounded_keys"
    }

    fn name(&self) -> &'static str {
        "Detects Redis key patterns that could lead to unbounded key growth."
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

            // Check for cache imports
            let has_cache = py.imports.iter().any(|imp| {
                imp.module.contains("cache")
                    || imp.names.iter().any(|n| n.to_lowercase().contains("cache"))
            });

            if !has_redis && !has_cache {
                continue;
            }

            // Look for potentially unbounded key patterns
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;
                let args = &call.args_repr;

                // Check for Redis operations with dynamic keys
                let is_redis_op = callee.ends_with(".set")
                    || callee.ends_with(".get")
                    || callee.ends_with(".hset")
                    || callee.ends_with(".lpush")
                    || callee.ends_with(".rpush")
                    || callee.ends_with(".sadd")
                    || callee.ends_with(".zadd")
                    || callee.ends_with(".incr")
                    || callee.ends_with(".setex");

                if !is_redis_op {
                    continue;
                }

                // Check for timestamp-based keys (common anti-pattern)
                let has_timestamp_key = args.contains("timestamp")
                    || args.contains("time.time")
                    || args.contains("datetime.now")
                    || args.contains("uuid")
                    || args.contains("uuid4")
                    || args.contains("uuid1");

                if has_timestamp_key {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Redis key with timestamp/UUID may cause unbounded growth".to_string(),
                        description: Some(
                            "Redis key appears to include a timestamp or UUID, which creates \
                             a new key for each operation. This can lead to unbounded key growth \
                             and memory exhaustion. Consider using fixed key patterns with TTL, \
                             or use sorted sets for time-series data.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::High,
                        confidence: 0.80,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_timestamp_key_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "redis".into(),
                            "unbounded".into(),
                            "memory".into(),
                        ],
                    });
                }

                // Check for f-string or format with user input in keys
                let has_dynamic_key = args.contains("f\"")
                    || args.contains("f'")
                    || args.contains(".format(")
                    || args.contains("% ")
                    || args.contains("{user")
                    || args.contains("{request")
                    || args.contains("{session");

                if has_dynamic_key && !has_timestamp_key {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Redis key with dynamic user input".to_string(),
                        description: Some(
                            "Redis key appears to include dynamic user input. If not properly \
                             bounded, this can lead to key explosion. Ensure keys are validated, \
                             normalized, and consider using hash slots or key prefixes with \
                             cleanup policies.".to_string()
                        ),
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
                        fix_preview: Some(generate_dynamic_key_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "redis".into(),
                            "dynamic-key".into(),
                        ],
                    });
                }

                // Check for list/set operations without size limits
                let is_collection_op = callee.ends_with(".lpush")
                    || callee.ends_with(".rpush")
                    || callee.ends_with(".sadd")
                    || callee.ends_with(".zadd");

                if is_collection_op {
                    // Check if there's a corresponding trim/limit operation
                    let has_trim = py.calls.iter().any(|c| {
                        c.function_call.callee_expr.ends_with(".ltrim")
                            || c.function_call.callee_expr.ends_with(".zremrangebyrank")
                            || c.function_call.callee_expr.ends_with(".zremrangebyscore")
                    });

                    if !has_trim {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Redis collection without size limit".to_string(),
                            description: Some(
                                "Redis list/set/sorted set operation without visible size limit. \
                                 Collections can grow unbounded. Use LTRIM for lists, or \
                                 ZREMRANGEBYRANK for sorted sets to maintain a maximum size.".to_string()
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Medium,
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
                            fix_preview: Some(generate_collection_limit_fix_preview()),
                            tags: vec![
                                "python".into(),
                                "redis".into(),
                                "collection".into(),
                                "unbounded".into(),
                            ],
                        });
                    }
                }
            }

            // Check for KEYS command usage (dangerous in production)
            for call in &py.calls {
                if call.function_call.callee_expr.ends_with(".keys") && call.args_repr.contains("*") {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Redis KEYS command with wildcard".to_string(),
                        description: Some(
                            "Redis KEYS command with wildcard pattern is dangerous in production. \
                             It blocks the server while scanning all keys. Use SCAN instead for \
                             iterating over keys.".to_string()
                        ),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::High,
                        confidence: 0.90,
                        dimension: Dimension::Performance,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_scan_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "redis".into(),
                            "keys".into(),
                            "performance".into(),
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

/// Generate fix preview for timestamp-based keys.
fn generate_timestamp_key_fix_preview() -> String {
    r#"# Avoid timestamp/UUID-based Redis keys

import redis
import time

r = redis.Redis()

# Bad: Creates new key for each event
r.set(f"event:{time.time()}", data)  # Unbounded keys!
r.set(f"session:{uuid.uuid4()}", data)  # Unbounded keys!

# Good: Use sorted sets for time-series data
r.zadd("events", {json.dumps(data): time.time()})
# Trim to keep only recent entries
r.zremrangebyrank("events", 0, -10001)  # Keep last 10000

# Good: Use fixed keys with TTL
r.setex("latest_event", 3600, json.dumps(data))

# Good: Use time-bucketed keys
hour_bucket = time.strftime("%Y%m%d%H")
r.lpush(f"events:{hour_bucket}", json.dumps(data))
r.expire(f"events:{hour_bucket}", 86400)  # Expire after 1 day

# Good: Use hash for related data
r.hset("user:123:events", "latest", json.dumps(data))
r.expire("user:123:events", 3600)

# Good: Use streams for event logs (Redis 5.0+)
r.xadd("events_stream", {"data": json.dumps(data)}, maxlen=10000)

# For session data, use fixed session IDs with TTL:
session_id = generate_session_id()  # Fixed per session
r.setex(f"session:{session_id}", 3600, json.dumps(session_data))"#.to_string()
}

/// Generate fix preview for dynamic keys.
fn generate_dynamic_key_fix_preview() -> String {
    r#"# Safely handle dynamic Redis keys

import redis
import hashlib

r = redis.Redis()

# Bad: Unbounded user-generated keys
r.set(f"user:{user_input}", data)  # User controls key space!

# Good: Validate and normalize keys
def safe_cache_key(prefix: str, identifier: str, max_length: int = 100) -> str:
    """Create a safe, bounded cache key."""
    # Normalize the identifier
    normalized = identifier.lower().strip()
    # Hash if too long
    if len(normalized) > max_length:
        normalized = hashlib.sha256(normalized.encode()).hexdigest()[:16]
    # Remove dangerous characters
    safe_id = "".join(c for c in normalized if c.isalnum() or c in "-_")
    return f"{prefix}:{safe_id}"

key = safe_cache_key("user", user_input)
r.setex(key, 3600, data)

# Good: Use hash slots for user data
r.hset("users", user_id, json.dumps(data))  # Single key, multiple fields
r.expire("users", 3600)

# Good: Limit key cardinality
MAX_CACHED_USERS = 10000
if r.scard("cached_users") < MAX_CACHED_USERS:
    r.sadd("cached_users", user_id)
    r.setex(f"user:{user_id}", 3600, data)

# Good: Use LRU eviction policy in Redis config
# maxmemory-policy allkeys-lru

# Good: Implement key cleanup
def cleanup_old_keys(pattern: str, max_age: int):
    for key in r.scan_iter(pattern):
        if r.ttl(key) == -1:  # No TTL set
            r.expire(key, max_age)"#.to_string()
}

/// Generate fix preview for collection limits.
fn generate_collection_limit_fix_preview() -> String {
    r#"# Limit Redis collection sizes

import redis

r = redis.Redis()

# Bad: Unbounded list growth
r.lpush("events", event_data)  # List grows forever!

# Good: Use LTRIM to cap list size
MAX_EVENTS = 1000
pipe = r.pipeline()
pipe.lpush("events", event_data)
pipe.ltrim("events", 0, MAX_EVENTS - 1)  # Keep only latest 1000
pipe.execute()

# Good: Use sorted set with score-based cleanup
r.zadd("events", {event_data: time.time()})
# Remove entries older than 1 hour
r.zremrangebyscore("events", 0, time.time() - 3600)
# Or keep only top N entries
r.zremrangebyrank("events", 0, -MAX_EVENTS - 1)

# Good: Use capped streams (Redis 5.0+)
r.xadd("events_stream", {"data": event_data}, maxlen=MAX_EVENTS)

# Good: Use MAXLEN with approximate trimming (faster)
r.xadd("events_stream", {"data": event_data}, maxlen=MAX_EVENTS, approximate=True)

# For sets, periodically clean up:
def trim_set(key: str, max_size: int):
    current_size = r.scard(key)
    if current_size > max_size:
        # Remove random members to get back to max_size
        to_remove = current_size - max_size
        members = r.srandmember(key, to_remove)
        if members:
            r.srem(key, *members)

# Monitor collection sizes:
def check_collection_sizes():
    for key in r.scan_iter("*"):
        key_type = r.type(key)
        if key_type == b"list":
            size = r.llen(key)
        elif key_type == b"set":
            size = r.scard(key)
        elif key_type == b"zset":
            size = r.zcard(key)
        else:
            continue
        if size > 10000:
            print(f"Warning: {key} has {size} elements")"#.to_string()
}

/// Generate fix preview for SCAN vs KEYS.
fn generate_scan_fix_preview() -> String {
    r#"# Use SCAN instead of KEYS in production

import redis

r = redis.Redis()

# Bad: KEYS blocks the server
keys = r.keys("user:*")  # Blocks until complete!

# Good: Use SCAN for iteration
def get_keys_safely(pattern: str):
    """Iterate over keys without blocking."""
    keys = []
    cursor = 0
    while True:
        cursor, batch = r.scan(cursor, match=pattern, count=100)
        keys.extend(batch)
        if cursor == 0:
            break
    return keys

# Good: Use scan_iter (Python redis client helper)
for key in r.scan_iter("user:*"):
    # Process each key
    pass

# Good: Process in batches
def process_keys_in_batches(pattern: str, batch_size: int = 100):
    cursor = 0
    while True:
        cursor, keys = r.scan(cursor, match=pattern, count=batch_size)
        if keys:
            # Process batch
            pipe = r.pipeline()
            for key in keys:
                pipe.get(key)
            results = pipe.execute()
            yield from zip(keys, results)
        if cursor == 0:
            break

# For hash fields, use HSCAN:
for field, value in r.hscan_iter("myhash"):
    pass

# For set members, use SSCAN:
for member in r.sscan_iter("myset"):
    pass

# For sorted set, use ZSCAN:
for member, score in r.zscan_iter("myzset"):
    pass"#.to_string()
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
        let rule = RedisUnboundedKeysRule::new();
        assert_eq!(rule.id(), "python.redis.unbounded_keys");
    }

    #[test]
    fn rule_name_mentions_unbounded() {
        let rule = RedisUnboundedKeysRule::new();
        assert!(rule.name().contains("unbounded"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_redis_code() {
        let rule = RedisUnboundedKeysRule::new();
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
    async fn fix_preview_contains_scan() {
        let preview = generate_scan_fix_preview();
        assert!(preview.contains("scan_iter"));
        assert!(preview.contains("SCAN"));
    }

    #[tokio::test]
    async fn fix_preview_contains_ltrim() {
        let preview = generate_collection_limit_fix_preview();
        assert!(preview.contains("ltrim"));
        assert!(preview.contains("zremrangebyrank"));
    }
}