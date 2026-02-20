//! Redis framework-specific rules for Go.
//!
//! Contains rules for detecting production-readiness issues in Redis client usage.

pub mod connection_pool;
pub mod missing_ttl;

pub use connection_pool::RedisConnectionPoolRule;
pub use missing_ttl::RedisMissingTtlRule;

/// Returns all Redis rules
pub fn all_rules() -> Vec<Box<dyn crate::rules::Rule>> {
    vec![
        Box::new(RedisMissingTtlRule::new()),
        Box::new(RedisConnectionPoolRule::new()),
    ]
}
