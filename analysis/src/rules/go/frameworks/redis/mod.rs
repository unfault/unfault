//! Redis framework-specific rules for Go.
//!
//! Contains rules for detecting production-readiness issues in Redis client usage.

pub mod missing_ttl;
pub mod connection_pool;

pub use missing_ttl::RedisMissingTtlRule;
pub use connection_pool::RedisConnectionPoolRule;

/// Returns all Redis rules
pub fn all_rules() -> Vec<Box<dyn crate::rules::Rule>> {
    vec![
        Box::new(RedisMissingTtlRule::new()),
        Box::new(RedisConnectionPoolRule::new()),
    ]
}