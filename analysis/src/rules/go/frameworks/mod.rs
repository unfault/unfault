//! Go framework-specific rules.
//!
//! Contains rules for popular Go web frameworks and libraries:
//! - net/http (standard library)
//! - Gin
//! - Echo
//! - GORM
//! - gRPC
//! - Redis

pub mod echo;
pub mod gin;
pub mod gorm;
pub mod grpc;
pub mod nethttp;
pub mod redis;

// Re-export Gin rules
pub use gin::{GinMissingValidationRule, GinUntrustedInputRule};

// Re-export net/http rules
pub use nethttp::{NetHttpHandlerTimeoutRule, NetHttpServerTimeoutRule};

// Re-export Echo rules
pub use echo::{EchoMissingMiddlewareRule, EchoRequestValidationRule};

// Re-export GORM rules
pub use gorm::{
    GormConnectionPoolRule, GormNPlusOneRule, GormQueryTimeoutRule, GormSessionManagementRule,
};

// Re-export gRPC rules
pub use grpc::GrpcMissingDeadlineRule;

// Re-export Redis rules
pub use redis::{RedisConnectionPoolRule, RedisMissingTtlRule};
