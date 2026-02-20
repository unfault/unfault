//! Framework-specific rules for TypeScript
//!
//! This module contains rules for popular TypeScript/JavaScript frameworks:
//! - Express.js
//! - NestJS (future)
//! - Fastify (future)

pub mod express;
pub mod nextjs;

// Re-exports
pub use express::ExpressMissingErrorMiddlewareRule;
pub use nextjs::NextJsApiMissingErrorLoggingRule;
