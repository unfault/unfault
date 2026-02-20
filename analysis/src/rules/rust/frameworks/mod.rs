//! Framework-specific Rust rules.
//!
//! Contains rules for detecting production-readiness issues in
//! Rust web framework code (Axum, Actix), async runtimes (Tokio),
//! and database libraries (SQLx, Diesel).

pub mod axum;
pub mod sqlx;
pub mod tokio;

// Re-export Axum rules
pub use axum::AxumMissingCorsRule;
pub use axum::AxumMissingErrorHandlerRule;
pub use axum::AxumMissingTimeoutRule;

// Re-export Tokio rules
pub use tokio::TokioMissingGracefulShutdownRule;
pub use tokio::TokioMissingRuntimeConfigRule;

// Re-export SQLx rules
pub use sqlx::SqlxMissingPoolTimeoutRule;
pub use sqlx::SqlxMissingTransactionRule;
pub use sqlx::SqlxQueryWithoutTimeoutRule;
