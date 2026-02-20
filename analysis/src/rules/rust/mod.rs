//! Rust rules module.
//!
//! Contains rules for detecting production-readiness issues in Rust code.
//! These rules cover error handling, async patterns, security, observability,
//! and performance concerns.
//!
//! ## Rule Count: 42 rules
//!
//! ### By Category:
//! - Error handling: 3 rules
//! - Async/concurrency: 8 rules
//! - Safety/security: 3 rules
//! - Observability: 4 rules
//! - Performance: 6 rules
//! - Resilience: 2 rules
//! - Memory: 3 rules
//! - Data/storage: 3 rules
//! - Network: 2 rules
//! - Framework (Axum/Tokio/SQLx): 8 rules

// Error handling rules
pub mod ignored_result;
pub mod panic_in_library;
pub mod unsafe_unwrap;

// Async/concurrency rules
pub mod arc_mutex_contention;
pub mod blocking_in_async;
pub mod cpu_in_async;
pub mod missing_async_timeout;
pub mod missing_select_timeout;
pub mod spawn_no_error_handling;
pub mod unbounded_channel;
pub mod unbounded_concurrency;
pub mod uncancelled_tasks;

// Safety/security rules
pub mod hardcoded_secrets;
pub mod regex_compile;
pub mod sql_injection;
pub mod unsafe_block_unaudited;

// Observability rules
pub mod missing_correlation_id;
pub mod missing_structured_logging;
pub mod missing_tracing;
pub mod println_in_lib;

// Performance rules
pub mod clone_in_loop;
pub mod io_in_hot_path;
pub mod n_plus_one;
pub mod sync_dns_lookup;
pub mod unbounded_memory;
pub mod unbounded_recursion;

// Resilience rules
pub mod circuit_breaker;
pub mod unbounded_retry;

// Memory rules
pub mod large_response_memory;
pub mod unbounded_cache;

// Datetime rules
pub mod naive_datetime;

// Concurrency rules
pub mod global_mutable_state;

// Data/storage rules
pub mod ephemeral_filesystem_write;
pub mod idempotency_key;

// Network rules
pub mod grpc_no_deadline;

// Maintainability rules
pub mod halstead_complexity;

// Framework-specific rules
pub mod frameworks;

// Re-export error handling rules
pub use ignored_result::RustIgnoredResultRule;
pub use panic_in_library::RustPanicInLibraryRule;
pub use unsafe_unwrap::RustUnsafeUnwrapRule;

// Re-export async/concurrency rules
pub use arc_mutex_contention::RustArcMutexContentionRule;
pub use blocking_in_async::RustBlockingInAsyncRule;
pub use cpu_in_async::RustCpuInAsyncRule;
pub use missing_async_timeout::RustMissingAsyncTimeoutRule;
pub use missing_select_timeout::RustMissingSelectTimeoutRule;
pub use spawn_no_error_handling::RustSpawnNoErrorHandlingRule;
pub use unbounded_channel::RustUnboundedChannelRule;
pub use unbounded_concurrency::RustUnboundedConcurrencyRule;
pub use uncancelled_tasks::RustUncancelledTasksRule;

// Re-export safety/security rules
pub use hardcoded_secrets::RustHardcodedSecretsRule;
pub use regex_compile::RustRegexCompileRule;
pub use sql_injection::RustSqlInjectionRule;
pub use unsafe_block_unaudited::RustUnsafeBlockUnauditedRule;

// Re-export observability rules
pub use missing_correlation_id::RustMissingCorrelationIdRule;
pub use missing_structured_logging::RustMissingStructuredLoggingRule;
pub use missing_tracing::RustMissingTracingRule;
pub use println_in_lib::RustPrintlnInLibRule;

// Re-export performance rules
pub use clone_in_loop::RustCloneInLoopRule;
pub use io_in_hot_path::RustIoInHotPathRule;
pub use n_plus_one::RustNPlusOneRule;
pub use sync_dns_lookup::RustSyncDnsLookupRule;
pub use unbounded_memory::RustUnboundedMemoryRule;
pub use unbounded_recursion::RustUnboundedRecursionRule;

// Re-export resilience rules
pub use circuit_breaker::RustMissingCircuitBreakerRule;
pub use unbounded_retry::RustUnboundedRetryRule;

// Re-export memory rules
pub use large_response_memory::RustLargeResponseMemoryRule;
pub use unbounded_cache::RustUnboundedCacheRule;

// Re-export datetime rules
pub use naive_datetime::RustNaiveDatetimeRule;

// Re-export concurrency rules
pub use global_mutable_state::RustGlobalMutableStateRule;

// Re-export data/storage rules
pub use ephemeral_filesystem_write::RustEphemeralFilesystemWriteRule;
pub use idempotency_key::RustMissingIdempotencyKeyRule;

// Re-export network rules
pub use grpc_no_deadline::RustGrpcNoDeadlineRule;

// Re-export maintainability rules
pub use halstead_complexity::RustHalsteadComplexityRule;

// Re-export framework rules
pub use frameworks::{
    AxumMissingCorsRule, AxumMissingErrorHandlerRule, AxumMissingTimeoutRule,
    SqlxMissingPoolTimeoutRule, SqlxMissingTransactionRule, SqlxQueryWithoutTimeoutRule,
    TokioMissingGracefulShutdownRule, TokioMissingRuntimeConfigRule,
};
