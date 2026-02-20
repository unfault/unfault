//! Go rules module.
//!
//! Contains rules for detecting production-readiness issues in Go code.

// Core rules
pub mod bare_recover;
pub mod context_background;
pub mod defer_in_loop;
pub mod empty_critical_section;
pub mod goroutine_leak;
pub mod http_timeout;
pub mod sql_injection;
pub mod unchecked_error;
pub mod unhandled_error_goroutine;

// Observability rules
pub mod missing_correlation_id;
pub mod missing_structured_logging;
pub mod missing_tracing;

// Resilience rules
pub mod circuit_breaker;
pub mod graceful_shutdown;
pub mod http_retry;
pub mod rate_limiting;
pub mod unbounded_retry;

// Security rules
pub mod hardcoded_secrets;
pub mod unsafe_template;

// Concurrency rules
pub mod channel_never_closed;
pub mod concurrent_map_access;
pub mod global_mutable_state;
pub mod race_condition;
pub mod regex_compile;
pub mod unbounded_goroutines;
pub mod uncancelled_context;

// Memory/Performance rules
pub mod cpu_in_hot_path;
pub mod large_response_memory;
pub mod map_without_size_hint;
pub mod reflect_in_hot_path;
pub mod slice_append_in_loop;
pub mod slice_memory_leak;
pub mod unbounded_cache;
pub mod unbounded_memory;

// Type safety rules
pub mod type_assertion_no_ok;

// Error handling rules
pub mod error_type_assertion;
pub mod panic_in_library;
pub mod sentinel_error_comparison;

// Data/Storage rules
pub mod ephemeral_filesystem_write;
pub mod idempotency_key;
pub mod transaction_boundary;

// Network rules
pub mod sync_dns_lookup;

// Maintainability rules
pub mod halstead_complexity;

pub mod frameworks;

// Re-export core rules for convenience
pub use bare_recover::GoBareRecoverRule;
pub use context_background::GoContextBackgroundRule;
pub use defer_in_loop::GoDeferInLoopRule;
pub use empty_critical_section::GoEmptyCriticalSectionRule;
pub use goroutine_leak::GoGoroutineLeakRule;
pub use http_timeout::GoHttpTimeoutRule;
pub use sql_injection::GoSqlInjectionRule;
pub use unchecked_error::GoUncheckedErrorRule;
pub use unhandled_error_goroutine::GoUnhandledErrorGoroutineRule;

// Re-export observability rules
pub use missing_correlation_id::GoMissingCorrelationIdRule;
pub use missing_structured_logging::GoMissingStructuredLoggingRule;
pub use missing_tracing::GoMissingTracingRule;

// Re-export resilience rules
pub use circuit_breaker::GoMissingCircuitBreakerRule;
pub use graceful_shutdown::GoMissingGracefulShutdownRule;
pub use http_retry::GoHttpRetryRule;
pub use rate_limiting::GoRateLimitingRule;
pub use unbounded_retry::GoUnboundedRetryRule;

// Re-export security rules
pub use hardcoded_secrets::GoHardcodedSecretsRule;
pub use unsafe_template::GoUnsafeTemplateRule;

// Re-export concurrency rules
pub use channel_never_closed::GoChannelNeverClosedRule;
pub use concurrent_map_access::GoConcurrentMapAccessRule;
pub use global_mutable_state::GoGlobalMutableStateRule;
pub use race_condition::GoRaceConditionRule;
pub use regex_compile::GoRegexCompileRule;
pub use unbounded_goroutines::GoUnboundedGoroutinesRule;
pub use uncancelled_context::GoUncancelledContextRule;

// Re-export memory/performance rules
pub use cpu_in_hot_path::GoCpuInHotPathRule;
pub use large_response_memory::GoLargeResponseMemoryRule;
pub use map_without_size_hint::GoMapWithoutSizeHintRule;
pub use reflect_in_hot_path::GoReflectInHotPathRule;
pub use slice_append_in_loop::GoSliceAppendInLoopRule;
pub use slice_memory_leak::GoSliceMemoryLeakRule;
pub use unbounded_cache::GoUnboundedCacheRule;
pub use unbounded_memory::GoUnboundedMemoryRule;

// Re-export type safety rules
pub use type_assertion_no_ok::GoTypeAssertionNoOkRule;

// Re-export error handling rules
pub use error_type_assertion::GoErrorTypeAssertionRule;
pub use panic_in_library::GoPanicInLibraryRule;
pub use sentinel_error_comparison::GoSentinelErrorComparisonRule;

// Re-export data/storage rules
pub use ephemeral_filesystem_write::GoEphemeralFilesystemWriteRule;
pub use idempotency_key::GoIdempotencyKeyRule;
pub use transaction_boundary::GoTransactionBoundaryRule;

// Re-export network rules
pub use sync_dns_lookup::GoSyncDnsLookupRule;

// Re-export maintainability rules
pub use halstead_complexity::GoHalsteadComplexityRule;
