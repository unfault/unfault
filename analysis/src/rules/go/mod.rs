//! Go rules module.
//!
//! Contains rules for detecting production-readiness issues in Go code.

// Core rules
pub mod context_background;
pub mod defer_in_loop;
pub mod empty_critical_section;
pub mod goroutine_leak;
pub mod http_timeout;
pub mod sql_injection;
pub mod unchecked_error;
pub mod unhandled_error_goroutine;
pub mod bare_recover;

// Observability rules
pub mod missing_structured_logging;
pub mod missing_tracing;
pub mod missing_correlation_id;

// Resilience rules
pub mod unbounded_retry;
pub mod circuit_breaker;
pub mod graceful_shutdown;
pub mod http_retry;
pub mod rate_limiting;

// Security rules
pub mod hardcoded_secrets;
pub mod unsafe_template;

// Concurrency rules
pub mod unbounded_goroutines;
pub mod race_condition;
pub mod regex_compile;
pub mod global_mutable_state;
pub mod uncancelled_context;
pub mod channel_never_closed;
pub mod concurrent_map_access;

// Memory/Performance rules
pub mod unbounded_memory;
pub mod unbounded_cache;
pub mod large_response_memory;
pub mod cpu_in_hot_path;
pub mod slice_memory_leak;
pub mod slice_append_in_loop;
pub mod map_without_size_hint;
pub mod reflect_in_hot_path;

// Type safety rules
pub mod type_assertion_no_ok;

// Error handling rules
pub mod sentinel_error_comparison;
pub mod error_type_assertion;
pub mod panic_in_library;

// Data/Storage rules
pub mod transaction_boundary;
pub mod idempotency_key;
pub mod ephemeral_filesystem_write;

// Network rules
pub mod sync_dns_lookup;

// Maintainability rules
pub mod halstead_complexity;

pub mod frameworks;

// Re-export core rules for convenience
pub use context_background::GoContextBackgroundRule;
pub use defer_in_loop::GoDeferInLoopRule;
pub use empty_critical_section::GoEmptyCriticalSectionRule;
pub use goroutine_leak::GoGoroutineLeakRule;
pub use http_timeout::GoHttpTimeoutRule;
pub use sql_injection::GoSqlInjectionRule;
pub use unchecked_error::GoUncheckedErrorRule;
pub use unhandled_error_goroutine::GoUnhandledErrorGoroutineRule;
pub use bare_recover::GoBareRecoverRule;

// Re-export observability rules
pub use missing_structured_logging::GoMissingStructuredLoggingRule;
pub use missing_tracing::GoMissingTracingRule;
pub use missing_correlation_id::GoMissingCorrelationIdRule;

// Re-export resilience rules
pub use unbounded_retry::GoUnboundedRetryRule;
pub use circuit_breaker::GoMissingCircuitBreakerRule;
pub use graceful_shutdown::GoMissingGracefulShutdownRule;
pub use http_retry::GoHttpRetryRule;
pub use rate_limiting::GoRateLimitingRule;

// Re-export security rules
pub use hardcoded_secrets::GoHardcodedSecretsRule;
pub use unsafe_template::GoUnsafeTemplateRule;

// Re-export concurrency rules
pub use unbounded_goroutines::GoUnboundedGoroutinesRule;
pub use race_condition::GoRaceConditionRule;
pub use regex_compile::GoRegexCompileRule;
pub use global_mutable_state::GoGlobalMutableStateRule;
pub use uncancelled_context::GoUncancelledContextRule;
pub use channel_never_closed::GoChannelNeverClosedRule;
pub use concurrent_map_access::GoConcurrentMapAccessRule;

// Re-export memory/performance rules
pub use unbounded_memory::GoUnboundedMemoryRule;
pub use unbounded_cache::GoUnboundedCacheRule;
pub use large_response_memory::GoLargeResponseMemoryRule;
pub use cpu_in_hot_path::GoCpuInHotPathRule;
pub use slice_memory_leak::GoSliceMemoryLeakRule;
pub use slice_append_in_loop::GoSliceAppendInLoopRule;
pub use map_without_size_hint::GoMapWithoutSizeHintRule;
pub use reflect_in_hot_path::GoReflectInHotPathRule;

// Re-export type safety rules
pub use type_assertion_no_ok::GoTypeAssertionNoOkRule;

// Re-export error handling rules
pub use sentinel_error_comparison::GoSentinelErrorComparisonRule;
pub use error_type_assertion::GoErrorTypeAssertionRule;
pub use panic_in_library::GoPanicInLibraryRule;

// Re-export data/storage rules
pub use transaction_boundary::GoTransactionBoundaryRule;
pub use idempotency_key::GoIdempotencyKeyRule;
pub use ephemeral_filesystem_write::GoEphemeralFilesystemWriteRule;

// Re-export network rules
pub use sync_dns_lookup::GoSyncDnsLookupRule;

// Re-export maintainability rules
pub use halstead_complexity::GoHalsteadComplexityRule;