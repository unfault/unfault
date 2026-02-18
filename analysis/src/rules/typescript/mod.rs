//! TypeScript-specific rules for production readiness analysis.

pub mod async_without_error_handling;
pub mod bare_catch;
pub mod circuit_breaker;
pub mod console_in_production;
pub mod cpu_in_event_loop;
pub mod empty_catch;
pub mod global_mutable_state;
pub mod graceful_shutdown;
pub mod grpc_no_deadline;
pub mod hardcoded_secrets;
pub mod http_missing_timeout;
pub mod http_retry;
pub mod idempotency_key;
pub mod large_response_memory;
pub mod missing_correlation_id;
pub mod missing_null_check;
pub mod missing_structured_logging;
pub mod missing_tracing;
pub mod n_plus_one_queries;
pub mod naive_datetime;
pub mod promise_no_catch;
pub mod race_condition;
pub mod rate_limiting;
pub mod regex_compile;
pub mod sql_injection;
pub mod sync_dns_lookup;
pub mod transaction_boundary;
pub mod unbounded_cache;
pub mod unbounded_concurrency;
pub mod unbounded_memory;
pub mod unbounded_retry;
pub mod unsafe_any;
pub mod unsafe_eval;

// Framework rules
pub mod frameworks;

// Maintainability rules
pub mod halstead_complexity;

// Re-exports
pub use async_without_error_handling::TypescriptAsyncWithoutErrorHandlingRule;
pub use bare_catch::TypescriptBareCatchRule;
pub use circuit_breaker::TypescriptMissingCircuitBreakerRule;
pub use console_in_production::TypescriptConsoleInProductionRule;
pub use cpu_in_event_loop::TypescriptCpuInEventLoopRule;
pub use empty_catch::TypescriptEmptyCatchRule;
pub use global_mutable_state::TypescriptGlobalMutableStateRule;
pub use graceful_shutdown::TypescriptMissingGracefulShutdownRule;
pub use grpc_no_deadline::TypescriptGrpcNoDeadlineRule;
pub use hardcoded_secrets::TypescriptHardcodedSecretsRule;
pub use http_missing_timeout::TypescriptHttpMissingTimeoutRule;
pub use http_retry::TypescriptHttpMissingRetryRule;
pub use idempotency_key::TypescriptMissingIdempotencyKeyRule;
pub use large_response_memory::TypescriptLargeResponseMemoryRule;
pub use missing_correlation_id::TypescriptMissingCorrelationIdRule;
pub use missing_null_check::TypescriptMissingNullCheckRule;
pub use missing_structured_logging::TypescriptMissingStructuredLoggingRule;
pub use missing_tracing::TypescriptMissingTracingRule;
pub use n_plus_one_queries::TypescriptNPlusOneQueriesRule;
pub use naive_datetime::TypescriptNaiveDatetimeRule;
pub use promise_no_catch::TypescriptPromiseNoCatchRule;
pub use race_condition::TypescriptRaceConditionRule;
pub use rate_limiting::TypescriptMissingRateLimitingRule;
pub use regex_compile::TypescriptRegexCompileRule;
pub use sql_injection::TypescriptSqlInjectionRule;
pub use sync_dns_lookup::TypescriptSyncDnsLookupRule;
pub use transaction_boundary::TypescriptTransactionBoundaryRule;
pub use unbounded_cache::TypescriptUnboundedCacheRule;
pub use unbounded_concurrency::TypescriptUnboundedConcurrencyRule;
pub use unbounded_memory::TypescriptUnboundedMemoryRule;
pub use unbounded_retry::TypescriptUnboundedRetryRule;
pub use unsafe_any::TypescriptUnsafeAnyRule;
pub use unsafe_eval::TypescriptUnsafeEvalRule;

// Re-export maintainability rules
pub use halstead_complexity::TypescriptHalsteadComplexityRule;