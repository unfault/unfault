use std::collections::HashSet;
use std::sync::Arc;

use crate::rules::Rule;

// Go core rules
use crate::rules::go::bare_recover::GoBareRecoverRule;
use crate::rules::go::context_background::GoContextBackgroundRule;
use crate::rules::go::defer_in_loop::GoDeferInLoopRule;
use crate::rules::go::empty_critical_section::GoEmptyCriticalSectionRule;
use crate::rules::go::goroutine_leak::GoGoroutineLeakRule;
use crate::rules::go::http_timeout::GoHttpTimeoutRule;
use crate::rules::go::sql_injection::GoSqlInjectionRule;
use crate::rules::go::unchecked_error::GoUncheckedErrorRule;
use crate::rules::go::unhandled_error_goroutine::GoUnhandledErrorGoroutineRule;

// Go observability rules
use crate::rules::go::missing_correlation_id::GoMissingCorrelationIdRule;
use crate::rules::go::missing_structured_logging::GoMissingStructuredLoggingRule;
use crate::rules::go::missing_tracing::GoMissingTracingRule;

// Go resilience rules
use crate::rules::go::circuit_breaker::GoMissingCircuitBreakerRule;
use crate::rules::go::graceful_shutdown::GoMissingGracefulShutdownRule;
use crate::rules::go::http_retry::GoHttpRetryRule;
use crate::rules::go::rate_limiting::GoRateLimitingRule;
use crate::rules::go::unbounded_retry::GoUnboundedRetryRule;

// Go security rules
use crate::rules::go::hardcoded_secrets::GoHardcodedSecretsRule;
use crate::rules::go::unsafe_template::GoUnsafeTemplateRule;

// Go concurrency rules
use crate::rules::go::channel_never_closed::GoChannelNeverClosedRule;
use crate::rules::go::concurrent_map_access::GoConcurrentMapAccessRule;
use crate::rules::go::global_mutable_state::GoGlobalMutableStateRule;
use crate::rules::go::race_condition::GoRaceConditionRule;
use crate::rules::go::regex_compile::GoRegexCompileRule;
use crate::rules::go::unbounded_goroutines::GoUnboundedGoroutinesRule;
use crate::rules::go::uncancelled_context::GoUncancelledContextRule;

// Go memory/performance rules
use crate::rules::go::cpu_in_hot_path::GoCpuInHotPathRule;
use crate::rules::go::large_response_memory::GoLargeResponseMemoryRule;
use crate::rules::go::map_without_size_hint::GoMapWithoutSizeHintRule;
use crate::rules::go::reflect_in_hot_path::GoReflectInHotPathRule;
use crate::rules::go::slice_append_in_loop::GoSliceAppendInLoopRule;
use crate::rules::go::slice_memory_leak::GoSliceMemoryLeakRule;
use crate::rules::go::unbounded_cache::GoUnboundedCacheRule;
use crate::rules::go::unbounded_memory::GoUnboundedMemoryRule;

// Go type safety rules
use crate::rules::go::type_assertion_no_ok::GoTypeAssertionNoOkRule;

// Go error handling rules
use crate::rules::go::error_type_assertion::GoErrorTypeAssertionRule;
use crate::rules::go::panic_in_library::GoPanicInLibraryRule;
use crate::rules::go::sentinel_error_comparison::GoSentinelErrorComparisonRule;

// Go data/storage rules
use crate::rules::go::ephemeral_filesystem_write::GoEphemeralFilesystemWriteRule;
use crate::rules::go::idempotency_key::GoIdempotencyKeyRule;
use crate::rules::go::transaction_boundary::GoTransactionBoundaryRule;

// Go network rules
use crate::rules::go::sync_dns_lookup::GoSyncDnsLookupRule;

// Go maintainability rules
use crate::rules::go::halstead_complexity::GoHalsteadComplexityRule;

// Go framework rules
use crate::rules::go::frameworks::echo::{EchoMissingMiddlewareRule, EchoRequestValidationRule};
use crate::rules::go::frameworks::gin::{GinMissingValidationRule, GinUntrustedInputRule};
use crate::rules::go::frameworks::gorm::{
    GormConnectionPoolRule, GormNPlusOneRule, GormQueryTimeoutRule, GormSessionManagementRule,
};
use crate::rules::go::frameworks::grpc::GrpcMissingDeadlineRule;
use crate::rules::go::frameworks::nethttp::{NetHttpHandlerTimeoutRule, NetHttpServerTimeoutRule};
use crate::rules::go::frameworks::redis::{
    RedisConnectionPoolRule as GoRedisConnectionPoolRule,
    RedisMissingTtlRule as GoRedisMissingTtlRule,
};

// Rust rules - Error handling
use crate::rules::rust::RustIgnoredResultRule;
use crate::rules::rust::RustPanicInLibraryRule;
use crate::rules::rust::RustUnsafeUnwrapRule;

// Rust rules - Async/concurrency
use crate::rules::rust::RustArcMutexContentionRule;
use crate::rules::rust::RustBlockingInAsyncRule;
use crate::rules::rust::RustCpuInAsyncRule;
use crate::rules::rust::RustMissingAsyncTimeoutRule;
use crate::rules::rust::RustMissingSelectTimeoutRule;
use crate::rules::rust::RustSpawnNoErrorHandlingRule;
use crate::rules::rust::RustUnboundedChannelRule;
use crate::rules::rust::RustUnboundedConcurrencyRule;
use crate::rules::rust::RustUncancelledTasksRule;

// Rust rules - Safety/security
use crate::rules::rust::RustHardcodedSecretsRule;
use crate::rules::rust::RustSqlInjectionRule;
use crate::rules::rust::RustUnsafeBlockUnauditedRule;

// Rust rules - Performance (additional)
use crate::rules::rust::RustRegexCompileRule;

// Rust rules - Observability
use crate::rules::rust::RustMissingStructuredLoggingRule;
use crate::rules::rust::RustMissingTracingRule;
use crate::rules::rust::RustPrintlnInLibRule;

// Rust rules - Performance
use crate::rules::rust::RustCloneInLoopRule;
use crate::rules::rust::RustIoInHotPathRule;
use crate::rules::rust::RustNPlusOneRule;
use crate::rules::rust::RustSyncDnsLookupRule;
use crate::rules::rust::RustUnboundedMemoryRule;
use crate::rules::rust::RustUnboundedRecursionRule;

// Rust rules - Datetime
use crate::rules::rust::RustNaiveDatetimeRule;

// Rust framework rules - Axum
use crate::rules::rust::AxumMissingCorsRule;
use crate::rules::rust::AxumMissingErrorHandlerRule;
use crate::rules::rust::AxumMissingTimeoutRule;

// Rust framework rules - Tokio
use crate::rules::rust::TokioMissingGracefulShutdownRule;
use crate::rules::rust::TokioMissingRuntimeConfigRule;

// Rust framework rules - SQLx
use crate::rules::rust::SqlxMissingPoolTimeoutRule;
use crate::rules::rust::SqlxMissingTransactionRule;
use crate::rules::rust::SqlxQueryWithoutTimeoutRule;

// Rust rules - Resilience
use crate::rules::rust::RustMissingCircuitBreakerRule;
use crate::rules::rust::RustUnboundedRetryRule;

// Rust rules - Observability
use crate::rules::rust::RustMissingCorrelationIdRule;

// Rust rules - Memory
use crate::rules::rust::RustLargeResponseMemoryRule;
use crate::rules::rust::RustUnboundedCacheRule;

// Rust rules - Concurrency
use crate::rules::rust::RustGlobalMutableStateRule;

// Rust rules - Data/Storage
use crate::rules::rust::RustEphemeralFilesystemWriteRule;
use crate::rules::rust::RustMissingIdempotencyKeyRule;

// Rust rules - Network
use crate::rules::rust::RustGrpcNoDeadlineRule;

// Rust rules - Maintainability
use crate::rules::rust::RustHalsteadComplexityRule;

// Python rules
use crate::rules::python::async_task_no_error_handling::PythonAsyncTaskNoErrorHandlingRule;
use crate::rules::python::asyncio_timeout::PythonAsyncioTimeoutRule;
use crate::rules::python::bare_except::PythonBareExceptRule;
use crate::rules::python::circuit_breaker::PythonMissingCircuitBreakerRule;
use crate::rules::python::code_duplication::PythonCodeDuplicationRule;
use crate::rules::python::cpu_in_event_loop::PythonCpuInEventLoopRule;
use crate::rules::python::db_timeout::PythonDbTimeoutRule;
use crate::rules::python::ephemeral_filesystem_write::PythonEphemeralFilesystemWriteRule;
use crate::rules::python::frameworks::async_resource_cleanup::PythonAsyncResourceCleanupRule;
use crate::rules::python::frameworks::django::allowed_hosts::DjangoAllowedHostsRule;
use crate::rules::python::frameworks::django::missing_csrf::DjangoMissingCsrfRule;
use crate::rules::python::frameworks::django::orm_select_related::DjangoOrmSelectRelatedRule;
use crate::rules::python::frameworks::django::secure_settings::DjangoSecureSettingsRule;
use crate::rules::python::frameworks::django::session_settings::DjangoSessionSettingsRule;
use crate::rules::python::frameworks::fastapi::exception_handler::FastApiExceptionHandlerRule;
use crate::rules::python::frameworks::fastapi::health_check::FastApiHealthCheckRule;
use crate::rules::python::frameworks::fastapi::input_validation::FastApiInputValidationRule;
use crate::rules::python::frameworks::fastapi::missing_cors::FastApiMissingCorsRule;
use crate::rules::python::frameworks::fastapi::rate_limiting::FastApiMissingRateLimitingRule;
use crate::rules::python::frameworks::fastapi::request_body_unbounded::FastApiRequestBodyUnboundedRule;
use crate::rules::python::frameworks::fastapi::request_timeout::FastApiRequestTimeoutRule;
use crate::rules::python::frameworks::flask::cookie_settings::FlaskInsecureCookieSettingsRule;
use crate::rules::python::frameworks::flask::secret_key::FlaskHardcodedSecretKeyRule;
use crate::rules::python::frameworks::flask::session_timeout::FlaskSessionTimeoutRule;
use crate::rules::python::frameworks::http_blocking_async::PythonHttpBlockingInAsyncRule;
use crate::rules::python::frameworks::http_retry::PythonHttpMissingRetryRule;
use crate::rules::python::frameworks::http_timeout::PythonHttpMissingTimeoutRule;
use crate::rules::python::frameworks::pydantic::arbitrary_types::PydanticArbitraryTypesRule;
use crate::rules::python::frameworks::pydantic::missing_validators::PydanticMissingValidatorsRule;
use crate::rules::python::frameworks::redis::missing_ttl::RedisMissingTtlRule;
use crate::rules::python::frameworks::redis::unbounded_keys::RedisUnboundedKeysRule;
use crate::rules::python::frameworks::sqlalchemy::connection_pool::SqlAlchemyConnectionPoolRule;
use crate::rules::python::frameworks::sqlalchemy::lazy_loading::SqlAlchemyLazyLoadingRule;
use crate::rules::python::frameworks::sqlalchemy::pgvector_optimization::PgvectorOptimizationRule;
use crate::rules::python::frameworks::sqlalchemy::query_timeout::SqlAlchemyQueryTimeoutRule;
use crate::rules::python::frameworks::sqlalchemy::session_management::SqlAlchemySessionManagementRule;
use crate::rules::python::global_mutable_state::PythonGlobalMutableStateRule;
use crate::rules::python::graceful_shutdown::PythonMissingGracefulShutdownRule;
use crate::rules::python::grpc_no_deadline::PythonGrpcNoDeadlineRule;
use crate::rules::python::halstead_complexity::PythonHalsteadComplexityRule;
use crate::rules::python::idempotency_key::PythonMissingIdempotencyKeyRule;
use crate::rules::python::io_in_hot_path::PythonIoInHotPathRule;
use crate::rules::python::large_response_memory::PythonLargeResponseMemoryRule;
use crate::rules::python::missing_correlation_id::PythonMissingCorrelationIdRule;
use crate::rules::python::missing_structured_logging::PythonMissingStructuredLoggingRule;
use crate::rules::python::missing_tracing::PythonMissingTracingRule;
use crate::rules::python::n_plus_one_queries::PythonNPlusOneQueriesRule;
use crate::rules::python::naive_datetime::PythonNaiveDatetimeRule;
use crate::rules::python::race_condition::PythonRaceConditionRiskRule;
use crate::rules::python::recursive_no_base_case::PythonRecursiveNoBaseCaseRule;
use crate::rules::python::regex_compile::PythonRegexCompileRule;
use crate::rules::python::sql_injection::PythonSqlInjectionRule;
use crate::rules::python::sync_dns_lookup::PythonSyncDnsLookupRule;
use crate::rules::python::transaction_boundary::PythonMissingTransactionBoundaryRule;
use crate::rules::python::unbounded_cache::PythonUnboundedCacheRule;
use crate::rules::python::unbounded_concurrency::PythonUnboundedConcurrencyRule;
use crate::rules::python::unbounded_memory::PythonUnboundedMemoryOperationRule;
use crate::rules::python::unbounded_retry::PythonUnboundedRetryRule;
use crate::rules::python::uncancelled_tasks::PythonUncancelledTasksRule;
use crate::rules::python::unsafe_eval::PythonUnsafeEvalRule;

// TypeScript rules - Core
use crate::rules::typescript::TypescriptAsyncWithoutErrorHandlingRule;
use crate::rules::typescript::TypescriptBareCatchRule;
use crate::rules::typescript::TypescriptConsoleInProductionRule;
use crate::rules::typescript::TypescriptEmptyCatchRule;
use crate::rules::typescript::TypescriptGlobalMutableStateRule;
use crate::rules::typescript::TypescriptHardcodedSecretsRule;
use crate::rules::typescript::TypescriptHttpMissingTimeoutRule;
use crate::rules::typescript::TypescriptMissingCircuitBreakerRule;
use crate::rules::typescript::TypescriptMissingCorrelationIdRule;
use crate::rules::typescript::TypescriptMissingGracefulShutdownRule;
use crate::rules::typescript::TypescriptMissingNullCheckRule;
use crate::rules::typescript::TypescriptPromiseNoCatchRule;
use crate::rules::typescript::TypescriptSqlInjectionRule;
use crate::rules::typescript::TypescriptUnboundedConcurrencyRule;
use crate::rules::typescript::TypescriptUnsafeAnyRule;

// TypeScript rules - Additional
use crate::rules::typescript::TypescriptCpuInEventLoopRule;
use crate::rules::typescript::TypescriptGrpcNoDeadlineRule;
use crate::rules::typescript::TypescriptHttpMissingRetryRule;
use crate::rules::typescript::TypescriptLargeResponseMemoryRule;
use crate::rules::typescript::TypescriptMissingIdempotencyKeyRule;
use crate::rules::typescript::TypescriptMissingRateLimitingRule;
use crate::rules::typescript::TypescriptMissingStructuredLoggingRule;
use crate::rules::typescript::TypescriptMissingTracingRule;
use crate::rules::typescript::TypescriptNPlusOneQueriesRule;
use crate::rules::typescript::TypescriptNaiveDatetimeRule;
use crate::rules::typescript::TypescriptRaceConditionRule;
use crate::rules::typescript::TypescriptRegexCompileRule;
use crate::rules::typescript::TypescriptSyncDnsLookupRule;
use crate::rules::typescript::TypescriptTransactionBoundaryRule;
use crate::rules::typescript::TypescriptUnboundedCacheRule;
use crate::rules::typescript::TypescriptUnboundedMemoryRule;
use crate::rules::typescript::TypescriptUnboundedRetryRule;
use crate::rules::typescript::TypescriptUnsafeEvalRule;

// TypeScript rules - Maintainability
use crate::rules::typescript::TypescriptHalsteadComplexityRule;

// TypeScript framework rules
use crate::rules::typescript::frameworks::ExpressMissingErrorMiddlewareRule;
use crate::rules::typescript::frameworks::NextJsApiMissingErrorLoggingRule;

#[derive(Debug, Default, Clone)]
pub struct RuleRegistry {
    rules: Vec<Arc<dyn Rule>>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn register(&mut self, rule: Arc<dyn Rule>) {
        self.rules.push(rule);
    }

    pub fn all(&self) -> &[Arc<dyn Rule>] {
        &self.rules
    }

    /// Get a rule by ID.
    pub fn get(&self, id: &str) -> Option<Arc<dyn Rule>> {
        self.rules.iter().find(|r| r.id() == id).cloned()
    }

    /// Check if a rule exists.
    pub fn contains(&self, id: &str) -> bool {
        self.rules.iter().any(|r| r.id() == id)
    }

    /// Number of registered rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Create a new registry containing only rules with the given IDs.
    ///
    /// Rules not found are silently ignored.
    pub fn filter_by_ids(&self, ids: &[String]) -> Self {
        let id_set: HashSet<&str> = ids.iter().map(|s| s.as_str()).collect();
        let filtered_rules: Vec<Arc<dyn Rule>> = self
            .rules
            .iter()
            .filter(|r| id_set.contains(r.id()))
            .cloned()
            .collect();

        Self {
            rules: filtered_rules,
        }
    }

    /// Convenience factory to build a registry with built-in rules.
    pub fn with_builtin_rules() -> Self {
        let mut registry = RuleRegistry::new();

        // FastAPI rules
        registry.register(Arc::new(FastApiMissingCorsRule::new()));
        registry.register(Arc::new(FastApiExceptionHandlerRule::new()));
        registry.register(Arc::new(FastApiRequestTimeoutRule::new()));
        registry.register(Arc::new(FastApiHealthCheckRule::new()));
        registry.register(Arc::new(FastApiInputValidationRule::new()));

        // Python HTTP
        registry.register(Arc::new(PythonHttpMissingTimeoutRule::new()));
        registry.register(Arc::new(PythonHttpBlockingInAsyncRule::new()));
        registry.register(Arc::new(PythonHttpMissingRetryRule::new()));

        // Python async resource cleanup
        registry.register(Arc::new(PythonAsyncResourceCleanupRule::new()));

        // Python exception handling
        registry.register(Arc::new(PythonBareExceptRule::new()));

        // Python SQL injection
        registry.register(Arc::new(PythonSqlInjectionRule::new()));

        // Python datetime
        registry.register(Arc::new(PythonNaiveDatetimeRule::new()));

        // Python database timeout
        registry.register(Arc::new(PythonDbTimeoutRule::new()));

        // Phase 3 rules
        // B2: Global mutable state
        registry.register(Arc::new(PythonGlobalMutableStateRule::new()));

        // B3: Unbounded concurrency
        registry.register(Arc::new(PythonUnboundedConcurrencyRule::new()));

        // A6: Missing structured logging
        registry.register(Arc::new(PythonMissingStructuredLoggingRule::new()));

        // A7: Missing correlation ID
        registry.register(Arc::new(PythonMissingCorrelationIdRule::new()));

        // A12: Async tasks without error handling
        registry.register(Arc::new(PythonAsyncTaskNoErrorHandlingRule::new()));

        // B5: N+1 queries
        registry.register(Arc::new(PythonNPlusOneQueriesRule::new()));

        // B6: Unbounded caches
        registry.register(Arc::new(PythonUnboundedCacheRule::new()));

        // B9: Recursive without base case
        registry.register(Arc::new(PythonRecursiveNoBaseCaseRule::new()));

        // B11: CPU work in event loop
        registry.register(Arc::new(PythonCpuInEventLoopRule::new()));

        // B12: I/O in hot paths
        registry.register(Arc::new(PythonIoInHotPathRule::new()));

        // B15: Ephemeral filesystem writes
        registry.register(Arc::new(PythonEphemeralFilesystemWriteRule::new()));

        // B18: Sync DNS lookups
        registry.register(Arc::new(PythonSyncDnsLookupRule::new()));

        // B20: Code duplication
        registry.register(Arc::new(PythonCodeDuplicationRule::new()));

        // New Phase 1 rules
        // Circuit breaker for HTTP calls
        registry.register(Arc::new(PythonMissingCircuitBreakerRule::new()));

        // Graceful shutdown for FastAPI apps
        registry.register(Arc::new(PythonMissingGracefulShutdownRule::new()));

        // Transaction boundary for database operations
        registry.register(Arc::new(PythonMissingTransactionBoundaryRule::new()));

        // Race condition risk detection
        registry.register(Arc::new(PythonRaceConditionRiskRule::new()));

        // Unbounded memory operations
        registry.register(Arc::new(PythonUnboundedMemoryOperationRule::new()));

        // Idempotency key for state-changing operations
        registry.register(Arc::new(PythonMissingIdempotencyKeyRule::new()));

        // New Phase 2 rules
        // A5: Unbounded retry loops
        registry.register(Arc::new(PythonUnboundedRetryRule::new()));

        // A10: Missing tracing (OpenTelemetry)
        registry.register(Arc::new(PythonMissingTracingRule::new()));

        // A11: gRPC client without deadline
        registry.register(Arc::new(PythonGrpcNoDeadlineRule::new()));

        // B10: Large response bodies loaded into memory
        registry.register(Arc::new(PythonLargeResponseMemoryRule::new()));

        // B14: Unsafe eval/exec and dynamic code execution
        registry.register(Arc::new(PythonUnsafeEvalRule::new()));

        // FastAPI rate limiting
        registry.register(Arc::new(FastApiMissingRateLimitingRule::new()));

        // FastAPI request body size limits
        registry.register(Arc::new(FastApiRequestBodyUnboundedRule::new()));

        // Django rules
        registry.register(Arc::new(DjangoMissingCsrfRule::new()));
        registry.register(Arc::new(DjangoOrmSelectRelatedRule::new()));
        registry.register(Arc::new(DjangoAllowedHostsRule::new()));
        registry.register(Arc::new(DjangoSessionSettingsRule::new()));
        registry.register(Arc::new(DjangoSecureSettingsRule::new()));

        // Flask rules
        registry.register(Arc::new(FlaskHardcodedSecretKeyRule::new()));
        registry.register(Arc::new(FlaskSessionTimeoutRule::new()));
        registry.register(Arc::new(FlaskInsecureCookieSettingsRule::new()));

        // SQLAlchemy rules
        registry.register(Arc::new(SqlAlchemySessionManagementRule::new()));
        registry.register(Arc::new(SqlAlchemyLazyLoadingRule::new()));
        registry.register(Arc::new(SqlAlchemyConnectionPoolRule::new()));
        registry.register(Arc::new(SqlAlchemyQueryTimeoutRule::new()));
        registry.register(Arc::new(PgvectorOptimizationRule::new()));

        // Pydantic rules
        registry.register(Arc::new(PydanticArbitraryTypesRule::new()));
        registry.register(Arc::new(PydanticMissingValidatorsRule::new()));

        // Async rules
        registry.register(Arc::new(PythonAsyncioTimeoutRule::new()));
        registry.register(Arc::new(PythonUncancelledTasksRule::new()));

        // Redis/Cache rules
        registry.register(Arc::new(RedisMissingTtlRule::new()));
        registry.register(Arc::new(RedisUnboundedKeysRule::new()));

        // Python regex performance rule
        registry.register(Arc::new(PythonRegexCompileRule::new()));

        // Halstead complexity (Maintainability dimension)
        registry.register(Arc::new(PythonHalsteadComplexityRule::new()));

        // ==================== Go Rules ====================

        // Go core rules
        registry.register(Arc::new(GoUncheckedErrorRule::new()));
        registry.register(Arc::new(GoDeferInLoopRule::new()));
        registry.register(Arc::new(GoGoroutineLeakRule::new()));
        registry.register(Arc::new(GoContextBackgroundRule::new()));
        registry.register(Arc::new(GoHttpTimeoutRule::new()));
        registry.register(Arc::new(GoSqlInjectionRule::new()));
        registry.register(Arc::new(GoUnhandledErrorGoroutineRule::new()));
        registry.register(Arc::new(GoEmptyCriticalSectionRule::new()));

        // Go observability rules
        registry.register(Arc::new(GoMissingStructuredLoggingRule::new()));
        registry.register(Arc::new(GoMissingTracingRule::new()));
        registry.register(Arc::new(GoMissingCorrelationIdRule::new()));

        // Go resilience rules
        registry.register(Arc::new(GoUnboundedRetryRule::new()));
        registry.register(Arc::new(GoMissingCircuitBreakerRule::new()));
        registry.register(Arc::new(GoMissingGracefulShutdownRule::new()));

        // Go resilience rules (additional)
        registry.register(Arc::new(GoHttpRetryRule::new()));
        registry.register(Arc::new(GoRateLimitingRule::new()));

        // Go security rules
        registry.register(Arc::new(GoHardcodedSecretsRule::new()));
        registry.register(Arc::new(GoUnsafeTemplateRule::new()));

        // Go concurrency rules
        registry.register(Arc::new(GoUnboundedGoroutinesRule::new()));
        registry.register(Arc::new(GoRaceConditionRule::new()));
        registry.register(Arc::new(GoGlobalMutableStateRule::new()));
        registry.register(Arc::new(GoUncancelledContextRule::new()));
        registry.register(Arc::new(GoChannelNeverClosedRule::new()));
        registry.register(Arc::new(GoConcurrentMapAccessRule::new()));

        // Go core rules (additional)
        registry.register(Arc::new(GoBareRecoverRule::new()));

        // Go memory/performance rules
        registry.register(Arc::new(GoUnboundedMemoryRule::new()));
        registry.register(Arc::new(GoUnboundedCacheRule::new()));
        registry.register(Arc::new(GoLargeResponseMemoryRule::new()));
        registry.register(Arc::new(GoCpuInHotPathRule::new()));
        registry.register(Arc::new(GoSliceMemoryLeakRule::new()));
        registry.register(Arc::new(GoSliceAppendInLoopRule::new()));
        registry.register(Arc::new(GoMapWithoutSizeHintRule::new()));
        registry.register(Arc::new(GoReflectInHotPathRule::new()));

        // Go type safety rules
        registry.register(Arc::new(GoTypeAssertionNoOkRule::new()));

        // Go error handling rules
        registry.register(Arc::new(GoSentinelErrorComparisonRule::new()));
        registry.register(Arc::new(GoErrorTypeAssertionRule::new()));
        registry.register(Arc::new(GoPanicInLibraryRule::new()));

        // Go data/storage rules
        registry.register(Arc::new(GoTransactionBoundaryRule::new()));
        registry.register(Arc::new(GoIdempotencyKeyRule::new()));
        registry.register(Arc::new(GoEphemeralFilesystemWriteRule::new()));

        // Go network rules
        registry.register(Arc::new(GoSyncDnsLookupRule::new()));

        // Go regex performance rule
        registry.register(Arc::new(GoRegexCompileRule::new()));

        // Go Halstead complexity (Maintainability dimension)
        registry.register(Arc::new(GoHalsteadComplexityRule::new()));

        // Go net/http rules
        registry.register(Arc::new(NetHttpServerTimeoutRule::new()));
        registry.register(Arc::new(NetHttpHandlerTimeoutRule::new()));

        // Go Gin framework rules
        registry.register(Arc::new(GinMissingValidationRule::new()));
        registry.register(Arc::new(GinUntrustedInputRule::new()));

        // Go Echo framework rules
        registry.register(Arc::new(EchoMissingMiddlewareRule::new()));
        registry.register(Arc::new(EchoRequestValidationRule::new()));

        // Go GORM framework rules
        registry.register(Arc::new(GormConnectionPoolRule::new()));
        registry.register(Arc::new(GormNPlusOneRule::new()));
        registry.register(Arc::new(GormQueryTimeoutRule::new()));
        registry.register(Arc::new(GormSessionManagementRule::new()));

        // Go gRPC framework rules
        registry.register(Arc::new(GrpcMissingDeadlineRule::new()));

        // Go Redis rules
        registry.register(Arc::new(GoRedisMissingTtlRule::new()));
        registry.register(Arc::new(GoRedisConnectionPoolRule::new()));

        // ==================== Rust Rules ====================

        // Rust error handling rules
        registry.register(Arc::new(RustUnsafeUnwrapRule::new()));
        registry.register(Arc::new(RustPanicInLibraryRule::new()));
        registry.register(Arc::new(RustIgnoredResultRule::new()));

        // Rust async/concurrency rules
        registry.register(Arc::new(RustBlockingInAsyncRule::new()));
        registry.register(Arc::new(RustSpawnNoErrorHandlingRule::new()));
        registry.register(Arc::new(RustUnboundedChannelRule::new()));
        registry.register(Arc::new(RustMissingSelectTimeoutRule::new()));
        registry.register(Arc::new(RustArcMutexContentionRule::new()));
        registry.register(Arc::new(RustMissingAsyncTimeoutRule::new()));
        registry.register(Arc::new(RustCpuInAsyncRule::new()));
        registry.register(Arc::new(RustUnboundedConcurrencyRule::new()));
        registry.register(Arc::new(RustUncancelledTasksRule::new()));

        // Rust safety/security rules
        registry.register(Arc::new(RustUnsafeBlockUnauditedRule::new()));
        registry.register(Arc::new(RustHardcodedSecretsRule::new()));
        registry.register(Arc::new(RustSqlInjectionRule::new()));

        // Rust regex performance rule
        registry.register(Arc::new(RustRegexCompileRule::new()));

        // Rust observability rules
        registry.register(Arc::new(RustPrintlnInLibRule::new()));
        registry.register(Arc::new(RustMissingTracingRule::new()));
        registry.register(Arc::new(RustMissingStructuredLoggingRule::new()));

        // Rust performance rules
        registry.register(Arc::new(RustCloneInLoopRule::new()));
        registry.register(Arc::new(RustIoInHotPathRule::new()));
        registry.register(Arc::new(RustNPlusOneRule::new()));
        registry.register(Arc::new(RustUnboundedMemoryRule::new()));
        registry.register(Arc::new(RustSyncDnsLookupRule::new()));
        registry.register(Arc::new(RustUnboundedRecursionRule::new()));

        // Rust datetime rules
        registry.register(Arc::new(RustNaiveDatetimeRule::new()));

        // Rust framework rules - Axum
        registry.register(Arc::new(AxumMissingErrorHandlerRule::new()));
        registry.register(Arc::new(AxumMissingCorsRule::new()));
        registry.register(Arc::new(AxumMissingTimeoutRule::new()));

        // Rust framework rules - Tokio
        registry.register(Arc::new(TokioMissingGracefulShutdownRule::new()));
        registry.register(Arc::new(TokioMissingRuntimeConfigRule::new()));

        // Rust framework rules - SQLx
        registry.register(Arc::new(SqlxMissingPoolTimeoutRule::new()));
        registry.register(Arc::new(SqlxMissingTransactionRule::new()));
        registry.register(Arc::new(SqlxQueryWithoutTimeoutRule::new()));

        // Rust resilience rules
        registry.register(Arc::new(RustMissingCircuitBreakerRule::new()));
        registry.register(Arc::new(RustUnboundedRetryRule::new()));

        // Rust observability rules (additional)
        registry.register(Arc::new(RustMissingCorrelationIdRule::new()));

        // Rust memory rules
        registry.register(Arc::new(RustUnboundedCacheRule::new()));
        registry.register(Arc::new(RustLargeResponseMemoryRule::new()));

        // Rust concurrency rules (additional)
        registry.register(Arc::new(RustGlobalMutableStateRule::new()));

        // Rust data/storage rules
        registry.register(Arc::new(RustMissingIdempotencyKeyRule::new()));
        registry.register(Arc::new(RustEphemeralFilesystemWriteRule::new()));

        // Rust network rules
        registry.register(Arc::new(RustGrpcNoDeadlineRule::new()));

        // Rust Halstead complexity (Maintainability dimension)
        registry.register(Arc::new(RustHalsteadComplexityRule::new()));

        // ==================== TypeScript Rules ====================

        // TypeScript core rules
        registry.register(Arc::new(TypescriptEmptyCatchRule::new()));
        registry.register(Arc::new(TypescriptGlobalMutableStateRule::new()));
        registry.register(Arc::new(TypescriptHttpMissingTimeoutRule::new()));
        registry.register(Arc::new(TypescriptAsyncWithoutErrorHandlingRule::new()));
        registry.register(Arc::new(TypescriptUnsafeAnyRule::new()));
        registry.register(Arc::new(TypescriptMissingNullCheckRule::new()));
        registry.register(Arc::new(TypescriptBareCatchRule::new()));
        registry.register(Arc::new(TypescriptUnboundedConcurrencyRule::new()));
        registry.register(Arc::new(TypescriptConsoleInProductionRule::new()));
        registry.register(Arc::new(TypescriptHardcodedSecretsRule::new()));
        registry.register(Arc::new(TypescriptPromiseNoCatchRule::new()));

        // TypeScript security rules
        registry.register(Arc::new(TypescriptSqlInjectionRule::new()));

        // TypeScript resilience rules
        registry.register(Arc::new(TypescriptMissingCircuitBreakerRule::new()));
        registry.register(Arc::new(TypescriptMissingGracefulShutdownRule::new()));
        registry.register(Arc::new(TypescriptUnboundedRetryRule::new()));

        // TypeScript observability rules
        registry.register(Arc::new(TypescriptMissingCorrelationIdRule::new()));
        registry.register(Arc::new(TypescriptMissingStructuredLoggingRule::new()));
        registry.register(Arc::new(TypescriptMissingTracingRule::new()));

        // TypeScript performance/memory rules
        registry.register(Arc::new(TypescriptUnboundedCacheRule::new()));
        registry.register(Arc::new(TypescriptCpuInEventLoopRule::new()));
        registry.register(Arc::new(TypescriptLargeResponseMemoryRule::new()));

        // TypeScript datetime rules
        registry.register(Arc::new(TypescriptNaiveDatetimeRule::new()));

        // TypeScript data/storage rules
        registry.register(Arc::new(TypescriptMissingIdempotencyKeyRule::new()));
        registry.register(Arc::new(TypescriptTransactionBoundaryRule::new()));
        registry.register(Arc::new(TypescriptNPlusOneQueriesRule::new()));

        // TypeScript memory rules
        registry.register(Arc::new(TypescriptUnboundedMemoryRule::new()));

        // TypeScript concurrency rules
        registry.register(Arc::new(TypescriptRaceConditionRule::new()));

        // TypeScript network rules
        registry.register(Arc::new(TypescriptSyncDnsLookupRule::new()));
        registry.register(Arc::new(TypescriptGrpcNoDeadlineRule::new()));

        // TypeScript security rules (additional)
        registry.register(Arc::new(TypescriptUnsafeEvalRule::new()));
        registry.register(Arc::new(TypescriptMissingRateLimitingRule::new()));

        // TypeScript resilience rules (additional)
        registry.register(Arc::new(TypescriptHttpMissingRetryRule::new()));

        // TypeScript framework rules - Express.js
        registry.register(Arc::new(ExpressMissingErrorMiddlewareRule::new()));

        // TypeScript framework rules - Next.js
        registry.register(Arc::new(NextJsApiMissingErrorLoggingRule::new()));

        // TypeScript regex performance rule
        registry.register(Arc::new(TypescriptRegexCompileRule::new()));

        // TypeScript Halstead complexity (Maintainability dimension)
        registry.register(Arc::new(TypescriptHalsteadComplexityRule::new()));

        registry
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::CodeGraph;
    use crate::parse::ast::FileId;
    use crate::rules::finding::RuleFinding;
    use crate::semantics::SourceSemantics;
    use async_trait::async_trait;

    // ==================== Mock Rule for Testing ====================

    #[derive(Debug)]
    struct TestRule {
        id: &'static str,
        name: &'static str,
    }

    impl TestRule {
        fn new(id: &'static str, name: &'static str) -> Self {
            Self { id, name }
        }
    }

    #[async_trait]
    impl Rule for TestRule {
        fn id(&self) -> &'static str {
            self.id
        }

        fn name(&self) -> &'static str {
            self.name
        }

        async fn evaluate(
            &self,
            _semantics: &[(FileId, Arc<SourceSemantics>)],
            _graph: Option<&CodeGraph>,
        ) -> Vec<RuleFinding> {
            vec![]
        }
    }

    // ==================== RuleRegistry::new Tests ====================

    #[test]
    fn new_creates_empty_registry() {
        let registry = RuleRegistry::new();
        assert!(registry.all().is_empty());
    }

    #[test]
    fn new_registry_has_zero_rules() {
        let registry = RuleRegistry::new();
        assert_eq!(registry.all().len(), 0);
    }

    // ==================== RuleRegistry::default Tests ====================

    #[test]
    fn default_creates_empty_registry() {
        let registry = RuleRegistry::default();
        assert!(registry.all().is_empty());
    }

    #[test]
    fn default_is_equivalent_to_new() {
        let new_registry = RuleRegistry::new();
        let default_registry = RuleRegistry::default();
        assert_eq!(new_registry.all().len(), default_registry.all().len());
    }

    // ==================== RuleRegistry::register Tests ====================

    #[test]
    fn register_adds_single_rule() {
        let mut registry = RuleRegistry::new();
        let rule = Arc::new(TestRule::new("test.rule", "Test Rule"));

        registry.register(rule);

        assert_eq!(registry.all().len(), 1);
    }

    #[test]
    fn register_adds_multiple_rules() {
        let mut registry = RuleRegistry::new();

        registry.register(Arc::new(TestRule::new("rule.one", "Rule One")));
        registry.register(Arc::new(TestRule::new("rule.two", "Rule Two")));
        registry.register(Arc::new(TestRule::new("rule.three", "Rule Three")));

        assert_eq!(registry.all().len(), 3);
    }

    #[test]
    fn register_preserves_order() {
        let mut registry = RuleRegistry::new();

        registry.register(Arc::new(TestRule::new("first", "First")));
        registry.register(Arc::new(TestRule::new("second", "Second")));
        registry.register(Arc::new(TestRule::new("third", "Third")));

        let rules = registry.all();
        assert_eq!(rules[0].id(), "first");
        assert_eq!(rules[1].id(), "second");
        assert_eq!(rules[2].id(), "third");
    }

    #[test]
    fn register_allows_duplicate_rule_ids() {
        let mut registry = RuleRegistry::new();

        registry.register(Arc::new(TestRule::new("same.id", "Rule One")));
        registry.register(Arc::new(TestRule::new("same.id", "Rule Two")));

        // Both rules are registered even with same ID
        assert_eq!(registry.all().len(), 2);
    }

    // ==================== RuleRegistry::all Tests ====================

    #[test]
    fn all_returns_empty_slice_for_empty_registry() {
        let registry = RuleRegistry::new();
        let rules = registry.all();
        assert!(rules.is_empty());
    }

    #[test]
    fn all_returns_all_registered_rules() {
        let mut registry = RuleRegistry::new();

        registry.register(Arc::new(TestRule::new("rule.a", "Rule A")));
        registry.register(Arc::new(TestRule::new("rule.b", "Rule B")));

        let rules = registry.all();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn all_returns_rules_with_correct_ids() {
        let mut registry = RuleRegistry::new();

        registry.register(Arc::new(TestRule::new("test.id.one", "Test One")));
        registry.register(Arc::new(TestRule::new("test.id.two", "Test Two")));

        let rules = registry.all();
        let ids: Vec<&str> = rules.iter().map(|r| r.id()).collect();

        assert!(ids.contains(&"test.id.one"));
        assert!(ids.contains(&"test.id.two"));
    }

    #[test]
    fn all_returns_rules_with_correct_names() {
        let mut registry = RuleRegistry::new();

        registry.register(Arc::new(TestRule::new("rule.1", "First Rule Name")));
        registry.register(Arc::new(TestRule::new("rule.2", "Second Rule Name")));

        let rules = registry.all();
        let names: Vec<&str> = rules.iter().map(|r| r.name()).collect();

        assert!(names.contains(&"First Rule Name"));
        assert!(names.contains(&"Second Rule Name"));
    }

    // ==================== RuleRegistry::with_builtin_rules Tests ====================

    #[test]
    fn with_builtin_rules_creates_non_empty_registry() {
        let registry = RuleRegistry::with_builtin_rules();
        assert!(!registry.all().is_empty());
    }

    #[test]
    fn with_builtin_rules_contains_fastapi_cors_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_cors_rule = rules.iter().any(|r| r.id() == "fastapi.missing_cors");
        assert!(has_cors_rule, "Registry should contain FastAPI CORS rule");
    }

    #[test]
    fn with_builtin_rules_contains_http_timeout_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_timeout_rule = rules
            .iter()
            .any(|r| r.id() == "python.http.missing_timeout");
        assert!(
            has_timeout_rule,
            "Registry should contain HTTP timeout rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_http_blocking_async_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_blocking_rule = rules
            .iter()
            .any(|r| r.id() == "python.http.blocking_in_async");
        assert!(
            has_blocking_rule,
            "Registry should contain HTTP blocking in async rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_bare_except_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_bare_except_rule = rules.iter().any(|r| r.id() == "python.bare_except");
        assert!(
            has_bare_except_rule,
            "Registry should contain bare except rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_expected_rule_count() {
        let registry = RuleRegistry::with_builtin_rules();
        // 60 Python rules + 56 Go rules + 45 Rust rules + 35 TypeScript rules = 196
        assert_eq!(registry.all().len(), 196);
    }

    #[test]
    fn with_builtin_rules_contains_go_unchecked_error_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_rule = rules.iter().any(|r| r.id() == "go.unchecked_error");
        assert!(has_rule, "Registry should contain Go unchecked error rule");
    }

    #[test]
    fn with_builtin_rules_contains_go_defer_in_loop_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_rule = rules.iter().any(|r| r.id() == "go.defer_in_loop");
        assert!(has_rule, "Registry should contain Go defer in loop rule");
    }

    #[test]
    fn with_builtin_rules_contains_go_http_timeout_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_rule = rules.iter().any(|r| r.id() == "go.http_missing_timeout");
        assert!(has_rule, "Registry should contain Go HTTP timeout rule");
    }

    #[test]
    fn with_builtin_rules_contains_go_sql_injection_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_rule = rules.iter().any(|r| r.id() == "go.sql_injection");
        assert!(has_rule, "Registry should contain Go SQL injection rule");
    }

    #[test]
    fn with_builtin_rules_contains_db_timeout_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_db_timeout_rule = rules.iter().any(|r| r.id() == "python.db.missing_timeout");
        assert!(
            has_db_timeout_rule,
            "Registry should contain database timeout rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_fastapi_input_validation_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_input_validation_rule = rules
            .iter()
            .any(|r| r.id() == "python.fastapi.missing_input_validation");
        assert!(
            has_input_validation_rule,
            "Registry should contain FastAPI input validation rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_async_resource_cleanup_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_async_cleanup_rule = rules
            .iter()
            .any(|r| r.id() == "python.async_resource_cleanup");
        assert!(
            has_async_cleanup_rule,
            "Registry should contain async resource cleanup rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_fastapi_health_check_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_health_check_rule = rules
            .iter()
            .any(|r| r.id() == "python.fastapi.missing_health_check");
        assert!(
            has_health_check_rule,
            "Registry should contain FastAPI health check rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_fastapi_request_timeout_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_request_timeout_rule = rules
            .iter()
            .any(|r| r.id() == "python.fastapi.missing_request_timeout");
        assert!(
            has_request_timeout_rule,
            "Registry should contain FastAPI request timeout rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_sql_injection_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_sql_injection_rule = rules.iter().any(|r| r.id() == "python.sql_injection");
        assert!(
            has_sql_injection_rule,
            "Registry should contain SQL injection rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_naive_datetime_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_naive_datetime_rule = rules.iter().any(|r| r.id() == "python.naive_datetime");
        assert!(
            has_naive_datetime_rule,
            "Registry should contain naive datetime rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_http_retry_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_retry_rule = rules.iter().any(|r| r.id() == "python.http.missing_retry");
        assert!(
            has_retry_rule,
            "Registry should contain HTTP missing retry rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_fastapi_exception_handler_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_exception_handler_rule = rules
            .iter()
            .any(|r| r.id() == "python.fastapi.missing_exception_handler");
        assert!(
            has_exception_handler_rule,
            "Registry should contain FastAPI exception handler rule"
        );
    }

    #[test]
    fn with_builtin_rules_contains_pgvector_optimization_rule() {
        let registry = RuleRegistry::with_builtin_rules();
        let rules = registry.all();

        let has_pgvector_rule = rules
            .iter()
            .any(|r| r.id() == "python.sqlalchemy.pgvector_suboptimal_query");
        assert!(
            has_pgvector_rule,
            "Registry should contain pgvector optimization rule"
        );
    }

    #[test]
    fn with_builtin_rules_all_rules_have_non_empty_ids() {
        let registry = RuleRegistry::with_builtin_rules();

        for rule in registry.all() {
            assert!(!rule.id().is_empty(), "Rule ID should not be empty");
        }
    }

    #[test]
    fn with_builtin_rules_all_rules_have_non_empty_names() {
        let registry = RuleRegistry::with_builtin_rules();

        for rule in registry.all() {
            assert!(!rule.name().is_empty(), "Rule name should not be empty");
        }
    }

    // ==================== Debug Trait Tests ====================

    #[test]
    fn registry_implements_debug() {
        let registry = RuleRegistry::new();
        let debug_str = format!("{:?}", registry);
        assert!(debug_str.contains("RuleRegistry"));
    }

    #[test]
    fn registry_with_rules_implements_debug() {
        let mut registry = RuleRegistry::new();
        registry.register(Arc::new(TestRule::new("test", "Test")));

        let debug_str = format!("{:?}", registry);
        assert!(debug_str.contains("RuleRegistry"));
    }

    // ==================== Integration Tests ====================

    #[test]
    fn can_add_rules_after_builtin() {
        let mut registry = RuleRegistry::with_builtin_rules();
        let initial_count = registry.all().len();

        registry.register(Arc::new(TestRule::new("custom.rule", "Custom Rule")));

        assert_eq!(registry.all().len(), initial_count + 1);
    }

    #[test]
    fn builtin_rules_are_accessible_via_all() {
        let registry = RuleRegistry::with_builtin_rules();

        for rule in registry.all() {
            // Each rule should be accessible and have valid id/name
            let _ = rule.id();
            let _ = rule.name();
        }
    }

    #[tokio::test]
    async fn builtin_rules_can_be_evaluated() {
        let registry = RuleRegistry::with_builtin_rules();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        for rule in registry.all() {
            // Each rule should be callable without panicking
            let _ = rule.evaluate(&semantics, None).await;
        }
    }
}
