//! Built-in profile definitions.
//!
//! This module contains the default profiles that ship with Unfault.

use crate::profiles::ProfileRegistry;
use crate::types::context::{Dimension, Framework, Language};
use crate::types::profile::{FilePredicate, FileQueryHint, Profile};

/// Register all built-in profiles with the registry.
pub fn register_builtin_profiles(registry: &mut ProfileRegistry) {
    // Python profiles
    registry.register(python_fastapi_backend());
    registry.register(python_django_backend());
    registry.register(python_flask_backend());
    registry.register(python_generic_backend());

    // Go profiles
    registry.register(go_gin_service());
    registry.register(go_generic_service());

    // Rust profiles
    registry.register(rust_axum_service());
    registry.register(rust_actix_service());

    // TypeScript/JavaScript profiles
    registry.register(typescript_express_backend());
    registry.register(typescript_nextjs_app());

    // LSP profiles (reduced rule sets for single-file analysis)
    registry.register(python_lsp());
    registry.register(go_lsp());
    registry.register(rust_lsp());
    registry.register(typescript_lsp());

    // Maintainability profiles (opt-in, for complexity analysis)
    registry.register(python_maintainability());
    registry.register(go_maintainability());
    registry.register(rust_maintainability());
    registry.register(typescript_maintainability());
}

// ==================== Python Profiles ====================

/// Python FastAPI backend profile.
fn python_fastapi_backend() -> Profile {
    Profile::new("python_fastapi_backend", "Python FastAPI backend")
        .with_language(Language::Python)
        .with_framework(Framework::FastAPI)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Performance)
        .with_dimension(Dimension::Scalability)
        .with_dimension(Dimension::Observability)
        .with_rules([
            "fastapi.missing_cors",
            "python.fastapi.missing_exception_handler",
            "python.fastapi.missing_request_timeout",
            "python.fastapi.missing_health_check",
            "python.fastapi.missing_input_validation",
            "python.fastapi.missing_rate_limiting",
            "python.fastapi.request_body_unbounded",
            "python.http.missing_timeout",
            "python.http.missing_retry",
            "python.http.blocking_in_async",
            "python.async_resource_cleanup",
            "python.bare_except",
            "python.sql_injection",
            "python.naive_datetime",
            "python.db.missing_timeout",
            // Phase 3 rules
            "python.global_mutable_state",
            "python.unbounded_concurrency",
            "python.missing_structured_logging",
            "python.missing_correlation_id",
            "python.async_task_no_error_handling",
            // Phase 4 rules
            "python.n_plus_one_queries",
            "python.unbounded_cache",
            "python.recursive_no_base_case",
            "python.cpu_in_event_loop",
            "python.io_in_hot_path",
            "python.ephemeral_filesystem_write",
            "python.sync_dns_lookup",
            "python.code_duplication",
            "python.regex_compile",
            // Resilience & stability rules
            "python.resilience.missing_circuit_breaker",
            "python.graceful_shutdown",
            "python.unbounded_retry",
            "python.unbounded_memory",
            "python.large_response_memory",
            "python.idempotency_key",
            "python.race_condition",
            // SQLAlchemy/database rules
            "python.sqlalchemy.pgvector_suboptimal_query",
        ])
        .with_file_hint(
            FileQueryHint::new("fastapi_entrypoints")
                .with_label("FastAPI entrypoints")
                .with_max_files(8)
                .include(FilePredicate::path_glob("**/main.py"))
                .include(FilePredicate::path_glob("**/app.py"))
                .include(FilePredicate::path_glob("**/application.py")),
        )
        .with_file_hint(
            FileQueryHint::new("fastapi_routers")
                .with_label("FastAPI routers")
                .with_max_files(32)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "from fastapi import",
                    "from fastapi.routing import",
                    "APIRouter",
                ])),
        )
        .with_file_hint(
            FileQueryHint::new("python_http_clients")
                .with_label("Python HTTP clients")
                .with_max_files(64)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "requests.",
                    "httpx.",
                    "aiohttp.",
                    "urllib.request",
                ])),
        )
        // Cross-file support: logging modules for missing_structured_logging rule
        .with_file_hint(
            FileQueryHint::new("python_logging_modules")
                .with_label("Python logging modules")
                .with_max_files(16)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "import structlog",
                    "from loguru",
                ])),
        )
        // Cross-file support: middleware for correlation_id, circuit_breaker rules
        .with_file_hint(
            FileQueryHint::new("python_middleware")
                .with_label("Python middleware")
                .with_max_files(16)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "Middleware",
                    "BaseHTTPMiddleware",
                    "@app.middleware",
                    "correlation_id",
                    "request_id",
                    "X-Request-ID",
                    "X-Correlation-ID",
                ])),
        )
        // Cross-file support: resilience patterns for circuit_breaker, retry rules
        .with_file_hint(
            FileQueryHint::new("python_resilience")
                .with_label("Python resilience patterns")
                .with_max_files(16)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "circuit_breaker",
                    "CircuitBreaker",
                    "pybreaker",
                    "tenacity",
                    "@retry",
                    "backoff",
                    "resilience",
                ])),
        )
        // Cross-file support: config files for app-wide settings
        .with_file_hint(
            FileQueryHint::new("python_config")
                .with_label("Python configuration")
                .with_max_files(8)
                .include(FilePredicate::path_glob("**/config.py"))
                .include(FilePredicate::path_glob("**/settings.py"))
                .include(FilePredicate::path_glob("**/conf.py"))
                .include(FilePredicate::path_glob("**/config/*.py")),
        )
}

/// Python Django backend profile.
fn python_django_backend() -> Profile {
    Profile::new("python_django_backend", "Python Django backend")
        .with_language(Language::Python)
        .with_framework(Framework::Django)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Performance)
        .with_dimension(Dimension::Observability)
        .with_rules([
            "python.http.missing_timeout",
            "python.http.missing_retry",
            "python.http.blocking_in_async",
            "python.bare_except",
            "python.sql_injection",
            "python.naive_datetime",
            "python.db.missing_timeout",
            // Phase 3 rules
            "python.global_mutable_state",
            "python.missing_structured_logging",
            // Phase 4 rules
            "python.n_plus_one_queries",
            "python.unbounded_cache",
            "python.cpu_in_event_loop",
            "python.io_in_hot_path",
            "python.regex_compile",
        ])
        .with_file_hint(
            FileQueryHint::new("django_settings")
                .with_label("Django settings")
                .with_max_files(4)
                .include(FilePredicate::path_glob("**/settings.py"))
                .include(FilePredicate::path_glob("**/settings/*.py")),
        )
        .with_file_hint(
            FileQueryHint::new("django_views")
                .with_label("Django views")
                .with_max_files(32)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "from django.views",
                    "from django.http",
                    "from rest_framework",
                ])),
        )
        .with_file_hint(
            FileQueryHint::new("python_http_clients")
                .with_label("Python HTTP clients")
                .with_max_files(64)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "requests.",
                    "httpx.",
                    "aiohttp.",
                    "urllib.request",
                ])),
        )
        // Cross-file support: logging modules
        .with_file_hint(
            FileQueryHint::new("python_logging_modules")
                .with_label("Python logging modules")
                .with_max_files(16)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "import structlog",
                    "from loguru",
                ])),
        )
        // Cross-file support: Django middleware
        .with_file_hint(
            FileQueryHint::new("django_middleware")
                .with_label("Django middleware")
                .with_max_files(16)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "MiddlewareMixin",
                    "MIDDLEWARE",
                    "process_request",
                    "process_response",
                    "correlation_id",
                ])),
        )
}

/// Python Flask backend profile.
fn python_flask_backend() -> Profile {
    Profile::new("python_flask_backend", "Python Flask backend")
        .with_language(Language::Python)
        .with_framework(Framework::Flask)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Observability)
        .with_rules([
            "python.http.missing_timeout",
            "python.http.missing_retry",
            "python.bare_except",
            "python.sql_injection",
            "python.naive_datetime",
            "python.db.missing_timeout",
            // Phase 3 rules
            "python.global_mutable_state",
            "python.missing_structured_logging",
            "python.regex_compile",
        ])
        .with_file_hint(
            FileQueryHint::new("flask_app")
                .with_label("Flask application")
                .with_max_files(8)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "from flask import Flask",
                    "Flask(__name__)",
                ])),
        )
        .with_file_hint(
            FileQueryHint::new("python_http_clients")
                .with_label("Python HTTP clients")
                .with_max_files(64)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "requests.",
                    "httpx.",
                    "urllib.request",
                ])),
        )
        // Cross-file support: logging modules
        .with_file_hint(
            FileQueryHint::new("python_logging_modules")
                .with_label("Python logging modules")
                .with_max_files(16)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "import structlog",
                    "from loguru",
                ])),
        )
}

/// Generic Python backend profile.
fn python_generic_backend() -> Profile {
    Profile::new("python_generic_backend", "Python generic backend")
        .with_language(Language::Python)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Observability)
        .with_rules([
            "python.http.missing_timeout",
            "python.http.missing_retry",
            "python.bare_except",
            "python.sql_injection",
            "python.naive_datetime",
            "python.db.missing_timeout",
            // Phase 3 rules
            "python.global_mutable_state",
            "python.missing_structured_logging",
            "python.async_task_no_error_handling",
            "python.regex_compile",
        ])
        .with_file_hint(
            FileQueryHint::new("python_entrypoints")
                .with_label("Python entrypoints")
                .with_max_files(8)
                .include(FilePredicate::path_glob("**/main.py"))
                .include(FilePredicate::path_glob("**/app.py"))
                .include(FilePredicate::path_glob("**/run.py")),
        )
        .with_file_hint(
            FileQueryHint::new("python_http_clients")
                .with_label("Python HTTP clients")
                .with_max_files(64)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "requests.",
                    "httpx.",
                    "aiohttp.",
                    "urllib.request",
                ])),
        )
        // Cross-file support: logging modules
        .with_file_hint(
            FileQueryHint::new("python_logging_modules")
                .with_label("Python logging modules")
                .with_max_files(16)
                .include(FilePredicate::language("python"))
                .include(FilePredicate::text_contains_any([
                    "import structlog",
                    "from loguru",
                ])),
        )
}

// ==================== Go Profiles ====================

/// Go Gin service profile.
fn go_gin_service() -> Profile {
    Profile::new("go_gin_service", "Go Gin service")
        .with_language(Language::Go)
        .with_framework(Framework::Gin)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Performance)
        .with_dimension(Dimension::Security)
        .with_dimension(Dimension::Observability)
        .with_rules([
            // Core rules
            "go.http_missing_timeout",
            "go.unchecked_error",
            "go.sql_injection",
            "go.goroutine_leak",
            "go.defer_in_loop",
            "go.context_background",
            "go.bare_recover",
            // Resilience rules
            "go.unbounded_retry",
            "go.missing_circuit_breaker",
            "go.graceful_shutdown",
            "go.http_retry",
            // Observability rules
            "go.missing_structured_logging",
            "go.missing_correlation_id",
            // Concurrency rules
            "go.unbounded_goroutines",
            "go.race_condition",
            "go.global_mutable_state",
            "go.uncancelled_context",
            // Memory rules
            "go.unbounded_memory",
            "go.large_response_memory",
            // Security rules
            "go.hardcoded_secrets",
            "go.unsafe_template",
            // Performance
            "go.regex_compile",
            // Type safety
            "go.type_assertion_no_ok",
            // Gin-specific rules
            "go.gin.missing_validation",
            "go.gin.untrusted_input",
        ])
        .with_file_hint(
            FileQueryHint::new("go_entrypoints")
                .with_label("Go entrypoints")
                .with_max_files(8)
                .include(FilePredicate::path_glob("**/main.go"))
                .include(FilePredicate::path_glob("cmd/**/*.go")),
        )
        .with_file_hint(
            FileQueryHint::new("gin_handlers")
                .with_label("Gin handlers")
                .with_max_files(32)
                .include(FilePredicate::language("go"))
                .include(FilePredicate::text_contains_any([
                    "gin.Context",
                    "gin.Engine",
                    "gin.RouterGroup",
                ])),
        )
        // Cross-file support: logging modules for missing_structured_logging rule
        .with_file_hint(
            FileQueryHint::new("go_logging_modules")
                .with_label("Go logging modules")
                .with_max_files(16)
                .include(FilePredicate::language("go"))
                .include(FilePredicate::text_contains_any([
                    "log.Logger",
                    "logrus.",
                    "zap.",
                    "zerolog.",
                    "slog.",
                    "log.New(",
                    "logging.",
                ])),
        )
        // Cross-file support: middleware for correlation_id rule
        .with_file_hint(
            FileQueryHint::new("go_middleware")
                .with_label("Go middleware")
                .with_max_files(16)
                .include(FilePredicate::language("go"))
                .include(FilePredicate::text_contains_any([
                    "middleware",
                    "Middleware",
                    "HandlerFunc",
                    "correlation",
                    "request_id",
                    "RequestID",
                    "X-Request-ID",
                    "X-Correlation-ID",
                ])),
        )
        // Cross-file support: resilience patterns for circuit_breaker rule
        .with_file_hint(
            FileQueryHint::new("go_resilience")
                .with_label("Go resilience patterns")
                .with_max_files(16)
                .include(FilePredicate::language("go"))
                .include(FilePredicate::text_contains_any([
                    "circuit",
                    "Circuit",
                    "breaker",
                    "Breaker",
                    "hystrix",
                    "gobreaker",
                    "resilience",
                ])),
        )
        // Cross-file support: config files
        .with_file_hint(
            FileQueryHint::new("go_config")
                .with_label("Go configuration")
                .with_max_files(8)
                .include(FilePredicate::path_glob("**/config.go"))
                .include(FilePredicate::path_glob("**/config/*.go"))
                .include(FilePredicate::path_glob("internal/config/*.go")),
        )
}

/// Generic Go service profile.
fn go_generic_service() -> Profile {
    Profile::new("go_generic_service", "Go generic service")
        .with_language(Language::Go)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Performance)
        .with_dimension(Dimension::Observability)
        .with_rules([
            // Core rules
            "go.http_missing_timeout",
            "go.unchecked_error",
            "go.sql_injection",
            "go.goroutine_leak",
            "go.defer_in_loop",
            "go.context_background",
            "go.bare_recover",
            // Resilience rules
            "go.unbounded_retry",
            "go.missing_circuit_breaker",
            "go.graceful_shutdown",
            "go.http_retry",
            // Observability rules
            "go.missing_structured_logging",
            "go.missing_correlation_id",
            // Concurrency rules
            "go.unbounded_goroutines",
            "go.race_condition",
            "go.global_mutable_state",
            "go.uncancelled_context",
            // Memory rules
            "go.unbounded_memory",
            "go.large_response_memory",
            // Security rules
            "go.hardcoded_secrets",
            // Performance
            "go.regex_compile",
            // Type safety
            "go.type_assertion_no_ok",
        ])
        .with_file_hint(
            FileQueryHint::new("go_entrypoints")
                .with_label("Go entrypoints")
                .with_max_files(8)
                .include(FilePredicate::path_glob("**/main.go"))
                .include(FilePredicate::path_glob("cmd/**/*.go")),
        )
        .with_file_hint(
            FileQueryHint::new("go_http_handlers")
                .with_label("Go HTTP handlers")
                .with_max_files(32)
                .include(FilePredicate::language("go"))
                .include(FilePredicate::text_contains_any([
                    "http.Handler",
                    "http.HandlerFunc",
                    "http.ServeMux",
                ])),
        )
        // Cross-file support: logging modules
        .with_file_hint(
            FileQueryHint::new("go_logging_modules")
                .with_label("Go logging modules")
                .with_max_files(16)
                .include(FilePredicate::language("go"))
                .include(FilePredicate::text_contains_any([
                    "log.Logger",
                    "logrus.",
                    "zap.",
                    "zerolog.",
                    "slog.",
                    "log.New(",
                    "logging.",
                ])),
        )
        // Cross-file support: middleware
        .with_file_hint(
            FileQueryHint::new("go_middleware")
                .with_label("Go middleware")
                .with_max_files(16)
                .include(FilePredicate::language("go"))
                .include(FilePredicate::text_contains_any([
                    "middleware",
                    "Middleware",
                    "HandlerFunc",
                    "correlation",
                    "request_id",
                    "RequestID",
                ])),
        )
        // Cross-file support: resilience patterns
        .with_file_hint(
            FileQueryHint::new("go_resilience")
                .with_label("Go resilience patterns")
                .with_max_files(16)
                .include(FilePredicate::language("go"))
                .include(FilePredicate::text_contains_any([
                    "circuit",
                    "Circuit",
                    "breaker",
                    "Breaker",
                    "hystrix",
                    "gobreaker",
                ])),
        )
}

// ==================== Rust Profiles ====================

/// Rust Axum service profile.
fn rust_axum_service() -> Profile {
    Profile::new("rust_axum_service", "Rust Axum service")
        .with_language(Language::Rust)
        .with_framework(Framework::Axum)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Performance)
        .with_dimension(Dimension::Security)
        .with_dimension(Dimension::Observability)
        .with_rules([
            // Error handling rules
            "rust.unsafe_unwrap",
            "rust.panic_in_library",
            "rust.ignored_result",
            // Async/concurrency rules
            "rust.blocking_in_async",
            "rust.spawn_no_error_handling",
            "rust.unbounded_channel",
            "rust.missing_select_timeout",
            "rust.arc_mutex_contention",
            "rust.missing_async_timeout",
            "rust.cpu_in_async",
            "rust.unbounded_concurrency",
            "rust.uncancelled_tasks",
            // Safety/security rules
            "rust.unsafe_block_unaudited",
            "rust.hardcoded_secrets",
            "rust.sql_injection",
            // Observability rules
            "rust.println_in_lib",
            "rust.missing_tracing",
            "rust.missing_correlation_id",
            "rust.missing_structured_logging",
            // Performance rules
            "rust.clone_in_loop",
            "rust.io_in_hot_path",
            "rust.n_plus_one",
            "rust.unbounded_memory",
            "rust.sync_dns_lookup",
            "rust.unbounded_recursion",
            "rust.regex_compile",
            // Resilience rules
            "rust.missing_circuit_breaker",
            "rust.unbounded_retry",
            // Memory rules
            "rust.unbounded_cache",
            "rust.large_response_memory",
            // Datetime rules
            "rust.naive_datetime",
            // Concurrency rules
            "rust.global_mutable_state",
            // Data/storage rules
            "rust.missing_idempotency_key",
            "rust.ephemeral_filesystem_write",
            // Network rules
            "rust.grpc_no_deadline",
            // Axum framework rules
            "rust.axum.missing_cors",
            "rust.axum.missing_error_handler",
            "rust.axum.missing_timeout",
            // SQLx rules
            "rust.sqlx.missing_pool_timeout",
            "rust.sqlx.missing_transaction",
            "rust.sqlx.query_without_timeout",
            // Tokio rules
            "rust.tokio.missing_graceful_shutdown",
            "rust.tokio.missing_runtime_config",
        ])
        .with_file_hint(
            FileQueryHint::new("rust_entrypoints")
                .with_label("Rust entrypoints")
                .with_max_files(8)
                .include(FilePredicate::path_glob("**/main.rs"))
                .include(FilePredicate::path_glob("**/lib.rs")),
        )
        .with_file_hint(
            FileQueryHint::new("axum_handlers")
                .with_label("Axum handlers")
                .with_max_files(32)
                .include(FilePredicate::language("rust"))
                .include(FilePredicate::text_contains_any(["axum::", "use axum"])),
        )
        // Cross-file support: logging/tracing modules for missing_structured_logging rule
        .with_file_hint(
            FileQueryHint::new("rust_logging_modules")
                .with_label("Rust logging/tracing modules")
                .with_max_files(16)
                .include(FilePredicate::language("rust"))
                .include(FilePredicate::text_contains_any([
                    "tracing::",
                    "use tracing",
                    "log::",
                    "use log",
                    "env_logger",
                    "tracing_subscriber",
                    "init_tracing",
                    "setup_logging",
                ])),
        )
        // Cross-file support: middleware/layers for correlation_id rule
        .with_file_hint(
            FileQueryHint::new("rust_middleware")
                .with_label("Rust middleware/layers")
                .with_max_files(16)
                .include(FilePredicate::language("rust"))
                .include(FilePredicate::text_contains_any([
                    "tower::",
                    "use tower",
                    "Layer",
                    "Service",
                    "middleware",
                    "correlation",
                    "request_id",
                    "RequestId",
                    "TraceLayer",
                ])),
        )
        // Cross-file support: resilience patterns for circuit_breaker rule
        .with_file_hint(
            FileQueryHint::new("rust_resilience")
                .with_label("Rust resilience patterns")
                .with_max_files(16)
                .include(FilePredicate::language("rust"))
                .include(FilePredicate::text_contains_any([
                    "circuit",
                    "Circuit",
                    "breaker",
                    "Breaker",
                    "failsafe",
                    "resilience",
                    "retry",
                    "Retry",
                ])),
        )
        // Cross-file support: config files
        .with_file_hint(
            FileQueryHint::new("rust_config")
                .with_label("Rust configuration")
                .with_max_files(8)
                .include(FilePredicate::path_glob("**/config.rs"))
                .include(FilePredicate::path_glob("**/config/*.rs"))
                .include(FilePredicate::path_glob("**/settings.rs")),
        )
}

/// Rust Actix-web service profile.
fn rust_actix_service() -> Profile {
    Profile::new("rust_actix_service", "Rust Actix-web service")
        .with_language(Language::Rust)
        .with_framework(Framework::ActixWeb)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Performance)
        .with_dimension(Dimension::Security)
        .with_dimension(Dimension::Observability)
        .with_rules([
            // Error handling rules
            "rust.unsafe_unwrap",
            "rust.panic_in_library",
            "rust.ignored_result",
            // Async/concurrency rules
            "rust.blocking_in_async",
            "rust.spawn_no_error_handling",
            "rust.unbounded_channel",
            "rust.missing_select_timeout",
            "rust.arc_mutex_contention",
            "rust.missing_async_timeout",
            "rust.cpu_in_async",
            "rust.unbounded_concurrency",
            "rust.uncancelled_tasks",
            // Safety/security rules
            "rust.unsafe_block_unaudited",
            "rust.hardcoded_secrets",
            "rust.sql_injection",
            // Observability rules
            "rust.println_in_lib",
            "rust.missing_tracing",
            "rust.missing_correlation_id",
            "rust.missing_structured_logging",
            // Performance rules
            "rust.clone_in_loop",
            "rust.io_in_hot_path",
            "rust.n_plus_one",
            "rust.unbounded_memory",
            "rust.sync_dns_lookup",
            "rust.unbounded_recursion",
            "rust.regex_compile",
            // Resilience rules
            "rust.missing_circuit_breaker",
            "rust.unbounded_retry",
            // Memory rules
            "rust.unbounded_cache",
            "rust.large_response_memory",
            // Datetime rules
            "rust.naive_datetime",
            // Concurrency rules
            "rust.global_mutable_state",
            // Data/storage rules
            "rust.missing_idempotency_key",
            "rust.ephemeral_filesystem_write",
            // Network rules
            "rust.grpc_no_deadline",
            // SQLx rules
            "rust.sqlx.missing_pool_timeout",
            "rust.sqlx.missing_transaction",
            "rust.sqlx.query_without_timeout",
            // Tokio rules
            "rust.tokio.missing_graceful_shutdown",
            "rust.tokio.missing_runtime_config",
        ])
        .with_file_hint(
            FileQueryHint::new("rust_entrypoints")
                .with_label("Rust entrypoints")
                .with_max_files(8)
                .include(FilePredicate::path_glob("**/main.rs"))
                .include(FilePredicate::path_glob("**/lib.rs")),
        )
        .with_file_hint(
            FileQueryHint::new("actix_handlers")
                .with_label("Actix handlers")
                .with_max_files(32)
                .include(FilePredicate::language("rust"))
                .include(FilePredicate::text_contains_any([
                    "actix_web::",
                    "use actix_web",
                ])),
        )
        // Cross-file support: logging/tracing modules
        .with_file_hint(
            FileQueryHint::new("rust_logging_modules")
                .with_label("Rust logging/tracing modules")
                .with_max_files(16)
                .include(FilePredicate::language("rust"))
                .include(FilePredicate::text_contains_any([
                    "tracing::",
                    "use tracing",
                    "log::",
                    "use log",
                    "env_logger",
                    "tracing_subscriber",
                ])),
        )
        // Cross-file support: middleware
        .with_file_hint(
            FileQueryHint::new("rust_middleware")
                .with_label("Rust middleware/layers")
                .with_max_files(16)
                .include(FilePredicate::language("rust"))
                .include(FilePredicate::text_contains_any([
                    "tower::",
                    "use tower",
                    "Layer",
                    "middleware",
                    "correlation",
                    "request_id",
                ])),
        )
        // Cross-file support: resilience patterns
        .with_file_hint(
            FileQueryHint::new("rust_resilience")
                .with_label("Rust resilience patterns")
                .with_max_files(16)
                .include(FilePredicate::language("rust"))
                .include(FilePredicate::text_contains_any([
                    "circuit",
                    "Circuit",
                    "breaker",
                    "Breaker",
                    "failsafe",
                    "retry",
                    "Retry",
                ])),
        )
}

// ==================== TypeScript/JavaScript Profiles ====================

/// TypeScript Express backend profile.
fn typescript_express_backend() -> Profile {
    Profile::new("typescript_express_backend", "TypeScript Express backend")
        .with_language(Language::Typescript)
        .with_framework(Framework::Express)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Performance)
        .with_dimension(Dimension::Security)
        .with_dimension(Dimension::Observability)
        .with_rules([
            // Error handling rules
            "typescript.promise_no_catch",
            "typescript.async_without_error_handling",
            "typescript.empty_catch",
            "typescript.bare_catch",
            // HTTP rules
            "typescript.http_missing_timeout",
            "typescript.http_retry",
            // Security rules
            "typescript.sql_injection",
            "typescript.hardcoded_secrets",
            "typescript.unsafe_eval",
            "typescript.unsafe_any",
            // Observability rules
            "typescript.console_in_production",
            "typescript.missing_structured_logging",
            "typescript.missing_correlation_id",
            // Resilience rules
            "typescript.missing_circuit_breaker",
            "typescript.unbounded_retry",
            "typescript.graceful_shutdown",
            // Data integrity rules
            "typescript.missing_idempotency_key",
            "typescript.transaction_boundary",
            // Performance/memory rules
            "typescript.unbounded_memory",
            "typescript.large_response_memory",
            "typescript.unbounded_cache",
            "typescript.n_plus_one_queries",
            "typescript.cpu_in_event_loop",
            "typescript.regex_compile",
            // Concurrency rules
            "typescript.global_mutable_state",
            "typescript.unbounded_concurrency",
            "typescript.race_condition",
            // Framework-specific rules
            "typescript.express.missing_error_middleware",
        ])
        .with_file_hint(
            FileQueryHint::new("express_entrypoints")
                .with_label("Express entrypoints")
                .with_max_files(8)
                .include(FilePredicate::path_glob("**/index.ts"))
                .include(FilePredicate::path_glob("**/app.ts"))
                .include(FilePredicate::path_glob("**/server.ts")),
        )
        .with_file_hint(
            FileQueryHint::new("express_routes")
                .with_label("Express routes")
                .with_max_files(32)
                .include(FilePredicate::language("typescript"))
                .include(FilePredicate::text_contains_any([
                    "express.Router",
                    "app.get(",
                    "app.post(",
                    "router.get(",
                    "router.post(",
                ])),
        )
        // Cross-file support: logging modules for missing_structured_logging rule
        .with_file_hint(
            FileQueryHint::new("typescript_logging_modules")
                .with_label("TypeScript logging modules")
                .with_max_files(16)
                .include(FilePredicate::language("typescript"))
                .include(FilePredicate::text_contains_any([
                    "winston",
                    "pino",
                    "bunyan",
                    "log4js",
                    "logger.",
                    "Logger(",
                    "createLogger",
                    "getLogger",
                ])),
        )
        // Cross-file support: middleware for correlation_id rule
        .with_file_hint(
            FileQueryHint::new("typescript_middleware")
                .with_label("TypeScript middleware")
                .with_max_files(16)
                .include(FilePredicate::language("typescript"))
                .include(FilePredicate::text_contains_any([
                    "middleware",
                    "Middleware",
                    "app.use(",
                    "correlation",
                    "requestId",
                    "request-id",
                    "x-request-id",
                    "x-correlation-id",
                ])),
        )
        // Cross-file support: resilience patterns for circuit_breaker rule
        .with_file_hint(
            FileQueryHint::new("typescript_resilience")
                .with_label("TypeScript resilience patterns")
                .with_max_files(16)
                .include(FilePredicate::language("typescript"))
                .include(FilePredicate::text_contains_any([
                    "circuit",
                    "Circuit",
                    "breaker",
                    "Breaker",
                    "opossum",
                    "cockatiel",
                    "resilience",
                ])),
        )
        // Cross-file support: config files
        .with_file_hint(
            FileQueryHint::new("typescript_config")
                .with_label("TypeScript configuration")
                .with_max_files(8)
                .include(FilePredicate::path_glob("**/config.ts"))
                .include(FilePredicate::path_glob("**/config/*.ts"))
                .include(FilePredicate::path_glob("**/settings.ts")),
        )
}

/// TypeScript Next.js application profile.
fn typescript_nextjs_app() -> Profile {
    Profile::new("typescript_nextjs_app", "TypeScript Next.js application")
        .with_language(Language::Typescript)
        .with_framework(Framework::NextJs)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Performance)
        .with_dimension(Dimension::Security)
        .with_dimension(Dimension::Observability)
        .with_rules([
            // Error handling rules
            "typescript.promise_no_catch",
            "typescript.async_without_error_handling",
            "typescript.empty_catch",
            "typescript.bare_catch",
            // HTTP rules
            "typescript.http_missing_timeout",
            "typescript.http_retry",
            // Security rules
            "typescript.sql_injection",
            "typescript.hardcoded_secrets",
            "typescript.unsafe_eval",
            "typescript.unsafe_any",
            // Observability rules
            "typescript.console_in_production",
            "typescript.missing_structured_logging",
            "typescript.nextjs.api_missing_error_logging",
            // Performance/memory rules
            "typescript.unbounded_memory",
            "typescript.large_response_memory",
            "typescript.unbounded_cache",
            "typescript.n_plus_one_queries",
            "typescript.cpu_in_event_loop",
            "typescript.regex_compile",
            // Concurrency rules
            "typescript.global_mutable_state",
            "typescript.race_condition",
        ])
        .with_file_hint(
            FileQueryHint::new("nextjs_pages")
                .with_label("Next.js pages")
                .with_max_files(32)
                .include(FilePredicate::path_glob("pages/**/*.tsx"))
                .include(FilePredicate::path_glob("pages/**/*.ts"))
                .include(FilePredicate::path_glob("app/**/*.tsx"))
                .include(FilePredicate::path_glob("app/**/*.ts"))
                .include(FilePredicate::path_glob("next.config.js"))
                .include(FilePredicate::path_glob("next.config.mjs")),
        )
        .with_file_hint(
            FileQueryHint::new("nextjs_api_routes")
                .with_label("Next.js API routes")
                .with_max_files(16)
                .include(FilePredicate::path_glob("pages/api/**/*.ts"))
                .include(FilePredicate::path_glob("app/api/**/*.ts")),
        )
        // Cross-file support: logging modules
        .with_file_hint(
            FileQueryHint::new("typescript_logging_modules")
                .with_label("TypeScript logging modules")
                .with_max_files(16)
                .include(FilePredicate::language("typescript"))
                .include(FilePredicate::text_contains_any([
                    "winston",
                    "pino",
                    "bunyan",
                    "log4js",
                    "logger.",
                    "Logger(",
                    "createLogger",
                ])),
        )
        // Cross-file support: lib/utils for shared code
        .with_file_hint(
            FileQueryHint::new("nextjs_lib")
                .with_label("Next.js lib/utils")
                .with_max_files(16)
                .include(FilePredicate::path_glob("lib/**/*.ts"))
                .include(FilePredicate::path_glob("utils/**/*.ts"))
                .include(FilePredicate::path_glob("src/lib/**/*.ts")),
        )
}

// ==================== LSP Profiles ====================
//
// LSP profiles are designed for IDE/editor integration where files are analyzed
// individually or in small batches. They exclude rules that require cross-file
// context to avoid false positives.
//
// Rules excluded from LSP profiles:
// - CORS/middleware rules (might be configured in a different file)
// - Health check rules (might be in a separate router)
// - Graceful shutdown rules (typically in main/entrypoint)
// - Circuit breaker rules (might be configured globally)
// - Correlation ID rules (might be middleware)
// - Tracing rules (might be configured at app level)
// - Rate limiting rules (might be middleware)

/// Python LSP profile - excludes cross-file rules for single-file analysis.
fn python_lsp() -> Profile {
    Profile::new("python_lsp", "Python LSP (single-file analysis)")
        .with_language(Language::Python)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Security)
        .with_dimension(Dimension::Performance)
        .with_rules([
            // HTTP/Network (local to the call)
            "python.http.missing_timeout",
            "python.http.blocking_in_async",
            "python.http.missing_retry",
            "python.sync_dns_lookup",
            "python.grpc_no_deadline",
            // Error Handling (local)
            "python.bare_except",
            "python.async_task_no_error_handling",
            // Security (local)
            "python.sql_injection",
            "python.unsafe_eval",
            // Data/Types (local)
            "python.naive_datetime",
            "python.global_mutable_state",
            // Async (local)
            "python.asyncio_timeout",
            "python.uncancelled_tasks",
            "python.cpu_in_event_loop",
            // Memory/Performance (local)
            "python.unbounded_cache",
            "python.unbounded_concurrency",
            "python.unbounded_retry",
            "python.unbounded_memory",
            "python.large_response_memory",
            "python.n_plus_one_queries",
            "python.io_in_hot_path",
            "python.regex_compile",
            // Database (local)
            "python.db.missing_timeout",
            "python.transaction_boundary",
            // Code Quality (local)
            "python.recursive_no_base_case",
            "python.race_condition",
            "python.ephemeral_filesystem_write",
            "python.code_duplication",
            // Framework-specific (local checks only)
            "python.pydantic.missing_validators",
            "python.pydantic.arbitrary_types",
            "python.redis.missing_ttl",
            "python.redis.unbounded_keys",
            "python.sqlalchemy.lazy_loading",
            "python.sqlalchemy.query_timeout",
            "python.sqlalchemy.session_management",
            "python.sqlalchemy.connection_pool",
            "python.sqlalchemy.pgvector_suboptimal_query",
            "python.fastapi.missing_input_validation",
            "python.fastapi.request_body_unbounded",
            "python.fastapi.missing_request_timeout",
            "python.django.missing_csrf",
            "python.django.orm_select_related",
            "python.django.allowed_hosts",
            "python.django.session_settings",
            "python.django.secure_settings",
            "python.flask.hardcoded_secret_key",
            "python.flask.session_timeout",
            "python.flask.insecure_cookie_settings",
            // Observability (local - checks if logging is used in handlers)
            "python.missing_structured_logging",
        ])
        // LSP profiles don't need file hints - the client provides the file
        // ===== EXCLUDED: Cross-file rules =====
        // NOT included:
        // - fastapi.missing_cors (CORS might be in app factory)
        // - fastapi.missing_health_check (might be in separate router)
        // - fastapi.missing_exception_handler (might be in main)
        // - fastapi.missing_rate_limiting (might be middleware)
        // - python.graceful_shutdown (might be in main.py)
        // - python.resilience.missing_circuit_breaker (might be configured globally)
        // - python.missing_correlation_id (might be middleware)
        // - python.missing_tracing (might be configured at app level)
        // - python.async_resource_cleanup (resource cleanup might span multiple files)
        // - python.idempotency_key (might be handled at middleware level)
}

/// Go LSP profile - excludes cross-file rules for single-file analysis.
fn go_lsp() -> Profile {
    Profile::new("go_lsp", "Go LSP (single-file analysis)")
        .with_language(Language::Go)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Security)
        .with_dimension(Dimension::Performance)
        .with_rules([
            // Error Handling (local)
            "go.unchecked_error",
            "go.bare_recover",
            "go.panic_in_library",
            "go.error_type_assertion",
            "go.sentinel_error_comparison",
            "go.unhandled_error_goroutine",
            // Concurrency (local)
            "go.defer_in_loop",
            "go.goroutine_leak",
            "go.empty_critical_section",
            "go.race_condition",
            "go.channel_never_closed",
            "go.concurrent_map_access",
            "go.uncancelled_context",
            "go.unbounded_goroutines",
            // HTTP/Network (local)
            "go.http_missing_timeout",
            "go.sync_dns_lookup",
            "go.http_retry",
            // Security (local)
            "go.sql_injection",
            "go.hardcoded_secrets",
            "go.unsafe_template",
            // Types (local)
            "go.type_assertion_no_ok",
            "go.context_background",
            // Memory/Performance (local)
            "go.unbounded_memory",
            "go.unbounded_cache",
            "go.large_response_memory",
            "go.slice_memory_leak",
            "go.slice_append_in_loop",
            "go.map_without_size_hint",
            "go.reflect_in_hot_path",
            "go.cpu_in_hot_path",
            "go.regex_compile",
            // Data (local)
            "go.transaction_boundary",
            "go.idempotency_key",
            "go.ephemeral_filesystem_write",
            // Framework-specific (local)
            "go.gin.missing_validation",
            "go.gin.untrusted_input",
            "go.echo.missing_middleware",
            "go.echo.request_validation",
            "go.gorm.connection_pool",
            "go.gorm.n_plus_one",
            "go.gorm.query_timeout",
            "go.gorm.session_management",
            "go.grpc.missing_deadline",
            "go.redis.missing_ttl",
            "go.redis.connection_pool",
            "go.nethttp.server_timeout",
            "go.nethttp.handler_timeout",
            // Observability (local)
            "go.missing_structured_logging",
            // Resilience (local)
            "go.unbounded_retry",
        ])
        // ===== EXCLUDED: Cross-file rules =====
        // NOT included:
        // - go.graceful_shutdown (signal handling in main.go)
        // - go.missing_circuit_breaker (might be configured globally)
        // - go.missing_correlation_id (might be middleware)
        // - go.missing_tracing (might be configured at app level)
        // - go.rate_limiting (might be middleware)
}

/// Rust LSP profile - excludes cross-file rules for single-file analysis.
fn rust_lsp() -> Profile {
    Profile::new("rust_lsp", "Rust LSP (single-file analysis)")
        .with_language(Language::Rust)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Security)
        .with_dimension(Dimension::Performance)
        .with_rules([
            // Error Handling (local)
            "rust.unsafe_unwrap",
            "rust.panic_in_library",
            "rust.ignored_result",
            // Async/Concurrency (local)
            "rust.blocking_in_async",
            "rust.spawn_no_error_handling",
            "rust.unbounded_channel",
            "rust.missing_select_timeout",
            "rust.arc_mutex_contention",
            "rust.missing_async_timeout",
            "rust.cpu_in_async",
            "rust.unbounded_concurrency",
            "rust.uncancelled_tasks",
            // Safety/Security (local)
            "rust.unsafe_block_unaudited",
            "rust.hardcoded_secrets",
            "rust.sql_injection",
            // Observability (local)
            "rust.println_in_lib",
            "rust.missing_structured_logging",
            // Performance (local)
            "rust.clone_in_loop",
            "rust.io_in_hot_path",
            "rust.n_plus_one",
            "rust.unbounded_memory",
            "rust.sync_dns_lookup",
            "rust.unbounded_recursion",
            "rust.regex_compile",
            // Data (local)
            "rust.naive_datetime",
            "rust.global_mutable_state",
            "rust.missing_idempotency_key",
            "rust.ephemeral_filesystem_write",
            "rust.grpc_no_deadline",
            // Memory (local)
            "rust.unbounded_cache",
            "rust.large_response_memory",
            // Resilience (local)
            "rust.unbounded_retry",
            // Framework-specific (local)
            "rust.axum.missing_timeout",
            "rust.axum.missing_error_handler",
            "rust.sqlx.missing_pool_timeout",
            "rust.sqlx.missing_transaction",
            "rust.sqlx.query_without_timeout",
            "rust.tokio.missing_runtime_config",
        ])
        // ===== EXCLUDED: Cross-file rules =====
        // NOT included:
        // - rust.axum.missing_cors (CORS layer in router setup)
        // - rust.tokio.missing_graceful_shutdown (in main)
        // - rust.missing_circuit_breaker (might be configured globally)
        // - rust.missing_correlation_id (might be middleware)
        // - rust.missing_tracing (might be configured at app level)
}

/// TypeScript LSP profile - excludes cross-file rules for single-file analysis.
fn typescript_lsp() -> Profile {
    Profile::new("typescript_lsp", "TypeScript LSP (single-file analysis)")
        .with_language(Language::Typescript)
        .with_dimension(Dimension::Stability)
        .with_dimension(Dimension::Correctness)
        .with_dimension(Dimension::Security)
        .with_dimension(Dimension::Performance)
        .with_rules([
            // Error Handling (local)
            "typescript.empty_catch",
            "typescript.bare_catch",
            "typescript.async_without_error_handling",
            "typescript.promise_no_catch",
            // Types (local)
            "typescript.unsafe_any",
            "typescript.missing_null_check",
            // HTTP/Network (local)
            "typescript.http_missing_timeout",
            "typescript.http_retry",
            "typescript.sync_dns_lookup",
            "typescript.grpc_no_deadline",
            // Security (local)
            "typescript.sql_injection",
            "typescript.hardcoded_secrets",
            "typescript.unsafe_eval",
            "typescript.console_in_production",
            // Memory/Performance (local)
            "typescript.unbounded_cache",
            "typescript.unbounded_concurrency",
            "typescript.unbounded_retry",
            "typescript.unbounded_memory",
            "typescript.large_response_memory",
            "typescript.cpu_in_event_loop",
            "typescript.n_plus_one_queries",
            "typescript.regex_compile",
            // Data (local)
            "typescript.naive_datetime",
            "typescript.transaction_boundary",
            "typescript.missing_idempotency_key",
            "typescript.global_mutable_state",
            "typescript.race_condition",
            // Observability (local)
            "typescript.missing_structured_logging",
        ])
        // ===== EXCLUDED: Cross-file rules =====
        // NOT included:
        // - typescript.graceful_shutdown (in server setup)
        // - typescript.missing_circuit_breaker (might be configured globally)
        // - typescript.missing_correlation_id (might be middleware)
        // - typescript.missing_tracing (might be configured at app level)
        // - typescript.missing_rate_limiting (might be middleware)
        // - typescript.express.missing_error_middleware (in app setup)
}

// ==================== Maintainability Profiles ====================
//
// These profiles focus on code complexity and maintainability metrics.
// They are opt-in and NOT included in default analysis profiles to avoid
// sending large codebases for complexity analysis.
//
// Use these profiles explicitly when you want to analyze code maintainability.

/// Python Maintainability profile - Halstead complexity and code quality metrics.
///
/// This profile is opt-in and focuses on code maintainability analysis.
/// It uses targeted file hints to limit the amount of code sent for analysis.
fn python_maintainability() -> Profile {
    Profile::new("python_maintainability", "Python Maintainability Analysis")
        .with_language(Language::Python)
        .with_dimension(Dimension::Maintainability)
        .with_rules([
            // Halstead complexity
            "python.halstead_complexity",
            // Code duplication (also relevant to maintainability)
            "python.code_duplication",
        ])
        // File hints limit the amount of code sent for complexity analysis
        .with_file_hint(
            FileQueryHint::new("python_core_modules")
                .with_label("Core Python modules for complexity analysis")
                .with_max_files(30)
                .with_max_total_bytes(500_000) // 500KB max
                .include(FilePredicate::language("python"))
                .include(FilePredicate::under_directory("src"))
                .exclude(FilePredicate::path_glob("**/test_*.py"))
                .exclude(FilePredicate::path_glob("**/*_test.py"))
                .exclude(FilePredicate::path_glob("**/tests/**"))
                .exclude(FilePredicate::path_glob("**/conftest.py"))
                .exclude(FilePredicate::path_glob("**/__pycache__/**")),
        )
        .with_file_hint(
            FileQueryHint::new("python_app_modules")
                .with_label("Application modules for complexity analysis")
                .with_max_files(30)
                .with_max_total_bytes(500_000) // 500KB max
                .include(FilePredicate::language("python"))
                .include(FilePredicate::under_directory("app"))
                .exclude(FilePredicate::path_glob("**/test_*.py"))
                .exclude(FilePredicate::path_glob("**/*_test.py"))
                .exclude(FilePredicate::path_glob("**/tests/**")),
        )
        .with_file_hint(
            FileQueryHint::new("python_lib_modules")
                .with_label("Library modules for complexity analysis")
                .with_max_files(20)
                .with_max_total_bytes(300_000) // 300KB max
                .include(FilePredicate::language("python"))
                .include(FilePredicate::under_directory("lib"))
                .exclude(FilePredicate::path_glob("**/test_*.py"))
                .exclude(FilePredicate::path_glob("**/*_test.py")),
        )
}

/// Go Maintainability profile - Halstead complexity and code quality metrics.
///
/// This profile is opt-in and focuses on code maintainability analysis.
fn go_maintainability() -> Profile {
    Profile::new("go_maintainability", "Go Maintainability Analysis")
        .with_language(Language::Go)
        .with_dimension(Dimension::Maintainability)
        .with_rules([
            // Halstead complexity
            "go.halstead_complexity",
        ])
        // File hints limit the amount of code sent for complexity analysis
        .with_file_hint(
            FileQueryHint::new("go_core_modules")
                .with_label("Core Go modules for complexity analysis")
                .with_max_files(30)
                .with_max_total_bytes(500_000) // 500KB max
                .include(FilePredicate::language("go"))
                .include(FilePredicate::under_directory("internal"))
                .exclude(FilePredicate::path_glob("**/*_test.go"))
                .exclude(FilePredicate::path_glob("**/testdata/**")),
        )
        .with_file_hint(
            FileQueryHint::new("go_cmd_modules")
                .with_label("Command modules for complexity analysis")
                .with_max_files(20)
                .with_max_total_bytes(300_000) // 300KB max
                .include(FilePredicate::language("go"))
                .include(FilePredicate::under_directory("cmd"))
                .exclude(FilePredicate::path_glob("**/*_test.go")),
        )
        .with_file_hint(
            FileQueryHint::new("go_pkg_modules")
                .with_label("Package modules for complexity analysis")
                .with_max_files(30)
                .with_max_total_bytes(500_000) // 500KB max
                .include(FilePredicate::language("go"))
                .include(FilePredicate::under_directory("pkg"))
                .exclude(FilePredicate::path_glob("**/*_test.go")),
        )
}

/// Rust Maintainability profile - Halstead complexity and code quality metrics.
///
/// This profile is opt-in and focuses on code maintainability analysis.
fn rust_maintainability() -> Profile {
    Profile::new("rust_maintainability", "Rust Maintainability Analysis")
        .with_language(Language::Rust)
        .with_dimension(Dimension::Maintainability)
        .with_rules([
            // Halstead complexity
            "rust.halstead_complexity",
        ])
        // File hints limit the amount of code sent for complexity analysis
        .with_file_hint(
            FileQueryHint::new("rust_src_modules")
                .with_label("Source modules for complexity analysis")
                .with_max_files(30)
                .with_max_total_bytes(500_000) // 500KB max
                .include(FilePredicate::language("rust"))
                .include(FilePredicate::under_directory("src"))
                .exclude(FilePredicate::path_glob("**/tests/**"))
                .exclude(FilePredicate::path_glob("**/test*.rs"))
                .exclude(FilePredicate::path_glob("**/benches/**")),
        )
        .with_file_hint(
            FileQueryHint::new("rust_lib_modules")
                .with_label("Library modules for complexity analysis")
                .with_max_files(20)
                .with_max_total_bytes(300_000) // 300KB max
                .include(FilePredicate::language("rust"))
                .include(FilePredicate::path_glob("**/lib.rs"))
                .include(FilePredicate::path_glob("**/mod.rs")),
        )
}

/// TypeScript Maintainability profile - Halstead complexity and code quality metrics.
///
/// This profile is opt-in and focuses on code maintainability analysis.
fn typescript_maintainability() -> Profile {
    Profile::new("typescript_maintainability", "TypeScript Maintainability Analysis")
        .with_language(Language::Typescript)
        .with_dimension(Dimension::Maintainability)
        .with_rules([
            // Halstead complexity
            "typescript.halstead_complexity",
        ])
        // File hints limit the amount of code sent for complexity analysis
        .with_file_hint(
            FileQueryHint::new("typescript_src_modules")
                .with_label("Source modules for complexity analysis")
                .with_max_files(30)
                .with_max_total_bytes(500_000) // 500KB max
                .include(FilePredicate::language("typescript"))
                .include(FilePredicate::under_directory("src"))
                .exclude(FilePredicate::path_glob("**/*.test.ts"))
                .exclude(FilePredicate::path_glob("**/*.spec.ts"))
                .exclude(FilePredicate::path_glob("**/test/**"))
                .exclude(FilePredicate::path_glob("**/tests/**"))
                .exclude(FilePredicate::path_glob("**/__tests__/**")),
        )
        .with_file_hint(
            FileQueryHint::new("typescript_lib_modules")
                .with_label("Library modules for complexity analysis")
                .with_max_files(20)
                .with_max_total_bytes(300_000) // 300KB max
                .include(FilePredicate::language("typescript"))
                .include(FilePredicate::under_directory("lib"))
                .exclude(FilePredicate::path_glob("**/*.test.ts"))
                .exclude(FilePredicate::path_glob("**/*.spec.ts")),
        )
        .with_file_hint(
            FileQueryHint::new("typescript_app_modules")
                .with_label("Application modules for complexity analysis")
                .with_max_files(30)
                .with_max_total_bytes(500_000) // 500KB max
                .include(FilePredicate::language("typescript"))
                .include(FilePredicate::under_directory("app"))
                .exclude(FilePredicate::path_glob("**/*.test.ts"))
                .exclude(FilePredicate::path_glob("**/*.spec.ts")),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_fastapi_backend_has_correct_id() {
        let profile = python_fastapi_backend();
        assert_eq!(profile.id, "python_fastapi_backend");
    }

    #[test]
    fn python_fastapi_backend_has_rules() {
        let profile = python_fastapi_backend();
        assert!(!profile.rule_ids.is_empty());
        assert!(
            profile
                .rule_ids
                .contains(&"fastapi.missing_cors".to_string())
        );
    }

    #[test]
    fn python_fastapi_backend_has_file_hints() {
        let profile = python_fastapi_backend();
        assert!(!profile.file_hints.is_empty());
    }

    #[test]
    fn python_django_backend_has_correct_id() {
        let profile = python_django_backend();
        assert_eq!(profile.id, "python_django_backend");
    }

    #[test]
    fn go_gin_service_has_correct_id() {
        let profile = go_gin_service();
        assert_eq!(profile.id, "go_gin_service");
    }

    #[test]
    fn rust_axum_service_has_correct_id() {
        let profile = rust_axum_service();
        assert_eq!(profile.id, "rust_axum_service");
    }

    #[test]
    fn typescript_express_backend_has_correct_id() {
        let profile = typescript_express_backend();
        assert_eq!(profile.id, "typescript_express_backend");
    }

    #[test]
    fn register_builtin_profiles_adds_all_profiles() {
        let mut registry = ProfileRegistry::new();
        register_builtin_profiles(&mut registry);

        // Should have all the profiles we defined
        assert!(registry.contains("python_fastapi_backend"));
        assert!(registry.contains("python_django_backend"));
        assert!(registry.contains("python_flask_backend"));
        assert!(registry.contains("python_generic_backend"));
        assert!(registry.contains("go_gin_service"));
        assert!(registry.contains("go_generic_service"));
        assert!(registry.contains("rust_axum_service"));
        assert!(registry.contains("rust_actix_service"));
        assert!(registry.contains("typescript_express_backend"));
        assert!(registry.contains("typescript_nextjs_app"));
    }

    #[test]
    fn all_builtin_profiles_have_languages() {
        let registry = ProfileRegistry::with_builtin_profiles();
        for profile in registry.all() {
            assert!(
                !profile.languages.is_empty(),
                "Profile {} should have at least one language",
                profile.id
            );
        }
    }

    #[test]
    fn all_builtin_profiles_have_dimensions() {
        let registry = ProfileRegistry::with_builtin_profiles();
        for profile in registry.all() {
            assert!(
                !profile.dimensions.is_empty(),
                "Profile {} should have at least one dimension",
                profile.id
            );
        }
    }

    #[test]
    fn all_builtin_profiles_have_file_hints_except_lsp() {
        let registry = ProfileRegistry::with_builtin_profiles();
        for profile in registry.all() {
            // LSP profiles don't need file hints - the client provides the file
            if profile.id.ends_with("_lsp") {
                continue;
            }
            assert!(
                !profile.file_hints.is_empty(),
                "Profile {} should have at least one file hint",
                profile.id
            );
        }
    }

    // ==================== LSP Profile Tests ====================

    #[test]
    fn python_lsp_has_correct_id() {
        let profile = python_lsp();
        assert_eq!(profile.id, "python_lsp");
    }

    #[test]
    fn python_lsp_excludes_cross_file_rules() {
        let profile = python_lsp();
        // These rules require cross-file context and should NOT be in LSP profile
        assert!(
            !profile.rule_ids.contains(&"fastapi.missing_cors".to_string()),
            "LSP profile should not contain fastapi.missing_cors"
        );
        assert!(
            !profile
                .rule_ids
                .contains(&"python.fastapi.missing_health_check".to_string()),
            "LSP profile should not contain fastapi.missing_health_check"
        );
        assert!(
            !profile
                .rule_ids
                .contains(&"python.graceful_shutdown".to_string()),
            "LSP profile should not contain python.graceful_shutdown"
        );
        assert!(
            !profile
                .rule_ids
                .contains(&"python.resilience.missing_circuit_breaker".to_string()),
            "LSP profile should not contain python.resilience.missing_circuit_breaker"
        );
        assert!(
            !profile
                .rule_ids
                .contains(&"python.missing_correlation_id".to_string()),
            "LSP profile should not contain python.missing_correlation_id"
        );
    }

    #[test]
    fn python_lsp_includes_local_rules() {
        let profile = python_lsp();
        // These rules are local and should be in LSP profile
        assert!(
            profile
                .rule_ids
                .contains(&"python.http.missing_timeout".to_string()),
            "LSP profile should contain python.http.missing_timeout"
        );
        assert!(
            profile.rule_ids.contains(&"python.bare_except".to_string()),
            "LSP profile should contain python.bare_except"
        );
        assert!(
            profile
                .rule_ids
                .contains(&"python.sql_injection".to_string()),
            "LSP profile should contain python.sql_injection"
        );
    }

    #[test]
    fn go_lsp_has_correct_id() {
        let profile = go_lsp();
        assert_eq!(profile.id, "go_lsp");
    }

    #[test]
    fn go_lsp_excludes_cross_file_rules() {
        let profile = go_lsp();
        assert!(
            !profile
                .rule_ids
                .contains(&"go.graceful_shutdown".to_string()),
            "LSP profile should not contain go.graceful_shutdown"
        );
        assert!(
            !profile
                .rule_ids
                .contains(&"go.missing_circuit_breaker".to_string()),
            "LSP profile should not contain go.missing_circuit_breaker"
        );
        assert!(
            !profile
                .rule_ids
                .contains(&"go.missing_correlation_id".to_string()),
            "LSP profile should not contain go.missing_correlation_id"
        );
    }

    #[test]
    fn go_lsp_includes_local_rules() {
        let profile = go_lsp();
        assert!(
            profile
                .rule_ids
                .contains(&"go.http_missing_timeout".to_string()),
            "LSP profile should contain go.http_missing_timeout"
        );
        assert!(
            profile
                .rule_ids
                .contains(&"go.unchecked_error".to_string()),
            "LSP profile should contain go.unchecked_error"
        );
        assert!(
            profile.rule_ids.contains(&"go.sql_injection".to_string()),
            "LSP profile should contain go.sql_injection"
        );
    }

    #[test]
    fn rust_lsp_has_correct_id() {
        let profile = rust_lsp();
        assert_eq!(profile.id, "rust_lsp");
    }

    #[test]
    fn rust_lsp_excludes_cross_file_rules() {
        let profile = rust_lsp();
        assert!(
            !profile
                .rule_ids
                .contains(&"rust.axum.missing_cors".to_string()),
            "LSP profile should not contain rust.axum.missing_cors"
        );
        assert!(
            !profile
                .rule_ids
                .contains(&"rust.tokio.missing_graceful_shutdown".to_string()),
            "LSP profile should not contain rust.tokio.missing_graceful_shutdown"
        );
        assert!(
            !profile
                .rule_ids
                .contains(&"rust.missing_circuit_breaker".to_string()),
            "LSP profile should not contain rust.missing_circuit_breaker"
        );
    }

    #[test]
    fn rust_lsp_includes_local_rules() {
        let profile = rust_lsp();
        assert!(
            profile
                .rule_ids
                .contains(&"rust.unsafe_unwrap".to_string()),
            "LSP profile should contain rust.unsafe_unwrap"
        );
        assert!(
            profile
                .rule_ids
                .contains(&"rust.blocking_in_async".to_string()),
            "LSP profile should contain rust.blocking_in_async"
        );
        assert!(
            profile
                .rule_ids
                .contains(&"rust.sql_injection".to_string()),
            "LSP profile should contain rust.sql_injection"
        );
    }

    #[test]
    fn typescript_lsp_has_correct_id() {
        let profile = typescript_lsp();
        assert_eq!(profile.id, "typescript_lsp");
    }

    #[test]
    fn typescript_lsp_excludes_cross_file_rules() {
        let profile = typescript_lsp();
        assert!(
            !profile
                .rule_ids
                .contains(&"typescript.graceful_shutdown".to_string()),
            "LSP profile should not contain typescript.graceful_shutdown"
        );
        assert!(
            !profile
                .rule_ids
                .contains(&"typescript.missing_circuit_breaker".to_string()),
            "LSP profile should not contain typescript.missing_circuit_breaker"
        );
        assert!(
            !profile
                .rule_ids
                .contains(&"typescript.express.missing_error_middleware".to_string()),
            "LSP profile should not contain typescript.express.missing_error_middleware"
        );
    }

    #[test]
    fn typescript_lsp_includes_local_rules() {
        let profile = typescript_lsp();
        assert!(
            profile
                .rule_ids
                .contains(&"typescript.http_missing_timeout".to_string()),
            "LSP profile should contain typescript.http_missing_timeout"
        );
        assert!(
            profile
                .rule_ids
                .contains(&"typescript.empty_catch".to_string()),
            "LSP profile should contain typescript.empty_catch"
        );
        assert!(
            profile
                .rule_ids
                .contains(&"typescript.sql_injection".to_string()),
            "LSP profile should contain typescript.sql_injection"
        );
    }

    #[test]
    fn register_builtin_profiles_includes_lsp_profiles() {
        let mut registry = ProfileRegistry::new();
        register_builtin_profiles(&mut registry);

        assert!(registry.contains("python_lsp"));
        assert!(registry.contains("go_lsp"));
        assert!(registry.contains("rust_lsp"));
        assert!(registry.contains("typescript_lsp"));
    }

    #[test]
    fn lsp_profiles_have_no_file_hints() {
        let registry = ProfileRegistry::with_builtin_profiles();

        for profile_id in ["python_lsp", "go_lsp", "rust_lsp", "typescript_lsp"] {
            let profile = registry.get(profile_id).expect("LSP profile should exist");
            assert!(
                profile.file_hints.is_empty(),
                "LSP profile {} should have no file hints",
                profile_id
            );
        }
    }

    #[test]
    fn lsp_profiles_have_rules() {
        let registry = ProfileRegistry::with_builtin_profiles();

        for profile_id in ["python_lsp", "go_lsp", "rust_lsp", "typescript_lsp"] {
            let profile = registry.get(profile_id).expect("LSP profile should exist");
            assert!(
                !profile.rule_ids.is_empty(),
                "LSP profile {} should have rules",
                profile_id
            );
        }
    }

    // ==================== Maintainability Profile Tests ====================

    #[test]
    fn python_maintainability_has_correct_id() {
        let profile = python_maintainability();
        assert_eq!(profile.id, "python_maintainability");
    }

    #[test]
    fn python_maintainability_has_maintainability_dimension() {
        let profile = python_maintainability();
        assert!(
            profile.dimensions.contains(&Dimension::Maintainability),
            "Maintainability profile should have Maintainability dimension"
        );
    }

    #[test]
    fn python_maintainability_has_halstead_rule() {
        let profile = python_maintainability();
        assert!(
            profile.rule_ids.contains(&"python.halstead_complexity".to_string()),
            "Maintainability profile should contain python.halstead_complexity"
        );
    }

    #[test]
    fn python_maintainability_has_code_duplication_rule() {
        let profile = python_maintainability();
        assert!(
            profile.rule_ids.contains(&"python.code_duplication".to_string()),
            "Maintainability profile should contain python.code_duplication"
        );
    }

    #[test]
    fn python_maintainability_has_file_hints() {
        let profile = python_maintainability();
        assert!(
            !profile.file_hints.is_empty(),
            "Maintainability profile should have file hints to limit code sent"
        );
    }

    #[test]
    fn python_maintainability_file_hints_have_max_limits() {
        let profile = python_maintainability();
        for hint in &profile.file_hints {
            assert!(
                hint.max_files.is_some() || hint.max_total_bytes.is_some(),
                "File hint {} should have max_files or max_total_bytes limit",
                hint.id
            );
        }
    }

    #[test]
    fn python_maintainability_file_hints_exclude_tests() {
        let profile = python_maintainability();
        // At least one hint should exclude test files
        let has_test_exclusion = profile.file_hints.iter().any(|hint| {
            hint.exclude.iter().any(|pred| {
                match pred {
                    FilePredicate::PathGlob { pattern } => {
                        pattern.contains("test_") || pattern.contains("_test")
                    }
                    _ => false,
                }
            })
        });
        assert!(
            has_test_exclusion,
            "Maintainability profile should exclude test files from analysis"
        );
    }

    #[test]
    fn register_builtin_profiles_includes_maintainability() {
        let mut registry = ProfileRegistry::new();
        register_builtin_profiles(&mut registry);

        assert!(registry.contains("python_maintainability"));
    }

    #[test]
    fn python_maintainability_is_opt_in() {
        // Verify that maintainability rules are NOT in the default Python profiles
        let default_profiles = [
            python_fastapi_backend(),
            python_django_backend(),
            python_flask_backend(),
            python_generic_backend(),
        ];

        for profile in default_profiles {
            assert!(
                !profile.rule_ids.contains(&"python.halstead_complexity".to_string()),
                "Profile {} should NOT contain halstead_complexity by default",
                profile.id
            );
            assert!(
                !profile.dimensions.contains(&Dimension::Maintainability),
                "Profile {} should NOT have Maintainability dimension by default",
                profile.id
            );
        }
    }
}
