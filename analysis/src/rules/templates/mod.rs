//! Cross-language rule templates for common patterns.
//!
//! This module provides template traits and helpers for implementing rules that
//! target common patterns across multiple programming languages. Each template
//! encapsulates the detection logic and patch generation for a specific pattern.

pub mod http_timeout;
pub mod retry;
pub mod structured_logging;

use crate::semantics::common::CommonLocation;
use crate::types::context::Dimension;
use crate::types::finding::{Finding, FindingKind, Severity};

/// Result of a template-based rule check
#[derive(Debug)]
pub struct TemplateCheckResult {
    /// Finding message
    pub message: String,
    /// Additional diagnostic info
    pub diagnostic: Option<String>,
    /// Location in source
    pub location: CommonLocation,
    /// Suggested fix description
    pub fix_description: Option<String>,
}

impl TemplateCheckResult {
    pub fn new(message: impl Into<String>, location: CommonLocation) -> Self {
        Self {
            message: message.into(),
            diagnostic: None,
            location,
            fix_description: None,
        }
    }

    pub fn with_diagnostic(mut self, diagnostic: impl Into<String>) -> Self {
        self.diagnostic = Some(diagnostic.into());
        self
    }

    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix_description = Some(fix.into());
        self
    }

    /// Convert to a Finding
    pub fn into_finding(
        self,
        rule_id: impl Into<String>,
        file_path: impl Into<String>,
        severity: Severity,
        dimension: Dimension,
    ) -> Finding {
        let rule_id_str = rule_id.into();
        let file_path_str = file_path.into();
        let applicability = crate::rules::metadata::applicability_for_rule_id(&rule_id_str);
        let fix_preview = if let Some(diag) = self.diagnostic {
            Some(format!(
                "{}\n\nDiagnostic: {}",
                self.fix_description.unwrap_or_default(),
                diag
            ))
        } else {
            self.fix_description
        };

        Finding {
            id: format!("{}:{}:{}", rule_id_str, file_path_str, self.location.line),
            rule_id: rule_id_str,
            kind: FindingKind::StabilityRisk,
            title: self.message.clone(),
            description: self.message,
            severity,
            confidence: 0.9,
            dimension,
            applicability,
            file_path: file_path_str,
            line: Some(self.location.line),
            column: Some(self.location.column),
            end_line: None,
            end_column: None,
            byte_range: None,
            diff: None,
            fix_preview,
        }
    }
}

/// Trait for language-specific HTTP timeout configurations
pub trait HttpTimeoutConfig {
    /// Get the timeout parameter name for this language/library
    fn timeout_param_name(&self, library: &str) -> &'static str;

    /// Get the default timeout value suggestion
    fn default_timeout(&self) -> f64 {
        30.0
    }

    /// Generate a patch for adding timeout to an HTTP call
    fn generate_timeout_patch(
        &self,
        call_text: &str,
        library: &str,
        timeout: f64,
    ) -> Option<String>;
}

/// Trait for language-specific retry configurations
pub trait RetryConfig {
    /// Get the retry decorator/wrapper name for this language
    fn retry_decorator_name(&self) -> &'static str;

    /// Generate code to wrap a function with retry logic
    fn generate_retry_wrapper(
        &self,
        max_attempts: u32,
        backoff_factor: f64,
        retryable_exceptions: &[&str],
    ) -> String;
}

/// Trait for language-specific structured logging
pub trait StructuredLoggingConfig {
    /// Get the logging library for this language
    fn logging_library(&self) -> &'static str;

    /// Generate structured log statement
    fn generate_log_statement(
        &self,
        level: &str,
        message: &str,
        context_vars: &[(&str, &str)],
    ) -> String;
}

/// Common patterns that can be detected across languages
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommonPattern {
    /// HTTP call without timeout
    HttpMissingTimeout,
    /// HTTP call without retry
    HttpMissingRetry,
    /// Database query without timeout
    DbMissingTimeout,
    /// Missing structured logging
    MissingStructuredLogging,
    /// Missing correlation ID
    MissingCorrelationId,
    /// Unbounded collection/buffer
    UnboundedCollection,
    /// Missing error handling in async code
    AsyncMissingErrorHandling,
    /// SQL injection risk
    SqlInjection,
    /// Missing input validation
    MissingInputValidation,
    /// Unbounded retry without backoff
    UnboundedRetry,
    /// Missing circuit breaker
    MissingCircuitBreaker,
}

impl CommonPattern {
    /// Get the rule ID for this pattern
    pub fn rule_id(&self) -> &'static str {
        match self {
            Self::HttpMissingTimeout => "HTTP_MISSING_TIMEOUT",
            Self::HttpMissingRetry => "HTTP_MISSING_RETRY",
            Self::DbMissingTimeout => "DB_MISSING_TIMEOUT",
            Self::MissingStructuredLogging => "MISSING_STRUCTURED_LOGGING",
            Self::MissingCorrelationId => "MISSING_CORRELATION_ID",
            Self::UnboundedCollection => "UNBOUNDED_COLLECTION",
            Self::AsyncMissingErrorHandling => "ASYNC_MISSING_ERROR_HANDLING",
            Self::SqlInjection => "SQL_INJECTION",
            Self::MissingInputValidation => "MISSING_INPUT_VALIDATION",
            Self::UnboundedRetry => "UNBOUNDED_RETRY",
            Self::MissingCircuitBreaker => "MISSING_CIRCUIT_BREAKER",
        }
    }

    /// Get the severity for this pattern
    pub fn severity(&self) -> Severity {
        match self {
            Self::SqlInjection => Severity::High,
            Self::UnboundedRetry | Self::HttpMissingTimeout | Self::DbMissingTimeout => {
                Severity::Medium
            }
            _ => Severity::Low,
        }
    }

    /// Get the dimension this pattern affects
    pub fn dimension(&self) -> &'static str {
        match self {
            Self::HttpMissingTimeout | Self::DbMissingTimeout | Self::UnboundedRetry => {
                "reliability"
            }
            Self::HttpMissingRetry | Self::MissingCircuitBreaker => "availability",
            Self::MissingStructuredLogging | Self::MissingCorrelationId => "observability",
            Self::UnboundedCollection | Self::AsyncMissingErrorHandling => "stability",
            Self::SqlInjection | Self::MissingInputValidation => "security",
        }
    }
}
