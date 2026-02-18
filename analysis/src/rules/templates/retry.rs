//! Retry pattern rule template for cross-language implementation.
//!
//! This module provides a template for implementing retry-related rules
//! across multiple programming languages.

/// Retry configuration template
#[derive(Debug, Clone)]
pub struct RetryTemplate {
    /// Maximum recommended retry attempts
    pub max_attempts: u32,
    /// Minimum recommended backoff in seconds
    pub min_backoff: f64,
    /// Maximum recommended backoff in seconds
    pub max_backoff: f64,
}

impl Default for RetryTemplate {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            min_backoff: 1.0,
            max_backoff: 60.0,
        }
    }
}

impl RetryTemplate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if a retry configuration is reasonable
    pub fn is_reasonable(&self, attempts: u32, backoff: f64) -> bool {
        attempts <= self.max_attempts && backoff >= self.min_backoff && backoff <= self.max_backoff
    }

    /// Get retry decorator/library recommendation for Python
    pub fn python_recommendation(&self) -> RetryRecommendation {
        RetryRecommendation {
            library: "tenacity",
            import_statement: "from tenacity import retry, stop_after_attempt, wait_exponential",
            decorator: format!(
                "@retry(stop=stop_after_attempt({}), wait=wait_exponential(multiplier=1, max={}))",
                self.max_attempts, self.max_backoff as u32
            ),
            retryable_exceptions: vec!["requests.RequestException", "httpx.HTTPError"],
        }
    }

    /// Get retry recommendation for Go
    pub fn go_recommendation(&self) -> RetryRecommendation {
        RetryRecommendation {
            library: "github.com/avast/retry-go",
            import_statement: r#"import "github.com/avast/retry-go""#,
            decorator: format!(
                r#"retry.Do(func() error {{ ... }}, 
    retry.Attempts({}),
    retry.Delay(time.Second),
    retry.MaxDelay({}*time.Second),
)"#,
                self.max_attempts, self.max_backoff as u32
            ),
            retryable_exceptions: vec!["net.Error", "http.ErrServerClosed"],
        }
    }

    /// Get retry recommendation for Rust
    pub fn rust_recommendation(&self) -> RetryRecommendation {
        RetryRecommendation {
            library: "backoff",
            import_statement: "use backoff::{ExponentialBackoff, Error};",
            decorator: format!(
                r#"backoff::retry(ExponentialBackoff::default(), || {{
    // Your operation here
    Ok(())
}})"#
            ),
            retryable_exceptions: vec!["reqwest::Error", "std::io::Error"],
        }
    }

    /// Get retry recommendation for TypeScript
    pub fn typescript_recommendation(&self) -> RetryRecommendation {
        RetryRecommendation {
            library: "p-retry",
            import_statement: "import pRetry from 'p-retry';",
            decorator: format!(
                r#"await pRetry(async () => {{
    // Your operation here
}}, {{ retries: {} }})"#,
                self.max_attempts
            ),
            retryable_exceptions: vec!["Error", "AxiosError"],
        }
    }

    /// Get retry recommendation for Java (Spring)
    pub fn java_recommendation(&self) -> RetryRecommendation {
        RetryRecommendation {
            library: "resilience4j-retry",
            import_statement: "import io.github.resilience4j.retry.Retry;",
            decorator: format!(
                r#"RetryConfig config = RetryConfig.custom()
    .maxAttempts({})
    .waitDuration(Duration.ofSeconds(1))
    .build();
Retry retry = Retry.of("name", config);
Retry.decorateSupplier(retry, () -> yourMethod());"#,
                self.max_attempts
            ),
            retryable_exceptions: vec!["IOException", "HttpClientErrorException"],
        }
    }
}

/// A retry library/pattern recommendation
#[derive(Debug, Clone)]
pub struct RetryRecommendation {
    /// Library to use
    pub library: &'static str,
    /// Import statement
    pub import_statement: &'static str,
    /// Decorator or wrapper code
    pub decorator: String,
    /// Common retryable exceptions
    pub retryable_exceptions: Vec<&'static str>,
}

/// Backoff strategy types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffStrategy {
    /// Fixed delay between retries
    Fixed,
    /// Exponential backoff (recommended)
    Exponential,
    /// Linear backoff
    Linear,
    /// No backoff (dangerous!)
    None,
}

impl BackoffStrategy {
    /// Check if this strategy is safe for production
    pub fn is_safe(&self) -> bool {
        !matches!(self, Self::None | Self::Fixed)
    }

    /// Get a description of why this strategy may be problematic
    pub fn warning(&self) -> Option<&'static str> {
        match self {
            Self::None => Some("No backoff can cause retry storms and overwhelm services"),
            Self::Fixed => Some("Fixed backoff may cause synchronized retries across clients"),
            Self::Linear => None,
            Self::Exponential => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_template_values() {
        let template = RetryTemplate::new();
        assert_eq!(template.max_attempts, 3);
        assert_eq!(template.min_backoff, 1.0);
        assert_eq!(template.max_backoff, 60.0);
    }

    #[test]
    fn reasonable_config() {
        let template = RetryTemplate::new();
        assert!(template.is_reasonable(3, 2.0));
        assert!(!template.is_reasonable(10, 2.0)); // Too many attempts
        assert!(!template.is_reasonable(3, 0.1)); // Too short backoff
    }

    #[test]
    fn python_recommendation_includes_tenacity() {
        let template = RetryTemplate::new();
        let rec = template.python_recommendation();
        assert_eq!(rec.library, "tenacity");
        assert!(rec.import_statement.contains("tenacity"));
    }

    #[test]
    fn backoff_strategy_safety() {
        assert!(BackoffStrategy::Exponential.is_safe());
        assert!(BackoffStrategy::Linear.is_safe());
        assert!(!BackoffStrategy::None.is_safe());
        assert!(!BackoffStrategy::Fixed.is_safe());
    }

    #[test]
    fn backoff_strategy_warnings() {
        assert!(BackoffStrategy::None.warning().is_some());
        assert!(BackoffStrategy::Fixed.warning().is_some());
        assert!(BackoffStrategy::Exponential.warning().is_none());
    }
}
