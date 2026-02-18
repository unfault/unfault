//! Structured logging rule template for cross-language implementation.
//!
//! This module provides a template for implementing structured logging rules
//! across multiple programming languages.

/// Structured logging template
#[derive(Debug, Clone)]
pub struct StructuredLoggingTemplate {
    /// Required context fields for production logging
    pub required_fields: Vec<String>,
    /// Recommended logging libraries by language
    pub recommended_libraries: Vec<(&'static str, &'static str)>,
}

impl Default for StructuredLoggingTemplate {
    fn default() -> Self {
        Self {
            required_fields: vec![
                "correlation_id".into(),
                "request_id".into(),
                "timestamp".into(),
            ],
            recommended_libraries: vec![
                ("python", "structlog"),
                ("go", "zap"),
                ("rust", "tracing"),
                ("typescript", "pino"),
                ("java", "logback with JSON encoder"),
            ],
        }
    }
}

impl StructuredLoggingTemplate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the recommended logging library for a language
    pub fn recommended_library(&self, language: &str) -> Option<&'static str> {
        self.recommended_libraries
            .iter()
            .find(|(lang, _)| *lang == language)
            .map(|(_, lib)| *lib)
    }

    /// Generate Python structured logging setup
    pub fn python_setup(&self) -> LoggingSetup {
        LoggingSetup {
            imports: vec![
                "import structlog".into(),
                "from structlog.stdlib import LoggerFactory".into(),
            ],
            configuration: r#"
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer()
    ],
    logger_factory=LoggerFactory(),
)
logger = structlog.get_logger()
"#
            .into(),
            log_example: r#"
logger.info(
    "request_processed",
    correlation_id=correlation_id,
    user_id=user_id,
    duration_ms=duration,
)
"#
            .into(),
        }
    }

    /// Generate Go structured logging setup
    pub fn go_setup(&self) -> LoggingSetup {
        LoggingSetup {
            imports: vec![r#"import "go.uber.org/zap""#.into()],
            configuration: r#"
logger, _ := zap.NewProduction()
defer logger.Sync()
sugar := logger.Sugar()
"#
            .into(),
            log_example: r#"
sugar.Infow("request_processed",
    "correlation_id", correlationID,
    "user_id", userID,
    "duration_ms", duration,
)
"#
            .into(),
        }
    }

    /// Generate Rust structured logging setup
    pub fn rust_setup(&self) -> LoggingSetup {
        LoggingSetup {
            imports: vec![
                "use tracing::{info, span, Level};".into(),
                "use tracing_subscriber::fmt::format::FmtSpan;".into(),
            ],
            configuration: r#"
tracing_subscriber::fmt()
    .json()
    .with_span_events(FmtSpan::CLOSE)
    .init();
"#
            .into(),
            log_example: r#"
let span = span!(Level::INFO, "request", correlation_id = %correlation_id);
let _enter = span.enter();

info!(
    user_id = %user_id,
    duration_ms = duration,
    "request_processed"
);
"#
            .into(),
        }
    }

    /// Generate TypeScript structured logging setup
    pub fn typescript_setup(&self) -> LoggingSetup {
        LoggingSetup {
            imports: vec!["import pino from 'pino';".into()],
            configuration: r#"
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  formatters: {
    level(label) {
      return { level: label };
    },
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});
"#
            .into(),
            log_example: r#"
logger.info({
  correlationId,
  userId,
  durationMs: duration,
}, 'request_processed');
"#
            .into(),
        }
    }

    /// Generate Java structured logging setup (Logback with JSON)
    pub fn java_setup(&self) -> LoggingSetup {
        LoggingSetup {
            imports: vec![
                "import org.slf4j.Logger;".into(),
                "import org.slf4j.LoggerFactory;".into(),
                "import net.logstash.logback.argument.StructuredArguments;".into(),
            ],
            configuration: r#"
<!-- logback.xml -->
<configuration>
  <appender name="JSON" class="ch.qos.logback.core.ConsoleAppender">
    <encoder class="net.logstash.logback.encoder.LogstashEncoder"/>
  </appender>
  <root level="INFO">
    <appender-ref ref="JSON"/>
  </root>
</configuration>
"#
            .into(),
            log_example: r#"
logger.info("request_processed",
    StructuredArguments.kv("correlationId", correlationId),
    StructuredArguments.kv("userId", userId),
    StructuredArguments.kv("durationMs", duration)
);
"#
            .into(),
        }
    }

    /// Check if a log statement uses structured logging
    pub fn is_structured(&self, log_text: &str) -> bool {
        // Heuristics for detecting structured logging
        let structured_patterns = [
            // Python structlog
            "structlog",
            "logger.info(",
            "logger.error(",
            // Key-value patterns
            "=",
            // JSON-like patterns
            "{",
            // Go zap
            "Infow(",
            "Errorw(",
            "With(",
            // Rust tracing
            "info!(",
            "error!(",
            "span!(",
        ];

        // Check for print/printf patterns (not structured)
        let unstructured_patterns = [
            "print(",
            "println!(",
            "fmt.Print",
            "console.log(",
            "System.out.print",
            "%s",
            "%d",
            "f\"",
            "f'",
        ];

        let has_structured = structured_patterns.iter().any(|p| log_text.contains(p));
        let has_unstructured = unstructured_patterns.iter().any(|p| log_text.contains(p));

        has_structured && !has_unstructured
    }

    /// Check if a log statement includes correlation ID
    pub fn has_correlation_id(&self, log_text: &str) -> bool {
        let correlation_patterns = [
            "correlation_id",
            "correlationId",
            "correlation-id",
            "request_id",
            "requestId",
            "request-id",
            "trace_id",
            "traceId",
            "trace-id",
            "x-request-id",
        ];

        correlation_patterns
            .iter()
            .any(|p| log_text.to_lowercase().contains(&p.to_lowercase()))
    }
}

/// Logging setup code for a language
#[derive(Debug, Clone)]
pub struct LoggingSetup {
    /// Import statements needed
    pub imports: Vec<String>,
    /// Configuration code
    pub configuration: String,
    /// Example log statement
    pub log_example: String,
}

/// Log level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl LogLevel {
    /// Parse log level from common patterns
    pub fn from_str(s: &str) -> Option<Self> {
        let s = s.to_lowercase();
        if s.contains("trace") || s.contains("verbose") {
            Some(Self::Trace)
        } else if s.contains("debug") {
            Some(Self::Debug)
        } else if s.contains("info") {
            Some(Self::Info)
        } else if s.contains("warn") {
            Some(Self::Warn)
        } else if s.contains("error") || s.contains("err") {
            Some(Self::Error)
        } else if s.contains("fatal") || s.contains("critical") || s.contains("panic") {
            Some(Self::Fatal)
        } else {
            None
        }
    }

    /// Check if this level should have structured context
    pub fn needs_context(&self) -> bool {
        matches!(self, Self::Info | Self::Warn | Self::Error | Self::Fatal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recommended_library_by_language() {
        let template = StructuredLoggingTemplate::new();
        assert_eq!(template.recommended_library("python"), Some("structlog"));
        assert_eq!(template.recommended_library("go"), Some("zap"));
        assert_eq!(template.recommended_library("rust"), Some("tracing"));
    }

    #[test]
    fn detect_structured_logging() {
        let template = StructuredLoggingTemplate::new();

        // Structured patterns
        assert!(template.is_structured("logger.info('event', user_id=123)"));
        assert!(template.is_structured("sugar.Infow('event', 'key', value)"));

        // Unstructured patterns
        assert!(!template.is_structured("print(f'User {user_id}')"));
        assert!(!template.is_structured("console.log('something')"));
    }

    #[test]
    fn detect_correlation_id() {
        let template = StructuredLoggingTemplate::new();

        assert!(template.has_correlation_id("logger.info('x', correlation_id=cid)"));
        assert!(template.has_correlation_id("correlationId: uuid"));
        assert!(template.has_correlation_id("request_id=rid"));
        assert!(!template.has_correlation_id("logger.info('no id')"));
    }

    #[test]
    fn log_level_parsing() {
        assert_eq!(LogLevel::from_str("logger.info"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("log.Error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_str("DEBUG:"), Some(LogLevel::Debug));
    }

    #[test]
    fn log_level_needs_context() {
        assert!(!LogLevel::Trace.needs_context());
        assert!(!LogLevel::Debug.needs_context());
        assert!(LogLevel::Info.needs_context());
        assert!(LogLevel::Error.needs_context());
    }
}
