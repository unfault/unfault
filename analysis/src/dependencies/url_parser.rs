//! URL extraction from code call expressions.
//!
//! This module provides utilities for extracting URLs from code constructs
//! like function call arguments.

use regex::Regex;
use std::sync::LazyLock;

/// Regex patterns for extracting URLs from code.
static URL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        # Match URL-like strings in quotes
        ['"]
        (
            # Standard URLs with scheme
            (?:https?|postgres(?:ql)?|mysql|redis(?:s)?|mongodb(?:\+srv)?|amqp(?:s)?|grpc(?:s)?|ws(?:s)?|kafka|sqlite)
            ://
            [^'"]+
        |
            # Environment variable references
            (?:\$\{[A-Z_][A-Z0-9_]*\}|\$[A-Z_][A-Z0-9_]*)
        )
        ['"]
        |
        # Python os.environ/os.getenv patterns
        os\.(?:environ\s*\[\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*\]|getenv\s*\(\s*['"]([A-Z_][A-Z0-9_]*)['"])
        |
        # Go os.Getenv pattern
        os\.Getenv\s*\(\s*["']([A-Z_][A-Z0-9_]*)["']\s*\)
        |
        # Rust env::var pattern
        (?:std::)?env::var\s*\(\s*["']([A-Z_][A-Z0-9_]*)["']\s*\)
        |
        # TypeScript/JavaScript process.env pattern
        process\.env\.([A-Z_][A-Z0-9_]*)
        "#,
    )
    .expect("URL regex should compile")
});

/// f-string/template URL pattern for Python, Go, TypeScript
static FSTRING_URL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?x)
        # Python f-string: f"https://...{var}..."
        f['"]([^'"]*\{[^}]+\}[^'"]*)['"']
        |
        # Go template literal: fmt.Sprintf("https://...%s...", var)
        fmt\.Sprintf\s*\(\s*["']([^"']+)["']
        |
        # JavaScript template literal: `https://...${var}...`
        [`]([^`]*\$\{[^}]+\}[^`]*)[`]
        "#,
    )
    .expect("f-string URL regex should compile")
});

/// Result of URL extraction from call text.
#[derive(Debug, Clone, PartialEq)]
pub struct ExtractedUrl {
    /// The extracted URL or environment variable reference.
    pub raw_value: String,
    /// Whether this is a dynamic URL (contains variables).
    pub is_dynamic: bool,
}

/// Extract URL from a function call expression text.
///
/// This function attempts to extract URL-like strings from code patterns like:
/// - `requests.get("https://api.example.com")`
/// - `http.Get(os.Getenv("API_URL"))`
/// - `fetch(f"https://api.example.com/{path}")`
/// - `redis.NewClient(&redis.Options{Addr: "localhost:6379"})`
///
/// Returns the first URL-like string found, or None if no URL is detected.
pub fn extract_url_from_call(call_text: &str) -> Option<ExtractedUrl> {
    // Try direct URL patterns first
    if let Some(caps) = URL_PATTERN.captures(call_text) {
        // Try each capture group
        // Groups 1: URL in quotes or env var syntax like ${VAR}
        // Groups 2-6: Environment variable names extracted from os.environ, os.getenv, etc.
        for i in 1..=6 {
            if let Some(m) = caps.get(i) {
                let value = m.as_str().to_string();
                // Groups 2-6 are env var names, so they're always dynamic
                // Group 1 is dynamic only if the value itself contains dynamic patterns
                let is_dynamic = i > 1 || is_dynamic_value(&value);
                return Some(ExtractedUrl {
                    raw_value: value,
                    is_dynamic,
                });
            }
        }
    }

    // Try f-string/template patterns
    if let Some(caps) = FSTRING_URL_PATTERN.captures(call_text) {
        for i in 1..=3 {
            if let Some(m) = caps.get(i) {
                let value = m.as_str().to_string();
                return Some(ExtractedUrl {
                    raw_value: value,
                    is_dynamic: true, // f-strings are always dynamic
                });
            }
        }
    }

    // Try to find quoted strings that look like URLs
    extract_simple_quoted_url(call_text)
}

/// Extract a simple quoted URL from text.
fn extract_simple_quoted_url(text: &str) -> Option<ExtractedUrl> {
    // Find quoted strings
    let mut in_quote = false;
    let mut quote_char = '"';
    let mut start = 0;

    for (i, c) in text.char_indices() {
        if !in_quote && (c == '"' || c == '\'') {
            in_quote = true;
            quote_char = c;
            start = i + 1;
        } else if in_quote && c == quote_char {
            let potential_url = &text[start..i];
            if looks_like_url(potential_url) {
                return Some(ExtractedUrl {
                    raw_value: potential_url.to_string(),
                    is_dynamic: is_dynamic_value(potential_url),
                });
            }
            in_quote = false;
        }
    }

    None
}

/// Check if a string looks like a URL or connection string.
fn looks_like_url(s: &str) -> bool {
    let lower = s.to_lowercase();

    // Check for URL schemes
    if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("postgres://")
        || lower.starts_with("postgresql://")
        || lower.starts_with("mysql://")
        || lower.starts_with("redis://")
        || lower.starts_with("rediss://")
        || lower.starts_with("mongodb://")
        || lower.starts_with("mongodb+srv://")
        || lower.starts_with("amqp://")
        || lower.starts_with("amqps://")
        || lower.starts_with("grpc://")
        || lower.starts_with("grpcs://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://")
        || lower.starts_with("kafka://")
        || lower.starts_with("sqlite://")
    {
        return true;
    }

    // Check for host:port pattern (e.g., "localhost:6379")
    if s.contains(':') && !s.contains(' ') && !s.starts_with(':') {
        let parts: Vec<&str> = s.rsplitn(2, ':').collect();
        if parts.len() == 2 {
            if let Ok(port) = parts[0].parse::<u16>() {
                // Common ports for network services
                // Common ports for network services
                // Note: 5432 (PostgreSQL), 3306 (MySQL) are covered by ranges
                if matches!(
                    port,
                    80 | 443
                        | 3000..=3999  // includes MySQL 3306
                        | 5000..=5999  // includes PostgreSQL 5432
                        | 6379         // Redis
                        | 8000..=8999  // common dev servers
                        | 27017        // MongoDB
                        | 9092         // Kafka
                        | 11211        // Memcached
                        | 9200         // Elasticsearch
                        | 50051        // gRPC
                ) {
                    return true;
                }
            }
        }
    }

    // Check for domain-like patterns
    if s.contains('.') && !s.contains(' ') && s.len() > 4 {
        // Likely a domain name
        return true;
    }

    false
}

/// Check if a value is dynamic (contains variable references).
fn is_dynamic_value(value: &str) -> bool {
    value.contains("${")
        || value.contains("$ENV")
        || value.contains("os.environ")
        || value.contains("os.getenv")
        || value.contains("os.Getenv")
        || value.contains("process.env")
        || value.contains("env::var")
        || value.contains("env!")
        || value.contains("{") // f-string interpolation
        || (value.contains('$') && !value.contains("://"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== extract_url_from_call Tests ====================

    #[test]
    fn test_extract_https_url() {
        let result = extract_url_from_call("requests.get('https://api.example.com/users')");
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(extracted.raw_value, "https://api.example.com/users");
        assert!(!extracted.is_dynamic);
    }

    #[test]
    fn test_extract_http_url() {
        let result = extract_url_from_call("http.Get(\"http://localhost:8080/api\")");
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(extracted.raw_value, "http://localhost:8080/api");
        assert!(!extracted.is_dynamic);
    }

    #[test]
    fn test_extract_postgres_url() {
        let result = extract_url_from_call("create_engine('postgres://user:pass@host:5432/mydb')");
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(extracted.raw_value, "postgres://user:pass@host:5432/mydb");
        assert!(!extracted.is_dynamic);
    }

    #[test]
    fn test_extract_redis_url() {
        let result = extract_url_from_call("redis.from_url('redis://localhost:6379/0')");
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(extracted.raw_value, "redis://localhost:6379/0");
        assert!(!extracted.is_dynamic);
    }

    #[test]
    fn test_extract_mongodb_url() {
        let result = extract_url_from_call("MongoClient('mongodb+srv://cluster.example.com/mydb')");
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(
            extracted.raw_value,
            "mongodb+srv://cluster.example.com/mydb"
        );
        assert!(!extracted.is_dynamic);
    }

    #[test]
    fn test_extract_env_var_syntax() {
        let result = extract_url_from_call("create_engine('${DATABASE_URL}')");
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(extracted.raw_value, "${DATABASE_URL}");
        assert!(extracted.is_dynamic);
    }

    #[test]
    fn test_extract_python_os_getenv() {
        let result = extract_url_from_call("create_engine(os.getenv('DATABASE_URL'))");
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(extracted.raw_value, "DATABASE_URL");
        assert!(extracted.is_dynamic);
    }

    #[test]
    fn test_extract_python_os_environ() {
        let result = extract_url_from_call("redis.from_url(os.environ['REDIS_URL'])");
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(extracted.raw_value, "REDIS_URL");
        assert!(extracted.is_dynamic);
    }

    #[test]
    fn test_extract_go_os_getenv() {
        let result = extract_url_from_call("sql.Open(\"postgres\", os.Getenv(\"DATABASE_URL\"))");
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(extracted.raw_value, "DATABASE_URL");
        assert!(extracted.is_dynamic);
    }

    #[test]
    fn test_extract_host_port() {
        let result =
            extract_url_from_call("redis.NewClient(&redis.Options{Addr: \"localhost:6379\"})");
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert_eq!(extracted.raw_value, "localhost:6379");
        assert!(!extracted.is_dynamic);
    }

    #[test]
    fn test_extract_domain_only() {
        let result = extract_url_from_call("httpx.get('https://api.stripe.com/v1/charges')");
        assert!(result.is_some());
        let extracted = result.unwrap();
        assert!(extracted.raw_value.contains("stripe.com"));
    }

    #[test]
    fn test_no_url_in_text() {
        let result = extract_url_from_call("print('hello world')");
        assert!(result.is_none());
    }

    #[test]
    fn test_empty_string() {
        let result = extract_url_from_call("");
        assert!(result.is_none());
    }

    // ==================== looks_like_url Tests ====================

    #[test]
    fn test_looks_like_url_https() {
        assert!(looks_like_url("https://example.com"));
    }

    #[test]
    fn test_looks_like_url_postgres() {
        assert!(looks_like_url("postgres://user:pass@host:5432/db"));
    }

    #[test]
    fn test_looks_like_url_redis_port() {
        assert!(looks_like_url("localhost:6379"));
    }

    #[test]
    fn test_looks_like_url_postgres_port() {
        assert!(looks_like_url("db.internal:5432"));
    }

    #[test]
    fn test_looks_like_url_domain() {
        assert!(looks_like_url("api.example.com"));
    }

    #[test]
    fn test_not_url_simple_text() {
        assert!(!looks_like_url("hello world"));
    }

    #[test]
    fn test_not_url_number() {
        assert!(!looks_like_url("12345"));
    }

    // ==================== is_dynamic_value Tests ====================

    #[test]
    fn test_is_dynamic_env_var() {
        assert!(is_dynamic_value("${DATABASE_URL}"));
    }

    #[test]
    fn test_is_dynamic_python_os_environ() {
        assert!(is_dynamic_value("os.environ['VAR']"));
    }

    #[test]
    fn test_is_dynamic_fstring() {
        assert!(is_dynamic_value("https://api.example.com/{path}"));
    }

    #[test]
    fn test_not_dynamic_static_url() {
        assert!(!is_dynamic_value("https://api.example.com"));
    }
}
