//! HTTP timeout rule template for cross-language implementation.
//!
//! This module provides a template for implementing HTTP timeout rules
//! across multiple programming languages.

use crate::semantics::common::http::{HttpCall, HttpClientLibrary};

/// HTTP timeout rule template
pub struct HttpTimeoutTemplate {
    /// Minimum recommended timeout in seconds
    pub min_timeout: f64,
    /// Maximum recommended timeout in seconds  
    pub max_timeout: f64,
}

impl Default for HttpTimeoutTemplate {
    fn default() -> Self {
        Self {
            min_timeout: 5.0,
            max_timeout: 120.0,
        }
    }
}

impl HttpTimeoutTemplate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check if an HTTP call needs a timeout
    pub fn needs_timeout(&self, call: &HttpCall) -> bool {
        !call.has_timeout
    }

    /// Check if a timeout value is reasonable
    pub fn is_reasonable_timeout(&self, timeout: f64) -> bool {
        timeout >= self.min_timeout && timeout <= self.max_timeout
    }

    /// Get the suggested timeout for a library
    pub fn suggested_timeout(&self, library: &HttpClientLibrary) -> f64 {
        match library {
            // Sync libraries - shorter timeout by default
            HttpClientLibrary::Requests => 30.0,
            HttpClientLibrary::Urllib3 => 30.0,

            // Async libraries - can handle longer timeouts
            HttpClientLibrary::Httpx => 30.0,
            HttpClientLibrary::Aiohttp => 30.0,
            HttpClientLibrary::Reqwest => 30.0,
            HttpClientLibrary::Axios => 30.0,
            HttpClientLibrary::Got => 30.0,

            // Java - typically longer timeouts
            HttpClientLibrary::RestTemplate => 60.0,
            HttpClientLibrary::WebClient => 30.0,
            HttpClientLibrary::OkHttp => 30.0,
            HttpClientLibrary::HttpClient => 30.0,

            // Go - net/http default is no timeout!
            HttpClientLibrary::NetHttp => 30.0,
            HttpClientLibrary::Resty => 30.0,

            // Rust clients
            HttpClientLibrary::Hyper => 30.0,
            HttpClientLibrary::Ureq => 30.0,

            // Browser APIs
            HttpClientLibrary::Fetch => 30.0,
            HttpClientLibrary::NodeFetch => 30.0,

            _ => 30.0,
        }
    }

    /// Get the timeout parameter name for a library/language
    pub fn timeout_param_name(&self, library: &HttpClientLibrary) -> &'static str {
        match library {
            // Python
            HttpClientLibrary::Requests | HttpClientLibrary::Httpx => "timeout",
            HttpClientLibrary::Aiohttp => "timeout",
            HttpClientLibrary::Urllib3 => "timeout",

            // Go
            HttpClientLibrary::NetHttp => "Timeout", // client.Timeout
            HttpClientLibrary::Resty => "SetTimeout",

            // Rust
            HttpClientLibrary::Reqwest => "timeout",
            HttpClientLibrary::Hyper => "timeout",
            HttpClientLibrary::Ureq => "timeout",

            // TypeScript/JavaScript
            HttpClientLibrary::Axios => "timeout",
            HttpClientLibrary::Got => "timeout",
            HttpClientLibrary::Fetch | HttpClientLibrary::NodeFetch => "signal",

            // Java
            HttpClientLibrary::RestTemplate => "setConnectTimeout",
            HttpClientLibrary::WebClient => "timeout",
            HttpClientLibrary::OkHttp => "callTimeout",
            HttpClientLibrary::HttpClient => "connectTimeout",

            _ => "timeout",
        }
    }

    /// Generate a Python patch for adding timeout
    pub fn generate_python_patch(&self, call: &HttpCall, timeout: f64) -> Option<PatchSuggestion> {
        let lib = &call.library;
        let param = self.timeout_param_name(lib);

        match lib {
            HttpClientLibrary::Requests | HttpClientLibrary::Httpx => {
                // requests.get(url) -> requests.get(url, timeout=30)
                // httpx.get(url) -> httpx.get(url, timeout=30)
                Some(PatchSuggestion {
                    description: format!("Add {} parameter", param),
                    code_hint: format!("{param}={timeout}"),
                    insertion_point: InsertionPoint::LastArgument,
                })
            }
            HttpClientLibrary::Aiohttp => {
                // aiohttp uses ClientTimeout
                Some(PatchSuggestion {
                    description: "Add timeout using ClientTimeout".into(),
                    code_hint: format!("timeout=aiohttp.ClientTimeout(total={timeout})"),
                    insertion_point: InsertionPoint::LastArgument,
                })
            }
            _ => None,
        }
    }

    /// Generate a Rust patch for adding timeout
    pub fn generate_rust_patch(&self, call: &HttpCall, timeout: f64) -> Option<PatchSuggestion> {
        match call.library {
            HttpClientLibrary::Reqwest => {
                // .timeout(Duration::from_secs(30))
                Some(PatchSuggestion {
                    description: "Chain .timeout() method".into(),
                    code_hint: format!(
                        ".timeout(std::time::Duration::from_secs({}))",
                        timeout as u64
                    ),
                    insertion_point: InsertionPoint::MethodChain,
                })
            }
            HttpClientLibrary::Ureq => Some(PatchSuggestion {
                description: "Chain .timeout() method".into(),
                code_hint: format!(
                    ".timeout(std::time::Duration::from_secs({}))",
                    timeout as u64
                ),
                insertion_point: InsertionPoint::MethodChain,
            }),
            _ => None,
        }
    }

    /// Generate a Go patch for adding timeout
    pub fn generate_go_patch(&self, call: &HttpCall, timeout: f64) -> Option<PatchSuggestion> {
        match call.library {
            HttpClientLibrary::NetHttp => {
                // For net/http, need to use context with timeout
                Some(PatchSuggestion {
                    description: "Use context.WithTimeout for request deadline".into(),
                    code_hint: format!(
                        "ctx, cancel := context.WithTimeout(context.Background(), {}*time.Second)\ndefer cancel()",
                        timeout as u64
                    ),
                    insertion_point: InsertionPoint::BeforeCall,
                })
            }
            HttpClientLibrary::Resty => Some(PatchSuggestion {
                description: "Add SetTimeout to client".into(),
                code_hint: format!(".SetTimeout({}*time.Second)", timeout as u64),
                insertion_point: InsertionPoint::MethodChain,
            }),
            _ => None,
        }
    }

    /// Generate a TypeScript patch for adding timeout
    pub fn generate_typescript_patch(
        &self,
        call: &HttpCall,
        timeout: f64,
    ) -> Option<PatchSuggestion> {
        match call.library {
            HttpClientLibrary::Axios => {
                Some(PatchSuggestion {
                    description: "Add timeout to config".into(),
                    code_hint: format!("timeout: {}", (timeout * 1000.0) as u64), // Axios uses ms
                    insertion_point: InsertionPoint::InConfig,
                })
            }
            HttpClientLibrary::Fetch | HttpClientLibrary::NodeFetch => {
                // Fetch needs AbortController
                Some(PatchSuggestion {
                    description: "Use AbortController with signal".into(),
                    code_hint: format!(
                        "const controller = new AbortController();\nconst timeoutId = setTimeout(() => controller.abort(), {});\ntry {{ ... }} finally {{ clearTimeout(timeoutId); }}",
                        (timeout * 1000.0) as u64
                    ),
                    insertion_point: InsertionPoint::WrapCall,
                })
            }
            HttpClientLibrary::Got => Some(PatchSuggestion {
                description: "Add timeout to options".into(),
                code_hint: format!("timeout: {{ request: {} }}", (timeout * 1000.0) as u64),
                insertion_point: InsertionPoint::InConfig,
            }),
            _ => None,
        }
    }

    /// Generate a Java patch for adding timeout
    pub fn generate_java_patch(&self, call: &HttpCall, timeout: f64) -> Option<PatchSuggestion> {
        let timeout_ms = (timeout * 1000.0) as u64;

        match call.library {
            HttpClientLibrary::HttpClient => Some(PatchSuggestion {
                description: "Set connectTimeout in HttpClient builder".into(),
                code_hint: format!(".connectTimeout(Duration.ofMillis({}))", timeout_ms),
                insertion_point: InsertionPoint::MethodChain,
            }),
            HttpClientLibrary::OkHttp => Some(PatchSuggestion {
                description: "Set callTimeout in OkHttpClient builder".into(),
                code_hint: format!(".callTimeout({}, TimeUnit.MILLISECONDS)", timeout_ms),
                insertion_point: InsertionPoint::MethodChain,
            }),
            HttpClientLibrary::RestTemplate => {
                // RestTemplate needs factory configuration
                Some(PatchSuggestion {
                    description: "Configure timeout via SimpleClientHttpRequestFactory".into(),
                    code_hint: format!(
                        "SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();\nfactory.setConnectTimeout({});\nfactory.setReadTimeout({});",
                        timeout_ms, timeout_ms
                    ),
                    insertion_point: InsertionPoint::BeforeCall,
                })
            }
            HttpClientLibrary::WebClient => Some(PatchSuggestion {
                description: "Use .timeout() on Mono/Flux".into(),
                code_hint: format!(".timeout(Duration.ofMillis({}))", timeout_ms),
                insertion_point: InsertionPoint::MethodChain,
            }),
            _ => None,
        }
    }
}

/// Where to insert the fix in the code
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertionPoint {
    /// Add as the last argument in function call
    LastArgument,
    /// Add as a method chain
    MethodChain,
    /// Add inside a config object
    InConfig,
    /// Insert before the call
    BeforeCall,
    /// Wrap the entire call
    WrapCall,
}

/// A suggested patch for fixing an issue
#[derive(Debug, Clone)]
pub struct PatchSuggestion {
    /// Human-readable description of the patch
    pub description: String,
    /// Code snippet hint
    pub code_hint: String,
    /// Where to insert the fix
    pub insertion_point: InsertionPoint,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::semantics::common::CommonLocation;
    use crate::semantics::common::http::{HttpCallBuilder, HttpMethod};

    fn make_location() -> CommonLocation {
        CommonLocation {
            file_id: FileId(1),
            line: 10,
            column: 5,
            start_byte: 100,
            end_byte: 150,
        }
    }

    fn make_http_call(library: HttpClientLibrary, has_timeout: bool) -> HttpCall {
        HttpCallBuilder::new()
            .library(library)
            .method(HttpMethod::Get)
            .has_timeout(has_timeout)
            .call_text("example call")
            .location(make_location())
            .build()
            .unwrap()
    }

    #[test]
    fn needs_timeout_when_missing() {
        let template = HttpTimeoutTemplate::new();
        let call = make_http_call(HttpClientLibrary::Requests, false);
        assert!(template.needs_timeout(&call));
    }

    #[test]
    fn no_timeout_needed_when_present() {
        let template = HttpTimeoutTemplate::new();
        let call = make_http_call(HttpClientLibrary::Requests, true);
        assert!(!template.needs_timeout(&call));
    }

    #[test]
    fn reasonable_timeout_range() {
        let template = HttpTimeoutTemplate::new();
        assert!(!template.is_reasonable_timeout(1.0)); // Too short
        assert!(template.is_reasonable_timeout(30.0)); // Good
        assert!(!template.is_reasonable_timeout(200.0)); // Too long
    }

    #[test]
    fn python_patch_for_requests() {
        let template = HttpTimeoutTemplate::new();
        let call = make_http_call(HttpClientLibrary::Requests, false);
        let patch = template.generate_python_patch(&call, 30.0);

        assert!(patch.is_some());
        let patch = patch.unwrap();
        assert!(patch.code_hint.contains("timeout=30"));
    }

    #[test]
    fn rust_patch_for_reqwest() {
        let template = HttpTimeoutTemplate::new();
        let call = make_http_call(HttpClientLibrary::Reqwest, false);
        let patch = template.generate_rust_patch(&call, 30.0);

        assert!(patch.is_some());
        let patch = patch.unwrap();
        assert!(patch.code_hint.contains("Duration::from_secs(30)"));
    }

    #[test]
    fn go_patch_for_net_http() {
        let template = HttpTimeoutTemplate::new();
        let call = make_http_call(HttpClientLibrary::NetHttp, false);
        let patch = template.generate_go_patch(&call, 30.0);

        assert!(patch.is_some());
        let patch = patch.unwrap();
        assert!(patch.code_hint.contains("context.WithTimeout"));
    }

    #[test]
    fn typescript_patch_for_axios() {
        let template = HttpTimeoutTemplate::new();
        let call = make_http_call(HttpClientLibrary::Axios, false);
        let patch = template.generate_typescript_patch(&call, 30.0);

        assert!(patch.is_some());
        let patch = patch.unwrap();
        assert!(patch.code_hint.contains("timeout: 30000")); // 30s in ms
    }
}
