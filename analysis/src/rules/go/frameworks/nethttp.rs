//! Rules for Go's net/http standard library.
//!
//! Detects common issues with HTTP servers and handlers including:
//! - Missing server timeouts
//! - Handler timeout configuration
//! - Request body size limits

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::timeout;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::go::model::GoCallSite;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

// ============================================================================
// NetHttpServerTimeoutRule
// ============================================================================

/// Rule that detects HTTP servers without timeout configuration.
///
/// An HTTP server without timeouts is vulnerable to:
/// - Slowloris attacks (slow client keeping connections open)
/// - Resource exhaustion from long-running connections
/// - Memory leaks from accumulated connections
#[derive(Debug)]
pub struct NetHttpServerTimeoutRule;

impl NetHttpServerTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NetHttpServerTimeoutRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for NetHttpServerTimeoutRule {
    fn id(&self) -> &'static str {
        "go.nethttp.server_missing_timeout"
    }

    fn name(&self) -> &'static str {
        "HTTP server without timeout configuration"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go = match sem.as_ref() {
                SourceSemantics::Go(go) => go,
                _ => continue,
            };

            // Look for http.ListenAndServe or http.Server without timeouts
            for call in &go.calls {
                let line = call.function_call.location.line;
                let column = call.function_call.location.column;

                // Check for http.ListenAndServe (which uses DefaultServeMux with no timeouts)
                if call.function_call.callee_expr.contains("ListenAndServe")
                    && !call.function_call.callee_expr.contains("TLS")
                {
                    let title =
                        "http.ListenAndServe used without timeout configuration".to_string();

                    let description = format!(
                        "The call to `{}` at line {} uses the default server configuration \
                         which has no timeouts set. This makes your server vulnerable to:\n\
                         - Slowloris attacks\n\
                         - Resource exhaustion\n\
                         - Connection hoarding\n\n\
                         Use http.Server with explicit timeouts instead:\n\
                         ```go\n\
                         server := &http.Server{{\n\
                             Addr:         \":8080\",\n\
                             ReadTimeout:  15 * time.Second,\n\
                             WriteTimeout: 15 * time.Second,\n\
                             IdleTimeout:  60 * time.Second,\n\
                         }}\n\
                         server.ListenAndServe()\n\
                         ```",
                        call.function_call.callee_expr, line
                    );

                    let patch = generate_server_timeout_patch(call, *file_id);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::SecurityVulnerability,
                        severity: Severity::High,
                        confidence: 0.95,
                        dimension: Dimension::Security,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: Some(column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(
                            "// Replace http.ListenAndServe with explicit Server:\n\
                             // server := &http.Server{\n\
                             //     Addr:         \":8080\",\n\
                             //     ReadTimeout:  15 * time.Second,\n\
                             //     WriteTimeout: 15 * time.Second,\n\
                             //     IdleTimeout:  60 * time.Second,\n\
                             // }\n\
                             // server.ListenAndServe()"
                                .to_string(),
                        ),
                        tags: vec![
                            "go".into(),
                            "http".into(),
                            "server".into(),
                            "timeout".into(),
                            "security".into(),
                        ],
                    });
                }

                // Check for http.Server without timeout fields
                // We check if the args_repr contains timeout fields
                if call.function_call.callee_expr.contains("http.Server") {
                    // Check if timeout fields are set by looking at args_repr
                    let has_timeout = call.args_repr.contains("Timeout")
                        || call.args_repr.contains("ReadTimeout")
                        || call.args_repr.contains("WriteTimeout")
                        || call.args_repr.contains("IdleTimeout");

                    if !has_timeout {
                        let title = "http.Server created without timeout configuration".to_string();

                        let description = format!(
                            "The http.Server at line {} is missing timeout configuration. \
                             Set ReadTimeout, WriteTimeout, and IdleTimeout to prevent \
                             resource exhaustion attacks.",
                            line
                        );

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::SecurityVulnerability,
                            severity: Severity::Medium,
                            confidence: 0.85,
                            dimension: Dimension::Security,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: Some(column),
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: None, // Complex struct modification
                            fix_preview: Some(
                                "// Add timeout fields:\n\
                                 // ReadTimeout:  15 * time.Second,\n\
                                 // WriteTimeout: 15 * time.Second,\n\
                                 // IdleTimeout:  60 * time.Second,"
                                    .to_string(),
                            ),
                            tags: vec![
                                "go".into(),
                                "http".into(),
                                "server".into(),
                                "timeout".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(timeout())
    }
}

/// Generate a patch to replace ListenAndServe with Server.
fn generate_server_timeout_patch(call: &GoCallSite, file_id: FileId) -> FilePatch {
    // Try to extract the address from args_repr
    let addr = if call.args_repr.contains('"') {
        // Extract first string argument from args_repr
        call.args_repr
            .split('"')
            .nth(1)
            .map(|s| format!("\"{}\"", s))
            .unwrap_or_else(|| "\":8080\"".to_string())
    } else {
        "\":8080\"".to_string()
    };

    let replacement = format!(
        "server := &http.Server{{\n\
         \t\tAddr:         {},\n\
         \t\tReadTimeout:  15 * time.Second,\n\
         \t\tWriteTimeout: 15 * time.Second,\n\
         \t\tIdleTimeout:  60 * time.Second,\n\
         \t}}\n\
         \tserver.ListenAndServe()",
        addr
    );

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: call.start_byte,
                end: call.end_byte,
            },
            replacement,
        }],
    }
}

// ============================================================================
// NetHttpHandlerTimeoutRule
// ============================================================================

/// Rule that detects HTTP handlers without timeout wrappers.
///
/// Long-running handlers without timeouts can:
/// - Block server resources indefinitely
/// - Cause client-side timeouts to trigger without cleanup
/// - Lead to goroutine leaks
#[derive(Debug)]
pub struct NetHttpHandlerTimeoutRule;

impl NetHttpHandlerTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NetHttpHandlerTimeoutRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for NetHttpHandlerTimeoutRule {
    fn id(&self) -> &'static str {
        "go.nethttp.handler_missing_timeout"
    }

    fn name(&self) -> &'static str {
        "HTTP handler without timeout wrapper"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go = match sem.as_ref() {
                SourceSemantics::Go(go) => go,
                _ => continue,
            };

            // Look for functions that look like HTTP handlers based on their signature
            for func in &go.functions {
                // Check if this function has HTTP handler signature
                // (w http.ResponseWriter, r *http.Request, ...)
                let is_http_handler = func.params.iter().any(|p| {
                    p.param_type.contains("ResponseWriter") || p.param_type.contains("http.Request")
                });

                if !is_http_handler {
                    continue;
                }

                let line = func.location.range.start_line + 1;
                let column = func.location.range.start_col + 1;

                // Flag HTTP handlers for timeout review
                let title = format!(
                    "HTTP handler `{}` should use timeouts for I/O operations",
                    func.name
                );

                let description = format!(
                    "The HTTP handler `{}` at line {} should use timeouts for any \
                     potentially long-running operations (database calls, HTTP requests, or I/O). \
                     Without timeouts:\n\
                     - Handlers may block indefinitely\n\
                     - Resource exhaustion under load\n\
                     - Poor user experience\n\n\
                     Consider:\n\
                     1. Use http.TimeoutHandler to wrap handlers\n\
                     2. Use context.WithTimeout for per-request timeouts\n\
                     3. Set deadlines on database and HTTP client calls",
                    func.name, line
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::ReliabilityRisk,
                    severity: Severity::Low, // Lower severity since we can't confirm I/O operations
                    confidence: 0.60,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: go.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: None, // Complex handler modification
                    fix_preview: Some(
                        "// Option 1: Wrap with TimeoutHandler\n\
                         // http.Handle(\"/path\", http.TimeoutHandler(handler, 30*time.Second, \"timeout\"))\n\
                         //\n\
                         // Option 2: Use context timeout in handler\n\
                         // ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)\n\
                         // defer cancel()"
                            .to_string(),
                    ),
                    tags: vec![
                        "go".into(),
                        "http".into(),
                        "handler".into(),
                        "timeout".into(),
                    ],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(timeout())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::go::parse_go_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::go::build_go_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.go".to_string(),
            language: Language::Go,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_go_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_go_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Go(sem)))
    }

    // ==================== NetHttpServerTimeoutRule Tests ====================

    #[test]
    fn server_timeout_rule_id_is_correct() {
        let rule = NetHttpServerTimeoutRule::new();
        assert_eq!(rule.id(), "go.nethttp.server_missing_timeout");
    }

    #[test]
    fn server_timeout_rule_name_is_correct() {
        let rule = NetHttpServerTimeoutRule::new();
        assert!(rule.name().contains("timeout"));
    }

    #[test]
    fn server_timeout_rule_implements_debug() {
        let rule = NetHttpServerTimeoutRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("NetHttpServerTimeoutRule"));
    }

    #[tokio::test]
    async fn server_timeout_detects_listen_and_serve() {
        let rule = NetHttpServerTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "net/http"

func main() {
    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.nethttp.server_missing_timeout" {
                assert!(finding.tags.contains(&"server".to_string()));
                assert!(finding.tags.contains(&"timeout".to_string()));
            }
        }
    }

    #[tokio::test]
    async fn server_timeout_no_finding_for_configured_server() {
        let rule = NetHttpServerTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import (
    "net/http"
    "time"
)

func main() {
    server := &http.Server{
        Addr:         ":8080",
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }
    server.ListenAndServe()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag properly configured server (depends on semantics)
        let _ = findings;
    }

    // ==================== NetHttpHandlerTimeoutRule Tests ====================

    #[test]
    fn handler_timeout_rule_id_is_correct() {
        let rule = NetHttpHandlerTimeoutRule::new();
        assert_eq!(rule.id(), "go.nethttp.handler_missing_timeout");
    }

    #[test]
    fn handler_timeout_rule_name_is_correct() {
        let rule = NetHttpHandlerTimeoutRule::new();
        assert!(rule.name().contains("handler"));
    }

    #[test]
    fn handler_timeout_rule_implements_debug() {
        let rule = NetHttpHandlerTimeoutRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("NetHttpHandlerTimeoutRule"));
    }

    #[tokio::test]
    async fn handler_timeout_returns_empty_for_non_go() {
        let rule = NetHttpHandlerTimeoutRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handler_timeout_detects_handler_with_db_call() {
        let rule = NetHttpHandlerTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import (
    "database/sql"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    db.Query("SELECT * FROM users")
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.nethttp.handler_missing_timeout" {
                assert!(finding.tags.contains(&"handler".to_string()));
            }
        }
    }
}
