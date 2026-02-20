//! Rule: Synchronous DNS lookup in Go
//!
//! Detects blocking DNS lookups that can cause latency issues.

use async_trait::async_trait;
use std::sync::Arc;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::timeout;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects synchronous DNS lookups.
#[derive(Debug, Default)]
pub struct GoSyncDnsLookupRule;

impl GoSyncDnsLookupRule {
    pub fn new() -> Self {
        Self
    }

    /// Check if a function looks like an HTTP handler based on its parameters
    fn is_http_handler(func: &crate::semantics::go::model::GoFunction) -> bool {
        func.params.iter().any(|p| {
            p.param_type.contains("http.ResponseWriter")
                || p.param_type.contains("*gin.Context")
                || p.param_type.contains("echo.Context")
                || p.param_type.contains("*fiber.Ctx")
        }) || func.name.to_lowercase().contains("handler")
    }
}

#[async_trait]
impl Rule for GoSyncDnsLookupRule {
    fn id(&self) -> &'static str {
        "go.sync_dns_lookup"
    }

    fn name(&self) -> &'static str {
        "Synchronous DNS lookup"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(timeout())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Check if file has HTTP handlers
            let has_handlers = go.functions.iter().any(|f| Self::is_http_handler(f));

            for call in &go.calls {
                let callee = &call.function_call.callee_expr;

                // Check for DNS lookup calls
                let is_dns_lookup = callee == "net.LookupHost"
                    || callee == "net.LookupIP"
                    || callee == "net.LookupAddr"
                    || callee == "net.LookupCNAME"
                    || callee == "net.LookupMX"
                    || callee == "net.LookupNS"
                    || callee == "net.LookupSRV"
                    || callee == "net.LookupTXT";

                if !is_dns_lookup {
                    continue;
                }

                let line = call.function_call.location.line;
                let column = call.function_call.location.column;

                // Check if in HTTP handler (latency sensitive)
                if has_handlers {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "DNS lookup in HTTP handler context".to_string(),
                        description: Some(
                            "DNS lookups can block for seconds or timeout. In HTTP handlers, \
                             this adds unpredictable latency. Consider caching DNS results \
                             or resolving hosts at startup."
                                .to_string(),
                        ),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        dimension: Dimension::Performance,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: Some(column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: "// Cache DNS results or resolve at startup:
// 
// Option 1: Resolve at initialization
// var serverIPs []net.IP
// func init() {
//     ips, err := net.LookupIP(\"remote-host\")
//     if err != nil { log.Fatal(err) }
//     serverIPs = ips
// }
// 
// Option 2: Use caching DNS resolver
// import \"github.com/rs/dnscache\"
// resolver := &dnscache.Resolver{}
// go resolver.Refresh(time.Hour)
// ips, _ := resolver.LookupHost(ctx, \"remote-host\")"
                                    .to_string(),
                            }],
                        }),
                        fix_preview: Some("Cache DNS results".to_string()),
                        tags: vec![
                            "go".into(),
                            "dns".into(),
                            "performance".into(),
                            "latency".into(),
                        ],
                    });
                }

                // Check for DNS lookup without timeout/context
                // These functions don't accept context and can block indefinitely
                let uses_context_resolver =
                    callee.contains("Resolver") || callee == "net.LookupIPAddr"; // LookupIPAddr has context version

                if !uses_context_resolver {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "DNS lookup without timeout".to_string(),
                        description: Some(
                            "net.LookupHost and similar functions don't accept a context \
                             and can block indefinitely. Use net.Resolver with context \
                             for timeout control."
                                .to_string(),
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.80,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: Some(column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: "// Use Resolver with context for timeout control:
// resolver := &net.Resolver{}
// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// defer cancel()
// ips, err := resolver.LookupIPAddr(ctx, \"hostname\")"
                                    .to_string(),
                            }],
                        }),
                        fix_preview: Some("Use Resolver with context".to_string()),
                        tags: vec!["go".into(), "dns".into(), "timeout".into()],
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::{AstLocation, TextRange};
    use crate::semantics::go::model::GoFunction;

    #[test]
    fn test_rule_metadata() {
        let rule = GoSyncDnsLookupRule::new();
        assert_eq!(rule.id(), "go.sync_dns_lookup");
        assert!(!rule.name().is_empty());
    }

    #[test]
    fn test_is_http_handler() {
        let func = GoFunction {
            name: "handleRequest".to_string(),
            params: vec![crate::semantics::go::model::GoParam {
                name: "w".to_string(),
                param_type: "http.ResponseWriter".to_string(),
            }],
            return_types: vec![],
            returns_error: false,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 0,
                },
            },
        };
        assert!(GoSyncDnsLookupRule::is_http_handler(&func));
    }

    #[test]
    fn test_is_not_http_handler() {
        let func = GoFunction {
            name: "processData".to_string(),
            params: vec![],
            return_types: vec![],
            returns_error: false,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 0,
                },
            },
        };
        assert!(!GoSyncDnsLookupRule::is_http_handler(&func));
    }
}
