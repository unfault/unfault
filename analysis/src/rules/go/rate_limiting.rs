//! Rule: Rate limiting in Go
//!
//! Detects HTTP handlers without rate limiting protection.

use std::sync::Arc;
use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::cors_policy;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects HTTP handlers without rate limiting.
#[derive(Debug, Default)]
pub struct GoRateLimitingRule;

impl GoRateLimitingRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoRateLimitingRule {
    fn id(&self) -> &'static str {
        "go.rate_limiting"
    }

    fn name(&self) -> &'static str {
        "Missing rate limiting"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(cors_policy())
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

            // Check for rate limiter imports
            let has_rate_limiter = go.imports.iter().any(|imp| {
                imp.path.contains("rate") ||
                imp.path.contains("limiter") ||
                imp.path.contains("tollbooth") ||
                imp.path.contains("throttle") ||
                imp.path.contains("uber-go/ratelimit") ||
                imp.path.contains("ulule/limiter") ||
                imp.path.contains("didip/tollbooth")
            });

            if has_rate_limiter {
                continue; // File uses rate limiting
            }

            // Check for rate limiting patterns in calls
            let has_rate_pattern = go.calls.iter().any(|call| {
                call.function_call.callee_expr.contains("rate.NewLimiter") ||
                call.function_call.callee_expr.contains("RateLimit") ||
                call.function_call.callee_expr.contains("rateLimit")
            });

            if has_rate_pattern {
                continue;
            }

            // Check HTTP handlers (functions with http.ResponseWriter parameter)
            for func in &go.functions {
                let is_http_handler = func.params.iter().any(|p| {
                    p.param_type.contains("http.ResponseWriter") ||
                    p.param_type.contains("*gin.Context") ||
                    p.param_type.contains("echo.Context") ||
                    p.param_type.contains("*fiber.Ctx")
                });

                if is_http_handler {
                    let line = func.location.range.start_line + 1;
                    let column = func.location.range.start_col + 1;
                    
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: format!("HTTP handler '{}' without rate limiting", func.name),
                        description: Some(
                            "HTTP endpoints without rate limiting are vulnerable to abuse \
                             and denial-of-service attacks. Implement rate limiting using \
                             golang.org/x/time/rate or a middleware like tollbooth.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.70,
                        dimension: Dimension::Scalability,
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
                                range: PatchRange::InsertBeforeLine { line: 1 },
                                replacement: 
"// Add rate limiting middleware:
// import \"golang.org/x/time/rate\"
// 
// var limiter = rate.NewLimiter(rate.Limit(100), 200) // 100 req/sec, burst 200
// 
// func rateLimitMiddleware(next http.Handler) http.Handler {
//     return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//         if !limiter.Allow() {
//             http.Error(w, \"Too Many Requests\", http.StatusTooManyRequests)
//             return
//         }
//         next.ServeHTTP(w, r)
//     })
// }".to_string(),
                            }],
                        }),
                        fix_preview: Some("Add rate limiting middleware".to_string()),
                        tags: vec!["go".into(), "http".into(), "security".into(), "rate-limit".into()],
                    });
                    break; // One finding per file
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_metadata() {
        let rule = GoRateLimitingRule::new();
        assert_eq!(rule.id(), "go.rate_limiting");
        assert!(!rule.name().is_empty());
    }
}