//! Rule: CPU-intensive operations in hot path in Go
//!
//! Detects CPU-intensive operations in HTTP handlers or critical paths.

use std::sync::Arc;
use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::timeout;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects CPU-intensive operations in hot paths.
#[derive(Debug, Default)]
pub struct GoCpuInHotPathRule;

impl GoCpuInHotPathRule {
    pub fn new() -> Self {
        Self
    }

    /// Check if a function looks like an HTTP handler based on its parameters
    fn is_http_handler(func: &crate::semantics::go::model::GoFunction) -> bool {
        func.params.iter().any(|p| {
            p.param_type.contains("http.ResponseWriter") ||
            p.param_type.contains("*gin.Context") ||
            p.param_type.contains("echo.Context") ||
            p.param_type.contains("*fiber.Ctx")
        }) || func.name.to_lowercase().contains("handler")
    }
}

#[async_trait]
impl Rule for GoCpuInHotPathRule {
    fn id(&self) -> &'static str {
        "go.cpu_in_hot_path"
    }

    fn name(&self) -> &'static str {
        "CPU-intensive operation in hot path"
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

            // Check for CPU-intensive operations in HTTP handlers by looking at call sites
            for call in &go.calls {
                let callee = &call.function_call.callee_expr;
                
                // Check for crypto operations
                if callee.starts_with("bcrypt.") || 
                   callee.starts_with("scrypt.") ||
                   callee.starts_with("argon2.") ||
                   callee.starts_with("pbkdf2.") {
                    let line = call.function_call.location.line;
                    let column = call.function_call.location.column;
                    
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "CPU-intensive hash operation".to_string(),
                        description: Some(
                            "Password hashing (bcrypt, scrypt, argon2) is intentionally \
                             CPU-intensive and blocks the goroutine. Consider running \
                             these operations in a worker pool or limiting concurrent \
                             operations.".to_string()
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
                                replacement: 
"// Consider using a bounded worker pool for CPU-intensive operations:
// var hashPool = make(chan struct{}, runtime.NumCPU())
// 
// func hashPassword(password string) (string, error) {
//     hashPool <- struct{}{} // Acquire
//     defer func() { <-hashPool }() // Release
//     return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
// }".to_string(),
                            }],
                        }),
                        fix_preview: Some("Use worker pool for hashing".to_string()),
                        tags: vec!["go".into(), "performance".into(), "crypto".into()],
                    });
                }

                // Check for compression calls
                if callee.contains("gzip.NewWriter") ||
                   callee.contains("zlib.NewWriter") {
                    let line = call.function_call.location.line;
                    let column = call.function_call.location.column;
                    
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Compression operation".to_string(),
                        description: Some(
                            "Compression is CPU-intensive and can block the handler. \
                             Consider using compression middleware that streams, or \
                             pre-compressing static content.".to_string()
                        ),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::Low,
                        confidence: 0.70,
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
                                replacement: "// Consider compression middleware or pre-compressed content".to_string(),
                            }],
                        }),
                        fix_preview: Some("Use compression middleware".to_string()),
                        tags: vec!["go".into(), "performance".into(), "compression".into()],
                    });
                }

                // Check for image processing
                if callee.contains("image.Decode") ||
                   callee.starts_with("imaging.") {
                    let line = call.function_call.location.line;
                    let column = call.function_call.location.column;
                    
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Image processing operation".to_string(),
                        description: Some(
                            "Image processing is CPU and memory intensive. Handle image \
                             operations asynchronously with a job queue, or offload to \
                             a dedicated service.".to_string()
                        ),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::High,
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
                                replacement: 
"// Process images asynchronously:
// 1. Accept upload and return immediately with job ID
// 2. Process in background worker
// 3. Notify client when complete (webhook, polling, websocket)".to_string(),
                            }],
                        }),
                        fix_preview: Some("Process images asynchronously".to_string()),
                        tags: vec!["go".into(), "performance".into(), "image".into()],
                    });
                }

                // Check for regex compilation in handler
                if callee == "regexp.MustCompile" || callee == "regexp.Compile" {
                    // Check if this is likely inside a function (not at package level)
                    // by checking if it's in a loop or in the function body
                    if call.in_loop {
                        let line = call.function_call.location.line;
                        let column = call.function_call.location.column;
                        
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Regex compilation in loop".to_string(),
                            description: Some(
                                "Compiling regex is expensive. Compile patterns once at \
                                 initialization and reuse them.".to_string()
                            ),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::High,
                            confidence: 0.95,
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
                                    replacement: 
"// Compile regex once at package level:
// var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$`)".to_string(),
                                }],
                            }),
                            fix_preview: Some("Compile regex at init".to_string()),
                            tags: vec!["go".into(), "performance".into(), "regex".into()],
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantics::go::model::GoFunction;
    use crate::parse::ast::{AstLocation, TextRange};

    #[test]
    fn test_rule_metadata() {
        let rule = GoCpuInHotPathRule::new();
        assert_eq!(rule.id(), "go.cpu_in_hot_path");
        assert!(!rule.name().is_empty());
    }

    #[test]
    fn test_is_http_handler_net_http() {
        let func = GoFunction {
            name: "handleRequest".to_string(),
            params: vec![
                crate::semantics::go::model::GoParam {
                    name: "w".to_string(),
                    param_type: "http.ResponseWriter".to_string(),
                },
                crate::semantics::go::model::GoParam {
                    name: "r".to_string(),
                    param_type: "*http.Request".to_string(),
                },
            ],
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
        assert!(GoCpuInHotPathRule::is_http_handler(&func));
    }

    #[test]
    fn test_is_http_handler_by_name() {
        let func = GoFunction {
            name: "UserHandler".to_string(),
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
        assert!(GoCpuInHotPathRule::is_http_handler(&func));
    }

    #[test]
    fn test_is_not_http_handler() {
        let func = GoFunction {
            name: "processData".to_string(),
            params: vec![
                crate::semantics::go::model::GoParam {
                    name: "data".to_string(),
                    param_type: "[]byte".to_string(),
                },
            ],
            return_types: vec!["error".to_string()],
            returns_error: true,
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
        assert!(!GoCpuInHotPathRule::is_http_handler(&func));
    }
}