//! Rule: Unbounded memory in Go
//!
//! Detects patterns that can lead to memory exhaustion like unbounded slice growth.

use std::sync::Arc;
use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unbounded memory patterns.
#[derive(Debug, Default)]
pub struct GoUnboundedMemoryRule;

impl GoUnboundedMemoryRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoUnboundedMemoryRule {
    fn id(&self) -> &'static str {
        "go.unbounded_memory"
    }

    fn name(&self) -> &'static str {
        "Unbounded memory allocation"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(unbounded_resource())
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

            // Check for dangerous patterns via calls
            
            // Check for ReadAll without LimitReader
            let has_limit_reader = go.calls.iter().any(|c| c.function_call.callee_expr.contains("LimitReader"));
            
            for call in &go.calls {
                // ioutil.ReadAll / io.ReadAll without bounds
                if (call.function_call.callee_expr.contains("ReadAll") || call.function_call.callee_expr == "io.ReadAll" || call.function_call.callee_expr == "ioutil.ReadAll") 
                    && !has_limit_reader {
                    let line = call.function_call.location.line;
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "ReadAll without size limit".to_string(),
                        description: Some(
                            "ioutil.ReadAll/io.ReadAll reads entire content into memory. \
                             For HTTP responses or file reads, this can cause memory exhaustion. \
                             Use io.LimitReader to cap the size or stream the data.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::High,
                        confidence: 0.85,
                        dimension: Dimension::Scalability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: "// Consider using io.LimitReader(reader, maxBytes) to bound memory\n// Example: data, err := io.ReadAll(io.LimitReader(r.Body, 10*1024*1024))".to_string(),
                            }],
                        }),
                        fix_preview: Some("Wrap with io.LimitReader".to_string()),
                        tags: vec!["go".into(), "memory".into(), "dos".into()],
                    });
                }

                // Check for unbounded append in loop
                if call.function_call.callee_expr == "append" && call.in_loop {
                    let line = call.function_call.location.line;
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Unbounded slice growth in loop".to_string(),
                        description: Some(
                            "Appending to a slice in a loop without bounds checking \
                             can lead to memory exhaustion. Add a maximum size check \
                             before appending.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.70,
                        dimension: Dimension::Scalability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: "// Add bounds check: if len(slice) >= maxSize { break }".to_string(),
                            }],
                        }),
                        fix_preview: Some("Add maximum size check".to_string()),
                        tags: vec!["go".into(), "memory".into()],
                    });
                }
            }

            // Check HTTP handlers for JSON decode without size limit
            let has_max_bytes_reader = go.calls.iter().any(|c| c.function_call.callee_expr.contains("MaxBytesReader"));
            
            for func in &go.functions {
                let is_http_handler = func.params.iter().any(|p| {
                    p.param_type.contains("http.ResponseWriter") ||
                    p.param_type.contains("*gin.Context") ||
                    p.param_type.contains("echo.Context")
                });

                if is_http_handler && !has_max_bytes_reader {
                    // Check if JSON decode is used in this file
                    let has_json_decode = go.calls.iter().any(|c| {
                        c.function_call.callee_expr.contains("json.Decode") || 
                        c.function_call.callee_expr.contains("json.NewDecoder")
                    });

                    if has_json_decode {
                        let line = func.location.range.start_line + 1;
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "JSON decode without request size limit".to_string(),
                            description: Some(
                                "JSON decoding HTTP request body without size limit \
                                 allows clients to send arbitrarily large payloads. \
                                 Use http.MaxBytesReader to limit request body size.".to_string()
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.90,
                            dimension: Dimension::Scalability,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertAfterLine { line },
                                    replacement: "\tr.Body = http.MaxBytesReader(w, r.Body, 1048576) // 1MB limit".to_string(),
                                }],
                            }),
                            fix_preview: Some("Add http.MaxBytesReader".to_string()),
                            tags: vec!["go".into(), "memory".into(), "http".into()],
                        });
                        break; // One finding per handler
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

    #[test]
    fn test_rule_metadata() {
        let rule = GoUnboundedMemoryRule::new();
        assert_eq!(rule.id(), "go.unbounded_memory");
        assert!(!rule.name().is_empty());
    }
}