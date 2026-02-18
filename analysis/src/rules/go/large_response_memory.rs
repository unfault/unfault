//! Rule: Large response memory in Go
//!
//! Detects HTTP responses that load entire content into memory instead of streaming.

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

/// Rule that detects large response memory patterns.
#[derive(Debug, Default)]
pub struct GoLargeResponseMemoryRule;

impl GoLargeResponseMemoryRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoLargeResponseMemoryRule {
    fn id(&self) -> &'static str {
        "go.large_response_memory"
    }

    fn name(&self) -> &'static str {
        "Large response loaded into memory"
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

            // Check for json.Marshal calls that might be on large data
            for call in &go.calls {
                if call.function_call.callee_expr.contains("json.Marshal") {
                    // Look for patterns that suggest large data in args
                    let has_large_data_hint = 
                        call.args_repr.contains("[]") || 
                        call.args_repr.contains("rows") ||
                        call.args_repr.contains("results") ||
                        call.args_repr.contains("items") ||
                        call.args_repr.contains("all");

                    if has_large_data_hint {
                        let line = call.function_call.location.line;
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "json.Marshal on potentially large data".to_string(),
                            description: Some(
                                "json.Marshal loads the entire response into memory before \
                                 sending. For large datasets, use json.NewEncoder(w).Encode() \
                                 to stream the response directly to the client.".to_string()
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
                                    replacement: 
"// Stream JSON response instead of buffering:
// w.Header().Set(\"Content-Type\", \"application/json\")
// if err := json.NewEncoder(w).Encode(data); err != nil {
//     http.Error(w, err.Error(), http.StatusInternalServerError)
// }".to_string(),
                                }],
                            }),
                            fix_preview: Some("Use json.NewEncoder().Encode()".to_string()),
                            tags: vec!["go".into(), "memory".into(), "http".into(), "streaming".into()],
                        });
                    }
                }
            }

            // Check for WriteFile calls
            for call in &go.calls {
                if call.function_call.callee_expr.contains("WriteFile") {
                    let line = call.function_call.location.line;
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "File write fully buffered in memory".to_string(),
                        description: Some(
                            "Writing large files by first buffering to []byte loads \
                             everything into memory. Use os.Create() with streaming \
                             writes for large files.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.65,
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
                                replacement: 
"// Stream to file instead of buffering:
// f, err := os.Create(filename)
// if err != nil { return err }
// defer f.Close()
// return json.NewEncoder(f).Encode(data)".to_string(),
                            }],
                        }),
                        fix_preview: Some("Stream writes to file".to_string()),
                        tags: vec!["go".into(), "memory".into(), "file".into(), "streaming".into()],
                    });
                }
            }

            // Check for rows.Scan in a loop with append (database result collection)
            let has_rows_scan = go.calls.iter().any(|c| c.function_call.callee_expr.contains("Scan"));
            let has_append_in_loop = go.calls.iter().any(|c| c.function_call.callee_expr == "append" && c.in_loop);
            let has_pagination = go.calls.iter().any(|c| {
                c.args_repr.to_lowercase().contains("limit") ||
                c.args_repr.to_lowercase().contains("offset")
            });

            if has_rows_scan && has_append_in_loop && !has_pagination {
                // Find the append call location
                if let Some(append_call) = go.calls.iter().find(|c| c.function_call.callee_expr == "append" && c.in_loop) {
                    let line = append_call.function_call.location.line;
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Database results collected into unbounded slice".to_string(),
                        description: Some(
                            "Collecting all database rows into a slice without pagination \
                             can exhaust memory for large result sets. Implement pagination \
                             or streaming.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::High,
                        confidence: 0.75,
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
                                replacement: 
"// Add pagination to database queries:
// SELECT * FROM table LIMIT ? OFFSET ?
// 
// Or stream results:
// for rows.Next() {
//     // Process each row individually
//     if err := processRow(row); err != nil { ... }
// }".to_string(),
                            }],
                        }),
                        fix_preview: Some("Add pagination or streaming".to_string()),
                        tags: vec!["go".into(), "memory".into(), "database".into()],
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

    #[test]
    fn test_rule_metadata() {
        let rule = GoLargeResponseMemoryRule::new();
        assert_eq!(rule.id(), "go.large_response_memory");
        assert!(!rule.name().is_empty());
    }
}