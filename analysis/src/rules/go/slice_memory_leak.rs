//! Rule: Slice memory leak detection
//!
//! Detects patterns where small slices keep references to large backing arrays,
//! preventing garbage collection of the underlying memory.

use async_trait::async_trait;
use std::sync::Arc;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects slice patterns that can cause memory leaks.
///
/// When you slice a large array/slice (e.g., data[:10]), the small slice
/// still references the entire backing array. If the large slice goes out
/// of scope but the small slice is retained, the GC cannot collect the
/// backing array memory.
#[derive(Debug, Default)]
pub struct GoSliceMemoryLeakRule;

impl GoSliceMemoryLeakRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoSliceMemoryLeakRule {
    fn id(&self) -> &'static str {
        "go.slice_memory_leak"
    }

    fn name(&self) -> &'static str {
        "Slice retaining large backing array"
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

            // Check for functions that return sliced data
            for func in &go.functions {
                // Look for return types that are slices
                let returns_slice = func
                    .return_types
                    .iter()
                    .any(|rt| rt.starts_with("[]") || rt == "string");

                if returns_slice {
                    // Check if function name suggests it returns a portion
                    let name_lower = func.name.to_lowercase();
                    let is_prefix_suffix_func = name_lower.contains("prefix")
                        || name_lower.contains("suffix")
                        || name_lower.contains("head")
                        || name_lower.contains("tail")
                        || name_lower.contains("first")
                        || name_lower.contains("last")
                        || name_lower.contains("take")
                        || name_lower.contains("trim");

                    if is_prefix_suffix_func {
                        let line = func.location.range.start_line + 1;

                        let title =
                            format!("Function '{}' may leak backing array memory", func.name);

                        let description = format!(
                            "Function '{}' at line {} returns a slice and its name suggests it \
                             returns only a portion of data. If this returns a sub-slice of a \
                             larger slice, the backing array cannot be garbage collected.\n\n\
                             Consider:\n\
                             1. Copy the data to a new slice before returning:\n\
                             ```go\n\
                             result := make([]byte, len(prefix))\n\
                             copy(result, prefix)\n\
                             return result\n\
                             ```\n\
                             2. Use bytes.Clone() for []byte (Go 1.20+)\n\
                             3. Use strings.Clone() for strings (Go 1.20+)",
                            func.name, line
                        );

                        let patch = FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: "// Consider copying slice to release backing array:\n// result := make([]T, len(slice))\n// copy(result, slice)\n// return result".to_string(),
                            }],
                        };

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::ResourceLeak,
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
                            patch: Some(patch),
                            fix_preview: Some("Copy slice before returning".to_string()),
                            tags: vec!["go".into(), "memory".into(), "slice".into(), "leak".into()],
                        });
                    }
                }
            }

            // Check calls for risky slice patterns
            for call in &go.calls {
                // Check for ioutil.ReadAll or io.ReadAll followed by slicing
                if call.function_call.callee_expr.contains("ReadAll") {
                    let line = call.function_call.location.line;

                    // Check if there are any functions that return slice portions
                    // This is a heuristic - ReadAll returns potentially large data
                    // that users often slice

                    let title = "ReadAll result may be partially sliced".to_string();

                    let description = format!(
                        "ReadAll at line {} reads entire content into memory. If you later \
                         slice this data (e.g., data[:100]), the small slice retains the \
                         entire backing array. For large files or HTTP responses, this can \
                         cause significant memory waste.\n\n\
                         Consider:\n\
                         1. Use io.LimitReader if you only need first N bytes\n\
                         2. Copy needed portion to new slice\n\
                         3. Use streaming APIs instead of ReadAll",
                        line
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::ResourceLeak,
                        severity: Severity::Low,
                        confidence: 0.50,
                        dimension: Dimension::Scalability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: None,
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: None,
                        fix_preview: Some("Use io.LimitReader or copy slice".to_string()),
                        tags: vec!["go".into(), "memory".into(), "slice".into()],
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

    #[test]
    fn test_rule_metadata() {
        let rule = GoSliceMemoryLeakRule::new();
        assert_eq!(rule.id(), "go.slice_memory_leak");
        assert!(!rule.name().is_empty());
    }

    #[tokio::test]
    async fn test_detects_prefix_function() {
        let rule = GoSliceMemoryLeakRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

func GetPrefix(data []byte) []byte {
    return data[:10]
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        assert!(findings.iter().any(|f| f.rule_id == "go.slice_memory_leak"));
    }

    #[tokio::test]
    async fn test_detects_readall() {
        let rule = GoSliceMemoryLeakRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "io/ioutil"

func ReadData(r io.Reader) ([]byte, error) {
    return ioutil.ReadAll(r)
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        assert!(findings.iter().any(|f| f.rule_id == "go.slice_memory_leak"));
    }
}
