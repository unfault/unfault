//! Rule: Slice append in loop without pre-allocation
//!
//! Detects append() calls in loops without pre-allocating slice capacity,
//! which causes multiple memory allocations and copies.

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

/// Rule that detects inefficient slice growth patterns.
///
/// When appending to a slice in a loop, Go may need to reallocate and copy
/// the underlying array multiple times. Pre-allocating with make([]T, 0, capacity)
/// avoids these allocations.
#[derive(Debug, Default)]
pub struct GoSliceAppendInLoopRule;

impl GoSliceAppendInLoopRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoSliceAppendInLoopRule {
    fn id(&self) -> &'static str {
        "go.slice_append_in_loop"
    }

    fn name(&self) -> &'static str {
        "Slice append in loop without pre-allocation"
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

            // Look for append calls in loops
            for call in &go.calls {
                if call.function_call.callee_expr == "append" && call.in_loop {
                    let line = call.function_call.location.line;
                    
                    // Check if there's a make() call with capacity nearby
                    // This is heuristic - we look for make with 3 args (type, len, cap)
                    let has_prealloc = go.calls.iter().any(|c| {
                        c.function_call.callee_expr == "make" && 
                        c.args_repr.matches(',').count() >= 2 // make([]T, len, cap)
                    });

                    if !has_prealloc {
                        let title = "Append in loop without capacity pre-allocation".to_string();

                        let description = format!(
                            "append() is called inside a loop at line {} without apparent \
                             capacity pre-allocation. Each time the slice's capacity is exceeded, \
                             Go allocates a new backing array (typically 2x the size) and copies \
                             all elements. For N elements, this can result in O(log N) allocations \
                             and O(N log N) copy operations.\n\n\
                             Before:\n\
                             ```go\n\
                             var result []T\n\
                             for _, item := range items {{\n\
                             \tresult = append(result, transform(item))\n\
                             }}\n\
                             ```\n\n\
                             After:\n\
                             ```go\n\
                             result := make([]T, 0, len(items))  // Pre-allocate capacity\n\
                             for _, item := range items {{\n\
                             \tresult = append(result, transform(item))\n\
                             }}\n\
                             ```\n\n\
                             If the final size is unknown, estimate a reasonable initial capacity.",
                            line
                        );

                        let patch = FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: "// PERF: Pre-allocate slice capacity to avoid reallocations\n// slice := make([]T, 0, expectedLen)".to_string(),
                            }],
                        };

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::Medium,
                            confidence: 0.80,
                            dimension: Dimension::Performance,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some("Pre-allocate with make([]T, 0, cap)".to_string()),
                            tags: vec![
                                "go".into(),
                                "performance".into(),
                                "allocation".into(),
                                "slice".into(),
                            ],
                        });
                        
                        // Only one finding per file for append in loop
                        break;
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
    use crate::parse::ast::FileId;
    use crate::parse::go::parse_go_file;
    use crate::semantics::go::build_go_semantics;
    use crate::semantics::SourceSemantics;
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
        let rule = GoSliceAppendInLoopRule::new();
        assert_eq!(rule.id(), "go.slice_append_in_loop");
        assert!(!rule.name().is_empty());
    }

    #[tokio::test]
    async fn test_detects_append_without_prealloc() {
        let rule = GoSliceAppendInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(r#"
package main

func collect(items []int) []int {
    var result []int
    for _, item := range items {
        result = append(result, item*2)
    }
    return result
}
"#);
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        
        assert!(findings.iter().any(|f| f.rule_id == "go.slice_append_in_loop"));
    }

    #[tokio::test]
    async fn test_no_finding_with_prealloc() {
        let rule = GoSliceAppendInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(r#"
package main

func collect(items []int) []int {
    result := make([]int, 0, len(items))
    for _, item := range items {
        result = append(result, item*2)
    }
    return result
}
"#);
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        
        let append_findings: Vec<_> = findings.iter()
            .filter(|f| f.rule_id == "go.slice_append_in_loop")
            .collect();
        assert!(append_findings.is_empty());
    }
}