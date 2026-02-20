//! Rule: Map without size hint detection
//!
//! Detects map creation without initial capacity hint in hot paths,
//! which causes multiple rehashing operations as the map grows.

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

/// Rule that detects map creation without size hints.
///
/// When creating maps in performance-critical code, providing an initial
/// capacity hint can significantly reduce allocations by avoiding rehashing
/// as the map grows.
#[derive(Debug, Default)]
pub struct GoMapWithoutSizeHintRule;

impl GoMapWithoutSizeHintRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoMapWithoutSizeHintRule {
    fn id(&self) -> &'static str {
        "go.map_without_size_hint"
    }

    fn name(&self) -> &'static str {
        "Map created without size hint"
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

            // Look for make(map[...]) calls
            for call in &go.calls {
                if call.function_call.callee_expr == "make" && call.args_repr.contains("map[") {
                    // Check if this is in a loop or performance-critical area
                    // Maps created in loops without size hints are particularly bad
                    if call.in_loop {
                        let line = call.function_call.location.line;

                        // Check if size hint is provided (make(map[K]V, size))
                        let has_size_hint = call.args_repr.matches(',').count() >= 1;

                        if !has_size_hint {
                            let title = "Map created in loop without size hint".to_string();

                            let description = format!(
                                "make(map[...]) at line {} is called inside a loop without a \
                                 capacity hint. Each iteration creates a new map that will need \
                                 to rehash as items are added. If the expected size is known, \
                                 providing a hint avoids rehashing.\n\n\
                                 Before:\n\
                                 ```go\n\
                                 for _, item := range items {{\n\
                                 \tm := make(map[string]int)\n\
                                 \t// populate map...\n\
                                 }}\n\
                                 ```\n\n\
                                 After:\n\
                                 ```go\n\
                                 for _, item := range items {{\n\
                                 \tm := make(map[string]int, expectedSize)\n\
                                 \t// populate map...\n\
                                 }}\n\
                                 ```\n\n\
                                 Note: Even a rough estimate helps (Go rounds up to power of 2).",
                                line
                            );

                            let patch = FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line },
                                    replacement:
                                        "// PERF: Add size hint: make(map[K]V, expectedSize)"
                                            .to_string(),
                                }],
                            };

                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title,
                                description: Some(description),
                                kind: FindingKind::PerformanceSmell,
                                severity: Severity::Low,
                                confidence: 0.75,
                                dimension: Dimension::Performance,
                                file_id: *file_id,
                                file_path: go.path.clone(),
                                line: Some(line),
                                column: None,
                                end_line: None,
                                end_column: None,
                                byte_range: None,
                                patch: Some(patch),
                                fix_preview: Some("Add size hint to make()".to_string()),
                                tags: vec![
                                    "go".into(),
                                    "performance".into(),
                                    "map".into(),
                                    "allocation".into(),
                                ],
                            });
                        }
                    }

                    // Also flag function-level maps without hints if they're likely to grow large
                    // based on function name heuristics
                    if !call.in_loop {
                        let has_size_hint = call.args_repr.matches(',').count() >= 1;

                        if !has_size_hint {
                            // Check if function name suggests bulk processing
                            let func_name_lower = go
                                .functions
                                .iter()
                                .find(|f| {
                                    let line = f.location.range.start_line + 1;
                                    let call_line = call.function_call.location.line;
                                    call_line >= line && call_line <= line + 50 // Within 50 lines of function start
                                })
                                .map(|f| f.name.to_lowercase());

                            let is_bulk_func = func_name_lower.as_ref().is_some_and(|name| {
                                name.contains("batch")
                                    || name.contains("bulk")
                                    || name.contains("all")
                                    || name.contains("many")
                                    || name.contains("collect")
                                    || name.contains("aggregate")
                                    || name.contains("index")
                                    || name.contains("cache")
                            });

                            if is_bulk_func {
                                let line = call.function_call.location.line;

                                let title = "Map in bulk operation without size hint".to_string();

                                let description = format!(
                                    "make(map[...]) at line {} is in a function that appears to \
                                     process data in bulk, but doesn't have a capacity hint. \
                                     For maps expected to hold many entries, providing an initial \
                                     capacity avoids repeated rehashing.\n\n\
                                     Example: make(map[string]int, len(items))",
                                    line
                                );

                                let patch = FilePatch {
                                    file_id: *file_id,
                                    hunks: vec![PatchHunk {
                                        range: PatchRange::InsertBeforeLine { line },
                                        replacement:
                                            "// PERF: Consider adding size hint for bulk operation"
                                                .to_string(),
                                    }],
                                };

                                findings.push(RuleFinding {
                                    rule_id: self.id().to_string(),
                                    title,
                                    description: Some(description),
                                    kind: FindingKind::PerformanceSmell,
                                    severity: Severity::Low,
                                    confidence: 0.60,
                                    dimension: Dimension::Performance,
                                    file_id: *file_id,
                                    file_path: go.path.clone(),
                                    line: Some(line),
                                    column: None,
                                    end_line: None,
                                    end_column: None,
                                    byte_range: None,
                                    patch: Some(patch),
                                    fix_preview: Some("Add size hint".to_string()),
                                    tags: vec!["go".into(), "performance".into(), "map".into()],
                                });
                            }
                        }
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
        let rule = GoMapWithoutSizeHintRule::new();
        assert_eq!(rule.id(), "go.map_without_size_hint");
        assert!(!rule.name().is_empty());
    }

    #[tokio::test]
    async fn test_detects_map_in_loop_without_hint() {
        let rule = GoMapWithoutSizeHintRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

func process(batches [][]Item) []map[string]int {
    var results []map[string]int
    for _, batch := range batches {
        m := make(map[string]int)  // No size hint
        for _, item := range batch {
            m[item.Key] = item.Value
        }
        results = append(results, m)
    }
    return results
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "go.map_without_size_hint")
        );
    }

    #[tokio::test]
    async fn test_no_finding_with_size_hint() {
        let rule = GoMapWithoutSizeHintRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

func process(items []Item) map[string]int {
    m := make(map[string]int, len(items))
    for _, item := range items {
        m[item.Key] = item.Value
    }
    return m
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        let map_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go.map_without_size_hint")
            .collect();
        assert!(map_findings.is_empty());
    }
}
