//! Rule: Reflection in hot path detection
//!
//! Detects use of the reflect package in performance-critical code paths
//! like loops, which can significantly impact performance.

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

/// Rule that detects reflection usage in hot paths.
///
/// The reflect package is powerful but slow. Using reflection in loops
/// or frequently-called functions can cause significant performance degradation.
/// Consider code generation, type switches, or generics (Go 1.18+) instead.
#[derive(Debug, Default)]
pub struct GoReflectInHotPathRule;

impl GoReflectInHotPathRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoReflectInHotPathRule {
    fn id(&self) -> &'static str {
        "go.reflect_in_hot_path"
    }

    fn name(&self) -> &'static str {
        "Reflection used in performance-critical code"
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

            // Check if reflect package is imported
            let has_reflect_import = go.imports.iter().any(|i| i.path == "reflect");
            
            if !has_reflect_import {
                continue;
            }

            // Look for reflect calls in loops
            for call in &go.calls {
                if call.in_loop && call.function_call.callee_expr.starts_with("reflect.") {
                    let line = call.function_call.location.line;
                    
                    let title = format!(
                        "Reflection call '{}' in loop",
                        call.function_call.callee_expr
                    );

                    let description = format!(
                        "reflect.{} is called inside a loop at line {}. Reflection is \
                         significantly slower than direct type operations (10-100x slower). \
                         For hot paths, this can severely impact performance.\n\n\
                         Consider alternatives:\n\
                         1. Use generics (Go 1.18+) for type-safe polymorphism\n\
                         2. Use type switches for known types\n\
                         3. Use code generation (go generate) for compile-time type handling\n\
                         4. Cache reflect.Type and reflect.Value if reflection is necessary\n\
                         5. Move reflection outside the loop if possible",
                        call.function_call.callee_expr.strip_prefix("reflect.").unwrap_or(&call.function_call.callee_expr),
                        line
                    );

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line },
                            replacement: "// PERF: Consider replacing reflection with generics or type switch\n// var t reflect.Type = reflect.TypeOf(v) // Cache outside loop if needed".to_string(),
                        }],
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::High,
                        confidence: 0.90,
                        dimension: Dimension::Performance,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("Use generics or type switch".to_string()),
                        tags: vec![
                            "go".into(),
                            "performance".into(),
                            "reflection".into(),
                        ],
                    });
                }
            }

            // Also flag reflect.ValueOf and reflect.TypeOf in any call
            // as these are expensive operations
            let expensive_reflect_calls = [
                "reflect.ValueOf",
                "reflect.TypeOf", 
                "reflect.New",
                "reflect.MakeSlice",
                "reflect.MakeMap",
                "reflect.MakeChan",
            ];

            for call in &go.calls {
                if call.in_loop {
                    for expensive in &expensive_reflect_calls {
                        if call.function_call.callee_expr == *expensive {
                            let line = call.function_call.location.line;
                            
                            let title = format!(
                                "Expensive reflection '{}' in loop",
                                expensive
                            );

                            let description = format!(
                                "{} is called inside a loop at line {}. This is one of the \
                                 most expensive reflection operations as it involves type \
                                 introspection and memory allocation on each call.\n\n\
                                 Performance impact:\n\
                                 - reflect.ValueOf: allocates and escapes to heap\n\
                                 - reflect.TypeOf: requires type lookup\n\n\
                                 Mitigations:\n\
                                 1. Hoist reflect calls outside the loop\n\
                                 2. Cache reflect.Type in a package-level variable\n\
                                 3. Use generics instead: func Process[T any](items []T)",
                                expensive, line
                            );

                            let patch = FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line },
                                    replacement: format!(
                                        "// PERF: Hoist {} outside the loop\n// cachedType := reflect.TypeOf((*YourType)(nil)).Elem()",
                                        expensive
                                    ),
                                }],
                            };

                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title,
                                description: Some(description),
                                kind: FindingKind::PerformanceSmell,
                                severity: Severity::High,
                                confidence: 0.95,
                                dimension: Dimension::Performance,
                                file_id: *file_id,
                                file_path: go.path.clone(),
                                line: Some(line),
                                column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                                patch: Some(patch),
                                fix_preview: Some("Cache reflect result outside loop".to_string()),
                                tags: vec![
                                    "go".into(),
                                    "performance".into(),
                                    "reflection".into(),
                                    "allocation".into(),
                                ],
                            });
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
        let rule = GoReflectInHotPathRule::new();
        assert_eq!(rule.id(), "go.reflect_in_hot_path");
        assert!(!rule.name().is_empty());
    }

    #[tokio::test]
    async fn test_detects_reflect_in_loop() {
        let rule = GoReflectInHotPathRule::new();
        let (file_id, sem) = parse_and_build_semantics(r#"
package main

import "reflect"

func process(items []interface{}) {
    for _, item := range items {
        v := reflect.ValueOf(item)
        // expensive per iteration
        _ = v
    }
}
"#);
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        
        assert!(findings.iter().any(|f| f.rule_id == "go.reflect_in_hot_path"));
    }

    #[tokio::test]
    async fn test_no_finding_when_no_reflect() {
        let rule = GoReflectInHotPathRule::new();
        let (file_id, sem) = parse_and_build_semantics(r#"
package main

func process(items []string) {
    for _, item := range items {
        println(item)
    }
}
"#);
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        
        let reflect_findings: Vec<_> = findings.iter()
            .filter(|f| f.rule_id == "go.reflect_in_hot_path")
            .collect();
        assert!(reflect_findings.is_empty());
    }
}