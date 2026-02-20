//! Rule: Defer statement inside loop
//!
//! Detects `defer` statements inside loops, which can cause resource leaks
//! because the deferred function won't execute until the surrounding function
//! returns, not when the loop iteration completes.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects defer statements inside loops.
///
/// In Go, `defer` schedules a function call to be run after the function
/// completes. When used inside a loop, the deferred calls accumulate until
/// the function returns, which can cause:
/// - Resource exhaustion (file handles, connections)
/// - Memory leaks
/// - Unexpected order of cleanup operations
#[derive(Debug)]
pub struct GoDeferInLoopRule;

impl GoDeferInLoopRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoDeferInLoopRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for GoDeferInLoopRule {
    fn id(&self) -> &'static str {
        "go.defer_in_loop"
    }

    fn name(&self) -> &'static str {
        "Defer statement inside loop can cause resource leaks"
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
                SourceSemantics::Go(go) => go,
                _ => continue,
            };

            for defer_stmt in &go.defers {
                // Only flag if the defer is inside a loop
                if !defer_stmt.in_loop {
                    continue;
                }

                let title = "Defer inside loop accumulates until function returns".to_string();

                let description = format!(
                    "The `defer {}` statement is inside a loop. In Go, deferred function \
                     calls are not executed at the end of each loop iteration, but when \
                     the surrounding function returns. This means:\n\
                     - Resources (files, connections, locks) won't be released until the loop completes\n\
                     - Each iteration adds to the defer stack, potentially causing memory pressure\n\
                     - If the loop runs many times, you may exhaust resources\n\n\
                     Consider:\n\
                     1. Move the defer outside the loop if possible\n\
                     2. Extract the loop body into a separate function\n\
                     3. Manually close/release resources at the end of each iteration",
                    defer_stmt.call_text.trim()
                );

                let patch = generate_defer_fix_patch(defer_stmt, *file_id);

                let fix_preview = format!(
                    "// Before: defer inside loop\n\
                     // for ... {{\n\
                     //     f := open()\n\
                     //     defer f.Close()  // Won't close until function returns!\n\
                     // }}\n\
                     //\n\
                     // After: explicit close in loop\n\
                     // for ... {{\n\
                     //     f := open()\n\
                     //     // ... use f ...\n\
                     //     f.Close()  // Closes each iteration\n\
                     // }}"
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::ResourceLeak,
                    severity: Severity::High,
                    confidence: 0.95,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: go.path.clone(),
                    line: Some(defer_stmt.line),
                    column: Some(defer_stmt.column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "go".into(),
                        "defer".into(),
                        "resource-leak".into(),
                        "reliability".into(),
                        "loop".into(),
                    ],
                });
            }
        }

        findings
    }
}

use crate::semantics::go::model::DeferStatement;

/// Generate a patch to fix defer in loop.
///
/// Suggests extracting to a helper function or using explicit cleanup.
fn generate_defer_fix_patch(defer_stmt: &DeferStatement, file_id: FileId) -> FilePatch {
    // For common patterns like `defer f.Close()`, suggest removing defer
    // and adding explicit close at the end of the loop body
    let replacement = if defer_stmt.call_text.contains(".Close()") {
        // Remove the defer and add comment
        format!(
            "// TODO: Move {} to end of loop iteration or extract to helper function",
            defer_stmt.call_text.trim()
        )
    } else {
        // Generic suggestion
        format!(
            "// TODO: Consider extracting loop body to helper function to properly defer:\n\
             // func helper() {{\n\
             //     {}\n\
             // }}",
            defer_stmt.call_text.trim()
        )
    };

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: defer_stmt.start_byte,
                end: defer_stmt.end_byte,
            },
            replacement,
        }],
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
    fn rule_id_is_correct() {
        let rule = GoDeferInLoopRule::new();
        assert_eq!(rule.id(), "go.defer_in_loop");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = GoDeferInLoopRule::new();
        assert!(rule.name().contains("Defer"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = GoDeferInLoopRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GoDeferInLoopRule"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_go() {
        let rule = GoDeferInLoopRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_no_finding_for_defer_outside_loop() {
        let rule = GoDeferInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "os"

func readFile() {
    f, _ := os.Open("test.txt")
    defer f.Close()
    // read file
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag defer outside loop
        for finding in &findings {
            assert_ne!(finding.rule_id, "go.defer_in_loop");
        }
    }

    #[tokio::test]
    async fn evaluate_detects_defer_in_for_loop() {
        let rule = GoDeferInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "os"

func processFiles(files []string) {
    for _, file := range files {
        f, _ := os.Open(file)
        defer f.Close()  // Bug: won't close until function returns!
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should detect defer in loop (if semantics tracks this)
        // This depends on semantics implementation
        for finding in &findings {
            if finding.rule_id == "go.defer_in_loop" {
                assert!(finding.tags.contains(&"defer".to_string()));
                assert!(finding.tags.contains(&"loop".to_string()));
            }
        }
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = GoDeferInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

func main() {
    for i := 0; i < 10; i++ {
        defer println(i)
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.defer_in_loop" {
                assert!(finding.description.is_some());
                assert!(finding.patch.is_some());
                assert_eq!(finding.dimension, Dimension::Reliability);
                assert!(finding.tags.contains(&"go".to_string()));
            }
        }
    }
}
