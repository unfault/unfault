//! Rule: Go Unbounded Goroutines
//!
//! Detects goroutine spawning without limits or worker pools.

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

/// Rule that detects unbounded goroutine spawning in Go code.
#[derive(Debug, Default)]
pub struct GoUnboundedGoroutinesRule;

impl GoUnboundedGoroutinesRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoUnboundedGoroutinesRule {
    fn id(&self) -> &'static str {
        "go.unbounded_goroutines"
    }

    fn name(&self) -> &'static str {
        "Go Unbounded Goroutines"
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
            let go_sem = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Check for worker pool libraries
            let has_worker_pool = go_sem.imports.iter().any(|imp| {
                imp.path.contains("github.com/gammazero/workerpool")
                    || imp.path.contains("github.com/panjf2000/ants")
                    || imp.path.contains("golang.org/x/sync/errgroup")
            });

            if has_worker_pool {
                continue;
            }

            // Look for goroutines spawned in loops by checking if any
            // calls in loops have goroutines nearby, or check for pattern
            // of goroutine calls that might be in loops
            let calls_in_loops = go_sem.calls.iter().filter(|c| c.in_loop).count();

            // Check for goroutines that might be in loops
            for goroutine in &go_sem.goroutines {
                // Heuristic: if there are multiple calls in loops, the goroutine
                // is likely in a loop context (not perfect but reasonable detection)
                if calls_in_loops > 0 || goroutine.is_anonymous {
                    let line = goroutine.line;

                    let title =
                        format!("Potentially unbounded goroutine spawning at line {}", line);

                    let description = format!(
                        "Goroutine at line {} may be spawned without rate limiting or \
                         worker pool. This can lead to resource exhaustion (memory, CPU, \
                         file descriptors) under load. Use a worker pool or semaphore to \
                         limit concurrent goroutines.",
                        line
                    );

                    let patch = generate_worker_pool_patch(*file_id, line);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::High,
                        confidence: 0.75,
                        dimension: Dimension::Scalability,
                        file_id: *file_id,
                        file_path: go_sem.path.clone(),
                        line: Some(line),
                        column: Some(1),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(
                            "// Use worker pool or semaphore for bounded concurrency".to_string(),
                        ),
                        tags: vec![
                            "go".into(),
                            "concurrency".into(),
                            "goroutine".into(),
                            "resource-exhaustion".into(),
                        ],
                    });
                    break; // One finding per file
                }
            }
        }

        findings
    }
}

fn generate_worker_pool_patch(file_id: FileId, line: u32) -> FilePatch {
    let replacement = r#"// Use a worker pool for bounded concurrency:
// import "github.com/gammazero/workerpool"
// wp := workerpool.New(10)  // Max 10 concurrent workers
// for _, item := range items {
//     item := item  // Capture loop variable
//     wp.Submit(func() {
//         process(item)
//     })
// }
// wp.StopWait()
"#
    .to_string();

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_has_correct_metadata() {
        let rule = GoUnboundedGoroutinesRule::new();
        assert_eq!(rule.id(), "go.unbounded_goroutines");
    }
}
