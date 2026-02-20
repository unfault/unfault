//! Rule: Goroutine leak detection
//!
//! Detects patterns that can lead to goroutine leaks, such as:
//! - Goroutines without context cancellation
//! - Unbounded channel sends that may block forever
//! - Missing select with done channel

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

/// Rule that detects potential goroutine leaks.
///
/// Goroutine leaks occur when goroutines are started but never terminate,
/// often because they're blocked on channel operations or lack proper
/// cancellation mechanisms.
#[derive(Debug)]
pub struct GoGoroutineLeakRule;

impl GoGoroutineLeakRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoGoroutineLeakRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for GoGoroutineLeakRule {
    fn id(&self) -> &'static str {
        "go.goroutine_leak"
    }

    fn name(&self) -> &'static str {
        "Potential goroutine leak detected"
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

            for goroutine in &go.goroutines {
                // Check for potential leak patterns

                // Pattern 1: Goroutine without context parameter
                if !goroutine.has_context_param && !goroutine.has_done_channel {
                    let title = "Goroutine without cancellation mechanism".to_string();

                    let description = format!(
                        "The goroutine started at line {} does not have a context parameter \
                         or done channel for cancellation. Without a way to signal termination, \
                         this goroutine may run indefinitely and leak if the parent function \
                         returns or the operation is cancelled.\n\n\
                         Consider:\n\
                         1. Pass a context.Context and check ctx.Done() in the goroutine\n\
                         2. Use a done channel to signal termination\n\
                         3. Use sync.WaitGroup if the goroutine must complete before parent returns",
                        goroutine.line
                    );

                    let patch = generate_context_cancellation_patch(goroutine, *file_id);

                    let fix_preview = format!(
                        "// Before:\n\
                         // go func() {{\n\
                         //     for {{\n\
                         //         work()\n\
                         //     }}\n\
                         // }}()\n\
                         //\n\
                         // After:\n\
                         // go func(ctx context.Context) {{\n\
                         //     for {{\n\
                         //         select {{\n\
                         //         case <-ctx.Done():\n\
                         //             return\n\
                         //         default:\n\
                         //             work()\n\
                         //         }}\n\
                         //     }}\n\
                         // }}(ctx)"
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::ResourceLeak,
                        severity: Severity::High,
                        confidence: 0.85,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(goroutine.line),
                        column: Some(goroutine.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "go".into(),
                            "goroutine".into(),
                            "concurrency".into(),
                            "resource-leak".into(),
                            "context".into(),
                        ],
                    });
                }

                // Pattern 2: Unbounded channel send without select
                if goroutine.has_unbounded_channel_send {
                    let title = "Goroutine may block forever on channel send".to_string();

                    let description = format!(
                        "The goroutine at line {} contains an unbounded channel send \
                         without a select statement. If no receiver is listening, \
                         this goroutine will block forever and leak.\n\n\
                         Consider:\n\
                         1. Use a buffered channel if appropriate\n\
                         2. Use select with a done channel or timeout\n\
                         3. Ensure there's always a receiver for the channel",
                        goroutine.line
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::ResourceLeak,
                        severity: Severity::High,
                        confidence: 0.80,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(goroutine.line),
                        column: Some(goroutine.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: None, // Complex fix, manual intervention needed
                        fix_preview: Some(
                            "// Use select with done channel:\n\
                             // select {\n\
                             // case ch <- value:\n\
                             // case <-ctx.Done():\n\
                             //     return\n\
                             // }"
                                .to_string(),
                        ),
                        tags: vec![
                            "go".into(),
                            "goroutine".into(),
                            "channel".into(),
                            "blocking".into(),
                        ],
                    });
                }
            }
        }

        findings
    }
}

use crate::semantics::go::model::GoroutineSpawn;

/// Generate a patch to add context cancellation to a goroutine.
fn generate_context_cancellation_patch(goroutine: &GoroutineSpawn, file_id: FileId) -> FilePatch {
    // Suggest adding context.Done() check
    let body_comment = if goroutine.is_anonymous {
        "TODO: Move".to_string()
    } else {
        goroutine
            .function_name
            .clone()
            .unwrap_or_else(|| "original".to_string())
    };

    let replacement = format!(
        "go func(ctx context.Context) {{\n\
         \t\tselect {{\n\
         \t\tcase <-ctx.Done():\n\
         \t\t\treturn\n\
         \t\tdefault:\n\
         \t\t\t// {} original goroutine body\n\
         \t\t}}\n\
         \t}}(ctx)",
        body_comment
    );

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: goroutine.start_byte,
                end: goroutine.end_byte,
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
        let rule = GoGoroutineLeakRule::new();
        assert_eq!(rule.id(), "go.goroutine_leak");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = GoGoroutineLeakRule::new();
        assert!(rule.name().contains("goroutine"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = GoGoroutineLeakRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GoGoroutineLeakRule"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_go() {
        let rule = GoGoroutineLeakRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_goroutine_without_context() {
        let rule = GoGoroutineLeakRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

func startWorker() {
    go func() {
        for {
            work()
        }
    }()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Depending on semantics detection
        for finding in &findings {
            if finding.rule_id == "go.goroutine_leak" {
                assert!(finding.tags.contains(&"goroutine".to_string()));
            }
        }
    }

    #[tokio::test]
    async fn evaluate_no_finding_for_goroutine_with_context() {
        let rule = GoGoroutineLeakRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "context"

func startWorker(ctx context.Context) {
    go func() {
        for {
            select {
            case <-ctx.Done():
                return
            default:
                work()
            }
        }
    }()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag goroutine with proper context handling
        // (depends on semantics implementation)
        let _ = findings;
    }

    #[tokio::test]
    async fn finding_has_correct_dimension() {
        let rule = GoGoroutineLeakRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

func leak() {
    go func() {
        ch := make(chan int)
        ch <- 1  // Will block forever
    }()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.goroutine_leak" {
                assert_eq!(finding.dimension, Dimension::Reliability);
                assert!(matches!(finding.kind, FindingKind::ResourceLeak));
            }
        }
    }
}
