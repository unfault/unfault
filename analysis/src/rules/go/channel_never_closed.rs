//! Rule: Channel never closed detection
//!
//! Detects channels that are created and written to but never closed,
//! which can cause goroutine leaks when receivers wait forever.

use std::sync::Arc;
use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::go::model::ChannelOpKind;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects channels that are never closed.
///
/// Channels that are written to but never closed can cause goroutine leaks
/// because receivers using range loops or blocking receives will wait forever.
#[derive(Debug, Default)]
pub struct GoChannelNeverClosedRule;

impl GoChannelNeverClosedRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoChannelNeverClosedRule {
    fn id(&self) -> &'static str {
        "go.channel_never_closed"
    }

    fn name(&self) -> &'static str {
        "Channel created but never closed"
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

            // Track channels: find sends and closes
            let has_close = go.channel_ops.iter().any(|op| {
                matches!(op.kind, ChannelOpKind::Close)
            });

            // Also check for close() calls in the source
            let has_close_call = go.calls.iter().any(|c| c.function_call.callee_expr == "close");

            // Find channel sends that are not in a select statement
            for op in &go.channel_ops {
                if matches!(op.kind, ChannelOpKind::Send) && !has_close && !has_close_call {
                    // Check if this is inside a goroutine that produces values
                    // This is a heuristic - if we see sends but no close, flag it
                    
                    let title = "Channel send without corresponding close".to_string();

                    let description = format!(
                        "Channel send at line {} detected, but no close() call found in this file. \
                         If receivers use `range` over the channel or blocking receives, \
                         they will wait forever, causing goroutine leaks.\n\n\
                         Consider:\n\
                         1. Use `defer close(ch)` in the producer goroutine\n\
                         2. Use sync.WaitGroup to coordinate closure\n\
                         3. Document clearly which goroutine is responsible for closing",
                        op.line
                    );

                    // Generate patch - suggest adding close
                    let replacement = format!(
                        "// TODO: Ensure channel is closed when done sending\n\
                         // defer close(ch) // Add this in the producer goroutine\n\
                         {}", 
                        op.text
                    );

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::ReplaceBytes {
                                start: op.start_byte,
                                end: op.end_byte,
                            },
                            replacement,
                        }],
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::ResourceLeak,
                        severity: Severity::High,
                        confidence: 0.75,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(op.line),
                        column: Some(op.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("Add defer close(ch) in producer".to_string()),
                        tags: vec![
                            "go".into(),
                            "channel".into(),
                            "goroutine-leak".into(),
                            "concurrency".into(),
                        ],
                    });
                    
                    // Only one finding per file for this pattern
                    break;
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
        let rule = GoChannelNeverClosedRule::new();
        assert_eq!(rule.id(), "go.channel_never_closed");
        assert!(!rule.name().is_empty());
    }

    #[tokio::test]
    async fn test_detects_channel_without_close() {
        let rule = GoChannelNeverClosedRule::new();
        let (file_id, sem) = parse_and_build_semantics(r#"
package main

func producer() {
    ch := make(chan int)
    go func() {
        for i := 0; i < 10; i++ {
            ch <- i
        }
        // Missing: close(ch)
    }()
}
"#);
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        
        // Should detect the missing close
        assert!(findings.iter().any(|f| f.rule_id == "go.channel_never_closed"));
    }

    #[tokio::test]
    async fn test_no_finding_when_close_present() {
        let rule = GoChannelNeverClosedRule::new();
        let (file_id, sem) = parse_and_build_semantics(r#"
package main

func producer() {
    ch := make(chan int)
    go func() {
        defer close(ch)
        for i := 0; i < 10; i++ {
            ch <- i
        }
    }()
}
"#);
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        
        // Should not flag when close is present
        let channel_findings: Vec<_> = findings.iter()
            .filter(|f| f.rule_id == "go.channel_never_closed")
            .collect();
        assert!(channel_findings.is_empty());
    }
}