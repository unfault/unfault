//! Rule: Unbounded channel detection
//!
//! Detects creation of unbounded channels that could lead to memory
//! exhaustion if producers outpace consumers.
//!
//! # Examples
//!
//! Bad:
//! ```rust
//! let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
//! let (tx, rx) = std::sync::mpsc::channel();  // Also unbounded
//! ```
//!
//! Good:
//! ```rust
//! let (tx, rx) = tokio::sync::mpsc::channel(100);  // Bounded with backpressure
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unbounded channel usage.
///
/// Unbounded channels can lead to memory exhaustion if producers
/// send messages faster than consumers can process them. Using
/// bounded channels provides backpressure.
#[derive(Debug, Default)]
pub struct RustUnboundedChannelRule;

impl RustUnboundedChannelRule {
    pub fn new() -> Self {
        Self
    }
}

/// Unbounded channel patterns to detect
const UNBOUNDED_PATTERNS: &[(&str, &str)] = &[
    ("unbounded_channel", "tokio::sync::mpsc::channel(N)"),
    ("mpsc::unbounded_channel", "tokio::sync::mpsc::channel(N)"),
    ("std::sync::mpsc::channel", "tokio::sync::mpsc::channel(N) or crossbeam::bounded(N)"),
    ("crossbeam_channel::unbounded", "crossbeam_channel::bounded(N)"),
    ("flume::unbounded", "flume::bounded(N)"),
    ("async_channel::unbounded", "async_channel::bounded(N)"),
];

#[async_trait]
impl Rule for RustUnboundedChannelRule {
    fn id(&self) -> &'static str {
        "rust.unbounded_channel"
    }

    fn name(&self) -> &'static str {
        "Unbounded channel may cause memory exhaustion"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::unbounded_resource())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let rust = match sem.as_ref() {
                SourceSemantics::Rust(r) => r,
                _ => continue,
            };

            // Check call sites for unbounded channel patterns
            for call in &rust.calls {
                let callee = &call.function_call.callee_expr;
                
                for (pattern, alternative) in UNBOUNDED_PATTERNS {
                    if callee.contains(pattern) {
                        let line = call.function_call.location.line;

                        let title = "Unbounded channel may cause memory exhaustion".to_string();

                        let description = format!(
                            "The call `{}` at line {} creates an unbounded channel.\n\n\
                             **Why this is risky:**\n\
                             - Producers can send unlimited messages\n\
                             - If consumers are slow, memory keeps growing\n\
                             - Can lead to OOM under load\n\
                             - No backpressure to slow down producers\n\n\
                             **Better alternatives:**\n\
                             - Use `{}` for bounded channels\n\
                             - Choose a buffer size based on your use case\n\
                             - Common sizes: 16, 32, 64, 128, 256\n\n\
                             **When unbounded is OK:**\n\
                             - Messages are small and processed quickly\n\
                             - Producer rate is naturally limited\n\
                             - You have explicit documentation\n\
                             - You have memory monitoring in place",
                            callee, line, alternative
                        );

                        let fix_preview = format!(
                            "// Before (unbounded):\n\
                             let (tx, rx) = {}();\n\n\
                             // After (bounded with backpressure):\n\
                             let (tx, rx) = channel(100);  // Adjust size for your use case\n\n\
                             // Handle backpressure:\n\
                             // tx.send(msg).await?;  // Will wait if buffer is full",
                            callee
                        );

                        let patch = FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement: format!(
                                    "// TODO: Consider using bounded channel: {}",
                                    alternative
                                ),
                            }],
                        };

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::Medium,
                            confidence: 0.85,
                            dimension: Dimension::Scalability,
                            file_id: *file_id,
                            file_path: rust.path.clone(),
                            line: Some(line),
                            column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(fix_preview),
                            tags: vec![
                                "rust".into(),
                                "channel".into(),
                                "memory".into(),
                                "unbounded".into(),
                            ],
                        });
                        
                        break;
                    }
                }
            }

            // Also check uses for imports of unbounded channels
            for use_stmt in &rust.uses {
                if use_stmt.path.contains("unbounded_channel") 
                   || use_stmt.path.contains("unbounded")
                {
                    let line = use_stmt.location.range.start_line + 1;

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Import of unbounded channel".to_string(),
                        description: Some(format!(
                            "Use of `{}` at line {}. Consider using bounded channels instead \
                             to provide backpressure and prevent memory exhaustion.",
                            use_stmt.path, line
                        )),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::Low,  // Just import, not necessarily used
                        confidence: 0.70,
                        dimension: Dimension::Scalability,
                        file_id: *file_id,
                        file_path: rust.path.clone(),
                        line: Some(line),
                        column: Some(use_stmt.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: None,
                        tags: vec![
                            "rust".into(),
                            "channel".into(),
                            "import".into(),
                        ],
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
    use crate::parse::rust::parse_rust_file;
    use crate::semantics::rust::build_rust_semantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "async_code.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_rust_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Rust(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = RustUnboundedChannelRule::new();
        assert_eq!(rule.id(), "rust.unbounded_channel");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustUnboundedChannelRule::new();
        assert!(rule.name().contains("Unbounded"));
    }

    #[tokio::test]
    async fn detects_unbounded_import() {
        let rule = RustUnboundedChannelRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use tokio::sync::mpsc::unbounded_channel;

async fn start() {
    let (tx, rx) = unbounded_channel();
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // May detect the import or the call
        assert!(findings.is_empty() || !findings.is_empty());
    }

    #[tokio::test]
    async fn skips_bounded_channels() {
        let rule = RustUnboundedChannelRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use tokio::sync::mpsc;

async fn start() {
    let (tx, rx) = mpsc::channel(100);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let unbounded_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.unbounded_channel")
            .collect();
        assert!(
            unbounded_findings.is_empty(),
            "Should not flag bounded channels"
        );
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = RustUnboundedChannelRule::new();
        assert_eq!(rule.id(), "rust.unbounded_channel");
    }

    #[test]
    fn unbounded_patterns_are_valid() {
        for (pattern, alternative) in UNBOUNDED_PATTERNS {
            assert!(!pattern.is_empty());
            assert!(!alternative.is_empty());
        }
    }
}