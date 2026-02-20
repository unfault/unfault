//! Rule: Large HTTP responses loaded entirely into memory.
//!
//! Large responses should be streamed rather than loaded entirely into memory.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects potentially large responses loaded into memory.
#[derive(Debug, Default)]
pub struct RustLargeResponseMemoryRule;

impl RustLargeResponseMemoryRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustLargeResponseMemoryRule {
    fn id(&self) -> &'static str {
        "rust.large_response_memory"
    }

    fn name(&self) -> &'static str {
        "Large HTTP response loaded entirely into memory"
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

            // Look for patterns that load entire response into memory
            for call in &rust.calls {
                let is_memory_load = call.function_call.callee_expr.contains(".bytes()")
                    || call.function_call.callee_expr.contains(".text()")
                    || call.function_call.callee_expr.contains(".json()")
                    || call.function_call.callee_expr.contains("to_vec()")
                    || call.function_call.callee_expr.contains("read_to_string")
                    || call.function_call.callee_expr.contains("read_to_end");

                if !is_memory_load {
                    continue;
                }

                // Check if this is in an HTTP context
                let in_http_context = rust.uses.iter().any(|u| {
                    u.path.contains("reqwest")
                        || u.path.contains("hyper")
                        || u.path.contains("surf")
                });

                if !in_http_context {
                    continue;
                }

                let line = call.function_call.location.line;

                let title = "HTTP response fully loaded into memory".to_string();

                let description = format!(
                    "A call at line {} loads the entire HTTP response into memory.\n\n\
                     **Why this matters:**\n\
                     - Large responses can cause OOM\n\
                     - Memory spikes affect other requests\n\
                     - Slower time-to-first-byte\n\
                     - No backpressure on slow consumers\n\n\
                     **Recommendations:**\n\
                     - Use `bytes_stream()` for streaming\n\
                     - Process data in chunks\n\
                     - Set response size limits\n\
                     - Use streaming JSON parsers\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use futures::StreamExt;\n\
                     \n\
                     let mut stream = response.bytes_stream();\n\
                     while let Some(chunk) = stream.next().await {{\n    \
                         let chunk = chunk?;\n    \
                         process_chunk(&chunk);\n\
                     }}\n\
                     ```",
                    line
                );

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement:
                            "// TODO: Consider streaming large responses with bytes_stream()"
                                .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::PerformanceSmell,
                    severity: Severity::Medium,
                    confidence: 0.65,
                    dimension: Dimension::Scalability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("let stream = response.bytes_stream();".to_string()),
                    tags: vec![
                        "rust".into(),
                        "memory".into(),
                        "http".into(),
                        "streaming".into(),
                    ],
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_id_is_correct() {
        let rule = RustLargeResponseMemoryRule::new();
        assert_eq!(rule.id(), "rust.large_response_memory");
    }
}
