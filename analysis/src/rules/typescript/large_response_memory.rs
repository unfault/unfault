//! TypeScript Large Response Memory Detection Rule
//!
//! Detects loading entire HTTP responses into memory without streaming.

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

#[derive(Debug)]
pub struct TypescriptLargeResponseMemoryRule;

impl TypescriptLargeResponseMemoryRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptLargeResponseMemoryRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptLargeResponseMemoryRule {
    fn id(&self) -> &'static str {
        "typescript.large_response_memory"
    }

    fn name(&self) -> &'static str {
        "Large Response Loaded into Memory"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let ts = match sem.as_ref() {
                SourceSemantics::Typescript(ts) => ts,
                _ => continue,
            };

            // Check for patterns that load entire responses
            for call in &ts.calls {
                let callee_lower = call.callee.to_lowercase();

                // Detect full-body loading patterns
                let is_memory_load = callee_lower.ends_with(".json()")
                    || callee_lower.ends_with(".text()")
                    || callee_lower.ends_with(".buffer()")
                    || callee_lower.ends_with(".arraybuffer()")
                    || (callee_lower.contains("axios") && !callee_lower.contains("stream"));

                if !is_memory_load {
                    continue;
                }

                let line = call.location.range.start_line + 1;
                let column = call.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// Consider streaming for large responses:\n\
                             // const response = await fetch(url);\n\
                             // const reader = response.body.getReader();\n\
                             // while (true) { const { done, value } = await reader.read(); ... }\n"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "Response loaded entirely into memory".to_string(),
                    description: Some(format!(
                        "Response body at line {} is loaded entirely into memory. \
                         For large responses, consider using streaming to avoid memory exhaustion.",
                        line
                    )),
                    kind: FindingKind::PerformanceSmell,
                    severity: Severity::Low,
                    confidence: 0.5,
                    dimension: Dimension::Performance,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Use streaming for large responses".to_string()),
                    tags: vec!["performance".into(), "memory".into(), "streaming".into()],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::unbounded_resource())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptLargeResponseMemoryRule::new();
        assert_eq!(rule.id(), "typescript.large_response_memory");
    }
}
