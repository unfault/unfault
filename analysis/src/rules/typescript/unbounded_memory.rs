//! TypeScript Unbounded Memory Detection Rule
//!
//! Detects operations that can consume unbounded memory.

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

/// Suppression comment marker for this rule (used in generated patches).
const SUPPRESSION_MARKER: &str = "unfault-ignore: typescript.unbounded_memory";

/// Rule that detects unbounded memory operations in TypeScript code.
///
/// Suppression is handled centrally in the session layer. Users can add:
/// `// unfault-ignore: typescript.unbounded_memory` or
/// `// unfault-ignore: unbounded_memory` (short form)
#[derive(Debug)]
pub struct TypescriptUnboundedMemoryRule;

impl TypescriptUnboundedMemoryRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptUnboundedMemoryRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptUnboundedMemoryRule {
    fn id(&self) -> &'static str {
        "typescript.unbounded_memory"
    }

    fn name(&self) -> &'static str {
        "Unbounded Memory Operation"
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

            // We need the source to check for suppression comments
            // The source is available via the parsed file, but we need to get it from somewhere
            // For now, we'll check suppression in the semantic model if available

        // Check for unbounded array operations
        for call in &ts.calls {
            let is_unbounded = call.callee.ends_with(".push")
                || call.callee.ends_with(".concat")
                || call.callee.ends_with(".slice")
                || (call.callee == "Array" && call.args_repr.contains("fill"))
                || call.callee.ends_with(".from");

            if !is_unbounded {
                continue;
            }

            // Check if it's inside a loop (using the in_loop field from semantic model)
            if !call.in_loop {
                continue;
            }

            let line = call.location.range.start_line + 1;
            let column = call.location.range.start_col + 1;

            // Suppression is handled centrally in session.rs
            // The patch adds a suppression marker comment that will be recognized by the centralized filter
                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: format!(
                            "// {} - bounded by loop iteration limit\n",
                            SUPPRESSION_MARKER
                        ),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!("Unbounded array growth: {}", call.callee),
                    description: Some(format!(
                        "Array operation '{}' inside loop at line {} can cause unbounded memory growth. \
                         Consider adding size limits to prevent out-of-memory conditions. \
                         If the loop is intentionally bounded, apply the fix to suppress this warning.",
                        call.callee, line
                    )),
                    kind: FindingKind::ResourceLeak,
                    severity: Severity::Medium,
                    confidence: 0.6,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Mark as intentionally bounded".to_string()),
                    tags: vec!["memory".into(), "stability".into(), "unbounded".into()],
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
        let rule = TypescriptUnboundedMemoryRule::new();
        assert_eq!(rule.id(), "typescript.unbounded_memory");
    }

    #[test]
    fn test_suppression_marker_constant() {
        // Verify the suppression marker uses the full rule ID format
        assert!(SUPPRESSION_MARKER.contains("typescript.unbounded_memory"));
    }
}