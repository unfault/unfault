//! Rule: GORM Query Timeout
//!
//! Detects GORM queries without context timeout.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::timeout;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects GORM queries without context timeout.
#[derive(Debug, Default)]
pub struct GormQueryTimeoutRule;

impl GormQueryTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GormQueryTimeoutRule {
    fn id(&self) -> &'static str {
        "go.gorm.query_timeout"
    }

    fn name(&self) -> &'static str {
        "GORM Query Timeout"
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

            // Check if GORM is imported
            let has_gorm = go_sem
                .imports
                .iter()
                .any(|imp| imp.path.contains("gorm.io/gorm"));

            if !has_gorm {
                continue;
            }

            // Check for WithContext usage
            let has_context = go_sem
                .calls
                .iter()
                .any(|c| c.function_call.callee_expr.contains("WithContext"));

            if has_context {
                continue;
            }

            // Look for query operations
            for call in &go_sem.calls {
                let is_query = call.function_call.callee_expr.contains(".Find")
                    || call.function_call.callee_expr.contains(".First")
                    || call.function_call.callee_expr.contains(".Create")
                    || call.function_call.callee_expr.contains(".Save")
                    || call.function_call.callee_expr.contains(".Update")
                    || call.function_call.callee_expr.contains(".Delete")
                    || call.function_call.callee_expr.contains(".Exec")
                    || call.function_call.callee_expr.contains(".Raw");

                if is_query {
                    let line = call.function_call.location.line;

                    let title = format!("GORM query at line {} lacks context timeout", line);

                    let description = format!(
                        "GORM query at line {} does not use WithContext for timeout. \
                         Database queries without timeout can hang indefinitely, blocking \
                         goroutines and potentially causing resource exhaustion. Use \
                         WithContext with a timeout context.",
                        line
                    );

                    let patch = generate_context_patch(*file_id, line);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.80,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go_sem.path.clone(),
                        line: Some(line),
                        column: Some(1),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("// Use WithContext for query timeout".to_string()),
                        tags: vec![
                            "go".into(),
                            "gorm".into(),
                            "database".into(),
                            "timeout".into(),
                        ],
                    });
                    break; // One finding per file
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(timeout())
    }
}

fn generate_context_patch(file_id: FileId, line: u32) -> FilePatch {
    let replacement = r#"// Add context timeout to GORM queries:
// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// defer cancel()
// db.WithContext(ctx).Find(&items)
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
        let rule = GormQueryTimeoutRule::new();
        assert_eq!(rule.id(), "go.gorm.query_timeout");
    }
}
