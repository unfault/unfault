//! Rule: GORM N+1 Query Detection
//!
//! Detects potential N+1 query patterns in GORM usage.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::n_plus_one;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects potential N+1 query patterns in GORM.
#[derive(Debug, Default)]
pub struct GormNPlusOneRule;

impl GormNPlusOneRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GormNPlusOneRule {
    fn id(&self) -> &'static str {
        "go.gorm.n_plus_one"
    }

    fn name(&self) -> &'static str {
        "GORM N+1 Query Detection"
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

            // Look for Find/First calls inside loops without Preload
            for call in &go_sem.calls {
                if !call.in_loop {
                    continue;
                }

                let is_query = call.function_call.callee_expr.contains(".Find")
                    || call.function_call.callee_expr.contains(".First")
                    || call.function_call.callee_expr.contains(".Take")
                    || call.function_call.callee_expr.ends_with("Find")
                    || call.function_call.callee_expr.ends_with("First");

                if is_query {
                    let line = call.function_call.location.line;

                    // Check if Preload is used
                    let has_preload = go_sem.calls.iter().any(|c| {
                        c.function_call.callee_expr.contains("Preload")
                            || c.function_call.callee_expr.contains("Joins")
                    });

                    if !has_preload {
                        let title = format!("Potential N+1 query at line {}", line);

                        let description = format!(
                            "Database query at line {} inside a loop without Preload could cause \
                             N+1 query problem. For each item in the loop, a separate query is \
                             executed, leading to poor performance. Use Preload() or Joins() to \
                             eager load related data.",
                            line
                        );

                        let patch = generate_preload_patch(*file_id, line);

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::High,
                            confidence: 0.75,
                            dimension: Dimension::Performance,
                            file_id: *file_id,
                            file_path: go_sem.path.clone(),
                            line: Some(line),
                            column: Some(1),
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(
                                "// Use Preload() to eager load related data".to_string(),
                            ),
                            tags: vec![
                                "go".into(),
                                "gorm".into(),
                                "database".into(),
                                "n-plus-one".into(),
                                "performance".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(n_plus_one())
    }
}

fn generate_preload_patch(file_id: FileId, line: u32) -> FilePatch {
    let replacement = r#"// Use Preload to avoid N+1 queries:
// db.Preload("RelatedModel").Find(&items)
// Or use Joins for single-table optimization:
// db.Joins("RelatedModel").Find(&items)
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
        let rule = GormNPlusOneRule::new();
        assert_eq!(rule.id(), "go.gorm.n_plus_one");
    }
}
