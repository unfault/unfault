//! TypeScript Naive DateTime Detection Rule
//!
//! Detects Date operations that don't handle timezones properly.

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

#[derive(Debug)]
pub struct TypescriptNaiveDatetimeRule;

impl TypescriptNaiveDatetimeRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptNaiveDatetimeRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptNaiveDatetimeRule {
    fn id(&self) -> &'static str {
        "typescript.naive_datetime"
    }

    fn name(&self) -> &'static str {
        "Naive DateTime Usage"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
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

            // Check if date-fns, luxon, or dayjs is already imported
            let has_date_lib = ts.imports.iter().any(|imp| {
                let module = imp.module.to_lowercase();
                module.contains("date-fns")
                    || module.contains("luxon")
                    || module.contains("dayjs")
                    || module.contains("moment")
            });

            if has_date_lib {
                continue;
            }

            // Find new Date() calls
            for call in &ts.calls {
                let callee_lower = call.callee.to_lowercase();
                
                if callee_lower != "date" && !call.args_repr.contains("new Date") {
                    continue;
                }

                // Skip if it's new Date() with ISO string (timezone-aware)
                let args_text = &call.args_repr;

                if args_text.contains("Z") || args_text.contains("T") || args_text.contains("ISO") {
                    continue;
                }

                let line = call.location.range.start_line + 1;
                let column = call.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// Use timezone-aware date library:\n\
                             // import { DateTime } from 'luxon';\n\
                             // const dt = DateTime.now().setZone('UTC');\n"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "Naive Date without timezone handling".to_string(),
                    description: Some(format!(
                        "Date creation at line {} may not handle timezones correctly. \
                         Use a timezone-aware library like luxon or date-fns-tz.",
                        line
                    )),
                    kind: FindingKind::BehaviorThreat,
                    severity: Severity::Low,
                    confidence: 0.5,
                    dimension: Dimension::Correctness,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Use luxon or date-fns with timezone".to_string()),
                    tags: vec!["correctness".into(), "datetime".into(), "timezone".into()],
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
    fn test_rule_id() {
        let rule = TypescriptNaiveDatetimeRule::new();
        assert_eq!(rule.id(), "typescript.naive_datetime");
    }
}