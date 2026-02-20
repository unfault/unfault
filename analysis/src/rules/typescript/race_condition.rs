//! TypeScript Race Condition Detection Rule
//!
//! Detects potential race conditions in concurrent code.

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
pub struct TypescriptRaceConditionRule;

impl TypescriptRaceConditionRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptRaceConditionRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptRaceConditionRule {
    fn id(&self) -> &'static str {
        "typescript.race_condition"
    }

    fn name(&self) -> &'static str {
        "Potential Race Condition"
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

            // Look for global mutable state accessed in async functions
            // This can lead to race conditions
            for global_state in &ts.global_mutable_state {
                // Find async functions that might access this global
                for func in &ts.functions {
                    if !func.is_async {
                        continue;
                    }

                    // Check if function name or inner calls suggest access to this variable
                    let var_name = &global_state.variable_name;
                    let accesses_var = func.inner_calls.iter().any(|c| c.contains(var_name));

                    if !accesses_var {
                        continue;
                    }

                    let line = global_state.location.range.start_line + 1;
                    let column = global_state.location.range.start_col + 1;

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line },
                            replacement: "// WARNING: Potential race condition\n\
                                 // Consider using atomic operations or a mutex:\n\
                                 // import { Mutex } from 'async-mutex';\n\
                                 // const mutex = new Mutex();\n\
                                 // await mutex.runExclusive(async () => { /* update */ });\n"
                                .to_string(),
                        }],
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: format!("Potential race condition on '{}'", var_name),
                        description: Some(format!(
                            "Global mutable variable '{}' may be accessed by async function \
                             '{}'. This can cause race conditions when multiple \
                             async operations run concurrently.",
                            var_name, func.name
                        )),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::High,
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
                        fix_preview: Some("Use Mutex for synchronization".to_string()),
                        tags: vec![
                            "concurrency".into(),
                            "race-condition".into(),
                            "async".into(),
                        ],
                    });
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::unbounded_concurrency())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptRaceConditionRule::new();
        assert_eq!(rule.id(), "typescript.race_condition");
    }
}
