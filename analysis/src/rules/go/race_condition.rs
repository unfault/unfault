//! Rule: Potential race conditions in Go code
//!
//! Detects goroutines that capture variables that may cause race conditions.

use std::sync::Arc;
use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects potential race conditions in Go code.
#[derive(Debug, Default)]
pub struct GoRaceConditionRule;

impl GoRaceConditionRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoRaceConditionRule {
    fn id(&self) -> &'static str {
        "go.race_condition"
    }

    fn name(&self) -> &'static str {
        "Potential race condition in goroutine"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(error_handling_in_handler())
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

            // Check for goroutines that might have race conditions
            for goroutine in &go.goroutines {
                // Anonymous goroutines capturing variables are risky
                if goroutine.is_anonymous {
                    // Check if it looks like it's using loop variables
                    // (common pattern: go func() { use_i }() inside for loop)
                    let _text = &goroutine.text;
                    
                    // Simple heuristic: anonymous goroutine in a loop-like context
                    // warning about variable capture
                    let title = "Anonymous goroutine may have race condition".to_string();

                    let description = format!(
                        "Anonymous goroutine at line {} may capture shared variables by reference. \
                         If used inside a loop, the variable may change before the goroutine \
                         executes. Pass variables as parameters to the goroutine function instead.",
                        goroutine.line
                    );

                    // Generate patch suggestion
                    let replacement = format!(
                        "// Pass captured variables as parameters to avoid race:\n// go func(val Type) {{\n//     // use val instead of captured variable\n// }}(capturedVar)"
                    );

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line: goroutine.line },
                            replacement,
                        }],
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::High,
                        confidence: 0.70,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(goroutine.line),
                        column: Some(goroutine.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("Pass variables as parameters to goroutine".to_string()),
                        tags: vec![
                            "go".into(),
                            "race-condition".into(),
                            "concurrency".into(),
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

    #[test]
    fn test_rule_metadata() {
        let rule = GoRaceConditionRule::new();
        assert_eq!(rule.id(), "go.race_condition");
        assert!(!rule.name().is_empty());
    }
}