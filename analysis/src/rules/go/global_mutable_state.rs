//! Rule: Global mutable state in Go
//!
//! Detects package-level mutable variables that can cause race conditions.

use async_trait::async_trait;
use std::sync::Arc;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects global mutable state.
#[derive(Debug, Default)]
pub struct GoGlobalMutableStateRule;

impl GoGlobalMutableStateRule {
    pub fn new() -> Self {
        Self
    }

    fn is_mutable_type(type_str: &Option<String>) -> bool {
        match type_str {
            Some(t) => {
                t.starts_with("map[")
                    || t.starts_with("[]")
                    || t.starts_with("*")
                    || t.contains("chan ")
            }
            None => false,
        }
    }
}

#[async_trait]
impl Rule for GoGlobalMutableStateRule {
    fn id(&self) -> &'static str {
        "go.global_mutable_state"
    }

    fn name(&self) -> &'static str {
        "Global mutable state"
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

            // Check package-level variable declarations
            for decl in &go.declarations {
                if decl.is_const {
                    continue; // Constants are fine
                }

                // Check if the type is mutable
                if Self::is_mutable_type(&decl.decl_type) {
                    let title = format!("Global mutable variable '{}'", decl.name);

                    let description = format!(
                        "Package-level variable '{}' with type '{}' is mutable and can be accessed \
                         from multiple goroutines. This can cause race conditions. Consider using \
                         sync.Mutex, sync.RWMutex, or sync.Map for safe concurrent access.",
                        decl.name,
                        decl.decl_type.as_deref().unwrap_or("unknown")
                    );

                    let replacement = format!(
                        "// Consider protecting with sync primitives:\n// var {}Mu sync.RWMutex\n// var {} {}",
                        decl.name,
                        decl.name,
                        decl.decl_type.as_deref().unwrap_or("")
                    );

                    // Convert 0-based line to 1-based for display
                    let line = decl.location.range.start_line + 1;
                    let column = decl.location.range.start_col + 1;

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line },
                            replacement,
                        }],
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::High,
                        confidence: 0.85,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: Some(column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("Add sync.Mutex protection".to_string()),
                        tags: vec!["go".into(), "concurrency".into(), "race-condition".into()],
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
        let rule = GoGlobalMutableStateRule::new();
        assert_eq!(rule.id(), "go.global_mutable_state");
        assert!(!rule.name().is_empty());
    }

    #[test]
    fn test_is_mutable_type() {
        assert!(GoGlobalMutableStateRule::is_mutable_type(&Some(
            "map[string]int".to_string()
        )));
        assert!(GoGlobalMutableStateRule::is_mutable_type(&Some(
            "[]string".to_string()
        )));
        assert!(GoGlobalMutableStateRule::is_mutable_type(&Some(
            "*Config".to_string()
        )));
        assert!(!GoGlobalMutableStateRule::is_mutable_type(&Some(
            "int".to_string()
        )));
        assert!(!GoGlobalMutableStateRule::is_mutable_type(&None));
    }
}
