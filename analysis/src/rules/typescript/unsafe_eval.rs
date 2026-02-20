//! TypeScript Unsafe Eval Detection Rule
//!
//! Detects use of eval() and similar dynamic code execution.

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
pub struct TypescriptUnsafeEvalRule;

impl TypescriptUnsafeEvalRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptUnsafeEvalRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptUnsafeEvalRule {
    fn id(&self) -> &'static str {
        "typescript.unsafe_eval"
    }

    fn name(&self) -> &'static str {
        "Unsafe Dynamic Code Execution"
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

            for call in &ts.calls {
                let is_unsafe = call.callee == "eval"
                    || call.callee == "Function"
                    || call.callee == "setTimeout"
                        && call.args.first().map_or(false, |a| {
                            a.value_repr.starts_with('"') || a.value_repr.starts_with('\'')
                        })
                    || call.callee == "setInterval"
                        && call.args.first().map_or(false, |a| {
                            a.value_repr.starts_with('"') || a.value_repr.starts_with('\'')
                        });

                if !is_unsafe {
                    continue;
                }

                let line = call.location.range.start_line + 1;
                let column = call.location.range.start_col + 1;

                let (title, suggestion) = if call.callee == "eval" {
                    (
                        "Use of eval() is a security risk".to_string(),
                        "Avoid eval(); use JSON.parse() for JSON or restructure code",
                    )
                } else if call.callee == "Function" {
                    (
                        "Use of Function constructor is a security risk".to_string(),
                        "Avoid Function constructor; use regular functions",
                    )
                } else {
                    (
                        "Use of string argument in timer is a security risk".to_string(),
                        "Pass a function reference instead of string",
                    )
                };

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: format!("// SECURITY: {}\n// {}\n", title, suggestion),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: title.clone(),
                    description: Some(format!(
                        "Dynamic code execution via '{}' at line {} can lead to code injection \
                         vulnerabilities. {}.",
                        call.callee, line, suggestion
                    )),
                    kind: FindingKind::SecurityVulnerability,
                    severity: Severity::High,
                    confidence: 0.9,
                    dimension: Dimension::Security,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(suggestion.to_string()),
                    tags: vec!["security".into(), "eval".into(), "injection".into()],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::sql_injection())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptUnsafeEvalRule::new();
        assert_eq!(rule.id(), "typescript.unsafe_eval");
    }
}
