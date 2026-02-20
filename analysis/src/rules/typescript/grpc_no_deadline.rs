//! TypeScript gRPC No Deadline Detection Rule
//!
//! Detects gRPC calls without deadline/timeout configuration.

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
pub struct TypescriptGrpcNoDeadlineRule;

impl TypescriptGrpcNoDeadlineRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptGrpcNoDeadlineRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptGrpcNoDeadlineRule {
    fn id(&self) -> &'static str {
        "typescript.grpc_no_deadline"
    }

    fn name(&self) -> &'static str {
        "gRPC Call Without Deadline"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
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

            // Check for gRPC imports
            let has_grpc = ts.imports.iter().any(|imp| {
                let module = imp.module.to_lowercase();
                module.contains("grpc") || module.contains("@grpc")
            });

            if !has_grpc {
                continue;
            }

            // Look for gRPC method calls
            for call in &ts.calls {
                // gRPC calls are typically method calls on client stubs
                let is_grpc_call = call.callee.contains("client.")
                    || call.callee.contains("Client.")
                    || call.callee.contains("stub.")
                    || call.callee.contains("Stub.");

                if !is_grpc_call {
                    continue;
                }

                // Check if deadline/timeout is set
                let has_deadline =
                    call.args_repr.contains("deadline") || call.args_repr.contains("timeout");

                if has_deadline {
                    continue;
                }

                let line = call.location.range.start_line + 1;
                let column = call.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// Add deadline to gRPC call:\n\
                             // const deadline = new Date();\n\
                             // deadline.setSeconds(deadline.getSeconds() + 5);\n\
                             // client.method(request, { deadline });\n"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "gRPC call without deadline".to_string(),
                    description: Some(format!(
                        "gRPC call '{}' at line {} has no deadline configured. \
                         Without a deadline, the call may wait indefinitely if the server \
                         is unresponsive, causing resource exhaustion.",
                        call.callee, line
                    )),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.7,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Add deadline option".to_string()),
                    tags: vec!["grpc".into(), "timeout".into(), "reliability".into()],
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
        let rule = TypescriptGrpcNoDeadlineRule::new();
        assert_eq!(rule.id(), "typescript.grpc_no_deadline");
    }
}
