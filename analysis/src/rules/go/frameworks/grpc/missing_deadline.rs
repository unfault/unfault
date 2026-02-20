//! Rule: gRPC Missing Deadline
//!
//! Detects gRPC client calls without deadline/timeout.

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

/// Rule that detects gRPC client calls without deadline.
#[derive(Debug, Default)]
pub struct GrpcMissingDeadlineRule;

impl GrpcMissingDeadlineRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GrpcMissingDeadlineRule {
    fn id(&self) -> &'static str {
        "go.grpc.missing_deadline"
    }

    fn name(&self) -> &'static str {
        "gRPC Missing Deadline"
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

            // Check if gRPC is imported
            let has_grpc = go_sem
                .imports
                .iter()
                .any(|imp| imp.path.contains("google.golang.org/grpc"));

            if !has_grpc {
                continue;
            }

            // Check if context deadline handling is present
            let has_deadline_handling = go_sem.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("context.WithTimeout")
                    || c.function_call.callee_expr.contains("context.WithDeadline")
                    || c.function_call.callee_expr.contains("WithDeadline")
                    || c.function_call.callee_expr.contains("WithTimeout")
            });

            // Look for gRPC client calls
            for call in &go_sem.calls {
                // Check for gRPC client method calls
                let is_grpc_call = call.function_call.callee_expr.contains("Client.")
                    || call.function_call.callee_expr.ends_with("Client")
                    || call.args_repr.contains("grpc.");

                if is_grpc_call && !has_deadline_handling {
                    let line = call.function_call.location.line;

                    let title = format!("gRPC client call at line {} lacks deadline", line);

                    let description = format!(
                        "gRPC client call at line {} lacks deadline. Use context.WithTimeout() \
                         to prevent hanging requests. Without a deadline, the call can wait \
                         indefinitely if the server is slow or unresponsive.",
                        line
                    );

                    let patch = generate_deadline_patch(*file_id, line);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::High,
                        confidence: 0.85,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go_sem.path.clone(),
                        line: Some(line),
                        column: Some(1),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("// Add deadline to gRPC call".to_string()),
                        tags: vec![
                            "go".into(),
                            "grpc".into(),
                            "deadline".into(),
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

fn generate_deadline_patch(file_id: FileId, line: u32) -> FilePatch {
    let replacement = r#"// Add deadline to gRPC call:
// ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
// defer cancel()
// resp, err := client.SomeMethod(ctx, request)
// if err != nil {
//     if status.Code(err) == codes.DeadlineExceeded {
//         // Handle timeout
//     }
//     return err
// }
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
        let rule = GrpcMissingDeadlineRule::new();
        assert_eq!(rule.id(), "go.grpc.missing_deadline");
    }
}
