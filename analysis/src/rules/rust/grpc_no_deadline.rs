//! Rule: gRPC calls without deadline/timeout.
//!
//! gRPC calls should have deadlines to prevent indefinite blocking.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects gRPC calls without deadlines.
#[derive(Debug, Default)]
pub struct RustGrpcNoDeadlineRule;

impl RustGrpcNoDeadlineRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustGrpcNoDeadlineRule {
    fn id(&self) -> &'static str {
        "rust.grpc_no_deadline"
    }

    fn name(&self) -> &'static str {
        "gRPC call without deadline/timeout"
    }

    fn applicability(&self) -> Option<crate::types::finding::FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let rust = match sem.as_ref() {
                SourceSemantics::Rust(r) => r,
                _ => continue,
            };

            // Check if using tonic (most common Rust gRPC library)
            let uses_grpc = rust
                .uses
                .iter()
                .any(|u| u.path.contains("tonic") || u.path.contains("grpc"));

            if !uses_grpc {
                continue;
            }

            // Check if timeout is set
            let has_timeout = rust.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("timeout")
                    || c.function_call.callee_expr.contains("deadline")
                    || c.function_call.callee_expr.contains("with_timeout")
            });

            if has_timeout {
                continue;
            }

            // Look for gRPC client calls
            for call in &rust.calls {
                let is_grpc_call = call.function_call.callee_expr.contains("_client")
                    || call.function_call.callee_expr.contains("Client::")
                    || call.function_call.callee_expr.ends_with("_rpc")
                    || (call.function_call.callee_expr.contains(".")
                        && rust.uses.iter().any(|u| u.path.contains("tonic")));

                if !is_grpc_call {
                    continue;
                }

                // Skip if this appears to have a timeout nearby
                if call.function_call.callee_expr.contains("timeout") {
                    continue;
                }

                let line = call.function_call.location.line;

                let title = "gRPC call without deadline".to_string();

                let description = format!(
                    "A gRPC call at line {} doesn't appear to have a deadline set.\n\n\
                     **Why this matters:**\n\
                     - Calls can block indefinitely if server is slow\n\
                     - No automatic retry on timeout\n\
                     - Resource exhaustion from accumulated calls\n\
                     - Poor user experience from hung requests\n\n\
                     **Recommendations:**\n\
                     - Set deadline using `Request::set_timeout()`\n\
                     - Use `tokio::time::timeout()` wrapper\n\
                     - Configure client-level defaults\n\
                     - Implement retry with backoff\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use tonic::Request;\n\
                     use std::time::Duration;\n\
                     \n\
                     let mut request = Request::new(payload);\n\
                     request.set_timeout(Duration::from_secs(30));\n\
                     \n\
                     let response = client.some_rpc(request).await?;\n\
                     \n\
                     // Or with tokio timeout:\n\
                     let response = tokio::time::timeout(\n    \
                         Duration::from_secs(30),\n    \
                         client.some_rpc(Request::new(payload))\n\
                     ).await??;\n\
                     ```",
                    line
                );

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Set gRPC deadline with request.set_timeout()"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::ReliabilityRisk,
                    severity: Severity::High,
                    confidence: 0.70,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("request.set_timeout(Duration::from_secs(30));".to_string()),
                    tags: vec![
                        "rust".into(),
                        "grpc".into(),
                        "tonic".into(),
                        "timeout".into(),
                    ],
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
    fn rule_id_is_correct() {
        let rule = RustGrpcNoDeadlineRule::new();
        assert_eq!(rule.id(), "rust.grpc_no_deadline");
    }
}
