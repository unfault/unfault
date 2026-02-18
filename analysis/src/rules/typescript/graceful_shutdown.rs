//! TypeScript Graceful Shutdown Detection Rule
//!
//! Detects Node.js servers that lack graceful shutdown handling.

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
pub struct TypescriptMissingGracefulShutdownRule;

impl TypescriptMissingGracefulShutdownRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptMissingGracefulShutdownRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptMissingGracefulShutdownRule {
    fn id(&self) -> &'static str {
        "typescript.missing_graceful_shutdown"
    }

    fn name(&self) -> &'static str {
        "Missing Graceful Shutdown"
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

            // Check if this is a server file
            let has_server = ts.calls.iter().any(|call| {
                let callee = call.callee.to_lowercase();
                callee.contains(".listen") || callee.contains("createserver")
            }) || ts.imports.iter().any(|imp| {
                let module = imp.module.to_lowercase();
                module == "express" || module == "fastify" || module == "@nestjs/core"
            });

            if !has_server {
                continue;
            }

            // Check for signal handlers
            let has_signal_handlers = ts.calls.iter().any(|call| {
                let callee = call.callee.to_lowercase();
                let has_sigterm = call.args.iter().any(|a| {
                    let al = a.value_repr.to_lowercase();
                    al.contains("sigterm") || al.contains("sigint")
                });
                (callee.contains("process.on") || callee.contains("process.once")) && has_sigterm
            });

            if has_signal_handlers {
                continue;
            }

            // Find the server.listen call
            let server_call = ts
                .calls
                .iter()
                .find(|call| call.callee.to_lowercase().contains(".listen"));

            let (line, column) = server_call
                .map(|c| (c.location.range.start_line + 1, c.location.range.start_col + 1))
                .unwrap_or((1, 1));

            let patch = FilePatch {
                file_id: *file_id,
                hunks: vec![PatchHunk {
                    range: PatchRange::InsertBeforeLine { line },
                    replacement: r#"// Add graceful shutdown handling:
// process.on('SIGTERM', async () => {
//   console.log('SIGTERM received, closing server...');
//   await server.close();
//   process.exit(0);
// });
"#
                        .to_string(),
                }],
            };

            findings.push(RuleFinding {
                rule_id: self.id().to_string(),
                title: "Server lacks graceful shutdown handling".to_string(),
                description: Some(format!(
                    "Server at line {} does not handle SIGTERM/SIGINT signals for graceful shutdown. \
                     In containerized environments (Kubernetes, Docker), graceful shutdown is critical \
                     to avoid dropped connections.",
                    line
                )),
                kind: FindingKind::ReliabilityRisk,
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
                fix_preview: Some("Add SIGTERM/SIGINT signal handlers".to_string()),
                tags: vec![
                    "reliability".into(),
                    "graceful-shutdown".into(),
                    "kubernetes".into(),
                ],
            });
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::graceful_shutdown())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptMissingGracefulShutdownRule::new();
        assert_eq!(rule.id(), "typescript.missing_graceful_shutdown");
    }
}