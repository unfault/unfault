//! Rule: Go Hardcoded Secrets
//!
//! Detects hardcoded passwords, API keys, and other secrets in Go code.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::hardcoded_secrets;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects hardcoded secrets in Go code.
#[derive(Debug, Default)]
pub struct GoHardcodedSecretsRule;

impl GoHardcodedSecretsRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoHardcodedSecretsRule {
    fn id(&self) -> &'static str {
        "go.hardcoded_secrets"
    }

    fn name(&self) -> &'static str {
        "Go Hardcoded Secrets"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(hardcoded_secrets())
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

            // Look for suspicious variable assignments
            for call in &go_sem.calls {
                let lower_callee = call.function_call.callee_expr.to_lowercase();
                let lower_args = call.args_repr.to_lowercase();

                // Check for suspicious patterns
                let is_suspicious = (lower_callee.contains("password")
                    || lower_callee.contains("secret")
                    || lower_callee.contains("apikey")
                    || lower_callee.contains("api_key")
                    || lower_callee.contains("token")
                    || lower_args.contains("password")
                    || lower_args.contains("secret"))
                    && (call.args_repr.contains("\"")
                        && !call.args_repr.contains("os.Getenv")
                        && !call.args_repr.contains("viper.")
                        && !call.args_repr.contains("config."));

                if is_suspicious {
                    let line = call.function_call.location.line;

                    let title = format!(
                        "Potential hardcoded secret at line {}",
                        line
                    );

                    let description = format!(
                        "A potential hardcoded secret was detected at line {}. \
                         Hardcoded secrets are a security risk as they can be \
                         exposed in source control, logs, or error messages. \
                         Use environment variables or a secrets manager instead.",
                        line
                    );

                    let patch = generate_secrets_patch(*file_id, line);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::Critical,
                        confidence: 0.60,
                        dimension: Dimension::Security,
                        file_id: *file_id,
                        file_path: go_sem.path.clone(),
                        line: Some(line),
                        column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("// Use os.Getenv() for secrets".to_string()),
                        tags: vec![
                            "go".into(),
                            "security".into(),
                            "secrets".into(),
                            "hardcoded".into(),
                        ],
                    });
                }
            }
        }

        findings
    }
}

fn generate_secrets_patch(file_id: FileId, line: u32) -> FilePatch {
    let replacement = r#"// Replace hardcoded secret with environment variable:
// password := os.Getenv("DB_PASSWORD")
// apiKey := os.Getenv("API_KEY")
// Or use a secrets manager like HashiCorp Vault
"#.to_string();

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
        let rule = GoHardcodedSecretsRule::new();
        assert_eq!(rule.id(), "go.hardcoded_secrets");
    }
}