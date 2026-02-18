//! Rule: Hardcoded secrets in source code
//!
//! Detects hardcoded passwords, API keys, tokens, and other secrets in source code.

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

/// Rule that detects hardcoded secrets in TypeScript code.
///
/// Hardcoded secrets can be exposed in version control, make rotation difficult,
/// and may lead to credential leaks.
#[derive(Debug)]
pub struct TypescriptHardcodedSecretsRule;

impl TypescriptHardcodedSecretsRule {
    pub fn new() -> Self {
        Self
    }

    fn is_secret_variable_name(name: &str) -> bool {
        let lower = name.to_lowercase();
        let secret_keywords = [
            "password",
            "secret",
            "api_key",
            "apikey",
            "api-key",
            "token",
            "auth",
            "credential",
            "private_key",
            "privatekey",
            "access_key",
            "accesskey",
            "jwt",
            "bearer",
            "encryption_key",
            "signing_key",
            "client_secret",
            "clientsecret",
            "db_password",
            "database_password",
        ];
        secret_keywords.iter().any(|kw| lower.contains(kw))
    }

    fn looks_like_secret_value(value: &str) -> bool {
        let trimmed = value
            .trim_matches(|c| c == '\'' || c == '"' || c == '`')
            .trim();

        if trimmed.len() < 8 {
            return false;
        }

        let secret_prefixes = [
            "sk-", "pk_", "sk_", "xoxb-", "xoxp-", "ghp_", "gho_", "ghu_", "ghs_", "github_pat",
            "Bearer ", "Basic ", "eyJ", "AKIA",
        ];

        for prefix in &secret_prefixes {
            if trimmed.starts_with(prefix) {
                return true;
            }
        }

        let has_letters = trimmed.chars().any(|c| c.is_alphabetic());
        let has_numbers = trimmed.chars().any(|c| c.is_numeric());

        if has_letters && has_numbers && trimmed.len() >= 20 {
            return true;
        }

        false
    }
}

impl Default for TypescriptHardcodedSecretsRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptHardcodedSecretsRule {
    fn id(&self) -> &'static str {
        "typescript.hardcoded_secrets"
    }

    fn name(&self) -> &'static str {
        "Hardcoded secrets should use environment variables"
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

            // Skip test and example files
            if ts.path.contains(".test.")
                || ts.path.contains(".spec.")
                || ts.path.contains(".example.")
                || ts.path.contains(".sample.")
            {
                continue;
            }

            for var in &ts.variables {
                let is_secret_name = Self::is_secret_variable_name(&var.name);
                let is_secret_value = Self::looks_like_secret_value(&var.value_repr);

                if is_secret_name && !var.value_repr.contains("process.env") {
                    let env_var_name = var.name.to_uppercase();

                    let title = format!(
                        "Variable '{}' appears to contain a hardcoded secret",
                        var.name
                    );

                    let description = format!(
                        "The variable '{}' appears to contain a secret value. \
                         Hardcoded secrets can be exposed in version control and make rotation difficult. \
                         Use environment variables instead: process.env.{}",
                        var.name, env_var_name
                    );

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::ReplaceBytes {
                                start: var.location.range.start_col as usize,
                                end: var.location.range.end_col as usize,
                            },
                            replacement: format!(
                                "{} {} = process.env.{} || '';",
                                if var.is_exported { "export const" } else { "const" },
                                var.name,
                                env_var_name
                            ),
                        }],
                    };

                    let fix_preview = format!(
                        "// Before:\nconst {} = '...';\n// After:\nconst {} = process.env.{} || '';",
                        var.name, var.name, env_var_name
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::Critical,
                        confidence: if is_secret_value { 0.95 } else { 0.7 },
                        dimension: Dimension::Security,
                        file_id: *file_id,
                        file_path: ts.path.clone(),
                        line: Some(var.location.range.start_line + 1),
                        column: Some(var.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "typescript".into(),
                            "security".into(),
                            "secrets".into(),
                            "critical".into(),
                        ],
                    });
                } else if is_secret_value && !is_secret_name {
                    // Value looks like a secret even if variable name doesn't suggest it
                    let title = format!(
                        "Variable '{}' contains a value that looks like a secret",
                        var.name
                    );

                    let description = format!(
                        "The variable '{}' contains a value that appears to be a secret (API key, token, etc.). \
                         Use environment variables to store secrets securely.",
                        var.name
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::Critical,
                        confidence: 0.6,
                        dimension: Dimension::Security,
                        file_id: *file_id,
                        file_path: ts.path.clone(),
                        line: Some(var.location.range.start_line + 1),
                        column: Some(var.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: None,
                        tags: vec![
                            "typescript".into(),
                            "security".into(),
                            "secrets".into(),
                        ],
                    });
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::hardcoded_secrets())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::typescript::parse_typescript_file;
    use crate::semantics::typescript::build_typescript_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(path: &str, source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: path.to_string(),
            language: Language::Typescript,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_typescript_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_typescript_semantics(&parsed).unwrap();
        (file_id, Arc::new(SourceSemantics::Typescript(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = TypescriptHardcodedSecretsRule::new();
        assert_eq!(rule.id(), "typescript.hardcoded_secrets");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = TypescriptHardcodedSecretsRule::new();
        assert!(rule.name().contains("secret"));
    }

    #[tokio::test]
    async fn evaluate_detects_hardcoded_password() {
        let rule = TypescriptHardcodedSecretsRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "config.ts",
            r#"
const databasePassword = 'super-secret-password123';
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("databasePassword"));
    }

    #[tokio::test]
    async fn evaluate_ignores_env_var_usage() {
        let rule = TypescriptHardcodedSecretsRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "config.ts",
            r#"
const apiKey = process.env.API_KEY;
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_test_files() {
        let rule = TypescriptHardcodedSecretsRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "config.test.ts",
            r#"
const testApiKey = 'sk-test-123456789012345678901234';
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_typescript() {
        let rule = TypescriptHardcodedSecretsRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn secret_detection_patterns() {
        assert!(TypescriptHardcodedSecretsRule::is_secret_variable_name(
            "apiKey"
        ));
        assert!(TypescriptHardcodedSecretsRule::is_secret_variable_name(
            "dbPassword"
        ));
        assert!(TypescriptHardcodedSecretsRule::is_secret_variable_name(
            "JWT_SECRET"
        ));
        assert!(!TypescriptHardcodedSecretsRule::is_secret_variable_name(
            "userName"
        ));
    }

    #[test]
    fn secret_value_detection() {
        assert!(TypescriptHardcodedSecretsRule::looks_like_secret_value(
            "sk-1234567890abcdef"
        ));
        assert!(TypescriptHardcodedSecretsRule::looks_like_secret_value(
            "ghp_1234567890abcdefghijklmnop"
        ));
        assert!(TypescriptHardcodedSecretsRule::looks_like_secret_value(
            "eyJhbGciOiJIUzI1NiJ9"
        ));
        assert!(!TypescriptHardcodedSecretsRule::looks_like_secret_value(
            "hello"
        ));
    }
}