//! Rule: Hardcoded secrets detection
//!
//! Detects hardcoded API keys, passwords, tokens, and other secrets
//! in Rust source code. These should be loaded from environment
//! variables or a secrets manager.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! const API_KEY: &str = "sk-1234567890abcdef";
//! let password = "super_secret_password";
//! ```
//!
//! Good:
//! ```rust,ignore
//! let api_key = std::env::var("API_KEY")?;
//! let password = std::env::var("DATABASE_PASSWORD")?;
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use regex::Regex;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects hardcoded secrets in code.
///
/// Secrets like API keys, passwords, and tokens should never be
/// hardcoded in source files. They should be loaded from environment
/// variables, configuration files, or a secrets manager.
#[derive(Debug, Default)]
pub struct RustHardcodedSecretsRule;

impl RustHardcodedSecretsRule {
    pub fn new() -> Self {
        Self
    }
}

/// Patterns that indicate a secret variable name
const SECRET_NAME_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "api_key",
    "apikey",
    "api-key",
    "token",
    "auth_token",
    "access_token",
    "refresh_token",
    "bearer",
    "credential",
    "private_key",
    "privatekey",
    "signing_key",
    "encryption_key",
    "client_secret",
    "client_id",
    "aws_access_key",
    "aws_secret",
];

/// Regex patterns for detecting various secret formats
fn get_secret_patterns() -> Vec<(&'static str, Regex, &'static str)> {
    vec![
        // AWS Access Keys
        (
            "AWS Access Key",
            Regex::new(r#"AKIA[0-9A-Z]{16}"#).unwrap(),
            "AWS access key detected - use environment variables or AWS credentials file",
        ),
        // AWS Secret Keys
        (
            "AWS Secret Key",
            Regex::new(r#"[A-Za-z0-9/+=]{40}"#).unwrap(),
            "Possible AWS secret key - use environment variables or AWS credentials file",
        ),
        // GitHub tokens
        (
            "GitHub Token",
            Regex::new(r#"gh[ps]_[A-Za-z0-9]{36,}"#).unwrap(),
            "GitHub token detected - use GITHUB_TOKEN environment variable",
        ),
        // Slack tokens
        (
            "Slack Token",
            Regex::new(r#"xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}"#).unwrap(),
            "Slack token detected - use environment variables",
        ),
        // OpenAI API keys
        (
            "OpenAI API Key",
            Regex::new(r#"sk-[A-Za-z0-9]{48}"#).unwrap(),
            "OpenAI API key detected - use OPENAI_API_KEY environment variable",
        ),
        // Stripe keys
        (
            "Stripe Key",
            Regex::new(r#"sk_live_[0-9a-zA-Z]{24}"#).unwrap(),
            "Stripe live key detected - use environment variables",
        ),
        // Generic high-entropy strings (potential secrets)
        (
            "High-entropy string",
            Regex::new(r#""[A-Za-z0-9+/=]{32,}""#).unwrap(),
            "Possible secret (high-entropy string) - verify and use environment variables",
        ),
        // JWT tokens
        (
            "JWT Token",
            Regex::new(r#"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"#).unwrap(),
            "JWT token detected - these should not be hardcoded",
        ),
    ]
}

#[async_trait]
impl Rule for RustHardcodedSecretsRule {
    fn id(&self) -> &'static str {
        "rust.hardcoded_secrets"
    }

    fn name(&self) -> &'static str {
        "Hardcoded secrets in source code"
    }

    fn applicability(&self) -> Option<crate::types::finding::FindingApplicability> {
        Some(crate::rules::applicability_defaults::hardcoded_secrets())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        let secret_patterns = get_secret_patterns();

        for (file_id, sem) in semantics {
            let rust = match sem.as_ref() {
                SourceSemantics::Rust(r) => r,
                _ => continue,
            };

            // Check static/const declarations for suspicious names and values
            for static_decl in &rust.statics {
                let name_lower = static_decl.name.to_lowercase();

                // Check if variable name suggests a secret
                let is_secret_name = SECRET_NAME_PATTERNS
                    .iter()
                    .any(|pattern| name_lower.contains(pattern));

                if is_secret_name {
                    let line = static_decl.location.range.start_line + 1;

                    let title = format!(
                        "Possible hardcoded secret in constant '{}'",
                        static_decl.name
                    );

                    let description = format!(
                        "The constant `{}` at line {} has a name suggesting it contains \
                         a secret value.\n\n\
                         **Why this is a security risk:**\n\
                         - Secrets in source code are stored in version control\n\
                         - Anyone with repo access can see them\n\
                         - They're included in compiled binaries\n\
                         - Hard to rotate without code changes\n\n\
                         **Better alternatives:**\n\
                         1. **Environment variables**: `std::env::var(\"{}\")?`\n\
                         2. **Config files** (gitignored): Load from file at startup\n\
                         3. **Secrets manager**: AWS Secrets Manager, HashiCorp Vault\n\
                         4. **dotenvy crate**: For .env file support",
                        static_decl.name,
                        line,
                        static_decl.name.to_uppercase()
                    );

                    let fix_preview = format!(
                        "// Before:\n\
                         const {}: &str = \"...\";\n\n\
                         // After:\n\
                         fn get_{}() -> Result<String, std::env::VarError> {{\n\
                             std::env::var(\"{}\")\n\
                         }}",
                        static_decl.name,
                        name_lower,
                        static_decl.name.to_uppercase()
                    );

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line },
                            replacement: format!(
                                "// TODO: Load from environment variable: std::env::var(\"{}\")?",
                                static_decl.name.to_uppercase()
                            ),
                        }],
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::SecurityVulnerability,
                        severity: Severity::Critical,
                        confidence: 0.80,
                        dimension: Dimension::Security,
                        file_id: *file_id,
                        file_path: rust.path.clone(),
                        line: Some(line),
                        column: Some(static_decl.location.range.start_col + 1),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "rust".into(),
                            "security".into(),
                            "secrets".into(),
                            "hardcoded".into(),
                        ],
                    });
                }
            }

            // Check call sites for patterns
            for call in &rust.calls {
                let callee = &call.function_call.callee_expr;

                // Check for secret patterns in the call text
                for (secret_type, pattern, advice) in &secret_patterns {
                    if pattern.is_match(callee) {
                        let line = call.function_call.location.line;

                        let title = format!("{} detected in source", secret_type);

                        let description = format!(
                            "A {} was detected at line {}.\n\n\
                             {}",
                            secret_type, line, advice
                        );

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::SecurityVulnerability,
                            severity: Severity::Critical,
                            confidence: 0.85,
                            dimension: Dimension::Security,
                            file_id: *file_id,
                            file_path: rust.path.clone(),
                            line: Some(line),
                            column: Some(call.function_call.location.column),
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: None,
                            fix_preview: Some(format!(
                                "// Use environment variable instead:\n\
                                 std::env::var(\"SECRET_KEY\")?"
                            )),
                            tags: vec![
                                "rust".into(),
                                "security".into(),
                                "secrets".into(),
                                secret_type.to_lowercase().replace(' ', "-"),
                            ],
                        });

                        break; // Found one pattern, no need to check others
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::rust::parse_rust_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::rust::build_rust_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "lib.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_rust_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Rust(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = RustHardcodedSecretsRule::new();
        assert_eq!(rule.id(), "rust.hardcoded_secrets");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustHardcodedSecretsRule::new();
        assert!(rule.name().contains("secret"));
    }

    #[tokio::test]
    async fn detects_api_key_constant() {
        let rule = RustHardcodedSecretsRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
const API_KEY: &str = "sk-1234567890abcdef";
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "rust.hardcoded_secrets"),
            "Should detect API_KEY constant"
        );
    }

    #[tokio::test]
    async fn detects_password_constant() {
        let rule = RustHardcodedSecretsRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
static DATABASE_PASSWORD: &str = "super_secret_password";
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "rust.hardcoded_secrets"),
            "Should detect DATABASE_PASSWORD constant"
        );
    }

    #[tokio::test]
    async fn skips_safe_constants() {
        let rule = RustHardcodedSecretsRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
const MAX_SIZE: usize = 1024;
const APP_NAME: &str = "my_app";
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let secret_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.hardcoded_secrets")
            .collect();
        assert!(
            secret_findings.is_empty(),
            "Should not flag non-secret constants"
        );
    }

    #[tokio::test]
    async fn finding_has_correct_severity() {
        let rule = RustHardcodedSecretsRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
const SECRET_TOKEN: &str = "secret_value";
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        for finding in &findings {
            if finding.rule_id == "rust.hardcoded_secrets" {
                assert_eq!(finding.severity, Severity::Critical);
                assert_eq!(finding.dimension, Dimension::Security);
                assert!(finding.tags.contains(&"security".to_string()));
            }
        }
    }

    #[test]
    fn secret_name_patterns_are_lowercase() {
        for pattern in SECRET_NAME_PATTERNS {
            assert_eq!(
                *pattern,
                pattern.to_lowercase(),
                "Secret name patterns should be lowercase for case-insensitive matching"
            );
        }
    }

    #[test]
    fn secret_patterns_compile() {
        let patterns = get_secret_patterns();
        assert!(!patterns.is_empty());

        for (name, _regex, advice) in patterns {
            assert!(!name.is_empty());
            assert!(!advice.is_empty());
        }
    }
}
