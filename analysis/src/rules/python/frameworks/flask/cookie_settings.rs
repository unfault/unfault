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

/// Rule: Flask Insecure Cookie Settings
///
/// Detects Flask applications with insecure cookie configuration such as
/// missing SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, or SESSION_COOKIE_SAMESITE.
#[derive(Debug)]
pub struct FlaskInsecureCookieSettingsRule;

impl FlaskInsecureCookieSettingsRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FlaskInsecureCookieSettingsRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for FlaskInsecureCookieSettingsRule {
    fn id(&self) -> &'static str {
        "python.flask.insecure_cookie_settings"
    }

    fn name(&self) -> &'static str {
        "Detects Flask applications with insecure cookie configuration."
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => continue,
            };

            // Check for Flask imports
            let has_flask = py
                .imports
                .iter()
                .any(|imp| imp.module == "flask" || imp.names.iter().any(|n| n == "Flask"));

            let is_config_file = py.path.contains("config")
                || py.path.contains("settings")
                || py.path.ends_with("config.py");

            if !has_flask && !is_config_file {
                continue;
            }

            // Track cookie-related settings
            let mut has_session_cookie_secure = false;
            let mut has_session_cookie_httponly = false;
            let mut has_session_cookie_samesite = false;

            for assign in &py.assignments {
                match assign.target.as_str() {
                    "SESSION_COOKIE_SECURE" => {
                        has_session_cookie_secure = true;
                        if assign.value_repr.trim() == "False" {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "Flask SESSION_COOKIE_SECURE is set to False".to_string(),
                                description: Some(
                                    "SESSION_COOKIE_SECURE=False allows session cookies to be \
                                     sent over unencrypted HTTP connections. In production, \
                                     set this to True to ensure cookies are only sent over HTTPS."
                                        .to_string(),
                                ),
                                kind: FindingKind::StabilityRisk,
                                severity: Severity::High,
                                confidence: 0.95,
                                dimension: Dimension::Stability,
                                file_id: *file_id,
                                file_path: py.path.clone(),
                                line: Some(assign.location.range.start_line + 1),
                                column: Some(assign.location.range.start_col + 1),
                                end_line: None,
                                end_column: None,
                                byte_range: None,
                                patch: Some(generate_setting_patch(
                                    *file_id,
                                    assign.location.range.start_line + 1,
                                    "SESSION_COOKIE_SECURE = True",
                                )),
                                fix_preview: Some(generate_secure_cookie_fix_preview()),
                                tags: vec![
                                    "python".into(),
                                    "flask".into(),
                                    "cookie".into(),
                                    "security".into(),
                                ],
                            });
                        }
                    }
                    "SESSION_COOKIE_HTTPONLY" => {
                        has_session_cookie_httponly = true;
                        if assign.value_repr.trim() == "False" {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "Flask SESSION_COOKIE_HTTPONLY is set to False".to_string(),
                                description: Some(
                                    "SESSION_COOKIE_HTTPONLY=False allows JavaScript to access \
                                     session cookies, making them vulnerable to XSS attacks. \
                                     Set this to True (the default) to prevent JavaScript access."
                                        .to_string(),
                                ),
                                kind: FindingKind::StabilityRisk,
                                severity: Severity::High,
                                confidence: 0.95,
                                dimension: Dimension::Stability,
                                file_id: *file_id,
                                file_path: py.path.clone(),
                                line: Some(assign.location.range.start_line + 1),
                                column: Some(assign.location.range.start_col + 1),
                                end_line: None,
                                end_column: None,
                                byte_range: None,
                                patch: Some(generate_setting_patch(
                                    *file_id,
                                    assign.location.range.start_line + 1,
                                    "SESSION_COOKIE_HTTPONLY = True",
                                )),
                                fix_preview: Some(generate_httponly_fix_preview()),
                                tags: vec![
                                    "python".into(),
                                    "flask".into(),
                                    "cookie".into(),
                                    "security".into(),
                                    "xss".into(),
                                ],
                            });
                        }
                    }
                    "SESSION_COOKIE_SAMESITE" => {
                        has_session_cookie_samesite = true;
                        let value = assign.value_repr.trim().to_lowercase();
                        if value == "none"
                            || value == "'none'"
                            || value == "\"none\""
                            || value == "false"
                        {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "Flask SESSION_COOKIE_SAMESITE is set to None".to_string(),
                                description: Some(
                                    "SESSION_COOKIE_SAMESITE=None allows the session cookie to be \
                                     sent with cross-site requests, making it vulnerable to CSRF \
                                     attacks. Use 'Lax' or 'Strict'."
                                        .to_string(),
                                ),
                                kind: FindingKind::StabilityRisk,
                                severity: Severity::Medium,
                                confidence: 0.90,
                                dimension: Dimension::Stability,
                                file_id: *file_id,
                                file_path: py.path.clone(),
                                line: Some(assign.location.range.start_line + 1),
                                column: Some(assign.location.range.start_col + 1),
                                end_line: None,
                                end_column: None,
                                byte_range: None,
                                patch: Some(generate_setting_patch(
                                    *file_id,
                                    assign.location.range.start_line + 1,
                                    "SESSION_COOKIE_SAMESITE = 'Lax'",
                                )),
                                fix_preview: Some(generate_samesite_fix_preview()),
                                tags: vec![
                                    "python".into(),
                                    "flask".into(),
                                    "cookie".into(),
                                    "csrf".into(),
                                ],
                            });
                        }
                    }
                    _ => {}
                }
            }

            // Check for Flask app creation without secure cookie settings
            let has_flask_app = py
                .calls
                .iter()
                .any(|c| c.function_call.callee_expr == "Flask");

            if has_flask_app {
                // Check if this looks like a production config
                let is_prod_config = py.path.contains("prod")
                    || py.path.contains("production")
                    || py
                        .assignments
                        .iter()
                        .any(|a| a.target == "DEBUG" && a.value_repr.trim() == "False");

                if is_prod_config {
                    let mut missing_settings = Vec::new();

                    if !has_session_cookie_secure {
                        missing_settings.push("SESSION_COOKIE_SECURE");
                    }
                    if !has_session_cookie_httponly {
                        // Note: Flask defaults to True, but explicit is better
                        missing_settings.push("SESSION_COOKIE_HTTPONLY");
                    }
                    if !has_session_cookie_samesite {
                        missing_settings.push("SESSION_COOKIE_SAMESITE");
                    }

                    if !missing_settings.is_empty() {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: format!(
                                "Flask missing cookie security settings: {}",
                                missing_settings.join(", ")
                            ),
                            description: Some(
                                "Production Flask configuration is missing important cookie \
                                 security settings. Add these settings to protect session cookies."
                                    .to_string(),
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Medium,
                            confidence: 0.75,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(1),
                            column: Some(1),
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: None,
                            fix_preview: Some(generate_all_cookie_settings_fix_preview()),
                            tags: vec![
                                "python".into(),
                                "flask".into(),
                                "cookie".into(),
                                "missing".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::cors_policy())
    }
}

/// Generate patch for a setting - adds actual configuration code.
fn generate_setting_patch(file_id: FileId, line: u32, replacement: &str) -> FilePatch {
    // Insert actual code that replaces the insecure setting
    let hunks = vec![PatchHunk {
        range: PatchRange::InsertBeforeLine { line },
        replacement: format!("{}\n", replacement),
    }];

    FilePatch { file_id, hunks }
}

/// Generate fix preview for SESSION_COOKIE_SECURE.
fn generate_secure_cookie_fix_preview() -> String {
    r#"# Secure session cookie settings for Flask production

# Always use HTTPS for session cookies in production
app.config['SESSION_COOKIE_SECURE'] = True

# For development, conditionally set this:
import os
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'

# Or use a config class:
class ProductionConfig:
    SESSION_COOKIE_SECURE = True

class DevelopmentConfig:
    SESSION_COOKIE_SECURE = False"#
        .to_string()
}

/// Generate fix preview for SESSION_COOKIE_HTTPONLY.
fn generate_httponly_fix_preview() -> String {
    r#"# Prevent JavaScript access to session cookies

# This is True by default in Flask, but explicitly set it:
app.config['SESSION_COOKIE_HTTPONLY'] = True

# This prevents XSS attacks from stealing session cookies
# Never set this to False unless you have a very specific need"#
        .to_string()
}

/// Generate fix preview for SESSION_COOKIE_SAMESITE.
fn generate_samesite_fix_preview() -> String {
    r#"# Configure SameSite attribute for session cookies

# 'Lax' - Cookies sent with top-level navigations and GET from third-party sites
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# 'Strict' - Cookies only sent in first-party context (more secure but may break some flows)
# app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# Never use None unless you need cross-site cookies
# If you must use None, SESSION_COOKIE_SECURE must be True"#
        .to_string()
}

/// Generate fix preview for all cookie settings.
fn generate_all_cookie_settings_fix_preview() -> String {
    r#"# Recommended cookie security settings for Flask production

from flask import Flask

app = Flask(__name__)

# Ensure cookies are only sent over HTTPS
app.config['SESSION_COOKIE_SECURE'] = True

# Prevent JavaScript access to session cookies (default is True)
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Prevent CSRF by restricting cross-site cookie sending
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Optional: Set cookie name (change from default 'session')
app.config['SESSION_COOKIE_NAME'] = 'myapp_session'

# Optional: Set cookie path
app.config['SESSION_COOKIE_PATH'] = '/'

# For development vs production, use config classes:
class Config:
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'

class ProductionConfig(Config):
    SESSION_COOKIE_SECURE = True

class DevelopmentConfig(Config):
    SESSION_COOKIE_SECURE = False

# Or use environment variables:
import os
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') == 'production'"#
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str, path: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: path.to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed)
            .expect("framework analysis should succeed");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = FlaskInsecureCookieSettingsRule::new();
        assert_eq!(rule.id(), "python.flask.insecure_cookie_settings");
    }

    #[test]
    fn rule_name_mentions_cookie() {
        let rule = FlaskInsecureCookieSettingsRule::new();
        assert!(rule.name().contains("cookie"));
    }

    #[tokio::test]
    async fn evaluate_detects_insecure_session_cookie_secure() {
        let rule = FlaskInsecureCookieSettingsRule::new();
        let src = r#"
from flask import Flask
app = Flask(__name__)
SESSION_COOKIE_SECURE = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "app.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("SESSION_COOKIE_SECURE"));
    }

    #[tokio::test]
    async fn evaluate_detects_insecure_session_cookie_httponly() {
        let rule = FlaskInsecureCookieSettingsRule::new();
        let src = r#"
from flask import Flask
app = Flask(__name__)
SESSION_COOKIE_HTTPONLY = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "app.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("SESSION_COOKIE_HTTPONLY"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_secure_settings() {
        let rule = FlaskInsecureCookieSettingsRule::new();
        let src = r#"
from flask import Flask
app = Flask(__name__)
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "app.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_flask_app() {
        let rule = FlaskInsecureCookieSettingsRule::new();
        let src = r#"
SESSION_COOKIE_SECURE = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "random.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_has_patch() {
        let rule = FlaskInsecureCookieSettingsRule::new();
        let src = r#"
from flask import Flask
SESSION_COOKIE_SECURE = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "app.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = FlaskInsecureCookieSettingsRule::new();
        let src = r#"
from flask import Flask
SESSION_COOKIE_SECURE = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "app.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
    }
}
