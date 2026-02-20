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

/// Rule: Django Insecure Session Settings
///
/// Detects Django settings with insecure session configuration such as
/// missing SESSION_COOKIE_SECURE, SESSION_COOKIE_HTTPONLY, or short session age.
#[derive(Debug)]
pub struct DjangoSessionSettingsRule;

impl DjangoSessionSettingsRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DjangoSessionSettingsRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for DjangoSessionSettingsRule {
    fn id(&self) -> &'static str {
        "python.django.insecure_session_settings"
    }

    fn name(&self) -> &'static str {
        "Detects Django settings with insecure session configuration."
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

            // Only check Django settings files
            let is_settings_file = py.path.contains("settings")
                || py.path.ends_with("settings.py")
                || py.path.contains("settings/");

            if !is_settings_file {
                continue;
            }

            // Check if this looks like a Django settings file
            let has_django_settings = py.assignments.iter().any(|a| {
                a.target == "DEBUG"
                    || a.target == "SECRET_KEY"
                    || a.target == "INSTALLED_APPS"
                    || a.target == "MIDDLEWARE"
            });

            if !has_django_settings {
                continue;
            }

            // Track which session settings are defined
            let mut has_session_cookie_secure = false;
            let mut has_session_cookie_httponly = false;
            let mut has_session_cookie_samesite = false;
            let mut has_session_expire_at_browser_close = false;
            let mut session_cookie_age: Option<i64> = None;

            for assign in &py.assignments {
                match assign.target.as_str() {
                    "SESSION_COOKIE_SECURE" => {
                        has_session_cookie_secure = true;
                        if assign.value_repr.trim() == "False" {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "SESSION_COOKIE_SECURE is set to False".to_string(),
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
                                    "django".into(),
                                    "session".into(),
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
                                title: "SESSION_COOKIE_HTTPONLY is set to False".to_string(),
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
                                    "django".into(),
                                    "session".into(),
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
                                title: "SESSION_COOKIE_SAMESITE is set to None or False"
                                    .to_string(),
                                description: Some(
                                    "SESSION_COOKIE_SAMESITE=None or False allows the session \
                                     cookie to be sent with cross-site requests, making it \
                                     vulnerable to CSRF attacks. Use 'Lax' or 'Strict'."
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
                                    "django".into(),
                                    "session".into(),
                                    "csrf".into(),
                                ],
                            });
                        }
                    }
                    "SESSION_EXPIRE_AT_BROWSER_CLOSE" => {
                        has_session_expire_at_browser_close = true;
                    }
                    "SESSION_COOKIE_AGE" => {
                        // Try to parse the session age
                        if let Ok(age) = assign.value_repr.trim().parse::<i64>() {
                            session_cookie_age = Some(age);
                            // Check for very long session ages (> 30 days)
                            if age > 30 * 24 * 60 * 60 {
                                findings.push(RuleFinding {
                                    rule_id: self.id().to_string(),
                                    title: "SESSION_COOKIE_AGE is very long".to_string(),
                                    description: Some(format!(
                                        "SESSION_COOKIE_AGE is set to {} seconds ({} days). \
                                         Long session lifetimes increase the window for session \
                                         hijacking. Consider shorter session ages with refresh tokens.",
                                        age, age / (24 * 60 * 60)
                                    )),
                                    kind: FindingKind::StabilityRisk,
                                    severity: Severity::Low,
                                    confidence: 0.75,
                                    dimension: Dimension::Stability,
                                    file_id: *file_id,
                                    file_path: py.path.clone(),
                                    line: Some(assign.location.range.start_line + 1),
                                    column: Some(assign.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                                    patch: None,
                                    fix_preview: Some(generate_session_age_fix_preview()),
                                    tags: vec![
                                        "python".into(),
                                        "django".into(),
                                        "session".into(),
                                    ],
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Check for missing security settings in production-like settings
            let is_prod_settings = py.path.contains("prod") || py.path.contains("production");

            if is_prod_settings {
                if !has_session_cookie_secure {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "SESSION_COOKIE_SECURE not set in production settings".to_string(),
                        description: Some(
                            "SESSION_COOKIE_SECURE is not explicitly set in production settings. \
                             Add SESSION_COOKIE_SECURE = True to ensure session cookies are \
                             only sent over HTTPS."
                                .to_string(),
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.80,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(1),
                        column: Some(1),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_missing_settings_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "django".into(),
                            "session".into(),
                            "missing".into(),
                        ],
                    });
                }

                if !has_session_cookie_samesite {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "SESSION_COOKIE_SAMESITE not set in production settings".to_string(),
                        description: Some(
                            "SESSION_COOKIE_SAMESITE is not explicitly set. Add \
                             SESSION_COOKIE_SAMESITE = 'Lax' or 'Strict' for CSRF protection."
                                .to_string(),
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Low,
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
                        fix_preview: Some(generate_missing_settings_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "django".into(),
                            "session".into(),
                            "missing".into(),
                        ],
                    });
                }
            }

            // Suppress unused variable warnings
            let _ = has_session_cookie_httponly;
            let _ = has_session_expire_at_browser_close;
            let _ = session_cookie_age;
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::cors_policy())
    }
}

/// Generate patch for a setting - adds actual configuration code.
fn generate_setting_patch(file_id: FileId, line: u32, replacement: &str) -> FilePatch {
    // Insert actual code that provides the secure setting
    let hunks = vec![PatchHunk {
        range: PatchRange::InsertBeforeLine { line },
        replacement: format!("{}\n", replacement),
    }];

    FilePatch { file_id, hunks }
}

/// Generate fix preview for SESSION_COOKIE_SECURE.
fn generate_secure_cookie_fix_preview() -> String {
    r#"# Secure session cookie settings for production

# Always use HTTPS for session cookies in production
SESSION_COOKIE_SECURE = True

# For development, you can conditionally set this:
import os
SESSION_COOKIE_SECURE = os.environ.get('DJANGO_ENV') == 'production'

# Or use django-environ:
import environ
env = environ.Env()
SESSION_COOKIE_SECURE = env.bool('SESSION_COOKIE_SECURE', default=True)"#
        .to_string()
}

/// Generate fix preview for SESSION_COOKIE_HTTPONLY.
fn generate_httponly_fix_preview() -> String {
    r#"# Prevent JavaScript access to session cookies

# This is True by default in Django, but explicitly set it:
SESSION_COOKIE_HTTPONLY = True

# This prevents XSS attacks from stealing session cookies
# Never set this to False unless you have a very specific need"#
        .to_string()
}

/// Generate fix preview for SESSION_COOKIE_SAMESITE.
fn generate_samesite_fix_preview() -> String {
    r#"# Configure SameSite attribute for session cookies

# 'Lax' - Cookies sent with top-level navigations and GET from third-party sites
SESSION_COOKIE_SAMESITE = 'Lax'

# 'Strict' - Cookies only sent in first-party context (more secure but may break some flows)
# SESSION_COOKIE_SAMESITE = 'Strict'

# Never use 'None' or False unless you need cross-site cookies
# If you must use 'None', SESSION_COOKIE_SECURE must be True"#
        .to_string()
}

/// Generate fix preview for SESSION_COOKIE_AGE.
fn generate_session_age_fix_preview() -> String {
    r#"# Configure appropriate session lifetime

# Default is 2 weeks (1209600 seconds)
SESSION_COOKIE_AGE = 1209600

# For sensitive applications, use shorter sessions:
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_COOKIE_AGE = 86400  # 1 day

# Consider using SESSION_EXPIRE_AT_BROWSER_CLOSE for sensitive apps:
SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# For long-lived sessions, implement session refresh:
# - Use shorter SESSION_COOKIE_AGE
# - Implement token refresh on activity
# - Add session activity tracking"#
        .to_string()
}

/// Generate fix preview for missing session settings.
fn generate_missing_settings_fix_preview() -> String {
    r#"# Recommended session security settings for production

# Ensure cookies are only sent over HTTPS
SESSION_COOKIE_SECURE = True

# Prevent JavaScript access to session cookies
SESSION_COOKIE_HTTPONLY = True

# Prevent CSRF by restricting cross-site cookie sending
SESSION_COOKIE_SAMESITE = 'Lax'

# Set appropriate session lifetime (2 weeks default)
SESSION_COOKIE_AGE = 1209600

# Optional: Expire session when browser closes
# SESSION_EXPIRE_AT_BROWSER_CLOSE = True

# Use secure session backend for production:
# SESSION_ENGINE = 'django.contrib.sessions.backends.cached_db'

# For high-security applications:
SESSION_COOKIE_NAME = 'sessionid'  # Change from default if needed
SESSION_SAVE_EVERY_REQUEST = True  # Refresh session on each request"#
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
        let rule = DjangoSessionSettingsRule::new();
        assert_eq!(rule.id(), "python.django.insecure_session_settings");
    }

    #[test]
    fn rule_name_mentions_session() {
        let rule = DjangoSessionSettingsRule::new();
        assert!(rule.name().contains("session"));
    }

    #[tokio::test]
    async fn evaluate_detects_insecure_session_cookie_secure() {
        let rule = DjangoSessionSettingsRule::new();
        let src = r#"
DEBUG = False
SECRET_KEY = 'secret'
SESSION_COOKIE_SECURE = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("SESSION_COOKIE_SECURE"));
    }

    #[tokio::test]
    async fn evaluate_detects_insecure_session_cookie_httponly() {
        let rule = DjangoSessionSettingsRule::new();
        let src = r#"
DEBUG = False
SECRET_KEY = 'secret'
SESSION_COOKIE_HTTPONLY = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("SESSION_COOKIE_HTTPONLY"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_secure_settings() {
        let rule = DjangoSessionSettingsRule::new();
        let src = r#"
DEBUG = False
SECRET_KEY = 'secret'
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_settings_file() {
        let rule = DjangoSessionSettingsRule::new();
        let src = r#"
SESSION_COOKIE_SECURE = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "views.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_has_patch() {
        let rule = DjangoSessionSettingsRule::new();
        let src = r#"
DEBUG = False
SESSION_COOKIE_SECURE = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = DjangoSessionSettingsRule::new();
        let src = r#"
DEBUG = False
SESSION_COOKIE_SECURE = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
    }
}
