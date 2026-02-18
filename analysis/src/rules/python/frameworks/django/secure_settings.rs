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

/// Rule: Django Missing SECURE_* Settings
///
/// Detects Django settings missing important security settings like
/// SECURE_SSL_REDIRECT, SECURE_HSTS_SECONDS, SECURE_BROWSER_XSS_FILTER, etc.
#[derive(Debug)]
pub struct DjangoSecureSettingsRule;

impl DjangoSecureSettingsRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DjangoSecureSettingsRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for DjangoSecureSettingsRule {
    fn id(&self) -> &'static str {
        "python.django.missing_secure_settings"
    }

    fn name(&self) -> &'static str {
        "Detects Django settings missing important SECURE_* security configurations."
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

            // Track which security settings are defined
            let mut has_secure_ssl_redirect = false;
            let mut has_secure_hsts_seconds = false;
            let mut has_secure_hsts_include_subdomains = false;
            let mut has_secure_hsts_preload = false;
            let mut has_secure_content_type_nosniff = false;
            let mut has_x_frame_options = false;
            let mut has_csrf_cookie_secure = false;

            for assign in &py.assignments {
                match assign.target.as_str() {
                    "SECURE_SSL_REDIRECT" => {
                        has_secure_ssl_redirect = true;
                        if assign.value_repr.trim() == "False" {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "SECURE_SSL_REDIRECT is set to False".to_string(),
                                description: Some(
                                    "SECURE_SSL_REDIRECT=False means HTTP requests won't be \
                                     redirected to HTTPS. In production, set this to True to \
                                     ensure all traffic uses HTTPS.".to_string()
                                ),
                                kind: FindingKind::StabilityRisk,
                                severity: Severity::High,
                                confidence: 0.90,
                                dimension: Dimension::Stability,
                                file_id: *file_id,
                                file_path: py.path.clone(),
                                line: Some(assign.location.range.start_line + 1),
                                column: Some(assign.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                                patch: Some(generate_setting_patch(*file_id, assign.location.range.start_line + 1, "SECURE_SSL_REDIRECT = True")),
                                fix_preview: Some(generate_ssl_redirect_fix_preview()),
                                tags: vec![
                                    "python".into(),
                                    "django".into(),
                                    "security".into(),
                                    "https".into(),
                                ],
                            });
                        }
                    }
                    "SECURE_HSTS_SECONDS" => {
                        has_secure_hsts_seconds = true;
                        // Check if HSTS is set to 0 or very low value
                        if let Ok(seconds) = assign.value_repr.trim().parse::<i64>() {
                            if seconds == 0 {
                                findings.push(RuleFinding {
                                    rule_id: self.id().to_string(),
                                    title: "SECURE_HSTS_SECONDS is set to 0".to_string(),
                                    description: Some(
                                        "SECURE_HSTS_SECONDS=0 disables HTTP Strict Transport Security. \
                                         Set this to at least 31536000 (1 year) for production.".to_string()
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
                                    patch: Some(generate_setting_patch(*file_id, assign.location.range.start_line + 1, "SECURE_HSTS_SECONDS = 31536000")),
                                    fix_preview: Some(generate_hsts_fix_preview()),
                                    tags: vec![
                                        "python".into(),
                                        "django".into(),
                                        "security".into(),
                                        "hsts".into(),
                                    ],
                                });
                            } else if seconds < 86400 {
                                findings.push(RuleFinding {
                                    rule_id: self.id().to_string(),
                                    title: "SECURE_HSTS_SECONDS is very low".to_string(),
                                    description: Some(format!(
                                        "SECURE_HSTS_SECONDS is set to {} seconds (less than 1 day). \
                                         For production, use at least 31536000 (1 year).",
                                        seconds
                                    )),
                                    kind: FindingKind::StabilityRisk,
                                    severity: Severity::Low,
                                    confidence: 0.80,
                                    dimension: Dimension::Stability,
                                    file_id: *file_id,
                                    file_path: py.path.clone(),
                                    line: Some(assign.location.range.start_line + 1),
                                    column: Some(assign.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                                    patch: None,
                                    fix_preview: Some(generate_hsts_fix_preview()),
                                    tags: vec![
                                        "python".into(),
                                        "django".into(),
                                        "security".into(),
                                        "hsts".into(),
                                    ],
                                });
                            }
                        }
                    }
                    "SECURE_HSTS_INCLUDE_SUBDOMAINS" => {
                        has_secure_hsts_include_subdomains = true;
                    }
                    "SECURE_HSTS_PRELOAD" => {
                        has_secure_hsts_preload = true;
                    }
                    "SECURE_CONTENT_TYPE_NOSNIFF" => {
                        has_secure_content_type_nosniff = true;
                        if assign.value_repr.trim() == "False" {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "SECURE_CONTENT_TYPE_NOSNIFF is set to False".to_string(),
                                description: Some(
                                    "SECURE_CONTENT_TYPE_NOSNIFF=False allows browsers to MIME-sniff \
                                     content types, which can lead to security vulnerabilities. \
                                     Set this to True.".to_string()
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
                                patch: Some(generate_setting_patch(*file_id, assign.location.range.start_line + 1, "SECURE_CONTENT_TYPE_NOSNIFF = True")),
                                fix_preview: None,
                                tags: vec![
                                    "python".into(),
                                    "django".into(),
                                    "security".into(),
                                ],
                            });
                        }
                    }
                    "X_FRAME_OPTIONS" => {
                        has_x_frame_options = true;
                        let value = assign.value_repr.trim().to_uppercase();
                        if value.contains("ALLOWALL") || value == "\"\"" || value == "''" {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "X_FRAME_OPTIONS allows framing".to_string(),
                                description: Some(
                                    "X_FRAME_OPTIONS is set to allow framing, which makes your \
                                     site vulnerable to clickjacking attacks. Use 'DENY' or 'SAMEORIGIN'.".to_string()
                                ),
                                kind: FindingKind::StabilityRisk,
                                severity: Severity::Medium,
                                confidence: 0.85,
                                dimension: Dimension::Stability,
                                file_id: *file_id,
                                file_path: py.path.clone(),
                                line: Some(assign.location.range.start_line + 1),
                                column: Some(assign.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                                patch: Some(generate_setting_patch(*file_id, assign.location.range.start_line + 1, "X_FRAME_OPTIONS = 'DENY'")),
                                fix_preview: Some(generate_x_frame_fix_preview()),
                                tags: vec![
                                    "python".into(),
                                    "django".into(),
                                    "security".into(),
                                    "clickjacking".into(),
                                ],
                            });
                        }
                    }
                    "CSRF_COOKIE_SECURE" => {
                        has_csrf_cookie_secure = true;
                        if assign.value_repr.trim() == "False" {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "CSRF_COOKIE_SECURE is set to False".to_string(),
                                description: Some(
                                    "CSRF_COOKIE_SECURE=False allows CSRF cookies to be sent over \
                                     HTTP. In production, set this to True.".to_string()
                                ),
                                kind: FindingKind::StabilityRisk,
                                severity: Severity::High,
                                confidence: 0.90,
                                dimension: Dimension::Stability,
                                file_id: *file_id,
                                file_path: py.path.clone(),
                                line: Some(assign.location.range.start_line + 1),
                                column: Some(assign.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                                patch: Some(generate_setting_patch(*file_id, assign.location.range.start_line + 1, "CSRF_COOKIE_SECURE = True")),
                                fix_preview: None,
                                tags: vec![
                                    "python".into(),
                                    "django".into(),
                                    "security".into(),
                                    "csrf".into(),
                                ],
                            });
                        }
                    }
                    _ => {}
                }
            }

            // Check for missing security settings in production-like settings
            let is_prod_settings = py.path.contains("prod") || py.path.contains("production");
            
            if is_prod_settings {
                let mut missing_settings = Vec::new();

                if !has_secure_ssl_redirect {
                    missing_settings.push("SECURE_SSL_REDIRECT");
                }
                if !has_secure_hsts_seconds {
                    missing_settings.push("SECURE_HSTS_SECONDS");
                }
                if !has_secure_content_type_nosniff {
                    missing_settings.push("SECURE_CONTENT_TYPE_NOSNIFF");
                }
                if !has_csrf_cookie_secure {
                    missing_settings.push("CSRF_COOKIE_SECURE");
                }

                if !missing_settings.is_empty() {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: format!("Missing security settings: {}", missing_settings.join(", ")),
                        description: Some(
                            "Production settings are missing important security configurations. \
                             Add these settings to harden your Django application.".to_string()
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
                        fix_preview: Some(generate_all_secure_settings_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "django".into(),
                            "security".into(),
                            "missing".into(),
                        ],
                    });
                }
            }

            // Suppress unused variable warnings
            let _ = has_secure_hsts_include_subdomains;
            let _ = has_secure_hsts_preload;
            let _ = has_x_frame_options;
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::runtime_config())
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

/// Generate fix preview for SECURE_SSL_REDIRECT.
fn generate_ssl_redirect_fix_preview() -> String {
    r#"# Redirect all HTTP requests to HTTPS

SECURE_SSL_REDIRECT = True

# If behind a proxy that terminates SSL, you may need:
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# For development, conditionally disable:
import os
SECURE_SSL_REDIRECT = os.environ.get('DJANGO_ENV') == 'production'"#.to_string()
}

/// Generate fix preview for HSTS settings.
fn generate_hsts_fix_preview() -> String {
    r#"# HTTP Strict Transport Security (HSTS) settings

# Enable HSTS for 1 year (recommended minimum)
SECURE_HSTS_SECONDS = 31536000  # 1 year

# Include subdomains in HSTS policy
SECURE_HSTS_INCLUDE_SUBDOMAINS = True

# Allow preloading in browser HSTS lists (requires submission to hstspreload.org)
SECURE_HSTS_PRELOAD = True

# WARNING: Start with a lower value when first enabling HSTS
# SECURE_HSTS_SECONDS = 3600  # 1 hour for testing
# Then gradually increase to 31536000 (1 year)"#.to_string()
}

/// Generate fix preview for X_FRAME_OPTIONS.
fn generate_x_frame_fix_preview() -> String {
    r#"# Prevent clickjacking attacks

# DENY - Never allow framing
X_FRAME_OPTIONS = 'DENY'

# Or SAMEORIGIN - Allow framing only from same origin
# X_FRAME_OPTIONS = 'SAMEORIGIN'

# For more control, use Content-Security-Policy frame-ancestors:
# SECURE_CONTENT_SECURITY_POLICY = "frame-ancestors 'self'"#.to_string()
}

/// Generate fix preview for all secure settings.
fn generate_all_secure_settings_fix_preview() -> String {
    r#"# Recommended security settings for Django production

# HTTPS/SSL Settings
SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# HTTP Strict Transport Security
SECURE_HSTS_SECONDS = 31536000  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Content Security
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Cookie Security
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'

# Additional security headers (Django 3.0+)
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# For development, use environment-based configuration:
import os
if os.environ.get('DJANGO_ENV') != 'production':
    SECURE_SSL_REDIRECT = False
    SECURE_HSTS_SECONDS = 0
    SESSION_COOKIE_SECURE = False
    CSRF_COOKIE_SECURE = False"#.to_string()
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
        let rule = DjangoSecureSettingsRule::new();
        assert_eq!(rule.id(), "python.django.missing_secure_settings");
    }

    #[test]
    fn rule_name_mentions_secure() {
        let rule = DjangoSecureSettingsRule::new();
        assert!(rule.name().contains("SECURE_"));
    }

    #[tokio::test]
    async fn evaluate_detects_ssl_redirect_false() {
        let rule = DjangoSecureSettingsRule::new();
        let src = r#"
DEBUG = False
SECRET_KEY = 'secret'
SECURE_SSL_REDIRECT = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("SECURE_SSL_REDIRECT"));
    }

    #[tokio::test]
    async fn evaluate_detects_hsts_zero() {
        let rule = DjangoSecureSettingsRule::new();
        let src = r#"
DEBUG = False
SECRET_KEY = 'secret'
SECURE_HSTS_SECONDS = 0
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("SECURE_HSTS_SECONDS"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_secure_settings() {
        let rule = DjangoSecureSettingsRule::new();
        let src = r#"
DEBUG = False
SECRET_KEY = 'secret'
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_CONTENT_TYPE_NOSNIFF = True
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_settings_file() {
        let rule = DjangoSecureSettingsRule::new();
        let src = r#"
SECURE_SSL_REDIRECT = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "views.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_has_patch() {
        let rule = DjangoSecureSettingsRule::new();
        let src = r#"
DEBUG = False
SECURE_SSL_REDIRECT = False
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_detects_missing_settings_in_production() {
        let rule = DjangoSecureSettingsRule::new();
        let src = r#"
DEBUG = False
SECRET_KEY = 'secret'
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings/production.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.title.contains("Missing")));
    }
}