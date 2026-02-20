use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::{ImportInsertionType, PyImport};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Check if os module is already imported
fn has_os_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| imp.module == "os")
}

/// Rule: Django Missing or Insecure ALLOWED_HOSTS
///
/// Detects Django settings where ALLOWED_HOSTS is missing, empty, or contains
/// wildcards that could allow host header attacks.
#[derive(Debug)]
pub struct DjangoAllowedHostsRule;

impl DjangoAllowedHostsRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DjangoAllowedHostsRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for DjangoAllowedHostsRule {
    fn id(&self) -> &'static str {
        "python.django.insecure_allowed_hosts"
    }

    fn name(&self) -> &'static str {
        "Detects Django settings with missing, empty, or wildcard ALLOWED_HOSTS."
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

            // Check for ALLOWED_HOSTS assignment
            let mut found_allowed_hosts = false;

            for assign in &py.assignments {
                if assign.target == "ALLOWED_HOSTS" {
                    found_allowed_hosts = true;
                    let value = assign.value_repr.trim();

                    // Check for wildcard '*'
                    if value.contains("'*'") || value.contains("\"*\"") {
                        let title = "Django ALLOWED_HOSTS contains wildcard '*'".to_string();

                        let description =
                            "ALLOWED_HOSTS contains '*' which allows any host header. \
                             This makes your application vulnerable to host header attacks \
                             and cache poisoning. In production, specify exact hostnames."
                                .to_string();

                        let fix_preview = generate_wildcard_fix_preview();

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
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
                            patch: None,
                            fix_preview: Some(fix_preview),
                            tags: vec![
                                "python".into(),
                                "django".into(),
                                "allowed-hosts".into(),
                                "security".into(),
                            ],
                        });
                    }

                    // Check for empty list
                    if value == "[]" || value.trim() == "[]" {
                        let title = "Django ALLOWED_HOSTS is empty".to_string();

                        let description =
                            "ALLOWED_HOSTS is an empty list. In production with DEBUG=False, \
                             Django will reject all requests. Configure allowed hostnames."
                                .to_string();

                        let fix_preview = generate_empty_fix_preview();

                        // Use stdlib_import since we're adding "import os"
                        let patch = generate_allowed_hosts_patch(
                            *file_id,
                            assign.location.range.start_line + 1,
                            &py.imports,
                            py.import_insertion_line_for(ImportInsertionType::stdlib_import()),
                        );

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
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
                            patch: Some(patch),
                            fix_preview: Some(fix_preview),
                            tags: vec![
                                "python".into(),
                                "django".into(),
                                "allowed-hosts".into(),
                                "configuration".into(),
                            ],
                        });
                    }

                    // Check for .localhost or development hosts in production-like settings
                    let has_dev_hosts = value.contains("localhost")
                        || value.contains("127.0.0.1")
                        || value.contains(".local");

                    let is_prod_settings =
                        py.path.contains("prod") || py.path.contains("production");

                    if has_dev_hosts && is_prod_settings {
                        let title =
                            "Django production settings contain development hosts".to_string();

                        let description =
                            "ALLOWED_HOSTS in production settings contains localhost or \
                             development hostnames. Remove these for production deployments."
                                .to_string();

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
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
                            fix_preview: None,
                            tags: vec!["python".into(), "django".into(), "allowed-hosts".into()],
                        });
                    }
                }
            }

            // Check if ALLOWED_HOSTS is missing entirely in settings file
            if !found_allowed_hosts {
                // Check if this looks like a Django settings file
                let has_django_settings = py.assignments.iter().any(|a| {
                    a.target == "DEBUG"
                        || a.target == "SECRET_KEY"
                        || a.target == "INSTALLED_APPS"
                        || a.target == "MIDDLEWARE"
                });

                if has_django_settings {
                    let title = "Django ALLOWED_HOSTS is not defined".to_string();

                    let description = "ALLOWED_HOSTS is not defined in this Django settings file. \
                         When DEBUG=False, Django requires ALLOWED_HOSTS to be set. \
                         Add ALLOWED_HOSTS with your production hostnames."
                        .to_string();

                    let fix_preview = generate_missing_fix_preview();

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
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
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "python".into(),
                            "django".into(),
                            "allowed-hosts".into(),
                            "missing".into(),
                        ],
                    });
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::runtime_config())
    }
}

/// Generate patch for empty ALLOWED_HOSTS - adds actual import and configuration.
fn generate_allowed_hosts_patch(
    file_id: FileId,
    line: u32,
    imports: &[PyImport],
    import_insertion_line: u32,
) -> FilePatch {
    let mut hunks = Vec::new();

    // Add os import at the top only if not already imported
    if !has_os_import(imports) {
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine {
                line: import_insertion_line,
            },
            replacement: "import os\n".to_string(),
        });
    }

    // Add environment-based ALLOWED_HOSTS configuration
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line },
        replacement:
            "ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost').split(',')\n"
                .to_string(),
    });

    FilePatch { file_id, hunks }
}

/// Generate fix preview for wildcard ALLOWED_HOSTS.
fn generate_wildcard_fix_preview() -> String {
    r#"# Never use '*' in ALLOWED_HOSTS for production!

# Bad - allows any host header
ALLOWED_HOSTS = ['*']

# Good - specify exact hostnames
ALLOWED_HOSTS = [
    'example.com',
    'www.example.com',
    'api.example.com',
]

# For development, use environment-based configuration:
import os

if os.environ.get('DJANGO_ENV') == 'production':
    ALLOWED_HOSTS = ['example.com', 'www.example.com']
else:
    ALLOWED_HOSTS = ['localhost', '127.0.0.1', '[::1]']

# Or use django-environ:
import environ
env = environ.Env()
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['localhost'])

# For containerized deployments, you might need:
ALLOWED_HOSTS = [
    os.environ.get('DJANGO_ALLOWED_HOST', 'localhost'),
    # Add health check endpoints
    'localhost',
]"#
    .to_string()
}

/// Generate fix preview for empty ALLOWED_HOSTS.
fn generate_empty_fix_preview() -> String {
    r#"# ALLOWED_HOSTS must not be empty in production

# Configure with your actual hostnames:
ALLOWED_HOSTS = [
    'example.com',
    'www.example.com',
]

# Or load from environment:
import os
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', '').split(',')

# Filter empty strings:
ALLOWED_HOSTS = [h.strip() for h in ALLOWED_HOSTS if h.strip()]"#
        .to_string()
}

/// Generate fix preview for missing ALLOWED_HOSTS.
fn generate_missing_fix_preview() -> String {
    r#"# Add ALLOWED_HOSTS to your Django settings

# For production:
ALLOWED_HOSTS = ['example.com', 'www.example.com']

# For development:
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '[::1]']

# Environment-based (recommended):
import os
ALLOWED_HOSTS = os.environ.get('DJANGO_ALLOWED_HOSTS', 'localhost').split(',')

# With django-environ:
import environ
env = environ.Env()
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['localhost'])"#
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
        let rule = DjangoAllowedHostsRule::new();
        assert_eq!(rule.id(), "python.django.insecure_allowed_hosts");
    }

    #[test]
    fn rule_name_mentions_allowed_hosts() {
        let rule = DjangoAllowedHostsRule::new();
        assert!(rule.name().contains("ALLOWED_HOSTS"));
    }

    #[tokio::test]
    async fn evaluate_detects_wildcard_allowed_hosts() {
        let rule = DjangoAllowedHostsRule::new();
        let src = r#"
DEBUG = False
SECRET_KEY = 'secret'
ALLOWED_HOSTS = ['*']
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("wildcard"));
    }

    #[tokio::test]
    async fn evaluate_detects_empty_allowed_hosts() {
        let rule = DjangoAllowedHostsRule::new();
        let src = r#"
DEBUG = False
SECRET_KEY = 'secret'
ALLOWED_HOSTS = []
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("empty"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_proper_allowed_hosts() {
        let rule = DjangoAllowedHostsRule::new();
        let src = r#"
DEBUG = False
SECRET_KEY = 'secret'
ALLOWED_HOSTS = ['example.com', 'www.example.com']
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_settings_file() {
        let rule = DjangoAllowedHostsRule::new();
        let src = r#"
ALLOWED_HOSTS = ['*']
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "views.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_has_high_severity_for_wildcard() {
        let rule = DjangoAllowedHostsRule::new();
        let src = r#"
DEBUG = False
ALLOWED_HOSTS = ['*']
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].severity, Severity::High));
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = DjangoAllowedHostsRule::new();
        let src = r#"
DEBUG = False
ALLOWED_HOSTS = ['*']
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "settings.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
    }
}
