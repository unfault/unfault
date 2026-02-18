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

/// Check if timedelta is already imported from datetime
fn has_timedelta_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| {
        imp.module == "datetime" && imp.names.iter().any(|n| n == "timedelta")
    })
}

/// Rule: Flask Missing Session Timeout
///
/// Detects Flask applications without proper session timeout configuration,
/// which can lead to sessions that never expire.
#[derive(Debug)]
pub struct FlaskSessionTimeoutRule;

impl FlaskSessionTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FlaskSessionTimeoutRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for FlaskSessionTimeoutRule {
    fn id(&self) -> &'static str {
        "python.flask.missing_session_timeout"
    }

    fn name(&self) -> &'static str {
        "Detects Flask applications without proper session timeout configuration."
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
            let has_flask = py.imports.iter().any(|imp| {
                imp.module == "flask" || imp.names.iter().any(|n| n == "Flask")
            });

            let is_config_file = py.path.contains("config")
                || py.path.contains("settings")
                || py.path.ends_with("config.py");

            if !has_flask && !is_config_file {
                continue;
            }

            // Track session-related settings
            let mut has_permanent_session_lifetime = false;
            let mut has_session_permanent = false;
            let mut session_lifetime_value: Option<i64> = None;

            for assign in &py.assignments {
                match assign.target.as_str() {
                    "PERMANENT_SESSION_LIFETIME" => {
                        has_permanent_session_lifetime = true;
                        // Try to parse the value (could be timedelta or seconds)
                        let value = assign.value_repr.trim();
                        if let Ok(seconds) = value.parse::<i64>() {
                            session_lifetime_value = Some(seconds);
                            // Check for very long session lifetimes (> 30 days)
                            if seconds > 30 * 24 * 60 * 60 {
                                findings.push(RuleFinding {
                                    rule_id: self.id().to_string(),
                                    title: "Flask PERMANENT_SESSION_LIFETIME is very long".to_string(),
                                    description: Some(format!(
                                        "PERMANENT_SESSION_LIFETIME is set to {} seconds ({} days). \
                                         Long session lifetimes increase the risk of session hijacking. \
                                         Consider shorter session lifetimes.",
                                        seconds, seconds / (24 * 60 * 60)
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
                                    fix_preview: Some(generate_session_lifetime_fix_preview()),
                                    tags: vec![
                                        "python".into(),
                                        "flask".into(),
                                        "session".into(),
                                    ],
                                });
                            }
                        }
                    }
                    "SESSION_PERMANENT" => {
                        has_session_permanent = true;
                    }
                    _ => {}
                }
            }

            // Check for Flask app creation without session configuration
            let has_flask_app = py.calls.iter().any(|c| c.function_call.callee_expr == "Flask");

            if has_flask_app && !has_permanent_session_lifetime {
                // Check if this file uses sessions
                let uses_sessions = py.imports.iter().any(|imp| {
                    imp.names.iter().any(|n| n == "session")
                }) || py.calls.iter().any(|c| {
                    c.function_call.callee_expr.contains("session")
                });

                if uses_sessions {
                    let title = "Flask session timeout not configured".to_string();

                    let description = 
                        "Flask application uses sessions but PERMANENT_SESSION_LIFETIME is not \
                         configured. By default, Flask sessions expire when the browser closes \
                         (if SESSION_PERMANENT is False) or after 31 days (if SESSION_PERMANENT \
                         is True). Configure an appropriate session lifetime.".to_string();

                    let fix_preview = generate_missing_timeout_fix_preview();

                    // Use stdlib_from_import since we're adding "from datetime import timedelta"
                    let import_line = py.import_insertion_line_for(ImportInsertionType::stdlib_from_import());
                    let patch = generate_session_timeout_patch(*file_id, 1, &py.imports, import_line);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.70,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(1),
                        column: Some(1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "python".into(),
                            "flask".into(),
                            "session".into(),
                            "timeout".into(),
                        ],
                    });
                }
            }

            // Suppress unused variable warnings
            let _ = has_session_permanent;
            let _ = session_lifetime_value;
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
    }
}

/// Generate patch for missing session timeout - adds actual import and configuration.
fn generate_session_timeout_patch(file_id: FileId, line: u32, imports: &[PyImport], import_insertion_line: u32) -> FilePatch {
    let mut hunks = Vec::new();
    
    // Add timedelta import at the top of the file only if not already imported
    if !has_timedelta_import(imports) {
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: import_insertion_line },
            replacement: "from datetime import timedelta\n".to_string(),
        });
    }
    
    // Add session configuration code before the problematic line
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line },
        replacement: r#"# Session timeout configuration (added by unfault)
PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
SESSION_PERMANENT = True
"#.to_string(),
    });

    FilePatch { file_id, hunks }
}

/// Generate fix preview for session lifetime.
fn generate_session_lifetime_fix_preview() -> String {
    r#"# Configure appropriate session lifetime

from datetime import timedelta

# Recommended: 1 hour for sensitive applications
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Or 1 day for less sensitive applications
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)

# Make sessions permanent (use PERMANENT_SESSION_LIFETIME)
app.config['SESSION_PERMANENT'] = True

# For per-request session refresh:
@app.before_request
def make_session_permanent():
    session.permanent = True"#.to_string()
}

/// Generate fix preview for missing session timeout.
fn generate_missing_timeout_fix_preview() -> String {
    r#"# Configure Flask session timeout

from datetime import timedelta
from flask import Flask, session

app = Flask(__name__)

# Set session lifetime (default is 31 days if SESSION_PERMANENT=True)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Make sessions permanent by default
app.config['SESSION_PERMANENT'] = True

# Or set per-request:
@app.before_request
def make_session_permanent():
    session.permanent = True
    session.modified = True  # Refresh session on each request

# For production, also configure:
app.config['SESSION_COOKIE_SECURE'] = True  # HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # No JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

# Consider using server-side sessions for better security:
# pip install Flask-Session
from flask_session import Session
app.config['SESSION_TYPE'] = 'redis'  # or 'filesystem', 'sqlalchemy'
Session(app)"#.to_string()
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
        let rule = FlaskSessionTimeoutRule::new();
        assert_eq!(rule.id(), "python.flask.missing_session_timeout");
    }

    #[test]
    fn rule_name_mentions_session_timeout() {
        let rule = FlaskSessionTimeoutRule::new();
        assert!(rule.name().contains("session timeout"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_flask_app() {
        let rule = FlaskSessionTimeoutRule::new();
        let src = r#"
def hello():
    return "Hello"
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "app.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_configured_timeout() {
        let rule = FlaskSessionTimeoutRule::new();
        let src = r#"
from flask import Flask
app = Flask(__name__)
PERMANENT_SESSION_LIFETIME = 3600
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "app.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag if PERMANENT_SESSION_LIFETIME is set
        assert!(findings.is_empty() || !findings.iter().any(|f| f.title.contains("not configured")));
    }

    #[tokio::test]
    async fn fix_preview_contains_timedelta() {
        let preview = generate_missing_timeout_fix_preview();
        assert!(preview.contains("timedelta"));
        assert!(preview.contains("PERMANENT_SESSION_LIFETIME"));
    }
}