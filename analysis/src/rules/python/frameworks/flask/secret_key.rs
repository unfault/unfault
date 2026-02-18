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

/// Rule: Flask Hardcoded Secret Key
///
/// Detects Flask applications with hardcoded SECRET_KEY values, which
/// compromises session security and should be loaded from environment.
#[derive(Debug)]
pub struct FlaskHardcodedSecretKeyRule;

impl FlaskHardcodedSecretKeyRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FlaskHardcodedSecretKeyRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for FlaskHardcodedSecretKeyRule {
    fn id(&self) -> &'static str {
        "python.flask.hardcoded_secret_key"
    }

    fn name(&self) -> &'static str {
        "Detects Flask applications with hardcoded SECRET_KEY which compromises session security."
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

            // Check for Flask imports or config files
            let has_flask = py.imports.iter().any(|imp| {
                imp.module == "flask" || imp.names.iter().any(|n| n == "Flask")
            });

            let is_config_file = py.path.contains("config")
                || py.path.contains("settings")
                || py.path.ends_with("config.py");

            if !has_flask && !is_config_file {
                continue;
            }

            // Check for SECRET_KEY assignments with hardcoded values
            for assign in &py.assignments {
                if assign.target == "SECRET_KEY" || assign.target.ends_with("SECRET_KEY") {
                    let value = assign.value_repr.trim();
                    
                    // Check if it's a hardcoded string (not from environment)
                    let is_hardcoded = (value.starts_with('"') || value.starts_with('\''))
                        && !value.contains("os.environ")
                        && !value.contains("os.getenv")
                        && !value.contains("config(")
                        && !value.contains("env(");

                    // Also check for common weak/default keys
                    let is_weak_key = value.contains("dev")
                        || value.contains("secret")
                        || value.contains("change")
                        || value.contains("your-secret")
                        || value.contains("xxx")
                        || value.len() < 20; // Very short keys

                    if is_hardcoded {
                        let severity = if is_weak_key {
                            Severity::Critical
                        } else {
                            Severity::High
                        };

                        let title = if is_weak_key {
                            "Flask SECRET_KEY is hardcoded with a weak/default value".to_string()
                        } else {
                            "Flask SECRET_KEY is hardcoded".to_string()
                        };

                        let description = 
                            "SECRET_KEY is hardcoded in the source code. This key is used to \
                             sign session cookies and other security-sensitive data. If exposed \
                             (e.g., in version control), attackers can forge sessions and \
                             potentially gain unauthorized access. Load SECRET_KEY from \
                             environment variables or a secure secrets manager.".to_string();

                        let fix_preview = generate_fix_preview();

                        // Use stdlib_import since we're adding "import os"
                        let patch = generate_secret_key_patch(
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
                            severity,
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
                                "flask".into(),
                                "secret-key".into(),
                                "security".into(),
                                "hardcoded".into(),
                            ],
                        });
                    }
                }
            }

            // Also check for app.secret_key = "..." pattern via calls
            for call in &py.calls {
                if call.function_call.callee_expr.contains("secret_key") && call.args_repr.contains('"') {
                    // This might be setting secret_key with a hardcoded value
                    let title = "Flask secret_key may be hardcoded".to_string();

                    let description = 
                        "A hardcoded string appears to be assigned to secret_key. \
                         Load secret keys from environment variables instead.".to_string();

                    let fix_preview = generate_fix_preview();

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
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "python".into(),
                            "flask".into(),
                            "secret-key".into(),
                        ],
                    });
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::sql_injection())
    }
}

/// Generate patch for hardcoded SECRET_KEY - adds actual import and replacement code.
fn generate_secret_key_patch(file_id: FileId, line: u32, imports: &[PyImport], import_insertion_line: u32) -> FilePatch {
    let mut hunks = Vec::new();
    
    // Add os import at the top of the file only if not already imported
    if !has_os_import(imports) {
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: import_insertion_line },
            replacement: "import os\n".to_string(),
        });
    }
    
    // Add the secure replacement before the problematic line
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line },
        replacement: "SECRET_KEY = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32)\n".to_string(),
    });

    FilePatch { file_id, hunks }
}

/// Generate a fix preview for hardcoded SECRET_KEY.
fn generate_fix_preview() -> String {
    r#"# Never hardcode SECRET_KEY in source code!

import os
from flask import Flask

app = Flask(__name__)

# Option 1: Load from environment variable (recommended)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise ValueError("No SECRET_KEY set for Flask application")

# Option 2: Generate random key (good for development, but sessions won't persist across restarts)
app.config['SECRET_KEY'] = os.urandom(32)

# Option 3: Use python-decouple
from decouple import config
app.config['SECRET_KEY'] = config('FLASK_SECRET_KEY')

# Option 4: Use a secrets file (not in version control)
import json
with open('secrets.json') as f:
    secrets = json.load(f)
app.config['SECRET_KEY'] = secrets['flask_secret_key']

# Generate a secure secret key for production:
# python -c "import secrets; print(secrets.token_hex(32))"
# Then set it as an environment variable:
# export FLASK_SECRET_KEY='your-generated-key-here'

# In production, use a secrets manager like:
# - AWS Secrets Manager
# - HashiCorp Vault
# - Azure Key Vault
# - Google Secret Manager"#.to_string()
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
        let rule = FlaskHardcodedSecretKeyRule::new();
        assert_eq!(rule.id(), "python.flask.hardcoded_secret_key");
    }

    #[test]
    fn rule_name_mentions_secret_key() {
        let rule = FlaskHardcodedSecretKeyRule::new();
        assert!(rule.name().contains("SECRET_KEY"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_flask_app() {
        let rule = FlaskHardcodedSecretKeyRule::new();
        let src = r#"
SECRET_KEY = "my-secret-key"
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "random.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_hardcoded_secret_key() {
        let rule = FlaskHardcodedSecretKeyRule::new();
        let src = r#"
from flask import Flask

app = Flask(__name__)
SECRET_KEY = "my-super-secret-key-12345"
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "app.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "python.flask.hardcoded_secret_key");
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_env_secret_key() {
        let rule = FlaskHardcodedSecretKeyRule::new();
        let src = r#"
from flask import Flask
import os

app = Flask(__name__)
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "app.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_has_patch() {
        let rule = FlaskHardcodedSecretKeyRule::new();
        let src = r#"
from flask import Flask
SECRET_KEY = "hardcoded"
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "app.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = FlaskHardcodedSecretKeyRule::new();
        let src = r#"
from flask import Flask
SECRET_KEY = "hardcoded"
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "app.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
        assert!(findings[0].fix_preview.as_ref().unwrap().contains("environ"));
    }
}