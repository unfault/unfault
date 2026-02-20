use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::circuit_breaker;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule: Missing Circuit Breaker
///
/// Detects HTTP client calls to external services without circuit breaker protection.
/// Circuit breakers provide graceful degradation when external dependencies are unavailable.
#[derive(Debug)]
pub struct PythonMissingCircuitBreakerRule;

impl PythonMissingCircuitBreakerRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonMissingCircuitBreakerRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonMissingCircuitBreakerRule {
    fn id(&self) -> &'static str {
        "python.resilience.missing_circuit_breaker"
    }

    fn name(&self) -> &'static str {
        "HTTP client calls without circuit breaker protection for graceful degradation"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(circuit_breaker())
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

            // Check if circuitbreaker is already imported
            let has_circuit_breaker_import = py.imports.iter().any(|imp| {
                imp.module == "circuitbreaker"
                    || imp.module == "pybreaker"
                    || imp
                        .names
                        .iter()
                        .any(|n| n == "circuit" || n == "CircuitBreaker")
            });

            if has_circuit_breaker_import {
                continue;
            }

            // Look for HTTP calls that could benefit from circuit breaker
            for call in &py.http_calls {
                let fn_label = call.function_name.as_deref().unwrap_or("<module>");

                let title = format!(
                    "HTTP call to external service in `{}` lacks circuit breaker protection",
                    fn_label
                );

                let description = format!(
                    "This HTTP call in `{fn_name}` does not have circuit breaker protection. \
                     A circuit breaker allows your service to fail fast and recover gracefully \
                     when external dependencies are slow or unavailable. \
                     Consider using the `circuitbreaker` or `pybreaker` library.",
                    fn_name = fn_label,
                );

                let fix_preview = generate_fix_preview(fn_label);

                // Generate patch
                let patch = generate_circuit_breaker_patch(
                    *file_id,
                    py.module_docstring_end_line.map(|l| l + 1).unwrap_or(1),
                    call.function_name.as_ref().and_then(|fn_name| {
                        py.functions
                            .iter()
                            .find(|f| &f.name == fn_name)
                            .map(|f| f.location.range.start_line + 1)
                    }),
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::High,
                    confidence: 0.80,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: py.path.clone(),
                    line: Some(call.location.range.start_line + 1),
                    column: Some(call.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "python".into(),
                        "resilience".into(),
                        "circuit-breaker".into(),
                        "cascading-failure".into(),
                    ],
                });
            }
        }

        findings
    }
}

/// Generate circuit breaker patch with import and decorator.
fn generate_circuit_breaker_patch(
    file_id: FileId,
    import_line: u32,
    function_def_line: Option<u32>,
) -> FilePatch {
    let mut hunks = Vec::new();

    // Hunk 1: Add circuitbreaker import
    let import_str = "from circuitbreaker import circuit\n";
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: import_line },
        replacement: import_str.to_string(),
    });

    // Hunk 2: Add @circuit decorator before the function definition
    if let Some(fn_line) = function_def_line {
        let decorator = "@circuit(failure_threshold=5, recovery_timeout=60)\n";
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: fn_line },
            replacement: decorator.to_string(),
        });
    }

    FilePatch { file_id, hunks }
}

/// Generate a fix preview showing how to add circuit breaker.
fn generate_fix_preview(fn_name: &str) -> String {
    format!(
        r#"# Install: pip install circuitbreaker
from circuitbreaker import circuit

@circuit(failure_threshold=5, recovery_timeout=60)
def {fn_name}():
    # After 5 consecutive failures, the circuit opens for 60 seconds
    # During this time, calls fail fast without hitting the external service
    response = requests.get('https://api.example.com/data', timeout=30)
    return response.json()

# Alternative: Use pybreaker for more control
from pybreaker import CircuitBreaker

breaker = CircuitBreaker(fail_max=5, reset_timeout=60)

@breaker
def {fn_name}_with_pybreaker():
    response = requests.get('https://api.example.com/data', timeout=30)
    return response.json()"#,
        fn_name = fn_name
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
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
        let rule = PythonMissingCircuitBreakerRule::new();
        assert_eq!(rule.id(), "python.resilience.missing_circuit_breaker");
    }

    #[test]
    fn rule_name_mentions_circuit_breaker() {
        let rule = PythonMissingCircuitBreakerRule::new();
        assert!(rule.name().contains("circuit breaker"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_http_code() {
        let rule = PythonMissingCircuitBreakerRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_circuit_breaker_imported() {
        let rule = PythonMissingCircuitBreakerRule::new();
        let src = r#"
from circuitbreaker import circuit

@circuit
def fetch_data():
    return requests.get('https://api.example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_missing_circuit_breaker() {
        let rule = PythonMissingCircuitBreakerRule::new();
        let src = r#"
def fetch_data():
    return requests.get('https://api.example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_id,
            "python.resilience.missing_circuit_breaker"
        );
    }

    #[tokio::test]
    async fn evaluate_finding_has_high_severity() {
        let rule = PythonMissingCircuitBreakerRule::new();
        let src = r#"
def fetch_data():
    return requests.get('https://api.example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].severity, Severity::High));
    }

    #[tokio::test]
    async fn evaluate_finding_has_patch() {
        let rule = PythonMissingCircuitBreakerRule::new();
        let src = r#"
def fetch_data():
    return requests.get('https://api.example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = PythonMissingCircuitBreakerRule::new();
        let src = r#"
def fetch_data():
    return requests.get('https://api.example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
        assert!(
            findings[0]
                .fix_preview
                .as_ref()
                .unwrap()
                .contains("circuitbreaker")
        );
    }
}
