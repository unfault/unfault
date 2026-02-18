//! Rule: Unbounded Retry Loops
//!
//! Detects retry patterns that don't have proper bounds, which can cause
//! infinite loops on permanent failures.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::python::model::{ImportInsertionType, PyCallSite, PyImport};
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unbounded retry loops.
#[derive(Debug, Default)]
pub struct PythonUnboundedRetryRule;

impl PythonUnboundedRetryRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for PythonUnboundedRetryRule {
    fn id(&self) -> &'static str {
        "python.unbounded_retry"
    }

    fn name(&self) -> &'static str {
        "Unbounded Retry Loop"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(unbounded_resource())
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

            // Check for retry-related imports
            let has_tenacity = py.imports.iter().any(|imp| imp.module == "tenacity");
            let has_backoff = py.imports.iter().any(|imp| imp.module == "backoff");

            if !has_tenacity && !has_backoff {
                continue;
            }

            // Check for retry decorators without stop conditions
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;
                let args = &call.args_repr;

                // Check for tenacity.retry without stop parameter
                if callee == "retry" || callee == "tenacity.retry" {
                    if !args.contains("stop=")
                        && !args.contains("stop_after_attempt")
                        && !args.contains("stop_after_delay")
                    {
                        // Use third_party_from_import line for `from tenacity import stop_after_attempt`
                        let import_line = py.import_insertion_line_for(ImportInsertionType::third_party_from_import());
                        let patch = generate_tenacity_retry_patch(call, *file_id, &py.imports, import_line);
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Tenacity retry without stop condition".to_string(),
                            description: Some(
                                "This tenacity @retry decorator doesn't specify a stop condition. \
                                 Without stop_after_attempt() or stop_after_delay(), retries will continue indefinitely."
                                    .to_string(),
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.85,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(
                                "Add a stop condition:\n\n@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))"
                                    .to_string(),
                            ),
                            tags: vec!["retry".to_string(), "infinite-loop".to_string(), "stability".to_string()],
                        });
                    }
                }

                // Check for backoff decorators without max_tries
                if callee.starts_with("backoff.") && callee.contains("on_") {
                    if !args.contains("max_tries=") && !args.contains("max_time=") {
                        let patch = generate_backoff_patch(call, *file_id);
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Backoff decorator without max_tries".to_string(),
                            description: Some(
                                "This backoff decorator doesn't specify max_tries or max_time. \
                                 Without a limit, retries will continue indefinitely on permanent failures."
                                    .to_string(),
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.85,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(
                                "Add max_tries:\n\n@backoff.on_exception(backoff.expo, Exception, max_tries=5)"
                                    .to_string(),
                            ),
                            tags: vec!["retry".to_string(), "infinite-loop".to_string(), "stability".to_string()],
                        });
                    }
                }
            }
        }

        findings
    }
}

/// Check if stop_after_attempt is already imported from tenacity
fn has_stop_after_attempt_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| {
        imp.module == "tenacity" && imp.names.iter().any(|n| n == "stop_after_attempt")
    })
}

/// Generate a patch to add stop condition to a tenacity @retry decorator.
///
/// Transforms: `@retry()` → `@retry(stop=stop_after_attempt(3))`
/// Transforms: `@retry(wait=...)` → `@retry(wait=..., stop=stop_after_attempt(3))`
fn generate_tenacity_retry_patch(call: &PyCallSite, file_id: FileId, imports: &[PyImport], import_insertion_line: u32) -> FilePatch {
    let args_trimmed = call.args_repr.trim();
    
    let replacement = if args_trimmed.is_empty() {
        // @retry() → @retry(stop=stop_after_attempt(3))
        format!("{}(stop=stop_after_attempt(3))", call.function_call.callee_expr)
    } else {
        // @retry(wait=...) → @retry(wait=..., stop=stop_after_attempt(3))
        format!("{}({}, stop=stop_after_attempt(3))", call.function_call.callee_expr, args_trimmed)
    };

    let mut hunks = Vec::new();
    
    // Only add import for stop_after_attempt if not already present
    if !has_stop_after_attempt_import(imports) {
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: import_insertion_line },
            replacement: "from tenacity import stop_after_attempt  # Added by unfault\n".to_string(),
        });
    }
    
    // Replace the @retry() call with bounded version
    hunks.push(PatchHunk {
        range: PatchRange::ReplaceBytes {
            start: call.start_byte,
            end: call.end_byte,
        },
        replacement,
    });

    FilePatch { file_id, hunks }
}

/// Generate a patch to add max_tries to a backoff decorator.
///
/// Transforms: `@backoff.on_exception(backoff.expo, Exception)`
///          → `@backoff.on_exception(backoff.expo, Exception, max_tries=5)`
fn generate_backoff_patch(call: &PyCallSite, file_id: FileId) -> FilePatch {
    let args_trimmed = call.args_repr.trim();
    
    let replacement = if args_trimmed.is_empty() {
        // Edge case: no args (shouldn't happen in practice)
        format!("{}(max_tries=5)", call.function_call.callee_expr)
    } else {
        // Add max_tries to existing arguments
        format!("{}({}, max_tries=5)", call.function_call.callee_expr, args_trimmed)
    };

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: call.start_byte,
                end: call.end_byte,
            },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};
    use crate::types::patch::apply_file_patch;

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed).expect("framework analysis should succeed");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    #[test]
    fn test_rule_id() {
        let rule = PythonUnboundedRetryRule::new();
        assert_eq!(rule.id(), "python.unbounded_retry");
    }

    #[test]
    fn test_rule_name() {
        let rule = PythonUnboundedRetryRule::new();
        assert_eq!(rule.name(), "Unbounded Retry Loop");
    }

    // ==================== Detection Tests ====================

    #[tokio::test]
    async fn detects_tenacity_retry_without_stop() {
        let rule = PythonUnboundedRetryRule::new();
        let src = r#"
from tenacity import retry

@retry()
def fetch_data():
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty(), "Should detect retry without stop condition");
        assert!(findings[0].patch.is_some(), "Should have a patch");
    }

    #[tokio::test]
    async fn no_finding_for_retry_with_stop() {
        let rule = PythonUnboundedRetryRule::new();
        let src = r#"
from tenacity import retry, stop_after_attempt

@retry(stop=stop_after_attempt(3))
def fetch_data():
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not flag retry with stop condition");
    }

    #[tokio::test]
    async fn detects_backoff_without_max_tries() {
        let rule = PythonUnboundedRetryRule::new();
        let src = r#"
import backoff

@backoff.on_exception(backoff.expo, Exception)
def fetch_data():
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty(), "Should detect backoff without max_tries");
        assert!(findings[0].patch.is_some(), "Should have a patch");
    }

    #[tokio::test]
    async fn no_finding_for_backoff_with_max_tries() {
        let rule = PythonUnboundedRetryRule::new();
        let src = r#"
import backoff

@backoff.on_exception(backoff.expo, Exception, max_tries=5)
def fetch_data():
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not flag backoff with max_tries");
    }

    // ==================== Patch Application Tests ====================

    #[tokio::test]
    async fn patch_adds_stop_to_tenacity_retry() {
        let rule = PythonUnboundedRetryRule::new();
        let src = "from tenacity import retry\n\n@retry()\ndef fetch():\n    pass\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty(), "Should detect retry without stop");
        
        let patch = findings[0].patch.as_ref().expect("Should have a patch");
        let patched = apply_file_patch(src, patch);
        
        assert!(patched.contains("stop=stop_after_attempt(3)"), "Patched code should contain stop condition");
        assert!(patched.contains("from tenacity import stop_after_attempt"), "Patched code should add import");
    }

    #[tokio::test]
    async fn patch_adds_max_tries_to_backoff() {
        let rule = PythonUnboundedRetryRule::new();
        let src = "import backoff\n\n@backoff.on_exception(backoff.expo, Exception)\ndef fetch():\n    pass\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty(), "Should detect backoff without max_tries");
        
        let patch = findings[0].patch.as_ref().expect("Should have a patch");
        let patched = apply_file_patch(src, patch);
        
        assert!(patched.contains("max_tries=5"), "Patched code should contain max_tries");
    }

    #[tokio::test]
    async fn patch_uses_replace_bytes() {
        let rule = PythonUnboundedRetryRule::new();
        let src = "from tenacity import retry\n\n@retry()\ndef fetch():\n    pass\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());
        
        let patch = findings[0].patch.as_ref().expect("Should have a patch");
        
        // Verify that one hunk is ReplaceBytes (the actual fix)
        let has_replace_bytes = patch.hunks.iter().any(|h| {
            matches!(h.range, PatchRange::ReplaceBytes { .. })
        });
        assert!(has_replace_bytes, "Patch should use ReplaceBytes for actual code replacement");
    }
}