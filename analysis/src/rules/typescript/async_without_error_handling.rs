//! Rule: Async functions without error handling
//!
//! Detects async functions that don't have proper error handling,
//! which can lead to unhandled promise rejections and crashes.

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

/// Rule that detects async functions without error handling.
///
/// Async functions that don't have try-catch blocks can lead to
/// unhandled promise rejections, causing crashes in Node.js
/// or silent failures in browsers.
#[derive(Debug)]
pub struct TypescriptAsyncWithoutErrorHandlingRule;

impl TypescriptAsyncWithoutErrorHandlingRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptAsyncWithoutErrorHandlingRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptAsyncWithoutErrorHandlingRule {
    fn id(&self) -> &'static str {
        "typescript.async_without_error_handling"
    }

    fn name(&self) -> &'static str {
        "Async function without error handling"
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

            // Check async functions without try-catch
            for func in &ts.functions {
                if func.is_async && !func.has_try_catch {
                    let title = format!("Async function `{}` lacks error handling", func.name);

                    let description = format!(
                        "The async function `{}` doesn't have a try-catch block. \
                         Unhandled errors in async functions will cause unhandled promise \
                         rejections, which can crash Node.js applications or cause silent \
                         failures in browsers. Wrap the function body in a try-catch block \
                         or ensure callers handle errors appropriately.",
                        func.name
                    );

                    let patch = generate_patch(*file_id, func.location.range.start_line + 1);
                    let fix_preview = format!(
                        "async function {}(...) {{\n    try {{\n        // existing code\n    }} catch (error) {{\n        console.error('Error in {}:', error);\n        throw error;\n    }}\n}}",
                        func.name, func.name
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: ts.path.clone(),
                        line: Some(func.location.range.start_line + 1),
                        column: Some(func.location.range.start_col + 1),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "typescript".into(),
                            "async".into(),
                            "error-handling".into(),
                            "correctness".into(),
                        ],
                    });
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
    }
}

fn generate_patch(file_id: FileId, line: u32) -> FilePatch {
    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement: "// TODO: Add try-catch error handling\n".to_string(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::typescript::parse_typescript_file;
    use crate::semantics::typescript::model::TsFileSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.ts".to_string(),
            language: Language::Typescript,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_typescript_file(file_id, &sf).expect("parsing should succeed");
        let sem = TsFileSemantics::from_parsed(&parsed);
        (file_id, Arc::new(SourceSemantics::Typescript(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = TypescriptAsyncWithoutErrorHandlingRule::new();
        assert_eq!(rule.id(), "typescript.async_without_error_handling");
    }

    #[tokio::test]
    async fn evaluate_detects_async_without_try_catch() {
        let rule = TypescriptAsyncWithoutErrorHandlingRule::new();
        let src = r#"
async function fetchData() {
    const response = await fetch('https://api.example.com');
    return response.json();
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("fetchData"));
    }

    #[tokio::test]
    async fn evaluate_ignores_async_with_try_catch() {
        let rule = TypescriptAsyncWithoutErrorHandlingRule::new();
        let src = r#"
async function fetchData() {
    try {
        const response = await fetch('https://api.example.com');
        return response.json();
    } catch (error) {
        console.error(error);
        throw error;
    }
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_non_async_functions() {
        let rule = TypescriptAsyncWithoutErrorHandlingRule::new();
        let src = r#"
function syncFunction() {
    return 42;
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}
