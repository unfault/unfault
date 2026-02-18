//! Rule: Unsafe `any` type usage
//!
//! Detects explicit use of the `any` type in TypeScript, which bypasses
//! type checking and can lead to runtime errors.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects explicit `any` type usage.
///
/// Using `any` disables TypeScript's type checking for that value,
/// eliminating the safety benefits of TypeScript and potentially
/// introducing runtime errors.
#[derive(Debug)]
pub struct TypescriptUnsafeAnyRule;

impl TypescriptUnsafeAnyRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptUnsafeAnyRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptUnsafeAnyRule {
    fn id(&self) -> &'static str {
        "typescript.unsafe_any"
    }

    fn name(&self) -> &'static str {
        "Explicit `any` type bypasses type safety"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
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

            // Check function parameters with `any` type
            for func in &ts.functions {
                for param in &func.params {
                    if let Some(ref type_ann) = param.type_annotation {
                        if type_ann.contains("any") && !type_ann.contains("unknown") {
                            let title = format!(
                                "Parameter `{}` in function `{}` uses `any` type",
                                param.name, func.name
                            );
                            let description = format!(
                                "The parameter `{}` has type `any`, which disables type checking. \
                                 Consider using `unknown` for values of uncertain type, or define \
                                 a more specific type or interface.",
                                param.name
                            );

                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title,
                                description: Some(description),
                                kind: FindingKind::AntiPattern,
                                severity: Severity::Low,
                                confidence: 1.0,
                                dimension: Dimension::Correctness,
                                file_id: *file_id,
                                file_path: ts.path.clone(),
                                line: Some(func.location.range.start_line + 1),
                                column: Some(func.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                                patch: None,
                                fix_preview: Some(format!("// Consider: {} : unknown", param.name)),
                                tags: vec![
                                    "typescript".into(),
                                    "type-safety".into(),
                                    "any".into(),
                                    "anti-pattern".into(),
                                ],
                            });
                        }
                    }
                }
            }

            // Check variables with `any` type
            for var in &ts.variables {
                if let Some(ref type_ann) = var.type_annotation {
                    if type_ann.contains("any") && !type_ann.contains("unknown") {
                        let title = format!(
                            "Variable `{}` uses `any` type",
                            var.name
                        );
                        let description = format!(
                            "The variable `{}` has type `any`, which disables type checking. \
                             Consider using `unknown` for values of uncertain type, or define \
                             a more specific type or interface.",
                            var.name
                        );

                        let patch = generate_patch(*file_id, var.location.range.start_line + 1);

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::AntiPattern,
                            severity: Severity::Low,
                            confidence: 1.0,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: ts.path.clone(),
                            line: Some(var.location.range.start_line + 1),
                            column: Some(var.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(format!("// Consider: const {}: unknown = ...", var.name)),
                            tags: vec![
                                "typescript".into(),
                                "type-safety".into(),
                                "any".into(),
                                "anti-pattern".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }
}

fn generate_patch(file_id: FileId, line: u32) -> FilePatch {
    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement: "// TODO: Replace `any` with a more specific type or `unknown`\n".to_string(),
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
        let rule = TypescriptUnsafeAnyRule::new();
        assert_eq!(rule.id(), "typescript.unsafe_any");
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_typescript() {
        let rule = TypescriptUnsafeAnyRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_typed_code() {
        let rule = TypescriptUnsafeAnyRule::new();
        let src = r#"
const value: string = "hello";
function greet(name: string): string {
    return `Hello, ${name}`;
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_unknown_type() {
        let rule = TypescriptUnsafeAnyRule::new();
        let src = r#"
const value: unknown = getExternalValue();
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}