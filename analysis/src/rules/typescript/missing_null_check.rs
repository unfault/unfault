//! Rule: Missing null/undefined checks
//!
//! Detects potential null/undefined access patterns that could benefit
//! from optional chaining or nullish coalescing operators.

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

/// Rule that detects potentially unsafe property access patterns.
///
/// This rule identifies cases where optional chaining (?.) or
/// nullish coalescing (??) could prevent runtime errors from
/// accessing properties on null/undefined values.
#[derive(Debug)]
pub struct TypescriptMissingNullCheckRule;

impl TypescriptMissingNullCheckRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptMissingNullCheckRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptMissingNullCheckRule {
    fn id(&self) -> &'static str {
        "typescript.missing_null_check"
    }

    fn name(&self) -> &'static str {
        "Potential null/undefined access without check"
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

            // Check function parameters marked optional without default value
            for func in &ts.functions {
                for param in &func.params {
                    if param.is_optional && param.default_value.is_none() {
                        // Check if the parameter name appears in inner_calls as property access
                        for call in &func.inner_calls {
                            if call.starts_with(&param.name) && call.contains('.') {
                                let title = format!(
                                    "Optional parameter `{}` accessed without null check in `{}`",
                                    param.name, func.name
                                );
                                let description = format!(
                                    "The optional parameter `{}` in function `{}` is accessed \
                                     without a null/undefined check. This could cause a runtime \
                                     error if the caller doesn't provide this argument. Consider \
                                     using optional chaining (`{0}?.property`) or a guard clause.",
                                    param.name, func.name
                                );

                                let patch =
                                    generate_patch(*file_id, func.location.range.start_line + 1);

                                findings.push(RuleFinding {
                                    rule_id: self.id().to_string(),
                                    title,
                                    description: Some(description),
                                    kind: FindingKind::StabilityRisk,
                                    severity: Severity::Medium,
                                    confidence: 0.75,
                                    dimension: Dimension::Correctness,
                                    file_id: *file_id,
                                    file_path: ts.path.clone(),
                                    line: Some(func.location.range.start_line + 1),
                                    column: Some(func.location.range.start_col + 1),
                                    end_line: None,
                                    end_column: None,
                                    byte_range: None,
                                    patch: Some(patch),
                                    fix_preview: Some(format!(
                                        "// Use optional chaining: {}?.property or add a guard",
                                        param.name
                                    )),
                                    tags: vec![
                                        "typescript".into(),
                                        "null-safety".into(),
                                        "optional-chaining".into(),
                                        "correctness".into(),
                                    ],
                                });
                                break; // Only report once per parameter
                            }
                        }
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
    }
}

fn generate_patch(file_id: FileId, line: u32) -> FilePatch {
    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement: "// TODO: Add null check or use optional chaining\n".to_string(),
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
        let rule = TypescriptMissingNullCheckRule::new();
        assert_eq!(rule.id(), "typescript.missing_null_check");
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_typescript() {
        let rule = TypescriptMissingNullCheckRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_required_parameters() {
        let rule = TypescriptMissingNullCheckRule::new();
        let src = r#"
function greet(name: string): string {
    return name.toUpperCase();
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_optional_with_default() {
        let rule = TypescriptMissingNullCheckRule::new();
        let src = r#"
function greet(name: string = "World"): string {
    return name.toUpperCase();
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}
