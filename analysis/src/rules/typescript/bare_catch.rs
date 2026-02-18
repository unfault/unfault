//! Rule: Bare catch clause without error type handling
//!
//! Detects TypeScript `catch` blocks that don't have an error parameter,
//! which makes debugging difficult.

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

/// Rule that detects bare catch clauses (without error parameter) in TypeScript code.
///
/// Bare catch clauses make debugging difficult because they don't capture
/// the error information.
#[derive(Debug)]
pub struct TypescriptBareCatchRule;

impl TypescriptBareCatchRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptBareCatchRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptBareCatchRule {
    fn id(&self) -> &'static str {
        "typescript.bare_catch"
    }

    fn name(&self) -> &'static str {
        "Bare catch clause without error parameter makes debugging difficult"
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

            for bare_catch in &ts.bare_catches {
                let title = "Bare catch clause without error parameter".to_string();

                let description = if let Some(ref fn_name) = bare_catch.function_name {
                    format!(
                        "The catch clause in function `{}` doesn't capture the error. \
                         This makes debugging difficult. Add an error parameter to the catch clause.",
                        fn_name
                    )
                } else {
                    "This catch clause doesn't capture the error. \
                     This makes debugging difficult. Add an error parameter to the catch clause."
                        .to_string()
                };

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::ReplaceBytes {
                            start: bare_catch.catch_keyword_start,
                            end: bare_catch.catch_keyword_end,
                        },
                        replacement: "catch (error)".to_string(),
                    }],
                };

                let fix_preview = "// Before:\ncatch {\n// After:\ncatch (error) {".to_string();

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::AntiPattern,
                    severity: Severity::Medium,
                    confidence: 1.0,
                    dimension: Dimension::Observability,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(bare_catch.line),
                    column: Some(bare_catch.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "typescript".into(),
                        "error-handling".into(),
                        "observability".into(),
                        "anti-pattern".into(),
                    ],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
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
        let rule = TypescriptBareCatchRule::new();
        assert_eq!(rule.id(), "typescript.bare_catch");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = TypescriptBareCatchRule::new();
        assert!(rule.name().contains("catch"));
    }

    #[tokio::test]
    async fn evaluate_detects_bare_catch() {
        let rule = TypescriptBareCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
try {
    risky();
} catch {
    console.log('error');
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "typescript.bare_catch");
    }

    #[tokio::test]
    async fn evaluate_ignores_catch_with_parameter() {
        let rule = TypescriptBareCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
try {
    risky();
} catch (error) {
    console.log(error);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_typescript() {
        let rule = TypescriptBareCatchRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}