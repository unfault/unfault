//! Rule: Empty catch blocks
//!
//! Detects TypeScript `catch` blocks that don't handle errors properly,
//! which can silently swallow errors and make debugging difficult.

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

/// Rule that detects empty catch blocks in TypeScript code.
///
/// Empty catch blocks silently swallow errors, making debugging extremely
/// difficult and potentially hiding critical issues.
#[derive(Debug)]
pub struct TypescriptEmptyCatchRule;

impl TypescriptEmptyCatchRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptEmptyCatchRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptEmptyCatchRule {
    fn id(&self) -> &'static str {
        "typescript.empty_catch"
    }

    fn name(&self) -> &'static str {
        "Empty catch blocks silently swallow errors"
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

            for empty_catch in &ts.empty_catches {
                let title = "Empty catch block silently swallows errors".to_string();

                let description = if let Some(ref fn_name) = empty_catch.function_name {
                    format!(
                        "The empty catch block in function `{}` silently ignores all errors. \
                         This can hide critical issues and make debugging extremely difficult. \
                         Consider logging the error or re-throwing it after handling.",
                        fn_name
                    )
                } else {
                    "This empty catch block silently ignores all errors. \
                     This can hide critical issues and make debugging extremely difficult. \
                     Consider logging the error or re-throwing it after handling."
                        .to_string()
                };

                // Generate patch to add minimal error logging
                let patch = generate_empty_catch_patch(empty_catch, *file_id);
                let fix_preview = "// Add error handling:\ncatch (error) {\n    console.error('Error:', error);\n}".to_string();

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::AntiPattern,
                    severity: Severity::High,
                    confidence: 1.0,
                    dimension: Dimension::Correctness,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(empty_catch.line),
                    column: Some(empty_catch.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "typescript".into(),
                        "error-handling".into(),
                        "correctness".into(),
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

fn generate_empty_catch_patch(
    empty_catch: &crate::semantics::typescript::model::EmptyCatchBlock,
    file_id: FileId,
) -> FilePatch {
    // The fix is to add error logging to the empty catch block
    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: empty_catch.start_byte,
                end: empty_catch.end_byte,
            },
            replacement: "catch (error) {\n    console.error('Unhandled error:', error);\n}".to_string(),
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
        let rule = TypescriptEmptyCatchRule::new();
        assert_eq!(rule.id(), "typescript.empty_catch");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = TypescriptEmptyCatchRule::new();
        assert!(rule.name().contains("catch"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_typescript() {
        let rule = TypescriptEmptyCatchRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_empty_catch() {
        let rule = TypescriptEmptyCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
try {
    riskyOperation();
} catch (e) {
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "typescript.empty_catch");
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_empty_catch() {
        let rule = TypescriptEmptyCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
try {
    riskyOperation();
} catch (e) {
    console.error(e);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}