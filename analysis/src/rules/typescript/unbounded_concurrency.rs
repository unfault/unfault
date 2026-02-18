//! Rule: Unbounded Promise.all concurrency
//!
//! Detects `Promise.all` or `Promise.allSettled` with potentially unbounded arrays,
//! which can overwhelm system resources.

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

/// Rule that detects unbounded Promise.all concurrency in TypeScript code.
///
/// Unbounded concurrency can exhaust file descriptors, overwhelm databases,
/// and cause memory pressure.
#[derive(Debug)]
pub struct TypescriptUnboundedConcurrencyRule;

impl TypescriptUnboundedConcurrencyRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptUnboundedConcurrencyRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptUnboundedConcurrencyRule {
    fn id(&self) -> &'static str {
        "typescript.unbounded_concurrency"
    }

    fn name(&self) -> &'static str {
        "Promise.all with unbounded array can overwhelm resources"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::unbounded_resource())
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

            // Look for Promise.all/Promise.allSettled calls with .map()
            for call in &ts.calls {
                if call.callee == "Promise.all" || call.callee == "Promise.allSettled" {
                    // Check if arguments contain .map() - indicates unbounded array
                    let args_text = call.args_repr.to_lowercase();
                    if args_text.contains(".map(") && !args_text.contains("limit") {
                        let title =
                            format!("{} with .map() can overwhelm resources", call.callee);

                        let description = format!(
                            "Using {} with an array from .map() can launch unbounded concurrent operations. \
                             This can exhaust file descriptors, overwhelm databases or APIs, and cause memory pressure. \
                             Consider using a concurrency limiter like p-limit.",
                            call.callee
                        );

                        // Check if p-limit is already imported
                        let has_plimit = ts.imports.iter().any(|imp| imp.module.contains("p-limit"));

                        let patch = if !has_plimit {
                            Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line: 1 },
                                    replacement:
                                        "import pLimit from 'p-limit';\nconst limit = pLimit(10);\n"
                                            .to_string(),
                                }],
                            })
                        } else {
                            None
                        };

                        let fix_preview = "// Add concurrency limiting:\nimport pLimit from 'p-limit';\nconst limit = pLimit(10);\nconst results = await Promise.all(items.map(item => limit(() => process(item))));".to_string();

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::High,
                            confidence: 0.8,
                            dimension: Dimension::Scalability,
                            file_id: *file_id,
                            file_path: ts.path.clone(),
                            line: Some(call.location.range.start_line + 1),
                            column: Some(call.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch,
                            fix_preview: Some(fix_preview),
                            tags: vec![
                                "typescript".into(),
                                "concurrency".into(),
                                "performance".into(),
                                "scalability".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::typescript::parse_typescript_file;
    use crate::semantics::typescript::build_typescript_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.ts".to_string(),
            language: Language::Typescript,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_typescript_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_typescript_semantics(&parsed).unwrap();
        (file_id, Arc::new(SourceSemantics::Typescript(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = TypescriptUnboundedConcurrencyRule::new();
        assert_eq!(rule.id(), "typescript.unbounded_concurrency");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = TypescriptUnboundedConcurrencyRule::new();
        assert!(rule.name().contains("Promise.all"));
    }

    #[tokio::test]
    async fn evaluate_detects_promise_all_with_map() {
        let rule = TypescriptUnboundedConcurrencyRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
const results = await Promise.all(items.map(item => fetchItem(item)));
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "typescript.unbounded_concurrency");
    }

    #[tokio::test]
    async fn evaluate_ignores_promise_all_without_map() {
        let rule = TypescriptUnboundedConcurrencyRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
const results = await Promise.all([promise1, promise2, promise3]);
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_with_limit() {
        let rule = TypescriptUnboundedConcurrencyRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
import pLimit from 'p-limit';
const limit = pLimit(10);
const results = await Promise.all(items.map(item => limit(() => fetchItem(item))));
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_typescript() {
        let rule = TypescriptUnboundedConcurrencyRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}