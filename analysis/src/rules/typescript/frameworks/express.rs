//! Express.js-specific rules for TypeScript
//!
//! Contains rules for detecting common issues in Express.js applications.

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

/// Rule that detects Express.js apps without error handling middleware.
///
/// Express.js applications should have error handling middleware to
/// catch and handle errors properly, preventing crashes and security issues.
#[derive(Debug)]
pub struct ExpressMissingErrorMiddlewareRule;

impl ExpressMissingErrorMiddlewareRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ExpressMissingErrorMiddlewareRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for ExpressMissingErrorMiddlewareRule {
    fn id(&self) -> &'static str {
        "typescript.express.missing_error_middleware"
    }

    fn name(&self) -> &'static str {
        "Express.js app missing error handling middleware"
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

            // Check if there's Express semantics
            let express = match &ts.express {
                Some(e) => e,
                None => continue,
            };

            // Skip if no apps are defined
            if express.apps.is_empty() {
                continue;
            }

            // Check if there's error middleware
            // Error middleware in Express has 4 parameters: (err, req, res, next)
            let has_error_middleware = express.middlewares.iter().any(|mw| {
                // Common error handling middleware names
                mw.middleware_name.contains("error")
                    || mw.middleware_name.contains("Error")
                    || mw.middleware_name == "errorHandler"
            });

            if !has_error_middleware {
                for app in &express.apps {
                    let title = format!(
                        "Express app `{}` missing error handling middleware",
                        app.variable_name
                    );
                    let description = format!(
                        "The Express app `{}` doesn't have error handling middleware. \
                         Without proper error handling, unhandled errors can crash the server \
                         or expose sensitive information. Add an error handling middleware \
                         with the signature `(err, req, res, next) => {{ ... }}`.",
                        app.variable_name
                    );

                    let patch = generate_patch(*file_id, app.location.range.end_line + 1);
                    let fix_preview = format!(
                        "{}.use((err, req, res, next) => {{\n    console.error(err);\n    res.status(500).json({{ error: 'Internal Server Error' }});\n}});",
                        app.variable_name
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::High,
                        confidence: 0.9,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: ts.path.clone(),
                        line: Some(app.location.range.start_line + 1),
                        column: Some(app.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "typescript".into(),
                            "express".into(),
                            "error-handling".into(),
                            "stability".into(),
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
            range: PatchRange::InsertAfterLine { line },
            replacement: r#"
// Error handling middleware - add at the end of middleware chain
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal Server Error' });
});
"#
            .to_string(),
        }],
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
            path: "app.ts".to_string(),
            language: Language::Typescript,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_typescript_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_typescript_semantics(&parsed).expect("semantics should succeed");
        (file_id, Arc::new(SourceSemantics::Typescript(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = ExpressMissingErrorMiddlewareRule::new();
        assert_eq!(rule.id(), "typescript.express.missing_error_middleware");
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_typescript() {
        let rule = ExpressMissingErrorMiddlewareRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_express() {
        let rule = ExpressMissingErrorMiddlewareRule::new();
        let src = r#"
const x = 42;
function hello() {}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_missing_error_middleware() {
        let rule = ExpressMissingErrorMiddlewareRule::new();
        let src = r#"
import express from 'express';

const app = express();

app.use(express.json());

app.get('/', (req, res) => {
    res.send('Hello');
});
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("error handling middleware"));
    }

    #[tokio::test]
    async fn evaluate_ignores_app_with_error_middleware() {
        let rule = ExpressMissingErrorMiddlewareRule::new();
        let src = r#"
import express from 'express';

const app = express();

app.use(errorHandler());
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}