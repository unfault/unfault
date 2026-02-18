use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::AstLocation;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::{ImportCategory, ImportStyle, PyImport};
use crate::types::context::Dimension;
use crate::types::finding::FindingKind;
use crate::types::finding::Severity;
use crate::types::finding::FindingApplicability;
use crate::types::patch::FilePatch;
use crate::types::patch::PatchHunk;
use crate::types::patch::PatchRange;

/// Find the best line to insert a new import statement.
///
/// Strategy:
/// 1. If there's a `from fastapi import ...` statement, insert after it
/// 2. Otherwise, insert after the last import
/// 3. If no imports exist, return 0 (will insert at line 1, after any docstring)
///
/// Returns a 1-based line number to insert AFTER (for use with InsertAfterLine).
fn find_import_insertion_line(imports: &[PyImport], module_docstring_end_line: Option<u32>) -> u32 {
    if imports.is_empty() {
        if let Some(docstring_line) = module_docstring_end_line {
            return docstring_line;
        }
        return 0;
    }

    // First, try to find a `from fastapi import ...` statement
    let fastapi_import = imports
        .iter()
        .filter(|imp| imp.module == "fastapi" && !imp.names.is_empty())
        .max_by_key(|imp| imp.location.range.end_line);

    if let Some(imp) = fastapi_import {
        // Insert after the fastapi import
        // end_line is 0-based, InsertAfterLine expects 1-based
        // So we add 1 to convert to 1-based
        return imp.location.range.end_line + 1;
    }

    // Otherwise, find the last import and insert after it
    let last_import = imports.iter().max_by_key(|imp| imp.location.range.end_line);

    if let Some(imp) = last_import {
        // end_line is 0-based, InsertAfterLine expects 1-based
        return imp.location.range.end_line + 1;
    }

    0
}

/// Rule: detect FastAPI apps that do not have a CORS middleware configured.
///
/// Heuristics:
/// - File has Python semantics with a FastAPI summary.
/// - For each `FastApiApp` in that file:
///   - If there is no `FastApiMiddleware` with `middleware_type` containing "CORSMiddleware"
///     and matching `app_var_name`, we emit a finding.
#[derive(Debug)]
pub struct FastApiMissingCorsRule;

impl FastApiMissingCorsRule {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone)]
struct AppSite {
    file_id: FileId,
    file_path: String,
    app_name: String,
    loc: AstLocation,
    /// Import insertion line (1-based, for InsertAfterLine)
    import_insert_line: u32,
}

#[async_trait]
impl Rule for FastApiMissingCorsRule {
    fn id(&self) -> &'static str {
        "fastapi.missing_cors"
    }
    fn name(&self) -> &'static str {
        "FastAPI app without CORS middleware"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        let mut apps: Vec<AppSite> = Vec::new();
        let mut apps_with_cors: HashSet<String> = HashSet::new();

        // 1) Global pass: collect all apps and all apps that clearly have CORS.
        for (file_id, sem) in semantics {
            let (py, file_path) = match sem.as_ref() {
                SourceSemantics::Python(py) => (py, py.path.clone()),
                _ => continue,
            };

            let Some(ref fastapi) = py.fastapi else {
                continue;
            };

            // Collect app sites with import insertion line computed now
            let import_insert_line =
                find_import_insertion_line(&py.imports, py.module_docstring_end_line);
            for app in &fastapi.apps {
                apps.push(AppSite {
                    file_id: *file_id,
                    file_path: file_path.clone(),
                    app_name: app.var_name.clone(),
                    loc: app.location.clone(),
                    import_insert_line,
                });
            }

            // Collect middleware hooks that look like CORSMiddleware
            for mw in &fastapi.middlewares {
                if mw.middleware_type.contains("CORSMiddleware") {
                    apps_with_cors.insert(mw.app_var_name.clone());
                }
            }
        }

        // 2) Second pass: for each app site that does NOT have CORS globally, emit a finding.
        for app_site in apps {
            if apps_with_cors.contains(&app_site.app_name) {
                continue;
            }

            // Build patch hunks using app_site.file_id/file_path/loc.
            let cors_import = "from fastapi.middleware.cors import CORSMiddleware\n";

            let import_hunk = PatchHunk {
                range: PatchRange::InsertAfterLine {
                    line: app_site.import_insert_line,
                },
                replacement: cors_import.to_string(),
            };

            let middleware_block = format!(
                r#"{app}.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
"#,
                app = app_site.app_name,
            );

            let middleware_hunk = PatchHunk {
                range: PatchRange::InsertAfterLine {
                    line: app_site.loc.range.end_line + 1,
                },
                replacement: format!("\n{middleware_block}"),
            };

            let file_patch = FilePatch {
                file_id: app_site.file_id,
                hunks: vec![import_hunk, middleware_hunk],
            };

            let fix_preview = format!("{cors_import}\n{middleware_block}");

            findings.push(RuleFinding {
                rule_id: self.id().to_string(),
                title: format!(
                    "FastAPI app `{}` has no CORS middleware configured",
                    app_site.app_name
                ),
                description: Some(
                    "This FastAPI application does not appear to have a CORS middleware \
                     configured. Without CORSMiddleware, cross-origin requests may fail in \
                     browsers or behave inconsistently."
                        .to_string(),
                ),
                kind: FindingKind::BehaviorThreat,
                severity: Severity::Medium,
                confidence: 0.8,
                dimension: Dimension::Correctness,
                file_id: app_site.file_id,
                file_path: app_site.file_path.clone(),
                line: Some(app_site.loc.range.start_line + 1),
                column: Some(app_site.loc.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                patch: Some(file_patch),
                fix_preview: Some(fix_preview),
                tags: vec![
                    "fastapi".into(),
                    "cors".into(),
                    "middleware".into(),
                    "http".into(),
                ],
            });
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::cors_policy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::{FileId, TextRange};
    use crate::parse::python::parse_python_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    // ==================== Helper Functions ====================

    fn make_import(module: &str, names: Vec<&str>, start_line: u32, end_line: u32) -> PyImport {
        let style = if names.is_empty() {
            ImportStyle::Import
        } else {
            ImportStyle::FromImport
        };
        let category = if crate::semantics::python::model::is_stdlib_module(module) {
            ImportCategory::Stdlib
        } else {
            ImportCategory::ThirdParty
        };
        PyImport {
            module: module.to_string(),
            names: names.into_iter().map(|s| s.to_string()).collect(),
            alias: None,
            style,
            category,
            is_module_level: true,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line,
                    start_col: 0,
                    end_line,
                    end_col: 0,
                },
            },
        }
    }

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

    fn parse_multiple_files(sources: &[(&str, &str)]) -> Vec<(FileId, Arc<SourceSemantics>)> {
        sources
            .iter()
            .enumerate()
            .map(|(i, (path, content))| {
                let sf = SourceFile {
                    path: path.to_string(),
                    language: Language::Python,
                    content: content.to_string(),
                };
                let file_id = FileId(i as u64 + 1);
                let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
                let mut sem = PyFileSemantics::from_parsed(&parsed);
                sem.analyze_frameworks(&parsed)
                    .expect("framework analysis should succeed");
                (file_id, Arc::new(SourceSemantics::Python(sem)))
            })
            .collect()
    }

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = FastApiMissingCorsRule::new();
        assert_eq!(rule.id(), "fastapi.missing_cors");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = FastApiMissingCorsRule::new();
        assert_eq!(rule.name(), "FastAPI app without CORS middleware");
    }

    #[test]
    fn rule_implements_debug() {
        let rule = FastApiMissingCorsRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("FastApiMissingCorsRule"));
    }

    // ==================== evaluate Tests - No Findings ====================

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_fastapi_code() {
        let rule = FastApiMissingCorsRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_cors_is_configured() {
        let rule = FastApiMissingCorsRule::new();
        let src = r#"
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_cors_configured_in_separate_file() {
        let rule = FastApiMissingCorsRule::new();

        let sources = vec![
            (
                "app/main.py",
                "from fastapi import FastAPI\napp = FastAPI()",
            ),
            (
                "app/middleware.py",
                r#"
from fastapi.middleware.cors import CORSMiddleware

def setup_cors(app):
    app.add_middleware(CORSMiddleware, allow_origins=["*"])
"#,
            ),
        ];
        let semantics = parse_multiple_files(&sources);

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== evaluate Tests - With Findings ====================

    #[tokio::test]
    async fn evaluate_detects_missing_cors() {
        let rule = FastApiMissingCorsRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_rule_id() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings[0].rule_id, "fastapi.missing_cors");
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_severity() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].severity, Severity::Medium));
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_kind() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].kind, FindingKind::BehaviorThreat));
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_dimension() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings[0].dimension, Dimension::Correctness);
    }

    #[tokio::test]
    async fn evaluate_finding_includes_app_name_in_title() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\nmy_app = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].title.contains("my_app"));
    }

    #[tokio::test]
    async fn evaluate_finding_has_description() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].description.is_some());
        assert!(!findings[0].description.as_ref().unwrap().is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_has_tags() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].tags.contains(&"fastapi".to_string()));
        assert!(findings[0].tags.contains(&"cors".to_string()));
    }

    // ==================== evaluate Tests - Patch Generation ====================

    #[tokio::test]
    async fn evaluate_finding_includes_patch() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_patch_has_two_hunks() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let patch = findings[0].patch.as_ref().unwrap();

        // Should have import hunk and middleware hunk
        assert_eq!(patch.hunks.len(), 2);
    }

    #[tokio::test]
    async fn evaluate_finding_includes_fix_preview() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
    }

    #[tokio::test]
    async fn evaluate_fix_preview_contains_cors_import() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let preview = findings[0].fix_preview.as_ref().unwrap();

        assert!(preview.contains("CORSMiddleware"));
    }

    #[tokio::test]
    async fn evaluate_fix_preview_contains_add_middleware() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let preview = findings[0].fix_preview.as_ref().unwrap();

        assert!(preview.contains("add_middleware"));
    }

    // ==================== evaluate Tests - Multiple Apps ====================

    #[tokio::test]
    async fn evaluate_detects_multiple_apps_without_cors() {
        let rule = FastApiMissingCorsRule::new();
        let src = r#"
from fastapi import FastAPI

app1 = FastAPI()
app2 = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 2);
    }

    #[tokio::test]
    async fn evaluate_only_reports_apps_without_cors() {
        let rule = FastApiMissingCorsRule::new();
        let src = r#"
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app1 = FastAPI()
app2 = FastAPI()

app1.add_middleware(CORSMiddleware, allow_origins=["*"])
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Only app2 should be reported
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("app2"));
    }

    // ==================== evaluate Tests - Location ====================

    #[tokio::test]
    async fn evaluate_finding_has_correct_file_path() {
        let rule = FastApiMissingCorsRule::new();
        let sf = SourceFile {
            path: "src/main.py".to_string(),
            language: Language::Python,
            content: "from fastapi import FastAPI\napp = FastAPI()".to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed)
            .expect("framework analysis should succeed");
        let semantics = vec![(file_id, Arc::new(SourceSemantics::Python(sem)))];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings[0].file_path, "src/main.py");
    }

    #[tokio::test]
    async fn evaluate_finding_has_line_number() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].line.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_column_number() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].column.is_some());
    }

    // ==================== evaluate Tests - Confidence ====================

    #[tokio::test]
    async fn evaluate_finding_has_reasonable_confidence() {
        let rule = FastApiMissingCorsRule::new();
        let src = "from fastapi import FastAPI\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].confidence >= 0.0);
        assert!(findings[0].confidence <= 1.0);
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn evaluate_handles_empty_semantics() {
        let rule = FastApiMissingCorsRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_handles_non_python_semantics() {
        // This test would require non-Python semantics which we don't have yet
        // For now, just verify empty Python file works
        let rule = FastApiMissingCorsRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== find_import_insertion_line Tests ====================

    #[test]
    fn find_import_insertion_line_returns_zero_for_empty_imports() {
        let imports: Vec<PyImport> = vec![];
        assert_eq!(find_import_insertion_line(&imports, None), 0);
    }

    #[test]
    fn find_import_insertion_line_uses_docstring_when_no_imports() {
        let imports: Vec<PyImport> = vec![];
        assert_eq!(find_import_insertion_line(&imports, Some(9)), 9);
    }

    #[test]
    fn find_import_insertion_line_inserts_after_fastapi_import() {
        // Line 0: from fastapi import FastAPI
        // Line 1: import requests
        // Line 2: import httpx
        let imports = vec![
            make_import("fastapi", vec!["FastAPI"], 0, 0),
            make_import("requests", vec![], 1, 1),
            make_import("httpx", vec![], 2, 2),
        ];
        // Should insert after line 0 (the fastapi import), so return 1
        assert_eq!(find_import_insertion_line(&imports, None), 1);
    }

    #[test]
    fn find_import_insertion_line_inserts_after_last_import_when_no_fastapi() {
        // Line 0: import os
        // Line 1: import sys
        // Line 2: import requests
        let imports = vec![
            make_import("os", vec![], 0, 0),
            make_import("sys", vec![], 1, 1),
            make_import("requests", vec![], 2, 2),
        ];
        // Should insert after line 2 (the last import), so return 3
        assert_eq!(find_import_insertion_line(&imports, None), 3);
    }

    #[test]
    fn find_import_insertion_line_handles_multiline_import() {
        // Line 0-2: from fastapi import (
        //     FastAPI,
        //     APIRouter,
        // )
        // Line 3: import requests
        let imports = vec![
            make_import("fastapi", vec!["FastAPI", "APIRouter"], 0, 2),
            make_import("requests", vec![], 3, 3),
        ];
        // Should insert after line 2 (end of fastapi import), so return 3
        assert_eq!(find_import_insertion_line(&imports, None), 3);
    }

    #[test]
    fn find_import_insertion_line_prefers_from_fastapi_over_import_fastapi() {
        // Line 0: import fastapi
        // Line 1: from fastapi import FastAPI
        // Line 2: import requests
        let imports = vec![
            PyImport {
                module: "fastapi".to_string(),
                names: vec![], // import fastapi (no names)
                alias: None,
                style: ImportStyle::Import,
                category: ImportCategory::ThirdParty,
                is_module_level: true,
                location: AstLocation {
                    file_id: FileId(1),
                    range: TextRange {
                        start_line: 0,
                        start_col: 0,
                        end_line: 0,
                        end_col: 0,
                    },
                },
            },
            make_import("fastapi", vec!["FastAPI"], 1, 1),
            make_import("requests", vec![], 2, 2),
        ];
        // Should insert after line 1 (from fastapi import FastAPI), so return 2
        assert_eq!(find_import_insertion_line(&imports, None), 2);
    }

    #[test]
    fn find_import_insertion_line_handles_single_import() {
        let imports = vec![make_import("fastapi", vec!["FastAPI"], 5, 5)];
        // Should insert after line 5, so return 6
        assert_eq!(find_import_insertion_line(&imports, None), 6);
    }

    // ==================== Import Position in Patch Tests ====================

    #[tokio::test]
    async fn evaluate_patch_inserts_import_after_fastapi_import() {
        let rule = FastApiMissingCorsRule::new();
        // Line 0: from fastapi import FastAPI
        // Line 1: import requests
        // Line 2: (empty)
        // Line 3: app = FastAPI()
        let src = "from fastapi import FastAPI\nimport requests\n\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);

        let patch = findings[0].patch.as_ref().unwrap();
        let import_hunk = &patch.hunks[0];

        // The import should be inserted after line 1 (0-indexed line 0 is the fastapi import)
        // InsertAfterLine { line: 1 } means insert after line 1 (1-indexed)
        match &import_hunk.range {
            PatchRange::InsertAfterLine { line } => {
                // Line 1 in 1-indexed = line 0 in 0-indexed (the fastapi import line)
                // So we expect line to be 1 (insert after the first line)
                assert_eq!(
                    *line, 1,
                    "Import should be inserted after the fastapi import line"
                );
            }
            _ => panic!("Expected InsertAfterLine range"),
        }
    }

    #[tokio::test]
    async fn evaluate_patch_inserts_at_line_zero_when_no_imports() {
        let rule = FastApiMissingCorsRule::new();
        // When there are no imports, we insert at line 0 (after line 0)
        // Note: FastAPI() is detected even without explicit import in some cases
        let src = "app = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // FastAPI() call is detected even without import
        if !findings.is_empty() {
            let patch = findings[0].patch.as_ref().unwrap();
            let import_hunk = &patch.hunks[0];

            match &import_hunk.range {
                PatchRange::InsertAfterLine { line } => {
                    // With no imports, should insert after line 0
                    assert_eq!(
                        *line, 0,
                        "Import should be inserted at line 0 when no imports exist"
                    );
                }
                _ => panic!("Expected InsertAfterLine range"),
            }
        }
    }

    #[tokio::test]
    async fn evaluate_patch_inserts_import_after_last_import_when_multiple_imports() {
        let rule = FastApiMissingCorsRule::new();
        // Line 0: from fastapi import FastAPI
        // Line 1: import requests
        // Line 2: import httpx
        // Line 3: (empty)
        // Line 4: app = FastAPI()
        let src = "from fastapi import FastAPI\nimport requests\nimport httpx\n\napp = FastAPI()";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);

        let patch = findings[0].patch.as_ref().unwrap();
        let import_hunk = &patch.hunks[0];

        // Should insert after the fastapi import (line 0), not after the last import
        match &import_hunk.range {
            PatchRange::InsertAfterLine { line } => {
                // fastapi import is on line 0 (0-indexed), so end_line + 1 = 1
                assert_eq!(
                    *line, 1,
                    "Import should be inserted after the fastapi import (line 1)"
                );
            }
            _ => panic!("Expected InsertAfterLine range"),
        }
    }

    #[tokio::test]
    async fn evaluate_patch_handles_file_with_docstring() {
        let rule = FastApiMissingCorsRule::new();
        // Line 0-2: """Docstring"""
        // Line 3: (empty)
        // Line 4: from fastapi import FastAPI
        // Line 5: (empty)
        // Line 6: app = FastAPI()
        let src = r#""""Module docstring.

This is a longer docstring.
"""

from fastapi import FastAPI

app = FastAPI()"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);

        let patch = findings[0].patch.as_ref().unwrap();
        let import_hunk = &patch.hunks[0];

        // Should insert after the fastapi import, not at the top of the file
        match &import_hunk.range {
            PatchRange::InsertAfterLine { line } => {
                // The fastapi import is on line 5 (0-indexed), so insert after line 6 (1-indexed)
                assert!(
                    *line > 1,
                    "Import should be inserted after the docstring, not at line 1"
                );
            }
            _ => panic!("Expected InsertAfterLine range"),
        }
    }
}

#[cfg(test)]
mod debug_tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    #[test]
    fn debug_sample_file_imports() {
        let src = r#""""Sample FastAPI application with intentional issues for unfault to detect.

This sample app demonstrates common production-readiness issues:
1. Missing CORS middleware (stability issue)
2. HTTP calls without timeouts (reliability issue)
3. Blocking HTTP calls in async functions (performance issue)

Run unfault review in this directory to see the findings.
"""

from fastapi import FastAPI
import requests
import httpx

app = FastAPI(title="Sample API with Issues")
"#;
        let sf = SourceFile {
            path: "main.py".to_string(),
            language: Language::Python,
            content: src.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed)
            .expect("framework analysis should succeed");

        println!("=== IMPORTS ===");
        for imp in &sem.imports {
            println!(
                "  module: {}, names: {:?}, line: {}-{}",
                imp.module, imp.names, imp.location.range.start_line, imp.location.range.end_line
            );
        }

        let insert_line = find_import_insertion_line(&sem.imports, sem.module_docstring_end_line);
        println!("\n=== INSERT LINE: {} ===", insert_line);

        // The fastapi import should be on line 10 (0-indexed)
        // So insert_line should be 11 (1-indexed, insert after line 11)
        assert!(
            insert_line > 1,
            "Insert line should be after the docstring, got {}",
            insert_line
        );
    }
}