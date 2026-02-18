use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::ImportInsertionType;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that checks if FastAPI applications have exception handlers registered.
///
/// FastAPI applications should have exception handlers for common error types
/// like `RequestValidationError` and `HTTPException` to ensure consistent
/// error responses across the API.
#[derive(Debug)]
pub struct FastApiExceptionHandlerRule;

impl FastApiExceptionHandlerRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for FastApiExceptionHandlerRule {
    fn id(&self) -> &'static str {
        "python.fastapi.missing_exception_handler"
    }

    fn name(&self) -> &'static str {
        "Checks if FastAPI apps have exception handlers for common error types"
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

            // Only check files with FastAPI apps
            let fastapi = match &py.fastapi {
                Some(f) => f,
                None => continue,
            };

            // Skip if no apps defined in this file
            if fastapi.apps.is_empty() {
                continue;
            }

            // Use third_party_from_import for FastAPI/Starlette imports
            let import_line = py.import_insertion_line_for(ImportInsertionType::third_party_from_import());
            
            // Check each app for exception handlers
            for app in &fastapi.apps {
                // Find exception handlers for this app
                let app_handlers: Vec<_> = fastapi
                    .exception_handlers
                    .iter()
                    .filter(|h| h.app_var_name == app.var_name)
                    .collect();

                // Check for RequestValidationError handler
                let has_validation_handler = app_handlers
                    .iter()
                    .any(|h| h.exception_type.contains("RequestValidationError"));

                // Check for HTTPException handler
                let has_http_exception_handler = app_handlers
                    .iter()
                    .any(|h| h.exception_type.contains("HTTPException"));

                // Check for generic Exception handler
                let has_generic_handler = app_handlers.iter().any(|h| {
                    h.exception_type == "Exception" || h.exception_type.ends_with(".Exception")
                });

                // If no exception handlers at all, report a finding
                if app_handlers.is_empty() {
                    let location = &app.location;

                    // Generate a patch with semantically sound hunks:
                    // 1. Imports at the top of the file
                    // 2. Handler code after the app definition
                    let imports = generate_exception_handler_imports();
                    let handler_code = generate_exception_handler_code(&app.var_name);

                    let file_patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![
                            // Hunk 1: Add imports at the top of the file
                            PatchHunk {
                                range: PatchRange::InsertBeforeLine { line: import_line },
                                replacement: imports.clone(),
                            },
                            // Hunk 2: Add handler code after the app definition
                            PatchHunk {
                                range: PatchRange::InsertAfterLine {
                                    line: location.range.end_line,
                                },
                                replacement: handler_code.clone(),
                            },
                        ],
                    };

                    let patch_content = format!("{}\n{}", imports, handler_code);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: format!(
                            "FastAPI app `{}` has no exception handlers",
                            app.var_name
                        ),
                        description: Some(
                            "FastAPI applications should have exception handlers registered \
                             for common error types like RequestValidationError and HTTPException. \
                             This ensures consistent error responses and prevents leaking \
                             internal error details to clients."
                                .to_string(),
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(location.range.start_line + 1),
                        column: Some(location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(file_patch),
                        fix_preview: Some(format!(
                            "# Add exception handlers after app definition:\n{}",
                            patch_content.trim()
                        )),
                        tags: vec![
                            "python".into(),
                            "fastapi".into(),
                            "exception-handling".into(),
                            "stability".into(),
                        ],
                    });
                } else {
                    // Has some handlers, but check for specific missing ones
                    let mut missing_handlers = Vec::new();

                    if !has_validation_handler {
                        missing_handlers.push("RequestValidationError");
                    }
                    if !has_http_exception_handler {
                        missing_handlers.push("HTTPException");
                    }

                    // Only report if missing important handlers (not generic)
                    if !missing_handlers.is_empty() && !has_generic_handler {
                        let location = &app.location;

                        // Generate a patch with semantically sound hunks:
                        // 1. Imports at the top of the file
                        // 2. Handler code after the app definition
                        let imports = generate_specific_imports(&missing_handlers);
                        let handler_code = generate_specific_handler_code(&app.var_name, &missing_handlers);

                        let file_patch = FilePatch {
                            file_id: *file_id,
                            hunks: vec![
                                // Hunk 1: Add imports at the top of the file
                                PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line: import_line },
                                    replacement: imports.clone(),
                                },
                                // Hunk 2: Add handler code after the app definition
                                PatchHunk {
                                    range: PatchRange::InsertAfterLine {
                                        line: location.range.end_line,
                                    },
                                    replacement: handler_code.clone(),
                                },
                            ],
                        };

                        let patch_content = format!("{}\n{}", imports, handler_code);

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: format!(
                                "FastAPI app `{}` missing exception handlers for: {}",
                                app.var_name,
                                missing_handlers.join(", ")
                            ),
                            description: Some(format!(
                                "The FastAPI app `{}` has some exception handlers but is missing \
                                 handlers for: {}. Consider adding handlers for these exception \
                                 types to ensure consistent error responses.",
                                app.var_name,
                                missing_handlers.join(", ")
                            )),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Low,
                            confidence: 0.75,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(location.range.start_line + 1),
                            column: Some(location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(file_patch),
                            fix_preview: Some(format!(
                                "# Add missing exception handlers:\n{}",
                                patch_content.trim()
                            )),
                            tags: vec![
                                "python".into(),
                                "fastapi".into(),
                                "exception-handling".into(),
                                "stability".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
    }
}

/// Generate the imports needed for exception handlers.
fn generate_exception_handler_imports() -> String {
    r#"from fastapi import Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
"#
    .to_string()
}

/// Generate the exception handler code (without imports).
fn generate_exception_handler_code(app_var: &str) -> String {
    format!(
        r#"
@{app}.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={{"detail": exc.errors(), "body": exc.body}},
    )


@{app}.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={{"detail": exc.detail}},
    )
"#,
        app = app_var
    )
}

/// Generate a patch to add all common exception handlers.
/// Returns (imports, code) as separate strings for distinct hunks.
fn generate_exception_handler_patch(app_var: &str) -> String {
    format!(
        "{}\n{}",
        generate_exception_handler_imports(),
        generate_exception_handler_code(app_var)
    )
}

/// Generate imports for specific missing handlers.
fn generate_specific_imports(missing: &[&str]) -> String {
    let mut imports = Vec::new();
    imports.push("from fastapi import Request");
    imports.push("from fastapi.responses import JSONResponse");

    for handler_type in missing {
        match *handler_type {
            "RequestValidationError" => {
                imports.push("from fastapi.exceptions import RequestValidationError");
            }
            "HTTPException" => {
                imports.push("from starlette.exceptions import HTTPException as StarletteHTTPException");
            }
            _ => {}
        }
    }

    imports.join("\n") + "\n"
}

/// Generate code for specific missing handlers.
fn generate_specific_handler_code(app_var: &str, missing: &[&str]) -> String {
    let mut code = String::new();

    for handler_type in missing {
        match *handler_type {
            "RequestValidationError" => {
                code.push_str(&format!(
                    r#"
@{app}.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={{"detail": exc.errors(), "body": exc.body}},
    )
"#,
                    app = app_var
                ));
            }
            "HTTPException" => {
                code.push_str(&format!(
                    r#"
@{app}.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={{"detail": exc.detail}},
    )
"#,
                    app = app_var
                ));
            }
            _ => {}
        }
    }

    code
}

/// Generate a patch for specific missing handlers.
fn generate_specific_handler_patch(app_var: &str, missing: &[&str]) -> String {
    format!(
        "{}\n{}",
        generate_specific_imports(missing),
        generate_specific_handler_code(app_var, missing)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::semantics::SourceSemantics;
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

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = FastApiExceptionHandlerRule::new();
        assert_eq!(rule.id(), "python.fastapi.missing_exception_handler");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = FastApiExceptionHandlerRule::new();
        assert!(rule.name().contains("exception"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = FastApiExceptionHandlerRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("FastApiExceptionHandlerRule"));
    }

    // ==================== No Finding Tests ====================

    #[tokio::test]
    async fn no_finding_for_non_fastapi_code() {
        let rule = FastApiExceptionHandlerRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_exception_handlers_present() {
        let rule = FastApiExceptionHandlerRule::new();
        let src = r#"
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException

app = FastAPI()

@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": exc.errors()})

@app.exception_handler(HTTPException)
async def http_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_generic_exception_handler_present() {
        let rule = FastApiExceptionHandlerRule::new();
        let src = r#"
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

@app.exception_handler(Exception)
async def generic_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"detail": str(exc)})
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Generic handler covers all exceptions, so no finding
        assert!(findings.is_empty());
    }

    // ==================== Finding Tests ====================

    #[tokio::test]
    async fn finding_when_no_exception_handlers() {
        let rule = FastApiExceptionHandlerRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello"}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("no exception handlers"));
    }

    #[tokio::test]
    async fn finding_has_correct_rule_id() {
        let rule = FastApiExceptionHandlerRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_id,
            "python.fastapi.missing_exception_handler"
        );
    }

    #[tokio::test]
    async fn finding_has_patch() {
        let rule = FastApiExceptionHandlerRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn finding_has_fix_preview() {
        let rule = FastApiExceptionHandlerRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].fix_preview.is_some());
        let preview = findings[0].fix_preview.as_ref().unwrap();
        assert!(preview.contains("exception_handler"));
    }

    #[tokio::test]
    async fn finding_when_missing_validation_handler() {
        let rule = FastApiExceptionHandlerRule::new();
        let src = r#"
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

app = FastAPI()

@app.exception_handler(HTTPException)
async def http_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("RequestValidationError"));
    }

    #[tokio::test]
    async fn finding_when_missing_http_exception_handler() {
        let rule = FastApiExceptionHandlerRule::new();
        let src = r#"
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

app = FastAPI()

@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": exc.errors()})
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("HTTPException"));
    }

    // ==================== Multiple Apps Tests ====================

    #[tokio::test]
    async fn finding_for_each_app_without_handlers() {
        let rule = FastApiExceptionHandlerRule::new();
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

    // ==================== Patch Generation Tests ====================

    #[test]
    fn generate_exception_handler_patch_includes_imports() {
        let patch = generate_exception_handler_patch("app");
        assert!(patch.contains("from fastapi import Request"));
        assert!(patch.contains("from fastapi.responses import JSONResponse"));
        assert!(patch.contains("from fastapi.exceptions import RequestValidationError"));
    }

    #[test]
    fn generate_exception_handler_patch_includes_validation_handler() {
        let patch = generate_exception_handler_patch("app");
        assert!(patch.contains("@app.exception_handler(RequestValidationError)"));
        assert!(patch.contains("validation_exception_handler"));
    }

    #[test]
    fn generate_exception_handler_patch_includes_http_handler() {
        let patch = generate_exception_handler_patch("app");
        assert!(patch.contains("@app.exception_handler(StarletteHTTPException)"));
        assert!(patch.contains("http_exception_handler"));
    }

    #[test]
    fn generate_exception_handler_patch_uses_correct_app_var() {
        let patch = generate_exception_handler_patch("my_app");
        assert!(patch.contains("@my_app.exception_handler"));
    }

    #[test]
    fn generate_specific_handler_patch_for_validation() {
        let patch = generate_specific_handler_patch("app", &["RequestValidationError"]);
        assert!(patch.contains("@app.exception_handler(RequestValidationError)"));
        assert!(!patch.contains("StarletteHTTPException"));
    }

    #[test]
    fn generate_specific_handler_patch_for_http_exception() {
        let patch = generate_specific_handler_patch("app", &["HTTPException"]);
        assert!(patch.contains("@app.exception_handler(StarletteHTTPException)"));
        assert!(!patch.contains("RequestValidationError"));
    }
}