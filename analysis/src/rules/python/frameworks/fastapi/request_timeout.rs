use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::{ImportInsertionType, PyImport};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Check if BaseHTTPMiddleware is already imported from starlette
fn has_base_http_middleware_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| {
        (imp.module == "starlette.middleware.base" && imp.names.iter().any(|n| n == "BaseHTTPMiddleware"))
            || imp.names.iter().any(|n| n == "BaseHTTPMiddleware")
    })
}

/// Check if asyncio module is already imported
fn has_asyncio_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| imp.module == "asyncio")
}

/// Check if JSONResponse is already imported from starlette
fn has_json_response_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| {
        (imp.module == "starlette.responses" && imp.names.iter().any(|n| n == "JSONResponse"))
            || (imp.module == "fastapi.responses" && imp.names.iter().any(|n| n == "JSONResponse"))
            || (imp.module == "fastapi" && imp.names.iter().any(|n| n == "JSONResponse"))
    })
}

/// Check if Request is already imported from starlette
fn has_request_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| {
        (imp.module == "starlette.requests" && imp.names.iter().any(|n| n == "Request"))
            || (imp.module == "fastapi" && imp.names.iter().any(|n| n == "Request"))
    })
}

/// Rule A8: Web framework without request timeout
///
/// Detects FastAPI applications that don't have request timeout middleware configured.
/// Without request timeouts, slow downstream services can cause stuck workers and 503 storms.
#[derive(Debug)]
pub struct FastApiRequestTimeoutRule;

impl FastApiRequestTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for FastApiRequestTimeoutRule {
    fn id(&self) -> &'static str {
        "python.fastapi.missing_request_timeout"
    }

    fn name(&self) -> &'static str {
        "Checks if FastAPI apps have request timeout middleware configured"
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

            // Check if there's any timeout middleware configured
            // Look for common timeout middleware patterns:
            // 1. starlette.middleware.timeout.TimeoutMiddleware
            // 2. Custom timeout middleware
            // 3. asyncio.timeout usage in middleware
            let has_timeout_middleware = py.imports.iter().any(|imp| {
                imp.module.contains("timeout")
                    || imp.names.iter().any(|n| n.contains("Timeout"))
            }) || py.calls.iter().any(|call| {
                call.function_call.callee_expr.contains("add_middleware")
                    && call.args.iter().any(|arg| {
                        arg.value_repr.contains("Timeout")
                    })
            });

            // Also check for ASGIMiddleware or similar patterns
            let has_asgi_timeout = py.imports.iter().any(|imp| {
                imp.names.iter().any(|n| n == "ASGIMiddleware" || n == "TimeoutMiddleware")
            });

            if has_timeout_middleware || has_asgi_timeout {
                continue;
            }

            // For mixed imports (stdlib + third-party), use stdlib_import line
            // since asyncio should be at the top
            let import_line = py.import_insertion_line_for(ImportInsertionType::stdlib_import());
            
            // Check each app for timeout middleware
            for app in &fastapi.apps {
                // Check if this specific app has timeout middleware
                let app_has_timeout = py.calls.iter().any(|call| {
                    call.function_call.callee_expr == format!("{}.add_middleware", app.var_name)
                        && call.args.iter().any(|arg| {
                            arg.value_repr.contains("Timeout")
                        })
                });

                if app_has_timeout {
                    continue;
                }

                let location = &app.location;

                // Generate patch with semantically sound hunks
                let imports = generate_timeout_imports(&py.imports);
                let middleware_class = generate_timeout_middleware_class();
                let middleware_call = generate_timeout_middleware_call(&app.var_name);

                let mut hunks = Vec::new();
                
                // Hunk 1: Add imports at the top of the file (only if needed)
                if !imports.is_empty() {
                    hunks.push(PatchHunk {
                        range: PatchRange::InsertBeforeLine { line: import_line },
                        replacement: imports.clone(),
                    });
                }
                
                // Hunk 2: Add middleware class BEFORE the app definition
                // (so the class is defined before it's used)
                hunks.push(PatchHunk {
                    range: PatchRange::InsertBeforeLine {
                        line: location.range.start_line + 1,  // Convert 0-based to 1-based
                    },
                    replacement: middleware_class.clone(),
                });
                
                // Hunk 3: Add middleware call AFTER the app definition
                hunks.push(PatchHunk {
                    range: PatchRange::InsertAfterLine {
                        line: location.range.end_line + 1,  // Convert 0-based to 1-based
                    },
                    replacement: middleware_call.clone(),
                });

                let file_patch = FilePatch {
                    file_id: *file_id,
                    hunks,
                };

                let patch_content = format!("{}\n{}\n{}", imports, middleware_class, middleware_call);

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!(
                        "FastAPI app `{}` has no request timeout middleware",
                        app.var_name
                    ),
                    description: Some(
                        "FastAPI applications should have request timeout middleware configured. \
                         Without request timeouts, slow downstream services or long-running \
                         requests can cause worker exhaustion and cascading failures. \
                         The suggested middleware excludes health check endpoints by default \
                         and supports per-route timeout configuration via request.state for \
                         routes that need longer timeouts (file uploads, streaming, etc.)."
                            .to_string(),
                    ),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.80,
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
                        "# Add request timeout middleware:\n{}",
                        patch_content.trim()
                    )),
                    tags: vec![
                        "python".into(),
                        "fastapi".into(),
                        "timeout".into(),
                        "stability".into(),
                        "middleware".into(),
                    ],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
    }
}

/// Generate the imports needed for timeout middleware.
/// Only includes imports that are not already present.
fn generate_timeout_imports(existing_imports: &[PyImport]) -> String {
    let mut import_lines = Vec::new();
    
    // Standard library imports first
    if !has_asyncio_import(existing_imports) {
        import_lines.push("import asyncio");
    }
    // typing imports for type annotations
    import_lines.push("from typing import Callable");
    
    // Starlette imports
    if !has_base_http_middleware_import(existing_imports) {
        import_lines.push("from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint");
    }
    if !has_request_import(existing_imports) {
        import_lines.push("from starlette.requests import Request");
    }
    if !has_json_response_import(existing_imports) {
        import_lines.push("from starlette.responses import JSONResponse, Response");
    }
    
    if import_lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", import_lines.join("\n"))
    }
}

/// Generate the timeout middleware class definition.
/// This is a production-ready implementation that:
/// - Excludes health check endpoints by default
/// - Supports per-route timeout configuration via state
/// - Has sensible defaults that can be customized
/// - Uses proper Python type annotations
fn generate_timeout_middleware_class() -> String {
    r#"
# Request timeout middleware - production-ready implementation
DEFAULT_TIMEOUT: float = 30.0  # seconds
DEFAULT_EXEMPT_PATHS: set[str] = {
    "/health", "/healthz", "/ready", "/readiness",
    "/live", "/liveness", "/metrics",
}


class TimeoutMiddleware(BaseHTTPMiddleware):
    """Request timeout middleware with per-route configuration.

    Args:
        app: The ASGI application.
        timeout: Default timeout in seconds for all requests.
        exempt_paths: Paths that bypass timeout enforcement.

    Usage:
        # Basic usage with default 30s timeout
        app.add_middleware(TimeoutMiddleware)

        # Custom default timeout
        app.add_middleware(TimeoutMiddleware, timeout=60.0)

        # Custom exempt paths
        app.add_middleware(
            TimeoutMiddleware,
            exempt_paths={"/health", "/long-task"},
        )

        # Per-route timeout via dependency:
        def timeout_120s(request: Request) -> None:
            request.state.timeout = 120.0

        @app.post("/upload", dependencies=[Depends(timeout_120s)])
        async def upload_file(...): ...

        # Disable timeout for specific route:
        def no_timeout(request: Request) -> None:
            request.state.timeout = None

        @app.get("/stream", dependencies=[Depends(no_timeout)])
        async def stream_data(...): ...
    """

    timeout: float
    exempt_paths: set[str]

    def __init__(
        self,
        app: Callable,
        timeout: float = DEFAULT_TIMEOUT,
        exempt_paths: set[str] | None = None,
    ) -> None:
        super().__init__(app)
        self.timeout = timeout
        self.exempt_paths = (
            exempt_paths if exempt_paths is not None
            else DEFAULT_EXEMPT_PATHS
        )

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Skip timeout for exempt paths (health checks, etc.)
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        # Check for per-route timeout override
        route_timeout: float | None = getattr(
            request.state, "timeout", self.timeout
        )

        # If timeout is None, skip timeout for this route
        if route_timeout is None:
            return await call_next(request)

        try:
            return await asyncio.wait_for(
                call_next(request), timeout=route_timeout
            )
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=504,
                content={"detail": f"Request timeout after {route_timeout}s"},
            )

"#
    .to_string()
}

/// Generate the middleware registration call.
fn generate_timeout_middleware_call(app_var: &str) -> String {
    format!("{}.add_middleware(TimeoutMiddleware, timeout=30.0)\n", app_var)
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
        let rule = FastApiRequestTimeoutRule::new();
        assert_eq!(rule.id(), "python.fastapi.missing_request_timeout");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = FastApiRequestTimeoutRule::new();
        assert!(rule.name().contains("timeout"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = FastApiRequestTimeoutRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("FastApiRequestTimeoutRule"));
    }

    // ==================== No Finding Tests ====================

    #[tokio::test]
    async fn no_finding_for_non_fastapi_code() {
        let rule = FastApiRequestTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_timeout_middleware_present() {
        let rule = FastApiRequestTimeoutRule::new();
        let src = r#"
from fastapi import FastAPI
from starlette.middleware.timeout import TimeoutMiddleware

app = FastAPI()

app.add_middleware(TimeoutMiddleware, timeout=30)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_custom_timeout_middleware_present() {
        let rule = FastApiRequestTimeoutRule::new();
        let src = r#"
from fastapi import FastAPI
from myapp.middleware import TimeoutMiddleware

app = FastAPI()

app.add_middleware(TimeoutMiddleware)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Finding Tests ====================

    #[tokio::test]
    async fn finding_when_no_timeout_middleware() {
        let rule = FastApiRequestTimeoutRule::new();
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
        assert!(findings[0].title.contains("no request timeout middleware"));
    }

    #[tokio::test]
    async fn finding_has_correct_rule_id() {
        let rule = FastApiRequestTimeoutRule::new();
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
            "python.fastapi.missing_request_timeout"
        );
    }

    #[tokio::test]
    async fn finding_has_correct_severity() {
        let rule = FastApiRequestTimeoutRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Medium));
    }

    #[tokio::test]
    async fn finding_has_correct_dimension() {
        let rule = FastApiRequestTimeoutRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].dimension, Dimension::Stability);
    }

    #[tokio::test]
    async fn finding_has_patch() {
        let rule = FastApiRequestTimeoutRule::new();
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
    async fn finding_patch_has_three_hunks() {
        let rule = FastApiRequestTimeoutRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        let patch = findings[0].patch.as_ref().unwrap();
        assert_eq!(patch.hunks.len(), 3, "Should have import hunk + middleware class hunk + middleware call hunk");
    }

    #[tokio::test]
    async fn finding_has_fix_preview() {
        let rule = FastApiRequestTimeoutRule::new();
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
        assert!(preview.contains("TimeoutMiddleware"));
    }

    #[tokio::test]
    async fn finding_has_correct_tags() {
        let rule = FastApiRequestTimeoutRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].tags.contains(&"python".to_string()));
        assert!(findings[0].tags.contains(&"fastapi".to_string()));
        assert!(findings[0].tags.contains(&"timeout".to_string()));
        assert!(findings[0].tags.contains(&"stability".to_string()));
    }

    // ==================== Multiple Apps Tests ====================

    #[tokio::test]
    async fn finding_for_each_app_without_timeout() {
        let rule = FastApiRequestTimeoutRule::new();
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

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = FastApiRequestTimeoutRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = FastApiRequestTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Patch Generation Tests ====================

    #[test]
    fn generate_timeout_imports_includes_required_imports() {
        // Give empty imports to get all required imports
        let imports = generate_timeout_imports(&[]);
        assert!(imports.contains("BaseHTTPMiddleware"));
        assert!(imports.contains("asyncio"));
        assert!(imports.contains("JSONResponse"));
    }
    
    #[test]
    fn generate_timeout_imports_skips_already_present() {
        use crate::parse::ast::{AstLocation, TextRange};
        use crate::semantics::python::model::{ImportCategory, ImportStyle};
        
        // Simulate asyncio already imported
        let existing_imports = vec![
            PyImport {
                module: "asyncio".to_string(),
                names: vec![],
                alias: None,
                style: ImportStyle::Import,
                category: ImportCategory::Stdlib,
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
        ];
        let imports = generate_timeout_imports(&existing_imports);
        assert!(!imports.contains("import asyncio"), "Should not include already imported asyncio");
        assert!(imports.contains("BaseHTTPMiddleware"), "Should still include BaseHTTPMiddleware");
    }

    #[test]
    fn generate_timeout_middleware_class_includes_class() {
        let code = generate_timeout_middleware_class();
        assert!(code.contains("class TimeoutMiddleware"));
        assert!(code.contains("asyncio.wait_for"));
        assert!(code.contains("asyncio.TimeoutError"));
    }

    #[test]
    fn generate_timeout_middleware_call_uses_correct_app_var() {
        let code = generate_timeout_middleware_call("my_app");
        assert!(code.contains("my_app.add_middleware"));
    }

    #[test]
    fn generate_timeout_middleware_call_has_default_timeout() {
        let code = generate_timeout_middleware_call("app");
        assert!(code.contains("timeout=30.0"));
    }

    // ==================== Patch Application Regression Tests ====================

    #[tokio::test]
    async fn patch_places_middleware_call_after_app_definition() {
        use crate::types::patch::apply_file_patch;
        
        let rule = FastApiRequestTimeoutRule::new();
        // Source code similar to what user reported
        let src = r#"from fastapi import FastAPI

app = FastAPI(title="RAG API with Issues")

@app.get("/")
def root():
    return {}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        
        let patch = findings[0].patch.as_ref().expect("should have patch");
        let patched = apply_file_patch(src, patch);
        
        // After the fix, the patched code should have:
        // 1. Imports at the top
        // 2. TimeoutMiddleware class definition BEFORE app = FastAPI(...)
        // 3. app.add_middleware(...) AFTER app = FastAPI(...)
        
        // Find the positions of key elements
        // Note: We look for the actual middleware call line, not the docstring example
        let app_def_pos = patched.find("app = FastAPI").expect("should have app definition");
        let add_middleware_pos = patched.find("\napp.add_middleware(TimeoutMiddleware").expect("should have add_middleware call (at start of line)");
        let class_def_pos = patched.find("class TimeoutMiddleware").expect("should have class definition");
        
        // Verify the order:
        // class definition comes BEFORE app definition
        assert!(
            class_def_pos < app_def_pos,
            "TimeoutMiddleware class should be defined BEFORE app = FastAPI(). \
             class_def at {}, app_def at {}",
            class_def_pos,
            app_def_pos
        );
        
        // add_middleware call comes AFTER app definition
        assert!(
            add_middleware_pos > app_def_pos,
            "app.add_middleware() should come AFTER app = FastAPI(). \
             add_middleware at {}, app_def at {}. This was the bug that was fixed.",
            add_middleware_pos,
            app_def_pos
        );
    }

    #[tokio::test]
    async fn patch_hunks_have_correct_line_numbers() {
        let rule = FastApiRequestTimeoutRule::new();
        // In this source:
        // Line 1: from fastapi import FastAPI
        // Line 2: (empty)
        // Line 3: app = FastAPI()
        let src = "from fastapi import FastAPI\n\napp = FastAPI()\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        
        let patch = findings[0].patch.as_ref().expect("should have patch");
        assert_eq!(patch.hunks.len(), 3);
        
        // Hunk 0: imports - should be inserted at top (line 1)
        match &patch.hunks[0].range {
            PatchRange::InsertBeforeLine { line } => {
                assert!(*line <= 2, "Import hunk should be near top of file, got line {}", line);
            }
            other => panic!("Expected InsertBeforeLine for imports, got {:?}", other),
        }
        
        // Hunk 1: middleware class - should be inserted BEFORE app definition (line 3)
        match &patch.hunks[1].range {
            PatchRange::InsertBeforeLine { line } => {
                assert_eq!(*line, 3, "Middleware class should be inserted before app definition at line 3");
            }
            other => panic!("Expected InsertBeforeLine for middleware class, got {:?}", other),
        }
        
        // Hunk 2: middleware call - should be inserted AFTER app definition (line 3)
        match &patch.hunks[2].range {
            PatchRange::InsertAfterLine { line } => {
                assert_eq!(*line, 3, "Middleware call should be inserted after app definition at line 3");
            }
            other => panic!("Expected InsertAfterLine for middleware call, got {:?}", other),
        }
    }
}