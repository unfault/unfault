//! Rule A7: Missing correlation ID middleware
//!
//! Detects FastAPI applications without correlation ID middleware, which is
//! essential for distributed tracing and debugging in production systems.
//!
//! # How correlation IDs work in production
//!
//! Correlation IDs should be handled at the **middleware** level, not per-handler:
//!
//! 1. Middleware extracts `X-Request-ID` from incoming request headers
//! 2. If not present, generates a new UUID
//! 3. Stores in `ContextVar` for cross-async-boundary propagation
//! 4. Adds to response headers
//! 5. Makes available to logging framework via structlog context
//!
//! This rule checks for proper middleware setup, not per-handler implementation.
//!
//! # Recommended Pattern: ObservabilityMiddleware
//!
//! The preferred pattern combines correlation ID handling with observability:
//!
//! ```python
//! from contextvars import ContextVar
//! from starlette.middleware.base import BaseHTTPMiddleware
//! import structlog
//! import uuid
//!
//! request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
//!
//! class ObservabilityMiddleware(BaseHTTPMiddleware):
//!     async def dispatch(self, request, call_next):
//!         request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:8]
//!         request_id_var.set(request_id)
//!         structlog.contextvars.bind_contextvars(request_id=request_id)
//!         try:
//!             response = await call_next(request)
//!             response.headers["X-Request-ID"] = request_id
//!             return response
//!         finally:
//!             structlog.contextvars.unbind_contextvars("request_id")
//!             request_id_var.set(None)
//!
//! def get_request_id() -> str | None:
//!     return request_id_var.get()
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::{ImportInsertionType, PyFileSemantics};
use crate::types::context::Dimension;
use crate::types::finding::{
    Benefit, DecisionLevel, FindingApplicability, FindingKind, InvestmentLevel, LifecycleStage,
    Severity,
};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects FastAPI apps without correlation ID middleware.
///
/// In distributed systems, correlation IDs (request IDs) are essential for
/// tracing requests across services. The correct approach is middleware-based,
/// not per-handler injection.
///
/// # What it checks
/// - FastAPI apps without correlation ID middleware
/// - Missing starlette-context or similar library usage
///
/// # What it suggests
/// - Adding correlation ID middleware to the FastAPI app
/// - The middleware pattern handles all requests automatically
#[derive(Debug)]
pub struct PythonMissingCorrelationIdRule;

impl PythonMissingCorrelationIdRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonMissingCorrelationIdRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a FastAPI app missing correlation ID middleware
#[derive(Debug, Clone)]
struct MissingCorrelationIdMiddleware {
    /// The FastAPI app variable name
    app_var_name: String,
    /// Start line number of the FastAPI app (1-based) - for finding location
    start_line: u32,
    /// End line number of the FastAPI app (1-based) - for inserting middleware after
    end_line: u32,
    /// Column number (1-based)
    column: u32,
}

/// Check if the file has correlation ID middleware configured
fn has_correlation_id_middleware(py: &PyFileSemantics) -> bool {
    // Check for starlette-context imports (third-party library for context propagation)
    let has_starlette_context = py.imports.iter().any(|imp| {
        imp.module.contains("starlette_context") || imp.module.contains("starlette-context")
    });
    
    if has_starlette_context {
        return true;
    }
    
    // Check for common correlation ID middleware patterns in function names
    let has_correlation_middleware = py.functions.iter().any(|f| {
        let name_lower = f.name.to_lowercase();
        name_lower.contains("correlation")
            || name_lower.contains("request_id")
            || name_lower.contains("trace_id")
            || name_lower.contains("get_request_id") // Helper function pattern
    });
    
    if has_correlation_middleware {
        return true;
    }
    
    // Check for ContextVar named "request_id" which is the proper pattern
    // This detects code like: request_id_var: ContextVar[str | None] = ContextVar("request_id", ...)
    let has_request_id_contextvar = py.imports.iter().any(|imp| {
        imp.module == "contextvars" && imp.names.iter().any(|n| n == "ContextVar")
    });
    
    // Check for middleware that mentions correlation/request ID/observability in calls
    if let Some(fastapi) = &py.fastapi {
        for middleware in &fastapi.middlewares {
            let mw_type_lower = middleware.middleware_type.to_lowercase();
            if mw_type_lower.contains("correlation")
                || mw_type_lower.contains("requestid")
                || mw_type_lower.contains("request_id")
                || mw_type_lower.contains("trace")
                || mw_type_lower.contains("observability") // ObservabilityMiddleware pattern
            {
                return true;
            }
        }
    }
    
    // Check for BaseHTTPMiddleware subclasses that handle correlation IDs
    for class in &py.classes {
        for base in &class.base_classes {
            if base.contains("BaseHTTPMiddleware") {
                let class_name_lower = class.name.to_lowercase();
                // Recognize various naming patterns for correlation ID middleware
                if class_name_lower.contains("correlation")
                    || class_name_lower.contains("request")
                    || class_name_lower.contains("trace")
                    || class_name_lower.contains("logging")
                    || class_name_lower.contains("observability") // ObservabilityMiddleware
                    || class_name_lower.contains("context")
                {
                    return true;
                }
                
                // If using ContextVar, this class likely handles request context
                if has_request_id_contextvar {
                    return true;
                }
            }
        }
    }
    
    false
}

#[async_trait]
impl Rule for PythonMissingCorrelationIdRule {
    fn id(&self) -> &'static str {
        "python.missing_correlation_id"
    }

    fn name(&self) -> &'static str {
        "Missing correlation ID middleware"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Medium,
            min_stage: LifecycleStage::Product,
            decision_level: DecisionLevel::ApiContract,
            benefits: vec![Benefit::Operability],
            prerequisites: vec![
                "Decide on header names and propagation rules across services".to_string(),
                "Ensure logs include the chosen correlation identifiers".to_string(),
            ],
            notes: Some(
                "Optional for demos; becomes valuable once multiple services or async workflows exist.".to_string(),
            ),
        })
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        // First pass: check if ANY file in the context has correlation ID middleware
        // This handles the case where middleware is defined in a separate file
        let context_has_middleware = semantics.iter().any(|(_, sem)| {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => return false,
            };
            has_correlation_id_middleware(py)
        });
        
        if context_has_middleware {
            return findings;
        }

        // Second pass: flag FastAPI apps that don't have correlation ID middleware
        for (file_id, sem) in semantics {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => continue,
            };

            // Check FastAPI apps
            if let Some(fastapi) = &py.fastapi {
                for app in &fastapi.apps {
                    let missing = MissingCorrelationIdMiddleware {
                        app_var_name: app.var_name.clone(),
                        start_line: app.location.range.start_line + 1,
                        end_line: app.location.range.end_line + 1,
                        column: app.location.range.start_col + 1,
                    };

                    let finding = create_finding(
                        self.id(),
                        &missing,
                        *file_id,
                        &py.path,
                        py,
                    );
                    findings.push(finding);
                }
            }
        }

        findings
    }
}

fn create_finding(
    rule_id: &str,
    missing: &MissingCorrelationIdMiddleware,
    file_id: FileId,
    file_path: &str,
    py: &PyFileSemantics,
) -> RuleFinding {
    let title = format!(
        "FastAPI app '{}' missing correlation ID middleware",
        missing.app_var_name
    );

    let description = format!(
        "The FastAPI application '{}' does not have correlation ID middleware configured. \
         Correlation IDs (X-Request-ID) are essential for distributed tracing. \
         Add ObservabilityMiddleware to extract/generate correlation IDs, \
         time requests, and integrate with structured logging.",
        missing.app_var_name
    );

    let patch = generate_middleware_patch(missing, file_id, py);

    let fix_preview = format!(
        "# Add ObservabilityMiddleware for correlation IDs and request tracing:\n\
         #\n\
         # from middleware import ObservabilityMiddleware\n\
         # {app}.add_middleware(ObservabilityMiddleware)\n\
         #\n\
         # See patch for full middleware implementation",
        app = missing.app_var_name
    );

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::AntiPattern,
        severity: Severity::Medium,
        confidence: 0.85,
        dimension: Dimension::Observability,
        file_id,
        file_path: file_path.to_string(),
        line: Some(missing.start_line),
        column: Some(missing.column),
        end_line: None,
        end_column: None,
            byte_range: None,
        patch: Some(patch),
        fix_preview: Some(fix_preview),
        tags: vec![
            "python".into(),
            "fastapi".into(),
            "observability".into(),
            "correlation-id".into(),
            "distributed-tracing".into(),
            "middleware".into(),
        ],
    }
}

fn generate_middleware_patch(
    missing: &MissingCorrelationIdMiddleware,
    file_id: FileId,
    py: &PyFileSemantics,
) -> FilePatch {
    let mut hunks = Vec::new();
    
    // Add standard library imports at the correct position
    let stdlib_from_line = py.import_insertion_line_for(ImportInsertionType::stdlib_import());
    
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: stdlib_from_line },
        replacement: "import time\nimport uuid\nfrom contextvars import ContextVar\n".to_string(),
    });
    
    // Add third-party imports
    let third_party_from_line = py.import_insertion_line_for(ImportInsertionType::third_party_from_import());
    
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: third_party_from_line },
        replacement: "import structlog\nfrom starlette.middleware.base import BaseHTTPMiddleware\nfrom starlette.requests import Request\nfrom starlette.responses import Response\n".to_string(),
    });
    
    // Add ObservabilityMiddleware implementation and registration after the app definition
    let middleware_code = format!(
        r#"

# Request ID context for cross-async-boundary propagation
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

def get_request_id() -> str | None:
    """Get the current request ID from context."""
    return request_id_var.get()

class ObservabilityMiddleware(BaseHTTPMiddleware):
    """Middleware for request timing, logging, and correlation ID propagation.
    
    Extracts X-Request-ID from headers or generates a new UUID, making it
    available via get_request_id() and automatically binding to structlog context.
    """
    
    async def dispatch(self, request: Request, call_next) -> Response:
        # Generate or extract request ID (short form for log readability)
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:8]
        request_id_var.set(request_id)
        
        # Bind to structlog context for all logs in this request
        structlog.contextvars.bind_contextvars(request_id=request_id)
        
        start_time = time.perf_counter()
        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            structlog.get_logger().info(
                "request_completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=round(duration_ms, 2),
            )
            
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            structlog.contextvars.unbind_contextvars("request_id")
            request_id_var.set(None)

{app}.add_middleware(ObservabilityMiddleware)
"#,
        app = missing.app_var_name,
    );
    
    hunks.push(PatchHunk {
        range: PatchRange::InsertAfterLine {
            line: missing.end_line,
        },
        replacement: middleware_code,
    });

    FilePatch {
        file_id,
        hunks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    // ==================== Helper Functions ====================

    fn parse_and_build_semantics_with_fastapi(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed).ok();
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonMissingCorrelationIdRule::new();
        assert_eq!(rule.id(), "python.missing_correlation_id");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonMissingCorrelationIdRule::new();
        assert!(rule.name().contains("correlation"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonMissingCorrelationIdRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonMissingCorrelationIdRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonMissingCorrelationIdRule::default();
        assert_eq!(rule.id(), "python.missing_correlation_id");
    }

    // ==================== evaluate Tests ====================

    #[tokio::test]
    async fn evaluate_detects_app_without_middleware() {
        let rule = PythonMissingCorrelationIdRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
async def get_users():
    return []
"#;
        let (file_id, sem) = parse_and_build_semantics_with_fastapi(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should detect app without correlation ID middleware
        assert!(!findings.is_empty(), "Should detect FastAPI app without correlation ID middleware");
        assert!(findings[0].title.contains("middleware"), "Finding should mention middleware");
    }

    #[tokio::test]
    async fn evaluate_ignores_app_with_starlette_context() {
        let rule = PythonMissingCorrelationIdRule::new();
        let src = r#"
from fastapi import FastAPI
from starlette_context import plugins
from starlette_context.middleware import RawContextMiddleware

app = FastAPI()

app.add_middleware(RawContextMiddleware, plugins=[plugins.RequestIdPlugin()])

@app.get("/users")
async def get_users():
    return []
"#;
        let (file_id, sem) = parse_and_build_semantics_with_fastapi(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag apps with starlette-context
        assert!(findings.is_empty(), "Should not flag app with starlette-context middleware");
    }

    #[tokio::test]
    async fn evaluate_ignores_app_with_custom_correlation_middleware() {
        let rule = PythonMissingCorrelationIdRule::new();
        let src = r#"
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware

class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        correlation_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = correlation_id
        return response

app = FastAPI()
app.add_middleware(CorrelationIdMiddleware)
"#;
        let (file_id, sem) = parse_and_build_semantics_with_fastapi(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag apps with custom correlation middleware
        assert!(findings.is_empty(), "Should not flag app with custom correlation middleware");
    }

    #[tokio::test]
    async fn evaluate_ignores_app_with_observability_middleware() {
        let rule = PythonMissingCorrelationIdRule::new();
        let src = r#"
import uuid
import time
from contextvars import ContextVar
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
import structlog

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

class ObservabilityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:8]
        request_id_var.set(request_id)
        structlog.contextvars.bind_contextvars(request_id=request_id)
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            structlog.contextvars.unbind_contextvars("request_id")
            request_id_var.set(None)

def get_request_id() -> str | None:
    return request_id_var.get()

app = FastAPI()
app.add_middleware(ObservabilityMiddleware)
"#;
        let (file_id, sem) = parse_and_build_semantics_with_fastapi(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag apps with ObservabilityMiddleware
        assert!(findings.is_empty(), "Should not flag app with ObservabilityMiddleware");
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn evaluate_handles_empty_semantics() {
        let rule = PythonMissingCorrelationIdRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_handles_non_fastapi_file() {
        let rule = PythonMissingCorrelationIdRule::new();
        let src = r#"
def regular_function():
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics_with_fastapi(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Finding Properties Tests ====================

    #[tokio::test]
    async fn evaluate_finding_has_correct_properties() {
        let rule = PythonMissingCorrelationIdRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/items")
async def create_item(data: dict):
    return data
"#;
        let (file_id, sem) = parse_and_build_semantics_with_fastapi(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert!(!findings.is_empty());
        let finding = &findings[0];
        assert_eq!(finding.rule_id, "python.missing_correlation_id");
        assert_eq!(finding.dimension, Dimension::Observability);
        assert!(finding.patch.is_some());
        assert!(finding.tags.contains(&"correlation-id".to_string()));
        assert!(finding.tags.contains(&"middleware".to_string()));
    }

    // ==================== Patch Application Tests ====================

    #[tokio::test]
    async fn patch_adds_middleware_to_app() {
        use crate::types::patch::apply_file_patch;
        
        let rule = PythonMissingCorrelationIdRule::new();
        let src = r#"from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
async def get_users():
    return []
"#;
        let (file_id, sem) = parse_and_build_semantics_with_fastapi(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty(), "Should detect app without correlation ID middleware");
        
        let patch = findings[0].patch.as_ref().expect("Should have a patch");
        let patched = apply_file_patch(src, patch);
        
        // Should contain the ObservabilityMiddleware class
        assert!(patched.contains("class ObservabilityMiddleware"),
            "Patched code should define ObservabilityMiddleware. Got:\n{}", patched);
        
        // Should contain the middleware registration
        assert!(patched.contains("add_middleware(ObservabilityMiddleware)"),
            "Patched code should add ObservabilityMiddleware. Got:\n{}", patched);
        
        // Should contain ContextVar for request ID
        assert!(patched.contains("request_id_var"),
            "Patched code should define request_id_var ContextVar. Got:\n{}", patched);
        
        // Should contain structlog integration
        assert!(patched.contains("structlog"),
            "Patched code should integrate with structlog. Got:\n{}", patched);
        
        // Should contain get_request_id helper
        assert!(patched.contains("def get_request_id"),
            "Patched code should define get_request_id helper. Got:\n{}", patched);
    }
    
    #[tokio::test]
    async fn patch_preserves_original_code() {
        use crate::types::patch::apply_file_patch;
        
        let rule = PythonMissingCorrelationIdRule::new();
        let src = r#"from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
async def get_users():
    return []
"#;
        let (file_id, sem) = parse_and_build_semantics_with_fastapi(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());
        
        let patch = findings[0].patch.as_ref().expect("Should have a patch");
        let patched = apply_file_patch(src, patch);
        
        // Should still contain the original code
        assert!(patched.contains("app = FastAPI()"),
            "Patched code should preserve FastAPI app. Got:\n{}", patched);
        assert!(patched.contains("async def get_users"),
            "Patched code should preserve handlers. Got:\n{}", patched);
        assert!(patched.contains("return []"),
            "Patched code should preserve handler body. Got:\n{}", patched);
    }

    #[tokio::test]
    async fn patch_uses_insert_after_line() {
        let rule = PythonMissingCorrelationIdRule::new();
        let src = r#"from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
async def get_users():
    return []
"#;
        let (file_id, sem) = parse_and_build_semantics_with_fastapi(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());
        
        let patch = findings[0].patch.as_ref().expect("Should have a patch");
        
        // Should have hunks that use InsertAfterLine for middleware placement
        let has_insert_after = patch.hunks.iter().any(|h| {
            matches!(h.range, crate::types::patch::PatchRange::InsertAfterLine { .. })
        });
        assert!(has_insert_after, "Patch should use InsertAfterLine for middleware placement");
    }

    #[tokio::test]
    async fn patch_works_with_multiline_fastapi_constructor() {
        use crate::types::patch::apply_file_patch;
        
        let rule = PythonMissingCorrelationIdRule::new();
        // Multi-line FastAPI() constructor - this is the case that was broken
        let src = r#"from fastapi import FastAPI

app = FastAPI(
    title="My API",
    version="1.0.0",
    openapi_url=None,
)

@app.get("/users")
async def get_users():
    return []
"#;
        let (file_id, sem) = parse_and_build_semantics_with_fastapi(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty(), "Should detect app without middleware");
        
        let patch = findings[0].patch.as_ref().expect("Should have a patch");
        let patched = apply_file_patch(src, patch);
        
        // The middleware should be added AFTER the closing ), not inside the constructor
        // Check that the FastAPI constructor is preserved intact
        assert!(patched.contains("app = FastAPI("),
            "Should preserve start of FastAPI constructor. Got:\n{}", patched);
        assert!(patched.contains("title=\"My API\""),
            "Should preserve FastAPI constructor arguments. Got:\n{}", patched);
        assert!(patched.contains("openapi_url=None,"),
            "Should preserve FastAPI constructor arguments. Got:\n{}", patched);
        
        // Check that middleware class is added (after the constructor, not inside)
        // The patched code should have the closing ) followed eventually by ObservabilityMiddleware
        let constructor_end = patched.find("openapi_url=None,").expect("Should have constructor arg");
        let middleware_start = patched.find("class ObservabilityMiddleware").expect("Should have middleware class");
        assert!(middleware_start > constructor_end,
            "Middleware should come after constructor arguments. Got:\n{}", patched);
        
        // Check the handler is still there
        assert!(patched.contains("@app.get(\"/users\")"),
            "Should preserve route handlers. Got:\n{}", patched);
        
        // Check middleware registration happens
        assert!(patched.contains("app.add_middleware(ObservabilityMiddleware)"),
            "Should add middleware to app. Got:\n{}", patched);
    }

    // ==================== Cross-File Context Tests ====================

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
                sem.analyze_frameworks(&parsed).ok();
                (file_id, Arc::new(SourceSemantics::Python(sem)))
            })
            .collect()
    }

    #[tokio::test]
    async fn evaluate_ignores_when_middleware_in_separate_file() {
        let rule = PythonMissingCorrelationIdRule::new();
        
        // Middleware configured in separate file
        let sources = vec![
            (
                "app/middleware.py",
                r#"
from starlette_context import plugins
from starlette_context.middleware import RawContextMiddleware

def configure_middleware(app):
    app.add_middleware(RawContextMiddleware, plugins=[plugins.RequestIdPlugin()])
"#,
            ),
            (
                "app/main.py",
                r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
async def get_users():
    return []
"#,
            ),
        ];
        let semantics = parse_multiple_files(&sources);

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag because middleware is configured in the context
        assert!(
            findings.is_empty(),
            "Should not flag when middleware is in separate file. Found: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}
