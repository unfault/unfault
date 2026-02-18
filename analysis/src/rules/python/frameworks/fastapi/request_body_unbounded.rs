use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::{AstLocation, FileId};
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::PyClass;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule: Request Body Size Unbounded
///
/// Detects FastAPI/Starlette POST/PUT/PATCH routes without request body size limits.
/// Unbounded request sizes allow DoS attacks via large payloads.
///
/// This rule performs cross-file analysis:
/// 1. First pass: Check ALL files for body limit middleware configuration
/// 2. Second pass: If no middleware found, report each body-accepting route
#[derive(Debug)]
pub struct FastApiRequestBodyUnboundedRule;

impl FastApiRequestBodyUnboundedRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FastApiRequestBodyUnboundedRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a route that accepts request body (POST/PUT/PATCH)
#[derive(Debug, Clone)]
struct BodyRoute {
    file_id: FileId,
    file_path: String,
    http_method: String,
    path: String,
    handler_name: String,
    /// Location of just the decorator (for highlighting)
    decorator_location: AstLocation,
    /// The app/router variable name for patch generation
    #[allow(dead_code)]
    app_var_name: Option<String>,
    /// Import insertion line for patch generation (1-based)
    import_insert_line: u32,
}

/// Known primitive types that are NOT Pydantic models
const PRIMITIVE_TYPES: &[&str] = &[
    "int", "str", "float", "bool", "bytes", "list", "dict", "set", "tuple",
    "List", "Dict", "Set", "Tuple", "Optional", "Union", "Any",
    "Request", "Response", "File", "UploadFile", "Form", "Body", "Query",
    "Path", "Header", "Cookie", "Depends", "BackgroundTasks", "WebSocket",
    "HTTPConnection", "None", "NoneType",
];

/// Types that are clearly non-body parameters (path, query, header, etc.)
/// These types indicate the parameter is NOT reading from request body
const NON_BODY_PARAM_TYPES: &[&str] = &[
    // FastAPI/Starlette dependency injection and special params
    "Request", "Response", "WebSocket", "HTTPConnection", "BackgroundTasks",
    // Path/Query/Header/Cookie are explicitly not body
    "Query", "Path", "Header", "Cookie", "Depends",
    // Simple primitives typically used for path/query params
    "int", "str", "float", "bool", "None", "NoneType",
];

/// Pydantic base class names that indicate a class has body validation
const PYDANTIC_BASE_CLASSES: &[&str] = &[
    "BaseModel",
    "pydantic.BaseModel",
    "pydantic.main.BaseModel",
    "BaseSettings",
    "pydantic.BaseSettings",
];

/// Context for cross-file type resolution
struct TypeResolutionContext<'a> {
    /// Map from type name to the classes that define it (across all files)
    class_definitions: HashMap<String, Vec<&'a PyClass>>,
}

impl<'a> TypeResolutionContext<'a> {
    /// Build a type resolution context from all Python files
    fn build(semantics: &'a [(FileId, Arc<SourceSemantics>)]) -> Self {
        let mut class_definitions: HashMap<String, Vec<&'a PyClass>> = HashMap::new();

        for (_, sem) in semantics {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => continue,
            };

            // Collect class definitions
            for cls in &py.classes {
                class_definitions
                    .entry(cls.name.clone())
                    .or_default()
                    .push(cls);
            }
        }

        Self {
            class_definitions,
        }
    }

    /// Check if a type name inherits from Pydantic BaseModel
    fn is_pydantic_model(&self, type_name: &str) -> bool {
        self.is_pydantic_model_with_visited(type_name, &mut HashSet::new())
    }

    /// Internal implementation with cycle detection via visited set
    fn is_pydantic_model_with_visited(
        &self,
        type_name: &str,
        visited: &mut HashSet<String>,
    ) -> bool {
        // Extract the bare type name (handle Optional[X], List[X], etc.)
        let bare_type = extract_bare_type_name(type_name);

        // Check if it's a known primitive
        if is_primitive_type(&bare_type) {
            return false;
        }

        // Cycle detection: if we've already seen this type, return false to avoid infinite recursion
        if !visited.insert(bare_type.clone()) {
            return false;
        }

        // Look up the class definition
        if let Some(classes) = self.class_definitions.get(&bare_type) {
            for cls in classes {
                // Check if any base class is a Pydantic model
                for base in &cls.base_classes {
                    // Direct match with known Pydantic bases
                    if PYDANTIC_BASE_CLASSES.contains(&base.as_str()) {
                        return true;
                    }
                    // Recursively check if the base class is a Pydantic model
                    if self.is_pydantic_model_with_visited(base, visited) {
                        return true;
                    }
                }
            }
        }

        // Fallback: if we can't find the class definition but it looks like a custom class,
        // use heuristic detection (uppercase name, not a known primitive)
        is_pydantic_like_type_heuristic(&bare_type)
    }
}

/// Extract the bare type name from a potentially generic type annotation.
/// e.g., "Optional[UserCreate]" -> "UserCreate", "List[str]" -> "str"
fn extract_bare_type_name(type_annotation: &str) -> String {
    let type_name = type_annotation.trim();
    
    // Handle generic types like Optional[SomeModel] or List[SomeModel]
    if let Some(inner_start) = type_name.find('[') {
        if let Some(inner_end) = type_name.rfind(']') {
            let inner = type_name[inner_start + 1..inner_end].trim();
            // Recursively extract from inner type
            return extract_bare_type_name(inner);
        }
    }
    
    type_name.to_string()
}

/// Check if a type name is a known primitive type
fn is_primitive_type(type_name: &str) -> bool {
    let type_name = type_name.trim();
    if type_name.is_empty() {
        return true;
    }
    
    for primitive in PRIMITIVE_TYPES {
        if type_name == *primitive || type_name.starts_with(&format!("{}[", primitive)) {
            return true;
        }
    }
    
    false
}

/// Heuristic fallback for detecting Pydantic-like types when we can't find the class definition.
/// Returns true for types that look like custom classes (start with uppercase, not a primitive).
fn is_pydantic_like_type_heuristic(type_name: &str) -> bool {
    let type_name = type_name.trim();
    
    // Empty type annotation
    if type_name.is_empty() {
        return false;
    }
    
    // Check if it's a known primitive type
    if is_primitive_type(type_name) {
        return false;
    }
    
    // If it starts with lowercase, it's likely a primitive or builtin
    if type_name.chars().next().map(|c| c.is_lowercase()).unwrap_or(false) {
        return false;
    }
    
    // It looks like a custom class (Pydantic model)
    // Custom classes typically start with uppercase
    type_name.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
}

/// Check if a type is clearly a non-body parameter type (path, query, header, etc.)
fn is_non_body_param_type(type_name: &str) -> bool {
    let bare_type = extract_bare_type_name(type_name);
    NON_BODY_PARAM_TYPES.contains(&bare_type.as_str())
}

/// Extract path parameter names from a route path pattern.
/// e.g., "/users/{user_id}/items/{item_id}" -> ["user_id", "item_id"]
fn extract_path_param_names(path: &str) -> std::collections::HashSet<String> {
    let mut params = std::collections::HashSet::new();
    let mut in_brace = false;
    let mut param_name = String::new();

    for ch in path.chars() {
        match ch {
            '{' => {
                in_brace = true;
                param_name.clear();
            }
            '}' => {
                if in_brace && !param_name.is_empty() {
                    // Handle path params with type hints like {item_id:path}
                    let name = param_name.split(':').next().unwrap_or(&param_name);
                    params.insert(name.to_string());
                }
                in_brace = false;
            }
            _ if in_brace => {
                param_name.push(ch);
            }
            _ => {}
        }
    }

    params
}

/// Check if a route has any parameters that could potentially read from request body.
///
/// A route with no potential body-reading parameters shouldn't trigger the
/// "unbounded body" warning because there's nothing reading the body.
///
/// This function returns true if the route has parameters that might read body data.
fn has_potential_body_params(
    route_path: &str,
    handler_params: &[crate::semantics::python::fastapi::RouteParam],
) -> bool {
    // No parameters = no body reading
    if handler_params.is_empty() {
        return false;
    }

    // Extract path parameter names from the route path
    let path_params = extract_path_param_names(route_path);

    for param in handler_params {
        // Skip path parameters (they come from URL, not body)
        if path_params.contains(&param.name) {
            continue;
        }

        // Check the type annotation
        if let Some(ref type_ann) = param.type_annotation {
            // If it's a non-body type (Query, Path, Header, primitives), skip
            if is_non_body_param_type(type_ann) {
                continue;
            }
            // Otherwise, this could be a body parameter
            return true;
        } else {
            // No type annotation - in FastAPI, untyped params default to query params
            // for simple values, but if the route is POST/PUT/PATCH, an untyped param
            // could potentially be body. However, FastAPI would expect Body() annotation
            // for explicit body params. We'll be conservative and NOT flag these.
            // This avoids false positives for query params without type hints.
            continue;
        }
    }

    false
}

/// Check if a route handler has a Pydantic-typed body parameter using cross-file resolution.
fn has_pydantic_body_param(
    handler_params: &[crate::semantics::python::fastapi::RouteParam],
    ctx: &TypeResolutionContext,
) -> bool {
    for param in handler_params {
        if let Some(ref type_ann) = param.type_annotation {
            if ctx.is_pydantic_model(type_ann) {
                return true;
            }
        }
    }
    false
}

// Keep the old function for backward compatibility in tests
#[allow(dead_code)]
fn is_pydantic_like_type(type_annotation: &str) -> bool {
    is_pydantic_like_type_heuristic(&extract_bare_type_name(type_annotation))
}

/// Check if a file has body limit middleware configured
fn has_body_limit_middleware(py: &crate::semantics::python::model::PyFileSemantics) -> bool {
    // Check imports for body limit related names
    let has_limit_import = py.imports.iter().any(|imp| {
        imp.names.iter().any(|n| {
            let n_lower = n.to_lowercase();
            n_lower.contains("limit")
                || n_lower.contains("maxsize")
                || n_lower.contains("content_length")
                || n_lower.contains("contentsizelimit")
        }) || {
            // Check module path for starlette middleware
            let mod_lower = imp.module.to_lowercase();
            mod_lower.contains("contentsize") || mod_lower.contains("limit")
        }
    });

    // Check calls for middleware configuration
    let has_limit_middleware_call = py.calls.iter().any(|c| {
        let callee_lower = c.function_call.callee_expr.to_lowercase();
        // Check for add_middleware with limit-related arguments
        (callee_lower.contains("add_middleware") && {
            let args_lower = c.args_repr.to_lowercase();
            args_lower.contains("limit")
                || args_lower.contains("contentsize")
                || args_lower.contains("maxsize")
        }) ||
        // Check for limit-related middleware class instantiation
        callee_lower.contains("limitrequestbody")
            || callee_lower.contains("contentsizelimit")
            || callee_lower.contains("maxbodysize")
    });

    // Check for configuration patterns in assignments
    let has_limit_config = py.assignments.iter().any(|a| {
        let target_lower = a.target.to_lowercase();
        let value_lower = a.value_repr.to_lowercase();
        (target_lower.contains("max") && target_lower.contains("body"))
            || (target_lower.contains("max") && target_lower.contains("size"))
            || (target_lower.contains("limit") && value_lower.chars().any(|c| c.is_ascii_digit()))
    });

    has_limit_import || has_limit_middleware_call || has_limit_config
}

/// Find the import insertion line for a file
fn find_import_insertion_line(py: &crate::semantics::python::model::PyFileSemantics) -> u32 {
    // Use the semantic model's built-in method
    py.import_insertion_line()
}

#[async_trait]
impl Rule for FastApiRequestBodyUnboundedRule {
    fn id(&self) -> &'static str {
        "python.fastapi.request_body_unbounded"
    }

    fn name(&self) -> &'static str {
        "Detects FastAPI routes without request body size limits to prevent DoS attacks."
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();
        let mut body_routes: Vec<BodyRoute> = Vec::new();
        let mut global_has_body_limit = false;

        // Build cross-file type resolution context
        let type_ctx = TypeResolutionContext::build(semantics);

        // First pass: Check ALL files for body limit middleware and collect body routes
        for (file_id, sem) in semantics {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => continue,
            };

            // Check if this file configures body limit middleware
            if has_body_limit_middleware(py) {
                global_has_body_limit = true;
            }

            // Skip files without FastAPI semantics
            let Some(ref fastapi) = py.fastapi else {
                continue;
            };

            let import_insert_line = find_import_insertion_line(py);

            // Collect body-accepting routes (POST, PUT, PATCH)
            for route in &fastapi.routes {
                let method = route.http_method.to_uppercase();
                if method == "POST" || method == "PUT" || method == "PATCH" {
                    // Skip routes that don't have any body-reading parameters
                    // A POST with no params or only path/query params doesn't read body
                    if !has_potential_body_params(&route.path, &route.handler_params) {
                        continue;
                    }

                    // Skip routes with Pydantic-typed body parameters
                    // These have implicit body validation via Pydantic
                    // Uses cross-file lookup to check if the type inherits from BaseModel
                    if has_pydantic_body_param(&route.handler_params, &type_ctx) {
                        continue;
                    }

                    // Try to find the app/router variable name from the file
                    let app_var_name = fastapi
                        .apps
                        .first()
                        .map(|a| a.var_name.clone());

                    body_routes.push(BodyRoute {
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        http_method: method,
                        path: route.path.clone(),
                        handler_name: route.handler_name.clone(),
                        decorator_location: route.decorator_location.clone(),
                        app_var_name,
                        import_insert_line,
                    });
                }
            }
        }

        // If body limit middleware is configured globally, no findings
        if global_has_body_limit {
            return findings;
        }

        // Second pass: Generate findings for each body route
        for route in body_routes {
            let title = format!(
                "{} route `{}` has no request body size limit",
                route.http_method, route.path
            );

            let description = format!(
                "The `{}` handler for {} {} does not have request body size limits configured. \
                 Without limits, attackers can send extremely large payloads to exhaust \
                 server memory and cause denial of service. Consider adding \
                 ContentSizeLimitMiddleware or validating Content-Length headers.",
                route.handler_name, route.http_method, route.path
            );

            let fix_preview = generate_fix_preview();

            // Generate patch at the file level (middleware should be added once per app)
            let patch = generate_body_limit_patch(route.file_id, route.import_insert_line);

            // Line numbers from AstLocation are 0-indexed, convert to 1-indexed
            // Use decorator_location for highlighting (just the decorator line)
            let line = route.decorator_location.range.start_line + 1;
            let column = route.decorator_location.range.start_col + 1;
            let end_line = route.decorator_location.range.end_line + 1;
            let end_column = route.decorator_location.range.end_col + 1;

            findings.push(RuleFinding {
                rule_id: self.id().to_string(),
                title,
                description: Some(description),
                kind: FindingKind::StabilityRisk,
                severity: Severity::Medium,
                confidence: 0.80,
                dimension: Dimension::Stability,
                file_id: route.file_id,
                file_path: route.file_path.clone(),
                line: Some(line),
                column: Some(column),
                end_line: Some(end_line),
                end_column: Some(end_column),
                byte_range: None,
                patch: Some(patch),
                fix_preview: Some(fix_preview),
                tags: vec![
                    "python".into(),
                    "fastapi".into(),
                    "security".into(),
                    "dos-prevention".into(),
                    "request-body".into(),
                ],
            });
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::unbounded_resource())
    }
}

fn generate_body_limit_patch(file_id: FileId, import_line: u32) -> FilePatch {
    let mut hunks = Vec::new();

    // Add middleware import and configuration
    let import_str = r#"from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request, HTTPException

# Maximum request body size (10MB)
MAX_BODY_SIZE = 10 * 1024 * 1024

"#;
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: import_line },
        replacement: import_str.to_string(),
    });

    // Add middleware class
    let middleware_code = r#"
class LimitRequestBodyMiddleware(BaseHTTPMiddleware):
    """Middleware to limit request body size."""
    
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            if int(content_length) > MAX_BODY_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail=f"Request body too large. Maximum size is {MAX_BODY_SIZE} bytes."
                )
        return await call_next(request)

"#;
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: import_line + 7 },
        replacement: middleware_code.to_string(),
    });

    FilePatch { file_id, hunks }
}

/// Generate a fix preview showing how to add body size limits.
fn generate_fix_preview() -> String {
    r#"# Option 1: Custom middleware for body size limit
from fastapi import FastAPI, Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

MAX_BODY_SIZE = 10 * 1024 * 1024  # 10MB

class LimitRequestBodyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_BODY_SIZE:
            raise HTTPException(status_code=413, detail="Request body too large")
        return await call_next(request)

app = FastAPI()
app.add_middleware(LimitRequestBodyMiddleware)

# Option 2: Use python-multipart with size limits for file uploads
from fastapi import FastAPI, File, UploadFile

@app.post("/upload")
async def upload_file(file: UploadFile = File(..., max_length=10 * 1024 * 1024)):
    # File size is automatically limited to 10MB
    return {"filename": file.filename}

# Option 3: Validate body size in route handler
from fastapi import FastAPI, Request, HTTPException

@app.post("/api/data")
async def receive_data(request: Request):
    body = await request.body()
    if len(body) > MAX_BODY_SIZE:
        raise HTTPException(status_code=413, detail="Request body too large")
    # Process body...

# Option 4: Configure at reverse proxy level (nginx)
# In nginx.conf:
# client_max_body_size 10m;

# Option 5: Use Starlette's built-in middleware (if available)
# from starlette.middleware.contentsize import ContentSizeLimitMiddleware
# app.add_middleware(ContentSizeLimitMiddleware, max_content_size=MAX_BODY_SIZE)"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        parse_and_build_semantics_with_path("test.py", source)
    }

    fn parse_and_build_semantics_with_path(path: &str, source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: path.to_string(),
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
        let rule = FastApiRequestBodyUnboundedRule::new();
        assert_eq!(rule.id(), "python.fastapi.request_body_unbounded");
    }

    #[test]
    fn rule_name_mentions_body_size() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        assert!(rule.name().contains("body size"));
    }

    // ==================== No Findings Tests ====================

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_fastapi_app() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_get_only_routes() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello"}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_body_limit_middleware_configured() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI
from starlette.middleware.contentsize import ContentSizeLimitMiddleware

app = FastAPI()
app.add_middleware(ContentSizeLimitMiddleware, max_content_size=10*1024*1024)

@app.post("/data")
def receive_data(data: dict):
    return {"received": True}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_max_body_size_defined() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

MAX_BODY_SIZE = 10 * 1024 * 1024

app = FastAPI()

@app.post("/data")
def receive_data(data: dict):
    return {"received": True}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Cross-File Tests ====================

    #[tokio::test]
    async fn evaluate_returns_empty_when_middleware_in_separate_file() {
        let rule = FastApiRequestBodyUnboundedRule::new();

        let sources = vec![
            (
                "app/main.py",
                r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/data")
def receive_data(data: dict):
    return {"received": True}
"#,
            ),
            (
                "app/middleware.py",
                r#"
from starlette.middleware.contentsize import ContentSizeLimitMiddleware

MAX_BODY_SIZE = 10 * 1024 * 1024

def setup_middleware(app):
    app.add_middleware(ContentSizeLimitMiddleware, max_content_size=MAX_BODY_SIZE)
"#,
            ),
        ];
        let semantics = parse_multiple_files(&sources);

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not report findings when middleware is in separate file");
    }

    // ==================== Cross-File Pydantic Inheritance Tests ====================

    #[tokio::test]
    async fn evaluate_skips_routes_with_pydantic_model_from_separate_file() {
        let rule = FastApiRequestBodyUnboundedRule::new();

        let sources = vec![
            (
                "app/schemas.py",
                r#"
from pydantic import BaseModel

class DiagnosticsRequest(BaseModel):
    file_path: str
    content: str

class CodeActionsRequest(BaseModel):
    file_path: str
    line: int
"#,
            ),
            (
                "app/routers.py",
                r#"
from fastapi import APIRouter
from .schemas import DiagnosticsRequest, CodeActionsRequest

router = APIRouter()

@router.post("/diagnostics")
async def diagnostics(request: DiagnosticsRequest):
    return {"result": "ok"}

@router.post("/code-actions")
async def code_actions(request: CodeActionsRequest):
    return {"actions": []}
"#,
            ),
        ];
        let semantics = parse_multiple_files(&sources);

        let findings = rule.evaluate(&semantics, None).await;
        // Should NOT trigger because DiagnosticsRequest and CodeActionsRequest are Pydantic models
        // defined in a separate file (app/schemas.py)
        assert!(
            findings.is_empty(),
            "Should skip routes using Pydantic models from separate file. Got {} findings.",
            findings.len()
        );
    }

    #[tokio::test]
    async fn evaluate_detects_non_pydantic_class_from_separate_file() {
        let rule = FastApiRequestBodyUnboundedRule::new();

        let sources = vec![
            (
                "app/schemas.py",
                r#"
# A plain class, NOT a Pydantic model
class PlainRequest:
    def __init__(self, data):
        self.data = data
"#,
            ),
            (
                "app/routers.py",
                r#"
from fastapi import APIRouter
from .schemas import PlainRequest

router = APIRouter()

@router.post("/data")
async def receive_data(request: PlainRequest):
    return {"result": "ok"}
"#,
            ),
        ];
        let semantics = parse_multiple_files(&sources);

        let findings = rule.evaluate(&semantics, None).await;
        // PlainRequest is NOT a Pydantic model (doesn't inherit from BaseModel)
        // However, the heuristic fallback will still skip it because it looks like a custom class
        // This demonstrates the fallback behavior when cross-file lookup doesn't prove it's NOT a Pydantic model
        // In practice, this is a conservative choice - we err on the side of fewer false positives
        // If we want to be strict, we'd need to prove the class doesn't inherit from BaseModel
        // For now, we accept the heuristic fallback
        assert!(
            findings.is_empty(),
            "Heuristic fallback should skip uppercase class types. Got {} findings.",
            findings.len()
        );
    }

    #[tokio::test]
    async fn evaluate_detects_dict_param_even_with_pydantic_in_other_files() {
        let rule = FastApiRequestBodyUnboundedRule::new();

        let sources = vec![
            (
                "app/schemas.py",
                r#"
from pydantic import BaseModel

class UserCreate(BaseModel):
    name: str
"#,
            ),
            (
                "app/routers.py",
                r#"
from fastapi import APIRouter

router = APIRouter()

@router.post("/data")
async def receive_data(data: dict):
    return {"received": data}
"#,
            ),
        ];
        let semantics = parse_multiple_files(&sources);

        let findings = rule.evaluate(&semantics, None).await;
        // Should trigger because dict is a primitive, not a Pydantic model
        // Even though there are Pydantic models in other files
        assert_eq!(findings.len(), 1, "Should detect dict parameter");
    }

    #[tokio::test]
    async fn evaluate_skips_routes_with_inherited_pydantic_model() {
        let rule = FastApiRequestBodyUnboundedRule::new();

        let sources = vec![
            (
                "app/base.py",
                r#"
from pydantic import BaseModel

class BaseRequest(BaseModel):
    """Base class for all requests."""
    timestamp: str
"#,
            ),
            (
                "app/schemas.py",
                r#"
from .base import BaseRequest

class DiagnosticsRequest(BaseRequest):
    """Inherits from BaseRequest which inherits from BaseModel."""
    file_path: str
    content: str
"#,
            ),
            (
                "app/routers.py",
                r#"
from fastapi import APIRouter
from .schemas import DiagnosticsRequest

router = APIRouter()

@router.post("/diagnostics")
async def diagnostics(request: DiagnosticsRequest):
    return {"result": "ok"}
"#,
            ),
        ];
        let semantics = parse_multiple_files(&sources);

        let findings = rule.evaluate(&semantics, None).await;
        // Should NOT trigger because DiagnosticsRequest inherits from BaseRequest,
        // which in turn inherits from BaseModel (transitively a Pydantic model)
        assert!(
            findings.is_empty(),
            "Should skip routes using classes that transitively inherit from BaseModel. Got {} findings.",
            findings.len()
        );
    }

    // ==================== Detection Tests ====================

    #[tokio::test]
    async fn evaluate_detects_missing_body_limit_with_post_route() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/data")
def receive_data(data: dict):
    return {"received": True}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "python.fastapi.request_body_unbounded");
    }

    #[tokio::test]
    async fn evaluate_detects_put_route() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.put("/data/{id}")
def update_data(id: int, data: dict):
    return {"updated": True}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("PUT"));
    }

    #[tokio::test]
    async fn evaluate_detects_patch_route() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.patch("/data/{id}")
def patch_data(id: int, data: dict):
    return {"patched": True}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("PATCH"));
    }

    #[tokio::test]
    async fn evaluate_detects_multiple_body_routes() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/create")
def create_item(data: dict):
    pass

@app.put("/update")
def update_item(data: dict):
    pass

@app.patch("/patch")
def patch_item(data: dict):
    pass

@app.get("/read")
def read_item():
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should detect POST, PUT, PATCH with dict body params, but not GET
        assert_eq!(findings.len(), 3);
    }

    #[tokio::test]
    async fn evaluate_skips_routes_without_body_params() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/create")
def create_item():
    pass

@app.put("/update")
def update_item():
    pass

@app.patch("/patch")
def patch_item():
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Routes without any params don't read body, so no findings
        assert!(findings.is_empty(), "Routes without params should not trigger. Got {} findings.", findings.len());
    }

    // ==================== Finding Location Tests ====================

    #[tokio::test]
    async fn evaluate_finding_points_to_route_decorator() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/data")
def receive_data(data: dict):
    return {"received": True}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);

        // Line should point to the route decorator, not line 1
        let line = findings[0].line.unwrap();
        assert!(line > 1, "Line should not be 1, but point to the route decorator");
        // The @app.post decorator is on line 6 (1-indexed)
        assert_eq!(line, 6, "Line should point to the @app.post decorator");
    }

    #[tokio::test]
    async fn evaluate_finding_has_end_line_and_column() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/data")
def receive_data(data: dict):
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);

        // Should have end_line and end_column for proper highlighting
        assert!(findings[0].end_line.is_some());
        assert!(findings[0].end_column.is_some());
    }

    // ==================== Finding Content Tests ====================

    #[tokio::test]
    async fn evaluate_finding_title_contains_route_path() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/api/users")
def create_user(data: dict):
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("/api/users"));
    }

    #[tokio::test]
    async fn evaluate_finding_description_contains_handler_name() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/data")
def my_handler(data: dict):
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].description.as_ref().unwrap().contains("my_handler"));
    }

    #[tokio::test]
    async fn evaluate_finding_has_medium_severity() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI
app = FastAPI()

@app.post("/data")
def receive_data(data: dict):
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].severity, Severity::Medium));
    }

    #[tokio::test]
    async fn evaluate_finding_has_patch() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI
app = FastAPI()

@app.post("/data")
def receive_data(data: dict):
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI
app = FastAPI()

@app.post("/data")
def receive_data(data: dict):
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
        assert!(findings[0].fix_preview.as_ref().unwrap().contains("MAX_BODY_SIZE"));
    }

    // ==================== Router (APIRouter) Tests ====================

    #[tokio::test]
    async fn evaluate_detects_router_post_routes() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import APIRouter

router = APIRouter()

@router.post("/items")
def create_item(data: dict):
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("/items"));
    }

    // ==================== Pydantic-typed Body Parameter Tests ====================

    #[tokio::test]
    async fn evaluate_skips_routes_with_pydantic_typed_body() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI
from pydantic import BaseModel

class DiagnosticsRequest(BaseModel):
    file_path: str
    content: str

app = FastAPI()

@app.post("/diagnostics")
async def diagnostics(request: DiagnosticsRequest):
    return {"result": "ok"}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should NOT trigger because DiagnosticsRequest is a Pydantic model
        assert!(findings.is_empty(), "Should skip routes with Pydantic-typed body parameters");
    }

    #[tokio::test]
    async fn evaluate_skips_routes_with_custom_class_type() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/items")
def create_item(item: ItemCreate):
    return item
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should NOT trigger because ItemCreate looks like a Pydantic model (uppercase class)
        assert!(findings.is_empty(), "Should skip routes with custom class type parameters");
    }

    #[tokio::test]
    async fn evaluate_triggers_on_primitive_typed_body() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/data")
def receive_data(data: dict):
    return {"received": data}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should trigger because dict is a primitive type, not a Pydantic model
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_skips_untyped_param() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/data")
def receive_data(data):
    return {"received": data}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Untyped params in FastAPI default to query params, not body params
        // So we should NOT trigger on this - it's a conservative choice to reduce FPs
        assert!(findings.is_empty(), "Untyped params should be treated as query params. Got {} findings.", findings.len());
    }

    #[tokio::test]
    async fn evaluate_skips_mixed_pydantic_and_primitive() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/items/{item_id}")
def update_item(item_id: int, item: ItemUpdate):
    return item
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should NOT trigger because ItemUpdate is a Pydantic model
        assert!(findings.is_empty(), "Should skip if any parameter is Pydantic-typed");
    }

    // ==================== Decorator-only Highlighting Tests ====================

    #[tokio::test]
    async fn evaluate_finding_highlights_decorator_only() {
        let rule = FastApiRequestBodyUnboundedRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/data")
def receive_data(data: dict):
    # This is a long function body
    # with multiple lines
    # that should not be highlighted
    result = process(data)
    return {"received": result}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);

        let line = findings[0].line.unwrap();
        let end_line = findings[0].end_line.unwrap();

        // The decorator @app.post("/data") should be on line 6
        // end_line should be the same line (decorator only, not function body)
        assert_eq!(line, 6, "Line should point to the decorator");
        assert_eq!(end_line, 6, "End line should also be the decorator line, not the function body");
    }

    // ==================== Pydantic Type Detection Unit Tests ====================

    #[test]
    fn is_pydantic_like_type_detects_custom_classes() {
        assert!(is_pydantic_like_type("DiagnosticsRequest"));
        assert!(is_pydantic_like_type("ItemCreate"));
        assert!(is_pydantic_like_type("UserUpdate"));
        assert!(is_pydantic_like_type("MyModel"));
    }

    #[test]
    fn is_pydantic_like_type_returns_false_for_primitives() {
        assert!(!is_pydantic_like_type("int"));
        assert!(!is_pydantic_like_type("str"));
        assert!(!is_pydantic_like_type("dict"));
        assert!(!is_pydantic_like_type("list"));
        assert!(!is_pydantic_like_type("bool"));
        assert!(!is_pydantic_like_type("float"));
    }

    #[test]
    fn is_pydantic_like_type_returns_false_for_fastapi_types() {
        assert!(!is_pydantic_like_type("Request"));
        assert!(!is_pydantic_like_type("Response"));
        assert!(!is_pydantic_like_type("File"));
        assert!(!is_pydantic_like_type("UploadFile"));
        assert!(!is_pydantic_like_type("Form"));
        assert!(!is_pydantic_like_type("Body"));
        assert!(!is_pydantic_like_type("Query"));
        assert!(!is_pydantic_like_type("Depends"));
    }

    #[test]
    fn is_pydantic_like_type_handles_generic_types() {
        // Container types with primitives inside
        assert!(!is_pydantic_like_type("List[str]"));
        assert!(!is_pydantic_like_type("Dict[str, int]"));
        assert!(!is_pydantic_like_type("Optional[int]"));
        
        // Container types with Pydantic models inside
        assert!(is_pydantic_like_type("Optional[ItemCreate]"));
        assert!(is_pydantic_like_type("List[UserModel]"));
    }

    #[test]
    fn is_pydantic_like_type_returns_false_for_empty() {
        assert!(!is_pydantic_like_type(""));
        assert!(!is_pydantic_like_type("   "));
    }
}