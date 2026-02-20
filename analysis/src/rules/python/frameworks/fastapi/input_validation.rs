//! Rule B8: Missing input validation
//!
//! Detects FastAPI endpoints that accept request body parameters without
//! using Pydantic models for validation, which can lead to crashes and
//! downstream type errors.

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

/// Rule that detects FastAPI endpoints without proper input validation.
///
/// # What it detects
/// - POST/PUT/PATCH endpoints using `dict` type hints instead of Pydantic models
/// - Endpoints with untyped request body parameters
/// - Endpoints using `Any` type for request bodies
///
/// # Why it matters
/// Without Pydantic validation, invalid input can cause:
/// - Runtime crashes from unexpected data types
/// - Security vulnerabilities from unvalidated input
/// - Inconsistent error responses
///
/// # Fix
/// Use Pydantic models for request body validation:
/// ```python
/// from pydantic import BaseModel
///
/// class ItemCreate(BaseModel):
///     name: str
///     price: float
///
/// @app.post("/items")
/// async def create_item(item: ItemCreate):
///     return item
/// ```
#[derive(Debug, Default)]
pub struct FastApiInputValidationRule;

impl FastApiInputValidationRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for FastApiInputValidationRule {
    fn id(&self) -> &'static str {
        "python.fastapi.missing_input_validation"
    }

    fn name(&self) -> &'static str {
        "Missing input validation in FastAPI endpoint"
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

            // Check if this file has FastAPI routes
            let fastapi = match &py.fastapi {
                Some(f) => f,
                None => continue,
            };

            // Check POST, PUT, PATCH routes for proper input validation
            for route in &fastapi.routes {
                // Only check routes that typically accept request bodies
                let needs_body = matches!(route.http_method.as_str(), "POST" | "PUT" | "PATCH");

                if !needs_body {
                    continue;
                }

                // Look for the function in the semantics to check its parameters
                let func = match py.functions.iter().find(|f| f.name == route.handler_name) {
                    Some(f) => f,
                    None => continue, // Can't validate without function info
                };

                // Check if there's a body parameter with a bad type annotation.
                // We look for parameters that:
                // 1. Have no type annotation (untyped) - excluding common non-body params
                // 2. Are typed as 'dict' or 'Dict'
                // 3. Are typed as 'Any'
                //
                // Parameters with FastAPI special types (Path, Query, Depends, etc.) are not body params.
                // Parameters with Pydantic model-like types (capitalized names) are properly validated.

                let bad_body_param = func.params.iter().find(|param| {
                    // Skip common non-body parameters
                    let name = param.name.as_str();
                    if name == "self" || name == "cls" || name == "request" {
                        return false;
                    }

                    match &param.type_annotation {
                        None => {
                            // Untyped parameter - could be a body parameter
                            // Skip if the name suggests it's not a body (e.g., path params often have specific names)
                            // This is heuristic - params with defaults using Depends/Path/Query are OK
                            if let Some(default) = &param.default {
                                // If default uses Depends, Path, Query, Header, Cookie, etc. it's not a body
                                if default.contains("Depends(")
                                    || default.contains("Path(")
                                    || default.contains("Query(")
                                    || default.contains("Header(")
                                    || default.contains("Cookie(")
                                    || default.contains("Form(")
                                    || default.contains("File(")
                                    || default.contains("Body(")
                                {
                                    return false;
                                }
                            }
                            true // Untyped without special default - flag it
                        }
                        Some(type_ann) => {
                            // Check if it's a bad type
                            let type_str = type_ann.trim();
                            is_bad_body_type(type_str)
                        }
                    }
                });

                // Only create a finding if we found a problematic body parameter
                let bad_param = match bad_body_param {
                    Some(p) => p,
                    None => continue, // All body params are properly typed
                };

                let line = route.location.range.start_line + 1;

                // Generate a patch suggesting Pydantic model usage
                let patch = generate_pydantic_suggestion_patch(
                    *file_id,
                    &route.handler_name,
                    &route.http_method,
                    &route.path,
                    line,
                );

                let type_info = match &bad_param.type_annotation {
                    Some(t) => format!("typed as '{}'", t),
                    None => "untyped".to_string(),
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!(
                        "{} endpoint '{}' has {} body parameter '{}' - use Pydantic model for validation",
                        route.http_method, route.path, type_info, bad_param.name
                    ),
                    description: Some(format!(
                        "The {} endpoint at '{}' (handler: {}) has parameter '{}' which is {}. \
                        Using a Pydantic model for request body validation ensures proper input \
                        validation, automatic documentation, and clear error messages.",
                        route.http_method, route.path, route.handler_name, bad_param.name, type_info
                    )),
                    kind: FindingKind::AntiPattern,
                    severity: Severity::Medium,
                    confidence: 0.85, // Higher confidence since we actually checked the type
                    dimension: Dimension::Correctness,
                    file_id: *file_id,
                    file_path: py.path.clone(),
                    line: Some(line),
                    column: Some(route.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(format!(
                        "# Define a Pydantic model for the request body:\n\
                         from pydantic import BaseModel\n\n\
                         class {}Request(BaseModel):\n    \
                         # Add your fields here\n    \
                         pass\n\n\
                         @app.{}(\"{}\")\n\
                         async def {}(data: {}Request):\n    \
                         ...",
                        capitalize_first(&route.handler_name),
                        route.http_method.to_lowercase(),
                        route.path,
                        route.handler_name,
                        capitalize_first(&route.handler_name)
                    )),
                    tags: vec!["validation".to_string(), "pydantic".to_string(), "fastapi".to_string()],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::runtime_config())
    }
}

/// Generate a patch suggesting Pydantic model usage.
fn generate_pydantic_suggestion_patch(
    file_id: FileId,
    handler_name: &str,
    http_method: &str,
    path: &str,
    line: u32,
) -> FilePatch {
    let model_name = format!("{}Request", capitalize_first(handler_name));

    let suggestion = format!(
        "# TODO: Define a Pydantic model for request validation:\n\
         # from pydantic import BaseModel\n\
         #\n\
         # class {}(BaseModel):\n\
         #     # Define your request fields here\n\
         #     field_name: str\n\
         #\n\
         # Then update the {} {} endpoint to use it:\n\
         # async def {}(data: {}):\n\
         #     ...\n",
        model_name, http_method, path, handler_name, model_name
    );

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement: suggestion,
        }],
    }
}

/// Check if a type annotation represents a "bad" body type that should be flagged.
///
/// Bad types are:
/// - `dict` or `Dict` (raw dict without Pydantic)
/// - `Any` (completely untyped)
///
/// Good types (not flagged):
/// - Pydantic models (typically PascalCase names)
/// - `list`, `List` (could be typed further but not as risky as dict)
/// - Any other type annotation (assumed to be a model or valid type)
fn is_bad_body_type(type_str: &str) -> bool {
    // Normalize the type string
    let normalized = type_str.trim();

    // Check for dict variants
    if normalized == "dict"
        || normalized == "Dict"
        || normalized.starts_with("dict[")
        || normalized.starts_with("Dict[")
        || normalized.starts_with("dict [")
        || normalized.starts_with("Dict [")
    {
        return true;
    }

    // Check for Any
    if normalized == "Any" || normalized == "typing.Any" {
        return true;
    }

    // All other types are considered OK (Pydantic models, custom types, etc.)
    false
}

/// Capitalize the first letter of a string.
fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    /// Helper to parse Python source and build semantics
    fn parse_and_analyze(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let parsed = parse_python_file(FileId(1), &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed).unwrap();
        (FileId(1), Arc::new(SourceSemantics::Python(sem)))
    }

    // ==================== Positive Tests (Should Detect) ====================

    #[tokio::test]
    async fn detects_post_endpoint() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/items")
async def create_item(item: dict):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect POST endpoint");
        assert!(findings[0].title.contains("POST"));
    }

    #[tokio::test]
    async fn detects_put_endpoint() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.put("/items/{item_id}")
async def update_item(item_id: int, item: dict):
    return {"id": item_id, **item}
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect PUT endpoint");
        assert!(findings[0].title.contains("PUT"));
    }

    #[tokio::test]
    async fn detects_patch_endpoint() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.patch("/items/{item_id}")
async def partial_update(item_id: int, updates: dict):
    return {"id": item_id, **updates}
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect PATCH endpoint");
        assert!(findings[0].title.contains("PATCH"));
    }

    #[tokio::test]
    async fn detects_multiple_endpoints() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/items")
async def create_item(item: dict):
    return item

@app.put("/items/{item_id}")
async def update_item(item_id: int, item: dict):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert_eq!(
            findings.len(),
            2,
            "Should detect both POST and PUT endpoints"
        );
    }

    // ==================== Negative Tests (Should Not Detect) ====================

    #[tokio::test]
    async fn ignores_get_endpoint() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/items")
async def get_items():
    return []
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(findings.is_empty(), "Should not flag GET endpoints");
    }

    #[tokio::test]
    async fn ignores_delete_endpoint() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.delete("/items/{item_id}")
async def delete_item(item_id: int):
    return {"deleted": item_id}
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(findings.is_empty(), "Should not flag DELETE endpoints");
    }

    #[tokio::test]
    async fn ignores_non_fastapi_file() {
        let src = r#"
def create_item(item: dict):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(findings.is_empty(), "Should not flag non-FastAPI files");
    }

    #[tokio::test]
    async fn ignores_empty_file() {
        let src = "";
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(findings.is_empty(), "Should not flag empty files");
    }

    #[tokio::test]
    async fn ignores_endpoint_with_pydantic_model() {
        let src = r#"
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class ItemCreate(BaseModel):
    name: str
    price: float

@app.post("/items")
async def create_item(item: ItemCreate):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(
            findings.is_empty(),
            "Should not flag endpoints with Pydantic models"
        );
    }

    #[tokio::test]
    async fn ignores_endpoint_with_custom_type() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/items")
async def create_item(item: SessionRunRequest):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(
            findings.is_empty(),
            "Should not flag endpoints with custom model types"
        );
    }

    #[tokio::test]
    async fn ignores_endpoint_with_depends() {
        let src = r#"
from fastapi import FastAPI, Depends

app = FastAPI()

@app.post("/items")
async def create_item(user = Depends(get_user)):
    return {"user": user}
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(
            findings.is_empty(),
            "Should not flag endpoints using Depends"
        );
    }

    #[tokio::test]
    async fn detects_dict_type_variations() {
        // Test various dict type spellings
        let src = r#"
from fastapi import FastAPI
from typing import Dict

app = FastAPI()

@app.post("/items1")
async def create1(item: Dict):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect Dict type");
    }

    #[tokio::test]
    async fn detects_any_type() {
        let src = r#"
from fastapi import FastAPI
from typing import Any

app = FastAPI()

@app.post("/items")
async def create_item(item: Any):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect Any type");
    }

    // ==================== Patch Tests ====================

    #[tokio::test]
    async fn generates_patch_with_pydantic_suggestion() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/items")
async def create_item(item: dict):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty());
        assert!(findings[0].patch.is_some(), "Should generate a patch");

        let patch = findings[0].patch.as_ref().unwrap();
        assert!(!patch.hunks.is_empty());
        assert!(patch.hunks[0].replacement.contains("Pydantic"));
    }

    #[tokio::test]
    async fn fix_preview_contains_model_example() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/items")
async def create_item(item: dict):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty());
        assert!(findings[0].fix_preview.is_some());

        let preview = findings[0].fix_preview.as_ref().unwrap();
        assert!(preview.contains("BaseModel"));
        assert!(preview.contains("class"));
    }

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_has_correct_id() {
        let rule = FastApiInputValidationRule::new();
        assert_eq!(rule.id(), "python.fastapi.missing_input_validation");
    }

    #[test]
    fn rule_has_correct_name() {
        let rule = FastApiInputValidationRule::new();
        assert_eq!(rule.name(), "Missing input validation in FastAPI endpoint");
    }

    #[tokio::test]
    async fn finding_has_correct_kind() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/items")
async def create_item(item: dict):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty());
        assert!(matches!(findings[0].kind, FindingKind::AntiPattern));
        assert!(matches!(findings[0].dimension, Dimension::Correctness));
    }

    // ==================== Helper Function Tests ====================

    #[test]
    fn capitalize_first_works() {
        assert_eq!(capitalize_first("hello"), "Hello");
        assert_eq!(capitalize_first("create_item"), "Create_item");
        assert_eq!(capitalize_first(""), "");
        assert_eq!(capitalize_first("A"), "A");
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn handles_router_routes() {
        let src = r#"
from fastapi import APIRouter

router = APIRouter()

@router.post("/items")
async def create_item(item: dict):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect router POST endpoints");
    }

    #[tokio::test]
    async fn handles_sync_endpoints() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/items")
def create_item(item: dict):
    return item
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect sync POST endpoints");
    }

    #[tokio::test]
    async fn handles_multiple_files() {
        let src1 = r#"
from fastapi import FastAPI

app = FastAPI()

@app.post("/items")
async def create_item(item: dict):
    return item
"#;
        let src2 = r#"
from fastapi import FastAPI

app = FastAPI()

@app.put("/users/{user_id}")
async def update_user(user_id: int, user: dict):
    return user
"#;
        let sf1 = SourceFile {
            path: "file1.py".to_string(),
            language: Language::Python,
            content: src1.to_string(),
        };
        let sf2 = SourceFile {
            path: "file2.py".to_string(),
            language: Language::Python,
            content: src2.to_string(),
        };

        let parsed1 = parse_python_file(FileId(1), &sf1).unwrap();
        let parsed2 = parse_python_file(FileId(2), &sf2).unwrap();

        let mut sem1 = PyFileSemantics::from_parsed(&parsed1);
        let mut sem2 = PyFileSemantics::from_parsed(&parsed2);
        sem1.analyze_frameworks(&parsed1).unwrap();
        sem2.analyze_frameworks(&parsed2).unwrap();

        let semantics = vec![
            (FileId(1), Arc::new(SourceSemantics::Python(sem1))),
            (FileId(2), Arc::new(SourceSemantics::Python(sem2))),
        ];

        let rule = FastApiInputValidationRule::new();
        let findings = rule.evaluate(&semantics, None).await;

        assert_eq!(findings.len(), 2, "Should detect issues in both files");
    }
}
