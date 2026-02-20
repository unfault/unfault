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

/// Rule: Missing Rate Limiting
///
/// Detects FastAPI applications without rate limiting configuration.
/// Without rate limiting, APIs are vulnerable to abuse and DoS attacks.
#[derive(Debug)]
pub struct FastApiMissingRateLimitingRule;

impl FastApiMissingRateLimitingRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FastApiMissingRateLimitingRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for FastApiMissingRateLimitingRule {
    fn id(&self) -> &'static str {
        "python.fastapi.missing_rate_limiting"
    }

    fn name(&self) -> &'static str {
        "Detects FastAPI applications without rate limiting to prevent API abuse and DoS attacks."
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

            // Only check FastAPI applications
            if py.fastapi.is_none() {
                continue;
            }

            // Check if rate limiting is already configured
            let has_rate_limiting = py.imports.iter().any(|imp| {
                imp.module == "slowapi"
                    || imp.module == "fastapi_limiter"
                    || imp.module == "ratelimit"
                    || imp.names.iter().any(|n| {
                        n == "Limiter" || n == "RateLimiter" || n.to_lowercase().contains("limit")
                    })
            });

            if has_rate_limiting {
                continue;
            }

            // Check for rate limit decorators on routes - check via calls
            let has_rate_limit_decorator = py.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("limit")
                    || c.function_call.callee_expr.contains("rate")
                    || c.function_call.callee_expr.contains("throttle")
            });

            if has_rate_limit_decorator {
                continue;
            }

            let title = "FastAPI application lacks rate limiting protection".to_string();

            let description = "This FastAPI application does not have rate limiting configured. \
                 Without rate limiting, the API is vulnerable to abuse, DoS attacks, \
                 and resource exhaustion. Consider using slowapi or fastapi-limiter \
                 to add rate limiting protection."
                .to_string();

            let fix_preview = generate_fix_preview();

            // Generate patch
            let patch = generate_rate_limiting_patch(
                *file_id,
                py.module_docstring_end_line.map(|l| l + 1).unwrap_or(1),
            );

            findings.push(RuleFinding {
                rule_id: self.id().to_string(),
                title,
                description: Some(description),
                kind: FindingKind::StabilityRisk,
                severity: Severity::Medium,
                confidence: 0.85,
                dimension: Dimension::Stability,
                file_id: *file_id,
                file_path: py.path.clone(),
                line: Some(1),
                column: Some(1),
                end_line: None,
                end_column: None,
                byte_range: None,
                patch: Some(patch),
                fix_preview: Some(fix_preview),
                tags: vec![
                    "python".into(),
                    "fastapi".into(),
                    "rate-limiting".into(),
                    "security".into(),
                    "dos-prevention".into(),
                ],
            });
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::missing_rate_limiting())
    }
}

/// Generate rate limiting patch.
fn generate_rate_limiting_patch(file_id: FileId, import_line: u32) -> FilePatch {
    let mut hunks = Vec::new();

    // Add slowapi imports
    let import_str = r#"from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

"#;
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: import_line },
        replacement: import_str.to_string(),
    });

    // Add limiter initialization
    let limiter_code = r#"
# Rate limiter configuration
limiter = Limiter(key_func=get_remote_address)

"#;
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine {
            line: import_line + 4,
        },
        replacement: limiter_code.to_string(),
    });

    FilePatch { file_id, hunks }
}

/// Generate a fix preview showing how to add rate limiting.
fn generate_fix_preview() -> String {
    r#"# Install: pip install slowapi

from fastapi import FastAPI, Request
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Initialize limiter with client IP as key
limiter = Limiter(key_func=get_remote_address)

app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.get("/api/data")
@limiter.limit("100/minute")  # 100 requests per minute per IP
async def get_data(request: Request):
    return {"data": "value"}

@app.post("/api/expensive")
@limiter.limit("10/minute")  # More restrictive for expensive operations
async def expensive_operation(request: Request):
    return {"result": "done"}

# Alternative: Use fastapi-limiter with Redis backend
# pip install fastapi-limiter

from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
import redis.asyncio as redis

@app.on_event("startup")
async def startup():
    redis_connection = redis.from_url("redis://localhost", encoding="utf-8")
    await FastAPILimiter.init(redis_connection)

@app.get("/api/limited")
async def limited_route(request: Request):
    return {"message": "This route is rate limited"}

# Add rate limiter as dependency
@app.get("/api/strict", dependencies=[Depends(RateLimiter(times=2, seconds=5))])
async def strict_route():
    return {"message": "Only 2 requests per 5 seconds"}"#
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
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

    #[test]
    fn rule_id_is_correct() {
        let rule = FastApiMissingRateLimitingRule::new();
        assert_eq!(rule.id(), "python.fastapi.missing_rate_limiting");
    }

    #[test]
    fn rule_name_mentions_rate_limiting() {
        let rule = FastApiMissingRateLimitingRule::new();
        assert!(rule.name().contains("rate limiting"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_fastapi_app() {
        let rule = FastApiMissingRateLimitingRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_slowapi_imported() {
        let rule = FastApiMissingRateLimitingRule::new();
        let src = r#"
from fastapi import FastAPI
from slowapi import Limiter

app = FastAPI()
limiter = Limiter(key_func=get_remote_address)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_missing_rate_limiting() {
        let rule = FastApiMissingRateLimitingRule::new();
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
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "python.fastapi.missing_rate_limiting");
    }

    #[tokio::test]
    async fn evaluate_finding_has_medium_severity() {
        let rule = FastApiMissingRateLimitingRule::new();
        let src = r#"
from fastapi import FastAPI
app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].severity, Severity::Medium));
    }

    #[tokio::test]
    async fn evaluate_finding_has_patch() {
        let rule = FastApiMissingRateLimitingRule::new();
        let src = r#"
from fastapi import FastAPI
app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = FastApiMissingRateLimitingRule::new();
        let src = r#"
from fastapi import FastAPI
app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
        assert!(
            findings[0]
                .fix_preview
                .as_ref()
                .unwrap()
                .contains("slowapi")
        );
    }
}
