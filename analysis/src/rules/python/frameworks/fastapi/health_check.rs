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

/// Rule B17: Missing health checks
///
/// Detects FastAPI applications that don't have health check endpoints configured.
/// Health checks are essential for container orchestration (Kubernetes), load balancers,
/// and deployment systems to determine if the service is ready to receive traffic.
#[derive(Debug)]
pub struct FastApiHealthCheckRule;

impl FastApiHealthCheckRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for FastApiHealthCheckRule {
    fn id(&self) -> &'static str {
        "python.fastapi.missing_health_check"
    }

    fn name(&self) -> &'static str {
        "Checks if FastAPI apps have health check endpoints (liveness/readiness)"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        // Detect health endpoints across the whole workspace.
        //
        // Many FastAPI projects define `/health` on an APIRouter in a separate module
        // and include it via `app.include_router(...)`. In that layout, the app file
        // has `apps` but may not contain the health route itself.
        let health_paths = [
            "/health",
            "/healthz",
            "/healthcheck",
            "/health-check",
            "/ready",
            "/readiness",
            "/live",
            "/liveness",
            "/ping",
            "/_health",
        ];

        let workspace_has_health_endpoint = semantics.iter().any(|(_file_id, sem)| {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => return false,
            };
            let fastapi = match &py.fastapi {
                Some(f) => f,
                None => return false,
            };

            fastapi.routes.iter().any(|route| {
                let path_lower = route.path.to_lowercase();
                health_paths.iter().any(|hp| path_lower.contains(hp))
            })
        });

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

            // If the workspace already exposes a health endpoint, do not flag apps.
            if workspace_has_health_endpoint {
                continue;
            }

            // Check each app for health endpoints
            for app in &fastapi.apps {
                let location = &app.location;

                // Generate patch with semantically sound hunks
                let health_code = generate_health_endpoint_code(&app.var_name);

                let file_patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![
                        // Add health endpoint after the app definition
                        PatchHunk {
                            range: PatchRange::InsertAfterLine {
                                line: location.range.end_line,
                            },
                            replacement: health_code.clone(),
                        },
                    ],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!(
                        "FastAPI app `{}` has no health check endpoint",
                        app.var_name
                    ),
                    description: Some(
                        "FastAPI applications should have health check endpoints for \
                         container orchestration (Kubernetes), load balancers, and deployment \
                         systems. Without health checks, the infrastructure cannot determine \
                         if the service is ready to receive traffic, leading to potential \
                         downtime during deployments or failures."
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
                        "# Add health check endpoints:\n{}",
                        health_code.trim()
                    )),
                    tags: vec![
                        "python".into(),
                        "fastapi".into(),
                        "health-check".into(),
                        "availability".into(),
                        "kubernetes".into(),
                    ],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::graceful_shutdown())
    }
}

/// Generate health check endpoint code.
fn generate_health_endpoint_code(app_var: &str) -> String {
    format!(
        r#"

# Health check endpoints for container orchestration
@{app}.get("/health", tags=["health"])
async def health_check():
    """
    Health check endpoint for load balancers and orchestration systems.
    Returns 200 OK if the service is healthy.
    """
    return {{"status": "healthy"}}


@{app}.get("/ready", tags=["health"])
async def readiness_check():
    """
    Readiness check endpoint for Kubernetes.
    Returns 200 OK if the service is ready to receive traffic.
    Add checks for database connections, external services, etc.
    """
    # TODO: Add actual readiness checks (database, cache, external services)
    return {{"status": "ready"}}
"#,
        app = app_var
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

    fn parse_and_build_semantics_at(
        path: &str,
        file_id: u64,
        source: &str,
    ) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: path.to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(file_id);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed)
            .expect("framework analysis should succeed");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = FastApiHealthCheckRule::new();
        assert_eq!(rule.id(), "python.fastapi.missing_health_check");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = FastApiHealthCheckRule::new();
        assert!(rule.name().contains("health"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = FastApiHealthCheckRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("FastApiHealthCheckRule"));
    }

    // ==================== No Finding Tests ====================

    #[tokio::test]
    async fn no_finding_for_non_fastapi_code() {
        let rule = FastApiHealthCheckRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_health_endpoint_present() {
        let rule = FastApiHealthCheckRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
async def health():
    return {"status": "healthy"}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_health_endpoint_in_different_file() {
        let rule = FastApiHealthCheckRule::new();

        let app_src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;

        let routes_src = r#"
from fastapi import APIRouter

router = APIRouter()

@router.get("/health")
async def health():
    return {"status": "ok"}
"#;

        let (app_id, app_sem) = parse_and_build_semantics_at("main.py", 1, app_src);
        let (routes_id, routes_sem) = parse_and_build_semantics_at("health.py", 2, routes_src);
        let semantics = vec![(app_id, app_sem), (routes_id, routes_sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "should not flag missing health check when /health exists anywhere in workspace"
        );
    }

    #[tokio::test]
    async fn no_finding_when_healthz_endpoint_present() {
        let rule = FastApiHealthCheckRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_ready_endpoint_present() {
        let rule = FastApiHealthCheckRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/ready")
async def ready():
    return {"status": "ready"}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_ping_endpoint_present() {
        let rule = FastApiHealthCheckRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/ping")
async def ping():
    return "pong"
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Finding Tests ====================

    #[tokio::test]
    async fn finding_when_no_health_endpoint() {
        let rule = FastApiHealthCheckRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello"}

@app.get("/users")
async def get_users():
    return []
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("no health check endpoint"));
    }

    #[tokio::test]
    async fn finding_has_correct_rule_id() {
        let rule = FastApiHealthCheckRule::new();
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
            "python.fastapi.missing_health_check"
        );
    }

    #[tokio::test]
    async fn finding_has_correct_severity() {
        let rule = FastApiHealthCheckRule::new();
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
        let rule = FastApiHealthCheckRule::new();
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
        let rule = FastApiHealthCheckRule::new();
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
    async fn finding_patch_has_one_hunk() {
        let rule = FastApiHealthCheckRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        let patch = findings[0].patch.as_ref().unwrap();
        assert_eq!(patch.hunks.len(), 1, "Should have one hunk for health endpoints");
    }

    #[tokio::test]
    async fn finding_has_fix_preview() {
        let rule = FastApiHealthCheckRule::new();
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
        assert!(preview.contains("/health"));
    }

    #[tokio::test]
    async fn finding_has_correct_tags() {
        let rule = FastApiHealthCheckRule::new();
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
        assert!(findings[0].tags.contains(&"health-check".to_string()));
        assert!(findings[0].tags.contains(&"availability".to_string()));
        assert!(findings[0].tags.contains(&"kubernetes".to_string()));
    }

    // ==================== Multiple Apps Tests ====================

    #[tokio::test]
    async fn finding_for_each_app_without_health_check() {
        let rule = FastApiHealthCheckRule::new();
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
        let rule = FastApiHealthCheckRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = FastApiHealthCheckRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_when_health_in_path() {
        let rule = FastApiHealthCheckRule::new();
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/api/v1/health-check")
async def api_health():
    return {"status": "ok"}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Patch Generation Tests ====================

    #[test]
    fn generate_health_endpoint_code_includes_health_route() {
        let code = generate_health_endpoint_code("app");
        assert!(code.contains("@app.get(\"/health\""));
        assert!(code.contains("health_check"));
    }

    #[test]
    fn generate_health_endpoint_code_includes_ready_route() {
        let code = generate_health_endpoint_code("app");
        assert!(code.contains("@app.get(\"/ready\""));
        assert!(code.contains("readiness_check"));
    }

    #[test]
    fn generate_health_endpoint_code_uses_correct_app_var() {
        let code = generate_health_endpoint_code("my_app");
        assert!(code.contains("@my_app.get"));
    }

    #[test]
    fn generate_health_endpoint_code_has_docstrings() {
        let code = generate_health_endpoint_code("app");
        assert!(code.contains("\"\"\""));
        assert!(code.contains("Health check endpoint"));
    }
}
