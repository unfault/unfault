//! Axum framework rules for detecting production-readiness issues.
//!
//! Axum is a popular web framework for Rust built on top of Tokio and Tower.
//! These rules detect common issues with Axum applications.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{
    Benefit, DecisionLevel, FindingApplicability, FindingKind, InvestmentLevel, LifecycleStage,
    Severity,
};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

// ================== Missing Error Handler Rule ==================

/// Rule that detects Axum routes without proper error handling.
///
/// Routes should return a `Result` type or use `IntoResponse` implementations
/// that properly handle errors, rather than unwrapping or panicking.
#[derive(Debug, Default)]
pub struct AxumMissingErrorHandlerRule;

impl AxumMissingErrorHandlerRule {
    pub fn new() -> Self {
        Self
    }
}

/// Check if a file uses Axum
fn uses_axum(rust: &crate::semantics::rust::model::RustFileSemantics) -> bool {
    rust.uses.iter().any(|u| u.path.contains("axum"))
}

#[async_trait]
impl Rule for AxumMissingErrorHandlerRule {
    fn id(&self) -> &'static str {
        "rust.axum.missing_error_handler"
    }

    fn name(&self) -> &'static str {
        "Axum route without error handling"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Low,
            min_stage: LifecycleStage::Prototype,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Reliability, Benefit::Correctness],
            prerequisites: vec![],
            notes: Some(
                "Worth fixing even in demos: panics/unwraps in request paths crash or 500.".to_string(),
            ),
        })
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let rust = match sem.as_ref() {
                SourceSemantics::Rust(r) => r,
                _ => continue,
            };

            // Only check files that use Axum
            if !uses_axum(rust) {
                continue;
            }

            // Look for handler functions (async fn that could be route handlers)
            for func in &rust.functions {
                if !func.is_async {
                    continue;
                }

                if func.is_test {
                    continue;
                }

                // Skip if function already returns Result
                if func.returns_result {
                    continue;
                }

                // Check for bare `.unwrap()` calls inside the function.
                //
                // `unwrap_or(_)/unwrap_or_else(_)/unwrap_or_default()` are fallback patterns and
                // should not be treated as panicking unwraps.
                let has_unwrap_in_func = rust.unwrap_calls.iter().any(|u| {
                    u.function_name.as_deref() == Some(&func.name) && u.method == "unwrap"
                });

                if !has_unwrap_in_func {
                    continue;
                }

                let line = func.location.range.start_line + 1;

                 let title = format!(
                     "Axum handler '{}' contains .unwrap() without error handling",
                     func.name
                 );

                let description = format!(
                    "The async function '{}' at line {} appears to be an Axum handler \
                     that uses .unwrap() without proper error handling.\n\n\
                     **Why this matters:**\n\
                     - .unwrap() in handlers can crash the server\n\
                     - Users will see unhelpful 500 errors\n\
                     - No structured error responses\n\n\
                     **Recommendations:**\n\
                     - Return `Result<impl IntoResponse, AppError>`\n\
                     - Implement `IntoResponse` for your error type\n\
                     - Use `?` operator for propagation\n\
                     - Consider using `anyhow` or `thiserror`\n\n\
                     **Example:**\n\
                     ```rust\n\
                     async fn handler() -> Result<Json<Data>, AppError> {{\n    \
                         let data = fetch_data().await?;\n    \
                         Ok(Json(data))\n\
                     }}\n\
                     ```",
                    func.name,
                    line
                );

                let fix_preview = format!(
                    "async fn {}(...) -> Result<impl IntoResponse, AppError> {{\n    \
                         // Use ? instead of .unwrap()\n    \
                         let value = fallible_op()?;\n    \
                         Ok(Json(value))\n\
                     }}",
                    func.name
                );

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Add proper error handling - return Result<impl IntoResponse, AppError>".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::High,
                    confidence: 0.75,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "axum".into(),
                        "error-handling".into(),
                        "web".into(),
                    ],
                });
            }
        }

        findings
    }
}

// ================== Missing CORS Rule ==================

/// Rule that detects Axum applications without CORS configuration.
///
/// Web APIs typically need CORS (Cross-Origin Resource Sharing) headers
/// to allow browser-based clients from different origins.
#[derive(Debug, Default)]
pub struct AxumMissingCorsRule;

impl AxumMissingCorsRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for AxumMissingCorsRule {
    fn id(&self) -> &'static str {
        "rust.axum.missing_cors"
    }

    fn name(&self) -> &'static str {
        "Axum application without CORS configuration"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Medium,
            min_stage: LifecycleStage::Product,
            decision_level: DecisionLevel::ApiContract,
            benefits: vec![Benefit::Operability, Benefit::Security],
            prerequisites: vec![
                "Decide allowed origins/methods/headers (avoid allow-any in production)".to_string(),
            ],
            notes: Some(
                "For demos, permissive CORS may be acceptable; for production, be explicit.".to_string(),
            ),
        })
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let rust = match sem.as_ref() {
                SourceSemantics::Rust(r) => r,
                _ => continue,
            };

            // Only check files that use Axum
            if !uses_axum(rust) {
                continue;
            }

            // Check if CORS is configured
            let has_cors = rust.uses.iter().any(|u| {
                u.path.contains("tower_http::cors") || u.path.contains("CorsLayer")
            });

            if has_cors {
                continue;
            }

            // Look for Router creation
            let has_router = rust.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("Router::new") || c.function_call.callee_expr.contains("Router::with_state")
            });

            if !has_router {
                continue;
            }

            // Find the router creation location
            if let Some(router_call) = rust.calls.iter().find(|c| {
                c.function_call.callee_expr.contains("Router::new") || c.function_call.callee_expr.contains("Router::with_state")
            }) {
                let line = router_call.function_call.location.line;

                let title = "Axum Router without CORS configuration".to_string();

                let description = format!(
                    "An Axum Router is created at line {} without CORS middleware.\n\n\
                     **Why this matters:**\n\
                     - Browser-based clients from different origins will be blocked\n\
                     - API won't work with frontend apps on different domains\n\
                     - Preflight OPTIONS requests will fail\n\n\
                     **Recommendations:**\n\
                     - Add `tower_http::cors::CorsLayer`\n\
                     - Configure allowed origins, methods, and headers\n\
                     - Consider using `CorsLayer::permissive()` for development\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use tower_http::cors::{{CorsLayer, Any}};\n\
                     \n\
                     let cors = CorsLayer::new()\n    \
                         .allow_origin(Any)\n    \
                         .allow_methods(Any)\n    \
                         .allow_headers(Any);\n\
                     \n\
                     let app = Router::new()\n    \
                         .route(\"/\", get(handler))\n    \
                         .layer(cors);\n\
                     ```",
                    line
                );

                let fix_preview = 
                    "use tower_http::cors::{CorsLayer, Any};\n\n\
                     let cors = CorsLayer::new()\n    \
                         .allow_origin(Any)\n    \
                         .allow_methods(Any)\n    \
                         .allow_headers(Any);\n\n\
                     let app = Router::new()\n    \
                         // ... routes ...\n    \
                         .layer(cors);".to_string();

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Add CORS middleware - use tower_http::cors::CorsLayer".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::AntiPattern,
                    severity: Severity::Medium,
                    confidence: 0.80,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "axum".into(),
                        "cors".into(),
                        "web".into(),
                    ],
                });
            }
        }

        findings
    }
}

// ================== Missing Timeout Rule ==================

/// Rule that detects Axum applications without request timeout configuration.
///
/// All web applications should have request timeouts to prevent slow clients
/// or slow backends from exhausting server resources.
#[derive(Debug, Default)]
pub struct AxumMissingTimeoutRule;

impl AxumMissingTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for AxumMissingTimeoutRule {
    fn id(&self) -> &'static str {
        "rust.axum.missing_timeout"
    }

    fn name(&self) -> &'static str {
        "Axum application without timeout middleware"
    }

    fn applicability(&self) -> Option<crate::types::finding::FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let rust = match sem.as_ref() {
                SourceSemantics::Rust(r) => r,
                _ => continue,
            };

            // Only check files that use Axum
            if !uses_axum(rust) {
                continue;
            }

            // Check if timeout is configured
            let has_timeout = rust.uses.iter().any(|u| {
                u.path.contains("tower_http::timeout")
                    || u.path.contains("TimeoutLayer")
                    || u.path.contains("tower::timeout")
            }) || rust.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("TimeoutLayer") || c.function_call.callee_expr.contains("timeout")
            });

            if has_timeout {
                continue;
            }

            // Look for Router creation
            let has_router = rust.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("Router::new") || c.function_call.callee_expr.contains("Router::with_state")
            });

            if !has_router {
                continue;
            }

            // Find the router creation location
            if let Some(router_call) = rust.calls.iter().find(|c| {
                c.function_call.callee_expr.contains("Router::new") || c.function_call.callee_expr.contains("Router::with_state")
            }) {
                let line = router_call.function_call.location.line;

                let title = "Axum Router without timeout middleware".to_string();

                let description = format!(
                    "An Axum Router is created at line {} without timeout middleware.\n\n\
                     **Why this matters:**\n\
                     - Slow clients can hold connections indefinitely\n\
                     - Backend delays can cascade to request timeouts\n\
                     - Server resources can be exhausted\n\
                     - No protection against slowloris attacks\n\n\
                     **Recommendations:**\n\
                     - Add `tower_http::timeout::TimeoutLayer`\n\
                     - Set appropriate timeout (e.g., 30 seconds)\n\
                     - Consider different timeouts for different routes\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use tower_http::timeout::TimeoutLayer;\n\
                     use std::time::Duration;\n\
                     \n\
                     let app = Router::new()\n    \
                         .route(\"/\", get(handler))\n    \
                         .layer(TimeoutLayer::new(Duration::from_secs(30)));\n\
                     ```",
                    line
                );

                let fix_preview = 
                    "use tower_http::timeout::TimeoutLayer;\n\
                     use std::time::Duration;\n\n\
                     let app = Router::new()\n    \
                         // ... routes ...\n    \
                         .layer(TimeoutLayer::new(Duration::from_secs(30)));".to_string();

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Add timeout middleware - use tower_http::timeout::TimeoutLayer".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::ReliabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.80,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "axum".into(),
                        "timeout".into(),
                        "web".into(),
                    ],
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::parse::ast::FileId;
    use crate::parse::rust::parse_rust_file;
    use crate::semantics::rust::build_rust_semantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "axum_app.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_rust_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Rust(sem)))
    }

    #[test]
    fn error_handler_rule_id_is_correct() {
        let rule = AxumMissingErrorHandlerRule::new();
        assert_eq!(rule.id(), "rust.axum.missing_error_handler");
    }

    #[test]
    fn cors_rule_id_is_correct() {
        let rule = AxumMissingCorsRule::new();
        assert_eq!(rule.id(), "rust.axum.missing_cors");
    }

    #[test]
    fn timeout_rule_id_is_correct() {
        let rule = AxumMissingTimeoutRule::new();
        assert_eq!(rule.id(), "rust.axum.missing_timeout");
    }

    #[tokio::test]
    async fn skips_non_axum_files() {
        let rule = AxumMissingCorsRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn main() {
    println!("Hello");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should skip non-Axum files");
    }

    #[tokio::test]
    async fn detects_missing_cors() {
        let rule = AxumMissingCorsRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use axum::{Router, routing::get};

async fn handler() -> &'static str {
    "Hello"
}

fn create_router() {
    let app = Router::new()
        .route("/", get(handler));
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.axum.missing_cors"),
            "Should detect missing CORS"
        );
    }

    #[tokio::test]
    async fn does_not_flag_unwrap_or_else_as_unwrap_in_handler() {
        let rule = AxumMissingErrorHandlerRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use axum::{Router, routing::get};
use std::sync::{Arc, Mutex};

type AppState = Arc<Mutex<u32>>;

async fn handler(state: AppState) -> &'static str {
    let _guard = state.lock().unwrap_or_else(|e| e.into_inner());
    "ok"
}

fn create_router(state: AppState) {
    let _app = Router::new().route("/", get(handler)).with_state(state);
}
"#,
        );

        let findings = rule.evaluate(&vec![(file_id, sem)], None).await;
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "rust.axum.missing_error_handler"),
            "should not flag unwrap_or_else as .unwrap() in handler"
        );
    }

    #[tokio::test]
    async fn skips_when_cors_present() {
        let rule = AxumMissingCorsRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use axum::{Router, routing::get};
use tower_http::cors::CorsLayer;

async fn handler() -> &'static str {
    "Hello"
}

fn create_router() {
    let app = Router::new()
        .route("/", get(handler))
        .layer(CorsLayer::permissive());
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let cors_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.axum.missing_cors")
            .collect();
        assert!(cors_findings.is_empty(), "Should not flag when CORS present");
    }

    #[tokio::test]
    async fn detects_missing_timeout() {
        let rule = AxumMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use axum::{Router, routing::get};

async fn handler() -> &'static str {
    "Hello"
}

fn create_router() {
    let app = Router::new()
        .route("/", get(handler));
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.axum.missing_timeout"),
            "Should detect missing timeout"
        );
    }
}
