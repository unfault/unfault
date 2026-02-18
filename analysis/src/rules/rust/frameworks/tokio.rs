//! Tokio runtime rules for detecting production-readiness issues.
//!
//! Tokio is the de facto async runtime for Rust. These rules detect common
//! issues with Tokio applications that can affect reliability.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

// ================== Missing Graceful Shutdown Rule ==================

/// Rule that detects Tokio applications without graceful shutdown handling.
///
/// Production applications should handle shutdown signals (SIGTERM, SIGINT)
/// gracefully to allow in-flight requests to complete and resources to be
/// cleaned up properly.
#[derive(Debug, Default)]
pub struct TokioMissingGracefulShutdownRule;

impl TokioMissingGracefulShutdownRule {
    pub fn new() -> Self {
        Self
    }
}

/// Check if a file uses Tokio
fn uses_tokio(rust: &crate::semantics::rust::model::RustFileSemantics) -> bool {
    rust.uses.iter().any(|u| u.path.contains("tokio"))
}

#[async_trait]
impl Rule for TokioMissingGracefulShutdownRule {
    fn id(&self) -> &'static str {
        "rust.tokio.missing_graceful_shutdown"
    }

    fn name(&self) -> &'static str {
        "Tokio application without graceful shutdown handling"
    }

    fn applicability(&self) -> Option<crate::types::finding::FindingApplicability> {
        Some(crate::rules::applicability_defaults::graceful_shutdown())
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

            // Only check files that use Tokio
            if !uses_tokio(rust) {
                continue;
            }

            // Check if this looks like a main entry point
            let has_main = rust.functions.iter().any(|f| f.name == "main");
            let has_tokio_main = rust.macro_invocations.iter().any(|m| {
                m.name.contains("tokio::main") || m.name == "main"
            });

            if !has_main && !has_tokio_main {
                continue;
            }

            // Check if signal handling is present
            let has_signal_handling = rust.uses.iter().any(|u| {
                u.path.contains("tokio::signal")
                    || u.path.contains("signal::ctrl_c")
                    || u.path.contains("signal::unix")
            }) || rust.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("signal::ctrl_c")
                    || c.function_call.callee_expr.contains("ctrl_c")
                    || c.function_call.callee_expr.contains("signal()")
                    || c.function_call.callee_expr.contains("SignalKind")
            });

            if has_signal_handling {
                continue;
            }

            // Check if there's a server running (web frameworks, etc.)
            let has_server = rust.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("serve")
                    || c.function_call.callee_expr.contains("bind")
                    || c.function_call.callee_expr.contains("listen")
                    || c.function_call.callee_expr.contains("run")
            });

            if !has_server {
                continue;
            }

            // Find main function location
            if let Some(main_fn) = rust.functions.iter().find(|f| f.name == "main") {
                let line = main_fn.location.range.start_line + 1;

                let title = "Tokio application without graceful shutdown handling".to_string();

                let description = format!(
                    "The main function at line {} runs a server without handling \
                     shutdown signals (SIGTERM, SIGINT).\n\n\
                     **Why this matters:**\n\
                     - In-flight requests will be abruptly terminated\n\
                     - Database connections may not be properly closed\n\
                     - Kubernetes/Docker deployment won't gracefully drain\n\
                     - Data corruption risk during shutdown\n\n\
                     **Recommendations:**\n\
                     - Use `tokio::signal::ctrl_c()` for SIGINT handling\n\
                     - Use `tokio::signal::unix::signal(SignalKind::terminate())` for SIGTERM\n\
                     - Implement graceful shutdown with `tokio::select!`\n\
                     - Set a shutdown timeout\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use tokio::signal;\n\
                     \n\
                     #[tokio::main]\n\
                     async fn main() {{\n    \
                         let server = /* create server */;\n\
                         \n    \
                         tokio::select! {{\n        \
                             _ = server => {{}}\n        \
                             _ = signal::ctrl_c() => {{\n            \
                                 println!(\"Shutting down gracefully...\");\n        \
                             }}\n    \
                         }}\n\
                     }}\n\
                     ```",
                    line
                );

                let fix_preview = 
                    "use tokio::signal;\n\n\
                     async fn shutdown_signal() {\n    \
                         let ctrl_c = async {\n        \
                             signal::ctrl_c()\n            \
                                 .await\n            \
                                 .expect(\"failed to install Ctrl+C handler\");\n    \
                         };\n\n    \
                         #[cfg(unix)]\n    \
                         let terminate = async {\n        \
                             signal::unix::signal(signal::unix::SignalKind::terminate())\n            \
                                 .expect(\"failed to install signal handler\")\n            \
                                 .recv()\n            \
                                 .await;\n    \
                         };\n\n    \
                         #[cfg(not(unix))]\n    \
                         let terminate = std::future::pending::<()>();\n\n    \
                         tokio::select! {\n        \
                             _ = ctrl_c => {},\n        \
                             _ = terminate => {},\n    \
                         }\n\
                     }".to_string();

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Implement graceful shutdown - use tokio::signal::ctrl_c()".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::ReliabilityRisk,
                    severity: Severity::High,
                    confidence: 0.75,
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
                        "tokio".into(),
                        "graceful-shutdown".into(),
                        "reliability".into(),
                    ],
                });
            }
        }

        findings
    }
}

// ================== Missing Runtime Config Rule ==================

/// Rule that detects Tokio applications without proper runtime configuration.
///
/// The Tokio runtime should be configured appropriately for the workload,
/// including thread pools, timeouts, and panic hooks.
#[derive(Debug, Default)]
pub struct TokioMissingRuntimeConfigRule;

impl TokioMissingRuntimeConfigRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for TokioMissingRuntimeConfigRule {
    fn id(&self) -> &'static str {
        "rust.tokio.missing_runtime_config"
    }

    fn name(&self) -> &'static str {
        "Tokio runtime without explicit configuration"
    }

    fn applicability(&self) -> Option<crate::types::finding::FindingApplicability> {
        Some(crate::rules::applicability_defaults::runtime_config())
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

            // Only check files that use Tokio
            if !uses_tokio(rust) {
                continue;
            }

            // Look for #[tokio::main] without configuration
            let has_simple_tokio_main = rust.macro_invocations.iter().any(|m| {
                let is_tokio_main =
                    m.name == "tokio::main" || m.name.contains("tokio :: main");

                // Check if it has configuration parameters
                let has_config = m.args.contains("flavor")
                    || m.args.contains("worker_threads")
                    || m.args.contains("start_paused");

                is_tokio_main && !has_config
            });

            if !has_simple_tokio_main {
                continue;
            }

            // Find the main function
            if let Some(main_fn) = rust.functions.iter().find(|f| f.name == "main") {
                let line = main_fn.location.range.start_line + 1;

                let title = "Tokio runtime without explicit configuration".to_string();

                let description = format!(
                    "The #[tokio::main] macro at line {} uses default runtime configuration.\n\n\
                     **Why this matters:**\n\
                     - Default thread count may not be optimal for your workload\n\
                     - No control over thread naming for debugging\n\
                     - May not handle panics appropriately\n\n\
                     **Recommendations:**\n\
                     - Specify `flavor` (current_thread or multi_thread)\n\
                     - Configure `worker_threads` based on workload\n\
                     - Consider using `Runtime::Builder` for more control\n\n\
                     **Example:**\n\
                     ```rust\n\
                     #[tokio::main(flavor = \"multi_thread\", worker_threads = 4)]\n\
                     async fn main() {{\n    \
                         // ...\n\
                     }}\n\
                     \n\
                     // Or with Runtime::Builder:\n\
                     fn main() {{\n    \
                         let runtime = Runtime::builder()\n        \
                             .multi_thread()\n        \
                             .worker_threads(4)\n        \
                             .thread_name(\"my-app-worker\")\n        \
                             .enable_all()\n        \
                             .build()\n        \
                             .unwrap();\n\n    \
                         runtime.block_on(async {{ /* ... */ }});\n\
                     }}\n\
                     ```",
                    line
                );

                let fix_preview =
                    "#[tokio::main(flavor = \"multi_thread\", worker_threads = 4)]\n\
                     async fn main() {\n    \
                         // ...\n\
                     }".to_string();

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Configure Tokio runtime - add flavor and worker_threads".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::AntiPattern,
                    severity: Severity::Low,
                    confidence: 0.70,
                    dimension: Dimension::Performance,
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
                        "tokio".into(),
                        "configuration".into(),
                        "performance".into(),
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
    use crate::parse::ast::FileId;
    use crate::parse::rust::parse_rust_file;
    use crate::semantics::rust::build_rust_semantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "main.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_rust_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Rust(sem)))
    }

    #[test]
    fn graceful_shutdown_rule_id_is_correct() {
        let rule = TokioMissingGracefulShutdownRule::new();
        assert_eq!(rule.id(), "rust.tokio.missing_graceful_shutdown");
    }

    #[test]
    fn runtime_config_rule_id_is_correct() {
        let rule = TokioMissingRuntimeConfigRule::new();
        assert_eq!(rule.id(), "rust.tokio.missing_runtime_config");
    }

    #[tokio::test]
    async fn skips_non_tokio_files() {
        let rule = TokioMissingGracefulShutdownRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn main() {
    println!("Hello");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should skip non-Tokio files");
    }

    #[tokio::test]
    async fn detects_missing_shutdown_handling() {
        let rule = TokioMissingGracefulShutdownRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
    
    loop {
        let (socket, _) = listener.accept().await.unwrap();
        // handle connection
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.tokio.missing_graceful_shutdown"),
            "Should detect missing graceful shutdown"
        );
    }

    #[tokio::test]
    async fn skips_when_signal_handling_present() {
        let rule = TokioMissingGracefulShutdownRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use tokio::net::TcpListener;
use tokio::signal;

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("0.0.0.0:8080").await.unwrap();
    
    tokio::select! {
        _ = async {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
            }
        } => {}
        _ = signal::ctrl_c() => {
            println!("Shutting down...");
        }
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let shutdown_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.tokio.missing_graceful_shutdown")
            .collect();
        assert!(
            shutdown_findings.is_empty(),
            "Should not flag when signal handling present"
        );
    }
}
