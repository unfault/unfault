use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::graceful_shutdown;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::PyImport;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Check if asynccontextmanager is already imported from contextlib
fn has_asynccontextmanager_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| {
        imp.module == "contextlib" && imp.names.iter().any(|n| n == "asynccontextmanager")
    })
}

/// Check if logging module is already imported
fn has_logging_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| imp.module == "logging")
}

/// Check if signal module is already imported
fn has_signal_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| imp.module == "signal")
}

/// Check if sys module is already imported
fn has_sys_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| imp.module == "sys")
}

/// Rule: Missing Graceful Shutdown
///
/// Detects applications that don't handle SIGTERM signal for graceful shutdown.
/// Without graceful shutdown, requests are dropped during deployments.
#[derive(Debug)]
pub struct PythonMissingGracefulShutdownRule;

impl PythonMissingGracefulShutdownRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonMissingGracefulShutdownRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonMissingGracefulShutdownRule {
    fn id(&self) -> &'static str {
        "python.resilience.missing_graceful_shutdown"
    }

    fn name(&self) -> &'static str {
        "Detects applications without graceful shutdown handling for zero-downtime deployments."
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(graceful_shutdown())
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

            // Check if this looks like a web application entry point
            let is_fastapi = py.fastapi.is_some();
            let is_web_app = is_fastapi
                || py.imports.iter().any(|imp| {
                    imp.module == "fastapi"
                        || imp.module == "flask"
                        || imp.module == "django"
                        || imp.module == "uvicorn"
                        || imp.module == "gunicorn"
                });

            if !is_web_app {
                continue;
            }

            // Check if signal handling is already present
            let has_signal_handling = py.imports.iter().any(|imp| {
                imp.module == "signal"
                    || imp.names.iter().any(|n| n == "signal" || n == "SIGTERM")
            });

            // Check for FastAPI lifespan context manager (check function names)
            let has_lifespan = py.functions.iter().any(|f| {
                f.name.contains("lifespan") || f.name.contains("shutdown")
            });

            // Check for atexit registration
            let has_atexit = py.imports.iter().any(|imp| {
                imp.module == "atexit"
            });

            if has_signal_handling || has_lifespan || has_atexit {
                continue;
            }

            let title = "Web application lacks graceful shutdown handling".to_string();

            let description = 
                "This web application does not handle SIGTERM signal for graceful shutdown. \
                 During deployments, Kubernetes sends SIGTERM to allow apps to finish in-flight \
                 requests. Without handling it, requests are dropped mid-processing, causing \
                 user-visible errors and potential data corruption.".to_string();

            let fix_preview = generate_fix_preview(is_fastapi);

            // Generate patch
            let patch = generate_graceful_shutdown_patch(
                *file_id,
                py.module_docstring_end_line.map(|l| l + 1).unwrap_or(1),
                is_fastapi,
                &py.imports,
            );

            findings.push(RuleFinding {
                rule_id: self.id().to_string(),
                title,
                description: Some(description),
                kind: FindingKind::StabilityRisk,
                severity: Severity::High,
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
                    "resilience".into(),
                    "graceful-shutdown".into(),
                    "kubernetes".into(),
                    "deployment".into(),
                ],
            });
        }

        findings
    }
}

/// Generate graceful shutdown patch.
fn generate_graceful_shutdown_patch(
    file_id: FileId,
    import_line: u32,
    is_fastapi: bool,
    imports: &[PyImport],
) -> FilePatch {
    let mut hunks = Vec::new();

    if is_fastapi {
        // For FastAPI, add lifespan context manager
        // Build import string based on what's missing
        let mut import_parts = Vec::new();
        if !has_asynccontextmanager_import(imports) {
            import_parts.push("from contextlib import asynccontextmanager");
        }
        if !has_logging_import(imports) {
            import_parts.push("import logging");
        }
        
        let mut import_str = String::new();
        if !import_parts.is_empty() {
            import_str = import_parts.join("\n");
            import_str.push('\n');
        }
        // Always add logger setup if logging import was added
        if !has_logging_import(imports) {
            import_str.push_str("\nlogger = logging.getLogger(__name__)\n");
        }
        
        if !import_str.is_empty() {
            hunks.push(PatchHunk {
                range: PatchRange::InsertBeforeLine { line: import_line },
                replacement: import_str,
            });
        }

        let lifespan_code = r#"
@asynccontextmanager
async def lifespan(app):
    # Startup
    logger.info("Application starting up")
    yield
    # Shutdown
    logger.info("Application shutting down gracefully")
    # Add cleanup logic here (close DB connections, flush caches, etc.)

"#;
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: import_line + 4 },
            replacement: lifespan_code.to_string(),
        });
    } else {
        // For generic Python apps, add signal handling
        // Build import string based on what's missing
        let mut import_parts = Vec::new();
        if !has_signal_import(imports) {
            import_parts.push("import signal");
        }
        if !has_sys_import(imports) {
            import_parts.push("import sys");
        }
        if !has_logging_import(imports) {
            import_parts.push("import logging");
        }
        
        let mut import_str = String::new();
        if !import_parts.is_empty() {
            import_str = import_parts.join("\n");
            import_str.push('\n');
        }
        // Always add logger setup if logging import was added
        if !has_logging_import(imports) {
            import_str.push_str("\nlogger = logging.getLogger(__name__)\n");
        }
        
        if !import_str.is_empty() {
            hunks.push(PatchHunk {
                range: PatchRange::InsertBeforeLine { line: import_line },
                replacement: import_str,
            });
        }

        let signal_code = r#"
def graceful_shutdown(signum, frame):
    """Handle shutdown signals gracefully."""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    # Add cleanup logic here (close DB connections, flush caches, etc.)
    sys.exit(0)

signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)

"#;
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: import_line + 5 },
            replacement: signal_code.to_string(),
        });
    }

    FilePatch { file_id, hunks }
}

/// Generate a fix preview showing how to add graceful shutdown.
fn generate_fix_preview(is_fastapi: bool) -> String {
    if is_fastapi {
        r#"# FastAPI with lifespan context manager (recommended)
from contextlib import asynccontextmanager
from fastapi import FastAPI
import logging

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize resources
    logger.info("Application starting up")
    yield
    # Shutdown: Clean up resources
    logger.info("Shutting down gracefully")
    # Close database connections, flush caches, etc.

app = FastAPI(lifespan=lifespan)

# Alternative: Using on_event decorators (deprecated in FastAPI 0.100+)
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down gracefully")
    # Cleanup logic here"#.to_string()
    } else {
        r#"# Generic Python application with signal handling
import signal
import sys
import logging

logger = logging.getLogger(__name__)

def graceful_shutdown(signum, frame):
    """Handle shutdown signals gracefully."""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    # Close database connections
    # Flush caches
    # Complete in-flight requests
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGTERM, graceful_shutdown)
signal.signal(signal.SIGINT, graceful_shutdown)

# For async applications using asyncio
import asyncio

async def shutdown(loop, signal=None):
    """Cleanup tasks tied to the service's shutdown."""
    if signal:
        logger.info(f"Received exit signal {signal.name}...")
    
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    [task.cancel() for task in tasks]
    
    logger.info(f"Cancelling {len(tasks)} outstanding tasks")
    await asyncio.gather(*tasks, return_exceptions=True)
    loop.stop()"#.to_string()
    }
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
        let rule = PythonMissingGracefulShutdownRule::new();
        assert_eq!(rule.id(), "python.resilience.missing_graceful_shutdown");
    }

    #[test]
    fn rule_name_mentions_graceful_shutdown() {
        let rule = PythonMissingGracefulShutdownRule::new();
        assert!(rule.name().contains("graceful shutdown"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_web_app() {
        let rule = PythonMissingGracefulShutdownRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_signal_handling_present() {
        let rule = PythonMissingGracefulShutdownRule::new();
        let src = r#"
import signal
from fastapi import FastAPI

app = FastAPI()

def shutdown_handler(signum, frame):
    pass

signal.signal(signal.SIGTERM, shutdown_handler)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_missing_graceful_shutdown_in_fastapi() {
        let rule = PythonMissingGracefulShutdownRule::new();
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
        assert_eq!(findings[0].rule_id, "python.resilience.missing_graceful_shutdown");
    }

    #[tokio::test]
    async fn evaluate_finding_has_high_severity() {
        let rule = PythonMissingGracefulShutdownRule::new();
        let src = r#"
from fastapi import FastAPI
app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].severity, Severity::High));
    }

    #[tokio::test]
    async fn evaluate_finding_has_patch() {
        let rule = PythonMissingGracefulShutdownRule::new();
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
        let rule = PythonMissingGracefulShutdownRule::new();
        let src = r#"
from fastapi import FastAPI
app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
        assert!(findings[0].fix_preview.as_ref().unwrap().contains("lifespan"));
    }
}