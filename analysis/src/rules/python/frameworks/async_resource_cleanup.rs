//! Rule B16: Improper async resource cleanup
//!
//! Detects when async resources (HTTP clients, database connections) are not
//! properly managed with `async with` context managers, which can lead to
//! leaked connections and file descriptor exhaustion.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects async resources not properly cleaned up with context managers.
///
/// # What it detects
/// - `httpx.AsyncClient()` used without `async with`
/// - `aiohttp.ClientSession()` used without `async with`
/// - Direct assignment of async clients without context manager
///
/// # Why it matters
/// Async HTTP clients and sessions hold connections and file descriptors.
/// Without proper cleanup via `async with`, these resources can leak,
/// leading to connection pool exhaustion and FD limits being hit.
///
/// # Fix
/// Use `async with` context manager to ensure proper cleanup:
/// ```python
/// async with httpx.AsyncClient() as client:
///     response = await client.get(url)
/// ```
#[derive(Debug, Default)]
pub struct PythonAsyncResourceCleanupRule;

impl PythonAsyncResourceCleanupRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for PythonAsyncResourceCleanupRule {
    fn id(&self) -> &'static str {
        "python.async_resource_cleanup"
    }

    fn name(&self) -> &'static str {
        "Improper async resource cleanup"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(unbounded_resource())
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

            // Look for assignments that create async clients without context managers
            for assignment in &py.assignments {
                let value = &assignment.value_repr;
                
                // Check for httpx.AsyncClient() or aiohttp.ClientSession()
                let is_async_client = value.contains("httpx.AsyncClient(")
                    || value.contains("AsyncClient(")
                    || value.contains("aiohttp.ClientSession(")
                    || value.contains("ClientSession(");

                if !is_async_client {
                    continue;
                }

                // This is an async client assignment - check if it's inside an async with
                // For now, we flag all direct assignments as they should use context managers
                let target = &assignment.target;
                let location = &assignment.location;
                let line = location.range.start_line + 1; // Convert to 1-based

                // Generate a patch to wrap with async with
                let patch = generate_context_manager_patch(
                    *file_id,
                    target,
                    value,
                    line,
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!(
                        "Async client '{}' should use 'async with' context manager",
                        target
                    ),
                    description: Some(format!(
                        "The async client '{}' is assigned directly without using 'async with'. \
                        This can lead to leaked connections and file descriptor exhaustion. \
                        Use 'async with {} as {}:' to ensure proper cleanup.",
                        target, value, target
                    )),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.85,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: py.path.clone(),
                    line: Some(line),
                    column: Some(location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(format!(
                        "async with {} as {}:\n    # Use {} here",
                        value, target, target
                    )),
                    tags: vec!["async".to_string(), "resource-leak".to_string()],
                });
            }

            // Also check for calls that create async clients in function bodies
            // without being wrapped in async with
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;
                
                // Check for direct async client creation calls
                let is_async_client_call = callee == "httpx.AsyncClient"
                    || callee == "AsyncClient"
                    || callee == "aiohttp.ClientSession"
                    || callee == "ClientSession";

                if !is_async_client_call {
                    continue;
                }

                let call_line = call.function_call.location.line;

                // Check if this call is already part of an assignment we've flagged
                // by looking at the line
                let already_flagged = findings.iter().any(|f| {
                    f.file_id == *file_id
                        && f.line == Some(call_line)
                });

                if already_flagged {
                    continue;
                }

                // This is a standalone async client creation - flag it
                let patch = generate_standalone_call_patch(
                    *file_id,
                    callee,
                    call_line,
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!(
                        "Async client '{}' should use 'async with' context manager",
                        callee
                    ),
                    description: Some(format!(
                        "The async client '{}' is created without using 'async with'. \
                        This can lead to leaked connections and file descriptor exhaustion. \
                        Use 'async with {}() as client:' to ensure proper cleanup.",
                        callee, callee
                    )),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.85,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: py.path.clone(),
                    line: Some(call_line),
                    column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(format!(
                        "async with {}() as client:\n    # Use client here",
                        callee
                    )),
                    tags: vec!["async".to_string(), "resource-leak".to_string()],
                });
            }
        }

        findings
    }
}

/// Generate a patch to wrap an async client assignment with async with.
fn generate_context_manager_patch(
    file_id: FileId,
    target: &str,
    value: &str,
    line: u32,
) -> FilePatch {
    // Transform: client = httpx.AsyncClient()
    // Into: async with httpx.AsyncClient() as client:
    //           # Use client here - move your code inside this block
    //           pass
    
    let new_code = format!(
        "# TODO: Replace the line below with this context manager:\n\
         # async with {} as {}:\n\
         #     # Use {} here - move your code inside this block\n\
         #     pass\n",
        value, target, target
    );

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement: new_code,
        }],
    }
}

/// Generate a patch for standalone async client creation calls.
fn generate_standalone_call_patch(
    file_id: FileId,
    callee: &str,
    line: u32,
) -> FilePatch {
    let suggestion = format!(
        "# TODO: Use context manager instead:\n\
         # async with {}() as client:\n\
         #     # Use client here\n\
         #     pass\n",
        callee
    );

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement: suggestion,
        }],
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
    async fn detects_httpx_async_client_assignment() {
        let src = r#"
import httpx

async def fetch():
    client = httpx.AsyncClient()
    response = await client.get("https://example.com")
    return response
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect httpx.AsyncClient without context manager");
        assert!(findings[0].title.contains("AsyncClient") || findings[0].title.contains("client"));
    }

    #[tokio::test]
    async fn detects_aiohttp_client_session_assignment() {
        let src = r#"
import aiohttp

async def fetch():
    session = aiohttp.ClientSession()
    response = await session.get("https://example.com")
    return response
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect aiohttp.ClientSession without context manager");
    }

    #[tokio::test]
    async fn detects_short_form_async_client() {
        let src = r#"
from httpx import AsyncClient

async def fetch():
    client = AsyncClient()
    response = await client.get("https://example.com")
    return response
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect AsyncClient without context manager");
    }

    #[tokio::test]
    async fn detects_short_form_client_session() {
        let src = r#"
from aiohttp import ClientSession

async def fetch():
    session = ClientSession()
    response = await session.get("https://example.com")
    return response
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect ClientSession without context manager");
    }

    #[tokio::test]
    async fn detects_multiple_async_clients() {
        let src = r#"
import httpx
import aiohttp

async def fetch_all():
    http_client = httpx.AsyncClient()
    aio_session = aiohttp.ClientSession()
    # Use both clients
    return None
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert_eq!(findings.len(), 2, "Should detect both async clients");
    }

    // ==================== Negative Tests (Should Not Detect) ====================

    #[tokio::test]
    async fn ignores_sync_requests_client() {
        let src = r#"
import requests

def fetch():
    response = requests.get("https://example.com")
    return response
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(findings.is_empty(), "Should not flag sync requests library");
    }

    #[tokio::test]
    async fn ignores_sync_httpx_client() {
        let src = r#"
import httpx

def fetch():
    response = httpx.get("https://example.com")
    return response
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(findings.is_empty(), "Should not flag sync httpx calls");
    }

    #[tokio::test]
    async fn ignores_regular_assignments() {
        let src = r#"
x = 42
name = "hello"
data = {"key": "value"}
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(findings.is_empty(), "Should not flag regular assignments");
    }

    #[tokio::test]
    async fn ignores_empty_file() {
        let src = "";
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(findings.is_empty(), "Should not flag empty file");
    }

    // ==================== Patch Tests ====================

    #[tokio::test]
    async fn generates_patch_for_async_client() {
        let src = r#"
import httpx

async def fetch():
    client = httpx.AsyncClient()
    return await client.get("https://example.com")
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty());
        assert!(findings[0].patch.is_some(), "Should generate a patch");
        
        let patch = findings[0].patch.as_ref().unwrap();
        assert!(!patch.hunks.is_empty());
        assert!(patch.hunks[0].replacement.contains("async with"));
    }

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_has_correct_id() {
        let rule = PythonAsyncResourceCleanupRule::new();
        assert_eq!(rule.id(), "python.async_resource_cleanup");
    }

    #[test]
    fn rule_has_correct_name() {
        let rule = PythonAsyncResourceCleanupRule::new();
        assert_eq!(rule.name(), "Improper async resource cleanup");
    }

    #[tokio::test]
    async fn finding_has_correct_kind() {
        let src = r#"
import httpx

async def fetch():
    client = httpx.AsyncClient()
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty());
        assert!(matches!(findings[0].kind, FindingKind::StabilityRisk));
        assert!(matches!(findings[0].dimension, Dimension::Stability));
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn handles_async_client_with_params() {
        let src = r#"
import httpx

async def fetch():
    client = httpx.AsyncClient(timeout=30, verify=False)
    return await client.get("https://example.com")
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect AsyncClient with parameters");
    }

    #[tokio::test]
    async fn handles_client_session_with_params() {
        let src = r#"
import aiohttp

async def fetch():
    session = aiohttp.ClientSession(headers={"User-Agent": "test"})
    return await session.get("https://example.com")
"#;
        let (file_id, sem) = parse_and_analyze(src);
        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        assert!(!findings.is_empty(), "Should detect ClientSession with parameters");
    }

    #[tokio::test]
    async fn handles_multiple_files() {
        let src1 = r#"
import httpx

async def fetch1():
    client = httpx.AsyncClient()
"#;
        let src2 = r#"
import aiohttp

async def fetch2():
    session = aiohttp.ClientSession()
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

        let rule = PythonAsyncResourceCleanupRule::new();
        let findings = rule.evaluate(&semantics, None).await;

        assert_eq!(findings.len(), 2, "Should detect issues in both files");
    }
}