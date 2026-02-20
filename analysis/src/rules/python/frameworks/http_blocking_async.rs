use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::http::HttpClientKind;
use crate::semantics::python::model::{ImportInsertionType, PyImport};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

#[derive(Debug)]
pub struct PythonHttpBlockingInAsyncRule;

impl PythonHttpBlockingInAsyncRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for PythonHttpBlockingInAsyncRule {
    fn id(&self) -> &'static str {
        "python.http.blocking_in_async"
    }

    fn name(&self) -> &'static str {
        "Detects blocking HTTP calls (requests) inside async functions."
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

            for call in &py.http_calls {
                if !call.in_async_function {
                    continue;
                }

                // Skip calls that are already offloaded to a thread
                // (e.g., wrapped in asyncio.to_thread or loop.run_in_executor)
                if call.is_thread_offloaded {
                    continue;
                }

                // For now we treat `requests` as clearly blocking; `httpx` is more nuanced
                // (sync vs async client), so we skip it here to avoid false positives.
                match call.client_kind {
                    HttpClientKind::Requests => {
                        let location = call.location.range;

                        let fn_label = call.function_name.as_deref().unwrap_or("<async function>");

                        let title = format!(
                            "Blocking HTTP call via `requests.{}` inside async function `{}`",
                            call.method_name, fn_label
                        );

                        let description = format!(
                            "This async function `{fn_name}` invokes a blocking HTTP call using \
                             the `requests` library. Blocking calls inside `async def` handlers \
                             can stall the event loop, increase tail latency, and reduce \
                             overall concurrency. Consider using an async HTTP client \
                             (e.g. `httpx.AsyncClient`) or offloading this to a thread pool.",
                            fn_name = fn_label,
                        );

                        // Generate patch to wrap with asyncio.to_thread
                        // Use stdlib_import() for `import asyncio` placement
                        let import_line =
                            py.import_insertion_line_for(ImportInsertionType::stdlib_import());
                        let patch = generate_to_thread_patch(
                            &call.call_text,
                            call.start_byte,
                            call.end_byte,
                            *file_id,
                            &py.imports,
                            import_line,
                        );

                        let fix_preview = format!(
                            "# Before (blocking):\n\
                             #   {}\n\
                             # After (non-blocking):\n\
                             #   await asyncio.to_thread(lambda: {})",
                            call.call_text.trim(),
                            call.call_text.trim(),
                        );

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::High,
                            confidence: 0.9,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(location.start_line + 1),
                            column: Some(location.start_col + 1),
                            end_line: Some(location.end_line + 1),
                            end_column: Some(location.end_col + 1),
                            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(fix_preview),
                            tags: vec![
                                "python".into(),
                                "http".into(),
                                "async".into(),
                                "blocking".into(),
                                "requests".into(),
                            ],
                        });
                    }
                    _ => {
                        // httpx and others: we'd need more nuance to avoid false positives.
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
    }
}

/// Check if asyncio is already imported
fn has_asyncio_import(imports: &[PyImport]) -> bool {
    imports
        .iter()
        .any(|imp| imp.module == "asyncio" || imp.names.iter().any(|n| n == "asyncio"))
}

/// Generate a patch to wrap a blocking call with asyncio.to_thread
fn generate_to_thread_patch(
    call_text: &str,
    start_byte: usize,
    end_byte: usize,
    file_id: FileId,
    imports: &[PyImport],
    import_insertion_line: u32,
) -> FilePatch {
    let mut hunks = Vec::new();

    // Only add asyncio import if not already present
    if !has_asyncio_import(imports) {
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine {
                line: import_insertion_line,
            },
            replacement: "import asyncio  # Added by unfault for to_thread\n".to_string(),
        });
    }

    // Wrap the blocking call with asyncio.to_thread using a lambda
    // This preserves the original call syntax while making it non-blocking
    // requests.get(url, timeout=5) -> await asyncio.to_thread(lambda: requests.get(url, timeout=5))
    let replacement = format!("await asyncio.to_thread(lambda: {})", call_text.trim());

    hunks.push(PatchHunk {
        range: PatchRange::ReplaceBytes {
            start: start_byte,
            end: end_byte,
        },
        replacement,
    });

    FilePatch { file_id, hunks }
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
        let rule = PythonHttpBlockingInAsyncRule::new();
        assert_eq!(rule.id(), "python.http.blocking_in_async");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        assert!(rule.name().contains("blocking"));
        assert!(rule.name().contains("async"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonHttpBlockingInAsyncRule"));
    }

    // ==================== evaluate Tests - No Findings ====================

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_http_code() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_sync_function() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
def fetch_data():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_module_level_requests() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let (file_id, sem) =
            parse_and_build_semantics("response = requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_httpx_in_async() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch_data():
    return httpx.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        // httpx is not flagged because it can be used async
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== evaluate Tests - With Findings ====================

    #[tokio::test]
    async fn evaluate_detects_requests_get_in_async_function() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch_data():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_detects_requests_post_in_async_function() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def send_data():
    return requests.post('https://example.com', data={})
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_rule_id() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings[0].rule_id, "python.http.blocking_in_async");
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_severity() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].severity, Severity::High));
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_kind() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].kind, FindingKind::PerformanceSmell));
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_dimension() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings[0].dimension, Dimension::Stability);
    }

    #[tokio::test]
    async fn evaluate_finding_includes_function_name_in_title() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def my_async_handler():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].title.contains("my_async_handler"));
    }

    #[tokio::test]
    async fn evaluate_finding_includes_method_in_title() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.post('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].title.contains("post"));
    }

    #[tokio::test]
    async fn evaluate_finding_has_description() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].description.is_some());
        assert!(!findings[0].description.as_ref().unwrap().is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_description_mentions_event_loop() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let desc = findings[0].description.as_ref().unwrap();
        assert!(desc.contains("event loop") || desc.contains("blocking"));
    }

    #[tokio::test]
    async fn evaluate_finding_has_tags() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].tags.contains(&"python".to_string()));
        assert!(findings[0].tags.contains(&"http".to_string()));
        assert!(findings[0].tags.contains(&"async".to_string()));
        assert!(findings[0].tags.contains(&"blocking".to_string()));
    }

    // ==================== evaluate Tests - Has Patch ====================

    #[tokio::test]
    async fn evaluate_finding_has_patch() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // This rule now auto-fixes with asyncio.to_thread
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_patch_contains_to_thread() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let patch = findings[0].patch.as_ref().unwrap();

        // Should have import hunk and replacement hunk
        assert_eq!(patch.hunks.len(), 2);

        // Check that the replacement contains to_thread
        let has_to_thread = patch
            .hunks
            .iter()
            .any(|h| h.replacement.contains("to_thread"));
        assert!(has_to_thread, "Patch should use asyncio.to_thread");
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
    }

    #[tokio::test]
    async fn evaluate_fix_preview_suggests_async_client() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let preview = findings[0].fix_preview.as_ref().unwrap();
        assert!(preview.contains("async") || preview.contains("httpx"));
    }

    // ==================== evaluate Tests - Multiple Calls ====================

    #[tokio::test]
    async fn evaluate_detects_multiple_blocking_calls() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch_all():
    a = requests.get('https://example.com/a')
    b = requests.post('https://example.com/b')
    return a, b
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 2);
    }

    #[tokio::test]
    async fn evaluate_detects_calls_in_multiple_async_functions() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch_a():
    return requests.get('https://example.com/a')

async def fetch_b():
    return requests.get('https://example.com/b')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 2);
    }

    // ==================== evaluate Tests - Mixed Scenarios ====================

    #[tokio::test]
    async fn evaluate_only_flags_async_functions() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
def sync_fetch():
    return requests.get('https://example.com/sync')

async def async_fetch():
    return requests.get('https://example.com/async')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Only the async function should be flagged
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("async_fetch"));
    }

    // ==================== evaluate Tests - Location ====================

    #[tokio::test]
    async fn evaluate_finding_has_line_number() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].line.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_column_number() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].column.is_some());
    }

    // ==================== evaluate Tests - Confidence ====================

    #[tokio::test]
    async fn evaluate_finding_has_high_confidence() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].confidence >= 0.8);
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn evaluate_handles_empty_semantics() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_handles_empty_file() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_handles_async_class_method() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
class Client:
    async def fetch(self):
        return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    // ==================== Thread Offloading Tests ====================

    #[tokio::test]
    async fn evaluate_skips_calls_wrapped_in_asyncio_to_thread() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    return await asyncio.to_thread(lambda: requests.get('https://example.com'))
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // The call is wrapped in asyncio.to_thread, so it's no longer blocking
        assert!(
            findings.is_empty(),
            "Should not flag calls wrapped in asyncio.to_thread"
        );
    }

    #[tokio::test]
    async fn evaluate_skips_calls_in_run_in_executor() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
async def fetch():
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: requests.get('https://example.com'))
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // The call is wrapped in run_in_executor, so it's no longer blocking
        assert!(
            findings.is_empty(),
            "Should not flag calls wrapped in run_in_executor"
        );
    }

    #[tokio::test]
    async fn evaluate_skips_calls_in_sync_to_async() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        let src = r#"
from asgiref.sync import sync_to_async

async def fetch():
    return await sync_to_async(lambda: requests.get('https://example.com'))()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // The call is wrapped in sync_to_async, so it's no longer blocking
        assert!(
            findings.is_empty(),
            "Should not flag calls wrapped in sync_to_async"
        );
    }

    #[tokio::test]
    async fn evaluate_still_flags_direct_calls_not_wrapped() {
        let rule = PythonHttpBlockingInAsyncRule::new();
        // Simplified test with just two separate async functions
        let src = r#"
async def wrapped_fetch():
    return await asyncio.to_thread(lambda: requests.get('https://example.com/safe'))

async def direct_fetch():
    return requests.get('https://example.com/blocking')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Only the direct call should be flagged (not the wrapped one)
        assert_eq!(
            findings.len(),
            1,
            "Should only flag the direct blocking call"
        );
        assert!(
            findings[0].title.contains("direct_fetch"),
            "Should flag the direct call in direct_fetch"
        );
    }
}
