use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::http::HttpClientKind;
use crate::semantics::python::model::PyImport;
use crate::types::context::Dimension;
use crate::types::finding::{
    Benefit, DecisionLevel, FindingApplicability, FindingKind, InvestmentLevel, LifecycleStage,
    Severity,
};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Check if tenacity retry imports are already present
fn has_tenacity_retry_imports(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| {
        imp.module == "tenacity" && imp.names.iter().any(|n| {
            n == "retry" || n == "stop_after_attempt" || n == "wait_exponential"
        })
    })
}

/// Information needed to generate a retry patch
struct RetryPatchContext<'a> {
    /// Line number where imports should be inserted (after docstring or at line 1)
    import_line: u32,
    /// Line number of the function definition (for decorator insertion)
    function_def_line: Option<u32>,
    /// Whether the function is async
    is_async: bool,
    /// Existing imports in the file
    imports: &'a [PyImport],
}

/// Rule A4: HTTP clients without retry policy
///
/// Detects HTTP client calls that don't have any retry mechanism configured.
/// Transient network failures can propagate as user-visible errors without retries.
#[derive(Debug)]
pub struct PythonHttpMissingRetryRule;

impl PythonHttpMissingRetryRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for PythonHttpMissingRetryRule {
    fn id(&self) -> &'static str {
        "python.http.missing_retry"
    }

    fn name(&self) -> &'static str {
        "Flags HTTP client calls without a retry policy, and suggests adding retry mechanisms."
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Medium,
            min_stage: LifecycleStage::Product,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Reliability],
            prerequisites: vec![
                "Only retry idempotent operations (or add idempotency keys)".to_string(),
                "Define which failures are retryable and apply backoff + max attempts".to_string(),
            ],
            notes: Some("Retries can increase load during outages; tune carefully and measure.".to_string()),
        })
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
                // Skip if retry is already configured
                if call.retry_source.is_some() {
                    continue;
                }

                let client_label = match call.client_kind {
                    HttpClientKind::Requests => "requests",
                    HttpClientKind::Httpx => "httpx",
                    HttpClientKind::Aiohttp => "aiohttp",
                    HttpClientKind::Other(ref s) => s.as_str(),
                };

                let location = call.location.range;
                let fn_label = call.function_name.as_deref().unwrap_or("<module>");

                let title = format!(
                    "HTTP call via `{client}`.{method} has no retry policy",
                    client = client_label,
                    method = call.method_name
                );

                let description = format!(
                    "This HTTP client call in `{fn_name}` does not have a retry mechanism. \
                     Transient network failures (connection timeouts, 5xx errors, DNS issues) \
                     will propagate directly as user-visible errors. Consider adding a retry \
                     policy using tenacity, backoff, or urllib3.Retry with HTTPAdapter.",
                    fn_name = fn_label,
                );

                let fix_preview = generate_fix_preview(&call.call_text, client_label);

                // Build patch context from semantics
                let patch_ctx = RetryPatchContext {
                    // Use docstring end line + 1, or line 1 if no docstring
                    import_line: py.module_docstring_end_line.map(|l| l + 1).unwrap_or(1),
                    // We need the function definition line to add decorator
                    function_def_line: call.function_name.as_ref().and_then(|fn_name| {
                        py.functions.iter()
                            .find(|f| &f.name == fn_name)
                            .map(|f| f.location.range.start_line + 1) // Convert 0-indexed to 1-indexed
                    }),
                    is_async: call.in_async_function,
                    imports: &py.imports,
                };

                // Generate client-specific patch with semantically sound hunks
                let file_patch = generate_retry_patch(client_label, *file_id, &patch_ctx);

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
                    line: Some(location.start_line + 1),
                    column: Some(location.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(file_patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "python".into(),
                        "http".into(),
                        "retry".into(),
                        "resilience".into(),
                        client_label.into(),
                    ],
                });
            }
        }

        findings
    }
}

/// Generate client-specific retry patch with semantically sound hunks.
///
/// For retry, the proper fix is:
/// 1. Add tenacity import after the module docstring (or at line 1) - only if not already present
/// 2. Add @retry decorator before the function definition
fn generate_retry_patch(client: &str, file_id: FileId, ctx: &RetryPatchContext) -> FilePatch {
    let mut hunks = Vec::new();
    
    // Hunk 1: Add tenacity import after docstring (only if not already present)
    if !has_tenacity_retry_imports(ctx.imports) {
        let import_str = "from tenacity import retry, stop_after_attempt, wait_exponential\n";
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: ctx.import_line },
            replacement: import_str.to_string(),
        });
    }
    
    // Hunk 2: Add @retry decorator before the function definition (if we know it)
    if let Some(fn_line) = ctx.function_def_line {
        let decorator = if ctx.is_async {
            // For async functions, tenacity works the same way
            "@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))\n"
        } else {
            "@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))\n"
        };
        
        // Add client-specific comment
        let comment = match client {
            "requests" => "# Retry policy added for requests HTTP calls\n",
            "httpx" => "# Retry policy added for httpx HTTP calls\n",
            "aiohttp" => "# Retry policy added for aiohttp HTTP calls\n",
            _ => "# Retry policy added for HTTP calls\n",
        };
        
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: fn_line },
            replacement: format!("{}{}", comment, decorator),
        });
    }
    
    FilePatch { file_id, hunks }
}

/// Generate a fix preview showing how to add retry to the HTTP call.
fn generate_fix_preview(call_text: &str, client: &str) -> String {
    match client {
        "requests" => format!(
            r#"# Option 1: Use tenacity decorator
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def make_request():
    {}

# Option 2: Use requests Session with HTTPAdapter
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)
# Then use session.get(), session.post(), etc."#,
            call_text.trim()
        ),
        "httpx" => format!(
            r#"# Option 1: Use tenacity decorator
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
async def make_request():
    {}

# Option 2: Use httpx with transport retries
import httpx

transport = httpx.HTTPTransport(retries=3)
client = httpx.Client(transport=transport)
# Then use client.get(), client.post(), etc."#,
            call_text.trim()
        ),
        _ => format!(
            r#"# Consider adding retry logic using tenacity:
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))
def make_request():
    {}"#,
            call_text.trim()
        ),
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
        let rule = PythonHttpMissingRetryRule::new();
        assert_eq!(rule.id(), "python.http.missing_retry");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonHttpMissingRetryRule::new();
        assert!(rule.name().contains("retry"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonHttpMissingRetryRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonHttpMissingRetryRule"));
    }

    // ==================== evaluate Tests - No Findings ====================

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_http_code() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_tenacity_decorator_present() {
        let rule = PythonHttpMissingRetryRule::new();
        let src = r#"
from tenacity import retry

@retry
def fetch_data():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not flag calls with @retry decorator");
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_tenacity_retry_decorator_present() {
        let rule = PythonHttpMissingRetryRule::new();
        let src = r#"
import tenacity

@tenacity.retry(stop=tenacity.stop_after_attempt(3))
def fetch_data():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not flag calls with @tenacity.retry decorator");
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_backoff_decorator_present() {
        let rule = PythonHttpMissingRetryRule::new();
        let src = r#"
import backoff

@backoff.on_exception(backoff.expo, Exception)
def fetch_data():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not flag calls with @backoff decorator");
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_session_retry_configured() {
        let rule = PythonHttpMissingRetryRule::new();
        let src = r#"
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

session = requests.Session()
retry_strategy = Retry(total=3, backoff_factor=1)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount("https://", adapter)

def fetch_data():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not flag calls when session retry is configured");
    }

    // ==================== evaluate Tests - With Findings ====================

    #[tokio::test]
    async fn evaluate_detects_missing_retry_in_requests_get() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_detects_missing_retry_in_requests_post() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) =
            parse_and_build_semantics("requests.post('https://example.com', data={})");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_detects_missing_retry_in_httpx_get() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("httpx.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_rule_id() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings[0].rule_id, "python.http.missing_retry");
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_severity() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].severity, Severity::Medium));
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_kind() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].kind, FindingKind::StabilityRisk));
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_dimension() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings[0].dimension, Dimension::Stability);
    }

    #[tokio::test]
    async fn evaluate_finding_includes_client_in_title() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].title.contains("requests"));
    }

    #[tokio::test]
    async fn evaluate_finding_includes_method_in_title() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.post('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].title.contains("post"));
    }

    #[tokio::test]
    async fn evaluate_finding_has_description() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].description.is_some());
        assert!(!findings[0].description.as_ref().unwrap().is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_description_mentions_retry() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let desc = findings[0].description.as_ref().unwrap();
        assert!(desc.contains("retry") || desc.contains("Retry"));
    }

    #[tokio::test]
    async fn evaluate_finding_has_tags() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].tags.contains(&"python".to_string()));
        assert!(findings[0].tags.contains(&"http".to_string()));
        assert!(findings[0].tags.contains(&"retry".to_string()));
        assert!(findings[0].tags.contains(&"resilience".to_string()));
    }

    // ==================== evaluate Tests - Patch ====================

    #[tokio::test]
    async fn evaluate_finding_has_patch() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_patch_has_two_hunks_when_in_function() {
        let rule = PythonHttpMissingRetryRule::new();
        // Code with a function context - should have 2 hunks (import + decorator)
        let src = r#"
def fetch_data():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let patch = findings[0].patch.as_ref().unwrap();
        assert_eq!(patch.hunks.len(), 2, "Should have import hunk + decorator hunk");
    }

    #[tokio::test]
    async fn evaluate_finding_patch_has_one_hunk_when_module_level() {
        let rule = PythonHttpMissingRetryRule::new();
        // Module-level call - only import hunk (no function to decorate)
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let patch = findings[0].patch.as_ref().unwrap();
        assert_eq!(patch.hunks.len(), 1, "Should only have import hunk for module-level calls");
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
    }

    #[tokio::test]
    async fn evaluate_fix_preview_suggests_tenacity() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let preview = findings[0].fix_preview.as_ref().unwrap();
        assert!(preview.contains("tenacity") || preview.contains("retry"));
    }

    // ==================== evaluate Tests - Multiple Calls ====================

    #[tokio::test]
    async fn evaluate_detects_multiple_missing_retries() {
        let rule = PythonHttpMissingRetryRule::new();
        let src = r#"
requests.get('https://example.com/a')
requests.post('https://example.com/b')
httpx.get('https://example.com/c')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 3);
    }

    // ==================== evaluate Tests - Function Context ====================

    #[tokio::test]
    async fn evaluate_includes_function_name_in_description() {
        let rule = PythonHttpMissingRetryRule::new();
        let src = r#"
def fetch_data():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        let desc = findings[0].description.as_ref().unwrap();
        assert!(desc.contains("fetch_data"));
    }

    // ==================== evaluate Tests - Location ====================

    #[tokio::test]
    async fn evaluate_finding_has_line_number() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].line.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_column_number() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].column.is_some());
    }

    // ==================== evaluate Tests - Confidence ====================

    #[tokio::test]
    async fn evaluate_finding_has_reasonable_confidence() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].confidence >= 0.0);
        assert!(findings[0].confidence <= 1.0);
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn evaluate_handles_empty_semantics() {
        let rule = PythonHttpMissingRetryRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_handles_empty_file() {
        let rule = PythonHttpMissingRetryRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Patch Content Tests ====================

    #[tokio::test]
    async fn evaluate_patch_imports_after_docstring() {
        let rule = PythonHttpMissingRetryRule::new();
        let src = r#""""Sample module docstring.

This is a multi-line docstring.
"""

def fetch_data():
    return requests.get('https://example.com')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        
        let patch = findings[0].patch.as_ref().unwrap();
        assert_eq!(patch.hunks.len(), 2);
        
        // First hunk should insert imports after docstring (line 5 = after line 4 which is """)
        let import_hunk = &patch.hunks[0];
        if let PatchRange::InsertBeforeLine { line } = import_hunk.range {
            assert!(line > 1, "Import should be after docstring, not at line 1");
            assert!(import_hunk.replacement.contains("tenacity"));
        } else {
            panic!("Expected InsertBeforeLine for import hunk");
        }
        
        // Second hunk should add decorator before function
        let decorator_hunk = &patch.hunks[1];
        if let PatchRange::InsertBeforeLine { line } = decorator_hunk.range {
            assert!(line > 4, "Decorator should be before function definition");
            assert!(decorator_hunk.replacement.contains("@retry"));
        } else {
            panic!("Expected InsertBeforeLine for decorator hunk");
        }
    }

    #[tokio::test]
    async fn evaluate_patch_decorator_before_function() {
        let rule = PythonHttpMissingRetryRule::new();
        let src = r#"
async def handle_webhook(data):
    result = requests.post("https://api.example.com/webhook", json=data)
    return result
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        
        let patch = findings[0].patch.as_ref().unwrap();
        assert_eq!(patch.hunks.len(), 2);
        
        // Decorator hunk should contain @retry
        let decorator_hunk = &patch.hunks[1];
        assert!(decorator_hunk.replacement.contains("@retry"));
        assert!(decorator_hunk.replacement.contains("stop_after_attempt"));
    }

    // ==================== generate_fix_preview Tests ====================

    #[test]
    fn fix_preview_for_requests_includes_tenacity() {
        let preview = generate_fix_preview("requests.get('https://example.com')", "requests");
        assert!(preview.contains("tenacity"));
    }

    #[test]
    fn fix_preview_for_requests_includes_http_adapter() {
        let preview = generate_fix_preview("requests.get('https://example.com')", "requests");
        assert!(preview.contains("HTTPAdapter"));
    }

    #[test]
    fn fix_preview_for_httpx_includes_transport() {
        let preview = generate_fix_preview("httpx.get('https://example.com')", "httpx");
        assert!(preview.contains("HTTPTransport"));
    }

    #[test]
    fn fix_preview_for_unknown_client_includes_tenacity() {
        let preview = generate_fix_preview("custom.get('https://example.com')", "custom");
        assert!(preview.contains("tenacity"));
    }
}
