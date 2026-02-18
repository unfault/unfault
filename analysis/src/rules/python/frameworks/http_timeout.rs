use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::http::HttpClientKind;
use crate::types::context::Dimension;
use crate::types::finding::{
    Benefit, DecisionLevel, FindingApplicability, FindingKind, InvestmentLevel, LifecycleStage,
    Severity,
};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

#[derive(Debug)]
pub struct PythonHttpMissingTimeoutRule;

impl PythonHttpMissingTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for PythonHttpMissingTimeoutRule {
    fn id(&self) -> &'static str {
        "python.http.missing_timeout"
    }

    fn name(&self) -> &'static str {
        "HTTP client calls (requests/httpx) without explicit timeout configuration"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Low,
            min_stage: LifecycleStage::Prototype,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Reliability, Benefit::Latency],
            prerequisites: vec![],
            notes: Some("Time bounds are helpful even in demos; pick a sensible default.".to_string()),
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
                if call.has_timeout {
                    continue;
                }

                // Be explicit about which clients we support.
                let client_label = match call.client_kind {
                    HttpClientKind::Requests => "requests",
                    HttpClientKind::Httpx => "httpx",
                    HttpClientKind::Aiohttp => "aiohttp",
                    HttpClientKind::Other(ref s) => s.as_str(),
                };

                let (patched_call, changed) = insert_timeout_kwarg(&call.call_text);
                if !changed {
                    // If we somehow couldn't build a safe patch, degrade gracefully:
                    // emit a finding without a patch.
                    let location = call.location.range;
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: format!(
                            "HTTP call via `{client}`.{method} has no timeout",
                            client = client_label,
                            method = call.method_name
                        ),
                        description: Some(
                            "This HTTP client call does not specify a timeout. \
                             A timeout ensures the call completes within a known time bound, \
                             which helps maintain predictable response times for your service. \
                             Consider adding a `timeout=` parameter."
                                .to_string(),
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(location.start_line + 1),
                        column: Some(location.start_col + 1),
                        end_line: Some(location.end_line + 1),
                        end_column: Some(location.end_col + 1),
                        byte_range: None,
                        patch: None,
                        fix_preview: Some(format!(
                            "# Consider adding a timeout here:\n{}",
                            call.call_text
                        )),
                        tags: vec![
                            "python".into(),
                            "http".into(),
                            "timeout".into(),
                            client_label.into(),
                        ],
                    });

                    continue;
                }

                // We know we can safely patch this call: replace the call expression bytes.
                let location = call.location.range;

                let file_patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::ReplaceBytes {
                            start: call.start_byte,
                            end: call.end_byte,
                        },
                        replacement: patched_call.clone(),
                    }],
                };

                let fn_label = call.function_name.as_deref().unwrap_or("<function>");

                let title = format!(
                    "HTTP call via `{client}`.{method} has no timeout",
                    client = client_label,
                    method = call.method_name
                );

                let description = format!(
                    "This HTTP client call in `{fn_name}` does not specify a timeout. \
                     A timeout ensures the call completes within a known time bound, \
                     which helps maintain predictable response times for your service. \
                     Consider using a sensible timeout value tuned to your requirements.",
                    fn_name = fn_label,
                );

                let fix_preview = format!(
                    "# Before:\n#   {}\n# After:\n{}",
                    call.call_text.trim(),
                    patched_call.trim()
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.9,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: py.path.clone(),
                    line: Some(location.start_line + 1),
                    column: Some(location.start_col + 1),
                    end_line: Some(location.end_line + 1),
                    end_column: Some(location.end_col + 1),
                    byte_range: None,
                    patch: Some(file_patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "python".into(),
                        "http".into(),
                        "timeout".into(),
                        client_label.into(),
                    ],
                });
            }
        }

        findings
    }
}

/// Insert `timeout=5.0` into a Python call expression.
///
/// Examples:
///   "requests.get('https://x')" ->
///       "requests.get('https://x', timeout=5.0)"
///
///   "requests.get()" ->
///       "requests.get(timeout=5.0)"
///
///   Multi-line:
///   "requests.post(\n    'url',\n    data={},\n)" ->
///       "requests.post(\n    'url',\n    data={},\n    timeout=5.0,\n)"
///
/// Returns `(new_call, changed)`.
fn insert_timeout_kwarg(call: &str) -> (String, bool) {
    // We *should* only be called on calls without timeout, but be defensive.
    if call.contains("timeout=") {
        return (call.to_string(), false);
    }

    // Find the last closing parenthesis in the expression.
    let closing_idx = match call.rfind(')') {
        Some(idx) => idx,
        None => {
            // Fallback: cannot safely patch, but we can still suggest via comment.
            return (format!("{call}  # TODO: add timeout=5.0"), true);
        }
    };

    let (before_paren, after_paren) = call.split_at(closing_idx);

    // Check if this is a multi-line call by looking at what's before the closing paren
    let is_multiline = before_paren.contains('\n');

    // For multi-line calls, we need to handle indentation properly
    if is_multiline {
        let lines: Vec<&str> = before_paren.lines().collect();

        // Detect the base indentation from the arguments (second line)
        let arg_indent = if lines.len() > 1 {
            let second_line = lines.get(1).unwrap_or(&"");
            let indent_len = second_line.len() - second_line.trim_start().len();
            &second_line[..indent_len]
        } else {
            "    " // Default to 4 spaces
        };

        // Find the last non-empty line (the one with the last argument)
        let mut last_arg_idx = lines.len() - 1;
        while last_arg_idx > 0 && lines[last_arg_idx].trim().is_empty() {
            last_arg_idx -= 1;
        }

        let last_arg_line = lines[last_arg_idx];
        let last_arg_trimmed = last_arg_line.trim();

        // Detect the indentation of the closing paren line
        // The closing paren is at closing_idx, find what's before it on the same line
        let paren_line_start = before_paren.rfind('\n').map(|i| i + 1).unwrap_or(0);
        let paren_indent = &before_paren[paren_line_start..];

        let mut new_call = String::new();

        // Rebuild the call up to and including the last argument line
        for (i, line) in lines.iter().enumerate().take(last_arg_idx + 1) {
            new_call.push_str(line);
            if i < last_arg_idx {
                new_call.push('\n');
            }
        }

        // Add comma if needed
        if !last_arg_trimmed.ends_with(',') {
            new_call.push(',');
        }

        // Add timeout on new line with argument indentation
        new_call.push('\n');
        new_call.push_str(arg_indent);
        new_call.push_str("timeout=5.0,");
        new_call.push('\n');

        // Add back the closing paren with its original indentation
        new_call.push_str(paren_indent);
        new_call.push_str(after_paren); // add back ")"
        return (new_call, true);
    }

    // Single-line call handling
    let mut new_call = String::new();

    // Heuristic: if the part before the closing paren ends with "(" (ignoring space),
    // there are no arguments yet → no leading comma.
    if before_paren.trim_end().ends_with('(') {
        new_call.push_str(before_paren);
        new_call.push_str("timeout=5.0");
    } else {
        new_call.push_str(before_paren);
        new_call.push_str(", timeout=5.0");
    }

    new_call.push_str(after_paren); // add back ")"

    (new_call, true)
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
        let rule = PythonHttpMissingTimeoutRule::new();
        assert_eq!(rule.id(), "python.http.missing_timeout");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonHttpMissingTimeoutRule::new();
        assert!(rule.name().contains("timeout"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonHttpMissingTimeoutRule"));
    }

    // ==================== evaluate Tests - No Findings ====================

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_http_code() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_when_timeout_is_present() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) =
            parse_and_build_semantics("requests.get('https://example.com', timeout=30)");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_httpx_with_timeout() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) =
            parse_and_build_semantics("httpx.get('https://example.com', timeout=10)");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== evaluate Tests - With Findings ====================

    #[tokio::test]
    async fn evaluate_detects_missing_timeout_in_requests_get() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_detects_missing_timeout_in_requests_post() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) =
            parse_and_build_semantics("requests.post('https://example.com', data={})");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_detects_missing_timeout_in_httpx_get() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("httpx.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_rule_id() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings[0].rule_id, "python.http.missing_timeout");
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_severity() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].severity, Severity::Medium));
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_kind() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].kind, FindingKind::StabilityRisk));
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_dimension() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings[0].dimension, Dimension::Stability);
    }

    #[tokio::test]
    async fn evaluate_finding_includes_client_in_title() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].title.contains("requests"));
    }

    #[tokio::test]
    async fn evaluate_finding_includes_method_in_title() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.post('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].title.contains("post"));
    }

    #[tokio::test]
    async fn evaluate_finding_has_description() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].description.is_some());
        assert!(!findings[0].description.as_ref().unwrap().is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_has_tags() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].tags.contains(&"python".to_string()));
        assert!(findings[0].tags.contains(&"http".to_string()));
        assert!(findings[0].tags.contains(&"timeout".to_string()));
    }

    // ==================== evaluate Tests - Patch Generation ====================

    #[tokio::test]
    async fn evaluate_finding_includes_patch() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_patch_has_one_hunk() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let patch = findings[0].patch.as_ref().unwrap();
        assert_eq!(patch.hunks.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_finding_includes_fix_preview() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
    }

    #[tokio::test]
    async fn evaluate_fix_preview_contains_timeout() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let preview = findings[0].fix_preview.as_ref().unwrap();
        assert!(preview.contains("timeout"));
    }

    // ==================== evaluate Tests - Multiple Calls ====================

    #[tokio::test]
    async fn evaluate_detects_multiple_missing_timeouts() {
        let rule = PythonHttpMissingTimeoutRule::new();
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

    #[tokio::test]
    async fn evaluate_only_reports_calls_without_timeout() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let src = r#"
requests.get('https://example.com/a', timeout=30)
requests.post('https://example.com/b')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("post"));
    }

    // ==================== evaluate Tests - Function Context ====================

    #[tokio::test]
    async fn evaluate_includes_function_name_in_description() {
        let rule = PythonHttpMissingTimeoutRule::new();
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
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].line.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_column_number() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].column.is_some());
    }

    // ==================== evaluate Tests - Confidence ====================

    #[tokio::test]
    async fn evaluate_finding_has_reasonable_confidence() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].confidence >= 0.0);
        assert!(findings[0].confidence <= 1.0);
    }

    // ==================== insert_timeout_kwarg Tests ====================

    #[test]
    fn insert_timeout_adds_to_call_with_args() {
        let (result, changed) = insert_timeout_kwarg("requests.get('https://x')");
        assert!(changed);
        assert_eq!(result, "requests.get('https://x', timeout=5.0)");
    }

    #[test]
    fn insert_timeout_adds_to_empty_call() {
        let (result, changed) = insert_timeout_kwarg("requests.get()");
        assert!(changed);
        assert_eq!(result, "requests.get(timeout=5.0)");
    }

    #[test]
    fn insert_timeout_does_not_modify_if_already_present() {
        let (result, changed) = insert_timeout_kwarg("requests.get('https://x', timeout=30)");
        assert!(!changed);
        assert_eq!(result, "requests.get('https://x', timeout=30)");
    }

    #[test]
    fn insert_timeout_handles_multiple_args() {
        let (result, changed) =
            insert_timeout_kwarg("requests.post('https://x', data={}, headers={})");
        assert!(changed);
        assert!(result.contains("timeout=5.0"));
        assert!(result.ends_with(")"));
    }

    #[test]
    fn insert_timeout_handles_no_closing_paren() {
        let (result, changed) = insert_timeout_kwarg("requests.get('https://x'");
        assert!(changed);
        assert!(result.contains("TODO"));
    }

    #[test]
    fn insert_timeout_handles_httpx() {
        let (result, changed) = insert_timeout_kwarg("httpx.get('https://x')");
        assert!(changed);
        assert_eq!(result, "httpx.get('https://x', timeout=5.0)");
    }

    #[test]
    fn insert_timeout_handles_multiline_call() {
        let call = "requests.post(\n    'https://x',\n    data={}\n)";
        let (result, changed) = insert_timeout_kwarg(call);
        assert!(changed);
        assert!(result.contains("timeout=5.0"));
    }

    #[test]
    fn insert_timeout_handles_multiline_call_with_trailing_comma() {
        // This is the exact format from samples/fastapi-app/main.py lines 45-48
        // Note: tree-sitter captures the call starting from "requests.post("
        // The indentation is preserved relative to the start of the call
        let call = "requests.post(\n    \"https://api.example.com/webhook\",\n    json=data,\n)";
        let (result, changed) = insert_timeout_kwarg(call);
        assert!(changed);
        assert!(result.contains("timeout=5.0"));
        // The result should be valid Python - timeout should be on its own line
        // NOT: ", timeout=5.0)" on the same line as the closing paren
        println!("Input:\n{}", call);
        println!("Output:\n{}", result);
        // Verify the output is syntactically correct
        assert!(
            !result.contains(", timeout=5.0)"),
            "timeout should not be on same line as closing paren"
        );
        // The closing paren should be on its own line
        assert!(
            result.ends_with("\n)"),
            "closing paren should be on its own line"
        );
        // Verify exact expected output
        let expected = "requests.post(\n    \"https://api.example.com/webhook\",\n    json=data,\n    timeout=5.0,\n)";
        assert_eq!(
            result, expected,
            "Output should match expected format exactly"
        );
    }

    #[test]
    fn insert_timeout_multiline_without_trailing_comma() {
        // Multi-line call without trailing comma
        let call = "requests.post(\n    \"https://api.example.com/webhook\",\n    json=data\n)";
        let (result, changed) = insert_timeout_kwarg(call);
        assert!(changed);
        println!("Input:\n{}", call);
        println!("Output:\n{}", result);
        // Should add comma after json=data, then timeout on new line
        let expected = "requests.post(\n    \"https://api.example.com/webhook\",\n    json=data,\n    timeout=5.0,\n)";
        assert_eq!(
            result, expected,
            "Output should match expected format exactly"
        );
    }

    #[test]
    fn insert_timeout_handles_indented_multiline_call() {
        // This is the ACTUAL format when the call is inside a function with indentation
        // The call_text captured by tree-sitter preserves the relative indentation
        // from the source file. When the call is inside a function body:
        //     result = requests.post(
        //         "url",
        //         json=data,
        //     )
        // The captured call_text is:
        let call = "requests.post(\n        \"https://api.example.com/webhook\",\n        json=data,\n    )";
        let (result, changed) = insert_timeout_kwarg(call);
        assert!(changed);
        println!("Input:\n{}", call);
        println!("Output:\n{}", result);
        // The timeout should use the same indentation as the arguments (8 spaces)
        // The closing paren should stay at 4 spaces
        let expected = "requests.post(\n        \"https://api.example.com/webhook\",\n        json=data,\n        timeout=5.0,\n    )";
        assert_eq!(
            result, expected,
            "Output should match expected format exactly"
        );
    }

    #[test]
    fn insert_timeout_preserves_trailing_content() {
        let (result, changed) = insert_timeout_kwarg("requests.get('https://x')");
        assert!(changed);
        assert!(result.ends_with(")"));
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn evaluate_handles_empty_semantics() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_handles_empty_file() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Tests for aiohttp and Other client kinds ====================

    #[tokio::test]
    async fn evaluate_handles_aiohttp_client() {
        let rule = PythonHttpMissingTimeoutRule::new();

        // Create semantics with an aiohttp call manually
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: "x = 1".to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed)
            .expect("framework analysis should succeed");

        // Manually add an aiohttp call
        use crate::parse::ast::{AstLocation, TextRange};
        use crate::semantics::python::http::{HttpCallSite, HttpClientKind};

        sem.http_calls.push(HttpCallSite {
            client_kind: HttpClientKind::Aiohttp,
            method_name: "get".to_string(),
            call_text: "aiohttp.get('https://example.com')".to_string(),
            has_timeout: false,
            location: AstLocation {
                file_id,
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 34,
                },
            },
            function_name: None,
            in_async_function: false,
            is_thread_offloaded: false,
            start_byte: 0,
            end_byte: 34,
            retry_source: None,
        });

        let semantics = vec![(file_id, Arc::new(SourceSemantics::Python(sem)))];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].tags.contains(&"aiohttp".to_string()));
    }

    #[tokio::test]
    async fn evaluate_handles_other_client_kind() {
        let rule = PythonHttpMissingTimeoutRule::new();

        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: "x = 1".to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed)
            .expect("framework analysis should succeed");

        use crate::parse::ast::{AstLocation, TextRange};
        use crate::semantics::python::http::{HttpCallSite, HttpClientKind};

        sem.http_calls.push(HttpCallSite {
            client_kind: HttpClientKind::Other("custom_client".to_string()),
            method_name: "fetch".to_string(),
            call_text: "custom_client.fetch('https://example.com')".to_string(),
            has_timeout: false,
            location: AstLocation {
                file_id,
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 42,
                },
            },
            function_name: None,
            in_async_function: false,
            is_thread_offloaded: false,
            start_byte: 0,
            end_byte: 42,
            retry_source: None,
        });

        let semantics = vec![(file_id, Arc::new(SourceSemantics::Python(sem)))];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].tags.contains(&"custom_client".to_string()));
    }

    // ==================== Tests for fallback path when patch can't be built ====================

    #[tokio::test]
    async fn evaluate_finding_without_patch_when_timeout_already_present_in_text() {
        let rule = PythonHttpMissingTimeoutRule::new();

        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: "x = 1".to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed)
            .expect("framework analysis should succeed");

        use crate::parse::ast::{AstLocation, TextRange};
        use crate::semantics::python::http::{HttpCallSite, HttpClientKind};

        // Create a call where call_text contains "timeout=" but has_timeout is false
        // This simulates a case where our detection might be inconsistent
        sem.http_calls.push(HttpCallSite {
            client_kind: HttpClientKind::Requests,
            method_name: "get".to_string(),
            call_text: "requests.get('https://example.com', timeout=30)".to_string(),
            has_timeout: false, // Inconsistent with call_text for testing
            location: AstLocation {
                file_id,
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 47,
                },
            },
            function_name: Some("fetch_data".to_string()),
            in_async_function: false,
            is_thread_offloaded: false,
            start_byte: 0,
            end_byte: 47,
            retry_source: None,
        });

        let semantics = vec![(file_id, Arc::new(SourceSemantics::Python(sem)))];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        // The patch should be None because insert_timeout_kwarg returns changed=false
        assert!(findings[0].patch.is_none());
        // But fix_preview should still be present
        assert!(findings[0].fix_preview.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_tags_for_requests() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("requests.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].tags.contains(&"requests".to_string()));
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_tags_for_httpx() {
        let rule = PythonHttpMissingTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics("httpx.get('https://example.com')");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].tags.contains(&"httpx".to_string()));
    }
}
