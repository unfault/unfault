//! Rule: Missing async timeout detection
//!
//! Detects async operations that should have timeout wrappers to prevent
//! indefinite blocking on external resources.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! async fn fetch_data() {
//!     let response = client.get(url).send().await?;  // No timeout
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! async fn fetch_data() {
//!     let response = tokio::time::timeout(
//!         Duration::from_secs(30),
//!         client.get(url).send()
//!     ).await??;
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::rust::RustFileSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{
    Benefit, DecisionLevel, FindingApplicability, FindingKind, InvestmentLevel, LifecycleStage,
    Severity,
};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Check if tokio::time timeout is already imported
fn has_tokio_timeout_import(rust: &RustFileSemantics) -> bool {
    rust.uses.iter().any(|u| {
        u.path.contains("tokio::time::timeout")
            || u.path.contains("tokio::time::{")
            || (u.path == "tokio::time" && u.path.contains("timeout"))
    })
}

/// Rule that detects async operations without timeout wrappers.
///
/// Async operations that call external services (HTTP, database, etc.)
/// should have timeouts to prevent indefinite blocking.
#[derive(Debug, Default)]
pub struct RustMissingAsyncTimeoutRule;

impl RustMissingAsyncTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

/// Patterns that indicate external async calls needing timeouts
const EXTERNAL_CALL_PATTERNS: &[&str] = &[
    ".send().await",
    ".get(",
    ".post(",
    ".put(",
    ".delete(",
    ".patch(",
    ".query(",
    ".execute(",
    ".fetch(",
    ".fetch_one(",
    ".fetch_all(",
    ".fetch_optional(",
    ".connect(",
    ".accept(",
    "TcpStream::connect",
    "UdpSocket::bind",
    "lookup_host",
];

/// Patterns that indicate timeout is already applied
const TIMEOUT_PATTERNS: &[&str] = &[
    "timeout(",
    "timeout::",
    "tokio::time::timeout",
    "async_std::future::timeout",
    "futures_time::timeout",
    "with_timeout",
    "timeout_at",
];

#[async_trait]
impl Rule for RustMissingAsyncTimeoutRule {
    fn id(&self) -> &'static str {
        "rust.missing_async_timeout"
    }

    fn name(&self) -> &'static str {
        "Async operation without timeout may hang indefinitely"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::Low,
            min_stage: LifecycleStage::Prototype,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Reliability, Benefit::Latency],
            prerequisites: vec!["Pick sensible time budgets for operations".to_string()],
            notes: Some(
                "Timeouts are almost always appropriate; tune values as the service matures."
                    .to_string(),
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

            // Check async functions for calls without timeout
            for func in &rust.functions {
                if !func.is_async {
                    continue;
                }

                // Best-effort: detect client-level timeout configuration.
                //
                // Many Rust HTTP clients (notably reqwest) support configuring a timeout on the
                // client/builder (e.g., `reqwest::Client::builder().timeout(...)`). In that case,
                // the awaited send expression won't contain `timeout(...)`, and we should not
                // insist on a `tokio::time::timeout` wrapper.
                //
                // We check if:
                // 1. There's a `timeout` method call in the file (on any callee)
                // 2. The file has reqwest usage (either via imports or via fully-qualified calls)
                let file_has_reqwest_timeout =
                    rust.calls
                        .iter()
                        .any(|c| c.method_name.as_deref() == Some("timeout"))
                        && (rust.uses.iter().any(|u| {
                            u.path.contains("reqwest") || u.path.starts_with("reqwest::")
                        }) || rust
                            .calls
                            .iter()
                            .any(|c| c.function_call.callee_expr.contains("reqwest::")));

                // Check await points in the function
                for await_point in &rust.async_info.await_points {
                    // Skip if not in this function
                    if await_point.function_name.as_deref() != Some(&func.name) {
                        continue;
                    }

                    let expr = &await_point.expr;

                    // Check if this is an external call pattern
                    let is_external_call = EXTERNAL_CALL_PATTERNS.iter().any(|p| expr.contains(p));

                    if !is_external_call {
                        continue;
                    }

                    // Check if timeout is already applied
                    let has_timeout = TIMEOUT_PATTERNS.iter().any(|p| expr.contains(p));

                    // Treat reqwest client-level `.timeout(...)` as satisfying the requirement.
                    //
                    // Note: formatting can split `.send()` and `.await` across lines.
                    let looks_like_send_await = expr.contains(".send(")
                        || expr.contains(".send()")
                        || expr.contains(".send\n");
                    let has_timeout =
                        has_timeout || (file_has_reqwest_timeout && looks_like_send_await);

                    if has_timeout {
                        continue;
                    }

                    let line = await_point.location.range.start_line + 1;

                    let title = format!("Async operation without timeout in '{}'", func.name);

                    let description = format!(
                        "The async call at line {} does not have a timeout wrapper.\n\n\
                        **Why this is risky:**\n\
                        - External services can become unresponsive\n\
                        - Without timeout, the call hangs indefinitely\n\
                        - Blocked tasks exhaust connection pools\n\
                        - Cascading failures affect the entire service\n\n\
                        **Recommended fix:**\n\
                        ```rust\n\
                        use tokio::time::{{timeout, Duration}};\n\
                        \n\
                        let result = timeout(\n\
                            Duration::from_secs(30),\n\
                            async_operation()\n\
                        ).await?;\n\
                        ```",
                        line
                    );

                    let fix_preview = format!(
                        "// Before (no timeout):\n\
                        let result = {}.await?;\n\n\
                        // After (with timeout):\n\
                        use tokio::time::{{timeout, Duration}};\n\
                        let result = timeout(\n\
                            Duration::from_secs(30),\n\
                            {}\n\
                        ).await??;",
                        expr.replace(".await", ""),
                        expr.replace(".await", "")
                    );

                    let mut hunks = Vec::new();

                    // Only add import if not already present
                    if !has_tokio_timeout_import(rust) {
                        hunks.push(PatchHunk {
                            range: PatchRange::InsertBeforeLine { line: 1 },
                            replacement: "use tokio::time::{timeout, Duration};\n".to_string(),
                        });
                    }

                    hunks.push(PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Add timeout wrapper around this async call\n"
                            .to_string(),
                    });

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks,
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.80,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: rust.path.clone(),
                        line: Some(line),
                        column: Some(await_point.location.range.start_col + 1),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "rust".into(),
                            "async".into(),
                            "timeout".into(),
                            "stability".into(),
                        ],
                    });
                }
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
    use crate::semantics::SourceSemantics;
    use crate::semantics::rust::build_rust_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "async_code.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_rust_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Rust(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = RustMissingAsyncTimeoutRule::new();
        assert_eq!(rule.id(), "rust.missing_async_timeout");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustMissingAsyncTimeoutRule::new();
        assert!(rule.name().contains("timeout"));
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = RustMissingAsyncTimeoutRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_sync_functions() {
        let rule = RustMissingAsyncTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn sync_fn() {
    let x = 1;
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn flags_reqwest_send_without_timeout() {
        let rule = RustMissingAsyncTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use reqwest;

async fn fetch(url: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::new();
    let _resp = client.get(url).send().await?;
    Ok(())
}
"#,
        );
        let findings = rule.evaluate(&vec![(file_id, sem)], None).await;
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "rust.missing_async_timeout"),
            "should flag reqwest send().await without timeout"
        );
    }

    #[tokio::test]
    async fn does_not_flag_reqwest_send_when_client_has_timeout() {
        let rule = RustMissingAsyncTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::time::Duration;
use reqwest;

async fn fetch(url: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let _resp = client.get(url).send().await?;
    Ok(())
}
"#,
        );
        let findings = rule.evaluate(&vec![(file_id, sem)], None).await;
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "rust.missing_async_timeout"),
            "should not flag when reqwest client is configured with timeout"
        );
    }

    #[tokio::test]
    async fn does_not_flag_reqwest_send_when_client_has_timeout_and_send_await_split_lines() {
        let rule = RustMissingAsyncTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::time::Duration;
use reqwest;

async fn fetch(url: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let _resp = client
        .get(url)
        .send()
        .await?;
    Ok(())
}
"#,
        );
        let findings = rule.evaluate(&vec![(file_id, sem)], None).await;
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "rust.missing_async_timeout"),
            "should not flag when reqwest client is configured with timeout and send/await are split across lines"
        );
    }

    #[tokio::test]
    async fn does_not_flag_reqwest_send_when_using_fully_qualified_timeout() {
        // Test case for code that uses fully-qualified calls without imports (like rustee)
        let rule = RustMissingAsyncTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::time::Duration;

async fn fetch(url: &str) -> Result<(), reqwest::Error> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let _resp = client.get(url).send().await?;
    Ok(())
}
"#,
        );
        let findings = rule.evaluate(&vec![(file_id, sem)], None).await;
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "rust.missing_async_timeout"),
            "should not flag when reqwest client is configured with timeout using fully-qualified calls"
        );
    }

    #[tokio::test]
    async fn does_not_flag_reqwest_send_when_match_on_client_builder() {
        // Test case matching rustee's structure: match on client builder result
        let rule = RustMissingAsyncTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::time::Duration;

async fn get_recipe(id: String) {
    match reqwest::Client::builder()
        .timeout(Duration::from_millis(2000))
        .build()
    {
        Ok(client) => {
            let res = client
                .post(format!("{}/api/recipe/accessed", "http://localhost:8080"))
                .send()
                .await;
        }
        Err(err) => {
            eprintln!("Failed to build HTTP client: {err}");
        }
    }
}
"#,
        );
        let findings = rule.evaluate(&vec![(file_id, sem)], None).await;
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "rust.missing_async_timeout"),
            "should not flag when reqwest client builder is wrapped in match and has timeout"
        );
    }

    #[tokio::test]
    async fn does_not_flag_reqwest_with_chained_calls_and_timeout() {
        // Exact rustee pattern: .post().header().json().send().await
        let rule = RustMissingAsyncTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::time::Duration;

async fn get_recipe(id: String) {
    match reqwest::Client::builder()
        .timeout(Duration::from_millis(2000))
        .build()
    {
        Ok(client) => {
            let res = client
                .post(format!("{}/api/recipe/accessed", "http://localhost:8080"))
                .header("x-request-id", "123")
                .json(&serde_json::json!({ "recipe_id": id }))
                .send()
                .await;
        }
        Err(err) => {
            eprintln!("Failed to build HTTP client: {err}");
        }
    }
}
"#,
        );
        let findings = rule.evaluate(&vec![(file_id, sem)], None).await;
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "rust.missing_async_timeout"),
            "should not flag when reqwest client has timeout and chained calls are used"
        );
    }

    #[tokio::test]
    async fn does_not_flag_exact_rustee_pattern() {
        // Exact rustee code pattern without imports
        let rule = RustMissingAsyncTimeoutRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::time::Duration;

async fn get_recipe(id: String) {
    match reqwest::Client::builder()
        .timeout(Duration::from_millis(2000))
        .build()
    {
        Ok(client) => {
            let res = client
                .post(format!("{}/api/recipe/accessed", remote_host))
                .header("x-request-id", request_id.clone())
                .json(&serde_json::json!({ "recipe_id": id }))
                .send()
                .await;
            if let Err(err) = res {
                eprintln!("Failed to notify recipe-accessed: {err}");
            }
        }
        Err(err) => {
            eprintln!("Failed to build HTTP client: {err}");
        }
    }
}
"#,
        );
        let findings = rule.evaluate(&vec![(file_id, sem)], None).await;
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "rust.missing_async_timeout"),
            "should not flag exact rustee pattern"
        );
    }

    #[test]
    fn timeout_patterns_are_valid() {
        for pattern in TIMEOUT_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[test]
    fn external_call_patterns_are_valid() {
        for pattern in EXTERNAL_CALL_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }
}
