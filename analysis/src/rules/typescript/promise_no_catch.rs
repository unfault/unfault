//! Rule: Unhandled promise rejection
//!
//! Detects promises that are not awaited and don't have .catch() error handling.

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

/// Rule that detects unhandled promise rejections in TypeScript code.
///
/// Unhandled promise rejections can crash Node.js applications,
/// lead to silent failures, and make debugging difficult.
#[derive(Debug)]
pub struct TypescriptPromiseNoCatchRule;

impl TypescriptPromiseNoCatchRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptPromiseNoCatchRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptPromiseNoCatchRule {
    fn id(&self) -> &'static str {
        "typescript.promise_no_catch"
    }

    fn name(&self) -> &'static str {
        "Unhandled promise rejection may crash the application"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let ts = match sem.as_ref() {
                SourceSemantics::Typescript(ts) => ts,
                _ => continue,
            };

            for call in &ts.calls {
                // Skip if already awaited
                if call.is_awaited {
                    continue;
                }

                // Skip if it has .catch() or .then()
                let callee_lower = call.callee.to_lowercase();
                if callee_lower.ends_with(".catch")
                    || callee_lower.ends_with(".then")
                    || callee_lower.ends_with(".finally")
                {
                    continue;
                }

                // Known HTTP client prefixes - these are clearly async
                let http_client_prefixes = [
                    "axios.",      // axios.get, axios.post, etc.
                    "http.",       // http.get, http.post, etc.
                    "https.",      // https.get, etc.
                    "got.",        // got HTTP client
                    "ky.",         // ky HTTP client
                    "superagent.", // superagent HTTP client
                    "request.",    // request library
                    "needle.",     // needle HTTP client
                    "node-fetch.", // node-fetch
                    "undici.",     // undici HTTP client
                ];

                // Check if this is an HTTP client method call
                let is_http_client = http_client_prefixes
                    .iter()
                    .any(|p| callee_lower.starts_with(p));

                // Standalone async APIs
                let is_fetch = callee_lower == "fetch";

                // ORM/database patterns that return promises
                // These are specific patterns that are almost always async
                let orm_patterns = [
                    ".save",       // model.save()
                    ".create",     // Model.create()
                    ".findone",    // Model.findOne()
                    ".findall",    // Model.findAll()
                    ".findbyid",   // Model.findById()
                    ".findmany",   // Model.findMany()
                    ".updateone",  // Model.updateOne()
                    ".updatemany", // Model.updateMany()
                    ".deleteone",  // Model.deleteOne()
                    ".deletemany", // Model.deleteMany()
                    ".insertone",  // Model.insertOne()
                    ".insertmany", // Model.insertMany()
                    ".upsert",     // Model.upsert()
                    ".aggregate",  // Model.aggregate()
                    ".execute",    // query.execute()
                ];

                let is_orm_pattern = orm_patterns
                    .iter()
                    .any(|p| callee_lower.ends_with(p));

                let might_be_async = is_fetch || is_http_client || is_orm_pattern;

                if might_be_async && !call.in_loop {
                    let title = format!(
                        "Async call '{}' may have unhandled rejection",
                        call.callee
                    );

                    let description = format!(
                        "The call to '{}' returns a Promise that is not awaited and has no .catch() handler. \
                         Unhandled promise rejections can crash Node.js applications with --unhandled-rejections=strict. \
                         Add .catch() or use await with try-catch.",
                        call.callee
                    );

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::ReplaceBytes {
                                start: call.start_byte,
                                end: call.end_byte,
                            },
                            replacement: format!(
                                "{}{}.catch(err => {{ logger.error('Unhandled error', {{ error: err }}); }})",
                                call.callee,
                                call.args_repr
                            ),
                        }],
                    };

                    let fix_preview = format!(
                        "// Before:\n{}{};\n// After:\n{}{}.catch(err => logger.error(err));",
                        call.callee, call.args_repr, call.callee, call.args_repr
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::High,
                        confidence: 0.7,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: ts.path.clone(),
                        line: Some(call.location.range.start_line + 1),
                        column: Some(call.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "typescript".into(),
                            "async".into(),
                            "error-handling".into(),
                            "stability".into(),
                        ],
                    });
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::typescript::parse_typescript_file;
    use crate::semantics::typescript::build_typescript_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.ts".to_string(),
            language: Language::Typescript,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_typescript_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_typescript_semantics(&parsed).unwrap();
        (file_id, Arc::new(SourceSemantics::Typescript(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = TypescriptPromiseNoCatchRule::new();
        assert_eq!(rule.id(), "typescript.promise_no_catch");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = TypescriptPromiseNoCatchRule::new();
        assert!(rule.name().contains("promise"));
    }

    #[tokio::test]
    async fn evaluate_detects_fire_and_forget_fetch() {
        let rule = TypescriptPromiseNoCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
function process() {
    fetch('https://api.example.com/notify');
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("fetch"));
    }

    #[tokio::test]
    async fn evaluate_ignores_awaited_calls() {
        let rule = TypescriptPromiseNoCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
async function process() {
    await fetch('https://api.example.com/data');
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_typescript() {
        let rule = TypescriptPromiseNoCatchRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_sync_vscode_apis() {
        let rule = TypescriptPromiseNoCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
import * as vscode from 'vscode';

function activate() {
    const outputChannel = vscode.window.createOutputChannel("Test");
    outputChannel.appendLine("Hello");
    const diagnostics = vscode.languages.createDiagnosticCollection("test");
    const statusBar = vscode.window.createStatusBarItem();
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not detect sync VS Code APIs as async. Found: {:?}", findings);
    }

    #[tokio::test]
    async fn evaluate_ignores_console_and_settimeout() {
        let rule = TypescriptPromiseNoCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
function test() {
    console.log("test");
    console.error("error");
    setTimeout(() => {}, 1000);
    setInterval(() => {}, 1000);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not detect console/setTimeout as async. Found: {:?}", findings);
    }

    #[tokio::test]
    async fn evaluate_ignores_sync_array_methods() {
        let rule = TypescriptPromiseNoCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
function test() {
    const arr = [1, 2, 3];
    arr.push(4);
    arr.map(x => x * 2);
    arr.filter(x => x > 2);
    arr.forEach(x => console.log(x));
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not detect sync array methods as async. Found: {:?}", findings);
    }

    #[tokio::test]
    async fn evaluate_detects_model_save() {
        let rule = TypescriptPromiseNoCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
function process() {
    user.save();
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("save"));
    }

    #[tokio::test]
    async fn evaluate_detects_axios_calls() {
        let rule = TypescriptPromiseNoCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
function process() {
    axios.get('https://api.example.com/data');
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("axios"));
    }

    #[tokio::test]
    async fn evaluate_ignores_config_get_methods() {
        let rule = TypescriptPromiseNoCatchRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
import * as vscode from 'vscode';

function activate() {
    const config = vscode.workspace.getConfiguration("unfault");
    if (config.get<boolean>("enable", true) && config.get<boolean>("analyzeOnSave", true)) {
        console.log("enabled");
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "Should not detect sync config.get() as async. Found: {:?}", findings);
    }
}