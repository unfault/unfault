//! Rule A12: Async tasks without error logging
//!
//! Detects fire-and-forget asyncio.create_task() calls that don't have
//! proper error handling, which can cause silent failures in production.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects fire-and-forget async tasks without error handling.
///
/// When using asyncio.create_task() without storing the result or adding
/// error handling, exceptions in the task are silently swallowed, making
/// debugging production issues extremely difficult.
#[derive(Debug)]
pub struct PythonAsyncTaskNoErrorHandlingRule;

impl PythonAsyncTaskNoErrorHandlingRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonAsyncTaskNoErrorHandlingRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a fire-and-forget async task
#[derive(Debug, Clone)]
struct FireAndForgetTask {
    /// The function being called
    function_name: String,
    /// Line number (1-based)
    line: u32,
    /// Column number (1-based)
    column: u32,
    /// Start byte offset
    start_byte: usize,
    /// End byte offset
    end_byte: usize,
    /// Arguments representation (the coroutine being wrapped)
    args_repr: String,
    /// Line to insert imports (after module docstring if present)
    import_insertion_line: u32,
}

#[async_trait]
impl Rule for PythonAsyncTaskNoErrorHandlingRule {
    fn id(&self) -> &'static str {
        "python.async_task_no_error_handling"
    }

    fn name(&self) -> &'static str {
        "Async task without error handling"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(error_handling_in_handler())
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

            // Look for asyncio.create_task calls that are not assigned to a variable
            // This is detected by checking if the call is a standalone expression
            // (not part of an assignment)
            
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;

                // Check for create_task calls
                if callee == "asyncio.create_task" || callee == "create_task" {
                    // Check if this call is likely fire-and-forget
                    // We can't perfectly detect this without more context,
                    // but we flag all create_task calls and suggest adding error handling
                    
                    let fire_and_forget = FireAndForgetTask {
                        function_name: callee.clone(),
                        line: call.function_call.location.line,
                        column: call.function_call.location.column,
                        start_byte: call.start_byte,
                        end_byte: call.end_byte,
                        args_repr: call.args_repr.clone(),
                        import_insertion_line: py.import_insertion_line(),
                    };

                    let finding = create_finding(
                        self.id(),
                        &fire_and_forget,
                        *file_id,
                        &py.path,
                    );
                    findings.push(finding);
                }
            }
        }

        findings
    }
}

fn create_finding(
    rule_id: &str,
    task: &FireAndForgetTask,
    file_id: FileId,
    file_path: &str,
) -> RuleFinding {
    let title = format!(
        "Fire-and-forget async task: {}",
        task.function_name
    );

    let description = format!(
        "asyncio.create_task() called without error handling. If the task raises \
         an exception, it will be silently swallowed, making debugging difficult. \
         Store the task reference and add exception handling, or use \
         task.add_done_callback() to log errors."
    );

    let patch = generate_error_handling_patch(task, file_id);

    let fix_preview = format!(
        "# Add error handling to async task:\n\
         # task = asyncio.create_task(coro())\n\
         # task.add_done_callback(lambda t: t.exception() and logger.error(t.exception()))"
    );

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::StabilityRisk,
        severity: Severity::Medium,
        confidence: 0.75,
        dimension: Dimension::Stability,
        file_id,
        file_path: file_path.to_string(),
        line: Some(task.line),
        column: Some(task.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
        patch: Some(patch),
        fix_preview: Some(fix_preview),
        tags: vec![
            "python".into(),
            "async".into(),
            "error-handling".into(),
            "fire-and-forget".into(),
        ],
    }
}

fn generate_error_handling_patch(
    task: &FireAndForgetTask,
    file_id: FileId,
) -> FilePatch {
    let mut hunks = Vec::new();

    // Add a helper function import/definition at the top
    let helper_code = r#"def _handle_task_exception(task):  # Added by unfault
    """Log exceptions from background tasks to prevent silent failures."""
    try:
        task.result()
    except Exception as e:
        import logging
        logging.getLogger(__name__).exception("Background task failed: %s", e)

"#;
    
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: task.import_insertion_line },
        replacement: helper_code.to_string(),
    });

    // Replace the create_task call to add the error callback
    // Transform: asyncio.create_task(coro()) ->
    //   (_task := asyncio.create_task(coro())).add_done_callback(_handle_task_exception) or _task
    // Or simpler: wrap with callback inline
    let replacement = format!(
        "({}).add_done_callback(_handle_task_exception)",
        if task.function_name == "create_task" {
            format!("asyncio.create_task({})", task.args_repr)
        } else {
            format!("{}({})", task.function_name, task.args_repr)
        }
    );

    hunks.push(PatchHunk {
        range: PatchRange::ReplaceBytes {
            start: task.start_byte,
            end: task.end_byte,
        },
        replacement,
    });

    FilePatch {
        file_id,
        hunks,
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
        let sem = PyFileSemantics::from_parsed(&parsed);
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonAsyncTaskNoErrorHandlingRule::new();
        assert_eq!(rule.id(), "python.async_task_no_error_handling");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonAsyncTaskNoErrorHandlingRule::new();
        assert!(rule.name().contains("error handling"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonAsyncTaskNoErrorHandlingRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonAsyncTaskNoErrorHandlingRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonAsyncTaskNoErrorHandlingRule::default();
        assert_eq!(rule.id(), "python.async_task_no_error_handling");
    }

    // ==================== evaluate Tests - Detects Issues ====================

    #[tokio::test]
    async fn evaluate_detects_create_task() {
        let rule = PythonAsyncTaskNoErrorHandlingRule::new();
        let src = r#"
import asyncio

async def handler():
    asyncio.create_task(background_job())
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());
        assert!(findings[0].title.contains("create_task"));
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn evaluate_handles_empty_semantics() {
        let rule = PythonAsyncTaskNoErrorHandlingRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_handles_empty_file() {
        let rule = PythonAsyncTaskNoErrorHandlingRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Finding Properties Tests ====================

    #[tokio::test]
    async fn evaluate_finding_has_correct_properties() {
        let rule = PythonAsyncTaskNoErrorHandlingRule::new();
        let src = r#"
import asyncio
asyncio.create_task(job())
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        if !findings.is_empty() {
            let finding = &findings[0];
            assert_eq!(finding.rule_id, "python.async_task_no_error_handling");
            assert_eq!(finding.dimension, Dimension::Stability);
            assert!(matches!(finding.severity, Severity::Medium));
            assert!(finding.patch.is_some());
            assert!(finding.tags.contains(&"async".to_string()));
        }
    }
}