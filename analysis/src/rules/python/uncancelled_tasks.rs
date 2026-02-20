use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::timeout;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::PyCallSite;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule: Uncancelled Async Tasks
///
/// Detects async tasks that are created but may not be properly cancelled
/// or awaited, leading to resource leaks and orphaned tasks.
#[derive(Debug)]
pub struct PythonUncancelledTasksRule;

impl PythonUncancelledTasksRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonUncancelledTasksRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonUncancelledTasksRule {
    fn id(&self) -> &'static str {
        "python.asyncio.uncancelled_tasks"
    }

    fn name(&self) -> &'static str {
        "Detects async tasks that may not be properly cancelled or awaited."
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(timeout())
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

            // Check for asyncio imports
            let has_asyncio = py
                .imports
                .iter()
                .any(|imp| imp.module == "asyncio" || imp.module.starts_with("asyncio."));

            if !has_asyncio {
                continue;
            }

            // Track task creation patterns
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;

                // Check for create_task without proper handling
                if callee == "asyncio.create_task"
                    || callee.ends_with(".create_task")
                    || callee == "loop.create_task"
                {
                    // Check if the task is assigned to a variable
                    // This is a heuristic - we can't fully track task lifecycle
                    let is_fire_and_forget = !py
                        .assignments
                        .iter()
                        .any(|a| a.value_repr.contains("create_task"));

                    if is_fire_and_forget {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Fire-and-forget async task detected".to_string(),
                            description: Some(
                                "asyncio.create_task() is called but the task is not stored \
                                 in a variable. This creates a 'fire-and-forget' task that \
                                 cannot be cancelled or awaited. Store the task reference and \
                                 ensure proper cleanup."
                                    .to_string(),
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Medium,
                            confidence: 0.70,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column),
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: None,
                            fix_preview: Some(generate_task_management_fix_preview()),
                            tags: vec![
                                "python".into(),
                                "asyncio".into(),
                                "task".into(),
                                "fire-and-forget".into(),
                            ],
                        });
                    }
                }

                // Check for ensure_future (deprecated pattern)
                if callee == "asyncio.ensure_future" || callee.ends_with(".ensure_future") {
                    let patch = generate_ensure_future_to_create_task_patch(call, *file_id);
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "asyncio.ensure_future is deprecated".to_string(),
                        description: Some(
                            "asyncio.ensure_future() is a legacy API. Use asyncio.create_task() \
                             for creating tasks from coroutines. ensure_future should only be \
                             used when you need to handle both coroutines and futures."
                                .to_string(),
                        ),
                        kind: FindingKind::AntiPattern,
                        severity: Severity::Low,
                        confidence: 0.85,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(generate_create_task_fix_preview()),
                        tags: vec!["python".into(), "asyncio".into(), "deprecated".into()],
                    });
                }

                // Check for tasks created in loops without tracking
                // This is a common pattern that leads to orphaned tasks
                if (callee == "asyncio.create_task" || callee.ends_with(".create_task"))
                    && py.calls.iter().any(|c| {
                        c.function_call.callee_expr.contains("for")
                            || c.function_call.callee_expr.contains("while")
                    })
                {
                    // Heuristic: if there's a loop and create_task, warn about task tracking
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Tasks created in loop may not be tracked".to_string(),
                        description: Some(
                            "Tasks appear to be created in a loop. Ensure all tasks are \
                             collected and properly awaited or cancelled. Use a list to \
                             track tasks and asyncio.gather() or TaskGroup to manage them."
                                .to_string(),
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Low,
                        confidence: 0.55,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_loop_tasks_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "asyncio".into(),
                            "task".into(),
                            "loop".into(),
                        ],
                    });
                }
            }

            // Check for missing task cancellation in shutdown handlers
            let has_shutdown_handler = py.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("signal")
                    || c.function_call.callee_expr.contains("shutdown")
                    || c.function_call.callee_expr.contains("cleanup")
            });

            let has_task_cancel = py.calls.iter().any(|c| {
                c.function_call.callee_expr.ends_with(".cancel")
                    || c.function_call.callee_expr.contains("cancel_task")
            });

            let has_all_tasks = py.calls.iter().any(|c| {
                c.function_call.callee_expr == "asyncio.all_tasks"
                    || c.function_call.callee_expr.ends_with(".all_tasks")
            });

            // If there's task creation but no cancellation pattern
            let has_task_creation = py
                .calls
                .iter()
                .any(|c| c.function_call.callee_expr.contains("create_task"));

            if has_task_creation && !has_task_cancel && !has_all_tasks && !has_shutdown_handler {
                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "No task cancellation pattern detected".to_string(),
                    description: Some(
                        "Tasks are created but there's no visible cancellation or cleanup \
                         pattern. Implement proper task lifecycle management to prevent \
                         orphaned tasks during shutdown."
                            .to_string(),
                    ),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Low,
                    confidence: 0.50,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: py.path.clone(),
                    line: Some(1),
                    column: Some(1),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: None,
                    fix_preview: Some(generate_shutdown_fix_preview()),
                    tags: vec![
                        "python".into(),
                        "asyncio".into(),
                        "task".into(),
                        "shutdown".into(),
                    ],
                });
            }
        }

        findings
    }
}

/// Generate a patch to replace asyncio.ensure_future with asyncio.create_task.
///
/// Transforms: `asyncio.ensure_future(coro())` → `asyncio.create_task(coro())`
fn generate_ensure_future_to_create_task_patch(call: &PyCallSite, file_id: FileId) -> FilePatch {
    // args_repr includes parentheses like "(coro())", so we strip only the outermost ones
    // Using trim_matches would be too aggressive as it removes ALL matching chars
    let args_trimmed = if call.args_repr.starts_with('(') && call.args_repr.ends_with(')') {
        &call.args_repr[1..call.args_repr.len() - 1]
    } else {
        &call.args_repr
    };

    // Replace ensure_future with create_task
    let replacement = format!("asyncio.create_task({})", args_trimmed);

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: call.start_byte,
                end: call.end_byte,
            },
            replacement,
        }],
    }
}

/// Generate fix preview for task management.
fn generate_task_management_fix_preview() -> String {
    r#"# Properly manage async tasks

import asyncio

# Bad: Fire-and-forget task (no reference kept)
asyncio.create_task(some_coroutine())  # Task may be garbage collected!

# Good: Store task reference
task = asyncio.create_task(some_coroutine())

# Good: Store in a set for background tasks
background_tasks = set()

task = asyncio.create_task(some_coroutine())
background_tasks.add(task)
task.add_done_callback(background_tasks.discard)

# Good: Use TaskGroup (Python 3.11+)
async with asyncio.TaskGroup() as tg:
    task1 = tg.create_task(coro1())
    task2 = tg.create_task(coro2())
# All tasks are awaited when exiting the context

# Good: Await the task when done
task = asyncio.create_task(some_coroutine())
# ... do other work ...
result = await task

# Good: Cancel task on shutdown
task = asyncio.create_task(some_coroutine())
try:
    await asyncio.sleep(10)
finally:
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass"#
        .to_string()
}

/// Generate fix preview for create_task vs ensure_future.
fn generate_create_task_fix_preview() -> String {
    r#"# Use asyncio.create_task instead of ensure_future

import asyncio

# Deprecated: ensure_future
task = asyncio.ensure_future(some_coroutine())

# Recommended: create_task (Python 3.7+)
task = asyncio.create_task(some_coroutine())

# create_task advantages:
# - Clearer intent
# - Better error messages
# - Slightly faster
# - Returns Task (not Future)

# Only use ensure_future when you need to handle both:
async def handle_awaitable(awaitable):
    # awaitable could be coroutine, Task, or Future
    return await asyncio.ensure_future(awaitable)

# For coroutines, always use create_task:
async def main():
    task = asyncio.create_task(my_coroutine())
    await task"#
        .to_string()
}

/// Generate fix preview for tasks in loops.
fn generate_loop_tasks_fix_preview() -> String {
    r#"# Properly track tasks created in loops

import asyncio

# Bad: Tasks created in loop without tracking
for item in items:
    asyncio.create_task(process(item))  # Tasks may be lost!

# Good: Collect tasks in a list
tasks = []
for item in items:
    task = asyncio.create_task(process(item))
    tasks.append(task)
results = await asyncio.gather(*tasks)

# Good: Use list comprehension
tasks = [asyncio.create_task(process(item)) for item in items]
results = await asyncio.gather(*tasks)

# Good: Use TaskGroup (Python 3.11+)
async with asyncio.TaskGroup() as tg:
    for item in items:
        tg.create_task(process(item))

# Good: Use asyncio.gather directly
results = await asyncio.gather(*[process(item) for item in items])

# Good: With concurrency limit
semaphore = asyncio.Semaphore(10)

async def limited_process(item):
    async with semaphore:
        return await process(item)

tasks = [asyncio.create_task(limited_process(item)) for item in items]
results = await asyncio.gather(*tasks)"#
        .to_string()
}

/// Generate fix preview for shutdown handling.
fn generate_shutdown_fix_preview() -> String {
    r#"# Implement proper task cleanup on shutdown

import asyncio
import signal

# Track all background tasks
background_tasks = set()

def create_background_task(coro):
    task = asyncio.create_task(coro)
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)
    return task

async def shutdown(signal_name=None):
    """Clean shutdown of all tasks."""
    if signal_name:
        print(f"Received {signal_name}, shutting down...")
    
    # Cancel all background tasks
    tasks = [t for t in background_tasks if not t.done()]
    for task in tasks:
        task.cancel()
    
    # Wait for all tasks to complete cancellation
    await asyncio.gather(*tasks, return_exceptions=True)
    
    # Or cancel ALL tasks (including current)
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

async def main():
    # Setup signal handlers
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(
            sig,
            lambda s=sig: asyncio.create_task(shutdown(s.name))
        )
    
    # Create background tasks
    create_background_task(background_worker())
    
    try:
        await run_main_logic()
    finally:
        await shutdown()

if __name__ == "__main__":
    asyncio.run(main())"#
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};
    use crate::types::patch::apply_file_patch;

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
        let rule = PythonUncancelledTasksRule::new();
        assert_eq!(rule.id(), "python.asyncio.uncancelled_tasks");
    }

    #[test]
    fn rule_name_mentions_tasks() {
        let rule = PythonUncancelledTasksRule::new();
        assert!(rule.name().contains("tasks"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_asyncio_code() {
        let rule = PythonUncancelledTasksRule::new();
        let src = r#"
def sync_function():
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn fix_preview_contains_task_management() {
        let preview = generate_task_management_fix_preview();
        assert!(preview.contains("create_task"));
        assert!(preview.contains("background_tasks"));
    }

    #[tokio::test]
    async fn fix_preview_contains_shutdown_handling() {
        let preview = generate_shutdown_fix_preview();
        assert!(preview.contains("shutdown"));
        assert!(preview.contains("cancel"));
    }

    // ==================== ensure_future Detection Tests ====================

    #[tokio::test]
    async fn detects_ensure_future() {
        let rule = PythonUncancelledTasksRule::new();
        let src = r#"
import asyncio

task = asyncio.ensure_future(some_coroutine())
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let ensure_future_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("ensure_future"))
            .collect();

        assert!(
            !ensure_future_findings.is_empty(),
            "Should detect ensure_future"
        );
        assert!(
            ensure_future_findings[0].patch.is_some(),
            "Should have a patch"
        );
    }

    #[tokio::test]
    async fn no_finding_for_create_task() {
        let rule = PythonUncancelledTasksRule::new();
        let src = r#"
import asyncio

task = asyncio.create_task(some_coroutine())
await task
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let ensure_future_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("ensure_future"))
            .collect();

        assert!(
            ensure_future_findings.is_empty(),
            "Should not flag create_task"
        );
    }

    // ==================== ensure_future Patch Tests ====================

    #[tokio::test]
    async fn patch_replaces_ensure_future_with_create_task() {
        let rule = PythonUncancelledTasksRule::new();
        let src = "import asyncio\n\ntask = asyncio.ensure_future(some_coroutine())\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let ensure_future_finding = findings
            .iter()
            .find(|f| f.title.contains("ensure_future"))
            .expect("Should detect ensure_future");

        let patch = ensure_future_finding
            .patch
            .as_ref()
            .expect("Should have a patch");
        let patched = apply_file_patch(src, patch);

        assert!(
            patched.contains("asyncio.create_task(some_coroutine())"),
            "Patched code should use asyncio.create_task()"
        );
        assert!(
            !patched.contains("ensure_future"),
            "Patched code should not contain ensure_future"
        );
    }

    #[tokio::test]
    async fn patch_uses_replace_bytes_for_ensure_future() {
        let rule = PythonUncancelledTasksRule::new();
        let src = "import asyncio\n\ntask = asyncio.ensure_future(some_coroutine())\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let ensure_future_finding = findings
            .iter()
            .find(|f| f.title.contains("ensure_future"))
            .expect("Should detect ensure_future");

        let patch = ensure_future_finding
            .patch
            .as_ref()
            .expect("Should have a patch");

        // Verify that one hunk is ReplaceBytes (the actual fix)
        let has_replace_bytes = patch
            .hunks
            .iter()
            .any(|h| matches!(h.range, PatchRange::ReplaceBytes { .. }));
        assert!(
            has_replace_bytes,
            "Patch should use ReplaceBytes for actual code replacement"
        );
    }
}
