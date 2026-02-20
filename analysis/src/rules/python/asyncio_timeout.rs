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

/// Rule: Missing asyncio.timeout
///
/// Detects async operations that should have timeouts but don't, which can
/// lead to tasks hanging indefinitely.
#[derive(Debug)]
pub struct PythonAsyncioTimeoutRule;

impl PythonAsyncioTimeoutRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonAsyncioTimeoutRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonAsyncioTimeoutRule {
    fn id(&self) -> &'static str {
        "python.asyncio.missing_timeout"
    }

    fn name(&self) -> &'static str {
        "Detects async operations without timeout that could hang indefinitely."
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

            // Look for async operations that should have timeouts
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;
                let args = &call.args_repr;

                // Check for asyncio.wait without timeout
                if (callee == "asyncio.wait" || callee.ends_with(".wait"))
                    && !args.contains("timeout")
                {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "asyncio.wait without timeout".to_string(),
                        description: Some(
                            "asyncio.wait is called without a timeout parameter. This can cause \
                             the operation to wait indefinitely if tasks don't complete. Add a \
                             timeout parameter to prevent hanging."
                                .to_string(),
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(generate_wait_timeout_patch(*file_id, call)),
                        fix_preview: Some(generate_wait_timeout_fix_preview()),
                        tags: vec!["python".into(), "asyncio".into(), "timeout".into()],
                    });
                }

                // Check for asyncio.gather without timeout wrapper
                if (callee == "asyncio.gather" || callee.ends_with(".gather"))
                    && !args.contains("return_exceptions")
                {
                    // Note: gather doesn't have a timeout param, needs wait_for wrapper
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "asyncio.gather without timeout protection".to_string(),
                        description: Some(
                            "asyncio.gather is called without timeout protection. If any task \
                             hangs, the entire gather will hang. Wrap with asyncio.wait_for or \
                             asyncio.timeout for protection."
                                .to_string(),
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Low,
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
                        fix_preview: Some(generate_gather_timeout_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "asyncio".into(),
                            "timeout".into(),
                            "gather".into(),
                        ],
                    });
                }

                // Check for asyncio.sleep without reasonable bounds
                if callee == "asyncio.sleep" || callee.ends_with(".sleep") {
                    // Try to detect very long sleeps
                    if args.contains("86400") || args.contains("3600") && !args.contains("*") {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Very long asyncio.sleep detected".to_string(),
                            description: Some(
                                "asyncio.sleep with a very long duration detected. Consider \
                                 using a cancellable approach or breaking into smaller intervals \
                                 to allow for graceful shutdown."
                                    .to_string(),
                            ),
                            kind: FindingKind::AntiPattern,
                            severity: Severity::Low,
                            confidence: 0.60,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column),
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: None,
                            fix_preview: Some(generate_sleep_fix_preview()),
                            tags: vec!["python".into(), "asyncio".into(), "sleep".into()],
                        });
                    }
                }

                // Check for Queue.get without timeout
                if callee.ends_with(".get")
                    && (callee.contains("queue") || callee.contains("Queue"))
                    && !args.contains("timeout")
                {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Async queue get without timeout".to_string(),
                        description: Some(
                            "Queue.get() is called without a timeout. This can block \
                             indefinitely if no items are available. Use get() with timeout \
                             or get_nowait() with exception handling."
                                .to_string(),
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.75,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_queue_timeout_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "asyncio".into(),
                            "queue".into(),
                            "timeout".into(),
                        ],
                    });
                }

                // Check for Lock.acquire without timeout
                if callee.ends_with(".acquire")
                    && (callee.contains("lock")
                        || callee.contains("Lock")
                        || callee.contains("semaphore")
                        || callee.contains("Semaphore"))
                    && !args.contains("timeout")
                {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Lock acquire without timeout".to_string(),
                        description: Some(
                            "Lock/Semaphore acquire() is called without a timeout. This can \
                             cause deadlocks if the lock is never released. Consider using \
                             acquire with timeout or async with statement."
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
                        fix_preview: Some(generate_lock_timeout_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "asyncio".into(),
                            "lock".into(),
                            "timeout".into(),
                        ],
                    });
                }
            }
        }

        findings
    }
}

/// Generate patch for asyncio.wait timeout.
/// Transforms: `asyncio.wait(tasks)` → `asyncio.wait(tasks, timeout=30.0)`
fn generate_wait_timeout_patch(file_id: FileId, call: &PyCallSite) -> FilePatch {
    let args_trimmed = call.args_repr.trim_matches(|c| c == '(' || c == ')');

    // Add timeout=30.0 to the wait call
    let replacement = if args_trimmed.is_empty() || args_trimmed.trim().is_empty() {
        format!("{}(timeout=30.0)", call.function_call.callee_expr)
    } else {
        format!(
            "{}({}, timeout=30.0)",
            call.function_call.callee_expr, args_trimmed
        )
    };

    let hunks = vec![PatchHunk {
        range: PatchRange::ReplaceBytes {
            start: call.start_byte,
            end: call.end_byte,
        },
        replacement,
    }];

    FilePatch { file_id, hunks }
}

/// Generate fix preview for asyncio.wait timeout.
fn generate_wait_timeout_fix_preview() -> String {
    r#"# Add timeout to asyncio.wait

import asyncio

# Bad: No timeout - can wait forever
done, pending = await asyncio.wait(tasks)

# Good: With timeout
done, pending = await asyncio.wait(tasks, timeout=30.0)

# Handle pending tasks after timeout
if pending:
    for task in pending:
        task.cancel()
    # Wait for cancellation to complete
    await asyncio.gather(*pending, return_exceptions=True)

# Using asyncio.timeout (Python 3.11+)
async with asyncio.timeout(30.0):
    done, pending = await asyncio.wait(tasks)

# Using asyncio.wait_for for single task
result = await asyncio.wait_for(single_task, timeout=30.0)"#
        .to_string()
}

/// Generate fix preview for asyncio.gather timeout.
fn generate_gather_timeout_fix_preview() -> String {
    r#"# Add timeout protection to asyncio.gather

import asyncio

# Bad: No timeout protection
results = await asyncio.gather(task1, task2, task3)

# Good: Wrap with asyncio.wait_for
results = await asyncio.wait_for(
    asyncio.gather(task1, task2, task3),
    timeout=30.0
)

# Good: Use asyncio.timeout (Python 3.11+)
async with asyncio.timeout(30.0):
    results = await asyncio.gather(task1, task2, task3)

# Good: Handle exceptions and timeout
try:
    async with asyncio.timeout(30.0):
        results = await asyncio.gather(
            task1, task2, task3,
            return_exceptions=True  # Don't fail on first exception
        )
except asyncio.TimeoutError:
    # Handle timeout
    pass

# Alternative: Use asyncio.TaskGroup (Python 3.11+)
async with asyncio.TaskGroup() as tg:
    task1 = tg.create_task(coro1())
    task2 = tg.create_task(coro2())"#
        .to_string()
}

/// Generate fix preview for long sleep.
fn generate_sleep_fix_preview() -> String {
    r#"# Handle long waits with cancellation support

import asyncio

# Bad: Long sleep that can't be interrupted
await asyncio.sleep(3600)  # 1 hour

# Good: Break into smaller intervals
async def cancellable_sleep(duration: float, interval: float = 1.0):
    """Sleep that can be cancelled quickly."""
    remaining = duration
    while remaining > 0:
        await asyncio.sleep(min(interval, remaining))
        remaining -= interval

# Good: Use Event for cancellable wait
stop_event = asyncio.Event()

async def wait_with_cancel():
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=3600)
    except asyncio.TimeoutError:
        pass  # Normal timeout

# To cancel: stop_event.set()

# Good: Use asyncio.timeout for bounded wait
async with asyncio.timeout(3600):
    await some_long_operation()"#
        .to_string()
}

/// Generate fix preview for queue timeout.
fn generate_queue_timeout_fix_preview() -> String {
    r#"# Add timeout to async queue operations

import asyncio

queue = asyncio.Queue()

# Bad: Can block forever
item = await queue.get()

# Good: With timeout
try:
    item = await asyncio.wait_for(queue.get(), timeout=30.0)
except asyncio.TimeoutError:
    # Handle timeout
    pass

# Good: Non-blocking with exception handling
try:
    item = queue.get_nowait()
except asyncio.QueueEmpty:
    # Handle empty queue
    pass

# Good: Poll with timeout
async def get_with_timeout(queue, timeout):
    try:
        return await asyncio.wait_for(queue.get(), timeout=timeout)
    except asyncio.TimeoutError:
        return None"#
        .to_string()
}

/// Generate fix preview for lock timeout.
fn generate_lock_timeout_fix_preview() -> String {
    r#"# Add timeout to lock acquisition

import asyncio

lock = asyncio.Lock()

# Bad: Can deadlock
await lock.acquire()
try:
    # critical section
    pass
finally:
    lock.release()

# Good: Use async with (auto-release)
async with lock:
    # critical section
    pass

# Good: With timeout (Python 3.11+)
try:
    async with asyncio.timeout(10.0):
        async with lock:
            # critical section
            pass
except asyncio.TimeoutError:
    # Handle timeout
    pass

# Good: Manual acquire with timeout
acquired = await asyncio.wait_for(lock.acquire(), timeout=10.0)
if acquired:
    try:
        # critical section
        pass
    finally:
        lock.release()

# For Semaphore
semaphore = asyncio.Semaphore(10)
async with semaphore:
    # limited concurrency section
    pass"#
        .to_string()
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
        let rule = PythonAsyncioTimeoutRule::new();
        assert_eq!(rule.id(), "python.asyncio.missing_timeout");
    }

    #[test]
    fn rule_name_mentions_timeout() {
        let rule = PythonAsyncioTimeoutRule::new();
        assert!(rule.name().contains("timeout"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_asyncio_code() {
        let rule = PythonAsyncioTimeoutRule::new();
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
    async fn fix_preview_contains_timeout_examples() {
        let preview = generate_wait_timeout_fix_preview();
        assert!(preview.contains("timeout"));
        assert!(preview.contains("asyncio.wait"));
    }

    // ==================== Detection Tests ====================

    #[tokio::test]
    async fn detects_asyncio_wait_without_timeout() {
        let rule = PythonAsyncioTimeoutRule::new();
        let src = r#"
import asyncio

async def main():
    done, pending = await asyncio.wait(tasks)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let wait_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("asyncio.wait"))
            .collect();
        assert!(
            !wait_findings.is_empty(),
            "Should detect asyncio.wait without timeout"
        );
    }

    #[tokio::test]
    async fn no_finding_when_timeout_present() {
        let rule = PythonAsyncioTimeoutRule::new();
        let src = r#"
import asyncio

async def main():
    done, pending = await asyncio.wait(tasks, timeout=30.0)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let wait_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("asyncio.wait"))
            .collect();
        assert!(
            wait_findings.is_empty(),
            "Should not flag asyncio.wait with timeout"
        );
    }

    // ==================== Patch Application Tests ====================

    #[tokio::test]
    async fn patch_adds_timeout_to_asyncio_wait() {
        use crate::types::patch::apply_file_patch;

        let rule = PythonAsyncioTimeoutRule::new();
        let src =
            "import asyncio\nasync def main():\n    done, pending = await asyncio.wait(tasks)\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let wait_finding = findings
            .iter()
            .find(|f| f.title.contains("asyncio.wait"))
            .expect("Should have an asyncio.wait finding");

        let patch = wait_finding
            .patch
            .as_ref()
            .expect("Finding should have a patch");
        let patched = apply_file_patch(src, patch);

        assert!(
            patched.contains("timeout=30.0"),
            "Patched code should contain timeout=30.0"
        );
    }

    #[tokio::test]
    async fn patch_uses_replace_bytes() {
        let rule = PythonAsyncioTimeoutRule::new();
        let src =
            "import asyncio\nasync def main():\n    done, pending = await asyncio.wait(tasks)\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let wait_finding = findings
            .iter()
            .find(|f| f.title.contains("asyncio.wait"))
            .expect("Should have an asyncio.wait finding");

        let patch = wait_finding
            .patch
            .as_ref()
            .expect("Finding should have a patch");

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
