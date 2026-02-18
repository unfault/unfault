use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::PyImport;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Check if threading module is already imported
fn has_threading_import(imports: &[PyImport]) -> bool {
    imports.iter().any(|imp| imp.module == "threading")
}

/// Rule: Race Condition Risk
///
/// Detects patterns that may lead to race conditions in concurrent code.
/// Common patterns include read-modify-write without locking and shared mutable state.
#[derive(Debug)]
pub struct PythonRaceConditionRiskRule;

impl PythonRaceConditionRiskRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonRaceConditionRiskRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonRaceConditionRiskRule {
    fn id(&self) -> &'static str {
        "python.concurrency.race_condition_risk"
    }

    fn name(&self) -> &'static str {
        "race condition risk: concurrent access without synchronization"
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

            // Check for concurrency-related imports
            let has_threading = py.imports.iter().any(|imp| {
                imp.module == "threading"
                    || imp.module == "asyncio"
                    || imp.module == "concurrent.futures"
                    || imp.module.contains("multiprocessing")
            });

            if !has_threading {
                continue;
            }

            // Check for locking imports
            let has_locking = py.imports.iter().any(|imp| {
                imp.names.iter().any(|n| {
                    n == "Lock" || n == "RLock" || n == "Semaphore" || n == "asyncio.Lock"
                })
            });

            // Look for read-modify-write patterns in calls
            let has_read_modify_write = check_read_modify_write_pattern(&py.calls);

            if has_read_modify_write && !has_locking {
                let title = "Potential race condition: read-modify-write without locking".to_string();

                let description =
                    "This code performs read-modify-write operations in a concurrent \
                     context without locking. When multiple threads/tasks access shared \
                     state simultaneously, updates may be lost or state may become inconsistent. \
                     Using threading.Lock, asyncio.Lock, or atomic operations makes the access \
                     pattern explicit.".to_string();

                let fix_preview = generate_fix_preview_rmw();

                let patch = generate_race_condition_patch(
                    *file_id,
                    py.module_docstring_end_line.map(|l| l + 1).unwrap_or(1),
                    &py.imports,
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::BehaviorThreat,
                    severity: Severity::High,
                    confidence: 0.70,
                    dimension: Dimension::Correctness,
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
                        "concurrency".into(),
                        "race-condition".into(),
                        "threading".into(),
                        "data-corruption".into(),
                    ],
                });
            }

            // Check for counter/increment patterns without atomic operations
            let has_counter_pattern = check_counter_pattern(&py.calls);

            if has_counter_pattern && !has_locking {
                let title = "Potential race condition: counter increment without atomic operation".to_string();

                let description =
                    "This code increments a counter in a concurrent context. The increment \
                     operation (read-add-write) is not atomic, so concurrent increments may \
                     lose updates. Using threading.Lock or atomic counters makes the increment \
                     behavior predictable.".to_string();

                let fix_preview = generate_fix_preview_counter();

                let patch = generate_race_condition_patch(
                    *file_id,
                    py.module_docstring_end_line.map(|l| l + 1).unwrap_or(1),
                    &py.imports,
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::BehaviorThreat,
                    severity: Severity::High,
                    confidence: 0.75,
                    dimension: Dimension::Correctness,
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
                        "concurrency".into(),
                        "race-condition".into(),
                        "counter".into(),
                        "atomic".into(),
                    ],
                });
            }
        }

        findings
    }
}

/// Check for read-modify-write patterns in calls.
fn check_read_modify_write_pattern(calls: &[crate::semantics::python::model::PyCallSite]) -> bool {
    // Look for patterns like dict access followed by assignment
    let has_dict_access = calls.iter().any(|call| {
        call.function_call.callee_expr.contains(".get(")
            || call.function_call.callee_expr.contains(".setdefault(")
            || call.function_call.callee_expr.contains("__getitem__")
    });

    let has_dict_write = calls.iter().any(|call| {
        call.function_call.callee_expr.contains(".update(")
            || call.function_call.callee_expr.contains("__setitem__")
    });

    has_dict_access && has_dict_write
}

/// Check for counter/increment patterns.
fn check_counter_pattern(calls: &[crate::semantics::python::model::PyCallSite]) -> bool {
    calls.iter().any(|call| {
        // Look for patterns that suggest counter operations
        call.function_call.callee_expr.contains("count")
            || call.function_call.callee_expr.contains("increment")
            || call.function_call.callee_expr.contains("+=")
    })
}

/// Generate race condition patch.
fn generate_race_condition_patch(file_id: FileId, import_line: u32, imports: &[PyImport]) -> FilePatch {
    let mut hunks = Vec::new();

    // Only add import if threading is not already imported
    let import_section = if has_threading_import(imports) {
        "# Lock for protecting shared state\n_lock = threading.Lock()\n\n"
    } else {
        "import threading\n\n# Lock for protecting shared state\n_lock = threading.Lock()\n\n"
    };
    
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: import_line },
        replacement: import_section.to_string(),
    });

    FilePatch { file_id, hunks }
}

/// Generate fix preview for read-modify-write patterns.
fn generate_fix_preview_rmw() -> String {
    r#"# Bad: Read-modify-write without locking
shared_dict = {}

def update_value(key, delta):
    current = shared_dict.get(key, 0)  # Read
    new_value = current + delta         # Modify
    shared_dict[key] = new_value        # Write
    # Race condition: another thread can modify between read and write!

# Good: Use a lock to protect the critical section
import threading

lock = threading.Lock()
shared_dict = {}

def update_value_safe(key, delta):
    with lock:  # Acquire lock
        current = shared_dict.get(key, 0)
        new_value = current + delta
        shared_dict[key] = new_value
    # Lock released automatically

# Good: For async code, use asyncio.Lock
import asyncio

async_lock = asyncio.Lock()
shared_dict = {}

async def update_value_async(key, delta):
    async with async_lock:
        current = shared_dict.get(key, 0)
        new_value = current + delta
        shared_dict[key] = new_value

# Good: Use thread-safe data structures
from collections import defaultdict
from threading import Lock

class ThreadSafeDict:
    def __init__(self):
        self._dict = defaultdict(int)
        self._lock = Lock()
    
    def increment(self, key, delta=1):
        with self._lock:
            self._dict[key] += delta
            return self._dict[key]"#.to_string()
}

/// Generate fix preview for counter patterns.
fn generate_fix_preview_counter() -> String {
    r#"# Bad: Counter increment without atomic operation
counter = 0

def increment():
    global counter
    counter += 1  # Not atomic! Read-add-write can race

# Good: Use a lock
import threading

counter = 0
counter_lock = threading.Lock()

def increment_safe():
    global counter
    with counter_lock:
        counter += 1

# Good: Use atomic operations (Python 3.8+)
# Note: Python doesn't have built-in atomic integers,
# but you can use the atomics library or implement with locks

# Good: Use threading.local for thread-local counters
import threading

thread_local = threading.local()

def get_local_counter():
    if not hasattr(thread_local, 'counter'):
        thread_local.counter = 0
    return thread_local.counter

def increment_local():
    thread_local.counter = get_local_counter() + 1

# Good: Use Queue for producer-consumer patterns
from queue import Queue

work_queue = Queue()

def producer():
    work_queue.put(item)  # Thread-safe

def consumer():
    item = work_queue.get()  # Thread-safe, blocks if empty

# Good: Use concurrent.futures for parallel processing
from concurrent.futures import ThreadPoolExecutor

def process_items(items):
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(process_item, items))
    return results"#.to_string()
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
        let rule = PythonRaceConditionRiskRule::new();
        assert_eq!(rule.id(), "python.concurrency.race_condition_risk");
    }

    #[test]
    fn rule_name_mentions_race_condition() {
        let rule = PythonRaceConditionRiskRule::new();
        assert!(rule.name().contains("race condition"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_concurrent_code() {
        let rule = PythonRaceConditionRiskRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn fix_preview_rmw_contains_lock() {
        let preview = generate_fix_preview_rmw();
        assert!(preview.contains("Lock"));
        assert!(preview.contains("with lock"));
    }

    #[test]
    fn fix_preview_counter_contains_atomic() {
        let preview = generate_fix_preview_counter();
        assert!(preview.contains("atomic") || preview.contains("Lock"));
    }
}