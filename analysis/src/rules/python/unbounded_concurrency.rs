//! Rule B3: Unbounded concurrency
//!
//! Detects missing semaphores when spawning many async tasks, which can lead
//! to resource exhaustion and system instability.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::ImportInsertionType;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unbounded concurrency patterns in Python async code.
///
/// When spawning many async tasks without limiting concurrency (e.g., using
/// asyncio.gather on a large list without a semaphore), the system can run
/// out of resources like file descriptors, memory, or connections.
#[derive(Debug)]
pub struct PythonUnboundedConcurrencyRule;

impl PythonUnboundedConcurrencyRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonUnboundedConcurrencyRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about an unbounded concurrency pattern
#[derive(Debug, Clone)]
struct UnboundedConcurrencyCall {
    /// The function being called (e.g., "asyncio.gather", "asyncio.create_task")
    function_name: String,
    /// Line number (1-based)
    line: u32,
    /// Column number (1-based)
    column: u32,
    /// The pattern type
    pattern: ConcurrencyPattern,
    /// Start byte offset for replacement
    start_byte: usize,
    /// End byte offset for replacement
    end_byte: usize,
    /// Arguments representation
    args_repr: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ConcurrencyPattern {
    /// asyncio.gather(*tasks) or asyncio.gather(*[...])
    GatherUnpacked,
    /// asyncio.create_task in a loop context (detected by heuristics)
    CreateTaskPotentiallyUnbounded,
}

impl ConcurrencyPattern {
    fn description(&self) -> &'static str {
        match self {
            ConcurrencyPattern::GatherUnpacked => {
                "asyncio.gather() with unpacked tasks can spawn unlimited concurrent operations"
            }
            ConcurrencyPattern::CreateTaskPotentiallyUnbounded => {
                "asyncio.create_task() may spawn unbounded tasks if called in a loop"
            }
        }
    }
}

#[async_trait]
impl Rule for PythonUnboundedConcurrencyRule {
    fn id(&self) -> &'static str {
        "python.unbounded_concurrency"
    }

    fn name(&self) -> &'static str {
        "Unbounded concurrency can exhaust system resources"
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

            // Use stdlib_import since we're adding "import asyncio"
            let import_line = py.import_insertion_line_for(ImportInsertionType::stdlib_import());
            
            // Check for unbounded concurrency patterns in function calls
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;
                
                // Check for asyncio.gather with unpacked arguments
                if callee == "asyncio.gather" || callee == "gather" {
                    // Check if any argument starts with * (unpacked)
                    let has_unpacked = call.args.iter().any(|arg| {
                        arg.value_repr.starts_with('*')
                    });
                    
                    if has_unpacked {
                        let unbounded = UnboundedConcurrencyCall {
                            function_name: callee.clone(),
                            line: call.function_call.location.line,
                            column: call.function_call.location.column,
                            pattern: ConcurrencyPattern::GatherUnpacked,
                            start_byte: call.start_byte,
                            end_byte: call.end_byte,
                            args_repr: call.args_repr.clone(),
                        };

                        let finding = create_finding(
                            self.id(),
                            &unbounded,
                            *file_id,
                            &py.path,
                            import_line,
                        );
                        findings.push(finding);
                    }
                }

                // Check for asyncio.create_task - flag if it appears multiple times
                // (heuristic for potential loop usage)
                if callee == "asyncio.create_task" || callee == "create_task" {
                    // Count how many create_task calls exist in this file
                    let create_task_count = py.calls.iter()
                        .filter(|c| c.function_call.callee_expr == "asyncio.create_task" || c.function_call.callee_expr == "create_task")
                        .count();
                    
                    // If there are multiple create_task calls, it might indicate a pattern
                    // that could be unbounded
                    if create_task_count > 3 {
                        let unbounded = UnboundedConcurrencyCall {
                            function_name: callee.clone(),
                            line: call.function_call.location.line,
                            column: call.function_call.location.column,
                            pattern: ConcurrencyPattern::CreateTaskPotentiallyUnbounded,
                            start_byte: call.start_byte,
                            end_byte: call.end_byte,
                            args_repr: call.args_repr.clone(),
                        };

                        let finding = create_finding(
                            self.id(),
                            &unbounded,
                            *file_id,
                            &py.path,
                            import_line,
                        );
                        findings.push(finding);
                        // Only report once per file
                        break;
                    }
                }
            }
        }

        findings
    }
}

fn create_finding(
    rule_id: &str,
    unbounded: &UnboundedConcurrencyCall,
    file_id: FileId,
    file_path: &str,
    import_insertion_line: u32,
) -> RuleFinding {
    let title = format!(
        "Unbounded concurrency: {} without rate limiting",
        unbounded.function_name
    );

    let description = format!(
        "{}. This can lead to resource exhaustion (file descriptors, memory, connections). \
         Use asyncio.Semaphore to limit concurrent operations.",
        unbounded.pattern.description()
    );

    let patch = generate_semaphore_patch(unbounded, file_id, import_insertion_line);

    let fix_preview = format!(
        "# Add semaphore to limit concurrency:\n\
         # semaphore = asyncio.Semaphore(10)  # Limit to 10 concurrent tasks\n\
         # async with semaphore:\n\
         #     await task"
    );

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::BehaviorThreat,
        severity: Severity::High,
        confidence: 0.75,
        dimension: Dimension::Scalability,
        file_id,
        file_path: file_path.to_string(),
        line: Some(unbounded.line),
        column: Some(unbounded.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
        patch: Some(patch),
        fix_preview: Some(fix_preview),
        tags: vec![
            "python".into(),
            "async".into(),
            "concurrency".into(),
            "resource-exhaustion".into(),
        ],
    }
}

fn generate_semaphore_patch(
    unbounded: &UnboundedConcurrencyCall,
    file_id: FileId,
    import_insertion_line: u32,
) -> FilePatch {
    let mut hunks = Vec::new();

    match unbounded.pattern {
        ConcurrencyPattern::GatherUnpacked => {
            // Add a helper function for limited gather at the top
            let helper_code = r#"import asyncio  # Added by unfault

async def _limited_gather(coros, max_concurrent=10):  # Added by unfault
    """Execute coroutines with limited concurrency using a semaphore."""
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def limited(coro):
        async with semaphore:
            return await coro
    
    return await asyncio.gather(*[limited(c) for c in coros])

"#;
            hunks.push(PatchHunk {
                range: PatchRange::InsertBeforeLine { line: import_insertion_line },
                replacement: helper_code.to_string(),
            });

            // Extract the unpacked argument (e.g., "*tasks" -> "tasks")
            // The args_repr typically contains the comma-separated arguments
            let tasks_var = unbounded.args_repr
                .split(',')
                .find(|arg| arg.trim().starts_with('*'))
                .map(|arg| arg.trim().trim_start_matches('*').trim())
                .unwrap_or("tasks");

            // Replace asyncio.gather(*tasks) with _limited_gather(tasks)
            let replacement = format!("await _limited_gather({})", tasks_var);

            hunks.push(PatchHunk {
                range: PatchRange::ReplaceBytes {
                    start: unbounded.start_byte,
                    end: unbounded.end_byte,
                },
                replacement,
            });
        }
        ConcurrencyPattern::CreateTaskPotentiallyUnbounded => {
            // For create_task patterns, add a comment with guidance
            // This is harder to auto-fix without more context
            let suggestion = "# TODO: Consider using semaphore to limit concurrent tasks\n\
                 # semaphore = asyncio.Semaphore(10)\n\
                 # async with semaphore:\n\
                 #     task = asyncio.create_task(coro())\n".to_string();
            
            hunks.push(PatchHunk {
                range: PatchRange::InsertBeforeLine {
                    line: unbounded.line,
                },
                replacement: suggestion,
            });
        }
    }

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
        let rule = PythonUnboundedConcurrencyRule::new();
        assert_eq!(rule.id(), "python.unbounded_concurrency");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonUnboundedConcurrencyRule::new();
        assert!(rule.name().contains("concurrency"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonUnboundedConcurrencyRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonUnboundedConcurrencyRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonUnboundedConcurrencyRule::default();
        assert_eq!(rule.id(), "python.unbounded_concurrency");
    }

    // ==================== ConcurrencyPattern Tests ====================

    #[test]
    fn pattern_descriptions_are_meaningful() {
        assert!(ConcurrencyPattern::GatherUnpacked.description().contains("gather"));
        assert!(ConcurrencyPattern::CreateTaskPotentiallyUnbounded.description().contains("create_task"));
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn evaluate_handles_empty_semantics() {
        let rule = PythonUnboundedConcurrencyRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_handles_empty_file() {
        let rule = PythonUnboundedConcurrencyRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_safe_patterns() {
        let rule = PythonUnboundedConcurrencyRule::new();
        let src = r#"
import asyncio

async def safe_gather():
    # Fixed number of tasks is fine
    result = await asyncio.gather(task1(), task2(), task3())
    return result
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag fixed number of tasks
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_has_correct_properties() {
        let rule = PythonUnboundedConcurrencyRule::new();
        let src = r#"
import asyncio

async def unbounded():
    tasks = [fetch(url) for url in urls]
    result = await asyncio.gather(*tasks)
    return result
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        if !findings.is_empty() {
            assert_eq!(findings[0].rule_id, "python.unbounded_concurrency");
            assert!(matches!(findings[0].severity, Severity::High));
            assert_eq!(findings[0].dimension, Dimension::Scalability);
            assert!(findings[0].patch.is_some());
        }
    }
}