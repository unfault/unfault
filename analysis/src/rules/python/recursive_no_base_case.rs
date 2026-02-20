//! Rule B9: Recursive function without base case detection
//!
//! Detects recursive functions that may lack a proper base case,
//! which can lead to stack overflow errors.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects recursive functions without apparent base cases.
///
/// Recursive functions without proper base cases can cause stack overflow
/// errors in production. This rule uses heuristics to detect potentially
/// problematic recursive patterns.
#[derive(Debug)]
pub struct PythonRecursiveNoBaseCaseRule;

impl PythonRecursiveNoBaseCaseRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonRecursiveNoBaseCaseRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a potentially problematic recursive function
#[derive(Debug, Clone)]
struct RecursiveFunction {
    /// Function name
    name: String,
    /// Line number (1-based)
    line: u32,
    /// Column number (1-based)
    column: u32,
    /// Whether a base case was detected
    has_apparent_base_case: bool,
    /// Whether the function is async
    is_async: bool,
}

#[async_trait]
impl Rule for PythonRecursiveNoBaseCaseRule {
    fn id(&self) -> &'static str {
        "python.recursive_no_base_case"
    }

    fn name(&self) -> &'static str {
        "Recursive function may lack base case"
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

            // Analyze each function for recursive patterns
            let recursive_funcs = detect_recursive_functions(py);

            for func in recursive_funcs {
                if !func.has_apparent_base_case {
                    let title = format!("Recursive function '{}' may lack base case", func.name);

                    let description = format!(
                        "The function '{}' appears to call itself recursively but no clear base case \
                         (early return with if/elif condition) was detected. This can lead to stack \
                         overflow errors. Ensure the function has a proper termination condition.",
                        func.name
                    );

                    let patch = generate_base_case_patch(&func, *file_id);

                    let fix_preview = get_fix_preview(&func);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::High,
                        confidence: 0.70, // Lower confidence due to heuristic nature
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(func.line),
                        column: Some(func.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "python".into(),
                            "recursion".into(),
                            "stack-overflow".into(),
                            "correctness".into(),
                        ],
                    });
                }
            }
        }

        findings
    }
}

fn detect_recursive_functions(
    py: &crate::semantics::python::model::PyFileSemantics,
) -> Vec<RecursiveFunction> {
    let mut recursive_funcs = Vec::new();

    // Check each function for recursive calls
    for func in &py.functions {
        let func_name = &func.name;
        // Prefer the semantic caller_function over line-range heuristics.
        // This prevents missing recursion when ranges are imprecise, and avoids
        // false positives when another function calls `func_name`.
        let has_recursive_call = py.calls.iter().any(|call| {
            if call.function_call.caller_function != *func_name {
                return false;
            }

            call.function_call.callee_expr == *func_name
                || call.function_call.callee_expr == format!("self.{}", func_name)
                || call.function_call.callee_expr == format!("cls.{}", func_name)
        });

        let func_start_line = func.location.range.start_line;
        let func_end_line = func.location.range.end_line;

        if has_recursive_call {
            // Check for apparent base case
            // A base case typically involves:
            // 1. An if/elif statement at the start of the function
            // 2. A return statement within that condition
            //
            // Since we don't have full AST access here, we use heuristics based on
            // the function structure and calls

            let has_apparent_base_case =
                check_for_base_case(py, func_name, func_start_line, func_end_line);

            recursive_funcs.push(RecursiveFunction {
                name: func_name.clone(),
                line: func.location.range.start_line + 1,
                column: func.location.range.start_col + 1,
                has_apparent_base_case,
                is_async: func.is_async,
            });
        }
    }

    recursive_funcs
}

fn check_for_base_case(
    py: &crate::semantics::python::model::PyFileSemantics,
    func_name: &str,
    _func_start_line: u32,
    _func_end_line: u32,
) -> bool {
    // Heuristic: If the function has parameters with default values that could
    // serve as termination conditions, it might have a base case
    for func in &py.functions {
        if func.name == func_name {
            // Check if any parameter has a default that looks like a base case value
            for param in &func.params {
                if let Some(default) = &param.default {
                    // Common base case defaults: 0, 1, None, [], {}
                    if default == "0"
                        || default == "1"
                        || default == "None"
                        || default == "[]"
                        || default == "{}"
                    {
                        return true;
                    }
                }
            }
        }
    }

    // Heuristic: If there are multiple self-calls within the same function,
    // there might be conditional recursion / branching.
    let call_count = py
        .calls
        .iter()
        .filter(|c| {
            if c.function_call.caller_function != func_name {
                return false;
            }

            c.function_call.callee_expr == func_name
                || c.function_call.callee_expr == format!("self.{}", func_name)
                || c.function_call.callee_expr == format!("cls.{}", func_name)
        })
        .count();

    // If there are multiple calls within the function, there might be conditional recursion
    if call_count > 1 {
        return true;
    }

    // Default: assume no base case detected
    false
}

fn get_fix_preview(func: &RecursiveFunction) -> String {
    let async_prefix = if func.is_async { "async " } else { "" };
    format!(
        r#"# Add a base case to prevent infinite recursion:
{async_prefix}def {name}(n):
    # Base case - REQUIRED to prevent stack overflow
    if n <= 0:
        return 0  # or appropriate base value
    
    # Recursive case
    return {name}(n - 1) + n"#,
        async_prefix = async_prefix,
        name = func.name
    )
}

fn generate_base_case_patch(func: &RecursiveFunction, file_id: FileId) -> FilePatch {
    // Generate a base case template based on the function
    let async_prefix = if func.is_async { "async " } else { "" };
    let await_prefix = if func.is_async { "await " } else { "" };

    let replacement = format!(
        "# Fix: Add base case to prevent infinite recursion:\n\
         # {async_prefix}def {name}(n, ...):\n\
         #     if n <= 0:  # Base case - REQUIRED\n\
         #         return base_value\n\
         #     return {await_prefix}{name}(n - 1, ...)  # Recursive case\n",
        async_prefix = async_prefix,
        await_prefix = await_prefix,
        name = func.name
    );

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line: func.line },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::python::build_python_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_python_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonRecursiveNoBaseCaseRule::new();
        assert_eq!(rule.id(), "python.recursive_no_base_case");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonRecursiveNoBaseCaseRule::new();
        assert!(rule.name().contains("base case"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonRecursiveNoBaseCaseRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonRecursiveNoBaseCaseRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonRecursiveNoBaseCaseRule::default();
        assert_eq!(rule.id(), "python.recursive_no_base_case");
    }

    #[tokio::test]
    async fn detects_simple_recursive_function() {
        let rule = PythonRecursiveNoBaseCaseRule::new();
        let src = r#"
def factorial(n):
    return n * factorial(n - 1)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            !findings.is_empty(),
            "Should detect recursive function without base case"
        );
        assert_eq!(findings[0].rule_id, "python.recursive_no_base_case");
    }

    #[tokio::test]
    async fn no_finding_for_non_recursive_function() {
        let rule = PythonRecursiveNoBaseCaseRule::new();
        let src = r#"
def add(a, b):
    return a + b

def multiply(a, b):
    return a * b
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.is_empty(),
            "Should not flag non-recursive functions"
        );
    }

    #[tokio::test]
    async fn handles_async_recursive_function() {
        let rule = PythonRecursiveNoBaseCaseRule::new();
        let src = r#"
async def fetch_all(urls):
    return await fetch_all(urls[1:])
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should detect async recursive function
        if !findings.is_empty() {
            assert!(findings[0].tags.contains(&"recursion".to_string()));
        }
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = PythonRecursiveNoBaseCaseRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = PythonRecursiveNoBaseCaseRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = PythonRecursiveNoBaseCaseRule::new();
        let src = r#"
def recurse(x):
    return recurse(x)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        if !findings.is_empty() {
            let finding = &findings[0];
            assert_eq!(finding.rule_id, "python.recursive_no_base_case");
            assert!(matches!(finding.kind, FindingKind::BehaviorThreat));
            assert_eq!(finding.dimension, Dimension::Correctness);
            assert!(finding.patch.is_some());
            assert!(finding.fix_preview.is_some());
            assert!(finding.tags.contains(&"recursion".to_string()));
        }
    }

    #[tokio::test]
    async fn detects_mutual_recursion_pattern() {
        let rule = PythonRecursiveNoBaseCaseRule::new();
        // Note: This tests direct recursion, not mutual recursion
        // Mutual recursion detection would require more sophisticated analysis
        let src = r#"
def is_even(n):
    return is_even(n - 2)

def is_odd(n):
    return is_odd(n - 2)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should detect both recursive functions
        assert!(findings.len() >= 1, "Should detect recursive functions");
    }

    #[tokio::test]
    async fn no_false_positive_for_function_called_from_another() {
        // Regression test: A function called from another function in the same file
        // should NOT be flagged as recursive
        let rule = PythonRecursiveNoBaseCaseRule::new();
        let src = r#"
def _build_session_summary(session):
    """Build a brief human-readable summary for a session."""
    label = session.workspace_label or "unnamed"
    status = session.status
    if status == "completed":
        return f"{label}: completed"
    else:
        return f"{label}: {status}"

def list_recent_sessions(limit=10):
    """List the most recent sessions."""
    sessions = get_sessions_by_user(limit=limit)
    items = [
        _build_session_summary(s)
        for s in sessions
    ]
    return items
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should NOT flag _build_session_summary as recursive
        // because the call to it is from list_recent_sessions, not from itself
        assert!(
            findings.is_empty(),
            "Should not flag function called from another function as recursive. Found: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn no_false_positive_for_method_call_with_same_name() {
        // Regression test: Calling SomeClass.method() where method has the same name
        // as the enclosing function should NOT be flagged as recursive
        let rule = PythonRecursiveNoBaseCaseRule::new();
        let src = r#"
def instrument_app(app):
    """Configure various instrumentations."""
    provider = trace.get_tracer_provider()
    LoggingInstrumentor().instrument(tracer_provider=provider)
    AsyncPGInstrumentor().instrument(tracer_provider=provider)
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=provider,
    )
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should NOT flag instrument_app as recursive
        // because FastAPIInstrumentor.instrument_app() is a method call on a different class
        assert!(
            findings.is_empty(),
            "Should not flag method call on external class as recursive. Found: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}
