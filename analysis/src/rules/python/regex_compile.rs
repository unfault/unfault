//! Rule: Python regex compilation in function scope
//!
//! Detects `re.compile()` calls inside functions that should be moved to
//! module level for compile-once semantics.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::{ImportInsertionType, PyCallSite, PyFileSemantics, PyFunction};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects regex compilation inside functions.
///
/// `re.compile()` creates a compiled regex pattern object. When called inside
/// a function, this compilation happens on every function call, wasting CPU
/// cycles. Moving the compilation to module level ensures the regex is compiled
/// only once when the module is loaded.
///
/// # Example
///
/// ```python
/// # Bad: Compiles regex on every function call
/// def validate_email(email):
///     pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
///     return pattern.match(email)
///
/// # Good: Compiles regex once at module load
/// EMAIL_PATTERN = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
///
/// def validate_email(email):
///     return EMAIL_PATTERN.match(email)
/// ```
#[derive(Debug)]
pub struct PythonRegexCompileRule;

impl PythonRegexCompileRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonRegexCompileRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a regex compilation inside a function
#[derive(Debug, Clone)]
struct RegexCompileInFunction {
    /// The callee being called (e.g., "re.compile")
    #[allow(dead_code)]
    callee: String,
    /// The pattern argument (if can be extracted)
    pattern_arg: Option<String>,
    /// Line number (1-based)
    line: u32,
    /// Column number (1-based)
    column: u32,
    /// Name of the enclosing function
    function_name: String,
    /// Start byte offset for the call
    start_byte: usize,
    /// End byte offset for the call
    end_byte: usize,
    /// The full call representation including args
    full_call: String,
    /// Line where imports should be inserted
    import_insertion_line: u32,
    /// Whether the assignment target can be extracted
    assignment_target: Option<String>,
}

#[async_trait]
impl Rule for PythonRegexCompileRule {
    fn id(&self) -> &'static str {
        "python.regex_compile"
    }

    fn name(&self) -> &'static str {
        "Regex compilation inside function recompiles on every call"
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

            // Find re.compile calls that are inside functions
            for call in &py.calls {
                if is_regex_compile_call(&call.function_call.callee_expr) {
                    // Check if this call is inside a function
                    if let Some(func_name) = find_enclosing_function(&py.functions, call.function_call.location.line) {
                        // Extract pattern argument if possible
                        let pattern_arg = extract_pattern_arg(&call.args_repr);
                        
                        // Try to find if this is an assignment
                        let assignment_target = find_assignment_target(py, call);
                        
                        let full_call = if call.args_repr.is_empty() {
                            call.function_call.callee_expr.clone()
                        } else {
                            format!("{}({})", call.function_call.callee_expr, call.args_repr)
                        };

                        let regex_info = RegexCompileInFunction {
                            callee: call.function_call.callee_expr.clone(),
                            pattern_arg,
                            line: call.function_call.location.line,
                            column: call.function_call.location.column,
                            function_name: func_name,
                            start_byte: call.start_byte,
                            end_byte: call.end_byte,
                            full_call,
                            import_insertion_line: py.import_insertion_line_for(ImportInsertionType::stdlib_from_import()),
                            assignment_target,
                        };

                        findings.push(create_finding(
                            self.id(),
                            &regex_info,
                            *file_id,
                            &py.path,
                        ));
                    }
                }
            }
        }

        findings
    }
}

/// Check if a callee is a regex compile call
fn is_regex_compile_call(callee: &str) -> bool {
    callee == "re.compile" || callee == "regex.compile"
}

/// Find the enclosing function for a given line
fn find_enclosing_function(functions: &[PyFunction], call_line: u32) -> Option<String> {
    let mut best_match: Option<&PyFunction> = None;
    
    for func in functions {
        let func_start = func.location.range.start_line;
        let func_end = func.location.range.end_line;
        
        // Check if the call is within the function's range
        if call_line >= func_start && call_line <= func_end {
            match best_match {
                None => best_match = Some(func),
                Some(current) => {
                    // Prefer the innermost function (the one that starts later)
                    if func_start > current.location.range.start_line {
                        best_match = Some(func);
                    }
                }
            }
        }
    }

    best_match.map(|f| f.name.clone())
}

/// Extract the pattern argument from the call args representation
fn extract_pattern_arg(args_repr: &str) -> Option<String> {
    // Try to extract the first argument (the pattern)
    // Handle cases like: (r'^pattern$'), (pattern, flags), etc.
    let trimmed = args_repr.trim();
    if trimmed.is_empty() {
        return None;
    }
    
    // Remove parentheses if present
    let inner = trimmed.trim_start_matches('(').trim_end_matches(')');
    
    // Get the first argument (before any comma)
    let first_arg = if let Some(comma_pos) = find_unquoted_comma(inner) {
        inner[..comma_pos].trim()
    } else {
        inner.trim()
    };
    
    if first_arg.is_empty() {
        None
    } else {
        Some(first_arg.to_string())
    }
}

/// Find the position of a comma that's not inside quotes
fn find_unquoted_comma(s: &str) -> Option<usize> {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev_char = None;
    
    for (i, c) in s.char_indices() {
        match c {
            '\'' if !in_double_quote && prev_char != Some('\\') => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote && prev_char != Some('\\') => {
                in_double_quote = !in_double_quote;
            }
            ',' if !in_single_quote && !in_double_quote => {
                return Some(i);
            }
            _ => {}
        }
        prev_char = Some(c);
    }
    
    None
}

/// Try to find if this call is part of an assignment
fn find_assignment_target(py: &PyFileSemantics, call: &PyCallSite) -> Option<String> {
    // Look for assignments where the value_repr contains this call
    for assign in &py.assignments {
        // Check if this assignment contains our call
        if assign.location.range.start_line == call.function_call.location.line {
            // Simple heuristic: if the assignment is on the same line, it's likely the target
            if !assign.is_module_level {
                return Some(assign.target.clone());
            }
        }
    }
    None
}

/// Generate a suggested constant name from the function and variable context
fn suggest_constant_name(regex_info: &RegexCompileInFunction) -> String {
    // If we have an assignment target, uppercase it
    if let Some(ref target) = regex_info.assignment_target {
        return target.to_uppercase() + "_PATTERN";
    }
    
    // Otherwise, derive from function name
    let base = regex_info.function_name.to_uppercase();
    format!("{}_PATTERN", base)
}

fn create_finding(
    rule_id: &str,
    regex_info: &RegexCompileInFunction,
    file_id: FileId,
    file_path: &str,
) -> RuleFinding {
    let title = format!(
        "Regex compilation in function '{}' recompiles on every call",
        regex_info.function_name
    );

    let suggested_name = suggest_constant_name(regex_info);
    
    let description = format!(
        "The regex compilation '{}' inside function '{}' will recompile the pattern \
         on every function call. Move the re.compile() to module level as a constant \
         like '{}' to compile once when the module loads.\n\n\
         Benefits:\n\
         - Faster function execution (no recompilation)\n\
         - Clearer code structure (patterns are visible at module level)\n\
         - Early error detection (compilation errors on module import)",
        regex_info.full_call,
        regex_info.function_name,
        suggested_name,
    );

    let (patch, fix_preview) = generate_patch(regex_info, file_id);

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::PerformanceSmell,
        severity: Severity::Low,
        confidence: 0.95,
        dimension: Dimension::Performance,
        file_id,
        file_path: file_path.to_string(),
        line: Some(regex_info.line),
        column: Some(regex_info.column),
        end_line: None,
        end_column: None,
            byte_range: None,
        patch: Some(patch),
        fix_preview: Some(fix_preview),
        tags: vec![
            "python".into(),
            "regex".into(),
            "performance".into(),
            "compile-once".into(),
        ],
    }
}

fn generate_patch(regex_info: &RegexCompileInFunction, file_id: FileId) -> (FilePatch, String) {
    let suggested_name = suggest_constant_name(regex_info);
    
    // Create the module-level constant definition
    let pattern_arg = regex_info.pattern_arg.as_deref().unwrap_or("r'pattern'");
    let constant_def = format!(
        "{} = re.compile({})\n",
        suggested_name,
        pattern_arg
    );
    
    // For the fix preview, show the before/after transformation
    let fix_preview = format!(
        r#"# Before (recompiles on every call):
def {}(...):
    pattern = re.compile({})
    ...

# After (compiles once at module load):
{} = re.compile({})

def {}(...):
    # Use {} directly
    ..."#,
        regex_info.function_name,
        pattern_arg,
        suggested_name,
        pattern_arg,
        regex_info.function_name,
        suggested_name,
    );

    // Create hunks:
    // 1. Insert the constant at module level (after imports)
    let hunks = vec![
        PatchHunk {
            range: PatchRange::InsertBeforeLine { 
                line: regex_info.import_insertion_line + 1  // After imports
            },
            replacement: format!("\n{}", constant_def),
        },
        // 2. Replace the re.compile() call with the constant reference
        PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: regex_info.start_byte,
                end: regex_info.end_byte,
            },
            replacement: suggested_name.clone(),
        },
    ];

    let patch = FilePatch {
        file_id,
        hunks,
    };

    (patch, fix_preview)
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

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonRegexCompileRule::new();
        assert_eq!(rule.id(), "python.regex_compile");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonRegexCompileRule::new();
        assert!(rule.name().contains("regex") || rule.name().contains("Regex"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonRegexCompileRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonRegexCompileRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonRegexCompileRule::default();
        assert_eq!(rule.id(), "python.regex_compile");
    }

    // ==================== Detection Tests ====================

    #[tokio::test]
    async fn detects_re_compile_in_function() {
        let rule = PythonRegexCompileRule::new();
        let src = r#"
import re

def validate_email(email):
    pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return pattern.match(email)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1, "Should detect re.compile in function");
        assert_eq!(findings[0].rule_id, "python.regex_compile");
        assert!(findings[0].description.as_ref().unwrap().contains("validate_email"));
    }

    #[tokio::test]
    async fn no_finding_for_module_level_compile() {
        let rule = PythonRegexCompileRule::new();
        let src = r#"
import re

EMAIL_PATTERN = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')

def validate_email(email):
    return EMAIL_PATTERN.match(email)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert!(findings.is_empty(), "Should not flag module-level re.compile");
    }

    #[tokio::test]
    async fn detects_multiple_compile_in_function() {
        let rule = PythonRegexCompileRule::new();
        let src = r#"
import re

def parse_data(text):
    email_pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    phone_pattern = re.compile(r'^\d{3}-\d{3}-\d{4}$')
    return email_pattern, phone_pattern
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 2, "Should detect both re.compile calls");
    }

    #[tokio::test]
    async fn detects_compile_in_nested_function() {
        let rule = PythonRegexCompileRule::new();
        let src = r#"
import re

def outer():
    def inner():
        pattern = re.compile(r'\d+')
        return pattern
    return inner
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1, "Should detect re.compile in nested function");
    }

    #[tokio::test]
    async fn detects_compile_in_async_function() {
        let rule = PythonRegexCompileRule::new();
        let src = r#"
import re

async def process_data(text):
    pattern = re.compile(r'pattern')
    return pattern.findall(text)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1, "Should detect re.compile in async function");
    }

    #[tokio::test]
    async fn detects_compile_in_method() {
        let rule = PythonRegexCompileRule::new();
        let src = r#"
import re

class Validator:
    def validate(self, text):
        pattern = re.compile(r'\w+')
        return pattern.match(text)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1, "Should detect re.compile in class method");
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = PythonRegexCompileRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = PythonRegexCompileRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_for_non_python_semantics() {
        let rule = PythonRegexCompileRule::new();
        // Create a file that won't have Python semantics
        let sf = SourceFile {
            path: "test.rs".to_string(),
            language: Language::Rust,
            content: "fn main() {}".to_string(),
        };
        let file_id = FileId(1);
        
        // Manually create non-Python semantics for the test
        let parsed = crate::parse::rust::parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let rust_sem = crate::semantics::rust::build_rust_semantics(&parsed).expect("semantics should build");
        let sem = Arc::new(SourceSemantics::Rust(rust_sem));
        
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Finding Properties Tests ====================

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = PythonRegexCompileRule::new();
        let src = r#"
import re

def validate(text):
    pattern = re.compile(r'\d+')
    return pattern.match(text)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        
        assert_eq!(finding.rule_id, "python.regex_compile");
        assert!(matches!(finding.kind, FindingKind::PerformanceSmell));
        assert_eq!(finding.dimension, Dimension::Performance);
        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.confidence > 0.9);
        assert!(finding.patch.is_some());
        assert!(finding.fix_preview.is_some());
        assert!(finding.tags.contains(&"regex".to_string()));
        assert!(finding.tags.contains(&"compile-once".to_string()));
    }

    #[tokio::test]
    async fn finding_description_mentions_function_name() {
        let rule = PythonRegexCompileRule::new();
        let src = r#"
import re

def my_special_validator(text):
    pattern = re.compile(r'\d+')
    return pattern.match(text)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1);
        let description = findings[0].description.as_ref().unwrap();
        assert!(description.contains("my_special_validator"));
    }

    // ==================== Helper Function Tests ====================

    #[test]
    fn is_regex_compile_call_detects_re_compile() {
        assert!(is_regex_compile_call("re.compile"));
        assert!(is_regex_compile_call("regex.compile"));
        assert!(!is_regex_compile_call("re.match"));
        assert!(!is_regex_compile_call("compile"));
        assert!(!is_regex_compile_call("re.search"));
    }

    #[test]
    fn extract_pattern_arg_handles_simple_pattern() {
        assert_eq!(
            extract_pattern_arg("(r'^pattern$')"),
            Some("r'^pattern$'".to_string())
        );
    }

    #[test]
    fn extract_pattern_arg_handles_pattern_with_flags() {
        assert_eq!(
            extract_pattern_arg("(r'^pattern$', re.IGNORECASE)"),
            Some("r'^pattern$'".to_string())
        );
    }

    #[test]
    fn extract_pattern_arg_handles_empty_args() {
        assert_eq!(extract_pattern_arg("()"), None);
        assert_eq!(extract_pattern_arg(""), None);
    }

    #[test]
    fn find_unquoted_comma_works_correctly() {
        assert_eq!(find_unquoted_comma("a, b"), Some(1));
        assert_eq!(find_unquoted_comma("'a,b', c"), Some(5));
        assert_eq!(find_unquoted_comma(r#""a,b", c"#), Some(5));
        assert_eq!(find_unquoted_comma("abc"), None);
    }

    #[test]
    fn suggest_constant_name_uses_function_name() {
        let info = RegexCompileInFunction {
            callee: "re.compile".to_string(),
            pattern_arg: Some(r"r'\d+'".to_string()),
            line: 5,
            column: 15,
            function_name: "validate_email".to_string(),
            start_byte: 100,
            end_byte: 150,
            full_call: "re.compile(r'\\d+')".to_string(),
            import_insertion_line: 2,
            assignment_target: None,
        };
        
        let name = suggest_constant_name(&info);
        assert_eq!(name, "VALIDATE_EMAIL_PATTERN");
    }

    #[test]
    fn suggest_constant_name_uses_assignment_target() {
        let info = RegexCompileInFunction {
            callee: "re.compile".to_string(),
            pattern_arg: Some(r"r'\d+'".to_string()),
            line: 5,
            column: 15,
            function_name: "validate".to_string(),
            start_byte: 100,
            end_byte: 150,
            full_call: "re.compile(r'\\d+')".to_string(),
            import_insertion_line: 2,
            assignment_target: Some("email_regex".to_string()),
        };
        
        let name = suggest_constant_name(&info);
        assert_eq!(name, "EMAIL_REGEX_PATTERN");
    }
}