//! Rule: Go regex compilation in function scope
//!
//! Detects `regexp.Compile()` or `regexp.MustCompile()` calls inside functions
//! that should be moved to package level for compile-once semantics.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::go::model::{GoCallSite, GoFileSemantics};
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects regex compilation inside functions.
///
/// `regexp.Compile()` and `regexp.MustCompile()` create compiled regex pattern
/// objects. When called inside a function, this compilation happens on every
/// function call, wasting CPU cycles. Moving the compilation to package level
/// ensures the regex is compiled only once when the package is initialized.
///
/// # Example
///
/// ```go
/// // Bad: Compiles regex on every function call
/// func validateEmail(email string) bool {
///     pattern := regexp.MustCompile(`^[\w\.-]+@[\w\.-]+\.\w+$`)
///     return pattern.MatchString(email)
/// }
///
/// // Good: Compiles regex once at package initialization
/// var emailPattern = regexp.MustCompile(`^[\w\.-]+@[\w\.-]+\.\w+$`)
///
/// func validateEmail(email string) bool {
///     return emailPattern.MatchString(email)
/// }
/// ```
#[derive(Debug)]
pub struct GoRegexCompileRule;

impl GoRegexCompileRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoRegexCompileRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a regex compilation inside a function
#[derive(Debug, Clone)]
struct RegexCompileInFunction {
    /// The callee being called (e.g., "regexp.MustCompile")
    #[allow(dead_code)]
    callee: String,
    /// Whether this is MustCompile (panics on error) or Compile (returns error)
    is_must_compile: bool,
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
}

#[async_trait]
impl Rule for GoRegexCompileRule {
    fn id(&self) -> &'static str {
        "go.regex_compile"
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
            let go = match sem.as_ref() {
                SourceSemantics::Go(go) => go,
                _ => continue,
            };

            // Find regexp.Compile/MustCompile calls that are inside functions
            for call in &go.calls {
                if is_regex_compile_call(&call.function_call.callee_expr) {
                    // Check if this call is inside a function
                    if let Some(func_name) = find_enclosing_function_or_method(go, call) {
                        let is_must_compile = call.function_call.callee_expr.contains("MustCompile");
                        let pattern_arg = extract_pattern_arg(&call.args_repr);
                        
                        let full_call = format!("{}{}", call.function_call.callee_expr, call.args_repr);

                        let regex_info = RegexCompileInFunction {
                            callee: call.function_call.callee_expr.clone(),
                            is_must_compile,
                            pattern_arg,
                            line: call.function_call.location.line,
                            column: call.function_call.location.column,
                            function_name: func_name,
                            start_byte: call.start_byte,
                            end_byte: call.end_byte,
                            full_call,
                        };

                        findings.push(create_finding(
                            self.id(),
                            &regex_info,
                            *file_id,
                            &go.path,
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
    callee == "regexp.Compile" 
        || callee == "regexp.MustCompile"
        || callee == "regexp.CompilePOSIX"
        || callee == "regexp.MustCompilePOSIX"
}

/// Find the enclosing function or method for a given call
fn find_enclosing_function_or_method(go: &GoFileSemantics, call: &GoCallSite) -> Option<String> {
    let call_line = call.function_call.location.line;
    
    // Check functions
    for func in &go.functions {
        let func_start = func.location.range.start_line;
        let func_end = func.location.range.end_line;
        
        if call_line >= func_start && call_line <= func_end {
            return Some(func.name.clone());
        }
    }
    
    // Check methods
    for method in &go.methods {
        let method_start = method.location.range.start_line;
        let method_end = method.location.range.end_line;
        
        if call_line >= method_start && call_line <= method_end {
            return Some(format!("{}.{}", method.receiver_type, method.name));
        }
    }
    
    None
}

/// Extract the pattern argument from the call args representation
fn extract_pattern_arg(args_repr: &str) -> Option<String> {
    let trimmed = args_repr.trim();
    if trimmed.is_empty() {
        return None;
    }
    
    // Remove parentheses
    let inner = trimmed.trim_start_matches('(').trim_end_matches(')').trim();
    
    if inner.is_empty() {
        None
    } else {
        Some(inner.to_string())
    }
}

/// Generate a suggested constant name from the function and pattern context
fn suggest_constant_name(regex_info: &RegexCompileInFunction) -> String {
    // Try to extract a meaningful name from the pattern
    if let Some(ref pattern) = regex_info.pattern_arg {
        // Common pattern prefixes
        if pattern.contains("email") || pattern.contains("@") {
            return "emailPattern".to_string();
        }
        if pattern.contains("url") || pattern.contains("http") {
            return "urlPattern".to_string();
        }
        if pattern.contains("phone") || pattern.contains(r"\d{3}") {
            return "phonePattern".to_string();
        }
    }
    
    // Default: derive from function name
    let base = regex_info.function_name
        .split('.')
        .last()
        .unwrap_or(&regex_info.function_name);
    
    // Convert to camelCase pattern name
    format!("{}Pattern", to_camel_case(base))
}

/// Convert a string to camelCase
fn to_camel_case(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = false;
    
    for c in s.chars() {
        if c == '_' || c == '-' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(c.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            result.push(c);
        }
    }
    
    result
}

fn create_finding(
    rule_id: &str,
    regex_info: &RegexCompileInFunction,
    file_id: FileId,
    file_path: &str,
) -> RuleFinding {
    let compile_fn = if regex_info.is_must_compile {
        "regexp.MustCompile()"
    } else {
        "regexp.Compile()"
    };
    
    let title = format!(
        "{} in function '{}' recompiles on every call",
        compile_fn,
        regex_info.function_name
    );

    let suggested_name = suggest_constant_name(regex_info);
    
    let description = format!(
        "The regex compilation '{}' inside function '{}' will recompile the pattern \
         on every function call. Move the {} call to package level as a \
         variable like 'var {} = {}(...)' to compile once at package initialization.\n\n\
         Benefits:\n\
         - Faster function execution (no recompilation overhead)\n\
         - Early error detection (compilation errors at startup, not runtime)\n\
         - Idiomatic Go pattern for regex usage",
        regex_info.full_call,
        regex_info.function_name,
        compile_fn,
        suggested_name,
        compile_fn.trim_end_matches("()"),
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
            "go".into(),
            "regex".into(),
            "regexp".into(),
            "performance".into(),
            "compile-once".into(),
        ],
    }
}

fn generate_patch(regex_info: &RegexCompileInFunction, file_id: FileId) -> (FilePatch, String) {
    let suggested_name = suggest_constant_name(regex_info);
    let pattern_arg = regex_info.pattern_arg.as_deref().unwrap_or("`pattern`");
    
    let compile_fn = if regex_info.is_must_compile {
        "regexp.MustCompile"
    } else {
        "regexp.Compile"
    };
    
    // For the fix preview, show the before/after transformation
    let fix_preview = format!(
        r#"// Before (recompiles on every call):
func {}(...) {{
    pattern := {}({})
    ...
}}

// After (compiles once at package initialization):
var {} = {}({})

func {}(...) {{
    // Use {} directly
    ...
}}"#,
        regex_info.function_name.split('.').last().unwrap_or(&regex_info.function_name),
        compile_fn,
        pattern_arg,
        suggested_name,
        compile_fn,
        pattern_arg,
        regex_info.function_name.split('.').last().unwrap_or(&regex_info.function_name),
        suggested_name,
    );

    // The patch replaces the compile call with the suggested variable name
    let patch = FilePatch {
        file_id,
        hunks: vec![
            PatchHunk {
                range: PatchRange::ReplaceBytes {
                    start: regex_info.start_byte,
                    end: regex_info.end_byte,
                },
                replacement: suggested_name.clone(),
            },
        ],
    };

    (patch, fix_preview)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::go::parse_go_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::go::build_go_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.go".to_string(),
            language: Language::Go,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_go_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_go_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Go(sem)))
    }

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = GoRegexCompileRule::new();
        assert_eq!(rule.id(), "go.regex_compile");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = GoRegexCompileRule::new();
        assert!(rule.name().contains("regex") || rule.name().contains("Regex"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = GoRegexCompileRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GoRegexCompileRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = GoRegexCompileRule::default();
        assert_eq!(rule.id(), "go.regex_compile");
    }

    // ==================== Detection Tests ====================

    #[tokio::test]
    async fn detects_mustcompile_in_function() {
        let rule = GoRegexCompileRule::new();
        let src = r#"
package main

import "regexp"

func validateEmail(email string) bool {
    pattern := regexp.MustCompile(`^[\w\.-]+@[\w\.-]+\.\w+$`)
    return pattern.MatchString(email)
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1, "Should detect regexp.MustCompile in function");
        assert_eq!(findings[0].rule_id, "go.regex_compile");
        assert!(findings[0].description.as_ref().unwrap().contains("validateEmail"));
    }

    #[tokio::test]
    async fn detects_compile_in_function() {
        let rule = GoRegexCompileRule::new();
        let src = r#"
package main

import "regexp"

func parseData(data string) (*regexp.Regexp, error) {
    pattern, err := regexp.Compile(`\d+`)
    if err != nil {
        return nil, err
    }
    return pattern, nil
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1, "Should detect regexp.Compile in function");
    }

    #[tokio::test]
    async fn no_finding_for_package_level_compile() {
        let rule = GoRegexCompileRule::new();
        let src = r#"
package main

import "regexp"

var emailPattern = regexp.MustCompile(`^[\w\.-]+@[\w\.-]+\.\w+$`)

func validateEmail(email string) bool {
    return emailPattern.MatchString(email)
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert!(findings.is_empty(), "Should not flag package-level regexp.MustCompile");
    }

    #[tokio::test]
    async fn detects_multiple_compile_in_function() {
        let rule = GoRegexCompileRule::new();
        let src = r#"
package main

import "regexp"

func parseAll(text string) {
    emailRe := regexp.MustCompile(`email-pattern`)
    phoneRe := regexp.MustCompile(`phone-pattern`)
    _ = emailRe
    _ = phoneRe
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 2, "Should detect both regexp.MustCompile calls");
    }

    #[tokio::test]
    async fn detects_compile_in_method() {
        let rule = GoRegexCompileRule::new();
        let src = r#"
package main

import "regexp"

type Validator struct{}

func (v *Validator) Validate(text string) bool {
    pattern := regexp.MustCompile(`\w+`)
    return pattern.MatchString(text)
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1, "Should detect regexp.MustCompile in method");
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = GoRegexCompileRule::new();
        let (file_id, sem) = parse_and_build_semantics("package main");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = GoRegexCompileRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Finding Properties Tests ====================

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = GoRegexCompileRule::new();
        let src = r#"
package main

import "regexp"

func validate(text string) bool {
    pattern := regexp.MustCompile(`\d+`)
    return pattern.MatchString(text)
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        
        assert_eq!(finding.rule_id, "go.regex_compile");
        assert!(matches!(finding.kind, FindingKind::PerformanceSmell));
        assert_eq!(finding.dimension, Dimension::Performance);
        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.confidence > 0.9);
        assert!(finding.patch.is_some());
        assert!(finding.fix_preview.is_some());
        assert!(finding.tags.contains(&"regexp".to_string()));
        assert!(finding.tags.contains(&"compile-once".to_string()));
    }

    #[tokio::test]
    async fn finding_description_mentions_function_name() {
        let rule = GoRegexCompileRule::new();
        let src = r#"
package main

import "regexp"

func mySpecialValidator(text string) bool {
    pattern := regexp.MustCompile(`\d+`)
    return pattern.MatchString(text)
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1);
        let description = findings[0].description.as_ref().unwrap();
        assert!(description.contains("mySpecialValidator"));
    }

    // ==================== Helper Function Tests ====================

    #[test]
    fn is_regex_compile_call_detects_variants() {
        assert!(is_regex_compile_call("regexp.Compile"));
        assert!(is_regex_compile_call("regexp.MustCompile"));
        assert!(is_regex_compile_call("regexp.CompilePOSIX"));
        assert!(is_regex_compile_call("regexp.MustCompilePOSIX"));
        assert!(!is_regex_compile_call("regexp.Match"));
        assert!(!is_regex_compile_call("compile"));
    }

    #[test]
    fn extract_pattern_arg_handles_backtick_string() {
        assert_eq!(
            extract_pattern_arg("(`^pattern$`)"),
            Some("`^pattern$`".to_string())
        );
    }

    #[test]
    fn extract_pattern_arg_handles_quoted_string() {
        assert_eq!(
            extract_pattern_arg(r#"("^pattern$")"#),
            Some(r#""^pattern$""#.to_string())
        );
    }

    #[test]
    fn extract_pattern_arg_handles_empty_args() {
        assert_eq!(extract_pattern_arg("()"), None);
        assert_eq!(extract_pattern_arg(""), None);
    }

    #[test]
    fn to_camel_case_works() {
        assert_eq!(to_camel_case("validate"), "validate");
        assert_eq!(to_camel_case("validate_email"), "validateEmail");
        assert_eq!(to_camel_case("parse-data"), "parseData");
    }

    #[test]
    fn suggest_constant_name_uses_function_name() {
        let info = RegexCompileInFunction {
            callee: "regexp.MustCompile".to_string(),
            is_must_compile: true,
            pattern_arg: Some("`\\d+`".to_string()),
            line: 5,
            column: 15,
            function_name: "validate_input".to_string(),
            start_byte: 100,
            end_byte: 150,
            full_call: "regexp.MustCompile(`\\d+`)".to_string(),
        };
        
        let name = suggest_constant_name(&info);
        assert_eq!(name, "validateInputPattern");
    }
}