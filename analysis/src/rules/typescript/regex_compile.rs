//! Rule: TypeScript regex creation in function scope
//!
//! Detects `new RegExp()` calls inside functions that should be moved to
//! module level for compile-once semantics.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::typescript::model::{TsCallSite, TsFileSemantics, TsFunction};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects regex creation inside functions.
///
/// `new RegExp()` creates a new RegExp object. When called inside a function,
/// this creation happens on every function call, wasting CPU cycles. Moving
/// the RegExp to module level as a constant ensures the regex is compiled
/// only once when the module is loaded.
///
/// # Example
///
/// ```typescript
/// // Bad: Creates regex on every function call
/// function validateEmail(email: string): boolean {
///     const pattern = new RegExp('^[\\w\\.-]+@[\\w\\.-]+\\.\\w+$');
///     return pattern.test(email);
/// }
///
/// // Good: Creates regex once at module load
/// const EMAIL_PATTERN = /^[\w\.-]+@[\w\.-]+\.\w+$/;
///
/// function validateEmail(email: string): boolean {
///     return EMAIL_PATTERN.test(email);
/// }
/// ```
#[derive(Debug)]
pub struct TypescriptRegexCompileRule;

impl TypescriptRegexCompileRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptRegexCompileRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a regex creation inside a function
#[derive(Debug, Clone)]
struct RegexInFunction {
    /// The callee being called (e.g., "RegExp", "new RegExp")
    callee: String,
    /// The pattern argument (if can be extracted)
    pattern_arg: Option<String>,
    /// The flags argument (if present)
    flags_arg: Option<String>,
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
impl Rule for TypescriptRegexCompileRule {
    fn id(&self) -> &'static str {
        "typescript.regex_compile"
    }

    fn name(&self) -> &'static str {
        "Regex creation inside function creates new object on every call"
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

            // Find new RegExp() calls that are inside functions
            for call in &ts.calls {
                if is_regexp_constructor_call(&call.callee) {
                    // Check if this call is inside a function
                    if let Some(func_name) = find_enclosing_function(&ts.functions, call) {
                        let (pattern_arg, flags_arg) = extract_regexp_args(&call.args_repr);
                        
                        let full_call = format!("{}{}", call.callee, call.args_repr);

                        let regex_info = RegexInFunction {
                            callee: call.callee.clone(),
                            pattern_arg,
                            flags_arg,
                            line: call.location.range.start_line + 1,
                            column: call.location.range.start_col + 1,
                            function_name: func_name,
                            start_byte: call.start_byte,
                            end_byte: call.end_byte,
                            full_call,
                        };

                        findings.push(create_finding(
                            self.id(),
                            &regex_info,
                            *file_id,
                            &ts.path,
                        ));
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::regex_compile())
    }
}

/// Check if a callee is a RegExp constructor call
fn is_regexp_constructor_call(callee: &str) -> bool {
    callee == "RegExp" || callee == "new RegExp"
}

/// Find the enclosing function for a given call
fn find_enclosing_function(functions: &[TsFunction], call: &TsCallSite) -> Option<String> {
    let call_line = call.location.range.start_line + 1;
    
    for func in functions {
        let func_start = func.location.range.start_line;
        let func_end = func.location.range.end_line;
        
        if call_line >= func_start && call_line <= func_end {
            return Some(func.name.clone());
        }
    }
    
    None
}

/// Extract the pattern and flags arguments from the call args
fn extract_regexp_args(args_repr: &str) -> (Option<String>, Option<String>) {
    let trimmed = args_repr.trim();
    if trimmed.is_empty() {
        return (None, None);
    }
    
    // Remove parentheses
    let inner = trimmed.trim_start_matches('(').trim_end_matches(')').trim();
    
    if inner.is_empty() {
        return (None, None);
    }
    
    // Split by comma (outside of quotes)
    let parts: Vec<&str> = split_args(inner);
    
    let pattern_arg = parts.first().map(|s| s.trim().to_string());
    let flags_arg = parts.get(1).map(|s| s.trim().to_string());
    
    (pattern_arg, flags_arg)
}

/// Split arguments by comma, respecting quotes
fn split_args(s: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut in_template = false;
    let mut prev_char = None;
    
    for (i, c) in s.char_indices() {
        match c {
            '\'' if !in_double_quote && !in_template && prev_char != Some('\\') => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote && !in_template && prev_char != Some('\\') => {
                in_double_quote = !in_double_quote;
            }
            '`' if !in_single_quote && !in_double_quote => {
                in_template = !in_template;
            }
            ',' if !in_single_quote && !in_double_quote && !in_template => {
                result.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        prev_char = Some(c);
    }
    
    if start < s.len() {
        result.push(&s[start..]);
    }
    
    result
}

/// Generate a suggested constant name from the function context
fn suggest_constant_name(regex_info: &RegexInFunction) -> String {
    // Try to extract a meaningful name from the pattern
    if let Some(ref pattern) = regex_info.pattern_arg {
        // Common pattern prefixes
        if pattern.contains("email") || pattern.contains("@") {
            return "EMAIL_PATTERN".to_string();
        }
        if pattern.contains("url") || pattern.contains("http") {
            return "URL_PATTERN".to_string();
        }
        if pattern.contains("phone") || pattern.contains("\\d{3}") {
            return "PHONE_PATTERN".to_string();
        }
    }
    
    // Default: derive from function name
    let base = regex_info.function_name
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect::<String>();
    
    format!("{}_PATTERN", to_screaming_snake_case(&base))
}

/// Convert a string to SCREAMING_SNAKE_CASE
fn to_screaming_snake_case(s: &str) -> String {
    let mut result = String::new();
    
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(c.to_ascii_uppercase());
    }
    
    result
}

/// Try to convert pattern string to regex literal if possible
fn pattern_to_literal(pattern: &Option<String>, flags: &Option<String>) -> Option<String> {
    if let Some(p) = pattern {
        // Check if pattern is a simple string literal
        let is_simple = p.starts_with('\'') || p.starts_with('"');
        
        if is_simple {
            // Remove quotes and create literal
            let inner = p.trim_matches(|c| c == '\'' || c == '"');
            
            // Check for special chars that would prevent literal conversion
            let has_forward_slash = inner.contains('/');
            
            if !has_forward_slash {
                let flags_str = flags.as_ref()
                    .map(|f| f.trim_matches(|c| c == '\'' || c == '"'))
                    .unwrap_or("");
                    
                return Some(format!("/{}/{}", inner, flags_str));
            }
        }
    }
    None
}

fn create_finding(
    rule_id: &str,
    regex_info: &RegexInFunction,
    file_id: FileId,
    file_path: &str,
) -> RuleFinding {
    let title = format!(
        "RegExp creation in function '{}' creates new object on every call",
        regex_info.function_name
    );

    let suggested_name = suggest_constant_name(regex_info);
    let literal_form = pattern_to_literal(&regex_info.pattern_arg, &regex_info.flags_arg);
    
    let suggestion = if let Some(ref lit) = literal_form {
        format!("Use regex literal: `const {} = {};`", suggested_name, lit)
    } else {
        format!("Move to module level: `const {} = new RegExp(...);`", suggested_name)
    };
    
    let description = format!(
        "The RegExp creation '{}' inside function '{}' will create a new RegExp object \
         on every function call. Move the RegExp to module level as a constant \
         like '{}' to create once when the module loads.\n\n\
         Benefits:\n\
         - Faster function execution (no object creation overhead)\n\
         - Clearer code structure (patterns visible at module level)\n\
         - Better memory usage (single instance, not one per call)\n\n\
         Suggestion: {}",
        regex_info.full_call,
        regex_info.function_name,
        suggested_name,
        suggestion,
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
            "typescript".into(),
            "regex".into(),
            "performance".into(),
            "compile-once".into(),
        ],
    }
}

fn generate_patch(regex_info: &RegexInFunction, file_id: FileId) -> (FilePatch, String) {
    let suggested_name = suggest_constant_name(regex_info);
    let literal_form = pattern_to_literal(&regex_info.pattern_arg, &regex_info.flags_arg);
    
    let pattern_repr = regex_info.pattern_arg.as_deref().unwrap_or("'pattern'");
    
    // For the fix preview, show the before/after transformation
    let fix_preview = if let Some(ref lit) = literal_form {
        format!(
            r#"// Before (creates new RegExp on every call):
function {}(...) {{
    const pattern = new RegExp({});
    ...
}}

// After (creates regex once at module load):
const {} = {};

function {}(...) {{
    // Use {} directly
    ...
}}"#,
            regex_info.function_name,
            pattern_repr,
            suggested_name,
            lit,
            regex_info.function_name,
            suggested_name,
        )
    } else {
        format!(
            r#"// Before (creates new RegExp on every call):
function {}(...) {{
    const pattern = new RegExp({});
    ...
}}

// After (creates regex once at module load):
const {} = new RegExp({});

function {}(...) {{
    // Use {} directly
    ...
}}"#,
            regex_info.function_name,
            pattern_repr,
            suggested_name,
            pattern_repr,
            regex_info.function_name,
            suggested_name,
        )
    };

    // The patch replaces the new RegExp call with the suggested constant name
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
    use crate::parse::typescript::parse_typescript_file;
    use crate::semantics::SourceSemantics;
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
        let sem = build_typescript_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Typescript(sem)))
    }

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = TypescriptRegexCompileRule::new();
        assert_eq!(rule.id(), "typescript.regex_compile");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = TypescriptRegexCompileRule::new();
        assert!(rule.name().contains("Regex") || rule.name().contains("regex"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = TypescriptRegexCompileRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("TypescriptRegexCompileRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = TypescriptRegexCompileRule::default();
        assert_eq!(rule.id(), "typescript.regex_compile");
    }

    // ==================== Detection Tests ====================

    #[tokio::test]
    async fn detects_new_regexp_in_function() {
        let rule = TypescriptRegexCompileRule::new();
        let src = r#"
function validateEmail(email: string): boolean {
    const pattern = new RegExp('^[\\w\\.-]+@[\\w\\.-]+\\.\\w+$');
    return pattern.test(email);
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1, "Should detect new RegExp in function");
        assert_eq!(findings[0].rule_id, "typescript.regex_compile");
        assert!(findings[0].description.as_ref().unwrap().contains("validateEmail"));
    }

    #[tokio::test]
    async fn no_finding_for_module_level_regexp() {
        let rule = TypescriptRegexCompileRule::new();
        let src = r#"
const EMAIL_PATTERN = new RegExp('^[\\w\\.-]+@[\\w\\.-]+\\.\\w+$');

function validateEmail(email: string): boolean {
    return EMAIL_PATTERN.test(email);
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert!(findings.is_empty(), "Should not flag module-level RegExp");
    }

    #[tokio::test]
    async fn no_finding_for_regex_literal() {
        let rule = TypescriptRegexCompileRule::new();
        let src = r#"
const EMAIL_PATTERN = /^[\w\.-]+@[\w\.-]+\.\w+$/;

function validateEmail(email: string): boolean {
    return EMAIL_PATTERN.test(email);
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert!(findings.is_empty(), "Should not flag regex literals");
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = TypescriptRegexCompileRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = TypescriptRegexCompileRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Finding Properties Tests ====================

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = TypescriptRegexCompileRule::new();
        let src = r#"
function validate(text: string): boolean {
    const pattern = new RegExp('\\d+');
    return pattern.test(text);
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        
        assert_eq!(finding.rule_id, "typescript.regex_compile");
        assert!(matches!(finding.kind, FindingKind::PerformanceSmell));
        assert_eq!(finding.dimension, Dimension::Performance);
        assert_eq!(finding.severity, Severity::Low);
        assert!(finding.confidence > 0.9);
        assert!(finding.patch.is_some());
        assert!(finding.fix_preview.is_some());
        assert!(finding.tags.contains(&"regex".to_string()));
        assert!(finding.tags.contains(&"compile-once".to_string()));
    }

    // ==================== Helper Function Tests ====================

    #[test]
    fn is_regexp_constructor_call_works() {
        assert!(is_regexp_constructor_call("RegExp"));
        assert!(is_regexp_constructor_call("new RegExp"));
        assert!(!is_regexp_constructor_call("test"));
        assert!(!is_regexp_constructor_call("Regexp"));
    }

    #[test]
    fn extract_regexp_args_handles_single_arg() {
        let (pattern, flags) = extract_regexp_args("('pattern')");
        assert_eq!(pattern, Some("'pattern'".to_string()));
        assert_eq!(flags, None);
    }

    #[test]
    fn extract_regexp_args_handles_two_args() {
        let (pattern, flags) = extract_regexp_args("('pattern', 'gi')");
        assert_eq!(pattern, Some("'pattern'".to_string()));
        assert_eq!(flags, Some("'gi'".to_string()));
    }

    #[test]
    fn extract_regexp_args_handles_empty() {
        let (pattern, flags) = extract_regexp_args("()");
        assert_eq!(pattern, None);
        assert_eq!(flags, None);
    }

    #[test]
    fn to_screaming_snake_case_works() {
        assert_eq!(to_screaming_snake_case("validateEmail"), "VALIDATE_EMAIL");
        assert_eq!(to_screaming_snake_case("test"), "TEST");
        assert_eq!(to_screaming_snake_case("myFunc"), "MY_FUNC");
    }

    #[test]
    fn pattern_to_literal_simple() {
        let pattern = Some("'hello'".to_string());
        let flags = None;
        let result = pattern_to_literal(&pattern, &flags);
        assert_eq!(result, Some("/hello/".to_string()));
    }

    #[test]
    fn pattern_to_literal_with_flags() {
        let pattern = Some("'hello'".to_string());
        let flags = Some("'gi'".to_string());
        let result = pattern_to_literal(&pattern, &flags);
        assert_eq!(result, Some("/hello/gi".to_string()));
    }

    #[test]
    fn pattern_to_literal_with_slash() {
        let pattern = Some("'hello/world'".to_string());
        let flags = None;
        let result = pattern_to_literal(&pattern, &flags);
        // Should return None because pattern contains forward slash
        assert_eq!(result, None);
    }

    #[test]
    fn suggest_constant_name_uses_function_name() {
        let info = RegexInFunction {
            callee: "new RegExp".to_string(),
            pattern_arg: Some("'\\d+'".to_string()),
            flags_arg: None,
            line: 5,
            column: 15,
            function_name: "validateInput".to_string(),
            start_byte: 100,
            end_byte: 150,
            full_call: "new RegExp('\\d+')".to_string(),
        };
        
        let name = suggest_constant_name(&info);
        assert_eq!(name, "VALIDATE_INPUT_PATTERN");
    }
}