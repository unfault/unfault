//! Rule: Global mutable state
//!
//! Detects module-level `let` or `var` declarations that represent
//! mutable global state, which can lead to race conditions and
//! unpredictable behavior in concurrent environments.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Suppression comment marker for this rule (used in generated patches).
const SUPPRESSION_MARKER: &str = "unfault-ignore: typescript.global_mutable_state";

/// Rule that detects global mutable state in TypeScript code.
///
/// Module-level `let` or `var` declarations create mutable global state
/// that can be modified from anywhere, leading to race conditions and
/// hard-to-debug issues.
///
/// Suppression is handled centrally in the session layer. Users can add:
/// `// unfault-ignore: typescript.global_mutable_state` or
/// `// unfault-ignore: global_mutable_state` (short form)
#[derive(Debug)]
pub struct TypescriptGlobalMutableStateRule;

impl TypescriptGlobalMutableStateRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptGlobalMutableStateRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptGlobalMutableStateRule {
    fn id(&self) -> &'static str {
        "typescript.global_mutable_state"
    }

    fn name(&self) -> &'static str {
        "Module-level mutable state"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::unbounded_resource())
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

            for global in &ts.global_mutable_state {
                let _line = global.location.range.start_line + 1;

                let kind_str = match global.kind {
                    crate::semantics::typescript::model::VariableKind::Let => "let",
                    crate::semantics::typescript::model::VariableKind::Var => "var",
                    crate::semantics::typescript::model::VariableKind::Const => continue, // Skip const
                };

                // Skip primitive literal initializers (boolean, number, string)
                // These are safer than mutable objects/arrays/Maps because:
                // 1. Primitives themselves are immutable - only the binding changes
                // 2. Simple flags like `let isConfigured = false` are common, safe patterns
                // 3. Race conditions are more concerning for complex mutable structures
                if is_primitive_literal(&global.value_repr) {
                    continue;
                }

                // Determine the best fix based on the variable's characteristics
                let (patch, fix_preview, description) = generate_smart_fix(
                    &global.variable_name,
                    kind_str,
                    &global.value_repr,
                    global.has_type_annotation,
                    *file_id,
                    global.keyword_start_byte,
                    global.keyword_end_byte,
                    global.location.range.start_line + 1,
                );

                let title = format!("Module-level mutable state `{}`", global.variable_name);

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.9,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(global.location.range.start_line + 1),
                    column: Some(global.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "typescript".into(),
                        "global-state".into(),
                        "stability".into(),
                        "concurrency".into(),
                    ],
                });
            }
        }

        findings
    }
}

/// Generate a smart fix based on the variable's characteristics.
///
/// Strategy:
/// - If no initializer: add suppression comment (cannot change to const without initializer)
/// - If initialized to `null`: add suppression comment (typically reassigned later)
/// - Otherwise: add suppression comment for review
fn generate_smart_fix(
    var_name: &str,
    kind_str: &str,
    value_repr: &str,
    _has_type_annotation: bool,
    file_id: FileId,
    _keyword_start: usize,
    _keyword_end: usize,
    line: u32,
) -> (FilePatch, String, String) {
    // Case 1: No initializer (e.g., `let diagnosticCollection: vscode.DiagnosticCollection;`)
    // This pattern means the variable is assigned later in code (e.g., in an activate function).
    // We cannot change to `const` because const declarations must be initialized in TypeScript.
    // Add a suppression comment instead.
    if value_repr.is_empty() {
        let patch = FilePatch {
            file_id,
            hunks: vec![PatchHunk {
                range: PatchRange::InsertBeforeLine { line },
                replacement: format!(
                    "// {} - assigned once during initialization\n",
                    SUPPRESSION_MARKER
                ),
            }],
        };
        let fix_preview = format!("Mark `{}` as assigned during initialization", var_name);
        let description = format!(
            "The module-level `{}` declaration `{}` has no initializer and is assigned later. \
             This pattern is common for deferred initialization (e.g., in activate() functions). \
             Since `const` declarations must be initialized, consider if this truly needs to be mutable. \
             If the variable is only assigned once, apply the fix to suppress this warning.",
            kind_str, var_name
        );
        return (patch, fix_preview, description);
    }

    // Case 2: Initialized to `null` (e.g., `let client: Client | null = null;`)
    // This pattern typically means the variable will be reassigned later
    // Adding a suppression comment that marks this as intentional
    if value_repr == "null" {
        let patch = FilePatch {
            file_id,
            hunks: vec![PatchHunk {
                range: PatchRange::InsertBeforeLine { line },
                replacement: format!(
                    "// {} - intentionally reassignable (initialized to null)\n",
                    SUPPRESSION_MARKER
                ),
            }],
        };
        let fix_preview = format!("Mark `{}` as intentionally reassignable", var_name);
        let description = format!(
            "The module-level `{}` declaration `{}` is initialized to `null` and likely reassigned later. \
             In concurrent environments (e.g., serverless functions, worker threads), \
             concurrent access may produce inconsistent results. If this is intentional, \
             apply the fix to suppress this warning.",
            kind_str, var_name
        );
        return (patch, fix_preview, description);
    }

    // Case 3: Has an initializer that isn't null
    // For primitives like `false`, `0`, `""`, we assume they might be reassigned
    // For objects/arrays, they might be mutated even if not reassigned
    let patch = FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement: format!("// {} - reviewed and accepted\n", SUPPRESSION_MARKER),
        }],
    };
    let fix_preview = format!("Mark `{}` as reviewed", var_name);
    let description = format!(
        "The module-level `{}` declaration `{}` creates mutable global state. \
         If the variable is never reassigned, consider changing to `const`. \
         If it is reassigned intentionally, apply the fix to suppress this warning.",
        kind_str, var_name
    );
    (patch, fix_preview, description)
}

/// Check if a value representation is a primitive literal.
///
/// Primitive literals are safer for module-level state because:
/// - They are immutable values (only the binding can be reassigned)
/// - Simple flags like `let isConfigured = false` are common patterns
/// - Race condition risks are lower compared to mutable objects/arrays
///
/// Returns true for:
/// - Boolean literals: `true`, `false`
/// - Numeric literals: `0`, `42`, `-1`, `3.14`, `0xff`, `1e10`
/// - String literals: `"hello"`, `'world'`, `` `template` ``
/// - Null/undefined literals: `null`, `undefined`
fn is_primitive_literal(value: &str) -> bool {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return false;
    }

    // Boolean literals
    if trimmed == "true" || trimmed == "false" {
        return true;
    }

    // Null/undefined literals
    if trimmed == "null" || trimmed == "undefined" {
        return false; // null is handled specially by the rule, undefined could be intentional
    }

    // String literals (single, double quotes, or template literals)
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
        || (trimmed.starts_with('`') && trimmed.ends_with('`'))
    {
        return true;
    }

    // Numeric literals (including negative, hex, binary, octal, scientific notation)
    // Try to parse as a number - handle various formats
    if is_numeric_literal(trimmed) {
        return true;
    }

    false
}

/// Check if a string represents a numeric literal in JavaScript/TypeScript.
fn is_numeric_literal(s: &str) -> bool {
    let s = s.trim();

    if s.is_empty() {
        return false;
    }

    // Handle negative/positive sign prefix
    let s = if let Some(rest) = s.strip_prefix('-') {
        rest
    } else if let Some(rest) = s.strip_prefix('+') {
        rest
    } else {
        s
    };

    if s.is_empty() {
        return false;
    }

    // Hex: 0x or 0X
    if s.starts_with("0x") || s.starts_with("0X") {
        return s[2..].chars().all(|c| c.is_ascii_hexdigit());
    }

    // Binary: 0b or 0B
    if s.starts_with("0b") || s.starts_with("0B") {
        return s[2..].chars().all(|c| c == '0' || c == '1');
    }

    // Octal: 0o or 0O
    if s.starts_with("0o") || s.starts_with("0O") {
        return s[2..].chars().all(|c| c >= '0' && c <= '7');
    }

    // BigInt literals
    let s = s.strip_suffix('n').unwrap_or(s);

    // Regular decimal, possibly with scientific notation
    // Allow: digits, one decimal point, one 'e' or 'E' followed by optional sign and digits
    let mut has_dot = false;
    let mut has_exp = false;
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '0'..='9' | '_' => continue, // digits and numeric separators
            '.' if !has_dot && !has_exp => has_dot = true,
            'e' | 'E' if !has_exp => {
                has_exp = true;
                // Optional sign after exponent
                if chars.peek() == Some(&'+') || chars.peek() == Some(&'-') {
                    chars.next();
                }
            }
            _ => return false,
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::typescript::parse_typescript_file;
    use crate::semantics::typescript::model::TsFileSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.ts".to_string(),
            language: Language::Typescript,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_typescript_file(file_id, &sf).expect("parsing should succeed");
        let sem = TsFileSemantics::from_parsed(&parsed);
        (file_id, Arc::new(SourceSemantics::Typescript(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = TypescriptGlobalMutableStateRule::new();
        assert_eq!(rule.id(), "typescript.global_mutable_state");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = TypescriptGlobalMutableStateRule::new();
        assert!(rule.name().contains("mutable"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_typescript() {
        let rule = TypescriptGlobalMutableStateRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_let_global_object() {
        let rule = TypescriptGlobalMutableStateRule::new();
        // Note: numeric primitives like 0 are now allowed, so we test with an object
        let (file_id, sem) = parse_and_build_semantics("let globalState = { count: 0 };");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("globalState"));
    }

    #[tokio::test]
    async fn evaluate_detects_var_global() {
        let rule = TypescriptGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("var globalState = {};");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_ignores_const() {
        let rule = TypescriptGlobalMutableStateRule::new();
        let (file_id, sem) =
            parse_and_build_semantics("const CONFIG = { apiUrl: 'http://example.com' };");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_local_let() {
        let rule = TypescriptGlobalMutableStateRule::new();
        let src = r#"
function increment() {
    let counter = 0;
    return ++counter;
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_boolean_literal() {
        let rule = TypescriptGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("let isConfigured = false;");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "boolean literals should not trigger the rule"
        );
    }

    #[tokio::test]
    async fn evaluate_ignores_true_literal() {
        let rule = TypescriptGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("let enabled = true;");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "true literal should not trigger the rule"
        );
    }

    #[tokio::test]
    async fn evaluate_ignores_number_literal() {
        let rule = TypescriptGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("let counter = 0;");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "number literals should not trigger the rule"
        );
    }

    #[tokio::test]
    async fn evaluate_ignores_string_literal() {
        let rule = TypescriptGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics(r#"let name = "default";"#);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "string literals should not trigger the rule"
        );
    }

    #[tokio::test]
    async fn evaluate_detects_object_literal() {
        let rule = TypescriptGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("let cache = {};");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1, "object literals should trigger the rule");
    }

    #[tokio::test]
    async fn evaluate_detects_array_literal() {
        let rule = TypescriptGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("let items = [];");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1, "array literals should trigger the rule");
    }

    #[tokio::test]
    async fn evaluate_detects_new_map() {
        let rule = TypescriptGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("let cache = new Map();");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1, "new Map() should trigger the rule");
    }

    #[test]
    fn is_primitive_literal_booleans() {
        assert!(is_primitive_literal("true"));
        assert!(is_primitive_literal("false"));
        assert!(is_primitive_literal(" true "));
        assert!(is_primitive_literal(" false "));
    }

    #[test]
    fn is_primitive_literal_numbers() {
        assert!(is_primitive_literal("0"));
        assert!(is_primitive_literal("42"));
        assert!(is_primitive_literal("-1"));
        assert!(is_primitive_literal("3.14"));
        assert!(is_primitive_literal("-3.14"));
        assert!(is_primitive_literal("1e10"));
        assert!(is_primitive_literal("1.5e-3"));
        assert!(is_primitive_literal("0xff"));
        assert!(is_primitive_literal("0xFF"));
        assert!(is_primitive_literal("0b1010"));
        assert!(is_primitive_literal("0o755"));
        assert!(is_primitive_literal("1_000_000"));
    }

    #[test]
    fn is_primitive_literal_strings() {
        assert!(is_primitive_literal(r#""hello""#));
        assert!(is_primitive_literal("'world'"));
        assert!(is_primitive_literal("`template`"));
    }

    #[test]
    fn is_primitive_literal_not_objects() {
        assert!(!is_primitive_literal("{}"));
        assert!(!is_primitive_literal("[]"));
        assert!(!is_primitive_literal("new Map()"));
        assert!(!is_primitive_literal("new Set()"));
        assert!(!is_primitive_literal("someFunction()"));
        assert!(!is_primitive_literal(""));
    }
}
