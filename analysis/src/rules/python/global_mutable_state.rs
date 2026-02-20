//! Rule B2: Global mutable state
//!
//! Detects module-level mutable objects (lists, dicts, sets) that can cause
//! race conditions in concurrent environments like web servers.

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

/// Rule that detects module-level mutable objects in Python code.
///
/// Module-level mutable objects (lists, dicts, sets) are shared across all
/// requests in web servers and can cause race conditions when modified
/// concurrently.
#[derive(Debug)]
pub struct PythonGlobalMutableStateRule;

impl PythonGlobalMutableStateRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonGlobalMutableStateRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a global mutable assignment
#[derive(Debug, Clone)]
struct GlobalMutableAssignment {
    /// Variable name
    name: String,
    /// Type of mutable object (list, dict, set)
    mutable_type: MutableType,
    /// Line number (1-based)
    line: u32,
    /// Column number (1-based)
    column: u32,
    /// The original assignment text
    text: String,
    /// True if the variable name follows UPPERCASE convention (likely a constant)
    #[allow(dead_code)]
    is_likely_constant: bool,
    /// Type annotation if present, e.g. "dict[str, str]" for annotated assignments
    type_annotation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum MutableType {
    List,
    Dict,
    Set,
}

impl MutableType {
    fn as_str(&self) -> &'static str {
        match self {
            MutableType::List => "list",
            MutableType::Dict => "dict",
            MutableType::Set => "set",
        }
    }
}

#[async_trait]
impl Rule for PythonGlobalMutableStateRule {
    fn id(&self) -> &'static str {
        "python.global_mutable_state"
    }

    fn name(&self) -> &'static str {
        "Module-level mutable object"
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

            // Check module-level assignments for mutable objects
            for assignment in &py.assignments {
                // Skip if not at module level (we only care about module-level)
                if !assignment.is_module_level {
                    continue;
                }

                // Skip __all__ - it's a standard Python module-level variable used to define
                // the public API of a module. While technically mutable, it's not intended
                // to be mutated at runtime and is a well-established Python idiom.
                if assignment.target == "__all__" {
                    continue;
                }

                if let Some(mutable_type) = detect_mutable_type(&assignment.value_repr) {
                    // Check if the variable name is UPPERCASE (Python constant convention)
                    // Variables like LANGUAGE_MAP are typically read-only configuration
                    let is_likely_constant = is_uppercase_name(&assignment.target);

                    // Check if the type annotation contains ReadOnly (Python 3.13+ / PEP 705)
                    // If so, the developer has explicitly marked it as read-only
                    let has_readonly_annotation = assignment
                        .type_annotation
                        .as_ref()
                        .map(|ann| ann.contains("ReadOnly"))
                        .unwrap_or(false);

                    // Skip findings for variables explicitly annotated as ReadOnly
                    if has_readonly_annotation {
                        continue;
                    }

                    let global_mutable = GlobalMutableAssignment {
                        name: assignment.target.clone(),
                        mutable_type,
                        line: assignment.location.range.start_line + 1,
                        column: assignment.location.range.start_col + 1,
                        text: format!("{} = {}", assignment.target, assignment.value_repr),
                        is_likely_constant,
                        type_annotation: assignment.type_annotation.clone(),
                    };

                    let (title, description, severity, patch, fix_preview) = if is_likely_constant {
                        // UPPERCASE variables are conventionally constants in Python
                        // Lower severity and suggest ReadOnly annotation if not present
                        let title = format!(
                            "Module-level mutable {} `{}` (appears to be a constant)",
                            global_mutable.mutable_type.as_str(),
                            global_mutable.name
                        );

                        // Generate patch to add ReadOnly annotation (Python 3.13+ / PEP 705)
                        let (patch, fix_preview, extra_advice) = if global_mutable
                            .type_annotation
                            .is_some()
                        {
                            // Has annotation but no ReadOnly - suggest wrapping with ReadOnly
                            let (preview, generated_patch) =
                                generate_readonly_annotation_patch(&global_mutable, py, *file_id);
                            (
                                Some(generated_patch),
                                Some(preview),
                                "Consider adding `ReadOnly` annotation (Python 3.13+) for type safety.",
                            )
                        } else {
                            // No annotation - mention ReadOnly as an option
                            (
                                None,
                                None,
                                "Consider adding a type annotation with `ReadOnly` (Python 3.13+) for explicit immutability.",
                            )
                        };

                        let description = format!(
                            "The module-level variable `{}` is initialized as a mutable {} (`{}`). \
                             While this uses a mutable type, the UPPERCASE naming convention suggests \
                             it's intended as a constant (read-only). If this variable is never mutated, \
                             this is generally safe. {} However, if any code modifies it, consider using \
                             a tuple/frozenset for immutability, or thread-local storage for true isolation.",
                            global_mutable.name,
                            global_mutable.mutable_type.as_str(),
                            assignment.value_repr,
                            extra_advice
                        );
                        (title, description, Severity::Low, patch, fix_preview)
                    } else {
                        // lowercase/mixedCase variables are more likely to be mutated
                        let title = format!(
                            "Module-level mutable {} `{}`",
                            global_mutable.mutable_type.as_str(),
                            global_mutable.name
                        );
                        let description = format!(
                            "The module-level variable `{}` is initialized as a mutable {} (`{}`). \
                             In web servers and concurrent applications, this object is shared across \
                             all requests/threads. If modified concurrently, updates may be lost or \
                             state may become inconsistent. Consider using thread-local storage, \
                             request-scoped state, or immutable defaults.",
                            global_mutable.name,
                            global_mutable.mutable_type.as_str(),
                            assignment.value_repr
                        );

                        // Generate patch to wrap in a function or use thread-local
                        let (patched_text, generated_patch) =
                            generate_global_mutable_patch(&global_mutable, *file_id);
                        let preview = format!(
                            "# Before:\n#   {}\n# After:\n#   {}",
                            global_mutable.text.trim(),
                            patched_text.trim()
                        );
                        (
                            title,
                            description,
                            Severity::High,
                            Some(generated_patch),
                            Some(preview),
                        )
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::BehaviorThreat,
                        severity,
                        confidence: if is_likely_constant { 0.6 } else { 0.85 },
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(global_mutable.line),
                        column: Some(global_mutable.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch,
                        fix_preview,
                        tags: vec![
                            "python".into(),
                            "concurrency".into(),
                            "race-condition".into(),
                            "global-state".into(),
                        ],
                    });
                }
            }
        }

        findings
    }
}

/// Detect if a value represents a mutable type
fn detect_mutable_type(value_repr: &str) -> Option<MutableType> {
    let trimmed = value_repr.trim();

    // Empty list literal: []
    if trimmed == "[]" || trimmed.starts_with('[') && trimmed.ends_with(']') {
        // Check it's not a list comprehension
        if !is_comprehension(trimmed) {
            return Some(MutableType::List);
        }
    }

    // Empty dict literal: {} or dict()
    if trimmed == "{}" || trimmed == "dict()" {
        return Some(MutableType::Dict);
    }

    // Dict with content: {key: value, ...}
    if trimmed.starts_with('{') && trimmed.ends_with('}') && trimmed.contains(':') {
        // Check it's not a dict comprehension
        if !is_comprehension(trimmed) {
            return Some(MutableType::Dict);
        }
    }

    // list() constructor
    if trimmed == "list()" || trimmed.starts_with("list(") {
        return Some(MutableType::List);
    }

    // set() constructor or set literal {1, 2, 3}
    if trimmed == "set()" || trimmed.starts_with("set(") {
        return Some(MutableType::Set);
    }

    // Set literal (no colons, has commas)
    if trimmed.starts_with('{')
        && trimmed.ends_with('}')
        && !trimmed.contains(':')
        && trimmed.len() > 2
    {
        if !is_comprehension(trimmed) {
            return Some(MutableType::Set);
        }
    }

    None
}

/// Check if the expression looks like a comprehension.
///
/// Comprehensions follow the pattern: `... for <identifier> in ...`
/// This check ignores comments (text after #) to avoid false positives
/// when comments happen to contain " for ".
fn is_comprehension(expr: &str) -> bool {
    // Remove comments from the expression before checking
    // Comments can contain " for " (e.g., "# Use TypeScript profile for JS")
    // which would falsely trigger comprehension detection
    let expr_without_comments: String = expr
        .lines()
        .map(|line| {
            // Remove inline comments (everything after #)
            // But be careful not to remove `#` inside strings
            // For simplicity, we only strip comments that appear after non-string content
            if let Some(hash_pos) = find_comment_start(line) {
                &line[..hash_pos]
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    // Check for the comprehension pattern: `for ... in`
    // This looks for " for " followed by " in " (with content in between)
    // This is a simple heuristic that works for most comprehensions
    if let Some(for_pos) = expr_without_comments.find(" for ") {
        let after_for = &expr_without_comments[for_pos + 5..];
        // Check if there's an " in " after the " for "
        if after_for.contains(" in ") {
            return true;
        }
    }

    false
}

/// Find the start position of a comment in a line.
/// Returns None if there's no comment, or if the `#` is inside a string literal.
fn find_comment_start(line: &str) -> Option<usize> {
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut prev_char = '\0';

    for (i, c) in line.char_indices() {
        // Handle escape sequences
        if prev_char == '\\' {
            prev_char = c;
            continue;
        }

        match c {
            '\'' if !in_double_quote => in_single_quote = !in_single_quote,
            '"' if !in_single_quote => in_double_quote = !in_double_quote,
            '#' if !in_single_quote && !in_double_quote => return Some(i),
            _ => {}
        }

        prev_char = c;
    }

    None
}

/// Check if a variable name follows Python's UPPERCASE constant convention.
///
/// Names like `LANGUAGE_MAP`, `CONFIG_DEFAULTS` are typically intended to be
/// read-only constants, even though they use mutable types.
fn is_uppercase_name(name: &str) -> bool {
    // A name is considered UPPERCASE if:
    // 1. It has at least one uppercase letter
    // 2. All alphabetic characters are uppercase
    // 3. It may contain underscores and digits
    let has_letter = name.chars().any(|c| c.is_alphabetic());
    let all_upper = name.chars().all(|c| !c.is_alphabetic() || c.is_uppercase());
    has_letter && all_upper
}

/// Generate a patch to fix global mutable state
fn generate_global_mutable_patch(
    global_mutable: &GlobalMutableAssignment,
    file_id: FileId,
) -> (String, FilePatch) {
    // The fix is to use a function that returns a new instance each time
    // or to use threading.local() for thread-local storage
    let (patched, empty_value) = match global_mutable.mutable_type {
        MutableType::List => (
            format!(
                "def get_{}():\n    \"\"\"Get a fresh {} instance (thread-safe).\"\"\"\n    return []",
                global_mutable.name,
                global_mutable.mutable_type.as_str()
            ),
            "[]".to_string(),
        ),
        MutableType::Dict => (
            format!(
                "def get_{}():\n    \"\"\"Get a fresh {} instance (thread-safe).\"\"\"\n    return {{}}",
                global_mutable.name,
                global_mutable.mutable_type.as_str()
            ),
            "{}".to_string(),
        ),
        MutableType::Set => (
            format!(
                "def get_{}():\n    \"\"\"Get a fresh {} instance (thread-safe).\"\"\"\n    return set()",
                global_mutable.name,
                global_mutable.mutable_type.as_str()
            ),
            "set()".to_string(),
        ),
    };

    // Generate actual executable code: the getter function and thread-local alternative
    let getter_code = format!(
        "\n\ndef get_{name}():\n    \
         \"\"\"Get a fresh {type_name} instance (thread-safe).\n    \
         \n    \
         Use this instead of the global `{name}` to avoid race conditions.\n    \
         \"\"\"\n    \
         return {empty_value}\n\n\
         # Alternative: Use threading.local() for true thread-local storage\n\
         # import threading\n\
         # _local = threading.local()\n\
         # def get_{name}():\n\
         #     if not hasattr(_local, '{name}'):\n\
         #         _local.{name} = {empty_value}\n\
         #     return _local.{name}\n",
        name = global_mutable.name,
        type_name = global_mutable.mutable_type.as_str(),
        empty_value = empty_value,
    );

    let patch = FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertAfterLine {
                line: global_mutable.line,
            },
            replacement: getter_code,
        }],
    };

    (patched, patch)
}

/// Generate a patch to add ReadOnly annotation to an UPPERCASE constant with existing type annotation.
///
/// This suggests wrapping the existing type annotation with `ReadOnly[...]` (Python 3.13+, PEP 705).
fn generate_readonly_annotation_patch(
    global_mutable: &GlobalMutableAssignment,
    py: &crate::semantics::python::model::PyFileSemantics,
    file_id: FileId,
) -> (String, FilePatch) {
    let type_annotation = global_mutable.type_annotation.as_deref().unwrap_or("dict");

    // Generate the preview of what the fix looks like
    let preview = format!(
        "# Before:\n#   {name}: {ann} = ...\n# After:\n#   {name}: ReadOnly[{ann}] = ...\n#   (requires: from typing import ReadOnly  # Python 3.13+)",
        name = global_mutable.name,
        ann = type_annotation
    );

    // Check if ReadOnly is already imported
    let has_readonly_import = py
        .imports
        .iter()
        .any(|imp| imp.module == "typing" && imp.names.iter().any(|n| n == "ReadOnly"));

    let mut hunks = Vec::new();

    // Add import if not present
    if !has_readonly_import {
        let import_line = py.import_insertion_line();
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: import_line },
            replacement: "from typing import ReadOnly  # Python 3.13+, PEP 705\n".to_string(),
        });
    }

    // Note: We don't modify the actual type annotation in the code because:
    // 1. Reconstructing the full annotated assignment is complex
    // 2. The user may want to review before making type changes
    // Instead, we provide clear guidance in the description

    let patch = FilePatch { file_id, hunks };

    (preview, patch)
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

    // ==================== detect_mutable_type Tests ====================

    #[test]
    fn detects_empty_list() {
        assert_eq!(detect_mutable_type("[]"), Some(MutableType::List));
    }

    #[test]
    fn detects_list_with_elements() {
        assert_eq!(detect_mutable_type("[1, 2, 3]"), Some(MutableType::List));
    }

    #[test]
    fn detects_list_constructor() {
        assert_eq!(detect_mutable_type("list()"), Some(MutableType::List));
    }

    #[test]
    fn detects_empty_dict() {
        assert_eq!(detect_mutable_type("{}"), Some(MutableType::Dict));
    }

    #[test]
    fn detects_dict_constructor() {
        assert_eq!(detect_mutable_type("dict()"), Some(MutableType::Dict));
    }

    #[test]
    fn detects_dict_with_content() {
        assert_eq!(
            detect_mutable_type("{'key': 'value'}"),
            Some(MutableType::Dict)
        );
    }

    #[test]
    fn detects_set_constructor() {
        assert_eq!(detect_mutable_type("set()"), Some(MutableType::Set));
    }

    #[test]
    fn detects_set_literal() {
        assert_eq!(detect_mutable_type("{1, 2, 3}"), Some(MutableType::Set));
    }

    #[test]
    fn does_not_detect_string() {
        assert_eq!(detect_mutable_type("\"hello\""), None);
    }

    #[test]
    fn does_not_detect_number() {
        assert_eq!(detect_mutable_type("42"), None);
    }

    #[test]
    fn does_not_detect_tuple() {
        assert_eq!(detect_mutable_type("(1, 2, 3)"), None);
    }

    #[test]
    fn does_not_detect_function_call() {
        assert_eq!(detect_mutable_type("some_function()"), None);
    }

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonGlobalMutableStateRule::new();
        assert_eq!(rule.id(), "python.global_mutable_state");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonGlobalMutableStateRule::new();
        assert!(rule.name().contains("mutable"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonGlobalMutableStateRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonGlobalMutableStateRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonGlobalMutableStateRule::default();
        assert_eq!(rule.id(), "python.global_mutable_state");
    }

    // ==================== evaluate Tests - Detects Mutable State ====================

    #[tokio::test]
    async fn evaluate_detects_global_empty_list() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("cache = []");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("list"));
        assert!(findings[0].title.contains("cache"));
    }

    #[tokio::test]
    async fn evaluate_detects_global_empty_dict() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("registry = {}");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("dict"));
    }

    #[tokio::test]
    async fn evaluate_detects_global_set() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("seen = set()");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("set"));
    }

    #[tokio::test]
    async fn evaluate_detects_multiple_global_mutables() {
        let rule = PythonGlobalMutableStateRule::new();
        let src = r#"
cache = []
registry = {}
seen = set()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 3);
    }

    // ==================== evaluate Tests - No Findings ====================

    #[tokio::test]
    async fn evaluate_ignores_immutable_types() {
        let rule = PythonGlobalMutableStateRule::new();
        let src = r#"
NAME = "constant"
COUNT = 42
RATIO = 3.14
ENABLED = True
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_tuple() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("ITEMS = (1, 2, 3)");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_frozenset() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("ITEMS = frozenset([1, 2, 3])");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Finding Properties Tests ====================

    #[tokio::test]
    async fn evaluate_finding_has_correct_rule_id() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("cache = []");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings[0].rule_id, "python.global_mutable_state");
    }

    #[tokio::test]
    async fn evaluate_finding_has_high_severity() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("cache = []");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].severity, Severity::High));
    }

    #[tokio::test]
    async fn evaluate_finding_has_correctness_dimension() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("cache = []");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings[0].dimension, Dimension::Correctness);
    }

    #[tokio::test]
    async fn evaluate_finding_has_patch() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("cache = []");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].patch.is_some());
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("cache = []");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
        assert!(
            findings[0]
                .fix_preview
                .as_ref()
                .unwrap()
                .contains("def get_cache")
        );
    }

    #[tokio::test]
    async fn evaluate_finding_has_tags() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("cache = []");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].tags.contains(&"python".to_string()));
        assert!(findings[0].tags.contains(&"concurrency".to_string()));
        assert!(findings[0].tags.contains(&"race-condition".to_string()));
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn evaluate_handles_empty_semantics() {
        let rule = PythonGlobalMutableStateRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_handles_empty_file() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Multiline Dict Tests ====================

    #[tokio::test]
    async fn evaluate_detects_multiline_dict_without_comment() {
        let rule = PythonGlobalMutableStateRule::new();
        let src = r#"
LANGUAGE_MAP = {
    "python": "Python",
    "go": "Go",
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        assert_eq!(findings.len(), 1, "Should detect multiline dict");
        assert!(findings[0].title.contains("dict"));
    }

    #[tokio::test]
    async fn evaluate_detects_multiline_dict_with_comment() {
        let rule = PythonGlobalMutableStateRule::new();
        let src = r#"
LANGUAGE_TO_LSP_PROFILE = {
    "python": "python_lsp",
    "javascript": "typescript_lsp",  # Use TypeScript profile for JS
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        assert_eq!(
            findings.len(),
            1,
            "Should detect multiline dict with comment"
        );
        assert!(findings[0].title.contains("dict"));
    }

    #[tokio::test]
    async fn evaluate_detects_both_multiline_dicts_in_same_file() {
        let rule = PythonGlobalMutableStateRule::new();
        let src = r#"
LANGUAGE_TO_LSP_PROFILE = {
    "python": "python_lsp",
    "javascript": "typescript_lsp",  # Use TypeScript profile for JS
}

LANGUAGE_MAP = {
    "python": "Python",
    "go": "Go",
}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        assert_eq!(findings.len(), 2, "Should detect both multiline dicts");
    }

    // ==================== Comprehension Detection Tests ====================

    #[test]
    fn is_comprehension_detects_list_comprehension() {
        assert!(is_comprehension("[x for x in items]"));
        assert!(is_comprehension("[x * 2 for x in range(10)]"));
        assert!(is_comprehension("[x for x in items if x > 0]"));
    }

    #[test]
    fn is_comprehension_detects_dict_comprehension() {
        assert!(is_comprehension("{k: v for k, v in items}"));
        assert!(is_comprehension("{k: v for k, v in items.items()}"));
    }

    #[test]
    fn is_comprehension_detects_set_comprehension() {
        assert!(is_comprehension("{x for x in items}"));
        assert!(is_comprehension("{x * 2 for x in range(10)}"));
    }

    #[test]
    fn is_comprehension_ignores_regular_dict_with_for_in_comment() {
        // This is the key bug fix - comments containing " for " shouldn't trigger
        let dict_with_comment = r#"{
    "python": "python_lsp",
    "javascript": "typescript_lsp",  # Use TypeScript profile for JS
}"#;
        assert!(!is_comprehension(dict_with_comment));
    }

    #[test]
    fn is_comprehension_ignores_regular_list() {
        assert!(!is_comprehension("[1, 2, 3]"));
        assert!(!is_comprehension("['a', 'b', 'c']"));
    }

    #[test]
    fn is_comprehension_ignores_regular_dict() {
        assert!(!is_comprehension("{'key': 'value'}"));
        assert!(!is_comprehension("{}"));
    }

    #[test]
    fn is_comprehension_ignores_regular_set() {
        assert!(!is_comprehension("{1, 2, 3}"));
    }

    // ==================== __all__ Variable Tests ====================

    #[tokio::test]
    async fn evaluate_ignores_dunder_all_list() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("__all__ = ['func1', 'Class2']");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "__all__ should be ignored as it's a standard Python idiom"
        );
    }

    #[tokio::test]
    async fn evaluate_ignores_dunder_all_empty_list() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("__all__ = []");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "__all__ = [] should be ignored");
    }

    #[tokio::test]
    async fn evaluate_ignores_dunder_all_in_module_with_other_code() {
        let rule = PythonGlobalMutableStateRule::new();
        let src = r#"
__all__ = ['MyClass', 'my_function']

class MyClass:
    pass

def my_function():
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "__all__ should be ignored even with surrounding code"
        );
    }

    #[tokio::test]
    async fn evaluate_detects_other_mutable_while_ignoring_dunder_all() {
        let rule = PythonGlobalMutableStateRule::new();
        let src = r#"
__all__ = ['MyClass']
cache = []
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1, "Should detect 'cache' but not '__all__'");
        assert!(findings[0].title.contains("cache"));
    }

    // ==================== UPPERCASE Constant Convention Tests ====================

    #[test]
    fn is_uppercase_name_detects_uppercase() {
        assert!(is_uppercase_name("CONFIG"));
        assert!(is_uppercase_name("LANGUAGE_MAP"));
        assert!(is_uppercase_name("HTTP_TIMEOUT"));
        assert!(is_uppercase_name("API_V2_ENDPOINTS"));
    }

    #[test]
    fn is_uppercase_name_rejects_lowercase() {
        assert!(!is_uppercase_name("config"));
        assert!(!is_uppercase_name("language_map"));
        assert!(!is_uppercase_name("cache"));
    }

    #[test]
    fn is_uppercase_name_rejects_mixed_case() {
        assert!(!is_uppercase_name("Config"));
        assert!(!is_uppercase_name("languageMap"));
        assert!(!is_uppercase_name("Language_Map"));
    }

    #[tokio::test]
    async fn evaluate_lowercase_mutable_has_high_severity_and_patch() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("cache = []");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::High));
        assert!(
            findings[0].patch.is_some(),
            "lowercase mutable should have patch"
        );
        assert!(findings[0].fix_preview.is_some());
    }

    #[tokio::test]
    async fn evaluate_uppercase_mutable_has_low_severity_and_no_patch() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("CACHE = []");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Low));
        assert!(
            findings[0].patch.is_none(),
            "UPPERCASE mutable should not have patch"
        );
        assert!(findings[0].fix_preview.is_none());
        assert!(findings[0].title.contains("appears to be a constant"));
    }

    #[tokio::test]
    async fn evaluate_uppercase_dict_has_low_severity() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("CONFIG = {'key': 'value'}");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Low));
        assert!(findings[0].title.contains("appears to be a constant"));
    }

    // ==================== ReadOnly Annotation Tests ====================

    #[tokio::test]
    async fn evaluate_skips_readonly_annotated_variable() {
        let rule = PythonGlobalMutableStateRule::new();
        let src = r#"from typing import ReadOnly
CONFIG: ReadOnly[dict[str, str]] = {'key': 'value'}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "ReadOnly annotated variables should be skipped"
        );
    }

    #[tokio::test]
    async fn evaluate_uppercase_with_type_annotation_suggests_readonly() {
        let rule = PythonGlobalMutableStateRule::new();
        let src = r#"CONFIG: dict[str, str] = {'key': 'value'}
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Low));
        // Should have patch suggesting ReadOnly
        assert!(
            findings[0].patch.is_some(),
            "UPPERCASE with annotation should have ReadOnly patch"
        );
        assert!(
            findings[0]
                .fix_preview
                .as_ref()
                .unwrap()
                .contains("ReadOnly")
        );
    }

    #[tokio::test]
    async fn evaluate_uppercase_without_annotation_has_no_patch() {
        let rule = PythonGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics("CONFIG = {'key': 'value'}");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::Low));
        // No type annotation, so no ReadOnly patch
        assert!(
            findings[0].patch.is_none(),
            "UPPERCASE without annotation should not have patch"
        );
    }

    #[tokio::test]
    async fn evaluate_readonly_in_type_union_is_skipped() {
        let rule = PythonGlobalMutableStateRule::new();
        // ReadOnly can appear in various positions in type annotations
        let src = r#"from typing import ReadOnly
DATA: ReadOnly[list[int]] = [1, 2, 3]
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty(), "ReadOnly in type should be skipped");
    }
}
