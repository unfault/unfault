//! Rule: Static Regex Compilation
//!
//! Detects `Regex::new()` calls that could be compiled once and reused,
//! suggesting `OnceLock` or `lazy_static!` for better performance.
//!
//! # Problem
//!
//! Calling `Regex::new()` in struct constructors or functions means the regex
//! is recompiled every time, wasting CPU cycles and potentially causing
//! panics if the pattern is invalid.
//!
//! # Examples
//!
//! Bad:
//! ```ignore
//! impl MyValidator {
//!     pub fn new() -> Self {
//!         Self {
//!             pattern: Regex::new(r"\d+").unwrap(),
//!         }
//!     }
//! }
//! ```
//!
//! Good:
//! ```ignore
//! use std::sync::OnceLock;
//!
//! static PATTERN: OnceLock<Regex> = OnceLock::new();
//!
//! impl MyValidator {
//!     pub fn new() -> Self {
//!         Self {
//!             pattern: PATTERN.get_or_init(|| {
//!                 Regex::new(r"\d+").expect("pattern is valid regex")
//!             }).clone(),
//!         }
//!     }
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::rust::model::UnwrapPattern;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects regex compilation that should be static.
///
/// This rule looks for `Regex::new()` calls (with or without `.unwrap()`)
/// and suggests using `OnceLock` or `lazy_static!` for compile-once semantics.
#[derive(Debug)]
pub struct RustRegexCompileRule;

impl Default for RustRegexCompileRule {
    fn default() -> Self {
        Self::new()
    }
}

impl RustRegexCompileRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustRegexCompileRule {
    fn id(&self) -> &'static str {
        "rust.regex_compile"
    }

    fn name(&self) -> &'static str {
        "Regex compiled repeatedly - consider OnceLock"
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
            let rust = match sem.as_ref() {
                SourceSemantics::Rust(r) => r,
                _ => continue,
            };

            // Check unwrap calls for RegexNew pattern
            for unwrap in &rust.unwrap_calls {
                // Skip test code
                if unwrap.in_test {
                    continue;
                }

                // Skip main() - acceptable to compile regex at startup
                if unwrap.in_main {
                    continue;
                }

                // Skip static initializers - this is already the correct pattern!
                if unwrap.in_static_init {
                    continue;
                }

                // Only flag RegexNew pattern
                if !matches!(unwrap.pattern, UnwrapPattern::RegexNew) {
                    continue;
                }

                let line = unwrap.location.range.start_line + 1;
                let function_name = unwrap.function_name.as_deref().unwrap_or("<unknown>");

                // Determine if this is in a constructor (new, build, create, etc.)
                let is_constructor = is_constructor_name(function_name);

                let title = if is_constructor {
                    format!(
                        "Regex recompiled on every `{}()` call - use `OnceLock` for compile-once",
                        function_name
                    )
                } else {
                    "Regex compiled at runtime - consider static compilation with `OnceLock`"
                        .to_string()
                };

                let description = generate_description(function_name, line, is_constructor);
                let patch = generate_static_regex_patch(unwrap, *file_id, rust);
                let fix_preview = generate_fix_preview(&unwrap.expr_text, is_constructor);

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::PerformanceSmell,
                    severity: Severity::Medium,
                    confidence: 0.90,
                    dimension: Dimension::Performance,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: Some(unwrap.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "performance".into(),
                        "regex".into(),
                        "once-lock".into(),
                    ],
                });
            }

            // Also check for Regex::new() calls that might not be unwrapped
            for call in &rust.calls {
                // Skip if already caught by unwrap detection
                if !call.function_call.callee_expr.contains("Regex::new") {
                    continue;
                }

                // Skip if we already have a finding at this location
                if findings.iter().any(|f| {
                    f.file_id == *file_id && f.line == Some(call.function_call.location.line)
                }) {
                    continue;
                }

                // Skip static initializers - this is already the correct pattern!
                if call.in_static_init {
                    continue;
                }

                // Skip test code and main()
                let function_name = call.function_name.as_deref().unwrap_or("<unknown>");
                if function_name.starts_with("test_")
                    || function_name.contains("_test")
                    || function_name == "main"
                {
                    continue;
                }

                let line = call.function_call.location.line;
                let is_constructor = is_constructor_name(function_name);

                let title = if is_constructor {
                    format!(
                        "Regex recompiled on every `{}()` call - use `OnceLock` for compile-once",
                        function_name
                    )
                } else {
                    "Regex compiled at runtime - consider static compilation with `OnceLock`"
                        .to_string()
                };

                let description = generate_description(function_name, line, is_constructor);
                let fix_preview =
                    generate_fix_preview(&call.function_call.callee_expr, is_constructor);

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::PerformanceSmell,
                    severity: Severity::Low,
                    confidence: 0.75,
                    dimension: Dimension::Performance,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: None, // No patch for non-unwrap calls (need more context)
                    fix_preview: Some(fix_preview),
                    tags: vec!["rust".into(), "performance".into(), "regex".into()],
                });
            }
        }

        findings
    }
}

/// Check if function name suggests it's a constructor.
fn is_constructor_name(name: &str) -> bool {
    matches!(
        name,
        "new" | "default" | "build" | "create" | "init" | "setup" | "from" | "with_config"
    ) || name.starts_with("new_")
        || name.starts_with("from_")
        || name.starts_with("build_")
        || name.starts_with("create_")
}

/// Generate detailed description for the finding.
fn generate_description(function_name: &str, line: u32, is_constructor: bool) -> String {
    if is_constructor {
        format!(
            "At line {}, `Regex::new()` is called inside `{}()`, which means the regex pattern \
             is **recompiled every time** an instance is created.\n\n\
             **Why this matters:**\n\
             - Regex compilation is expensive (parsing, NFA construction, optimization)\n\
             - For constant patterns, this work is repeated unnecessarily\n\
             - Can significantly impact performance in hot paths\n\n\
             **Recommended fix: Use `OnceLock` for compile-once semantics:**\n\
             ```rust\n\
             use std::sync::OnceLock;\n\
             use regex::Regex;\n\n\
             static MY_PATTERN: OnceLock<Regex> = OnceLock::new();\n\n\
             impl MyStruct {{\n    \
                 pub fn {}() -> Self {{\n        \
                     let pattern = MY_PATTERN.get_or_init(|| {{\n            \
                         Regex::new(r\"...\").expect(\"pattern is valid regex\")\n        \
                     }});\n        \
                     // Use pattern.clone() if you need to store it\n    \
                 }}\n\
             }}\n\
             ```\n\n\
             **Benefits:**\n\
             - Pattern compiled exactly once at first use\n\
             - `.expect()` is acceptable since failure means a bug in the pattern\n\
             - Zero overhead after first compilation\n\
             - Thread-safe by default",
            line, function_name, function_name
        )
    } else {
        format!(
            "At line {}, `Regex::new()` is called inside function `{}`.\n\n\
             If this pattern is constant, consider using `OnceLock` for compile-once semantics:\n\
             ```rust\n\
             use std::sync::OnceLock;\n\
             static PATTERN: OnceLock<Regex> = OnceLock::new();\n\n\
             fn {}() {{\n    \
                 let re = PATTERN.get_or_init(|| {{\n        \
                     Regex::new(r\"...\").expect(\"pattern is valid\")\n    \
                 }});\n\
             }}\n\
             ```\n\n\
             If the pattern is dynamic (built from user input), this is fine, but consider:\n\
             - Caching compiled regex by pattern string\n\
             - Using `RegexSet` for multiple patterns\n\
             - Validating patterns at startup rather than per-request",
            line, function_name, function_name
        )
    }
}

use crate::semantics::rust::model::RustFileSemantics;
use crate::semantics::rust::model::UnwrapCall;

/// Generate a patch to convert Regex::new().unwrap() to LazyLock static.
///
/// This generates a multi-hunk patch that:
/// 1. Adds `use std::sync::LazyLock;` import if not present
/// 2. Adds a static LazyLock declaration before the function
/// 3. Replaces the Regex::new().unwrap() call with a reference to the static
fn generate_static_regex_patch(
    unwrap: &UnwrapCall,
    file_id: FileId,
    rust_sem: &RustFileSemantics,
) -> FilePatch {
    let mut hunks = Vec::new();

    // Extract the pattern from Regex::new(r"...").unwrap()
    let pattern = extract_regex_pattern(&unwrap.expr_text);
    let static_name = generate_static_name(&pattern);

    // Check if LazyLock import already exists
    let has_lazy_lock_import = rust_sem
        .uses
        .iter()
        .any(|u| u.path.contains("LazyLock") || u.path.contains("std::sync::LazyLock"));

    // Hunk 1: Add import if needed (at line 1 or after existing use statements)
    if !has_lazy_lock_import {
        let import_line = if rust_sem.uses.is_empty() {
            1
        } else {
            // Find the last use statement line and insert after it
            rust_sem
                .uses
                .iter()
                .map(|u| u.location.range.end_line + 1)
                .max()
                .unwrap_or(1)
                + 1
        };

        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: import_line },
            replacement: "use std::sync::LazyLock;\n".to_string(),
        });
    }

    // Hunk 2: Add static declaration before the function/impl
    // We'll insert it at the start of the line containing the function
    let static_decl_line = unwrap.location.range.start_line; // 0-based, we want before

    // Find a good insertion point - ideally before the containing impl or fn
    let insert_line = find_static_insertion_line(rust_sem, static_decl_line);

    let static_decl = format!(
        "static {}: LazyLock<Regex> = LazyLock::new(|| {{\n    \
         Regex::new({}).expect(\"static regex pattern\")\n\
         }});\n\n",
        static_name, pattern
    );

    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine {
            line: insert_line + 1,
        }, // +1 for 1-indexed
        replacement: static_decl,
    });

    // Hunk 3: Replace the Regex::new().unwrap() with reference to static
    hunks.push(PatchHunk {
        range: PatchRange::ReplaceBytes {
            start: unwrap.start_byte,
            end: unwrap.end_byte,
        },
        replacement: format!("(*{}).clone()", static_name),
    });

    FilePatch { file_id, hunks }
}

/// Extract the regex pattern string from the expression.
fn extract_regex_pattern(expr: &str) -> String {
    // Look for r"..." or r#"..."# or "..." patterns
    if let Some(start) = expr.find("r#\"") {
        if let Some(end) = expr[start + 3..].find("\"#") {
            return format!("r#\"{}\"#", &expr[start + 3..start + 3 + end]);
        }
    }
    if let Some(start) = expr.find("r\"") {
        if let Some(end) = expr[start + 2..].find('"') {
            return format!("r\"{}\"", &expr[start + 2..start + 2 + end]);
        }
    }
    if let Some(start) = expr.find('"') {
        if let Some(end) = expr[start + 1..].find('"') {
            return format!("\"{}\"", &expr[start + 1..start + 1 + end]);
        }
    }
    "r\"PATTERN\"".to_string()
}

/// Generate a reasonable static name from the pattern.
fn generate_static_name(pattern: &str) -> String {
    // Extract just the pattern content without quotes
    let content = pattern
        .trim_start_matches("r#\"")
        .trim_start_matches("r\"")
        .trim_start_matches('"')
        .trim_end_matches("\"#")
        .trim_end_matches('"');

    // Take first few alphanumeric chars and make a valid identifier
    let base: String = content
        .chars()
        .take(15)
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();

    if base.is_empty() {
        "REGEX_PATTERN".to_string()
    } else {
        format!("{}_REGEX", base.to_uppercase())
    }
}

/// Find the best line to insert a static declaration.
///
/// We want to insert before the containing impl block or function,
/// not inside it.
fn find_static_insertion_line(rust_sem: &RustFileSemantics, unwrap_line: u32) -> u32 {
    // Check if we're inside an impl block
    for impl_block in &rust_sem.impls {
        let impl_start = impl_block.location.range.start_line;
        let impl_end = impl_block.location.range.end_line;

        if unwrap_line >= impl_start && unwrap_line <= impl_end {
            // We're inside this impl, insert before it
            return impl_start;
        }
    }

    // Check if we're inside a function
    for func in &rust_sem.functions {
        let func_start = func.location.range.start_line;
        let func_end = func.location.range.end_line;

        if unwrap_line >= func_start && unwrap_line <= func_end {
            return func_start;
        }
    }

    // Default: insert at the unwrap line (not ideal but safe)
    unwrap_line
}

/// Generate fix preview showing before/after.
fn generate_fix_preview(expr_text: &str, is_constructor: bool) -> String {
    if is_constructor {
        format!(
            "// Before (regex recompiled on each call):\n\
             impl MyStruct {{\n    \
                 pub fn new() -> Self {{\n        \
                     Self {{ pattern: {} }}\n    \
                 }}\n\
             }}\n\n\
             // After (compile once with OnceLock):\n\
             use std::sync::OnceLock;\n\n\
             static PATTERN: OnceLock<Regex> = OnceLock::new();\n\n\
             impl MyStruct {{\n    \
                 pub fn new() -> Self {{\n        \
                     let pattern = PATTERN.get_or_init(|| {{\n            \
                         Regex::new(r\"...\").expect(\"pattern is valid\")\n        \
                     }});\n        \
                     Self {{ pattern: pattern.clone() }}\n    \
                 }}\n\
             }}",
            expr_text
        )
    } else {
        format!(
            "// Before:\n\
             {}\n\n\
             // After (with OnceLock):\n\
             static PATTERN: OnceLock<Regex> = OnceLock::new();\n\
             let re = PATTERN.get_or_init(|| {{\n    \
                 Regex::new(r\"...\").expect(\"pattern is valid\")\n\
             }});",
            expr_text
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::rust::parse_rust_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::rust::build_rust_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_rust_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Rust(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = RustRegexCompileRule::new();
        assert_eq!(rule.id(), "rust.regex_compile");
    }

    #[test]
    fn rule_name_mentions_regex() {
        let rule = RustRegexCompileRule::new();
        assert!(rule.name().to_lowercase().contains("regex"));
    }

    #[test]
    fn is_constructor_name_identifies_constructors() {
        assert!(is_constructor_name("new"));
        assert!(is_constructor_name("default"));
        assert!(is_constructor_name("build"));
        assert!(is_constructor_name("create"));
        assert!(is_constructor_name("new_with_config"));
        assert!(is_constructor_name("from_str"));

        assert!(!is_constructor_name("process"));
        assert!(!is_constructor_name("validate"));
        assert!(!is_constructor_name("run"));
    }

    #[tokio::test]
    async fn detects_regex_in_constructor() {
        let rule = RustRegexCompileRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use regex::Regex;

impl MyValidator {
    pub fn new() -> Self {
        Self {
            pattern: Regex::new(r"\d+").unwrap(),
        }
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let regex_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.regex_compile")
            .collect();
        assert!(
            !regex_findings.is_empty(),
            "Should detect Regex::new() in constructor"
        );
    }

    #[tokio::test]
    async fn skips_regex_in_test_function() {
        let rule = RustRegexCompileRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use regex::Regex;

#[test]
fn test_pattern() {
    let re = Regex::new(r"\d+").unwrap();
    assert!(re.is_match("123"));
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let regex_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.regex_compile")
            .collect();
        assert!(
            regex_findings.is_empty(),
            "Should skip Regex::new() in test"
        );
    }

    #[tokio::test]
    async fn skips_regex_in_main() {
        let rule = RustRegexCompileRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use regex::Regex;

fn main() {
    let re = Regex::new(r"\d+").unwrap();
    println!("{}", re.is_match("123"));
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let regex_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.regex_compile")
            .collect();
        assert!(
            regex_findings.is_empty(),
            "Should skip Regex::new() in main"
        );
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = RustRegexCompileRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use regex::Regex;

impl Parser {
    pub fn new() -> Self {
        Self {
            pattern: Regex::new(r"\w+").unwrap(),
        }
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        for finding in &findings {
            if finding.rule_id == "rust.regex_compile" {
                assert_eq!(finding.dimension, Dimension::Performance);
                assert!(finding.tags.contains(&"regex".to_string()));
                assert!(finding.tags.contains(&"performance".to_string()));
                assert!(finding.patch.is_some());
                assert!(finding.fix_preview.is_some());
            }
        }
    }

    #[tokio::test]
    async fn returns_empty_for_non_rust() {
        let rule = RustRegexCompileRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn skips_regex_in_lazy_lock_initializer() {
        let rule = RustRegexCompileRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::sync::LazyLock;
use regex::Regex;

static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\d+").expect("valid regex")
});

fn use_pattern() {
    let _ = PATTERN.is_match("123");
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should NOT flag the Regex::new inside LazyLock::new()
        let regex_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.regex_compile")
            .collect();
        assert!(
            regex_findings.is_empty(),
            "Should skip Regex::new() inside LazyLock initializer, found {} findings",
            regex_findings.len()
        );
    }

    #[tokio::test]
    async fn skips_regex_in_once_lock_get_or_init() {
        let rule = RustRegexCompileRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::sync::OnceLock;
use regex::Regex;

static PATTERN: OnceLock<Regex> = OnceLock::new();

fn get_pattern() -> &'static Regex {
    PATTERN.get_or_init(|| {
        Regex::new(r"\d+").expect("valid regex")
    })
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should NOT flag the Regex::new inside OnceLock.get_or_init()
        let regex_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.regex_compile")
            .collect();
        assert!(
            regex_findings.is_empty(),
            "Should skip Regex::new() inside OnceLock.get_or_init(), found {} findings",
            regex_findings.len()
        );
    }

    #[test]
    fn extract_regex_pattern_works() {
        assert_eq!(
            extract_regex_pattern(r#"Regex::new(r"\d+").unwrap()"#),
            r#"r"\d+""#
        );
        assert_eq!(
            extract_regex_pattern(r#"Regex::new("test").unwrap()"#),
            r#""test""#
        );
    }

    #[test]
    fn generate_static_name_works() {
        assert_eq!(generate_static_name(r#"r"\d+""#), "D_REGEX");
        assert_eq!(generate_static_name(r#"r"email""#), "EMAIL_REGEX");
        assert_eq!(generate_static_name(r#""""#), "REGEX_PATTERN");
    }
}
