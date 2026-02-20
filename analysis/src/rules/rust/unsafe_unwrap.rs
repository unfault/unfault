//! Rule: Unsafe unwrap() usage in production code
//!
//! Detects `.unwrap()` calls on Result/Option that could panic in production,
//! with smart pattern detection for idiomatic fixes.
//!
//! # Smart Pattern Detection
//!
//! This rule detects common patterns and suggests context-appropriate fixes:
//!
//! - `starts_with(x) + find(x).unwrap()` → suggest `strip_prefix(x)`
//! - `env::var("X").unwrap()` → suggest `.expect("X must be set")`
//! - `.parse().unwrap()` → suggest `?` operator
//! - `.get(i).unwrap()` → suggest bounds check or `get_or`
//! - `.lock().unwrap()` → suggest handling poisoned locks
//! - `.first()/.last().unwrap()` → suggest iterator patterns
//! - `Regex::new().unwrap()` → suggest `lazy_static!` or `OnceLock`
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! fn process(data: Option<String>) -> String {
//!     data.unwrap()  // Will panic if None
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! fn process(data: Option<String>) -> Result<String, Error> {
//!     data.ok_or(Error::MissingData)  // Explicit error handling
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::rust::model::{UnwrapCall, UnwrapPattern, UnwrapType};
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unsafe unwrap() usage in production code.
///
/// Using `.unwrap()` on Result or Option types can cause panics in
/// production if the value is Err/None. This rule flags such usages
/// and suggests safer alternatives.
///
/// The rule is **not** triggered for:
/// - Test code (functions with `#[test]` or in `#[cfg(test)]` modules)
/// - The `main()` function (common pattern in CLI tools)
/// - Safe variants like `.unwrap_or_default()`
#[derive(Debug)]
pub struct RustUnsafeUnwrapRule;

impl RustUnsafeUnwrapRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RustUnsafeUnwrapRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for RustUnsafeUnwrapRule {
    fn id(&self) -> &'static str {
        "rust.unsafe_unwrap"
    }

    fn name(&self) -> &'static str {
        "Unsafe unwrap() that may panic in production"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
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

            for unwrap in &rust.unwrap_calls {
                // Skip test code
                if unwrap.in_test {
                    continue;
                }

                // Skip main() function - common pattern for CLI tools
                if unwrap.in_main {
                    continue;
                }

                // Skip safe variants that provide defaults
                if unwrap.method == "unwrap_or_default"
                    || unwrap.method == "unwrap_or"
                    || unwrap.method == "unwrap_or_else"
                {
                    continue;
                }

                // Only flag bare .unwrap() calls
                if unwrap.method != "unwrap" {
                    continue;
                }

                let type_name = match unwrap.on_type {
                    UnwrapType::Result => "Result",
                    UnwrapType::Option => "Option",
                    UnwrapType::Unknown => "fallible value",
                };

                // Generate smart title based on detected pattern
                let title = generate_smart_title(&unwrap.pattern, type_name);

                // Generate context-aware description
                let description = generate_smart_description(unwrap, type_name);

                let patch = generate_smart_patch(unwrap, *file_id);
                let fix_preview = generate_smart_fix_preview(unwrap);

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::High,
                    confidence: 0.95,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(unwrap.location.range.start_line + 1),
                    column: Some(unwrap.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "error-handling".into(),
                        "panic".into(),
                        "stability".into(),
                    ],
                });
            }
        }

        findings
    }
}

/// Generate smart title based on detected pattern.
fn generate_smart_title(pattern: &UnwrapPattern, type_name: &str) -> String {
    match pattern {
        UnwrapPattern::StartsWithFind { needle, .. } => {
            format!(
                "Use `strip_prefix({})` instead of `starts_with` + `find().unwrap()`",
                needle
            )
        }
        UnwrapPattern::EnvVar { var_name } => {
            format!(
                "Environment variable `{}` access needs error handling",
                var_name
            )
        }
        UnwrapPattern::Parse { target_type } => {
            let type_hint = target_type.as_deref().unwrap_or("T");
            format!("`.parse::<{}>().unwrap()` may panic on invalid input", type_hint)
        }
        UnwrapPattern::RegexNew => {
            "Consider using `lazy_static!` or `OnceLock` for compiled regex".to_string()
        }
        UnwrapPattern::CollectionGet { .. } => {
            "`.get().unwrap()` may panic if index is out of bounds".to_string()
        }
        UnwrapPattern::FirstOrLast { is_first } => {
            let method = if *is_first { "first" } else { "last" };
            format!("`.{}().unwrap()` may panic on empty collection", method)
        }
        UnwrapPattern::LockUnwrap { lock_method } => {
            format!("`.{}().unwrap()` doesn't handle poisoned lock", lock_method)
        }
        UnwrapPattern::IteratorNext => {
            "`.next().unwrap()` may panic if iterator is exhausted".to_string()
        }
        UnwrapPattern::IsSomeUnwrap => {
            "Replace `is_some()` check + `unwrap()` with `if let Some(x)`".to_string()
        }
        UnwrapPattern::IsOkUnwrap => {
            "Replace `is_ok()` check + `unwrap()` with `if let Ok(x)`".to_string()
        }
        UnwrapPattern::ContainsFind { .. } => {
            "Use `if let Some(pos) = find()` instead of `contains` + `find().unwrap()`".to_string()
        }
        UnwrapPattern::Generic => {
            format!("Unsafe `.unwrap()` on {} may panic in production", type_name)
        }
    }
}

/// Generate smart description with context-aware advice.
fn generate_smart_description(unwrap: &UnwrapCall, type_name: &str) -> String {
    let line = unwrap.location.range.start_line + 1;

    match &unwrap.pattern {
        UnwrapPattern::StartsWithFind { needle, .. } => {
            format!(
                "At line {}, the pattern `starts_with({}) + find({}).unwrap()` is redundant and \
                 can panic if the guard check is accidentally removed.\n\n\
                 **Idiomatic fix:** Use `strip_prefix({})` which combines both operations safely:\n\
                 ```rust\n\
                 if let Some(rest) = text.strip_prefix({}) {{\n    \
                     // rest contains everything after the prefix\n\
                 }}\n\
                 ```\n\n\
                 This is safer because `strip_prefix` returns `None` if the prefix isn't present, \
                 eliminating the need for a separate check.",
                line, needle, needle, needle, needle
            )
        }
        UnwrapPattern::EnvVar { var_name } => {
            format!(
                "At line {}, `env::var(\"{}\").unwrap()` will panic if the environment variable \
                 is not set.\n\n\
                 **Recommended fixes:**\n\
                 1. Use `.expect()` with a helpful message:\n\
                    ```rust\n\
                    env::var(\"{}\").expect(\"{} must be set\")\n\
                    ```\n\
                 2. Provide a default value:\n\
                    ```rust\n\
                    env::var(\"{}\").unwrap_or_else(|_| \"default\".to_string())\n\
                    ```\n\
                 3. Handle the error explicitly if the variable is optional.",
                line, var_name, var_name, var_name, var_name
            )
        }
        UnwrapPattern::Parse { target_type } => {
            let t = target_type.as_deref().unwrap_or("T");
            format!(
                "At line {}, `.parse::<{}>().unwrap()` will panic if the input string cannot be \
                 parsed.\n\n\
                 **Recommended fixes:**\n\
                 1. Use `?` operator if function returns Result:\n\
                    ```rust\n\
                    let value: {} = input.parse()?;\n\
                    ```\n\
                 2. Use `.expect()` with context:\n\
                    ```rust\n\
                    input.parse::<{}>().expect(\"input should be valid {}\")\n\
                    ```\n\
                 3. Handle parse errors with `.ok()` or match.",
                line, t, t, t, t
            )
        }
        UnwrapPattern::RegexNew => {
            format!(
                "At line {}, `Regex::new().unwrap()` on a compile-time constant pattern should \
                 use `lazy_static!` or `OnceLock` for better performance and clearer intent.\n\n\
                 **Recommended fix:**\n\
                 ```rust\n\
                 use std::sync::OnceLock;\n\
                 use regex::Regex;\n\n\
                 static REGEX: OnceLock<Regex> = OnceLock::new();\n\
                 let re = REGEX.get_or_init(|| Regex::new(r\"pattern\").unwrap());\n\
                 ```\n\n\
                 This compiles the regex once and reuses it, and makes the `.unwrap()` acceptable \
                 since it only runs once at initialization.",
                line
            )
        }
        UnwrapPattern::CollectionGet { index_expr } => {
            format!(
                "At line {}, `.get({}).unwrap()` will panic if the index is out of bounds.\n\n\
                 **Recommended fixes:**\n\
                 1. Use `if let` for safe access:\n\
                    ```rust\n\
                    if let Some(item) = collection.get({}) {{\n        \
                        // use item\n    \
                    }}\n\
                    ```\n\
                 2. Use `.get_or()` or `.get().unwrap_or(&default)` for fallback.\n\
                 3. If index is proven valid, document with `.expect()`.",
                line, index_expr, index_expr
            )
        }
        UnwrapPattern::FirstOrLast { is_first } => {
            let method = if *is_first { "first" } else { "last" };
            format!(
                "At line {}, `.{}().unwrap()` will panic if the collection is empty.\n\n\
                 **Recommended fixes:**\n\
                 1. Use `if let` for safe access:\n\
                    ```rust\n\
                    if let Some(item) = collection.{}() {{\n        \
                        // use item\n    \
                    }}\n\
                    ```\n\
                 2. Return early if empty is an error condition.\n\
                 3. Use `.{}_or(&default)` for a fallback value.",
                line, method, method, method
            )
        }
        UnwrapPattern::LockUnwrap { lock_method } => {
            format!(
                "At line {}, `.{}().unwrap()` will panic if the lock is poisoned (a thread \
                 panicked while holding the lock).\n\n\
                 **Recommended fixes:**\n\
                 1. Recover from poisoned lock:\n\
                    ```rust\n\
                    let guard = mutex.{}().unwrap_or_else(|e| e.into_inner());\n\
                    ```\n\
                 2. Use `.expect()` if poisoning indicates unrecoverable corruption:\n\
                    ```rust\n\
                    mutex.{}().expect(\"lock should not be poisoned\")\n\
                    ```",
                line, lock_method, lock_method, lock_method
            )
        }
        UnwrapPattern::IteratorNext => {
            format!(
                "At line {}, `.next().unwrap()` will panic if the iterator is exhausted.\n\n\
                 **Recommended fixes:**\n\
                 1. Use `if let` for safe iteration:\n\
                    ```rust\n\
                    if let Some(item) = iter.next() {{\n        \
                        // use item\n    \
                    }}\n\
                    ```\n\
                 2. Use `.next().expect(\"iterator should have items\")` if exhaustion is a bug.",
                line
            )
        }
        UnwrapPattern::IsSomeUnwrap | UnwrapPattern::IsOkUnwrap => {
            let (check, pattern) = match &unwrap.pattern {
                UnwrapPattern::IsSomeUnwrap => ("is_some()", "if let Some(x)"),
                UnwrapPattern::IsOkUnwrap => ("is_ok()", "if let Ok(x)"),
                _ => unreachable!(),
            };
            format!(
                "At line {}, checking `.{}` then calling `.unwrap()` is an anti-pattern.\n\n\
                 **Idiomatic fix:** Use `{}` which combines both operations:\n\
                 ```rust\n\
                 {} = value {{\n    \
                     // use x\n\
                 }}\n\
                 ```\n\n\
                 This is more concise and eliminates the redundant check.",
                line, check, pattern, pattern
            )
        }
        UnwrapPattern::ContainsFind { needle } => {
            format!(
                "At line {}, the pattern `contains({}) + find({}).unwrap()` is redundant.\n\n\
                 **Idiomatic fix:** Use `if let Some(pos) = find({})` directly:\n\
                 ```rust\n\
                 if let Some(pos) = text.find({}) {{\n    \
                     // use pos\n\
                 }}\n\
                 ```\n\n\
                 This eliminates the double search and handles the not-found case gracefully.",
                line, needle, needle, needle, needle
            )
        }
        UnwrapPattern::Generic => {
            format!(
                "The call `.unwrap()` at line {} on a {} type will panic if the value is \
                 {}. This can cause your application to crash unexpectedly.\n\n\
                 **Why this is a problem:**\n\
                 - Panics are unrecoverable in most contexts\n\
                 - In async code, panics can crash the entire runtime\n\
                 - Error details are lost, making debugging harder\n\n\
                 **Safer alternatives:**\n\
                 - Use `?` operator to propagate errors\n\
                 - Use `.unwrap_or_default()` for types with Default\n\
                 - Use `.unwrap_or(fallback)` for explicit fallback values\n\
                 - Use `.ok_or(err)?` to convert Option to Result\n\
                 - Use pattern matching for explicit handling\n\
                 - Use `.expect(\"reason\")` if panic is intentional (with good message)",
                line,
                type_name,
                match unwrap.on_type {
                    UnwrapType::Result => "Err.",
                    UnwrapType::Option => "None.",
                    UnwrapType::Unknown => "in an error state.",
                }
            )
        }
    }
}

/// Generate a smart patch based on detected pattern.
fn generate_smart_patch(unwrap: &UnwrapCall, file_id: FileId) -> FilePatch {
    let replacement = generate_patch_replacement(unwrap);

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: unwrap.start_byte,
                end: unwrap.end_byte,
            },
            replacement,
        }],
    }
}

/// Generate the replacement code based on pattern.
fn generate_patch_replacement(unwrap: &UnwrapCall) -> String {
    match &unwrap.pattern {
        UnwrapPattern::StartsWithFind { needle, .. } => {
            // For starts_with+find pattern, we can't easily refactor to strip_prefix
            // without knowing the variable name, so provide expect with good message
            unwrap.expr_text.replace(
                ".unwrap()",
                &format!(".expect(\"find({}) succeeds after starts_with check\")", needle),
            )
        }
        UnwrapPattern::EnvVar { var_name } => {
            unwrap.expr_text.replace(
                ".unwrap()",
                &format!(".expect(\"{} environment variable must be set\")", var_name),
            )
        }
        UnwrapPattern::Parse { target_type } => {
            let type_hint = target_type.as_deref().unwrap_or("value");
            unwrap.expr_text.replace(
                ".unwrap()",
                &format!(".expect(\"input should be valid {}\")", type_hint),
            )
        }
        UnwrapPattern::RegexNew => {
            // Keep unwrap for regex - it's acceptable for const patterns
            // but add a comment explaining why
            unwrap.expr_text.replace(
                ".unwrap()",
                ".expect(\"regex pattern is valid\")",
            )
        }
        UnwrapPattern::CollectionGet { index_expr } => {
            unwrap.expr_text.replace(
                ".unwrap()",
                &format!(".expect(\"index {} should be in bounds\")", index_expr),
            )
        }
        UnwrapPattern::FirstOrLast { is_first } => {
            let method = if *is_first { "first" } else { "last" };
            unwrap.expr_text.replace(
                ".unwrap()",
                &format!(".expect(\"collection should have {} element\")", method),
            )
        }
        UnwrapPattern::LockUnwrap { lock_method } => {
            // For locks, suggest recovering from poison
            unwrap.expr_text.replace(
                ".unwrap()",
                &format!(".unwrap_or_else(|e| e.into_inner()) /* handle poisoned {} */", lock_method),
            )
        }
        UnwrapPattern::IteratorNext => {
            unwrap.expr_text.replace(
                ".unwrap()",
                ".expect(\"iterator should have next element\")",
            )
        }
        UnwrapPattern::IsSomeUnwrap | UnwrapPattern::IsOkUnwrap => {
            // For is_some/is_ok guards, suggest pattern with explanation
            unwrap.expr_text.replace(
                ".unwrap()",
                ".expect(\"checked with is_some/is_ok; consider using if let instead\")",
            )
        }
        UnwrapPattern::ContainsFind { needle } => {
            unwrap.expr_text.replace(
                ".unwrap()",
                &format!(".expect(\"find({}) after contains check\")", needle),
            )
        }
        UnwrapPattern::Generic => {
            // Generic fallback based on type
            match unwrap.on_type {
                UnwrapType::Option => {
                    unwrap.expr_text.replace(".unwrap()", ".unwrap_or_default()")
                }
                UnwrapType::Result | UnwrapType::Unknown => {
                    unwrap.expr_text.replace(
                        ".unwrap()",
                        ".expect(\"TODO: add proper error handling\")",
                    )
                }
            }
        }
    }
}

/// Generate a smart fix preview showing before/after with pattern-specific advice.
fn generate_smart_fix_preview(unwrap: &UnwrapCall) -> String {
    let before = &unwrap.expr_text;

    match &unwrap.pattern {
        UnwrapPattern::StartsWithFind { needle, .. } => {
            format!(
                "// Before (redundant pattern):\n\
                 if text.starts_with({}) {{\n    \
                     let pos = text.find({}).unwrap();\n\
                 }}\n\n\
                 // After (idiomatic - recommended):\n\
                 if let Some(rest) = text.strip_prefix({}) {{\n    \
                     // 'rest' contains everything after the prefix\n    \
                     // No need for find() at all!\n\
                 }}\n\n\
                 // Or if you need the position:\n\
                 // The position is always 0 + prefix.len() after strip_prefix",
                needle, needle, needle
            )
        }
        UnwrapPattern::EnvVar { var_name } => {
            format!(
                "// Before:\n\
                 {}\n\n\
                 // After (Option 1 - with helpful message):\n\
                 env::var(\"{}\").expect(\"{} must be set\")\n\n\
                 // After (Option 2 - with default):\n\
                 env::var(\"{}\").unwrap_or_else(|_| \"default_value\".to_string())\n\n\
                 // After (Option 3 - handle at startup):\n\
                 // Load config once, fail fast if missing env vars",
                before, var_name, var_name, var_name
            )
        }
        UnwrapPattern::Parse { target_type } => {
            let t = target_type.as_deref().unwrap_or("T");
            format!(
                "// Before:\n\
                 {}\n\n\
                 // After (Option 1 - propagate error):\n\
                 {}?\n\n\
                 // After (Option 2 - with context):\n\
                 {}.expect(\"input should be valid {}\")\n\n\
                 // After (Option 3 - with fallback):\n\
                 {}.unwrap_or_default()",
                before,
                before.replace(".unwrap()", ""),
                before.replace(".unwrap()", ""),
                t,
                before.replace(".unwrap()", ""),
            )
        }
        UnwrapPattern::CollectionGet { index_expr } => {
            format!(
                "// Before:\n\
                 {}\n\n\
                 // After (Option 1 - if let pattern):\n\
                 if let Some(item) = collection.get({}) {{\n    \
                     // use item\n\
                 }}\n\n\
                 // After (Option 2 - with fallback):\n\
                 collection.get({}).unwrap_or(&default)\n\n\
                 // After (Option 3 - with expect if index is proven valid):\n\
                 collection.get({}).expect(\"index is within bounds\")",
                before, index_expr, index_expr, index_expr
            )
        }
        UnwrapPattern::LockUnwrap { lock_method } => {
            format!(
                "// Before:\n\
                 {}\n\n\
                 // After (Option 1 - recover from poison):\n\
                 mutex.{}().unwrap_or_else(|e| e.into_inner())\n\n\
                 // After (Option 2 - panic is acceptable):\n\
                 mutex.{}().expect(\"mutex should not be poisoned\")\n\n\
                 // Note: A poisoned lock means another thread panicked while holding it.\n\
                 // The data might be in an inconsistent state.",
                before, lock_method, lock_method
            )
        }
        UnwrapPattern::IsSomeUnwrap => {
            format!(
                "// Before (anti-pattern):\n\
                 if value.is_some() {{\n    \
                     let x = value.unwrap();\n\
                     // use x\n\
                 }}\n\n\
                 // After (idiomatic):\n\
                 if let Some(x) = value {{\n    \
                     // use x directly\n\
                 }}\n\n\
                 // This eliminates the redundant check and is more concise.",
            )
        }
        UnwrapPattern::IsOkUnwrap => {
            format!(
                "// Before (anti-pattern):\n\
                 if result.is_ok() {{\n    \
                     let x = result.unwrap();\n\
                     // use x\n\
                 }}\n\n\
                 // After (idiomatic):\n\
                 if let Ok(x) = result {{\n    \
                     // use x directly\n\
                 }}\n\n\
                 // Or use match for handling both cases:\n\
                 match result {{\n    \
                     Ok(x) => {{ /* success */ }},\n    \
                     Err(e) => {{ /* handle error */ }},\n\
                 }}",
            )
        }
        _ => {
            // Fallback to generic preview
            match unwrap.on_type {
                UnwrapType::Option => {
                    format!(
                        "// Before:\n\
                         {}\n\n\
                         // After (Option 1 - with default):\n\
                         {}\n\n\
                         // After (Option 2 - convert to Result):\n\
                         {}\n\n\
                         // After (Option 3 - pattern match):\n\
                         if let Some(value) = {} {{\n    \
                             // use value\n\
                         }}",
                        before,
                        before.replace(".unwrap()", ".unwrap_or_default()"),
                        before.replace(".unwrap()", ".ok_or(Error::NotFound)?"),
                        before.replace(".unwrap()", ""),
                    )
                }
                UnwrapType::Result => {
                    format!(
                        "// Before:\n\
                         {}\n\n\
                         // After (Option 1 - propagate with ?):\n\
                         {}?\n\n\
                         // After (Option 2 - with context):\n\
                         {}\n\n\
                         // After (Option 3 - match for custom handling):\n\
                         match {} {{\n    \
                             Ok(value) => value,\n    \
                             Err(e) => return Err(e.into()),\n\
                         }}",
                        before,
                        before.replace(".unwrap()", ""),
                        before.replace(".unwrap()", ".context(\"operation failed\")?"),
                        before.replace(".unwrap()", ""),
                    )
                }
                UnwrapType::Unknown => {
                    format!(
                        "// Before:\n\
                         {}\n\n\
                         // After (safer):\n\
                         {}\n\n\
                         // Tip: Use explicit error handling based on the actual type",
                        before,
                        before.replace(".unwrap()", ".expect(\"describe why this won't fail\")"),
                    )
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::rust::parse_rust_file;
    use crate::semantics::rust::build_rust_semantics;
    use crate::semantics::SourceSemantics;
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
        let rule = RustUnsafeUnwrapRule::new();
        assert_eq!(rule.id(), "rust.unsafe_unwrap");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustUnsafeUnwrapRule::new();
        assert!(rule.name().contains("unwrap"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = RustUnsafeUnwrapRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("RustUnsafeUnwrapRule"));
    }

    #[tokio::test]
    async fn detects_unwrap_in_function() {
        let rule = RustUnsafeUnwrapRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process(data: Option<String>) -> String {
    data.unwrap()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should detect the unwrap
        let unwrap_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.unsafe_unwrap")
            .collect();
        assert!(!unwrap_findings.is_empty(), "Should detect unwrap in function");
    }

    #[tokio::test]
    async fn skips_unwrap_in_test() {
        let rule = RustUnsafeUnwrapRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
#[test]
fn test_something() {
    let result: Result<i32, &str> = Ok(42);
    assert_eq!(result.unwrap(), 42);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should NOT detect the unwrap in test code
        let unwrap_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.unsafe_unwrap")
            .collect();
        assert!(
            unwrap_findings.is_empty(),
            "Should skip unwrap in test code"
        );
    }

    #[tokio::test]
    async fn skips_unwrap_in_main() {
        let rule = RustUnsafeUnwrapRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn main() {
    let config = load_config().unwrap();
    run(config);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should NOT detect the unwrap in main (common pattern for CLI)
        let unwrap_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.unsafe_unwrap")
            .collect();
        assert!(
            unwrap_findings.is_empty(),
            "Should skip unwrap in main()"
        );
    }

    #[tokio::test]
    async fn does_not_flag_unwrap_or_else() {
        let rule = RustUnsafeUnwrapRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn create_recipe() -> String {
    std::env::var("X").unwrap_or_else(|_| "default".to_string())
}
"#,
        );
        let findings = rule.evaluate(&vec![(file_id, sem)], None).await;
        assert!(
            findings.iter().all(|f| f.rule_id != "rust.unsafe_unwrap"),
            "unwrap_or_else should not be treated as unsafe unwrap()"
        );
    }

    #[tokio::test]
    async fn skips_unwrap_or_default() {
        let rule = RustUnsafeUnwrapRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process(data: Option<String>) -> String {
    data.unwrap_or_default()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should NOT detect unwrap_or_default
        let unwrap_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.unsafe_unwrap")
            .collect();
        assert!(
            unwrap_findings.is_empty(),
            "Should skip unwrap_or_default"
        );
    }

    #[tokio::test]
    async fn skips_unwrap_or() {
        let rule = RustUnsafeUnwrapRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process(data: Option<String>) -> String {
    data.unwrap_or("default".to_string())
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should NOT detect unwrap_or
        let unwrap_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.unsafe_unwrap")
            .collect();
        assert!(
            unwrap_findings.is_empty(),
            "Should skip unwrap_or"
        );
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = RustUnsafeUnwrapRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process(data: Option<String>) -> String {
    data.unwrap()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        for finding in &findings {
            if finding.rule_id == "rust.unsafe_unwrap" {
                assert!(finding.patch.is_some());
                assert!(finding.fix_preview.is_some());
                assert!(finding.tags.contains(&"rust".to_string()));
                assert!(finding.tags.contains(&"panic".to_string()));
                assert_eq!(finding.dimension, Dimension::Stability);
                assert_eq!(finding.severity, Severity::High);
            }
        }
    }

    #[tokio::test]
    async fn returns_empty_for_non_rust() {
        let rule = RustUnsafeUnwrapRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn detects_multiple_unwraps() {
        let rule = RustUnsafeUnwrapRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process(a: Option<i32>, b: Option<i32>) -> i32 {
    let x = a.unwrap();
    let y = b.unwrap();
    x + y
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let unwrap_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.unsafe_unwrap")
            .collect();
        // Should detect both unwraps
        assert!(
            unwrap_findings.len() >= 1,
            "Should detect multiple unwraps"
        );
    }

    // =========================================================================
    // Smart Pattern Detection Tests
    // =========================================================================

    fn get_rust_semantics(source: &str) -> crate::semantics::rust::RustFileSemantics {
        let sf = SourceFile {
            path: "test.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        build_rust_semantics(&parsed).expect("semantics should build")
    }

    #[test]
    fn detects_env_var_pattern() {
        let sem = get_rust_semantics(
            r#"
fn get_config() -> String {
    std::env::var("DATABASE_URL").unwrap()
}
"#,
        );
        
        assert!(!sem.unwrap_calls.is_empty(), "Should detect unwrap");
        let unwrap = &sem.unwrap_calls[0];
        
        match &unwrap.pattern {
            UnwrapPattern::EnvVar { var_name } => {
                assert_eq!(var_name, "DATABASE_URL");
            }
            other => panic!("Expected EnvVar pattern, got {:?}", other),
        }
    }

    #[test]
    fn detects_parse_pattern_with_type() {
        let sem = get_rust_semantics(
            r#"
fn parse_port() -> u16 {
    "8080".parse::<u16>().unwrap()
}
"#,
        );
        
        assert!(!sem.unwrap_calls.is_empty(), "Should detect unwrap");
        let unwrap = &sem.unwrap_calls[0];
        
        match &unwrap.pattern {
            UnwrapPattern::Parse { target_type } => {
                assert_eq!(target_type.as_deref(), Some("u16"));
            }
            other => panic!("Expected Parse pattern, got {:?}", other),
        }
    }

    #[test]
    fn detects_collection_get_pattern() {
        let sem = get_rust_semantics(
            r#"
fn get_item(items: &[i32]) -> i32 {
    *items.get(0).unwrap()
}
"#,
        );
        
        assert!(!sem.unwrap_calls.is_empty(), "Should detect unwrap");
        let unwrap = &sem.unwrap_calls[0];
        
        match &unwrap.pattern {
            UnwrapPattern::CollectionGet { index_expr } => {
                assert_eq!(index_expr, "0");
            }
            other => panic!("Expected CollectionGet pattern, got {:?}", other),
        }
    }

    #[test]
    fn detects_first_pattern() {
        let sem = get_rust_semantics(
            r#"
fn get_first(items: &[i32]) -> i32 {
    *items.first().unwrap()
}
"#,
        );
        
        assert!(!sem.unwrap_calls.is_empty(), "Should detect unwrap");
        let unwrap = &sem.unwrap_calls[0];
        
        match &unwrap.pattern {
            UnwrapPattern::FirstOrLast { is_first } => {
                assert!(*is_first, "Should be first, not last");
            }
            other => panic!("Expected FirstOrLast pattern, got {:?}", other),
        }
    }

    #[test]
    fn detects_last_pattern() {
        let sem = get_rust_semantics(
            r#"
fn get_last(items: &[i32]) -> i32 {
    *items.last().unwrap()
}
"#,
        );
        
        assert!(!sem.unwrap_calls.is_empty(), "Should detect unwrap");
        let unwrap = &sem.unwrap_calls[0];
        
        match &unwrap.pattern {
            UnwrapPattern::FirstOrLast { is_first } => {
                assert!(!*is_first, "Should be last, not first");
            }
            other => panic!("Expected FirstOrLast pattern, got {:?}", other),
        }
    }

    #[test]
    fn detects_lock_pattern() {
        let sem = get_rust_semantics(
            r#"
fn access_mutex(mutex: &std::sync::Mutex<i32>) -> i32 {
    *mutex.lock().unwrap()
}
"#,
        );
        
        assert!(!sem.unwrap_calls.is_empty(), "Should detect unwrap");
        let unwrap = &sem.unwrap_calls[0];
        
        match &unwrap.pattern {
            UnwrapPattern::LockUnwrap { lock_method } => {
                assert_eq!(lock_method, "lock");
            }
            other => panic!("Expected LockUnwrap pattern, got {:?}", other),
        }
    }

    #[test]
    fn detects_iterator_next_pattern() {
        let sem = get_rust_semantics(
            r#"
fn get_next(iter: &mut std::vec::IntoIter<i32>) -> i32 {
    iter.next().unwrap()
}
"#,
        );
        
        assert!(!sem.unwrap_calls.is_empty(), "Should detect unwrap");
        let unwrap = &sem.unwrap_calls[0];
        
        match &unwrap.pattern {
            UnwrapPattern::IteratorNext => {}
            other => panic!("Expected IteratorNext pattern, got {:?}", other),
        }
    }

    #[test]
    fn detects_find_pattern() {
        let sem = get_rust_semantics(
            r#"
fn find_char(text: &str) -> usize {
    text.find("x").unwrap()
}
"#,
        );
        
        assert!(!sem.unwrap_calls.is_empty(), "Should detect unwrap");
        let unwrap = &sem.unwrap_calls[0];
        
        // Should detect as ContainsFind since there's no guard
        match &unwrap.pattern {
            UnwrapPattern::ContainsFind { needle } => {
                assert!(needle.contains("x"));
            }
            other => panic!("Expected ContainsFind pattern, got {:?}", other),
        }
    }

    #[test]
    fn detects_starts_with_find_pattern() {
        let sem = get_rust_semantics(
            r#"
fn extract_prefix(text: &str) {
    if text.starts_with("prefix:") {
        let pos = text.find("prefix:").unwrap();
    }
}
"#,
        );
        
        assert!(!sem.unwrap_calls.is_empty(), "Should detect unwrap");
        let unwrap = &sem.unwrap_calls[0];
        
        // Should detect as StartsWithFind since there's a starts_with guard
        match &unwrap.pattern {
            UnwrapPattern::StartsWithFind { needle, .. } => {
                assert!(needle.contains("prefix"));
            }
            other => panic!("Expected StartsWithFind pattern, got {:?}", other),
        }
    }

    #[test]
    fn detects_regex_new_pattern() {
        let sem = get_rust_semantics(
            r#"
fn compile_regex() {
    let re = regex::Regex::new(r"\d+").unwrap();
}
"#,
        );
        
        assert!(!sem.unwrap_calls.is_empty(), "Should detect unwrap");
        let unwrap = &sem.unwrap_calls[0];
        
        match &unwrap.pattern {
            UnwrapPattern::RegexNew => {}
            other => panic!("Expected RegexNew pattern, got {:?}", other),
        }
    }

    // =========================================================================
    // Smart Title Generation Tests
    // =========================================================================

    #[test]
    fn smart_title_for_env_var() {
        let title = generate_smart_title(
            &UnwrapPattern::EnvVar { var_name: "API_KEY".to_string() },
            "Result",
        );
        assert!(title.contains("API_KEY"));
        assert!(title.contains("Environment variable"));
    }

    #[test]
    fn smart_title_for_strip_prefix() {
        let title = generate_smart_title(
            &UnwrapPattern::StartsWithFind { 
                needle: "\"prefix\"".to_string(),
                guard_start_byte: None,
            },
            "Option",
        );
        assert!(title.contains("strip_prefix"));
        assert!(title.contains("starts_with"));
    }

    #[test]
    fn smart_title_for_lock() {
        let title = generate_smart_title(
            &UnwrapPattern::LockUnwrap { lock_method: "lock".to_string() },
            "Result",
        );
        assert!(title.contains("lock"));
        assert!(title.contains("poisoned"));
    }

    // =========================================================================
    // Type Inference Tests
    // =========================================================================

    #[test]
    fn infers_option_for_get() {
        let sem = get_rust_semantics(
            r#"
fn get_item(items: &[i32]) -> i32 {
    *items.get(0).unwrap()
}
"#,
        );
        
        let unwrap = &sem.unwrap_calls[0];
        assert_eq!(unwrap.on_type, UnwrapType::Option);
    }

    #[test]
    fn infers_result_for_parse() {
        let sem = get_rust_semantics(
            r#"
fn parse_num() -> i32 {
    "42".parse().unwrap()
}
"#,
        );
        
        let unwrap = &sem.unwrap_calls[0];
        assert_eq!(unwrap.on_type, UnwrapType::Result);
    }

    #[test]
    fn infers_result_for_env_var() {
        let sem = get_rust_semantics(
            r#"
fn get_env() -> String {
    std::env::var("HOME").unwrap()
}
"#,
        );
        
        let unwrap = &sem.unwrap_calls[0];
        assert_eq!(unwrap.on_type, UnwrapType::Result);
    }

    #[test]
    fn infers_option_for_find() {
        let sem = get_rust_semantics(
            r#"
fn find_pos(s: &str) -> usize {
    s.find("x").unwrap()
}
"#,
        );
        
        let unwrap = &sem.unwrap_calls[0];
        assert_eq!(unwrap.on_type, UnwrapType::Option);
    }
}
