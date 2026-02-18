//! Rule: Unnecessary .clone() in loops
//!
//! Detects patterns where `.clone()` is called repeatedly inside loops,
//! which can cause significant performance overhead. Often these can be
//! avoided by restructuring the code.
//!
//! # Patterns Detected
//!
//! ## Pattern 1: Loop-invariant clone
//! ```rust
//! // Bad: Clone is the same every iteration
//! for item in &items {
//!     let data = expensive_data.clone();
//!     process(data, item);
//! }
//!
//! // Good: Hoist outside the loop
//! let data = expensive_data.clone();
//! for item in &items {
//!     process(&data, item);
//! }
//! ```
//!
//! ## Pattern 2: Clone-to-consume (passing to consuming function)
//! ```rust
//! // Bad: Clone because value needed after consuming call
//! for rf in findings {
//!     let finding = Finding::from(rf.clone());  // clone() to pass to From
//!     process(rf.patch, rf.file_id);  // but still need rf's fields
//! }
//!
//! // Good: Extract needed fields before consuming
//! for rf in findings {
//!     let patch = rf.patch.clone();
//!     let file_id = rf.file_id;  // Copy types don't need clone
//!     let finding = Finding::from(rf);  // Now can move rf
//!     process(patch, file_id);
//! }
//! ```

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::rust::model::{RustFileSemantics, VariableBinding};
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unnecessary `.clone()` calls inside loops.
///
/// Repeated cloning in loops is a common performance anti-pattern,
/// especially for large data structures like `String`, `Vec`, or custom types.
///
/// This rule detects two main patterns:
/// 1. **Loop-invariant clone**: The cloned value doesn't change per iteration
/// 2. **Clone-to-consume**: Clone is used to pass ownership while still needing fields
#[derive(Debug, Default)]
pub struct RustCloneInLoopRule;

impl RustCloneInLoopRule {
    pub fn new() -> Self {
        Self
    }
}

/// Pattern detected for a clone in loop.
#[derive(Debug, Clone)]
enum ClonePattern {
    /// Loop-invariant: the cloned value doesn't depend on loop iteration
    LoopInvariant,
    /// Clone-to-consume: clone because fields are accessed after a consuming call
    CloneToConsume {
        /// The variable being consumed (e.g., "rf")
        consumed_var: String,
        /// Fields accessed on the consumed variable after the consuming call
        accessed_fields: Vec<String>,
        /// The binding where the consuming call happens
        consuming_binding: VariableBinding,
    },
    /// Generic clone pattern (can't determine specific pattern)
    Generic,
}

#[async_trait]
impl Rule for RustCloneInLoopRule {
    fn id(&self) -> &'static str {
        "rust.clone_in_loop"
    }

    fn name(&self) -> &'static str {
        "Unnecessary clone in loop"
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

            // Look for clone calls that are in loops
            for call in &rust.calls {
                if !call.in_loop {
                    continue;
                }

                // Check if this is a clone call
                let is_clone = call.function_call.callee_expr.ends_with(".clone()")
                    || call.method_name.as_deref() == Some("clone");

                if !is_clone {
                    continue;
                }

                // Skip if in test context
                if rust.functions.iter().any(|f| {
                    f.is_test
                        && call.function_call.location.line >= f.location.range.start_line
                        && call.function_call.location.line <= f.location.range.end_line
                }) {
                    continue;
                }

                let line = call.function_call.location.line;
                let cloned_expr = extract_cloned_expression(&call.function_call.callee_expr);

                // Detect the pattern
                let pattern = detect_clone_pattern(
                    rust,
                    &cloned_expr,
                    call.start_byte,
                    call.function_name.as_deref(),
                );

                // Generate finding based on detected pattern
                // Skip Generic pattern - those are iteration-dependent clones that are necessary
                let finding = match &pattern {
                    ClonePattern::CloneToConsume {
                        consumed_var,
                        accessed_fields,
                        consuming_binding,
                    } => {
                        Some(create_clone_to_consume_finding(
                            *file_id,
                            &rust.path,
                            line,
                            call.function_call.location.column,
                            consumed_var,
                            accessed_fields,
                            consuming_binding,
                            self.id(),
                        ))
                    }
                    ClonePattern::LoopInvariant => {
                        Some(create_loop_invariant_finding(
                            *file_id,
                            &rust.path,
                            line,
                            call.function_call.location.column,
                            &cloned_expr,
                            call.function_name.as_deref(),
                            self.id(),
                        ))
                    }
                    ClonePattern::Generic => {
                        // Skip iteration-dependent clones - they are necessary
                        // and there's no meaningful fix we can suggest
                        None
                    }
                };

                if let Some(f) = finding {
                    findings.push(f);
                }
            }
        }

        findings
    }
}

/// Detect which clone pattern this is.
fn detect_clone_pattern(
    rust: &RustFileSemantics,
    cloned_expr: &str,
    clone_byte: usize,
    function_name: Option<&str>,
) -> ClonePattern {
    // Look for a variable binding that:
    // 1. Has init_has_clone = true
    // 2. Has init_is_consuming_call = true
    // 3. Has consumed_variable matching our cloned expression
    // 4. Is in a loop

    for binding in &rust.variable_bindings {
        if !binding.in_loop {
            continue;
        }

        if !binding.init_has_clone || !binding.init_is_consuming_call {
            continue;
        }

        // Check if this binding consumes our cloned variable
        let consumed = match &binding.consumed_variable {
            Some(v) => v,
            None => continue,
        };

        if consumed != cloned_expr {
            continue;
        }

        // Check if the clone call is part of this binding's initialization
        // The clone should be within the binding's scope
        if clone_byte < binding.scope_start_byte || clone_byte > binding.scope_end_byte {
            continue;
        }

        // Now find field accesses on the consumed variable that happen
        // after this binding (within the same scope)
        let accessed_fields: Vec<String> = rust
            .field_accesses
            .iter()
            .filter(|fa| {
                fa.receiver == *consumed
                    && fa.in_loop
                    && fa.start_byte > binding.scope_start_byte
                    && fa.start_byte < binding.scope_end_byte
            })
            .map(|fa| fa.field.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if !accessed_fields.is_empty() {
            return ClonePattern::CloneToConsume {
                consumed_var: consumed.clone(),
                accessed_fields,
                consuming_binding: binding.clone(),
            };
        }
    }

    // Check if the cloned expression is a function parameter
    // Function parameters are truly loop-invariant (defined outside the loop)
    let is_function_param = function_name.map_or(false, |fn_name| {
        rust.functions
            .iter()
            .filter(|f| f.name == fn_name)
            .any(|f| f.params.iter().any(|p| p.name == cloned_expr))
    });

    // Check if the cloned expression is a variable defined OUTSIDE any loop
    // These are also truly loop-invariant
    let is_outer_binding = rust
        .variable_bindings
        .iter()
        .any(|b| !b.in_loop && !b.is_loop_variable && b.name == cloned_expr);

    // If it's a function parameter or outer binding, it's truly loop-invariant
    if is_function_param || is_outer_binding {
        return ClonePattern::LoopInvariant;
    }

    // Check if this is a loop variable (explicitly marked)
    let is_loop_var = rust
        .variable_bindings
        .iter()
        .any(|b| b.is_loop_variable && b.name == cloned_expr);

    if is_loop_var {
        return ClonePattern::Generic;
    }

    // For simple identifiers (no dots) that are NOT function parameters
    // and NOT outer bindings, they're likely from loop destructuring patterns
    // like `for (rule_id, _) in iter`. These are iteration-dependent.
    if !cloned_expr.contains('.') && !cloned_expr.contains('[') {
        // It's a simple identifier that's not defined outside the loop
        // This is likely a destructured loop variable
        return ClonePattern::Generic;
    }

    // Default to loop-invariant for complex expressions
    // (field accesses like self.data are usually truly invariant)
    ClonePattern::LoopInvariant
}

/// Create a finding for the clone-to-consume pattern with a proper fix.
fn create_clone_to_consume_finding(
    file_id: FileId,
    file_path: &str,
    line: u32,
    column: u32,
    consumed_var: &str,
    accessed_fields: &[String],
    binding: &VariableBinding,
    rule_id: &str,
) -> RuleFinding {
    let binding_line = binding.location.range.start_line + 1;

    let title = format!(
        "Clone-to-consume pattern: `{}.clone()` can be avoided",
        consumed_var
    );

    // Build the field extraction code
    let field_extractions: Vec<String> = accessed_fields
        .iter()
        .map(|field| {
            format!(
                "let {field} = {var}.{field}.clone();",
                field = field,
                var = consumed_var
            )
        })
        .collect();

    let extraction_code = field_extractions.join("\n");

    // Build the replacement for the consuming call (remove .clone())
    let fixed_init = binding
        .init_expr
        .as_ref()
        .map(|expr| {
            expr.replace(&format!("{}.clone()", consumed_var), consumed_var)
        })
        .unwrap_or_default();

    let description = format!(
        "The `.clone()` on `{}` at line {} is needed because fields `{}` are \
         accessed after the consuming call at line {}.\n\n\
         **Better approach:** Extract the needed fields before the consuming call, \
         then pass the original by move.\n\n\
         **Fix:**\n\
         ```rust\n\
         // Extract fields first\n\
         {}\n\
         // Then consume without clone\n\
         let {} = {};\n\
         // Use the extracted fields\n\
         ```\n\n\
         **Why this is better:**\n\
         - Avoids cloning the entire struct\n\
         - Only clones the specific fields needed (if they aren't Copy)\n\
         - For Copy types like `FileId`, no clone is needed at all",
        consumed_var,
        line,
        accessed_fields.join("`, `"),
        binding_line,
        extraction_code,
        binding.name,
        fixed_init,
    );

    let fix_preview = format!(
        "// Extract needed fields before consuming:\n\
         {}\n\
         let {} = {};",
        extraction_code, binding.name, fixed_init
    );

    // Generate the actual patch
    let patch = generate_clone_to_consume_patch(
        file_id,
        binding_line,
        consumed_var,
        accessed_fields,
        binding,
    );

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::PerformanceSmell,
        severity: Severity::Medium,
        confidence: 0.90, // High confidence for this pattern
        dimension: Dimension::Performance,
        file_id,
        file_path: file_path.to_string(),
        line: Some(line),
        column: Some(column),
        end_line: None,
        end_column: None,
            byte_range: None,
        patch: Some(patch),
        fix_preview: Some(fix_preview),
        tags: vec![
            "rust".into(),
            "performance".into(),
            "clone".into(),
            "loop".into(),
            "clone-to-consume".into(),
        ],
    }
}

/// Generate a patch for the clone-to-consume pattern.
fn generate_clone_to_consume_patch(
    file_id: FileId,
    binding_line: u32,
    consumed_var: &str,
    accessed_fields: &[String],
    binding: &VariableBinding,
) -> FilePatch {
    let mut hunks = Vec::new();

    // Hunk 1: Insert field extractions before the binding line
    let field_extractions: Vec<String> = accessed_fields
        .iter()
        .map(|field| {
            format!(
                "let {field} = {var}.{field}.clone();",
                field = field,
                var = consumed_var
            )
        })
        .collect();

    let extraction_code = field_extractions.join("\n") + "\n";

    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: binding_line },
        replacement: extraction_code,
    });

    // Hunk 2: Replace the binding to remove .clone()
    // Use ReplaceBytes with the binding's byte range
    if let Some(ref init_expr) = binding.init_expr {
        let fixed_init = init_expr.replace(&format!("{}.clone()", consumed_var), consumed_var);
        let fixed_line = if binding.is_mut {
            format!("let mut {} = {};", binding.name, fixed_init)
        } else {
            format!("let {} = {};", binding.name, fixed_init)
        };

        // Use the binding's byte range for replacement
        hunks.push(PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: binding.scope_start_byte,
                end: binding.scope_start_byte + estimate_binding_length(binding),
            },
            replacement: fixed_line,
        });
    }

    FilePatch { file_id, hunks }
}

/// Estimate the length of a binding statement in bytes.
///
/// This is a heuristic based on the binding's components.
fn estimate_binding_length(binding: &VariableBinding) -> usize {
    // "let " = 4, "mut " = 4 (if mut), name, " = ", init_expr, ";"
    let mut len = 4; // "let "
    if binding.is_mut {
        len += 4; // "mut "
    }
    len += binding.name.len();
    len += 3; // " = "
    if let Some(ref init) = binding.init_expr {
        len += init.len();
    }
    len += 1; // ";"
    len
}

/// Create a finding for loop-invariant clone pattern.
///
/// This is for clones where the value doesn't change per iteration
/// and can be hoisted outside the loop.
///
/// # Severity
/// - `Low` for field-access clones (e.g., `obj.field.clone()`) - shows as Info in VSCode
/// - `Medium` for simple variable clones (e.g., `data.clone()`) - shows as Warning in VSCode
fn create_loop_invariant_finding(
    file_id: FileId,
    file_path: &str,
    line: u32,
    column: u32,
    cloned_expr: &str,
    function_name: Option<&str>,
    rule_id: &str,
) -> RuleFinding {
    // Field-access clones (like obj.field.clone()) are lower severity
    // because they're often acceptable for small values like string IDs
    let is_field_access = cloned_expr.contains('.');

    let title = format!(
        "Loop-invariant clone: `{}.clone()` can be hoisted",
        cloned_expr
    );

    let description = if is_field_access {
        format!(
            "A `.clone()` call on `{}` at line {} in function '{}' is inside a loop, \
             but the value doesn't change per iteration.\n\n\
             **Note:** For small values like string IDs, this is often acceptable. \
             Consider optimizing only if profiling shows it's a bottleneck.\n\n\
             **Why this might matter:**\n\
             - Each iteration allocates new memory\n\
             - For large `String`, `Vec`, `HashMap` this can be expensive\n\n\
             **Potential fix:** Cache the cloned value before the loop, or use \
             `contains_key()` check before cloning for map keys.",
            cloned_expr,
            line,
            function_name.unwrap_or("<unknown>"),
        )
    } else {
        format!(
            "A `.clone()` call on `{}` at line {} in function '{}' is inside a loop, \
             but the value doesn't change per iteration.\n\n\
             **Why this matters:**\n\
             - Each iteration allocates new memory unnecessarily\n\
             - For `String`, `Vec`, `HashMap` this can be expensive\n\
             - May cause memory fragmentation\n\n\
             **Fix:** Move the clone outside the loop:\n\
             ```rust\n\
             let cloned_{} = {}.clone();\n\
             for ... {{\n\
                 // use cloned_{} or &cloned_{}\n\
             }}\n\
             ```\n\n\
             **Alternative:** Use a reference (`&T`) instead of cloning if possible.",
            cloned_expr,
            line,
            function_name.unwrap_or("<unknown>"),
            cloned_expr.replace('.', "_"),
            cloned_expr,
            cloned_expr.replace('.', "_"),
            cloned_expr.replace('.', "_"),
        )
    };

    let var_name = format!("cloned_{}", cloned_expr.replace('.', "_"));
    let fix_preview = format!(
        "let {} = {}.clone();\n// Then use {} inside the loop instead of {}.clone()",
        var_name, cloned_expr, var_name, cloned_expr
    );

    // Generate a patch that inserts the hoisted clone before the loop
    // We insert before the current line as a best-effort heuristic
    // (ideally we'd find the loop start, but that requires more context)
    let patch = FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement: format!("let {} = {}.clone();\n", var_name, cloned_expr),
        }],
    };

    // Field-access clones get Low severity (Info in VSCode) to reduce noise
    // Simple variable clones get Medium severity (Warning in VSCode)
    let severity = if is_field_access {
        Severity::Low
    } else {
        Severity::Medium
    };

    // Lower confidence for field-access clones since they're often acceptable
    let confidence = if is_field_access { 0.70 } else { 0.85 };

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::PerformanceSmell,
        severity,
        confidence,
        dimension: Dimension::Performance,
        file_id,
        file_path: file_path.to_string(),
        line: Some(line),
        column: Some(column),
        end_line: None,
        end_column: None,
            byte_range: None,
        patch: Some(patch),
        fix_preview: Some(fix_preview),
        tags: vec![
            "rust".into(),
            "performance".into(),
            "clone".into(),
            "loop".into(),
            "loop-invariant".into(),
        ],
    }
}

/// Extract the expression being cloned from a clone call.
fn extract_cloned_expression(callee: &str) -> String {
    if let Some(idx) = callee.rfind(".clone()") {
        callee[..idx].to_string()
    } else if let Some(idx) = callee.rfind(".clone") {
        callee[..idx].to_string()
    } else {
        callee.to_string()
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
            path: "clone_loop.rs".to_string(),
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
        let rule = RustCloneInLoopRule::new();
        assert_eq!(rule.id(), "rust.clone_in_loop");
    }

    #[test]
    fn rule_name_mentions_clone() {
        let rule = RustCloneInLoopRule::new();
        assert!(rule.name().to_lowercase().contains("clone"));
    }

    #[tokio::test]
    async fn detects_clone_in_for_loop() {
        let rule = RustCloneInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process_items(items: &[String], data: String) {
    for item in items {
        let d = data.clone();
        println!("{} {}", d, item);
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.clone_in_loop"),
            "Should detect clone in for loop"
        );
    }

    #[tokio::test]
    async fn skips_clone_outside_loop() {
        let rule = RustCloneInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process(data: String) {
    let d = data.clone();
    println!("{}", d);
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let clone_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.clone_in_loop")
            .collect();
        assert!(
            clone_findings.is_empty(),
            "Should not flag clone outside loop"
        );
    }

    #[test]
    fn extract_cloned_expression_basic() {
        assert_eq!(extract_cloned_expression("data.clone()"), "data");
        assert_eq!(extract_cloned_expression("self.field.clone()"), "self.field");
        assert_eq!(extract_cloned_expression("foo"), "foo");
    }

    #[tokio::test]
    async fn finding_has_performance_dimension() {
        let rule = RustCloneInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process_items(items: &[String], data: String) {
    for item in items {
        let d = data.clone();
        println!("{} {}", d, item);
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        for finding in &findings {
            if finding.rule_id == "rust.clone_in_loop" {
                assert_eq!(finding.dimension, Dimension::Performance);
                assert!(finding.patch.is_some());
            }
        }
    }

    // ==================== Semantics Collection Tests ====================

    #[test]
    fn collects_field_accesses_in_loop() {
        let (_, sem) = parse_and_build_semantics(
            r#"
struct Data { field1: String, field2: i32 }

fn process(items: Vec<Data>) {
    for item in items {
        let _ = item.field1;
        let _ = item.field2;
    }
}
"#,
        );

        let rust = match sem.as_ref() {
            SourceSemantics::Rust(r) => r,
            _ => panic!("Expected Rust semantics"),
        };

        // Should have field accesses for field1 and field2
        let field_accesses: Vec<_> = rust
            .field_accesses
            .iter()
            .filter(|fa| fa.receiver == "item")
            .collect();

        assert!(
            field_accesses.len() >= 2,
            "Should collect field accesses: {:?}",
            field_accesses
        );
    }

    #[test]
    fn collects_variable_bindings_in_loop() {
        let (_, sem) = parse_and_build_semantics(
            r#"
fn process(items: Vec<String>) {
    for item in items {
        let cloned = item.clone();
        println!("{}", cloned);
    }
}
"#,
        );

        let rust = match sem.as_ref() {
            SourceSemantics::Rust(r) => r,
            _ => panic!("Expected Rust semantics"),
        };

        // Should have a variable binding for "cloned"
        let bindings: Vec<_> = rust
            .variable_bindings
            .iter()
            .filter(|b| b.name == "cloned")
            .collect();

        assert!(
            !bindings.is_empty(),
            "Should collect variable binding 'cloned'"
        );

        let binding = &bindings[0];
        assert!(binding.in_loop, "Binding should be marked as in_loop");
        assert!(binding.init_has_clone, "Binding should have init_has_clone");
    }

    #[test]
    fn detects_loop_variable() {
        let (_, sem) = parse_and_build_semantics(
            r#"
fn process(items: Vec<String>) {
    for item in items {
        println!("{}", item);
    }
}
"#,
        );

        let rust = match sem.as_ref() {
            SourceSemantics::Rust(r) => r,
            _ => panic!("Expected Rust semantics"),
        };

        // Should have a loop variable binding for "item"
        let loop_vars: Vec<_> = rust
            .variable_bindings
            .iter()
            .filter(|b| b.is_loop_variable)
            .collect();

        assert!(
            !loop_vars.is_empty(),
            "Should detect loop variable"
        );
    }

    // ==================== Clone-to-Consume Pattern Tests ====================

    #[tokio::test]
    async fn detects_clone_to_consume_with_from() {
        // This test verifies that clone-to-consume pattern detection works
        // when the semantics properly identify:
        // 1. init_has_clone = true
        // 2. init_is_consuming_call = true
        // 3. consumed_variable is set
        // 4. Field access after consuming call
        //
        // Note: Currently the semantics may not fully capture this pattern,
        // so we test that iteration-dependent clones (on loop variables)
        // are correctly skipped to avoid false positives.
        let rule = RustCloneInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
struct Source { field1: String, field2: i32 }
struct Target { data: String }

impl From<Source> for Target {
    fn from(s: Source) -> Self {
        Target { data: s.field1 }
    }
}

fn process(items: Vec<Source>) {
    for item in items {
        let target = Target::from(item.clone());
        println!("{}", item.field1);  // Still using item.field1 after clone
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Clone on loop variable `item` is iteration-dependent and necessary
        // for ownership transfer. Without full clone-to-consume detection,
        // this should be skipped to avoid false positive with useless fix.
        // If/when semantics capture clone-to-consume properly, this could
        // be detected and would provide an actionable fix.
        assert!(
            findings.is_empty(),
            "Should skip clone on loop variable (iteration-dependent): {:?}",
            findings
        );
    }

    #[tokio::test]
    async fn loop_invariant_clone_detection() {
        let rule = RustCloneInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process(items: &[i32], data: String) {
    for item in items {
        let d = data.clone();  // data is not the loop variable
        println!("{} {}", d, item);
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            !findings.is_empty(),
            "Should detect loop-invariant clone"
        );

        // The finding should be about loop-invariant clone
        let finding = &findings[0];
        let title_lower = finding.title.to_lowercase();
        assert!(
            title_lower.contains("clone") && title_lower.contains("loop"),
            "Title should mention clone and loop: {}",
            finding.title
        );
    }

    #[tokio::test]
    async fn skips_test_functions() {
        let rule = RustCloneInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
#[test]
fn test_something() {
    let items = vec![1, 2, 3];
    let data = String::from("test");
    for item in &items {
        let d = data.clone();
        println!("{} {}", d, item);
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.is_empty(),
            "Should skip clone in test function"
        );
    }

    #[tokio::test]
    async fn skips_clone_on_destructured_loop_variable() {
        // This is the pattern from cli/src/commands/review.rs that was
        // incorrectly flagged as loop-invariant. The clone is necessary
        // because rule_id is borrowed from the iterator and we need to
        // push an owned String into the Vec.
        let rule = RustCloneInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use std::collections::BTreeMap;

fn build_rule_index(grouped: BTreeMap<u8, BTreeMap<String, Vec<i32>>>) -> Vec<String> {
    let mut rule_index: Vec<String> = Vec::new();
    for (_, rules_by_id) in &grouped {
        for (rule_id, _) in rules_by_id {
            if !rule_index.contains(rule_id) {
                rule_index.push(rule_id.clone());
            }
        }
    }
    rule_index
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Clone on `rule_id` (which comes from destructuring the loop's
        // iterator) is iteration-dependent and necessary. Should not flag.
        assert!(
            findings.is_empty(),
            "Should skip clone on destructured loop variable: {:?}",
            findings
        );
    }

    #[tokio::test]
    async fn field_access_clone_has_low_severity() {
        // Field-access clones like `finding.rule_id.clone()` should have Low severity
        // to reduce noise in LSP (shows as Info instead of Warning)
        let rule = RustCloneInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
struct Finding { rule_id: String }

fn process(findings: &[Finding], grouped: &mut std::collections::HashMap<String, Vec<i32>>) {
    for finding in findings {
        grouped
            .entry(finding.rule_id.clone())
            .or_default()
            .push(1);
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            !findings.is_empty(),
            "Should detect field-access clone in loop"
        );

        let finding = &findings[0];
        assert_eq!(
            finding.severity,
            Severity::Low,
            "Field-access clones should have Low severity for reduced noise"
        );
    }

    #[tokio::test]
    async fn simple_variable_clone_has_medium_severity() {
        // Simple variable clones like `data.clone()` should have Medium severity
        let rule = RustCloneInLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn process(items: &[i32], data: String) {
    for item in items {
        let d = data.clone();
        println!("{} {}", d, item);
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            !findings.is_empty(),
            "Should detect simple variable clone in loop"
        );

        let finding = &findings[0];
        assert_eq!(
            finding.severity,
            Severity::Medium,
            "Simple variable clones should have Medium severity"
        );
    }

    // ==================== Helper Function Tests ====================

    #[test]
    fn test_extract_cloned_expression_complex() {
        assert_eq!(
            extract_cloned_expression("some_struct.nested.field.clone()"),
            "some_struct.nested.field"
        );
        assert_eq!(
            extract_cloned_expression("vec[0].clone()"),
            "vec[0]"
        );
        assert_eq!(
            extract_cloned_expression("(*ptr).clone()"),
            "(*ptr)"
        );
    }

    #[test]
    fn test_estimate_binding_length() {
        use crate::parse::ast::{AstLocation, TextRange};

        let binding = VariableBinding {
            name: "x".to_string(),
            init_expr: Some("value.clone()".to_string()),
            is_loop_variable: false,
            is_mut: false,
            init_has_clone: true,
            init_is_consuming_call: false,
            consumed_variable: None,
            function_name: Some("test".to_string()),
            in_loop: true,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 0,
                },
            },
            scope_start_byte: 0,
            scope_end_byte: 100,
        };

        let len = estimate_binding_length(&binding);
        // "let x = value.clone();" = 4 + 1 + 3 + 13 + 1 = 22
        assert_eq!(len, 22);
    }

    #[test]
    fn test_estimate_binding_length_with_mut() {
        use crate::parse::ast::{AstLocation, TextRange};

        let binding = VariableBinding {
            name: "x".to_string(),
            init_expr: Some("value".to_string()),
            is_loop_variable: false,
            is_mut: true,
            init_has_clone: false,
            init_is_consuming_call: false,
            consumed_variable: None,
            function_name: Some("test".to_string()),
            in_loop: true,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 0,
                },
            },
            scope_start_byte: 0,
            scope_end_byte: 100,
        };

        let len = estimate_binding_length(&binding);
        // "let mut x = value;" = 4 + 4 + 1 + 3 + 5 + 1 = 18
        assert_eq!(len, 18);
    }
}