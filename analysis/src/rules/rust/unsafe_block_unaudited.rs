//! Rule: Unsafe block without SAFETY comment
//!
//! Detects unsafe blocks that don't have a SAFETY comment explaining
//! why the code is safe. This is a Rust community convention for
//! documenting unsafe code.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! fn dangerous() {
//!     unsafe {
//!         *raw_ptr = 42;  // No explanation!
//!     }
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! fn dangerous() {
//!     // SAFETY: raw_ptr is valid because it was just allocated
//!     // and we have exclusive access via &mut self
//!     unsafe {
//!         *raw_ptr = 42;
//!     }
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::rust::model::UnsafeOp;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unsafe blocks without SAFETY documentation.
///
/// The Rust community convention is to document all unsafe blocks with
/// a `// SAFETY:` comment explaining why the unsafe code is sound.
#[derive(Debug, Default)]
pub struct RustUnsafeBlockUnauditedRule;

impl RustUnsafeBlockUnauditedRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustUnsafeBlockUnauditedRule {
    fn id(&self) -> &'static str {
        "rust.unsafe_block_unaudited"
    }

    fn name(&self) -> &'static str {
        "Unsafe block without SAFETY comment"
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

            for unsafe_block in &rust.unsafe_blocks {
                // Skip if already has safety comment
                if unsafe_block.has_safety_comment {
                    continue;
                }

                let line = unsafe_block.location.range.start_line + 1;
                
                // Determine severity based on operations in the block
                let severity = determine_severity(&unsafe_block.operations);
                
                // Generate description based on detected operations
                let ops_description = describe_operations(&unsafe_block.operations);

                let title = format!(
                    "Unsafe block without SAFETY documentation{}",
                    if !ops_description.is_empty() {
                        format!(" (contains {})", ops_description)
                    } else {
                        String::new()
                    }
                );

                let description = format!(
                    "The `unsafe` block at line {} in function '{}' lacks a SAFETY comment.\n\n\
                     **Why this matters:**\n\
                     - Unsafe code bypasses Rust's safety guarantees\n\
                     - Without documentation, reviewers can't verify correctness\n\
                     - Future maintainers won't know the invariants\n\
                     - clippy::undocumented_unsafe_blocks will flag this\n\n\
                     **The SAFETY comment should explain:**\n\
                     - What invariants must hold for this code to be safe\n\
                     - Why those invariants are guaranteed at this call site\n\
                     - Any assumptions about the caller or context\n\n\
                     **Example format:**\n\
                     ```rust\n\
                     // SAFETY: `ptr` is valid because:\n\
                     // 1. It was allocated with the same allocator\n\
                     // 2. The allocation is still live (&mut self guarantees this)\n\
                     // 3. It's properly aligned for T\n\
                     unsafe {{ ... }}\n\
                     ```",
                    line,
                    unsafe_block.function_name.as_deref().unwrap_or("<unknown>")
                );

                let fix_preview = format!(
                    "// SAFETY: TODO: Document why this unsafe block is sound\n\
                     // - What invariants must hold?\n\
                     // - Why are they guaranteed here?\n\
                     unsafe {{\n    \
                         // ... existing code ...\n\
                     }}"
                );

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// SAFETY: TODO: Document the safety invariants here".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::SecurityVulnerability,
                    severity,
                    confidence: 0.95,
                    dimension: Dimension::Security,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: Some(unsafe_block.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "unsafe".into(),
                        "documentation".into(),
                        "security".into(),
                    ],
                });
            }
        }

        findings
    }
}

/// Determine severity based on operations in the unsafe block.
fn determine_severity(operations: &[UnsafeOp]) -> Severity {
    for op in operations {
        match op {
            UnsafeOp::Transmute => return Severity::Critical,
            UnsafeOp::RawPointerDeref => return Severity::High,
            UnsafeOp::MutableStaticAccess => return Severity::High,
            UnsafeOp::ExternCall => return Severity::Medium,
            UnsafeOp::UnsafeFnCall => return Severity::Medium,
            UnsafeOp::UnionFieldAccess => return Severity::Medium,
        }
    }
    Severity::Medium
}

/// Describe the operations found in the unsafe block.
fn describe_operations(operations: &[UnsafeOp]) -> String {
    let mut descs = Vec::new();
    for op in operations {
        let desc = match op {
            UnsafeOp::RawPointerDeref => "raw pointer dereference",
            UnsafeOp::Transmute => "transmute",
            UnsafeOp::MutableStaticAccess => "mutable static access",
            UnsafeOp::ExternCall => "extern call",
            UnsafeOp::UnsafeFnCall => "unsafe function call",
            UnsafeOp::UnionFieldAccess => "union field access",
        };
        if !descs.contains(&desc) {
            descs.push(desc);
        }
    }
    descs.join(", ")
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
            path: "unsafe_code.rs".to_string(),
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
        let rule = RustUnsafeBlockUnauditedRule::new();
        assert_eq!(rule.id(), "rust.unsafe_block_unaudited");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustUnsafeBlockUnauditedRule::new();
        assert!(rule.name().contains("SAFETY"));
    }

    #[tokio::test]
    async fn detects_unsafe_without_comment() {
        let rule = RustUnsafeBlockUnauditedRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn dangerous(ptr: *mut i32) {
    unsafe {
        *ptr = 42;
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.unsafe_block_unaudited"),
            "Should detect unsafe block without SAFETY comment"
        );
    }

    #[tokio::test]
    async fn skips_unsafe_with_safety_comment() {
        let rule = RustUnsafeBlockUnauditedRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn dangerous(ptr: *mut i32) {
    // SAFETY: ptr is valid and we have exclusive access
    unsafe {
        *ptr = 42;
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let unsafe_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.unsafe_block_unaudited")
            .collect();
        assert!(
            unsafe_findings.is_empty(),
            "Should skip unsafe block with SAFETY comment"
        );
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = RustUnsafeBlockUnauditedRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn dangerous(ptr: *mut i32) {
    unsafe {
        *ptr = 42;
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        for finding in &findings {
            if finding.rule_id == "rust.unsafe_block_unaudited" {
                assert!(finding.patch.is_some());
                assert!(finding.fix_preview.is_some());
                assert!(finding.tags.contains(&"rust".to_string()));
                assert!(finding.tags.contains(&"unsafe".to_string()));
                assert_eq!(finding.dimension, Dimension::Security);
            }
        }
    }

    #[test]
    fn severity_for_transmute_is_critical() {
        let ops = vec![UnsafeOp::Transmute];
        assert_eq!(determine_severity(&ops), Severity::Critical);
    }

    #[test]
    fn severity_for_raw_pointer_is_high() {
        let ops = vec![UnsafeOp::RawPointerDeref];
        assert_eq!(determine_severity(&ops), Severity::High);
    }

    #[test]
    fn severity_for_extern_is_medium() {
        let ops = vec![UnsafeOp::ExternCall];
        assert_eq!(determine_severity(&ops), Severity::Medium);
    }
}