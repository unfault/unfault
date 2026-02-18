//! Rule: Unbounded memory operation detection
//!
//! Detects patterns that can lead to unbounded memory growth,
//! such as collecting large iterators without limits.
//!
//! # Examples
//!
//! Bad:
//! ```rust
//! fn process_file(reader: BufReader<File>) {
//!     let lines: Vec<String> = reader.lines().collect();  // OOM on large files
//! }
//! ```
//!
//! Good:
//! ```rust
//! fn process_file(reader: BufReader<File>) {
//!     for line in reader.lines().take(10000) {  // Bounded
//!         process(line?);
//!     }
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unbounded memory operations.
///
/// Loading unbounded data into memory (large files, unlimited query results,
/// etc.) can cause OOM crashes in production.
#[derive(Debug, Default)]
pub struct RustUnboundedMemoryRule;

impl RustUnboundedMemoryRule {
    pub fn new() -> Self {
        Self
    }
}

/// Patterns that indicate potentially unbounded memory consumption
const UNBOUNDED_PATTERNS: &[(&str, &str, &str)] = &[
    // (pattern, description, suggestion)
    (
        ".collect::<Vec",
        "collecting iterator into Vec",
        "Consider using .take(N) or streaming with for loop",
    ),
    (
        ".collect()",
        "collecting iterator without size limit",
        "Consider using .take(N) before collect",
    ),
    (
        ".read_to_end(",
        "reading entire file/stream to memory",
        "Use chunked reading with BufReader",
    ),
    (
        ".read_to_string(",
        "reading entire file to string",
        "Use chunked reading or streaming",
    ),
    (
        "to_vec()",
        "converting to Vec without size limit",
        "Consider working with slices or iterators",
    ),
    (
        ".bytes().collect",
        "collecting all bytes into memory",
        "Use streaming processing instead",
    ),
    (
        ".lines().collect",
        "collecting all lines into memory",
        "Process lines iteratively",
    ),
];

/// Patterns indicating bounded operations
const BOUNDED_PATTERNS: &[&str] = &[
    ".take(",
    ".limit(",
    "with_capacity(",
    "Vec::with_capacity",
    "String::with_capacity",
    ".truncate(",
    "MAX_",
    "_LIMIT",
    "bounded",
    // Internal iteration patterns - these iterate over known-bounded collections
    ".iter().filter",
    ".iter().map",
    ".iter().filter_map",
    ".iter().enumerate",
    ".iter().zip",
    ".iter().cloned",
    ".iter().copied",
    ".into_iter().filter",
    ".into_iter().map",
    // Self/struct field iteration (bounded by struct size)
    "self.",
    // Array/slice iteration (bounded by compile-time size)
    "..].iter()",
    // Explicit size bounds in variable names
    "_count",
    "_size",
    "_len",
];

/// Patterns that indicate truly unbounded/external data sources
/// These should ALWAYS trigger if no bounding is present
const EXTERNAL_SOURCE_PATTERNS: &[&str] = &[
    // File I/O
    "reader.lines()",
    "reader.bytes()",
    "BufReader",
    "File::",
    "fs::read",
    // Network I/O
    "response.bytes()",
    "response.text()",
    "body().collect",
    // Stdin
    "stdin()",
    "stdin.read",
    // Database/query results
    ".fetch_all(",
    ".query(",
    "stream.collect",
];

#[async_trait]
impl Rule for RustUnboundedMemoryRule {
    fn id(&self) -> &'static str {
        "rust.unbounded_memory"
    }

    fn name(&self) -> &'static str {
        "Unbounded memory operation may cause OOM"
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

            // Check calls for unbounded memory patterns
            for call in &rust.calls {
                let callee = &call.function_call.callee_expr;

                // Find matching unbounded pattern
                let pattern_match = UNBOUNDED_PATTERNS
                    .iter()
                    .find(|(pattern, _, _)| callee.contains(pattern));

                if let Some((pattern, description, suggestion)) = pattern_match {
                    // Check if there's a bounding operation nearby
                    let func_name = call.function_name.clone().unwrap_or_default();
                    let has_bounding = rust.calls.iter().any(|c| {
                        c.function_name.as_deref() == Some(&func_name)
                            && BOUNDED_PATTERNS.iter().any(|p| c.function_call.callee_expr.contains(p))
                    });

                    // Also check the callee itself for bounding
                    let self_bounded = BOUNDED_PATTERNS.iter().any(|p| callee.contains(p));

                    if has_bounding || self_bounded {
                        continue;
                    }

                    // Determine if this is from an external/unbounded source
                    // Check all calls in the same function for external source patterns
                    let has_external_source = rust.calls.iter().any(|c| {
                        c.function_name.as_deref() == Some(&func_name)
                            && EXTERNAL_SOURCE_PATTERNS.iter().any(|p| c.function_call.callee_expr.contains(p))
                    });

                    // Adjust severity and confidence based on source
                    // External sources (files, network, stdin) = high confidence
                    // Internal iteration (struct fields, etc.) = lower confidence
                    let (severity, confidence) = if has_external_source {
                        // Truly unbounded external data - high risk
                        if call.in_loop {
                            (Severity::High, 0.90)
                        } else {
                            (Severity::High, 0.85)
                        }
                    } else if call.in_loop {
                        // Internal data but in loop - medium risk
                        (Severity::Medium, 0.65)
                    } else {
                        // Internal data, not in loop - lower risk, might be false positive
                        (Severity::Low, 0.50)
                    };

                    let line = call.function_call.location.line;

                    let title = format!(
                        "Unbounded memory: {}",
                        description
                    );

                    let description_text = format!(
                        "The operation '{}' at line {} can consume unbounded memory.\n\n\
                        **Why this is risky:**\n\
                        - Large inputs can exhaust available memory\n\
                        - OOM kills are hard to debug in production\n\
                        - Memory pressure affects other services on the host\n\
                        - Attackers can exploit this for DoS\n\n\
                        **Recommendation:** {}",
                        pattern, line, suggestion
                    );

                    let fix_preview = format!(
                        "// Before (unbounded):\n\
                        let data: Vec<_> = reader.lines().collect();\n\n\
                        // After (bounded):\n\
                        const MAX_LINES: usize = 10_000;\n\
                        let data: Vec<_> = reader.lines().take(MAX_LINES).collect();\n\n\
                        // Or process iteratively:\n\
                        for line in reader.lines() {{\n\
                            process(line?);\n\
                        }}"
                    );

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line },
                            replacement: format!(
                                "// TODO: Add bounds check - {}\n",
                                suggestion
                            ),
                        }],
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description_text),
                        kind: FindingKind::PerformanceSmell,
                        severity,
                        confidence,
                        dimension: Dimension::Performance,
                        file_id: *file_id,
                        file_path: rust.path.clone(),
                        line: Some(line),
                        column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "rust".into(),
                            "memory".into(),
                            "unbounded".into(),
                            "oom".into(),
                        ],
                    });
                }
            }

            // Check for Vec::new() in loops without clear capacity
            for call in &rust.calls {
                if call.in_loop && call.function_call.callee_expr.contains("Vec::new()") {
                    // Check if push is used in the same loop (potential unbounded growth)
                    let func_name = call.function_name.clone().unwrap_or_default();
                    let has_push_in_loop = rust.calls.iter().any(|c| {
                        c.function_name.as_deref() == Some(&func_name)
                            && c.in_loop
                            && c.function_call.callee_expr.contains(".push(")
                    });

                    if has_push_in_loop {
                        let line = call.function_call.location.line;

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Vec growing in loop without capacity hint".to_string(),
                            description: Some(
                                "Creating Vec::new() and pushing in a loop causes repeated \
                                reallocations. Use Vec::with_capacity() if size is known.".to_string()
                            ),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::Low,
                            confidence: 0.65,
                            dimension: Dimension::Performance,
                            file_id: *file_id,
                            file_path: rust.path.clone(),
                            line: Some(line),
                            column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: None,
                            fix_preview: Some(
                                "// Use with_capacity when size is known:\n\
                                let mut vec = Vec::with_capacity(expected_size);".to_string()
                            ),
                            tags: vec![
                                "rust".into(),
                                "memory".into(),
                                "allocation".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
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
            path: "memory_code.rs".to_string(),
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
        let rule = RustUnboundedMemoryRule::new();
        assert_eq!(rule.id(), "rust.unbounded_memory");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustUnboundedMemoryRule::new();
        assert!(rule.name().contains("memory"));
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = RustUnboundedMemoryRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn unbounded_patterns_are_valid() {
        for (pattern, desc, suggestion) in UNBOUNDED_PATTERNS {
            assert!(!pattern.is_empty());
            assert!(!desc.is_empty());
            assert!(!suggestion.is_empty());
        }
    }

    #[test]
    fn bounded_patterns_are_valid() {
        for pattern in BOUNDED_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[test]
    fn external_source_patterns_are_valid() {
        for pattern in EXTERNAL_SOURCE_PATTERNS {
            assert!(!pattern.is_empty());
        }
    }

    #[test]
    fn internal_iteration_patterns_are_recognized_as_bounded() {
        // These patterns should be recognized as bounded (internal iteration)
        let internal_patterns = [
            "items.iter().filter(|x| x > 0).collect()",
            "self.data.iter().map(|x| x * 2).collect()",
            "list.iter().filter_map(|x| x.ok()).collect()",
        ];
        
        for pattern in internal_patterns {
            let is_bounded = BOUNDED_PATTERNS.iter().any(|p| pattern.contains(p));
            assert!(is_bounded, "Pattern '{}' should be recognized as bounded", pattern);
        }
    }

    #[test]
    fn external_sources_are_identified() {
        // These patterns should be identified as external sources
        let external_patterns = [
            "reader.lines().collect()",
            "File::open(path).unwrap()",
            "response.bytes().collect()",
            "stdin().read_line()",
        ];
        
        for pattern in external_patterns {
            let is_external = EXTERNAL_SOURCE_PATTERNS.iter().any(|p| pattern.contains(p));
            assert!(is_external, "Pattern '{}' should be identified as external source", pattern);
        }
    }
}