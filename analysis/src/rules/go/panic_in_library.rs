//! Rule: Panic in library code detection
//!
//! Detects panic() calls in library code (non-main packages), which is
//! generally an antipattern. Libraries should return errors instead.

use std::sync::Arc;
use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects panic usage in library code.
///
/// Library code (non-main packages) should return errors instead of panicking.
/// Panics take away error handling decisions from callers and can crash
/// the entire application. Only panic for truly unrecoverable situations
/// like programmer errors that should never happen.
#[derive(Debug, Default)]
pub struct GoPanicInLibraryRule;

impl GoPanicInLibraryRule {
    pub fn new() -> Self {
        Self
    }
}

/// Panic functions and patterns to detect
const PANIC_PATTERNS: &[&str] = &[
    "panic(",
    "log.Fatal(",
    "log.Fatalf(",
    "log.Fatalln(",
    "log.Panic(",
    "log.Panicf(",
    "log.Panicln(",
];

#[async_trait]
impl Rule for GoPanicInLibraryRule {
    fn id(&self) -> &'static str {
        "go.panic_in_library"
    }

    fn name(&self) -> &'static str {
        "Panic in library code"
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
            let go = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Skip main packages - they can use panic for fatal errors
            if go.package_name == "main" {
                continue;
            }

            // Also skip test files
            if go.path.ends_with("_test.go") {
                continue;
            }

            // Look for panic calls
            for call in &go.calls {
                let is_panic_call = PANIC_PATTERNS.iter().any(|p| {
                    call.function_call.callee_expr == p.trim_end_matches('(') || 
                    call.function_call.callee_expr.ends_with(p.trim_end_matches('('))
                });

                if is_panic_call || call.function_call.callee_expr == "panic" {
                    let line = call.function_call.location.line;
                    
                    // Check if this is in an init() function (more acceptable)
                    let in_init = go.functions.iter().any(|f| {
                        f.name == "init" && 
                        f.location.range.start_line < call.function_call.location.line &&
                        f.location.range.start_line + 50 > call.function_call.location.line
                    });

                    // Different severity for init() vs regular functions
                    let severity = if in_init {
                        Severity::Low
                    } else {
                        Severity::High
                    };

                    let title = format!(
                        "Use of {} in library package '{}'",
                        call.function_call.callee_expr, go.package_name
                    );

                    let description = if in_init {
                        format!(
                            "panic() in init() at line {} in package '{}'. While panicking \
                             in init() is more acceptable (e.g., for configuration errors), \
                             consider if returning an error from a Setup() function would \
                             be more user-friendly.",
                            line, go.package_name
                        )
                    } else {
                        format!(
                            "panic() at line {} in library package '{}' takes away error \
                             handling decisions from callers. It can crash the entire \
                             application unexpectedly.\n\n\
                             Problems with panic in libraries:\n\
                             1. Callers cannot handle the error gracefully\n\
                             2. Crashes the entire application\n\
                             3. No stack trace without defer/recover\n\
                             4. Breaks the Go philosophy of explicit error handling\n\n\
                             Instead:\n\
                             ```go\n\
                             // Before\n\
                             func Process(x int) int {{\n\
                             \tif x < 0 {{\n\
                             \t\tpanic(\"x must be positive\")\n\
                             \t}}\n\
                             \treturn x * 2\n\
                             }}\n\n\
                             // After\n\
                             func Process(x int) (int, error) {{\n\
                             \tif x < 0 {{\n\
                             \t\treturn 0, errors.New(\"x must be positive\")\n\
                             \t}}\n\
                             \treturn x * 2, nil\n\
                             }}\n\
                             ```",
                            line, go.package_name
                        )
                    };

                    let patch = FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line },
                            replacement: "// TODO: Return error instead of panicking\n// return ..., errors.New(\"error message\")".to_string(),
                        }],
                    };

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity,
                        confidence: 0.90,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("Return error instead of panic".to_string()),
                        tags: vec![
                            "go".into(),
                            "panic".into(),
                            "error-handling".into(),
                            "library".into(),
                        ],
                    });
                }
            }

            // Also detect Must* functions that panic
            for func in &go.functions {
                if func.name.starts_with("Must") && !func.returns_error {
                    // Check if this function likely panics (no error return)
                    let line = func.location.range.start_line + 1;
                    
                    let title = format!(
                        "Must* function '{}' in library may panic",
                        func.name
                    );

                    let description = format!(
                        "Function '{}' at line {} follows the Must* naming convention which \
                         typically indicates it panics on error. While this pattern is common, \
                         consider also providing a non-panicking alternative.\n\n\
                         Common patterns:\n\
                         ```go\n\
                         // Provide both options\n\
                         func ParseConfig(path string) (*Config, error) {{ ... }}\n\
                         func MustParseConfig(path string) *Config {{\n\
                         \tc, err := ParseConfig(path)\n\
                         \tif err != nil {{\n\
                         \t\tpanic(err)\n\
                         \t}}\n\
                         \treturn c\n\
                         }}\n\
                         ```",
                        func.name, line
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Low,
                        confidence: 0.70,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some("Provide non-panicking alternative".to_string()),
                        tags: vec![
                            "go".into(),
                            "panic".into(),
                            "must-function".into(),
                        ],
                    });
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
    use crate::parse::go::parse_go_file;
    use crate::semantics::go::build_go_semantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "mylib/parser.go".to_string(),
            language: Language::Go,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_go_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_go_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Go(sem)))
    }

    #[test]
    fn test_rule_metadata() {
        let rule = GoPanicInLibraryRule::new();
        assert_eq!(rule.id(), "go.panic_in_library");
        assert!(!rule.name().is_empty());
    }

    #[tokio::test]
    async fn test_detects_panic_in_library() {
        let rule = GoPanicInLibraryRule::new();
        let (file_id, sem) = parse_and_build_semantics(r#"
package mylib

func Process(x int) int {
    if x < 0 {
        panic("x must be positive")
    }
    return x * 2
}
"#);
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        
        assert!(findings.iter().any(|f| f.rule_id == "go.panic_in_library"));
    }

    #[tokio::test]
    async fn test_no_finding_in_main_package() {
        let rule = GoPanicInLibraryRule::new();
        let sf = SourceFile {
            path: "main.go".to_string(),
            language: Language::Go,
            content: r#"
package main

func main() {
    if err != nil {
        panic(err)
    }
}
"#.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_go_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_go_semantics(&parsed).expect("semantics should build");
        let semantics = vec![(file_id, Arc::new(SourceSemantics::Go(sem)))];
        
        let findings = rule.evaluate(&semantics, None).await;
        
        // Should not flag main package
        let panic_findings: Vec<_> = findings.iter()
            .filter(|f| f.rule_id == "go.panic_in_library")
            .collect();
        assert!(panic_findings.is_empty());
    }
}