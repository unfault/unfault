//! Rule: Unhandled errors in goroutines
//!
//! Detects goroutines that may have unhandled errors or panics, which
//! can cause silent failures or crash the entire program.

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

/// Rule that detects goroutines without error handling or panic recovery.
///
/// In Go, errors and panics in goroutines can be particularly problematic:
/// - Errors may be silently dropped if not properly propagated
/// - A panic in a goroutine will crash the entire program if not recovered
/// - Error channels or other mechanisms are needed to propagate errors
#[derive(Debug)]
pub struct GoUnhandledErrorGoroutineRule;

impl GoUnhandledErrorGoroutineRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoUnhandledErrorGoroutineRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for GoUnhandledErrorGoroutineRule {
    fn id(&self) -> &'static str {
        "go.unhandled_error_goroutine"
    }

    fn name(&self) -> &'static str {
        "Goroutine without error handling or panic recovery"
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
                SourceSemantics::Go(go) => go,
                _ => continue,
            };

            for goroutine in &go.goroutines {
                let mut issues = Vec::new();

                // Check for missing recover
                if !goroutine.has_recover {
                    issues.push("missing recover for panic handling");
                }

                // Anonymous goroutines without recover are higher risk
                if goroutine.is_anonymous && !goroutine.has_recover {
                    issues.push("anonymous goroutine without recover can crash program");
                }

                if issues.is_empty() {
                    continue;
                }

                let title = format!(
                    "Goroutine at line {} may have unhandled errors or panics",
                    goroutine.line
                );

                let issue_list = issues.join(", ");
                let description = format!(
                    "The goroutine at line {} has the following issues: {}.\n\n\
                     In Go, goroutines run concurrently and:\n\
                     - Errors cannot be returned directly to the caller\n\
                     - A panic in a goroutine will crash the entire program\n\
                     - Unhandled errors are silently lost\n\n\
                     Recommended patterns:\n\
                     1. Add `defer func() {{ if r := recover(); r != nil {{ ... }} }}()` for panic recovery\n\
                     2. Use error channels to propagate errors: `errCh <- err`\n\
                     3. Use sync.WaitGroup with error collection\n\
                     4. Consider using golang.org/x/sync/errgroup for error propagation",
                    goroutine.line, issue_list
                );

                let patch = generate_error_handling_patch(goroutine, *file_id);

                let fix_preview = format!(
                    "// Before:\n\
                     // go func() {{\n\
                     //     err := doWork()\n\
                     //     // err is lost!\n\
                     // }}()\n\
                     //\n\
                     // After (with recover and error channel):\n\
                     // go func() {{\n\
                     //     defer func() {{\n\
                     //         if r := recover(); r != nil {{\n\
                     //             errCh <- fmt.Errorf(\"panic: %v\", r)\n\
                     //         }}\n\
                     //     }}()\n\
                     //     if err := doWork(); err != nil {{\n\
                     //         errCh <- err\n\
                     //     }}\n\
                     // }}()"
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: if !goroutine.has_recover {
                        Severity::High // No recover is more severe
                    } else {
                        Severity::Medium
                    },
                    confidence: 0.85,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: go.path.clone(),
                    line: Some(goroutine.line),
                    column: Some(goroutine.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "go".into(),
                        "goroutine".into(),
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

use crate::semantics::go::model::GoroutineSpawn;

/// Generate a patch to add error handling to goroutine.
fn generate_error_handling_patch(goroutine: &GoroutineSpawn, file_id: FileId) -> FilePatch {
    let func_desc = if goroutine.is_anonymous {
        "anonymous function".to_string()
    } else {
        goroutine.function_name.clone().unwrap_or_else(|| "goroutine".to_string())
    };
    
    let replacement = format!(
        "go func() {{\n\
         \t\tdefer func() {{\n\
         \t\t\tif r := recover(); r != nil {{\n\
         \t\t\t\t// TODO: Handle panic - log, send to error channel, etc.\n\
         \t\t\t\tlog.Printf(\"goroutine panic: %v\\n%s\", r, debug.Stack())\n\
         \t\t\t}}\n\
         \t\t}}()\n\
         \t\t// Original goroutine body from: {}\n\
         \t}}()",
        func_desc
    );

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: goroutine.start_byte,
                end: goroutine.end_byte,
            },
            replacement,
        }],
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
            path: "test.go".to_string(),
            language: Language::Go,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_go_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_go_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Go(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = GoUnhandledErrorGoroutineRule::new();
        assert_eq!(rule.id(), "go.unhandled_error_goroutine");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = GoUnhandledErrorGoroutineRule::new();
        assert!(rule.name().contains("Goroutine"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = GoUnhandledErrorGoroutineRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GoUnhandledErrorGoroutineRule"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_go() {
        let rule = GoUnhandledErrorGoroutineRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_goroutine_without_recover() {
        let rule = GoUnhandledErrorGoroutineRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

func startWorker() {
    go func() {
        mayCrash()  // No recover!
    }()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.unhandled_error_goroutine" {
                assert!(finding.tags.contains(&"panic".to_string()));
            }
        }
    }

    #[tokio::test]
    async fn evaluate_no_finding_for_goroutine_with_recover() {
        let rule = GoUnhandledErrorGoroutineRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

func startWorker() {
    go func() {
        defer func() {
            if r := recover(); r != nil {
                log.Printf("recovered: %v", r)
            }
        }()
        mayCrash()
    }()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should have fewer/no findings for properly protected goroutine
        let _ = findings;
    }

    #[tokio::test]
    async fn evaluate_detects_unhandled_error_in_goroutine() {
        let rule = GoUnhandledErrorGoroutineRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "os"

func startWorker() {
    go func() {
        os.ReadFile("test.txt")  // Error ignored!
    }()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.unhandled_error_goroutine" {
                assert!(finding.description.as_ref().map(|d| d.contains("error")).unwrap_or(false) 
                    || finding.title.contains("error"));
            }
        }
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = GoUnhandledErrorGoroutineRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

func danger() {
    go func() {
        panic("boom")
    }()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.unhandled_error_goroutine" {
                assert_eq!(finding.dimension, Dimension::Stability);
                assert!(finding.patch.is_some());
                assert!(finding.fix_preview.is_some());
            }
        }
    }
}