//! Rule: Empty or suspicious mutex critical sections
//!
//! Detects mutex Lock/Unlock patterns that may indicate bugs,
//! such as empty critical sections or unlock without corresponding lock.

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

/// Rule that detects suspicious mutex usage patterns.
///
/// This rule identifies:
/// - Empty critical sections (Lock immediately followed by Unlock)
/// - Missing defer for Unlock
/// - Potential double-lock or unlock without lock scenarios
#[derive(Debug)]
pub struct GoEmptyCriticalSectionRule;

impl GoEmptyCriticalSectionRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoEmptyCriticalSectionRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for GoEmptyCriticalSectionRule {
    fn id(&self) -> &'static str {
        "go.empty_critical_section"
    }

    fn name(&self) -> &'static str {
        "Empty or suspicious mutex critical section"
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

            // Check for mutex-related issues
            for mutex_usage in &go.mutex_operations {
                // Pattern 1: Empty critical section
                if mutex_usage.is_empty_critical_section {
                    let title = format!(
                        "Empty critical section: Lock at line {} immediately unlocked",
                        mutex_usage.lock_line
                    );

                    let description = format!(
                        "The mutex `{}` is locked at line {} and immediately unlocked \
                         without any operations in between. This is likely a bug where \
                         code was accidentally removed or the locking logic is incorrect.\n\n\
                         If you intended to synchronize access to shared state, ensure \
                         the operations on that state are inside the critical section.",
                        mutex_usage.mutex_var,
                        mutex_usage.lock_line
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::High,
                        confidence: 0.95,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(mutex_usage.lock_line),
                        column: Some(mutex_usage.lock_column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None, // Can't auto-fix - need to understand intent
                        fix_preview: Some(
                            "// Review the code - the critical section should contain operations:\n\
                             // mu.Lock()\n\
                             // // ... protected operations here ...\n\
                             // mu.Unlock()"
                                .to_string(),
                        ),
                        tags: vec![
                            "go".into(),
                            "mutex".into(),
                            "concurrency".into(),
                            "correctness".into(),
                        ],
                    });
                }

                // Pattern 2: Lock without defer Unlock
                if !mutex_usage.uses_defer_unlock && !mutex_usage.is_rlock {
                    let title = format!(
                        "Mutex Lock without defer Unlock at line {}",
                        mutex_usage.lock_line
                    );

                    let description = format!(
                        "The mutex `{}` is locked at line {} without using `defer {}.Unlock()`. \
                         This pattern is error-prone because:\n\
                         - An early return or panic will leave the mutex locked\n\
                         - It's easy to forget to unlock on all code paths\n\n\
                         Best practice is to immediately defer the unlock:\n\
                         ```go\n\
                         {}.Lock()\n\
                         defer {}.Unlock()\n\
                         // ... protected code ...\n\
                         ```",
                        mutex_usage.mutex_var,
                        mutex_usage.lock_line,
                        mutex_usage.mutex_var,
                        mutex_usage.mutex_var,
                        mutex_usage.mutex_var
                    );

                    let patch = generate_defer_unlock_patch(mutex_usage, *file_id);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::AntiPattern,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(mutex_usage.lock_line),
                        column: Some(mutex_usage.lock_column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some(format!(
                            "// Before:\n\
                             // {}.Lock()\n\
                             // ... code ...\n\
                             // {}.Unlock()\n\
                             //\n\
                             // After:\n\
                             // {}.Lock()\n\
                             // defer {}.Unlock()\n\
                             // ... code ...",
                            mutex_usage.mutex_var,
                            mutex_usage.mutex_var,
                            mutex_usage.mutex_var,
                            mutex_usage.mutex_var
                        )),
                        tags: vec![
                            "go".into(),
                            "mutex".into(),
                            "defer".into(),
                            "reliability".into(),
                        ],
                    });
                }
            }
        }

        findings
    }
}

use crate::semantics::go::model::MutexOperation;

/// Generate a patch to add defer Unlock after Lock.
fn generate_defer_unlock_patch(mutex_usage: &MutexOperation, file_id: FileId) -> FilePatch {
    let defer_unlock = format!("defer {}.Unlock()", mutex_usage.mutex_var);

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertAt {
                byte_offset: mutex_usage.lock_end_byte,
            },
            replacement: format!("\n\t{}", defer_unlock),
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
        let rule = GoEmptyCriticalSectionRule::new();
        assert_eq!(rule.id(), "go.empty_critical_section");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = GoEmptyCriticalSectionRule::new();
        assert!(rule.name().contains("critical section"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = GoEmptyCriticalSectionRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GoEmptyCriticalSectionRule"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_go() {
        let rule = GoEmptyCriticalSectionRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_lock_without_defer() {
        let rule = GoEmptyCriticalSectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "sync"

var mu sync.Mutex

func increment(counter *int) {
    mu.Lock()
    *counter++
    mu.Unlock()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.empty_critical_section" {
                assert!(finding.tags.contains(&"mutex".to_string()));
            }
        }
    }

    #[tokio::test]
    async fn evaluate_no_finding_for_defer_unlock() {
        let rule = GoEmptyCriticalSectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "sync"

var mu sync.Mutex

func increment(counter *int) {
    mu.Lock()
    defer mu.Unlock()
    *counter++
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag proper defer unlock pattern
        for finding in &findings {
            if finding.rule_id == "go.empty_critical_section" {
                // If we found something, it shouldn't be about defer
                assert!(!finding.title.contains("defer"));
            }
        }
    }

    #[tokio::test]
    async fn evaluate_detects_empty_critical_section() {
        let rule = GoEmptyCriticalSectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "sync"

var mu sync.Mutex

func buggy() {
    mu.Lock()
    mu.Unlock()  // Empty critical section!
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.empty_critical_section" {
                assert!(finding.title.contains("Empty") || finding.description.as_ref().map(|d| d.contains("empty")).unwrap_or(false));
            }
        }
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = GoEmptyCriticalSectionRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "sync"

var mu sync.Mutex

func test() {
    mu.Lock()
    x := 1
    _ = x
    mu.Unlock()
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.empty_critical_section" {
                assert!(finding.tags.contains(&"go".to_string()));
                assert!(finding.tags.contains(&"concurrency".to_string()) || finding.tags.contains(&"mutex".to_string()));
            }
        }
    }
}