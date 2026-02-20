//! Rule: Concurrent map access detection
//!
//! Detects potential data races from accessing Go maps from multiple goroutines
//! without proper synchronization.

use async_trait::async_trait;
use std::sync::Arc;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects concurrent map access without synchronization.
///
/// Go maps are not safe for concurrent use. Reading and writing to a map
/// from multiple goroutines without locks causes data races and can crash
/// the program with "concurrent map writes" panic.
#[derive(Debug, Default)]
pub struct GoConcurrentMapAccessRule;

impl GoConcurrentMapAccessRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoConcurrentMapAccessRule {
    fn id(&self) -> &'static str {
        "go.concurrent_map_access"
    }

    fn name(&self) -> &'static str {
        "Concurrent map access without synchronization"
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

            // Check for sync.Map usage (safe pattern)
            let uses_sync_map = go.calls.iter().any(|c| {
                c.function_call.callee_expr.contains("sync.Map")
                    || c.function_call.callee_expr.contains(".Store(")
                    || c.function_call.callee_expr.contains(".Load(")
                    || c.function_call.callee_expr.contains(".LoadOrStore(")
                    || c.function_call.callee_expr.contains(".Delete(")
                    || c.function_call.callee_expr.contains(".Range(")
            });

            // Check for mutex usage
            let uses_mutex = go.mutex_operations.iter().any(|_| true)
                || go.calls.iter().any(|c| {
                    c.function_call.callee_expr.contains(".Lock()")
                        || c.function_call.callee_expr.contains(".RLock()")
                        || c.function_call.callee_expr.contains("sync.Mutex")
                        || c.function_call.callee_expr.contains("sync.RWMutex")
                });

            // Look for map declarations in the file
            let has_map_decl = go
                .declarations
                .iter()
                .any(|d| d.decl_type.as_ref().is_some_and(|t| t.starts_with("map[")));

            // Look for make(map[...]) calls
            let has_map_make = go
                .calls
                .iter()
                .any(|c| c.function_call.callee_expr == "make" && c.args_repr.contains("map["));

            let has_map = has_map_decl || has_map_make;

            // Check for goroutines that might access maps
            if has_map && !go.goroutines.is_empty() {
                // Heuristic: if we have maps and goroutines but no sync mechanisms
                if !uses_sync_map && !uses_mutex {
                    for goroutine in &go.goroutines {
                        // Check if goroutine body might access a map
                        // This is heuristic - looking for map-like access patterns
                        let text = &goroutine.text;

                        // Look for map access patterns: var[key] or var[key] = value
                        if text.contains('[') && text.contains(']') {
                            let title = "Potential concurrent map access".to_string();

                            let description = format!(
                                "Goroutine at line {} may access a map without synchronization. \
                                 Go maps are not safe for concurrent use. Concurrent reads and writes \
                                 to a map can cause a runtime panic.\n\n\
                                 Consider:\n\
                                 1. Use sync.Map for concurrent access\n\
                                 2. Protect map access with sync.Mutex or sync.RWMutex\n\
                                 3. Use channels to serialize map access\n\
                                 4. Use a concurrent-safe map wrapper",
                                goroutine.line
                            );

                            let patch = FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line: goroutine.line },
                                    replacement: "// WARNING: Ensure map access is protected with sync.Mutex or use sync.Map\n// var mu sync.RWMutex\n// mu.RLock() // for reads\n// mu.Lock()  // for writes".to_string(),
                                }],
                            };

                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title,
                                description: Some(description),
                                kind: FindingKind::StabilityRisk,
                                severity: Severity::Critical,
                                confidence: 0.70,
                                dimension: Dimension::Correctness,
                                file_id: *file_id,
                                file_path: go.path.clone(),
                                line: Some(goroutine.line),
                                column: Some(goroutine.column),
                                end_line: None,
                                end_column: None,
                                byte_range: None,
                                patch: Some(patch),
                                fix_preview: Some("Use sync.Map or protect with mutex".to_string()),
                                tags: vec![
                                    "go".into(),
                                    "concurrency".into(),
                                    "race-condition".into(),
                                    "map".into(),
                                ],
                            });
                        }
                    }
                }
            }

            // Also check for global map variables accessed in goroutines
            for decl in &go.declarations {
                if let Some(ref dtype) = decl.decl_type {
                    if dtype.starts_with("map[") && !decl.is_const {
                        // Global map - higher risk
                        if !go.goroutines.is_empty() && !uses_sync_map && !uses_mutex {
                            let line = decl.location.range.start_line + 1;

                            let title = "Global map may be accessed concurrently".to_string();

                            let description = format!(
                                "Package-level map '{}' at line {} may be accessed from goroutines \
                                 without synchronization. This is a common source of \"concurrent map writes\" \
                                 panics in production.\n\n\
                                 Consider:\n\
                                 1. Replace with sync.Map\n\
                                 2. Add a sync.RWMutex to protect access\n\
                                 3. Initialize map in init() with proper synchronization",
                                decl.name, line
                            );

                            // Generate patch to suggest sync.Map
                            let patch = FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line },
                                    replacement: format!(
                                        "// Replace with: var {} sync.Map // for thread safety",
                                        decl.name
                                    ),
                                }],
                            };

                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title,
                                description: Some(description),
                                kind: FindingKind::StabilityRisk,
                                severity: Severity::Critical,
                                confidence: 0.85,
                                dimension: Dimension::Correctness,
                                file_id: *file_id,
                                file_path: go.path.clone(),
                                line: Some(line),
                                column: None,
                                end_line: None,
                                end_column: None,
                                byte_range: None,
                                patch: Some(patch),
                                fix_preview: Some("Replace with sync.Map".to_string()),
                                tags: vec![
                                    "go".into(),
                                    "concurrency".into(),
                                    "race-condition".into(),
                                    "map".into(),
                                    "global".into(),
                                ],
                            });
                        }
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
    use crate::parse::go::parse_go_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::go::build_go_semantics;
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
    fn test_rule_metadata() {
        let rule = GoConcurrentMapAccessRule::new();
        assert_eq!(rule.id(), "go.concurrent_map_access");
        assert!(!rule.name().is_empty());
    }

    #[tokio::test]
    async fn test_detects_unsafe_map_in_goroutine() {
        let rule = GoConcurrentMapAccessRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

func main() {
    m := make(map[string]int)
    
    go func() {
        m["key"] = 1
    }()
    
    go func() {
        _ = m["key"]
    }()
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        // Should detect potential concurrent map access
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "go.concurrent_map_access")
        );
    }

    #[tokio::test]
    async fn test_no_finding_with_sync_map() {
        let rule = GoConcurrentMapAccessRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "sync"

func main() {
    var m sync.Map
    
    go func() {
        m.Store("key", 1)
    }()
    
    go func() {
        m.Load("key")
    }()
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        // Should not flag sync.Map usage
        let map_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go.concurrent_map_access")
            .collect();
        assert!(map_findings.is_empty());
    }

    #[tokio::test]
    async fn test_no_finding_with_mutex() {
        let rule = GoConcurrentMapAccessRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "sync"

var (
    m  = make(map[string]int)
    mu sync.RWMutex
)

func main() {
    go func() {
        mu.Lock()
        m["key"] = 1
        mu.Unlock()
    }()
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;

        // Should not flag when mutex is used
        let map_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "go.concurrent_map_access")
            .collect();
        assert!(map_findings.is_empty());
    }
}
