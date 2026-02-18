//! Rule: Global mutable state detection.
//!
//! Global mutable state (static mut, lazy_static without sync) can cause
//! race conditions and should be avoided.

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

/// Rule that detects global mutable state patterns.
#[derive(Debug, Default)]
pub struct RustGlobalMutableStateRule;

impl RustGlobalMutableStateRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustGlobalMutableStateRule {
    fn id(&self) -> &'static str {
        "rust.global_mutable_state"
    }

    fn name(&self) -> &'static str {
        "Global mutable state that could cause race conditions"
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

            // Check for static mut keywords
            for stat in &rust.statics {
                if !stat.is_mut {
                    continue;
                }

                let line = stat.location.range.start_line + 1;

                let title = format!("Global mutable static '{}'", stat.name);

                let description = format!(
                    "A `static mut` declaration '{}' at line {} creates global mutable state.\n\n\
                     **Why this matters:**\n\
                     - Access to `static mut` requires `unsafe`\n\
                     - Race conditions in multi-threaded code\n\
                     - Difficult to reason about program state\n\
                     - Prevents compiler optimizations\n\n\
                     **Recommendations:**\n\
                     - Use `std::sync::OnceLock` for lazily initialized values\n\
                     - Use `std::sync::atomic` types for simple values\n\
                     - Use `std::sync::Mutex` or `RwLock` for complex types\n\
                     - Consider thread-local storage with `thread_local!`\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use std::sync::OnceLock;\n\
                     \n\
                     // Instead of: static mut CONFIG: Option<Config> = None;\n\
                     static CONFIG: OnceLock<Config> = OnceLock::new();\n\
                     \n\
                     fn get_config() -> &'static Config {{\n    \
                         CONFIG.get_or_init(|| load_config())\n\
                     }}\n\
                     ```",
                    stat.name,
                    line
                );

                let fix_preview = format!(
                    "use std::sync::OnceLock;\n\n\
                     static {}: OnceLock<{}> = OnceLock::new();",
                    stat.name.to_uppercase(),
                    if stat.decl_type.is_empty() { "T" } else { &stat.decl_type }
                );

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Replace static mut with OnceLock or Mutex".to_string(),
                    }],
                };

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
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "rust".into(),
                        "global-state".into(),
                        "concurrency".into(),
                        "unsafe".into(),
                    ],
                });
            }

            // Check for lazy_static without proper synchronization
            for mac in &rust.macro_invocations {
                if mac.name != "lazy_static" {
                    continue;
                }

                // Check if the lazy_static contains unsynchronized types
                let has_mutex = mac.args.contains("Mutex")
                    || mac.args.contains("RwLock")
                    || mac.args.contains("Atomic");

                if has_mutex {
                    continue;
                }

                // Check if it's a mutable type
                let is_mutable_type = mac.args.contains("Vec<")
                    || mac.args.contains("HashMap<")
                    || mac.args.contains("HashSet<")
                    || mac.args.contains("mut ");

                if !is_mutable_type {
                    continue;
                }

                let line = mac.location.range.start_line + 1;

                let title = "lazy_static with mutable type without synchronization".to_string();

                let description = format!(
                    "A `lazy_static!` at line {} contains a mutable type without synchronization.\n\n\
                     **Why this matters:**\n\
                     - Mutable types in lazy_static need synchronization\n\
                     - Race conditions when mutating from multiple threads\n\
                     - Undefined behavior possible\n\n\
                     **Recommendations:**\n\
                     - Wrap with Mutex: `Mutex<HashMap<..>>`\n\
                     - Use `once_cell::sync::Lazy` with Mutex\n\
                     - Consider using `dashmap` for concurrent maps\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use std::sync::Mutex;\n\
                     use once_cell::sync::Lazy;\n\
                     \n\
                     static CACHE: Lazy<Mutex<HashMap<String, Value>>> = \n    \
                         Lazy::new(|| Mutex::new(HashMap::new()));\n\
                     ```",
                    line
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::High,
                    confidence: 0.80,
                    dimension: Dimension::Stability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(FilePatch {
                        file_id: *file_id,
                        hunks: vec![PatchHunk {
                            range: PatchRange::InsertBeforeLine { line },
                            replacement: "// TODO: Wrap mutable type with Mutex or RwLock".to_string(),
                        }],
                    }),
                    fix_preview: Some("static CACHE: Lazy<Mutex<HashMap<...>>> = Lazy::new(|| Mutex::new(HashMap::new()));".to_string()),
                    tags: vec![
                        "rust".into(),
                        "global-state".into(),
                        "concurrency".into(),
                    ],
                });
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
            path: "lib.rs".to_string(),
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
        let rule = RustGlobalMutableStateRule::new();
        assert_eq!(rule.id(), "rust.global_mutable_state");
    }

    #[tokio::test]
    async fn detects_static_mut() {
        let rule = RustGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
static mut COUNTER: i32 = 0;

fn increment() {
    unsafe {
        COUNTER += 1;
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.iter().any(|f| f.rule_id == "rust.global_mutable_state"),
            "Should detect static mut"
        );
    }

    #[tokio::test]
    async fn skips_immutable_static() {
        let rule = RustGlobalMutableStateRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
static VERSION: &str = "1.0.0";
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        let global_state_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "rust.global_mutable_state")
            .collect();
        assert!(global_state_findings.is_empty(), "Should skip immutable static");
    }
}