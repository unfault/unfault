//! Rule: Missing idempotency key for state-changing operations.
//!
//! State-changing HTTP endpoints should accept and validate idempotency keys
//! to prevent duplicate processing.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{
    Benefit, DecisionLevel, FindingApplicability, FindingKind, InvestmentLevel, LifecycleStage,
    Severity,
};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects missing idempotency key handling.
#[derive(Debug, Default)]
pub struct RustMissingIdempotencyKeyRule;

impl RustMissingIdempotencyKeyRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustMissingIdempotencyKeyRule {
    fn id(&self) -> &'static str {
        "rust.missing_idempotency_key"
    }

    fn name(&self) -> &'static str {
        "State-changing endpoint without idempotency key"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(FindingApplicability {
            investment_level: InvestmentLevel::High,
            min_stage: LifecycleStage::Product,
            decision_level: DecisionLevel::ApiContract,
            benefits: vec![Benefit::Reliability, Benefit::Correctness],
            prerequisites: vec![
                "Define idempotency key contract (scope, TTL, conflict behavior)".to_string(),
                "Persist request outcomes keyed by idempotency key".to_string(),
            ],
            notes: Some(
                "Often overkill for demos; valuable when clients may retry or payments/side-effects exist."
                    .to_string(),
            ),
        })
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

            // Check if idempotency handling exists
            let has_idempotency = rust.uses.iter().any(|u| {
                u.path.to_lowercase().contains("idempotency")
                    || u.path.to_lowercase().contains("idempotent")
            }) || rust.calls.iter().any(|c| {
                let hay = format!("{} {}", c.function_call.callee_expr, c.args_repr).to_lowercase();
                hay.contains("idempotency")
                    || hay.contains("idempotency-key")
                    || hay.contains("idempotency_key")
            });

            if has_idempotency {
                continue;
            }

            // Check if this uses HTTP frameworks
            let uses_http = rust.uses.iter().any(|u| {
                u.path.contains("axum") || u.path.contains("actix") || u.path.contains("warp")
            });

            if !uses_http {
                continue;
            }

            // Look for POST/PUT handlers
            for func in &rust.functions {
                if !func.is_async || func.is_test {
                    continue;
                }

                // Check for state-changing handler patterns
                let is_mutating = func.name.starts_with("post_")
                    || func.name.starts_with("put_")
                    || func.name.starts_with("create_")
                    || func.name.starts_with("update_")
                    || func.name.starts_with("delete_")
                    || func.name.contains("_create")
                    || func.name.contains("_update")
                    || func.name.contains("_submit")
                    || func.name.contains("_process");

                if !is_mutating {
                    continue;
                }

                let line = func.location.range.start_line + 1;

                let title = format!(
                    "State-changing handler '{}' lacks idempotency key",
                    func.name
                );

                let description = format!(
                    "The handler '{}' at line {} performs state changes without idempotency handling.\n\n\
                     **Why this matters:**\n\
                     - Network retries can cause duplicate processing\n\
                     - Users double-clicking can submit twice\n\
                     - Payment/order duplication risks\n\
                     - Inconsistent state on failures\n\n\
                     **Recommendations:**\n\
                     - Accept `Idempotency-Key` header\n\
                     - Store and check keys before processing\n\
                     - Return cached response for duplicate keys\n\
                     - Set appropriate TTL for keys\n\n\
                     **Example:**\n\
                     ```rust\n\
                     use axum::{{extract::{{Header, State}}, response::Json}};\n\
                     \n\
                     async fn create_order(\n    \
                         State(state): State<AppState>,\n    \
                         Header(idempotency_key): Header<Option<String>>,\n    \
                         Json(order): Json<CreateOrder>,\n\
                     ) -> Result<Json<Order>, AppError> {{\n    \
                         let key = idempotency_key.ok_or(AppError::MissingIdempotencyKey)?;\n    \
                         \n    \
                         if let Some(cached) = state.cache.get(&key).await {{\n        \
                             return Ok(Json(cached));\n    \
                         }}\n    \
                         \n    \
                         let result = process_order(order).await?;\n    \
                         state.cache.insert(key, result.clone()).await;\n    \
                         Ok(Json(result))\n\
                     }}\n\
                     ```",
                    func.name, line
                );

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement:
                            "// TODO: Add idempotency key handling (Idempotency-Key header)"
                                .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.70,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(
                        "Header(idempotency_key): Header<Option<String>>".to_string(),
                    ),
                    tags: vec![
                        "rust".into(),
                        "idempotency".into(),
                        "http".into(),
                        "reliability".into(),
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
    use std::sync::Arc;

    use crate::parse::ast::FileId;
    use crate::parse::rust::parse_rust_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::rust::build_rust_semantics;
    use crate::types::context::{Language, SourceFile};

    #[test]
    fn rule_id_is_correct() {
        let rule = RustMissingIdempotencyKeyRule::new();
        assert_eq!(rule.id(), "rust.missing_idempotency_key");
    }

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "main.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_rust_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Rust(sem)))
    }

    #[tokio::test]
    async fn skips_when_idempotency_header_is_handled() {
        let rule = RustMissingIdempotencyKeyRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
use axum::http::HeaderMap;

async fn create_recipe(headers: HeaderMap) {
    let _key = headers.get("Idempotency-Key");
}
"#,
        );

        let findings = rule.evaluate(&vec![(file_id, sem)], None).await;
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id != "rust.missing_idempotency_key"),
            "should not report missing idempotency key when header is referenced"
        );
    }
}
