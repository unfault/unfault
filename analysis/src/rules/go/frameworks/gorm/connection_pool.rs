//! Rule: GORM Connection Pool Configuration
//!
//! Detects GORM database connections without connection pool configuration.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects GORM connections without connection pool configuration.
#[derive(Debug, Default)]
pub struct GormConnectionPoolRule;

impl GormConnectionPoolRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GormConnectionPoolRule {
    fn id(&self) -> &'static str {
        "go.gorm.connection_pool"
    }

    fn name(&self) -> &'static str {
        "GORM Connection Pool Configuration"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go_sem = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Check if GORM is imported
            let has_gorm = go_sem
                .imports
                .iter()
                .any(|imp| imp.path.contains("gorm.io/gorm"));

            if !has_gorm {
                continue;
            }

            // Look for gorm.Open calls
            for call in &go_sem.calls {
                let is_gorm_open = call.function_call.callee_expr.contains("gorm.Open")
                    || call.function_call.callee_expr == "Open";

                if !is_gorm_open {
                    continue;
                }

                // Check if connection pool is configured
                let has_pool_config = go_sem.calls.iter().any(|c| {
                    c.function_call.callee_expr.contains("SetMaxIdleConns")
                        || c.function_call.callee_expr.contains("SetMaxOpenConns")
                        || c.function_call.callee_expr.contains("SetConnMaxLifetime")
                });

                if !has_pool_config {
                    let line = call.function_call.location.line;

                    let title = format!(
                        "GORM database at line {} lacks connection pool configuration",
                        line
                    );

                    let description = format!(
                        "GORM database connection at line {} does not configure connection pool \
                         settings. Without proper pool configuration, your application may exhaust \
                         database connections under load or leak connections. Configure \
                         SetMaxIdleConns, SetMaxOpenConns, and SetConnMaxLifetime.",
                        line
                    );

                    let patch = generate_pool_patch(*file_id, line);

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        dimension: Dimension::Reliability,
                        file_id: *file_id,
                        file_path: go_sem.path.clone(),
                        line: Some(line),
                        column: Some(1),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(patch),
                        fix_preview: Some("// Configure connection pool settings".to_string()),
                        tags: vec![
                            "go".into(),
                            "gorm".into(),
                            "database".into(),
                            "connection-pool".into(),
                        ],
                    });
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(unbounded_resource())
    }
}

fn generate_pool_patch(file_id: FileId, line: u32) -> FilePatch {
    let replacement = r#"// Configure GORM connection pool:
// sqlDB, _ := db.DB()
// sqlDB.SetMaxIdleConns(10)           // Idle connections in pool
// sqlDB.SetMaxOpenConns(100)          // Max open connections
// sqlDB.SetConnMaxLifetime(time.Hour) // Connection max lifetime
"#
    .to_string();

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertAfterLine { line },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_has_correct_metadata() {
        let rule = GormConnectionPoolRule::new();
        assert_eq!(rule.id(), "go.gorm.connection_pool");
    }
}
