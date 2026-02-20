//! TypeScript Transaction Boundary Detection Rule
//!
//! Detects database operations that should be wrapped in transactions.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

#[derive(Debug)]
pub struct TypescriptTransactionBoundaryRule;

impl TypescriptTransactionBoundaryRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptTransactionBoundaryRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptTransactionBoundaryRule {
    fn id(&self) -> &'static str {
        "typescript.transaction_boundary"
    }

    fn name(&self) -> &'static str {
        "Missing Transaction Boundary"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let ts = match sem.as_ref() {
                SourceSemantics::Typescript(ts) => ts,
                _ => continue,
            };

            // Check for ORM usage - Prisma, TypeORM, etc.
            let has_prisma = ts.imports.iter().any(|imp| imp.module.contains("prisma"));
            let has_typeorm = ts.imports.iter().any(|imp| imp.module.contains("typeorm"));
            let has_sequelize = ts
                .imports
                .iter()
                .any(|imp| imp.module.contains("sequelize"));

            if !has_prisma && !has_typeorm && !has_sequelize {
                continue;
            }

            // Look for functions that have multiple write operations
            for func in &ts.functions {
                // Check the function body for multiple write operations
                // This is a heuristic based on the function name patterns
                let func_name_lower = func.name.to_lowercase();

                // Functions that typically need transactions
                let needs_transaction = func_name_lower.contains("transfer")
                    || func_name_lower.contains("exchange")
                    || func_name_lower.contains("batch")
                    || func_name_lower.contains("bulk")
                    || func_name_lower.contains("multi")
                    || func_name_lower.contains("sync")
                    || func_name_lower.contains("migrate")
                    || func_name_lower.contains("process")
                    || func_name_lower.contains("import");

                if !needs_transaction {
                    continue;
                }

                let line = func.location.range.start_line + 1;
                let column = func.location.range.start_col + 1;

                let wrapper = if has_prisma {
                    "await prisma.$transaction(async (tx) => {\n  // Use tx instead of prisma for all DB operations\n});"
                } else if has_typeorm {
                    "await dataSource.transaction(async (manager) => {\n  // Use manager for all DB operations\n});"
                } else {
                    "await sequelize.transaction(async (t) => {\n  // Pass { transaction: t } to all DB operations\n});"
                };

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: format!(
                            "// TODO: Wrap operations in transaction:\n// {}\n",
                            wrapper
                        ),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!(
                        "Function '{}' may need transaction boundaries",
                        func.name
                    ),
                    description: Some(format!(
                        "Function '{}' appears to perform multiple database operations that should be atomic. \
                         Consider wrapping these operations in a database transaction to ensure data consistency \
                         and prevent partial updates on failures.",
                        func.name
                    )),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.55,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Wrap in database transaction".to_string()),
                    tags: vec!["database".into(), "transaction".into(), "consistency".into()],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::transaction_boundary())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptTransactionBoundaryRule::new();
        assert_eq!(rule.id(), "typescript.transaction_boundary");
    }
}
