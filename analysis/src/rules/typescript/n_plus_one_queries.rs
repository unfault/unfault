//! TypeScript N+1 Query Detection Rule
//!
//! Detects potential N+1 query patterns in database operations.

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
pub struct TypescriptNPlusOneQueriesRule;

impl TypescriptNPlusOneQueriesRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptNPlusOneQueriesRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptNPlusOneQueriesRule {
    fn id(&self) -> &'static str {
        "typescript.n_plus_one_queries"
    }

    fn name(&self) -> &'static str {
        "N+1 Query Pattern"
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

            // Check for ORM usage
            let has_orm = ts.imports.iter().any(|imp| {
                let module = imp.module.to_lowercase();
                module.contains("prisma")
                    || module.contains("typeorm")
                    || module.contains("sequelize")
                    || module.contains("mongoose")
            });

            if !has_orm {
                continue;
            }

            // Look for database calls inside loops (using in_loop field)
            for call in &ts.calls {
                // Skip if not inside a loop
                if !call.in_loop {
                    continue;
                }

                // Check if it's a database query
                let is_db_query = call.callee.contains("findOne")
                    || call.callee.contains("findUnique")
                    || call.callee.contains("findById")
                    || call.callee.contains("findByPk")
                    || call.callee.contains(".find(")
                    || call.callee.contains(".get(")
                    || call.callee.ends_with(".query")
                    || call.callee.contains("$queryRaw");

                if !is_db_query {
                    continue;
                }

                let line = call.location.range.start_line + 1;
                let column = call.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// FIX: N+1 query detected - fetch all data before loop:\n\
                             // const allData = await Model.findMany({ where: { id: { in: ids } } });\n\
                             // const dataMap = new Map(allData.map(d => [d.id, d]));\n"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!("N+1 query: {} inside loop", call.callee),
                    description: Some(format!(
                        "Database query '{}' inside loop at line {}. This causes N+1 queries \
                         where N is the number of iterations. Batch the queries using findMany/findAll \
                         with an IN clause before the loop.",
                        call.callee, line
                    )),
                    kind: FindingKind::PerformanceSmell,
                    severity: Severity::High,
                    confidence: 0.8,
                    dimension: Dimension::Performance,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Batch queries before loop".to_string()),
                    tags: vec!["performance".into(), "database".into(), "n+1".into()],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::n_plus_one())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptNPlusOneQueriesRule::new();
        assert_eq!(rule.id(), "typescript.n_plus_one_queries");
    }
}
