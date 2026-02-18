pub mod applicability_defaults;
pub mod finding;
pub mod metadata;
pub mod registry;
pub mod templates;

pub mod go;
pub mod python;
pub mod rust;
pub mod typescript;

use async_trait::async_trait;
use std::fmt::Debug;
use std::sync::Arc;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::finding::FindingApplicability;

/// A single rule Unfault can run.
///
/// Rules are pure: they inspect semantics & graph and return findings.
/// They do not mutate engine state.
#[async_trait]
pub trait Rule: Send + Sync + Debug {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;

    /// Optional applicability metadata for this rule.
    ///
    /// Consumers (CLI, UI, agents) can use this to prioritize recommendations
    /// without guessing repository maturity.
    fn applicability(&self) -> Option<FindingApplicability> {
        None
    }

    /// Evaluate the rule against the provided semantics and graph.
    ///
    /// Returns a list of findings (may be empty if no issues found).
    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::finding::RuleFinding;

    #[derive(Debug)]
    struct DummyRule;

    #[async_trait]
    impl Rule for DummyRule {
        fn id(&self) -> &'static str {
            "dummy.rule"
        }
        fn name(&self) -> &'static str {
            "Dummy Rule"
        }
        async fn evaluate(
            &self,
            _semantics: &[(FileId, Arc<SourceSemantics>)],
            _graph: Option<&CodeGraph>,
        ) -> Vec<RuleFinding> {
            vec![]
        }
    }

    #[test]
    fn test_rule_trait_methods() {
        let rule = DummyRule;
        assert_eq!(rule.id(), "dummy.rule");
        assert_eq!(rule.name(), "Dummy Rule");
        assert!(rule.applicability().is_none());
    }

    #[tokio::test]
    async fn test_rule_evaluate_empty() {
        let rule = DummyRule;
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}
