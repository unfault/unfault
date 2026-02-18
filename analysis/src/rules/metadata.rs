//! Applicability metadata lookup.
//!
//! The preferred source of truth is `Rule::applicability()` implemented by each rule.
//! This module provides a stable lookup by `rule_id` for call sites that only have
//! a finding / rule_id string.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::rules::registry::RuleRegistry;
use crate::types::finding::FindingApplicability;

static APPLICABILITY_BY_RULE_ID: OnceLock<HashMap<&'static str, FindingApplicability>> =
    OnceLock::new();

pub fn applicability_for_rule_id(rule_id: &str) -> Option<FindingApplicability> {
    let map = APPLICABILITY_BY_RULE_ID.get_or_init(|| {
        let registry = RuleRegistry::with_builtin_rules();
        registry
            .all()
            .iter()
            .filter_map(|r| r.applicability().map(|a| (r.id(), a)))
            .collect()
    });

    map.get(rule_id)
        .cloned()
        // Transitional fallback while we roll out `Rule::applicability()` to all rules.
        .or_else(|| legacy_applicability_for_rule_id(rule_id))
}

fn legacy_applicability_for_rule_id(rule_id: &str) -> Option<FindingApplicability> {
    use crate::types::finding::{Benefit, DecisionLevel, InvestmentLevel, LifecycleStage};

    match rule_id {
        // Security is worth fixing even in demos.
        "python.sql_injection"
        | "go.sql_injection"
        | "typescript.sql_injection"
        | "rust.sql_injection" => Some(FindingApplicability {
            investment_level: InvestmentLevel::Low,
            min_stage: LifecycleStage::Prototype,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Security],
            prerequisites: vec![],
            notes: Some("Security issues are worth fixing even in demos.".to_string()),
        }),
        "python.hardcoded_secrets" | "rust.hardcoded_secrets" | "typescript.hardcoded_secrets" => {
            Some(FindingApplicability {
                investment_level: InvestmentLevel::Low,
                min_stage: LifecycleStage::Prototype,
                decision_level: DecisionLevel::Config,
                benefits: vec![Benefit::Security],
                prerequisites: vec!["Move secrets to env vars / secret manager".to_string()],
                notes: Some("Hardcoded secrets leak via git history and logs.".to_string()),
            })
        }
        "python.unsafe_eval" | "typescript.unsafe_eval" => Some(FindingApplicability {
            investment_level: InvestmentLevel::Low,
            min_stage: LifecycleStage::Prototype,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Security],
            prerequisites: vec![],
            notes: Some("Avoid eval in most cases; prefer parsing/whitelisting.".to_string()),
        }),

        // General stability/perf rollups where maturity matters.
        "rust.unbounded_concurrency"
        | "python.unbounded_concurrency"
        | "typescript.unbounded_concurrency" => Some(FindingApplicability {
            investment_level: InvestmentLevel::Medium,
            min_stage: LifecycleStage::Product,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Reliability, Benefit::Latency],
            prerequisites: vec!["Define concurrency limits/backpressure".to_string()],
            notes: Some(
                "For demos it may be fine; for production it often becomes a stability incident."
                    .to_string(),
            ),
        }),
        "rust.unbounded_memory"
        | "python.performance.unbounded_memory_operation"
        | "typescript.unbounded_memory" => Some(FindingApplicability {
            investment_level: InvestmentLevel::Medium,
            min_stage: LifecycleStage::Product,
            decision_level: DecisionLevel::Code,
            benefits: vec![Benefit::Reliability, Benefit::Performance],
            prerequisites: vec!["Avoid loading unbounded data into memory".to_string()],
            notes: Some("Memory blowups are common when data sizes grow.".to_string()),
        }),
        "python.unbounded_cache" | "rust.unbounded_cache" | "typescript.unbounded_cache" => {
            Some(FindingApplicability {
                investment_level: InvestmentLevel::Medium,
                min_stage: LifecycleStage::Product,
                decision_level: DecisionLevel::Code,
                benefits: vec![Benefit::Reliability, Benefit::Performance],
                prerequisites: vec!["Define eviction/TTL and max size".to_string()],
                notes: Some("Caches often need explicit bounds once traffic grows.".to_string()),
            })
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_none_for_unknown_rule_id() {
        assert!(applicability_for_rule_id("does.not.exist").is_none());
    }

    #[test]
    fn rule_based_metadata_is_available_for_annotated_rules() {
        assert!(applicability_for_rule_id("rust.missing_circuit_breaker").is_some());
        assert!(applicability_for_rule_id("rust.missing_idempotency_key").is_some());
        assert!(applicability_for_rule_id("python.http.missing_timeout").is_some());
    }

    #[test]
    fn report_rules_missing_applicability_metadata() {
        let registry = RuleRegistry::with_builtin_rules();

        let mut missing: Vec<&'static str> = registry
            .all()
            .iter()
            .filter(|r| r.applicability().is_none())
            .map(|r| r.id())
            .collect();

        missing.sort();

        eprintln!(
            "rules missing applicability metadata: {} / {}",
            missing.len(),
            registry.all().len()
        );

        if !missing.is_empty() {
            eprintln!("missing rule applicability ids:\n{}", missing.join("\n"));
        }

        // Transitional gate: set UNFAULT_ENFORCE_RULE_APPLICABILITY=1 to fail the test.
        let enforce = std::env::var("UNFAULT_ENFORCE_RULE_APPLICABILITY")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if enforce {
            assert!(
                missing.is_empty(),
                "Some rules have no applicability metadata; add Rule::applicability() implementations"
            );
        }
    }
}
