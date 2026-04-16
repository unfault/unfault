use std::collections::HashSet;
use std::sync::Arc;

use crate::graph::traversal::{get_impact, workspace_overview};
use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{Finding, Severity};
use crate::types::sre_diagnostic::{BlastRadius, FailureMode, SystemHazard, TradeoffProfile};

use super::glossary;
use super::world_model;

// ---------------------------------------------------------------------------
// Rule ID prefixes / exact IDs that map to each failure mode.
// We match by prefix so future rules in the same family are picked up
// automatically without touching this file.
// ---------------------------------------------------------------------------

/// SLO-001 — missing timeout on outbound remote/HTTP/DB calls.
const TIMEOUT_RULE_PREFIXES: &[&str] = &[
    "python.http.missing_timeout",
    "python.db.missing_timeout",
    "python.asyncio.missing_timeout",
    "python.sqlalchemy.missing_query_timeout",
    "python.fastapi.missing_request_timeout",
    "go.http_missing_timeout",
    "go.nethttp.server_missing_timeout",
    "go.nethttp.handler_missing_timeout",
    "go.frameworks.gorm.query_timeout",
    "go.frameworks.grpc.missing_deadline",
    "typescript.http_missing_timeout",
    "rust.grpc_no_deadline",
];

/// SLO-002 — retry without exponential backoff/jitter.
const RETRY_RULE_PREFIXES: &[&str] = &[
    "python.unbounded_retry",
    "python.http.missing_retry",
    "go.unbounded_retry",
    "go.http_retry",
    "typescript.unbounded_retry",
    "typescript.http.missing_retry",
    "rust.unbounded_retry",
];

/// SLO-003 — blocking calls / zombie process risks.
const ZOMBIE_RULE_PREFIXES: &[&str] = &[
    "rust.blocking_in_async",
    "go.goroutine_leak",
    "go.channel_never_closed",
    "rust.uncancelled_tasks",
];

/// SLO-006 — missing circuit breaker / unshielded dependency calls.
const CASCADE_RULE_PREFIXES: &[&str] = &[
    "python.missing_circuit_breaker",
    "python.http.missing_circuit_breaker",
    "go.missing_circuit_breaker",
    "go.http_missing_circuit_breaker",
    "typescript.missing_circuit_breaker",
    "typescript.http.missing_circuit_breaker",
    "rust.missing_circuit_breaker",
    "rust.http_missing_circuit_breaker",
];

fn matches_prefix(rule_id: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|p| rule_id.starts_with(p))
}

fn failure_mode_for(rule_id: &str) -> Option<FailureMode> {
    if matches_prefix(rule_id, TIMEOUT_RULE_PREFIXES) {
        Some(FailureMode::SlowDeath)
    } else if matches_prefix(rule_id, RETRY_RULE_PREFIXES) {
        Some(FailureMode::RetryStorm)
    } else if matches_prefix(rule_id, ZOMBIE_RULE_PREFIXES) {
        Some(FailureMode::ZombieProcess)
    } else if matches_prefix(rule_id, CASCADE_RULE_PREFIXES) {
        Some(FailureMode::Cascade)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Blast radius computation
// ---------------------------------------------------------------------------

fn compute_blast_radius(file_path: &str, graph: &CodeGraph) -> BlastRadius {
    let overview = workspace_overview(graph);
    let entrypoint_set: HashSet<&str> = overview.entrypoints.iter().map(|s| s.as_str()).collect();

    let impact = get_impact(graph, file_path, 6);
    let affected_files = impact.affected_files.clone();

    let entrypoint_files: Vec<String> = affected_files
        .iter()
        .filter(|f: &&String| entrypoint_set.contains(f.as_str()))
        .cloned()
        .collect();

    // Also check if the symptom file itself is an entrypoint.
    let self_is_entrypoint = entrypoint_set.contains(file_path);
    let reaches_entrypoint = !entrypoint_files.is_empty() || self_is_entrypoint;

    // Ensure entrypoint_files is never empty when reaches_entrypoint is true,
    // so the impact sentence always has a concrete name to display.
    let entrypoint_files = if self_is_entrypoint && entrypoint_files.is_empty() {
        vec![file_path.to_string()]
    } else {
        entrypoint_files
    };

    BlastRadius {
        affected_files,
        entrypoint_files,
        reaches_entrypoint,
    }
}

// ---------------------------------------------------------------------------
// Severity upgrade based on blast radius
// ---------------------------------------------------------------------------

fn effective_severity(base: &Severity, blast: &BlastRadius) -> Severity {
    if blast.reaches_entrypoint && blast.affected_files.len() > 3 {
        Severity::Critical
    } else if blast.reaches_entrypoint {
        // Never downgrade — only upgrade.
        match base {
            Severity::Critical | Severity::High => base.clone(),
            _ => Severity::High,
        }
    } else if blast.affected_files.len() > 3 {
        match base {
            Severity::Critical | Severity::High | Severity::Medium => base.clone(),
            _ => Severity::Medium,
        }
    } else {
        base.clone()
    }
}

// ---------------------------------------------------------------------------
// One-line impact string
// ---------------------------------------------------------------------------

fn one_line_impact(_blast: &BlastRadius, failure_mode: &FailureMode) -> String {
    // The hazard sentence is all that's needed here. Blast radius context
    // (entrypoint reached, files affected, SLO at risk) is surfaced by the
    // World Model's ↳ line in the renderer — not by this string.
    glossary::lookup(failure_mode.glossary_id())
        .map(|e| e.hazard.to_string())
        .unwrap_or_else(|| "A systemic failure may propagate through the call graph.".to_string())
}

// ---------------------------------------------------------------------------
// Destruction path: shortest chain from symptom file → nearest entrypoint.
// We re-use the `affected_files` from the impact query and include the
// symptom file as the first element.
// ---------------------------------------------------------------------------

fn destruction_path(file_path: &str, blast: &BlastRadius) -> Vec<String> {
    let mut path = vec![file_path.to_string()];

    // Add intermediate files (trimmed for display, at most 3 hops).
    for f in blast.affected_files.iter().take(2) {
        if f.as_str() != file_path {
            path.push(f.clone());
        }
    }

    // Ensure the nearest entrypoint is the final node if reachable.
    if let Some(ep) = blast.entrypoint_files.first() {
        if path.last().map(|s: &String| s.as_str()) != Some(ep.as_str()) {
            path.push(ep.clone());
        }
    }

    path
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Pass 3: SRE synthesis.
///
/// Consumes the finalized `Finding` list and the `CodeGraph` to produce
/// `SystemHazard` entries. Each hazard wraps one root finding with
/// graph-derived blast radius and severity upgrade.
///
/// This function is intentionally fast: it performs only O(findings) rule_id
/// lookups and one BFS per qualifying finding. The tree-sitter traversal
/// in Passes 1–2 remains the bottleneck.
pub fn synthesize(
    findings: &[Finding],
    _semantics: &[(FileId, Arc<SourceSemantics>)],
    graph: &CodeGraph,
) -> Vec<SystemHazard> {
    let mut hazards: Vec<SystemHazard> = Vec::new();

    // Deduplicate: one hazard per (failure_mode, file_path) pair so that
    // multiple rules firing on the same file don't produce duplicate hazards.
    let mut seen: HashSet<(String, String)> = HashSet::new();

    for finding in findings {
        let Some(failure_mode) = failure_mode_for(&finding.rule_id) else {
            continue;
        };

        let dedup_key = (
            failure_mode.glossary_id().to_string(),
            finding.file_path.clone(),
        );
        if !seen.insert(dedup_key) {
            continue;
        }

        let blast = compute_blast_radius(&finding.file_path, graph);
        let eff_sev = effective_severity(&finding.severity, &blast);
        let impact = one_line_impact(&blast, &failure_mode);
        let dest_path = destruction_path(&finding.file_path, &blast);

        // World Model: compute weighted propagation path
        let propagation = world_model::compute_propagation(finding, graph);

        // Build tradeoff profile from glossary
        let tradeoff = glossary::lookup(failure_mode.glossary_id())
            .map(|e| TradeoffProfile {
                gain: e.tradeoff.gain.to_string(),
                risk: e.tradeoff.risk.to_string(),
            })
            .unwrap_or_default();

        // If World Model found a macro_goal, prefer it for the one_line_impact
        let impact = if let Some(ref goal) = propagation.macro_goal {
            if propagation.anchored_to_slo {
                let hazard_sentence = glossary::lookup(failure_mode.glossary_id())
                    .map(|e| e.hazard)
                    .unwrap_or("A systemic failure may propagate through the call graph.");
                format!(
                    "Propagation risk {:.0}% — reaches SLO '{}'. {}",
                    propagation.aggregate_risk, goal, hazard_sentence
                )
            } else {
                impact
            }
        } else {
            impact
        };

        hazards.push(SystemHazard {
            glossary_id: failure_mode.glossary_id().to_string(),
            aka: failure_mode.aka().to_string(),
            failure_mode,
            finding_id: finding.id.clone(),
            file_path: finding.file_path.clone(),
            line: finding.line,
            blast_radius: blast,
            effective_severity: eff_sev,
            one_line_impact: impact,
            destruction_path: dest_path,
            propagation,
            tradeoff,
            dimension: Dimension::Reliability,
        });
    }

    // Sort: Critical first, then High, then others; within tier by file path.
    hazards.sort_by(|a, b| {
        severity_order(&a.effective_severity)
            .cmp(&severity_order(&b.effective_severity))
            .then(a.file_path.cmp(&b.file_path))
    });

    hazards
}

fn severity_order(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_mode_timeout_rules() {
        assert!(matches!(
            failure_mode_for("python.http.missing_timeout"),
            Some(FailureMode::SlowDeath)
        ));
        assert!(matches!(
            failure_mode_for("go.http_missing_timeout"),
            Some(FailureMode::SlowDeath)
        ));
        assert!(matches!(
            failure_mode_for("typescript.http_missing_timeout"),
            Some(FailureMode::SlowDeath)
        ));
    }

    #[test]
    fn failure_mode_retry_rules() {
        assert!(matches!(
            failure_mode_for("python.unbounded_retry"),
            Some(FailureMode::RetryStorm)
        ));
        assert!(matches!(
            failure_mode_for("rust.unbounded_retry"),
            Some(FailureMode::RetryStorm)
        ));
    }

    #[test]
    fn failure_mode_zombie_rules() {
        assert!(matches!(
            failure_mode_for("rust.blocking_in_async"),
            Some(FailureMode::ZombieProcess)
        ));
        assert!(matches!(
            failure_mode_for("go.goroutine_leak"),
            Some(FailureMode::ZombieProcess)
        ));
    }

    #[test]
    fn failure_mode_unknown_rule() {
        assert!(failure_mode_for("python.bare_except").is_none());
        assert!(failure_mode_for("go.sql_injection").is_none());
    }

    #[test]
    fn severity_upgrade_reaches_entrypoint() {
        let blast = BlastRadius {
            affected_files: vec!["a.py".into(), "b.py".into(), "c.py".into(), "d.py".into()],
            entrypoint_files: vec!["d.py".into()],
            reaches_entrypoint: true,
        };
        assert_eq!(
            effective_severity(&Severity::Medium, &blast),
            Severity::Critical
        );
    }

    #[test]
    fn severity_upgrade_no_entrypoint_but_many_files() {
        let blast = BlastRadius {
            affected_files: vec!["a.py".into(), "b.py".into(), "c.py".into(), "d.py".into()],
            entrypoint_files: vec![],
            reaches_entrypoint: false,
        };
        assert_eq!(effective_severity(&Severity::Low, &blast), Severity::Medium);
    }

    #[test]
    fn severity_no_upgrade_isolated_file() {
        let blast = BlastRadius {
            affected_files: vec![],
            entrypoint_files: vec![],
            reaches_entrypoint: false,
        };
        assert_eq!(effective_severity(&Severity::Low, &blast), Severity::Low);
    }

    #[test]
    fn severity_never_downgraded() {
        let blast = BlastRadius {
            affected_files: vec!["a.py".into()],
            entrypoint_files: vec!["a.py".into()],
            reaches_entrypoint: true,
        };
        // Critical stays Critical even with a small blast radius.
        assert_eq!(
            effective_severity(&Severity::Critical, &blast),
            Severity::Critical
        );
    }
}
