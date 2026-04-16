use serde::{Deserialize, Serialize};

use crate::types::context::Dimension;
use crate::types::finding::Severity;

/// The gain/risk tradeoff profile for a failure mode.
///
/// Every engineering decision has a positive side effect (gain) and a negative
/// one (risk). Surfacing both moves the tool from "linter" to "system design
/// advisor" — the developer understands *why* the pattern is dangerous, not
/// just *that* it is.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TradeoffProfile {
    /// What the pattern provides when it works correctly.
    pub gain: String,
    /// What the pattern risks at the system level.
    pub risk: String,
}

/// A single hop in a failure propagation path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationHop {
    /// File or node display name.
    pub node: String,
    /// Edge type label for the hop leading to this node ("calls", "imports", etc.).
    /// Empty for the origin node.
    pub edge_label: String,
}

/// A full propagation path from a finding's origin to its Macro-Goal anchor.
///
/// Represents the World Model's answer to: "If this line breaks, what
/// does the system lose and how confident are we?"
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PropagationPath {
    /// Ordered hops: origin → intermediate files → anchor.
    pub hops: Vec<PropagationHop>,
    /// Aggregate risk in [0.0, 100.0].
    pub aggregate_risk: f64,
    /// The Macro-Goal: SLO name (if found) or entrypoint file path.
    pub macro_goal: Option<String>,
    /// True if the anchor is an SLO node, false if an inferred entrypoint.
    pub anchored_to_slo: bool,
}

impl PropagationPath {
    /// Returns just the file paths in order, for backward-compat display.
    pub fn file_paths(&self) -> Vec<String> {
        self.hops.iter().map(|h| h.node.clone()).collect()
    }
}

/// High-level SRE failure mode taxonomy.
///
/// Each variant maps to a glossary entry and represents a class of systemic failure
/// that a single linting rule cannot diagnose on its own — it requires cross-file
/// graph context to determine severity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FailureMode {
    /// SLO-001 — missing timeout on a remote call
    SlowDeath,
    /// SLO-002 — retry loop without backoff/jitter
    RetryStorm,
    /// SLO-003 — unbounded blocking / deadlock potential
    ZombieProcess,
    /// SLO-004 — cache miss → DB stampede with no singleflight
    ThunderingHerd,
    /// SLO-005 — hardcoded IP or expired credential
    Blackhole,
    /// SLO-006 — missing circuit breaker, failures cascade across call chains
    Cascade,
}

impl FailureMode {
    pub fn glossary_id(&self) -> &'static str {
        match self {
            FailureMode::SlowDeath => "SLO-001",
            FailureMode::RetryStorm => "SLO-002",
            FailureMode::ZombieProcess => "SLO-003",
            FailureMode::ThunderingHerd => "SLO-004",
            FailureMode::Blackhole => "SLO-005",
            FailureMode::Cascade => "SLO-006",
        }
    }

    pub fn aka(&self) -> &'static str {
        match self {
            FailureMode::SlowDeath => "The Slow Death",
            FailureMode::RetryStorm => "The Retry Storm",
            FailureMode::ZombieProcess => "The Zombie Process",
            FailureMode::ThunderingHerd => "The Thundering Herd",
            FailureMode::Blackhole => "The Blackhole",
            FailureMode::Cascade => "The Cascade",
        }
    }
}

/// Graph-derived blast radius for a symptom finding.
///
/// Answers: "how far does this bad line reach into the system?"
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlastRadius {
    /// Files transitively upstream of the symptom (importers / callers).
    pub affected_files: Vec<String>,
    /// Subset of affected_files that are entrypoints (0 incoming imports).
    pub entrypoint_files: Vec<String>,
    /// True if the symptom can be reached from at least one entrypoint.
    pub reaches_entrypoint: bool,
}

/// A system-level hazard: one rule finding enriched with SRE context.
///
/// `SystemHazard` is NOT a replacement for `Finding`. It wraps one via `finding_id`
/// and adds the cross-cutting, graph-derived layer that a single rule cannot compute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemHazard {
    /// The SRE failure mode this hazard represents (e.g. "SLO-001").
    pub glossary_id: String,
    /// Punchy alias used in output (e.g. "The Slow Death").
    pub aka: String,
    /// Failure mode enum for programmatic matching.
    pub failure_mode: FailureMode,

    /// Foreign key to the root `Finding.id` that triggered this hazard.
    pub finding_id: String,
    /// Duplicated for display convenience — avoids re-joining every time.
    pub file_path: String,
    pub line: Option<u32>,

    /// Graph-derived blast radius.
    pub blast_radius: BlastRadius,

    /// Effective severity, potentially upgraded from the root finding's severity
    /// based on blast radius (e.g. a Medium finding becomes Critical if it
    /// reaches an entrypoint through a 5-hop chain).
    pub effective_severity: Severity,

    /// Human-readable one-liner explaining the systemic risk.
    /// e.g. "Imported by checkout_api.py (entry point). A latency spike here
    /// will stall all workers on the shared pool."
    pub one_line_impact: String,

    /// Ordered list of files from symptom → nearest entrypoint.
    /// e.g. ["stripe.py", "payment_service.py", "checkout_api.py"]
    ///
    /// Deprecated in favour of `propagation` — kept for display compatibility.
    pub destruction_path: Vec<String>,

    /// World Model propagation path: risk-weighted chain from origin to Macro-Goal.
    ///
    /// Supersedes `destruction_path` with richer data: aggregate risk score,
    /// edge type labels, and SLO anchor information.
    #[serde(default)]
    pub propagation: PropagationPath,

    /// Gain/risk tradeoff profile — surfaces the system design tradeoff
    /// behind this failure mode.
    #[serde(default)]
    pub tradeoff: TradeoffProfile,

    /// Analysis dimension this hazard belongs to.
    pub dimension: Dimension,
}
