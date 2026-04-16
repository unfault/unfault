//! Graph and analysis types used by the CLI output layer.
//!
//! These types represent the local analysis results in a format that the CLI
//! commands and LSP can consume for output formatting.

use serde::{Deserialize, Serialize};
use tower_lsp::lsp_types::Range;

// =============================================================================
// Analysis Response Types
// =============================================================================

/// Response from local IR analysis.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IrAnalyzeResponse {
    /// Findings from rule evaluation
    pub findings: Vec<IrFinding>,
    /// System-level hazards from the SRE synthesis pass
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_hazards: Vec<IrSystemHazard>,
    /// Number of files analyzed
    pub file_count: i32,
    /// Analysis time in milliseconds
    pub elapsed_ms: i64,
    /// Graph statistics (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_stats: Option<IrGraphStats>,
}

/// CLI display-layer representation of a SystemHazard.
///
/// All fields are `String` for simple serialization and rendering.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IrSystemHazard {
    /// e.g. "SLO-001"
    pub glossary_id: String,
    /// e.g. "The Slow Death"
    pub aka: String,
    /// File where the root symptom was found
    pub file_path: String,
    /// Line number of the root symptom (0 if unknown)
    pub line: u32,
    /// Effective severity after blast-radius upgrade (e.g. "Critical")
    pub effective_severity: String,
    /// One-sentence systemic impact description
    pub one_line_impact: String,
    /// Chain from symptom file to nearest entrypoint
    pub destruction_path: Vec<String>,
    /// ID of the root Finding this hazard enriches
    pub finding_id: String,

    // ── World Model fields ────────────────────────────────────────────────
    /// World Model aggregate risk score [0.0–100.0].
    /// Represents propagation probability as a percentage.
    #[serde(default)]
    pub aggregate_risk: f64,

    /// Macro-Goal anchor: SLO name (if SLO-enriched) or entrypoint file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macro_goal: Option<String>,

    /// True if macro_goal is an SLO, false if an inferred entrypoint.
    #[serde(default)]
    pub anchored_to_slo: bool,

    // ── Tradeoff fields ───────────────────────────────────────────────────
    /// What the pattern provides when it works correctly.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tradeoff_gain: String,

    /// What the pattern risks at the system level.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tradeoff_risk: String,

    /// Human-readable title of the root finding (e.g. "Missing request timeout").
    /// Used as context line before the tradeoff block.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub finding_title: String,
}

/// A single finding from IR analysis.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IrFinding {
    /// Rule that produced this finding
    pub rule_id: String,
    /// Finding title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level (Critical, High, Medium, Low)
    pub severity: String,
    /// Analysis dimension (Stability, Performance, etc.)
    pub dimension: String,
    /// File path where the finding was detected
    pub file_path: String,
    /// Line number (1-based)
    pub line: u32,
    /// Column number (1-based)
    pub column: u32,
    /// End line (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    /// End column (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
    /// Human-readable message
    pub message: String,
    /// Serialized patch JSON (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_json: Option<String>,
    /// Human-readable fix preview (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_preview: Option<String>,
    /// Unified diff patch (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<String>,
    /// Byte start offset (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_start: Option<usize>,
    /// Byte end offset (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_end: Option<usize>,
}

/// Graph statistics from analysis.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IrGraphStats {
    pub file_count: i32,
    pub function_count: i32,
    pub class_count: i32,
    pub external_module_count: i32,
    pub import_edge_count: i32,
    pub contains_edge_count: i32,
    pub uses_library_edge_count: i32,
    pub total_nodes: i32,
    pub total_edges: i32,
}

// =============================================================================
// Centrality Types (used by LSP)
// =============================================================================

/// File centrality metrics.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileCentrality {
    /// File path
    pub path: String,
    /// Number of files that import this file
    pub in_degree: i32,
    /// Number of files this file imports
    pub out_degree: i32,
    /// Sum of in and out degrees
    pub total_degree: i32,
    /// Number of external libraries used
    pub library_usage: i32,
    /// Weighted importance score
    pub importance_score: i32,
}

// =============================================================================
// Function Info (used by LSP hover)
// =============================================================================

/// Information about a function, used by LSP for hover/code actions.
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    /// Function name (may be qualified)
    pub name: String,
    /// Source range in the file
    pub range: Range,
}
