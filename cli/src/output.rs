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
    /// Number of files analyzed
    pub file_count: i32,
    /// Analysis time in milliseconds
    pub elapsed_ms: i64,
    /// Graph statistics (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_stats: Option<IrGraphStats>,
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
