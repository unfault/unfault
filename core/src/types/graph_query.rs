//! Types returned by graph traversal queries.
//!
//! These are the result types for the graph traversal functions in
//! [`crate::graph::traversal`], used for impact analysis, flow tracing,
//! centrality ranking, and workspace overview.

use serde::{Deserialize, Serialize};

/// Context assembled from graph analysis.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GraphContext {
    /// Files affected by the target
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_files: Vec<String>,
    /// Dependencies of the target
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    /// Files that use a specific library
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub library_users: Vec<String>,
    /// Centrality-ranked files
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub central_files: Vec<(String, f64)>,
}

/// A node in a call flow path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowPathNode {
    pub name: String,
    pub file_path: Option<String>,
    pub node_type: String,
    pub depth: usize,
}

/// Context from flow/trace analysis.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlowContext {
    /// Entry points for the flow
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roots: Vec<FlowPathNode>,
    /// Call paths from roots
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<Vec<FlowPathNode>>,
}

/// Context from enumeration queries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnumerateContext {
    /// What was counted/listed
    pub entity_type: String,
    /// Total count
    pub count: usize,
    /// Listed items (may be truncated)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
}

/// A single caller in an inbound call chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallerInfo {
    /// Display name of the calling function.
    pub name: String,
    /// File where the caller is defined.
    pub file: Option<String>,
    /// Number of hops from the target function (1 = direct caller).
    pub depth: usize,
}

/// HTTP route information attached to a callers context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteInfo {
    /// HTTP method (GET, POST, …).
    pub method: String,
    /// URL path (e.g. /api/orders/{id}).
    pub path: String,
}

/// Result of a reverse-call-chain query (who calls this function?).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CallersContext {
    /// The function that was queried.
    pub target: String,
    /// File where the target function is defined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_file: Option<String>,
    /// All callers found, sorted by depth ascending.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<CallerInfo>,
    /// HTTP routes that anchor the call chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RouteInfo>,
}

/// A function suggested as a candidate when the queried name is not found or has no edges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSuggestion {
    /// Function name.
    pub name: String,
    /// File containing the function.
    pub file: String,
    /// HTTP method if this function is a route handler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// HTTP path if this function is a route handler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_path: Option<String>,
    /// Why this was suggested ("fuzzy_match", "same_file_handler", "most_called").
    pub reason: String,
}

/// Workspace structural information.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkspaceContext {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub languages: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub frameworks: Vec<String>,
    pub file_count: usize,
    pub function_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entrypoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub central_files: Vec<String>,
}
