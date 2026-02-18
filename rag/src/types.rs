use serde::{Deserialize, Serialize};

/// Supported query routing intents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteIntent {
    /// Describe the workspace structure
    Overview,
    /// Trace a code flow (e.g., "how does auth work?")
    Flow,
    /// Who uses / calls X?
    Usage,
    /// What breaks if I change X?
    Impact,
    /// What does X depend on?
    Dependencies,
    /// Most central / critical files
    Centrality,
    /// List/count items (routes, functions, files)
    Enumerate,
    /// Semantic / general question answered via embeddings + LLM
    Semantic,
}

/// A RAG query with parsed context.
#[derive(Debug, Clone)]
pub struct RagQuery {
    /// Original user query text
    pub text: String,
    /// Detected intent
    pub intent: RouteIntent,
    /// Target token extracted from query (e.g., file path, function name)
    pub target: Option<String>,
    /// Detected programming languages in query
    pub languages: Vec<String>,
    /// Detected frameworks in query
    pub frameworks: Vec<String>,
}

/// A finding record stored in the vector database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    /// Unique finding ID
    pub id: String,
    /// Workspace identifier
    pub workspace_id: String,
    /// File path where the finding was detected
    pub file_path: String,
    /// Rule that produced this finding
    pub rule_id: String,
    /// Finding title
    pub title: String,
    /// Finding description
    pub description: String,
    /// Analysis dimension (e.g., "stability", "performance")
    pub dimension: String,
    /// Severity level
    pub severity: String,
    /// Line number (optional)
    pub line: Option<u32>,
    /// Content hash for deduplication
    pub content_hash: String,
}

/// A finding with its similarity score from vector search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoredFinding {
    pub finding: FindingRecord,
    pub similarity: f32,
}

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

/// The complete RAG response.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RagResponse {
    /// Resolved intent
    pub intent: String,
    /// Human-readable summary of what was found
    pub context_summary: String,
    /// Similar findings from vector search
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<ScoredFinding>,
    /// Graph-based context (impact, dependencies, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph_context: Option<GraphContext>,
    /// Flow/trace context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_context: Option<FlowContext>,
    /// Enumeration results
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enumerate_context: Option<EnumerateContext>,
    /// Workspace overview
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_context: Option<WorkspaceContext>,
}
