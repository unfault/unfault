//! Types returned by graph traversal queries.
//!
//! These are the result types for the graph traversal functions in
//! [`crate::graph::traversal`], used for impact analysis, flow tracing,
//! centrality ranking, and workspace overview.

use serde::{Deserialize, Serialize};

use crate::graph::DecoratorSemantic;

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

/// Role of a caller in the call chain.
///
/// Distinguishes business-logic callers from structural wiring code (blueprint
/// registration, app factory setup, router inclusion) that appears in the graph
/// purely because of framework boilerplate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerKind {
    /// Regular business-logic caller.
    BusinessLogic,
    /// Flask/FastAPI blueprint or router registration (`register_blueprint`,
    /// `include_router`, `app.include_router`).
    BlueprintWiring,
    /// Application factory / `create_app` / `create_server` setup code.
    AppFactory,
    /// Top-level app entry-point file (`__init__.py`, `app.py`, `main.py`)
    /// that imports this module but does not call the function directly.
    AppEntrypoint,
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
    /// Structural role of this caller.
    #[serde(skip_serializing_if = "is_business_logic")]
    pub kind: CallerKind,
    /// True if the caller contains ORM write operations (INSERT/UPDATE/DELETE).
    /// Useful for identifying the write path without a separate grep.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_writer: bool,
}

fn is_business_logic(k: &CallerKind) -> bool {
    *k == CallerKind::BusinessLogic
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
    /// 1-based line number of the target function definition, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_line: Option<u32>,
    /// 1-based column number of the target function definition, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_column: Option<u32>,
    /// All callers found, sorted by depth ascending.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<CallerInfo>,
    /// HTTP routes that anchor the call chain.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<RouteInfo>,
    /// Other functions defined in the same file as the target — useful for
    /// understanding sibling patterns without an extra Read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub siblings: Vec<SiblingInfo>,
    /// Known analysis caveats, e.g. blind spots the static graph cannot trace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caveats: Vec<String>,
}

/// A function in the same file as the queried target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiblingInfo {
    /// Function name.
    pub name: String,
    /// HTTP method if this sibling is a route handler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// HTTP path if this sibling is a route handler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_path: Option<String>,
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

/// Result of a point-to-point path query (is there a call path from A to B?).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PathContext {
    /// The starting function that was queried.
    pub from: String,
    /// The target function that was queried.
    pub to: String,
    /// Whether a path was found.
    pub found: bool,
    /// The shortest call path from `from` to `to`, as a sequence of hop nodes.
    /// Empty when `found` is false.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path: Vec<FlowPathNode>,
    /// HTTP routes that can trigger the start of this path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entry_routes: Vec<RouteInfo>,
}

/// A detected HTTP route handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerInfo {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub file: String,
    pub is_async: bool,
    /// 1-based line number of the handler definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// 1-based column number of the handler definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    /// Semantic roles of the decorators attached to this handler.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decorators: Vec<DecoratorSemantic>,
    /// True if the handler contains at least one ORM write (INSERT/UPDATE/DELETE).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_writer: bool,
    /// Request body / query schema name from `@blp.arguments(SchemaX)` or `@use_args(SchemaX)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_schema: Option<String>,
    /// Response schema name from `@blp.response(200, SchemaY)` or `@marshal_with(SchemaY)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<String>,
}

/// Result of a route pattern query.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HandlersContext {
    /// The pattern that was searched.
    pub pattern: String,
    /// Matching route handlers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handlers: Vec<HandlerInfo>,
}

/// A route handler inside a subtree, as returned by `graph brief`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BriefRoute {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decorators: Vec<DecoratorSemantic>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_writer: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<String>,
}

/// A symbol exported from the subtree (imported by code outside).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedSymbol {
    /// Symbol name, e.g. `"process_order"` or `"OrderSchema"`.
    pub name: String,
    /// File inside the subtree that defines this symbol.
    pub defined_in: String,
    /// Files outside the subtree that import this symbol.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imported_by: Vec<String>,
}

/// A dependency imported into the subtree from outside.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingImport {
    /// The module or file being imported (external package name or internal file path).
    pub source: String,
    /// Specific symbols imported, if known (`from x import a, b`).
    /// Empty for whole-module imports (`import x`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbols: Vec<String>,
    /// Files inside the subtree that import from this source.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imported_by: Vec<String>,
}

/// A function inside the subtree that is only called from outside (or is an HTTP
/// handler / CLI entry point) — the de-facto public boundary regardless of layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPoint {
    pub name: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Why this was classified as an entry point.
    pub reason: EntryPointReason,
    /// HTTP method if this is a route handler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// HTTP path if this is a route handler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_path: Option<String>,
}

/// Reason a function was classified as an internal entry point.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryPointReason {
    /// HTTP route handler.
    HttpHandler,
    /// Called from outside the subtree but never called from inside.
    ExternalCallersOnly,
    /// No callers at all but exported (imported by outside code).
    ExportedUnused,
}

/// Size metrics for the queried subtree.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BriefSize {
    pub files: usize,
    pub functions: usize,
}

/// Result of a `graph brief <path>` query.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BriefContext {
    /// The subtree path that was queried.
    pub path: String,
    /// HTTP route handlers whose source file lives inside the subtree.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<BriefRoute>,
    /// Symbols defined inside the subtree imported by code outside it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outgoing_exports: Vec<ExportedSymbol>,
    /// Dependencies imported into the subtree from outside.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incoming_imports: Vec<IncomingImport>,
    /// Functions inside the subtree that are entry points from outside.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub internal_entry_points: Vec<EntryPoint>,
    /// File and function counts for the subtree.
    pub size: BriefSize,
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
