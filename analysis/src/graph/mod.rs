//! CodeGraph built from per-file semantics.
//!
//! This module provides a comprehensive code graph that captures:
//! - File nodes with path information
//! - Function/method nodes
//! - Class/type nodes
//! - External module/library nodes
//! - Framework-specific nodes (FastAPI apps, routes, middlewares)
//!
//! Edges capture relationships:
//! - Contains: File contains functions/classes
//! - Imports: File imports another file
//! - ImportsFrom: File imports specific items from module
//! - Calls: Function calls another function
//! - UsesLibrary: File/function uses external library
//! - Framework-specific edges (FastAPI routes, middlewares)

pub mod traversal;

use std::collections::HashMap;
use std::sync::Arc;

use petgraph::Direction;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

// Re-export NodeIndex so downstream crates don't need a direct petgraph dependency
pub use petgraph::graph::NodeIndex as GraphNodeIndex;

use crate::parse::ast::FileId;
use crate::semantics::SourceSemantics;
use crate::semantics::common::CommonSemantics;
use crate::semantics::python::fastapi::FastApiFileSummary;
use crate::semantics::python::model::PyFileSemantics;
use crate::types::context::Language;
use unfault_core::semantics::python::flask::FlaskFileSummary;

// Re-export graph node/edge types from unfault-core — the types are identical.
pub use unfault_core::graph::{GraphEdgeKind, GraphNode, ModuleCategory, SloProvider};

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeGraph {
    pub graph: DiGraph<GraphNode, GraphEdgeKind>,
    /// Quick lookup: file_id -> node index for the file node.
    #[serde(skip)]
    pub file_nodes: HashMap<FileId, NodeIndex>,
    /// Quick lookup: file path -> node index for the file node.
    #[serde(skip)]
    pub path_to_file: HashMap<String, NodeIndex>,
    /// Quick lookup: path suffix -> node index (e.g. "auth/middleware.py" -> node).
    /// Enables O(1) suffix matching for import resolution.
    #[serde(skip)]
    pub suffix_to_file: HashMap<String, NodeIndex>,
    /// Quick lookup: module-style dotted path -> node index
    /// (e.g. "auth.middleware" -> node for "auth/middleware.py").
    #[serde(skip)]
    pub module_to_file: HashMap<String, NodeIndex>,
    /// Quick lookup: external module name -> node index
    #[serde(skip)]
    pub external_modules: HashMap<String, NodeIndex>,
    /// Quick lookup: (file_id, function_name) -> node index
    #[serde(skip)]
    pub function_nodes: HashMap<(FileId, String), NodeIndex>,
    /// Quick lookup: (file_id, class_name) -> node index
    #[serde(skip)]
    pub class_nodes: HashMap<(FileId, String), NodeIndex>,
}

impl CodeGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            file_nodes: HashMap::new(),
            path_to_file: HashMap::new(),
            suffix_to_file: HashMap::new(),
            module_to_file: HashMap::new(),
            external_modules: HashMap::new(),
            function_nodes: HashMap::new(),
            class_nodes: HashMap::new(),
        }
    }

    /// Get or create an external module node
    pub fn get_or_create_external_module(
        &mut self,
        name: &str,
        category: ModuleCategory,
    ) -> NodeIndex {
        if let Some(&idx) = self.external_modules.get(name) {
            return idx;
        }
        let idx = self.graph.add_node(GraphNode::ExternalModule {
            name: name.to_string(),
            category,
        });
        self.external_modules.insert(name.to_string(), idx);
        idx
    }

    /// Find a file node by path. Supports exact paths, suffix paths, and
    /// module-style dotted paths (e.g. "auth.middleware" → "auth/middleware.py").
    /// All lookups are O(1) via pre-built indexes.
    pub fn find_file_by_path(&self, path: &str) -> Option<NodeIndex> {
        // 1. Exact match
        if let Some(&idx) = self.path_to_file.get(path) {
            return Some(idx);
        }
        // 2. Module-path lookup (e.g. "auth.middleware")
        if let Some(&idx) = self.module_to_file.get(path) {
            return Some(idx);
        }
        // 3. Suffix match (e.g. "middleware.py")
        if let Some(&idx) = self.suffix_to_file.get(path) {
            return Some(idx);
        }
        // 4. Convert dotted module path to file path and try suffix/module indexes
        if path.contains('.') {
            let file_path = path.replace('.', "/");
            for ext in &[".py", ".ts", ".tsx", ".js", ".go", ".rs"] {
                let full = format!("{}{}", file_path, ext);
                if let Some(&idx) = self.suffix_to_file.get(&full) {
                    return Some(idx);
                }
            }
            let init = format!("{}/__init__.py", file_path);
            if let Some(&idx) = self.suffix_to_file.get(&init) {
                return Some(idx);
            }
        }
        None
    }

    /// Add a file path to the suffix and module lookup indexes.
    fn add_path_to_indexes(
        path: &str,
        node_idx: NodeIndex,
        suffix_to_file: &mut HashMap<String, NodeIndex>,
        module_to_file: &mut HashMap<String, NodeIndex>,
    ) {
        // Build suffix entries: "src/auth/middleware.py" → ["middleware.py", "auth/middleware.py", ...]
        let parts: Vec<&str> = path.split('/').collect();
        for i in 0..parts.len() {
            let suffix = parts[i..].join("/");
            suffix_to_file.entry(suffix).or_insert(node_idx);
        }

        // Build module-style entries: "src/auth/middleware.py" → "src.auth.middleware", "auth.middleware", ...
        if let Some(without_ext) = path
            .strip_suffix(".py")
            .or_else(|| path.strip_suffix(".ts"))
            .or_else(|| path.strip_suffix(".tsx"))
            .or_else(|| path.strip_suffix(".js"))
            .or_else(|| path.strip_suffix(".go"))
            .or_else(|| path.strip_suffix(".rs"))
        {
            let module_path = without_ext.replace('/', ".");
            module_to_file
                .entry(module_path.clone())
                .or_insert(node_idx);
            let mod_parts: Vec<&str> = module_path.split('.').collect();
            for i in 0..mod_parts.len() {
                let partial = mod_parts[i..].join(".");
                module_to_file.entry(partial).or_insert(node_idx);
            }
        }

        // Special case: "src/auth/__init__.py" → "src.auth", "auth"
        if path.ends_with("__init__.py") {
            if let Some(dir_path) = path.strip_suffix("/__init__.py") {
                let module_path = dir_path.replace('/', ".");
                module_to_file.entry(module_path).or_insert(node_idx);
            }
        }
    }

    /// Get all files that directly import a given file
    pub fn get_importers(&self, file_id: FileId) -> Vec<FileId> {
        let Some(&target_idx) = self.file_nodes.get(&file_id) else {
            return vec![];
        };

        self.graph
            .edges_directed(target_idx, Direction::Incoming)
            .filter(|e| {
                matches!(
                    e.weight(),
                    GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. }
                )
            })
            .filter_map(|e| {
                let source_idx = e.source();
                if let GraphNode::File { file_id, .. } = &self.graph[source_idx] {
                    Some(*file_id)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all files that a given file directly imports
    pub fn get_imports(&self, file_id: FileId) -> Vec<FileId> {
        let Some(&source_idx) = self.file_nodes.get(&file_id) else {
            return vec![];
        };

        self.graph
            .edges_directed(source_idx, Direction::Outgoing)
            .filter(|e| {
                matches!(
                    e.weight(),
                    GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. }
                )
            })
            .filter_map(|e| {
                let target_idx = e.target();
                if let GraphNode::File { file_id, .. } = &self.graph[target_idx] {
                    Some(*file_id)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all files that transitively import a given file (up to max_depth hops)
    pub fn get_transitive_importers(
        &self,
        file_id: FileId,
        max_depth: usize,
    ) -> Vec<(FileId, usize)> {
        let Some(&start_idx) = self.file_nodes.get(&file_id) else {
            return vec![];
        };

        let mut result = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut queue = std::collections::VecDeque::new();

        visited.insert(start_idx);
        queue.push_back((start_idx, 0usize));

        while let Some((current_idx, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            for edge in self.graph.edges_directed(current_idx, Direction::Incoming) {
                if !matches!(
                    edge.weight(),
                    GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. }
                ) {
                    continue;
                }

                let importer_idx = edge.source();
                if visited.contains(&importer_idx) {
                    continue;
                }

                visited.insert(importer_idx);

                if let GraphNode::File { file_id, .. } = &self.graph[importer_idx] {
                    result.push((*file_id, depth + 1));
                    queue.push_back((importer_idx, depth + 1));
                }
            }
        }

        result
    }

    /// Get external libraries used by a file
    pub fn get_external_dependencies(&self, file_id: FileId) -> Vec<String> {
        let Some(&file_idx) = self.file_nodes.get(&file_id) else {
            return vec![];
        };

        self.graph
            .edges_directed(file_idx, Direction::Outgoing)
            .filter(|e| matches!(e.weight(), GraphEdgeKind::UsesLibrary))
            .filter_map(|e| {
                let target_idx = e.target();
                if let GraphNode::ExternalModule { name, .. } = &self.graph[target_idx] {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get all files that use a specific external library
    pub fn get_files_using_library(&self, library_name: &str) -> Vec<FileId> {
        let Some(&lib_idx) = self.external_modules.get(library_name) else {
            return vec![];
        };

        self.graph
            .edges_directed(lib_idx, Direction::Incoming)
            .filter(|e| matches!(e.weight(), GraphEdgeKind::UsesLibrary))
            .filter_map(|e| {
                let source_idx = e.source();
                if let GraphNode::File { file_id, .. } = &self.graph[source_idx] {
                    Some(*file_id)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn stats(&self) -> GraphStats {
        let mut file_count = 0;
        let mut function_count = 0;
        let mut class_count = 0;
        let mut external_module_count = 0;

        for node in self.graph.node_weights() {
            match node {
                GraphNode::File { .. } => file_count += 1,
                GraphNode::Function { .. } => function_count += 1,
                GraphNode::Class { .. } => class_count += 1,
                GraphNode::ExternalModule { .. } => external_module_count += 1,
                _ => {}
            }
        }

        let mut import_edge_count = 0;
        let mut contains_edge_count = 0;
        let mut uses_library_edge_count = 0;
        let mut calls_edge_count = 0;

        for edge in self.graph.edge_weights() {
            match edge {
                GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. } => {
                    import_edge_count += 1
                }
                GraphEdgeKind::Contains => contains_edge_count += 1,
                GraphEdgeKind::UsesLibrary => uses_library_edge_count += 1,
                GraphEdgeKind::Calls => calls_edge_count += 1,
                _ => {}
            }
        }

        GraphStats {
            file_count,
            function_count,
            class_count,
            external_module_count,
            import_edge_count,
            contains_edge_count,
            uses_library_edge_count,
            calls_edge_count,
            total_nodes: self.graph.node_count(),
            total_edges: self.graph.edge_count(),
        }
    }

    // ── SLO integration ────────────────────────────────────────────────────

    /// Add an SLO node to the graph and create `MonitoredBy` edges from the
    /// provided route handler node indices to the SLO.
    ///
    /// Returns the `NodeIndex` of the newly created SLO node.
    #[allow(clippy::too_many_arguments)]
    pub fn add_slo(
        &mut self,
        id: String,
        name: String,
        provider: SloProvider,
        path_pattern: String,
        http_method: Option<String>,
        target_percent: f64,
        current_percent: Option<f64>,
        error_budget_remaining: Option<f64>,
        timeframe: String,
        dashboard_url: Option<String>,
        handler_indices: Vec<NodeIndex>,
    ) -> NodeIndex {
        let slo_idx = self.graph.add_node(GraphNode::Slo {
            id,
            name,
            provider,
            path_pattern,
            http_method,
            target_percent,
            current_percent,
            error_budget_remaining,
            timeframe,
            dashboard_url,
        });

        // Create MonitoredBy edges: handler → SLO
        for handler_idx in handler_indices {
            self.graph
                .add_edge(handler_idx, slo_idx, GraphEdgeKind::MonitoredBy);
        }

        slo_idx
    }

    /// Return all HTTP route handler nodes in the graph.
    ///
    /// A "route handler" is a `Function` node where `is_handler == true`
    /// and `http_path` is set. Returns `(NodeIndex, http_path, http_method)`.
    pub fn get_http_route_handlers(&self) -> Vec<(NodeIndex, &str, Option<&str>)> {
        self.graph
            .node_indices()
            .filter_map(|idx| {
                if let GraphNode::Function {
                    is_handler: true,
                    http_path: Some(ref path),
                    ref http_method,
                    ..
                } = self.graph[idx]
                {
                    Some((idx, path.as_str(), http_method.as_deref()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get route information (http_method, http_path, function_name) for a node.
    ///
    /// Returns `None` if the node is not a Function handler.
    pub fn get_route_info(&self, idx: NodeIndex) -> Option<(Option<String>, String, String)> {
        match &self.graph[idx] {
            GraphNode::Function {
                name,
                http_method,
                http_path: Some(path),
                ..
            } => Some((http_method.clone(), path.clone(), name.clone())),
            _ => None,
        }
    }

    /// Return all SLO nodes in the graph.
    pub fn get_slos(&self) -> Vec<NodeIndex> {
        self.graph
            .node_indices()
            .filter(|&idx| matches!(self.graph[idx], GraphNode::Slo { .. }))
            .collect()
    }

    /// For a given handler NodeIndex, return SLO nodes it is monitored by.
    pub fn get_slos_for_handler(&self, handler_idx: NodeIndex) -> Vec<NodeIndex> {
        use petgraph::visit::EdgeRef as _;
        self.graph
            .edges_directed(handler_idx, Direction::Outgoing)
            .filter(|e| matches!(e.weight(), GraphEdgeKind::MonitoredBy))
            .map(|e| e.target())
            .collect()
    }

    /// Rebuild all lookup indexes from the graph.
    ///
    /// This must be called after deserializing a CodeGraph to restore
    /// the quick-lookup HashMaps that are skipped during serialization.
    pub fn rebuild_indexes(&mut self) {
        self.file_nodes.clear();
        self.path_to_file.clear();
        self.suffix_to_file.clear();
        self.module_to_file.clear();
        self.external_modules.clear();
        self.function_nodes.clear();
        self.class_nodes.clear();

        for node_idx in self.graph.node_indices() {
            match &self.graph[node_idx] {
                GraphNode::File { file_id, path, .. } => {
                    self.file_nodes.insert(*file_id, node_idx);
                    self.path_to_file.insert(path.clone(), node_idx);
                    Self::add_path_to_indexes(
                        path,
                        node_idx,
                        &mut self.suffix_to_file,
                        &mut self.module_to_file,
                    );
                }
                GraphNode::Function { file_id, name, .. } => {
                    self.function_nodes
                        .insert((*file_id, name.clone()), node_idx);
                }
                GraphNode::Class { file_id, name, .. } => {
                    self.class_nodes.insert((*file_id, name.clone()), node_idx);
                }
                GraphNode::ExternalModule { name, .. } => {
                    self.external_modules.insert(name.clone(), node_idx);
                }
                _ => {}
            }
        }
    }
}

impl Default for CodeGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a core `CodeGraph` into an analysis `CodeGraph` with zero copies.
///
/// Both types wrap the same petgraph `DiGraph<GraphNode, GraphEdgeKind>` —
/// `GraphNode` and `GraphEdgeKind` are now re-exported from core, so they are
/// literally the same types. The conversion moves the graph and rebuilds the
/// O(1) lookup indexes, replacing the previous JSON/msgpack round-trip.
impl From<unfault_core::graph::CodeGraph> for CodeGraph {
    fn from(core: unfault_core::graph::CodeGraph) -> Self {
        let mut cg = CodeGraph {
            graph: core.graph,
            file_nodes: HashMap::new(),
            path_to_file: HashMap::new(),
            suffix_to_file: HashMap::new(),
            module_to_file: HashMap::new(),
            external_modules: HashMap::new(),
            function_nodes: HashMap::new(),
            class_nodes: HashMap::new(),
        };
        cg.rebuild_indexes();
        cg
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphStats {
    pub file_count: usize,
    pub function_count: usize,
    pub class_count: usize,
    pub external_module_count: usize,
    pub import_edge_count: usize,
    pub contains_edge_count: usize,
    pub uses_library_edge_count: usize,
    pub calls_edge_count: usize,
    pub total_nodes: usize,
    pub total_edges: usize,
}

pub fn build_code_graph(sem_entries: &[(FileId, Arc<SourceSemantics>)]) -> CodeGraph {
    let mut cg = CodeGraph::new();

    // First pass: create file nodes and collect path mappings
    for (file_id, sem) in sem_entries {
        let (path, language) = match sem.as_ref() {
            SourceSemantics::Python(py) => (py.path.clone(), Language::Python),
            SourceSemantics::Go(go) => (go.path.clone(), Language::Go),
            SourceSemantics::Rust(rs) => (rs.path.clone(), Language::Rust),
            SourceSemantics::Typescript(ts) => (ts.path.clone(), Language::Typescript),
        };

        let node_index = cg.graph.add_node(GraphNode::File {
            file_id: *file_id,
            path: path.clone(),
            language,
        });

        cg.file_nodes.insert(*file_id, node_index);
        CodeGraph::add_path_to_indexes(
            &path,
            node_index,
            &mut cg.suffix_to_file,
            &mut cg.module_to_file,
        );
        cg.path_to_file.insert(path, node_index);
    }

    // Second pass: add functions, classes, imports, and framework-specific nodes
    for (file_id, sem) in sem_entries {
        let file_node = match cg.file_nodes.get(file_id) {
            Some(idx) => *idx,
            None => continue,
        };

        // Add imports (works for all languages via CommonSemantics)
        add_import_edges(&mut cg, file_node, *file_id, sem);

        // Add functions (works for all languages via CommonSemantics)
        add_function_nodes(&mut cg, file_node, *file_id, sem);

        // Language-specific additions
        match sem.as_ref() {
            SourceSemantics::Python(py) => {
                if let Some(fastapi) = &py.fastapi {
                    add_fastapi_nodes(&mut cg, file_node, *file_id, py, fastapi);
                }
                if let Some(flask) = &py.flask {
                    add_flask_nodes(&mut cg, file_node, *file_id, flask);
                }
            }
            SourceSemantics::Go(_go) => {
                // TODO: Add Go framework-specific nodes (Gin, Echo, Chi, etc.)
            }
            SourceSemantics::Rust(_rs) => {
                // TODO: Add Rust framework-specific nodes (Actix, Axum, Rocket, etc.)
            }
            SourceSemantics::Typescript(_ts) => {
                // TODO: Add TypeScript framework-specific nodes (Express, NestJS, etc.)
            }
        }
    }

    // Third pass: add Calls edges using per-function call sites.
    //
    // Keyed on func.name (simple name) to match the function_nodes HashMap.
    // Two-stage resolution mirrors the core graph builder:
    //   1. Intra-file: callee lives in the same file
    //   2. Cross-file: callee is reached through an import in the calling file
    //
    // Build import lookup first.
    let imports_by_file: std::collections::HashMap<
        FileId,
        (String, Vec<crate::semantics::Import>),
    > = sem_entries
        .iter()
        .map(|(file_id, sem)| {
            let (path, imports) = match sem.as_ref() {
                SourceSemantics::Python(py) => (py.path.clone(), py.imports()),
                SourceSemantics::Go(go) => (go.path.clone(), go.imports()),
                SourceSemantics::Rust(rs) => (rs.path.clone(), rs.imports()),
                SourceSemantics::Typescript(ts) => (ts.path.clone(), ts.imports()),
            };
            (*file_id, (path, imports))
        })
        .collect();

    for (file_id, sem) in sem_entries {
        let empty_path = String::new();
        let empty_imports: Vec<crate::semantics::Import> = Vec::new();
        let (file_path, imports) = imports_by_file
            .get(file_id)
            .map(|(p, i)| (p.as_str(), i.as_slice()))
            .unwrap_or((empty_path.as_str(), empty_imports.as_slice()));

        for func_call in sem.function_calls() {
            // Use caller_function (simple name) — function_nodes is keyed by simple name,
            // not the qualified name which includes class prefixes like "MyClass.method".
            let caller_name = if func_call.caller_function.is_empty() {
                // Fall back: take the last segment of the qualified name.
                func_call
                    .caller_qualified_name
                    .split('.')
                    .last()
                    .unwrap_or("")
                    .to_string()
            } else {
                func_call.caller_function.clone()
            };
            if caller_name.is_empty() {
                continue;
            }

            let caller_key = (*file_id, caller_name);
            let Some(&caller_node) = cg.function_nodes.get(&caller_key) else {
                continue;
            };

            // Callee simple name: last segment of callee_parts.
            let callee_name = match func_call.callee_parts.last() {
                Some(n) => n.clone(),
                None => continue,
            };

            // Stage 1: intra-file resolution
            let callee_key = (*file_id, callee_name.clone());
            if let Some(&callee_node) = cg.function_nodes.get(&callee_key) {
                cg.graph
                    .add_edge(caller_node, callee_node, GraphEdgeKind::Calls);
                continue;
            }

            // Stage 2: cross-file resolution through imports
            if let Some(callee_node) = resolve_cross_file_call(
                &cg,
                &callee_name,
                &func_call.callee_expr,
                imports,
                file_path,
            ) {
                cg.graph
                    .add_edge(caller_node, callee_node, GraphEdgeKind::Calls);
            }
        }
    }

    cg
}

/// Add import edges from a file to other files or external modules
fn add_import_edges(
    cg: &mut CodeGraph,
    file_node: NodeIndex,
    _file_id: FileId,
    sem: &Arc<SourceSemantics>,
) {
    // Get imports via CommonSemantics trait
    let imports = match sem.as_ref() {
        SourceSemantics::Python(py) => py.imports(),
        SourceSemantics::Go(go) => go.imports(),
        SourceSemantics::Rust(rs) => rs.imports(),
        SourceSemantics::Typescript(ts) => ts.imports(),
    };

    for import in imports {
        // First, try to find the imported module as a file in our graph
        // This handles both:
        // - Explicit local/relative imports (import.is_local() == true)
        // - Absolute imports to local packages (e.g., "from myapp.task import Task")
        //
        // We try multiple path patterns to find the file:
        // 1. Exact module path (e.g., "reliably_app.task" -> "reliably_app/task.py")
        // 2. Module path as directory init (e.g., "reliably_app" -> "reliably_app/__init__.py")
        let module_as_file = import.module_path.replace('.', "/");
        let possible_paths = [
            format!("{}.py", module_as_file),
            format!("{}/__init__.py", module_as_file),
            module_as_file.clone(),
        ];

        let mut found_local_file = false;
        for path in &possible_paths {
            if let Some(target_idx) = cg.find_file_by_path(path) {
                // Found as a local file - create import edge
                if import.items.is_empty() {
                    cg.graph
                        .add_edge(file_node, target_idx, GraphEdgeKind::Imports);
                } else {
                    let items: Vec<String> = import.items.iter().map(|i| i.name.clone()).collect();
                    cg.graph
                        .add_edge(file_node, target_idx, GraphEdgeKind::ImportsFrom { items });
                }
                found_local_file = true;
                break;
            }
        }

        // If not found as a local file, treat as external library
        if !found_local_file {
            let category = categorize_module(&import.module_path);
            let package_name = import.package_name().to_string();
            let module_idx = cg.get_or_create_external_module(&package_name, category);
            cg.graph
                .add_edge(file_node, module_idx, GraphEdgeKind::UsesLibrary);
        }
    }
}

/// Add function nodes from a file
/// Resolve a cross-file function call through imports.
///
/// Mirrors the core graph builder's `resolve_call_through_imports` with the
/// three strategies:
///   1. `from module import e`  then  `e()`
///   2. `import module`         then  `module.e()`
///   3. `from pkg import sub`   then  `sub.func()`  (submodule-as-item)
fn resolve_cross_file_call(
    cg: &CodeGraph,
    callee: &str,
    callee_expr: &str,
    imports: &[crate::semantics::Import],
    importing_file_path: &str,
) -> Option<NodeIndex> {
    // Strategy 1: direct import match — `from module import e` then `e()`
    for import in imports {
        if import.imports_item(callee) {
            if let Some(source_idx) = find_source_file(cg, &import.module_path, importing_file_path)
            {
                if let GraphNode::File { file_id, .. } = &cg.graph[source_idx] {
                    let key = (*file_id, callee.to_string());
                    if let Some(&node) = cg.function_nodes.get(&key) {
                        return Some(node);
                    }
                }
            }
        }
    }

    // Strategy 2 & 3: attribute call — `module.func()` or `sub.func()`
    if callee_expr.contains('.') {
        let parts: Vec<&str> = callee_expr.split('.').collect();
        if parts.len() >= 2 {
            let module_alias = parts[0];
            let func_name = parts[parts.len() - 1];

            // Strategy 2: `import module` / `import module as alias` then `module.func()`
            for import in imports {
                let matches = import.module_alias.as_deref() == Some(module_alias)
                    || import
                        .module_path
                        .split('.')
                        .last()
                        .map(|last| last == module_alias)
                        .unwrap_or(false);
                if matches {
                    if let Some(source_idx) =
                        find_source_file(cg, &import.module_path, importing_file_path)
                    {
                        if let GraphNode::File { file_id, .. } = &cg.graph[source_idx] {
                            let key = (*file_id, func_name.to_string());
                            if let Some(&node) = cg.function_nodes.get(&key) {
                                return Some(node);
                            }
                        }
                    }
                }
            }

            // Strategy 3: `from pkg import sub` then `sub.func()`
            for import in imports {
                if import.imports_item(module_alias) {
                    let submodule = format!("{}.{}", import.module_path, module_alias);
                    if let Some(source_idx) = find_source_file(cg, &submodule, importing_file_path)
                    {
                        if let GraphNode::File { file_id, .. } = &cg.graph[source_idx] {
                            let key = (*file_id, func_name.to_string());
                            if let Some(&node) = cg.function_nodes.get(&key) {
                                return Some(node);
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Find the graph node for the source file that provides `module_path`,
/// resolving relative imports using `importing_file_path` as context.
fn find_source_file(
    cg: &CodeGraph,
    module_path: &str,
    importing_file_path: &str,
) -> Option<NodeIndex> {
    let module_as_path = module_path.replace('.', "/");

    // Absolute import: try both `module/path.py` and `module/path/__init__.py`
    for &idx in cg.path_to_file.values() {
        if let GraphNode::File { path, .. } = &cg.graph[idx] {
            let normalized = path.replace('\\', "/");
            if normalized.ends_with(&format!("{}.py", module_as_path))
                || normalized.ends_with(&format!("{}/__init__.py", module_as_path))
            {
                return Some(idx);
            }
        }
    }

    // Relative import: resolve relative to the importing file's directory
    if module_path.starts_with('.') {
        let dots = module_path.chars().take_while(|&c| c == '.').count();
        let relative_module = &module_path[dots..];
        let base_dir = importing_file_path
            .rfind('/')
            .map(|i| &importing_file_path[..i])
            .unwrap_or("");

        // Walk up `dots - 1` parent directories
        let mut dir = base_dir.to_string();
        for _ in 1..dots {
            if let Some(i) = dir.rfind('/') {
                dir = dir[..i].to_string();
            }
        }

        let rel_as_path = relative_module.replace('.', "/");
        let candidate_prefix = if dir.is_empty() {
            rel_as_path.clone()
        } else {
            format!("{}/{}", dir, rel_as_path)
        };

        for &idx in cg.path_to_file.values() {
            if let GraphNode::File { path, .. } = &cg.graph[idx] {
                let normalized = path.replace('\\', "/");
                if normalized.ends_with(&format!("{}.py", candidate_prefix))
                    || normalized.ends_with(&format!("{}/__init__.py", candidate_prefix))
                {
                    return Some(idx);
                }
            }
        }
    }

    None
}

fn add_function_nodes(
    cg: &mut CodeGraph,
    file_node: NodeIndex,
    file_id: FileId,
    sem: &Arc<SourceSemantics>,
) {
    // Get functions via CommonSemantics trait
    let functions = match sem.as_ref() {
        SourceSemantics::Python(py) => py.functions(),
        SourceSemantics::Go(go) => go.functions(),
        SourceSemantics::Rust(rs) => rs.functions(),
        SourceSemantics::Typescript(ts) => ts.functions(),
    };

    // Collect handler names that will be added by framework-specific functions
    // with http_method/http_path populated. Skip them here to avoid creating a
    // second, metadata-free node that would shadow the framework node in
    // function_nodes and break edge lookup.
    let handler_names_to_skip: std::collections::HashSet<String> = match sem.as_ref() {
        SourceSemantics::Python(py) => {
            let mut skip = std::collections::HashSet::new();
            if let Some(fastapi) = &py.fastapi {
                skip.extend(fastapi.routes.iter().map(|r| r.handler_name.clone()));
            }
            if let Some(flask) = &py.flask {
                skip.extend(flask.routes.iter().map(|r| r.handler_name.clone()));
            }
            skip
        }
        _ => std::collections::HashSet::new(),
    };

    for func in functions {
        if handler_names_to_skip.contains(&func.name) {
            continue;
        }

        let qualified_name = match &func.class_name {
            Some(class) => format!("{}.{}", class, func.name),
            None => func.name.clone(),
        };

        let func_node = cg.graph.add_node(GraphNode::Function {
            file_id,
            name: func.name.clone(),
            qualified_name: qualified_name.clone(),
            is_async: func.is_async,
            is_handler: func.is_route_handler(),
            http_method: None,
            http_path: None,
            decorators: vec![],
            is_writer: false,
            line: None,
            column: None,
            request_schema: None,
            response_schema: None,
        });

        // File contains function
        cg.graph
            .add_edge(file_node, func_node, GraphEdgeKind::Contains);

        // Store for lookup
        cg.function_nodes
            .insert((file_id, func.name.clone()), func_node);
    }
}

/// Categorize a module based on its name
fn categorize_module(module_path: &str) -> ModuleCategory {
    let path_lower = module_path.to_lowercase();

    // Logging - check first to catch "logging", "structlog" etc before other patterns
    if path_lower == "logging"
        || path_lower.starts_with("logging.")
        || path_lower.contains("structlog")
        || path_lower == "tracing"
        || path_lower.starts_with("tracing::")
        || path_lower.contains("uber.org/zap")
        || path_lower.contains("zerolog")
        || path_lower == "winston"
        || path_lower == "pino"
    {
        return ModuleCategory::Logging;
    }

    // HTTP clients
    if path_lower.contains("requests")
        || path_lower.contains("httpx")
        || path_lower.contains("aiohttp")
        || path_lower.contains("urllib")
        || path_lower.contains("axios")
        || path_lower.contains("fetch")
        || path_lower.contains("got")
        || path_lower.contains("reqwest")
        || path_lower.contains("hyper")
    {
        return ModuleCategory::HttpClient;
    }

    // Databases
    if path_lower.contains("sqlalchemy")
        || path_lower.contains("prisma")
        || path_lower.contains("typeorm")
        || path_lower.contains("sequelize")
        || path_lower.contains("diesel")
        || path_lower.contains("sqlx")
        || path_lower.contains("gorm")
        || path_lower.contains("database/sql")
    {
        return ModuleCategory::Database;
    }

    // Web frameworks
    if path_lower.contains("fastapi")
        || path_lower.contains("flask")
        || path_lower.contains("django")
        || path_lower.contains("express")
        || path_lower.contains("nestjs")
        || path_lower.contains("gin")
        || path_lower.contains("echo")
        || path_lower.contains("chi")
        || path_lower.contains("axum")
        || path_lower.contains("actix")
    {
        return ModuleCategory::WebFramework;
    }

    // Async runtimes
    if path_lower.contains("asyncio")
        || path_lower.contains("tokio")
        || path_lower.contains("async_std")
    {
        return ModuleCategory::AsyncRuntime;
    }

    // Resilience
    if path_lower.contains("tenacity")
        || path_lower.contains("stamina")
        || path_lower.contains("retry")
        || path_lower.contains("backoff")
        || path_lower.contains("resilience")
    {
        return ModuleCategory::Resilience;
    }

    // Standard library (approximate)
    if module_path.starts_with("os")
        || module_path.starts_with("sys")
        || module_path.starts_with("io")
        || module_path.starts_with("time")
        || module_path.starts_with("json")
        || module_path.starts_with("re")
        || module_path.starts_with("collections")
        || module_path.starts_with("typing")
        || module_path.starts_with("pathlib")
        || module_path.starts_with("fmt")
        || module_path.starts_with("net/")
        || module_path.starts_with("std::")
    {
        return ModuleCategory::StandardLib;
    }

    ModuleCategory::Other
}

fn add_fastapi_nodes(
    cg: &mut CodeGraph,
    file_node: NodeIndex,
    file_id: FileId,
    py: &PyFileSemantics,
    fastapi: &FastApiFileSummary,
) {
    // Map app var_name -> node index so we can wire routes/middlewares.
    let mut app_nodes: HashMap<String, NodeIndex> = HashMap::new();

    // Apps
    for app in &fastapi.apps {
        let app_node = cg.graph.add_node(GraphNode::FastApiApp {
            file_id,
            var_name: app.var_name.clone(),
        });

        // File contains app
        cg.graph
            .add_edge(file_node, app_node, GraphEdgeKind::Contains);

        app_nodes.insert(app.var_name.clone(), app_node);
    }

    // Build a lookup: router var name → prefix (from include_router calls in this file).
    // e.g. `web.include_router(router, prefix="/assistant")` → "router" → "/assistant"
    // When multiple include_router calls for the same router var exist (e.g. web + api with
    // the same prefix), we just take the first prefix found.
    let mut router_prefix: HashMap<String, String> = HashMap::new();
    for inc in &fastapi.routers {
        // router_expr is the first positional arg text, e.g. "router" or "users.router"
        let var_name = inc
            .router_expr
            .split('.')
            .next()
            .unwrap_or(&inc.router_expr)
            .trim()
            .to_string();
        if let Some(ref prefix) = inc.prefix {
            router_prefix
                .entry(var_name)
                .or_insert_with(|| prefix.clone());
        }
    }

    // Routes
    for route in &fastapi.routes {
        // Resolve the full path by prepending any known prefix for this router variable.
        let full_path = match router_prefix.get(&route.router_var) {
            Some(prefix) => {
                // Avoid double slashes: strip trailing slash from prefix, leading from path.
                let p = prefix.trim_end_matches('/');
                let s = route.path.trim_start_matches('/');
                if s.is_empty() {
                    p.to_string()
                } else {
                    format!("{}/{}", p, s)
                }
            }
            None => route.path.clone(),
        };

        let route_node = cg.graph.add_node(GraphNode::FastApiRoute {
            file_id,
            http_method: route.http_method.clone(),
            path: full_path.clone(),
        });

        // File contains route
        cg.graph
            .add_edge(file_node, route_node, GraphEdgeKind::Contains);

        // Try to find an app owner by heuristic.
        // For now, we don't know which app exactly, so we might associate all apps.
        // Later, we can refine using app.var_name, routers, and decorators.
        for app_node in app_nodes.values() {
            cg.graph
                .add_edge(*app_node, route_node, GraphEdgeKind::FastApiAppOwnsRoute);
        }

        // Back-fill http_method and http_path on the corresponding Function node
        // (identified by handler_name in the same file) so that the Function node
        // carries the full prefixed path too.
        let handler_key = (file_id, route.handler_name.clone());
        if let Some(&fn_idx) = cg.function_nodes.get(&handler_key) {
            if let GraphNode::Function {
                ref mut http_method,
                ref mut http_path,
                ref mut is_handler,
                ..
            } = cg.graph[fn_idx]
            {
                *is_handler = true;
                *http_method = Some(route.http_method.clone());
                *http_path = Some(full_path.clone());
            }
        }
    }

    // Middlewares
    for mw in &fastapi.middlewares {
        let mw_node = cg.graph.add_node(GraphNode::FastApiMiddleware {
            file_id,
            app_var_name: mw.app_var_name.clone(),
            middleware_type: mw.middleware_type.clone(),
        });

        // File contains middleware
        cg.graph
            .add_edge(file_node, mw_node, GraphEdgeKind::Contains);

        // Attach middleware to its app if we know it.
        if let Some(app_node) = app_nodes.get(&mw.app_var_name) {
            cg.graph
                .add_edge(*app_node, mw_node, GraphEdgeKind::FastApiAppHasMiddleware);
        }
    }

    let _ = (py, router_prefix); // suppress unused warnings
}

/// Add Flask route handlers as function nodes with `http_method` and `http_path` populated.
fn add_flask_nodes(
    cg: &mut CodeGraph,
    file_node: NodeIndex,
    file_id: FileId,
    flask: &FlaskFileSummary,
) {
    for route in &flask.routes {
        let qualified_name = route.handler_name.clone();
        let func_node = cg.graph.add_node(GraphNode::Function {
            file_id,
            name: route.handler_name.clone(),
            qualified_name,
            is_async: route.is_async,
            is_handler: true,
            http_method: Some(route.http_method.clone()),
            http_path: Some(route.path.clone()),
            decorators: vec![],
            is_writer: false,
            line: None,
            column: None,
            request_schema: None,
            response_schema: None,
        });

        cg.graph
            .add_edge(file_node, func_node, GraphEdgeKind::Contains);

        cg.function_nodes
            .insert((file_id, route.handler_name.clone()), func_node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    /// Helper to parse Python source and build semantics with framework analysis
    fn parse_and_build_semantics(path: &str, source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: path.to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed)
            .expect("framework analysis should succeed");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    fn parse_python_with_id(path: &str, source: &str, id: u64) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: path.to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(id);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed)
            .expect("framework analysis should succeed");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    // ==================== CodeGraph Tests ====================

    #[test]
    fn code_graph_new_creates_empty_graph() {
        let cg = CodeGraph::new();
        assert_eq!(cg.graph.node_count(), 0);
        assert_eq!(cg.graph.edge_count(), 0);
        assert!(cg.file_nodes.is_empty());
    }

    #[test]
    fn code_graph_debug_impl() {
        let cg = CodeGraph::new();
        let debug_str = format!("{:?}", cg);
        assert!(debug_str.contains("CodeGraph"));
    }

    #[test]
    fn code_graph_default_impl() {
        let cg = CodeGraph::default();
        assert_eq!(cg.graph.node_count(), 0);
    }

    // ==================== GraphNode Tests ====================

    #[test]
    fn graph_node_file_debug() {
        let node = GraphNode::File {
            file_id: FileId(1),
            path: "test.py".to_string(),
            language: Language::Python,
        };
        let debug_str = format!("{:?}", node);
        assert!(debug_str.contains("File"));
        assert!(debug_str.contains("test.py"));
    }

    #[test]
    fn graph_node_function_debug() {
        let node = GraphNode::Function {
            file_id: FileId(1),
            name: "my_func".to_string(),
            qualified_name: "MyClass.my_func".to_string(),
            is_async: true,
            is_handler: false,
            http_method: None,
            http_path: None,
            decorators: vec![],
            is_writer: false,
            line: None,
            column: None,
            request_schema: None,
            response_schema: None,
        };
        let debug_str = format!("{:?}", node);
        assert!(debug_str.contains("Function"));
        assert!(debug_str.contains("my_func"));
    }

    #[test]
    fn graph_node_class_debug() {
        let node = GraphNode::Class {
            file_id: FileId(1),
            name: "MyClass".to_string(),
        };
        let debug_str = format!("{:?}", node);
        assert!(debug_str.contains("Class"));
        assert!(debug_str.contains("MyClass"));
    }

    #[test]
    fn graph_node_external_module_debug() {
        let node = GraphNode::ExternalModule {
            name: "requests".to_string(),
            category: ModuleCategory::HttpClient,
        };
        let debug_str = format!("{:?}", node);
        assert!(debug_str.contains("ExternalModule"));
        assert!(debug_str.contains("requests"));
    }

    #[test]
    fn graph_node_fastapi_app_debug() {
        let node = GraphNode::FastApiApp {
            file_id: FileId(1),
            var_name: "app".to_string(),
        };
        let debug_str = format!("{:?}", node);
        assert!(debug_str.contains("FastApiApp"));
        assert!(debug_str.contains("app"));
    }

    #[test]
    fn graph_node_fastapi_route_debug() {
        let node = GraphNode::FastApiRoute {
            file_id: FileId(1),
            http_method: "GET".to_string(),
            path: "/users".to_string(),
        };
        let debug_str = format!("{:?}", node);
        assert!(debug_str.contains("FastApiRoute"));
        assert!(debug_str.contains("GET"));
    }

    #[test]
    fn graph_node_fastapi_middleware_debug() {
        let node = GraphNode::FastApiMiddleware {
            file_id: FileId(1),
            app_var_name: "app".to_string(),
            middleware_type: "CORSMiddleware".to_string(),
        };
        let debug_str = format!("{:?}", node);
        assert!(debug_str.contains("FastApiMiddleware"));
        assert!(debug_str.contains("CORSMiddleware"));
    }

    #[test]
    fn graph_node_display_name() {
        let file = GraphNode::File {
            file_id: FileId(1),
            path: "src/main.py".to_string(),
            language: Language::Python,
        };
        assert_eq!(file.display_name(), "src/main.py");

        let func = GraphNode::Function {
            file_id: FileId(1),
            name: "process".to_string(),
            qualified_name: "Handler.process".to_string(),
            is_async: false,
            is_handler: true,
            http_method: None,
            http_path: None,
            decorators: vec![],
            is_writer: false,
            line: None,
            column: None,
            request_schema: None,
            response_schema: None,
        };
        assert_eq!(func.display_name(), "Handler.process");

        let module = GraphNode::ExternalModule {
            name: "fastapi".to_string(),
            category: ModuleCategory::WebFramework,
        };
        assert_eq!(module.display_name(), "fastapi");
    }

    #[test]
    fn graph_node_file_id() {
        let file = GraphNode::File {
            file_id: FileId(1),
            path: "test.py".to_string(),
            language: Language::Python,
        };
        assert_eq!(file.file_id(), Some(FileId(1)));

        let module = GraphNode::ExternalModule {
            name: "requests".to_string(),
            category: ModuleCategory::HttpClient,
        };
        assert_eq!(module.file_id(), None);
    }

    #[test]
    fn graph_node_is_file() {
        let file = GraphNode::File {
            file_id: FileId(1),
            path: "test.py".to_string(),
            language: Language::Python,
        };
        assert!(file.is_file());

        let func = GraphNode::Function {
            file_id: FileId(1),
            name: "test".to_string(),
            qualified_name: "test".to_string(),
            is_async: false,
            is_handler: false,
            http_method: None,
            http_path: None,
            decorators: vec![],
            is_writer: false,
            line: None,
            column: None,
            request_schema: None,
            response_schema: None,
        };
        assert!(!func.is_file());
    }

    // ==================== GraphEdgeKind Tests ====================

    #[test]
    fn graph_edge_kind_debug() {
        let edge = GraphEdgeKind::Contains;
        let debug_str = format!("{:?}", edge);
        assert!(debug_str.contains("Contains"));

        let edge = GraphEdgeKind::Imports;
        let debug_str = format!("{:?}", edge);
        assert!(debug_str.contains("Imports"));

        let edge = GraphEdgeKind::ImportsFrom {
            items: vec!["FastAPI".to_string()],
        };
        let debug_str = format!("{:?}", edge);
        assert!(debug_str.contains("ImportsFrom"));
        assert!(debug_str.contains("FastAPI"));

        let edge = GraphEdgeKind::UsesLibrary;
        let debug_str = format!("{:?}", edge);
        assert!(debug_str.contains("UsesLibrary"));
    }

    #[test]
    fn graph_edge_kind_eq() {
        assert_eq!(GraphEdgeKind::Contains, GraphEdgeKind::Contains);
        assert_eq!(GraphEdgeKind::Imports, GraphEdgeKind::Imports);
        assert_ne!(GraphEdgeKind::Contains, GraphEdgeKind::Imports);

        let edge1 = GraphEdgeKind::ImportsFrom {
            items: vec!["A".to_string()],
        };
        let edge2 = GraphEdgeKind::ImportsFrom {
            items: vec!["A".to_string()],
        };
        let edge3 = GraphEdgeKind::ImportsFrom {
            items: vec!["B".to_string()],
        };
        assert_eq!(edge1, edge2);
        assert_ne!(edge1, edge3);
    }

    // ==================== build_code_graph Tests ====================

    #[test]
    fn build_code_graph_empty_semantics() {
        let sem_entries: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let cg = build_code_graph(&sem_entries);
        assert_eq!(cg.graph.node_count(), 0);
        assert_eq!(cg.graph.edge_count(), 0);
    }

    #[test]
    fn build_code_graph_single_file_no_fastapi() {
        let (file_id, sem) = parse_and_build_semantics("test.py", "x = 1\ny = 2");
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        // Should have one file node
        assert!(cg.graph.node_count() >= 1);
        assert!(cg.file_nodes.contains_key(&file_id));
    }

    #[test]
    fn build_code_graph_with_function() {
        let src = r#"
def process_data(data):
    return data * 2

async def fetch_user(user_id):
    return {"id": user_id}
"#;
        let (file_id, sem) = parse_and_build_semantics("handlers.py", src);
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        // Should have file node + 2 function nodes
        let stats = cg.stats();
        assert_eq!(stats.file_count, 1);
        assert!(stats.function_count >= 2);

        // Functions should be in lookup
        assert!(
            cg.function_nodes
                .contains_key(&(file_id, "process_data".to_string()))
        );
        assert!(
            cg.function_nodes
                .contains_key(&(file_id, "fetch_user".to_string()))
        );
    }

    #[test]
    fn build_code_graph_with_external_imports() {
        let src = r#"
import requests
from fastapi import FastAPI
import sqlalchemy
"#;
        let (file_id, sem) = parse_and_build_semantics("main.py", src);
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        // Should have external module nodes
        assert!(cg.external_modules.contains_key("requests"));
        assert!(cg.external_modules.contains_key("fastapi"));
        assert!(cg.external_modules.contains_key("sqlalchemy"));

        // Should have UsesLibrary edges
        let stats = cg.stats();
        assert!(stats.uses_library_edge_count >= 3);

        // Check categories
        if let Some(&idx) = cg.external_modules.get("requests") {
            if let GraphNode::ExternalModule { category, .. } = &cg.graph[idx] {
                assert_eq!(*category, ModuleCategory::HttpClient);
            }
        }
    }

    #[test]
    fn build_code_graph_with_fastapi_app() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()
"#;
        let (file_id, sem) = parse_and_build_semantics("main.py", src);
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        // Should have file node + app node + external module
        assert!(cg.graph.node_count() >= 2);

        // Should have at least one edge (file contains app)
        assert!(cg.graph.edge_count() >= 1);
    }

    #[test]
    fn build_code_graph_with_fastapi_middleware() {
        let src = r#"
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
)
"#;
        let (file_id, sem) = parse_and_build_semantics("main.py", src);
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        // Should have file node + app node + middleware node
        assert!(cg.graph.node_count() >= 3);

        // Should have edges: file->app, file->middleware, app->middleware
        assert!(cg.graph.edge_count() >= 3);
    }

    #[test]
    fn build_code_graph_multiple_files() {
        let (file_id1, sem1) = parse_python_with_id("file1.py", "x = 1", 1);
        let (file_id2, sem2) = parse_python_with_id("file2.py", "y = 2", 2);

        let sem_entries = vec![(file_id1, sem1), (file_id2, sem2)];

        let cg = build_code_graph(&sem_entries);

        // Should have two file nodes
        assert_eq!(cg.stats().file_count, 2);
        assert!(cg.file_nodes.contains_key(&file_id1));
        assert!(cg.file_nodes.contains_key(&file_id2));
    }

    #[test]
    fn build_code_graph_with_fastapi_routes() {
        let src = r#"
from fastapi import FastAPI

app = FastAPI()

@app.get("/users")
async def get_users():
    return []

@app.post("/users")
async def create_user():
    return {}
"#;
        let (file_id, sem) = parse_and_build_semantics("routes.py", src);
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        // Should have: file node + app node + 2 route nodes + 2 function nodes
        assert!(cg.graph.node_count() >= 4);

        // Verify route nodes exist
        let mut route_count = 0;
        for node in cg.graph.node_weights() {
            if matches!(node, GraphNode::FastApiRoute { .. }) {
                route_count += 1;
            }
        }
        assert_eq!(route_count, 2);
    }

    #[test]
    fn build_code_graph_middleware_attached_to_correct_app() {
        let src = r#"
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(CORSMiddleware)
"#;
        let (file_id, sem) = parse_and_build_semantics("main.py", src);
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        // Find the middleware node and verify it's connected to the app
        let mut found_middleware_edge = false;
        for edge in cg.graph.edge_weights() {
            if matches!(edge, GraphEdgeKind::FastApiAppHasMiddleware) {
                found_middleware_edge = true;
                break;
            }
        }
        assert!(found_middleware_edge);
    }

    #[test]
    fn build_code_graph_middleware_without_matching_app() {
        let src = r#"
from fastapi.middleware.cors import CORSMiddleware

def setup_cors(app):
    app.add_middleware(CORSMiddleware)
"#;
        let (file_id, sem) = parse_and_build_semantics("cors_setup.py", src);
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        // Should still build without errors
        assert!(cg.graph.node_count() >= 1);
    }

    // ==================== Graph Query Tests ====================

    #[test]
    fn code_graph_get_external_dependencies() {
        let src = r#"
import requests
from fastapi import FastAPI
"#;
        let (file_id, sem) = parse_and_build_semantics("main.py", src);
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        let deps = cg.get_external_dependencies(file_id);
        assert!(deps.contains(&"requests".to_string()));
        assert!(deps.contains(&"fastapi".to_string()));
    }

    #[test]
    fn code_graph_get_files_using_library() {
        let src = r#"import requests"#;
        let (file_id, sem) = parse_and_build_semantics("main.py", src);
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        let files = cg.get_files_using_library("requests");
        assert!(files.contains(&file_id));
    }

    #[test]
    fn code_graph_stats() {
        let src = r#"
import requests
from fastapi import FastAPI

app = FastAPI()

def process():
    pass
"#;
        let (file_id, sem) = parse_and_build_semantics("main.py", src);
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);
        let stats = cg.stats();

        assert_eq!(stats.file_count, 1);
        assert!(stats.function_count >= 1);
        assert!(stats.external_module_count >= 2);
        assert!(stats.uses_library_edge_count >= 2);
        assert!(stats.contains_edge_count >= 1);
    }

    // ==================== Module Category Tests ====================

    #[test]
    fn categorize_module_http_client() {
        assert_eq!(categorize_module("requests"), ModuleCategory::HttpClient);
        assert_eq!(categorize_module("httpx"), ModuleCategory::HttpClient);
        assert_eq!(categorize_module("axios"), ModuleCategory::HttpClient);
        assert_eq!(categorize_module("reqwest"), ModuleCategory::HttpClient);
    }

    #[test]
    fn categorize_module_database() {
        assert_eq!(categorize_module("sqlalchemy"), ModuleCategory::Database);
        assert_eq!(categorize_module("prisma"), ModuleCategory::Database);
        assert_eq!(categorize_module("diesel"), ModuleCategory::Database);
    }

    #[test]
    fn categorize_module_web_framework() {
        assert_eq!(categorize_module("fastapi"), ModuleCategory::WebFramework);
        assert_eq!(categorize_module("express"), ModuleCategory::WebFramework);
        assert_eq!(categorize_module("gin"), ModuleCategory::WebFramework);
    }

    #[test]
    fn categorize_module_async_runtime() {
        assert_eq!(categorize_module("asyncio"), ModuleCategory::AsyncRuntime);
        assert_eq!(categorize_module("tokio"), ModuleCategory::AsyncRuntime);
    }

    #[test]
    fn categorize_module_logging() {
        assert_eq!(categorize_module("logging"), ModuleCategory::Logging);
        assert_eq!(categorize_module("structlog"), ModuleCategory::Logging);
        assert_eq!(categorize_module("tracing"), ModuleCategory::Logging);
    }

    #[test]
    fn categorize_module_resilience() {
        assert_eq!(categorize_module("tenacity"), ModuleCategory::Resilience);
        assert_eq!(categorize_module("stamina"), ModuleCategory::Resilience);
    }

    #[test]
    fn categorize_module_stdlib() {
        assert_eq!(categorize_module("os"), ModuleCategory::StandardLib);
        assert_eq!(categorize_module("json"), ModuleCategory::StandardLib);
        assert_eq!(categorize_module("typing"), ModuleCategory::StandardLib);
    }

    #[test]
    fn categorize_module_other() {
        assert_eq!(categorize_module("some_random_lib"), ModuleCategory::Other);
    }

    // ==================== Find File Tests ====================

    #[test]
    fn find_file_by_path_exact() {
        let (file_id, sem) = parse_and_build_semantics("src/main.py", "x = 1");
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        assert!(cg.find_file_by_path("src/main.py").is_some());
        assert!(cg.find_file_by_path("nonexistent.py").is_none());
    }

    #[test]
    fn find_file_by_path_suffix() {
        let (file_id, sem) = parse_and_build_semantics("src/auth/middleware.py", "x = 1");
        let sem_entries = vec![(file_id, sem)];

        let cg = build_code_graph(&sem_entries);

        // Should find by suffix
        assert!(cg.find_file_by_path("auth/middleware.py").is_some());
        assert!(cg.find_file_by_path("middleware.py").is_some());
    }

    // ── Calls edge construction ───────────────────────────────────────────────

    #[test]
    fn intra_file_calls_edge_added() {
        let src = r#"
def helper():
    return 42

def handler():
    return helper()
"#;
        let (file_id, sem) = parse_and_build_semantics("app.py", src);
        let sem_entries = vec![(file_id, sem)];
        let cg = build_code_graph(&sem_entries);

        // Both functions should be in the graph
        assert!(
            cg.function_nodes
                .contains_key(&(file_id, "helper".to_string()))
        );
        assert!(
            cg.function_nodes
                .contains_key(&(file_id, "handler".to_string()))
        );

        // There should be a Calls edge from handler -> helper
        let handler_idx = *cg
            .function_nodes
            .get(&(file_id, "handler".to_string()))
            .unwrap();
        let helper_idx = *cg
            .function_nodes
            .get(&(file_id, "helper".to_string()))
            .unwrap();

        let has_calls_edge = cg
            .graph
            .edges_directed(handler_idx, Direction::Outgoing)
            .any(|e| matches!(e.weight(), GraphEdgeKind::Calls) && e.target() == helper_idx);
        assert!(has_calls_edge, "expected Calls edge handler -> helper");
    }

    #[test]
    fn flask_handler_not_duplicated_in_graph() {
        // Verifies that a Flask route handler is emitted exactly once
        // (by add_flask_nodes, not again by add_function_nodes), and that
        // the single node carries http_method and http_path.
        let src = r#"
from flask import Flask

app = Flask(__name__)

@app.route('/users', methods=['GET'])
def list_users():
    return []
"#;
        let (file_id, sem) = parse_and_build_semantics("api.py", src);
        let sem_entries = vec![(file_id, sem)];
        let cg = build_code_graph(&sem_entries);

        // Should appear exactly once in function_nodes
        let node_idx = cg.function_nodes.get(&(file_id, "list_users".to_string()));
        assert!(node_idx.is_some(), "list_users should be in function_nodes");

        // Count all Function nodes named list_users
        let count = cg.graph.node_indices().filter(|&i| {
            matches!(&cg.graph[i], GraphNode::Function { name, .. } if name == "list_users")
        }).count();
        assert_eq!(
            count, 1,
            "list_users should appear exactly once in the graph"
        );

        // Should have HTTP metadata
        let node = &cg.graph[*node_idx.unwrap()];
        assert!(
            matches!(
                node,
                GraphNode::Function {
                    is_handler: true,
                    http_method: Some(_),
                    http_path: Some(_),
                    ..
                }
            ),
            "Flask handler should have http_method and http_path set"
        );
    }

    #[test]
    fn intra_file_calls_edge_from_flask_handler() {
        // The handler itself calls a helper. Callers of the helper should
        // be resolvable once the double-node bug is fixed.
        let src = r#"
from flask import Flask

app = Flask(__name__)

def process():
    return {"ok": True}

@app.route('/run', methods=['POST'])
def run_handler():
    return process()
"#;
        let (file_id, sem) = parse_and_build_semantics("api.py", src);
        let sem_entries = vec![(file_id, sem)];
        let cg = build_code_graph(&sem_entries);

        let handler_idx = *cg
            .function_nodes
            .get(&(file_id, "run_handler".to_string()))
            .unwrap();
        let process_idx = *cg
            .function_nodes
            .get(&(file_id, "process".to_string()))
            .unwrap();

        let has_calls_edge = cg
            .graph
            .edges_directed(handler_idx, Direction::Outgoing)
            .any(|e| matches!(e.weight(), GraphEdgeKind::Calls) && e.target() == process_idx);
        assert!(has_calls_edge, "expected Calls edge run_handler -> process");
    }

    // ── Cross-file calls from Flask handlers (function-scoped imports) ────────

    #[test]
    fn flask_handler_cross_file_call_via_module_level_import() {
        // Standard pattern: import at top of file, call inside handler.
        let handler_src = r#"
from flask import Flask
from services.users import get_all_users

app = Flask(__name__)

@app.route('/users', methods=['GET'])
def list_users():
    return get_all_users()
"#;
        let service_src = r#"
def get_all_users():
    return []
"#;
        let (handler_fid, handler_sem) = parse_python_with_id("routes/api.py", handler_src, 1);
        let (service_fid, service_sem) = parse_python_with_id("services/users.py", service_src, 2);
        let sem_entries = vec![(handler_fid, handler_sem), (service_fid, service_sem)];
        let cg = build_code_graph(&sem_entries);

        let handler_idx = *cg
            .function_nodes
            .get(&(handler_fid, "list_users".to_string()))
            .expect("list_users not in graph");
        let callee_idx = *cg
            .function_nodes
            .get(&(service_fid, "get_all_users".to_string()))
            .expect("get_all_users not in graph");

        let has_edge = cg
            .graph
            .edges_directed(handler_idx, Direction::Outgoing)
            .any(|e| matches!(e.weight(), GraphEdgeKind::Calls) && e.target() == callee_idx);
        assert!(
            has_edge,
            "expected Calls edge list_users -> get_all_users (module-level import)"
        );
    }

    #[test]
    fn flask_handler_cross_file_call_via_function_scoped_import() {
        // The pattern the user reported: import is *inside* the handler body.
        let handler_src = r#"
from flask import Flask

app = Flask(__name__)

@app.route('/users', methods=['GET'])
def list_users():
    from services.users import get_all_users
    return get_all_users()
"#;
        let service_src = r#"
def get_all_users():
    return []
"#;
        let (handler_fid, handler_sem) = parse_python_with_id("routes/api.py", handler_src, 1);
        let (service_fid, service_sem) = parse_python_with_id("services/users.py", service_src, 2);
        let sem_entries = vec![(handler_fid, handler_sem), (service_fid, service_sem)];
        let cg = build_code_graph(&sem_entries);

        let handler_idx = *cg
            .function_nodes
            .get(&(handler_fid, "list_users".to_string()))
            .expect("list_users not in graph");
        let callee_idx = *cg
            .function_nodes
            .get(&(service_fid, "get_all_users".to_string()))
            .expect("get_all_users not in graph");

        let has_edge = cg
            .graph
            .edges_directed(handler_idx, Direction::Outgoing)
            .any(|e| matches!(e.weight(), GraphEdgeKind::Calls) && e.target() == callee_idx);
        assert!(
            has_edge,
            "expected Calls edge list_users -> get_all_users (function-scoped import)"
        );
    }

    #[test]
    fn flask_handler_with_underscore_prefix_calls_inner_function() {
        // Reproduces: handler is named _my_function (underscore prefix),
        // it calls my_function (no prefix) defined in the same file.
        // `unfault graph callers my_function` should find _my_function as a caller.
        let src = r#"
from flask import Flask

app = Flask(__name__)

def my_function():
    return {"ok": True}

@app.route('/run', methods=['POST'])
def _my_function():
    return my_function()
"#;
        let (file_id, sem) = parse_and_build_semantics("api.py", src);
        let sem_entries = vec![(file_id, sem)];
        let cg = build_code_graph(&sem_entries);

        // Both nodes must be in the graph
        let handler_idx = cg
            .function_nodes
            .get(&(file_id, "_my_function".to_string()))
            .copied();
        let callee_idx = cg
            .function_nodes
            .get(&(file_id, "my_function".to_string()))
            .copied();

        assert!(handler_idx.is_some(), "_my_function not in function_nodes");
        assert!(callee_idx.is_some(), "my_function not in function_nodes");

        // Calls edge _my_function -> my_function must exist
        let has_edge = cg
            .graph
            .edges_directed(handler_idx.unwrap(), Direction::Outgoing)
            .any(|e| {
                matches!(e.weight(), GraphEdgeKind::Calls) && e.target() == callee_idx.unwrap()
            });
        assert!(has_edge, "expected Calls edge _my_function -> my_function");

        // get_callers("my_function") must find _my_function as a caller
        let ctx = super::traversal::get_callers(&cg, "my_function", 5);
        assert!(
            ctx.target_file.is_some(),
            "my_function should be found in graph"
        );
        assert!(
            ctx.callers.iter().any(|c| c.name == "_my_function"),
            "expected _my_function as a caller of my_function; got: {:?}",
            ctx.callers
        );
    }

    #[test]
    fn self_import_same_file_handler_calls_sibling_function() {
        // Exact pattern from the codebase:
        // _attach_email_to_invitation (action_route handler) does:
        //   from components.fr...employment import attach_email_to_invitation
        //   attach_email_to_invitation(...)
        // Both functions live in the SAME file.
        // The import resolves back to the same file, so this is an intra-file
        // call disguised as a cross-file import.
        let src = r#"
endpoint = Endpoint("company")

@endpoint.route("/<int:id>")
class CompanyController(BaseController):
    pass

@CompanyController.action_route("/<int:id>/attach_email", methods=["PATCH"])
def _attach_email_to_invitation(id: int):
    from components.fr.employment import attach_email_to_invitation
    attach_email_to_invitation(id)

def attach_email_to_invitation(company_id: int):
    pass
"#;
        let (file_id, sem) = parse_python_with_id("components/fr/employment.py", src, 1);
        let sem_entries = vec![(file_id, sem)];
        let cg = build_code_graph(&sem_entries);

        let handler_idx = cg
            .function_nodes
            .get(&(file_id, "_attach_email_to_invitation".to_string()))
            .copied()
            .expect("_attach_email_to_invitation not in function_nodes");
        let callee_idx = cg
            .function_nodes
            .get(&(file_id, "attach_email_to_invitation".to_string()))
            .copied()
            .expect("attach_email_to_invitation not in function_nodes");

        let has_edge = cg
            .graph
            .edges_directed(handler_idx, Direction::Outgoing)
            .any(|e| matches!(e.weight(), GraphEdgeKind::Calls) && e.target() == callee_idx);
        assert!(
            has_edge,
            "expected Calls edge _attach_email_to_invitation -> attach_email_to_invitation"
        );

        let ctx = super::traversal::get_callers(&cg, "attach_email_to_invitation", 5);
        assert!(
            ctx.target_file.is_some(),
            "attach_email_to_invitation should be found in graph"
        );
        assert!(
            ctx.callers
                .iter()
                .any(|c| c.name == "_attach_email_to_invitation"),
            "expected _attach_email_to_invitation as a caller; got: {:?}",
            ctx.callers
        );
    }

    #[test]
    fn action_route_handler_cross_file_call_function_scoped_import() {
        // action_route handler with underscore-prefixed name calls a function
        // in a separate business logic file via a function-scoped import.
        // This mirrors the exact pattern reported by the user.
        let controller_src = r#"
endpoint = Endpoint("company")

@endpoint.route("/company")
class CompanyController(BaseController):
    pass

@CompanyController.action_route("/<int:id>/do_thing/<int:user_id>", methods=["PATCH"])
def _do_thing(id: int, user_id: int):
    from business.actions import do_thing
    do_thing(id, user_id)
"#;
        let service_src = r#"
def do_thing(company_id: int, user_id: int):
    pass
"#;
        let (controller_fid, controller_sem) =
            parse_python_with_id("api/company/controller.py", controller_src, 1);
        let (service_fid, service_sem) =
            parse_python_with_id("business/actions.py", service_src, 2);
        let sem_entries = vec![(controller_fid, controller_sem), (service_fid, service_sem)];
        let cg = build_code_graph(&sem_entries);

        let handler_idx = cg
            .function_nodes
            .get(&(controller_fid, "_do_thing".to_string()))
            .copied()
            .expect("_do_thing not in function_nodes");
        let callee_idx = cg
            .function_nodes
            .get(&(service_fid, "do_thing".to_string()))
            .copied()
            .expect("do_thing not in function_nodes");

        let has_edge = cg
            .graph
            .edges_directed(handler_idx, Direction::Outgoing)
            .any(|e| matches!(e.weight(), GraphEdgeKind::Calls) && e.target() == callee_idx);
        assert!(
            has_edge,
            "expected Calls edge _do_thing -> do_thing (cross-file, function-scoped import)"
        );

        // get_callers("do_thing") must find _do_thing as a caller
        let ctx = super::traversal::get_callers(&cg, "do_thing", 5);
        assert!(
            ctx.callers.iter().any(|c| c.name == "_do_thing"),
            "expected _do_thing as a caller of do_thing; got: {:?}",
            ctx.callers
        );
    }

    #[test]
    fn action_route_with_inner_decorators_cross_file_call() {
        // action_route is the outermost decorator; additional decorators
        // (@use_args, @require_auth, etc.) sit between it and the function.
        // The handler name and call edges must still resolve correctly.
        let controller_src = r#"
endpoint = Endpoint("company")

@endpoint.route("/company")
class CompanyController(BaseController):
    pass

@CompanyController.action_route("/<int:id>/do_thing/<int:user_id>", methods=["PATCH"])
@use_args(SomeSchema(), location="json")
@require_auth
def _do_thing(id: int, user_id: int, json_args: dict):
    from business.actions import do_thing
    do_thing(id, user_id)
"#;
        let service_src = r#"
def do_thing(company_id: int, user_id: int):
    pass
"#;
        let (controller_fid, controller_sem) =
            parse_python_with_id("api/company/controller.py", controller_src, 1);
        let (service_fid, service_sem) =
            parse_python_with_id("business/actions.py", service_src, 2);
        let sem_entries = vec![(controller_fid, controller_sem), (service_fid, service_sem)];
        let cg = build_code_graph(&sem_entries);

        // Handler must be registered under its real name
        let handler_idx = cg
            .function_nodes
            .get(&(controller_fid, "_do_thing".to_string()))
            .copied()
            .expect("_do_thing not in function_nodes");
        let callee_idx = cg
            .function_nodes
            .get(&(service_fid, "do_thing".to_string()))
            .copied()
            .expect("do_thing not in function_nodes");

        let has_edge = cg
            .graph
            .edges_directed(handler_idx, Direction::Outgoing)
            .any(|e| matches!(e.weight(), GraphEdgeKind::Calls) && e.target() == callee_idx);
        assert!(
            has_edge,
            "expected Calls edge _do_thing -> do_thing with inner decorators present"
        );

        let ctx = super::traversal::get_callers(&cg, "do_thing", 5);
        assert!(
            ctx.callers.iter().any(|c| c.name == "_do_thing"),
            "expected _do_thing as caller of do_thing; got: {:?}",
            ctx.callers
        );
    }

    #[test]
    fn flask_restful_action_route_cross_file_call_via_function_scoped_import() {
        // The action_route pattern with a function-scoped import inside the handler.
        let handler_src = r#"
endpoint = Endpoint("users")

@endpoint.route("/users")
class UserController(BaseController):
    pass

@UserController.action_route("/", methods=["GET"])
def list_users():
    from services.users import get_all_users
    return get_all_users()
"#;
        let service_src = r#"
def get_all_users():
    return []
"#;
        let (handler_fid, handler_sem) =
            parse_python_with_id("controllers/users.py", handler_src, 1);
        let (service_fid, service_sem) = parse_python_with_id("services/users.py", service_src, 2);
        let sem_entries = vec![(handler_fid, handler_sem), (service_fid, service_sem)];
        let cg = build_code_graph(&sem_entries);

        let handler_idx = *cg
            .function_nodes
            .get(&(handler_fid, "list_users".to_string()))
            .expect("list_users not in graph");
        let callee_idx = *cg
            .function_nodes
            .get(&(service_fid, "get_all_users".to_string()))
            .expect("get_all_users not in graph");

        let has_edge = cg
            .graph
            .edges_directed(handler_idx, Direction::Outgoing)
            .any(|e| matches!(e.weight(), GraphEdgeKind::Calls) && e.target() == callee_idx);
        assert!(
            has_edge,
            "expected Calls edge list_users -> get_all_users (action_route, function-scoped import)"
        );
    }
}
