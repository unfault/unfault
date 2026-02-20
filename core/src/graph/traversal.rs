//! Graph traversal queries.
//!
//! These operate on the in-memory [`CodeGraph`] and do not require
//! embeddings or vector search. They provide structural analysis:
//!
//! - **Flow**: BFS forward on call edges from a target function
//! - **Impact**: Reverse BFS on import/call edges to find dependents
//! - **Dependencies**: Outgoing import/library edges from a target
//! - **Centrality**: In-degree ranking of files by import count
//! - **Enumerate**: Count/list entities by type (files, functions, routes, etc.)
//! - **Overview**: Aggregate workspace structure from the graph

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::Direction;
use petgraph::visit::EdgeRef;

use crate::graph::{CodeGraph, GraphEdgeKind, GraphNode};
use crate::types::graph_query::{
    EnumerateContext, FlowContext, FlowPathNode, GraphContext, WorkspaceContext,
};

/// Extract a call-flow starting from a target node name.
///
/// Performs BFS on the Calls edges to build a tree of call paths.
pub fn extract_flow(graph: &CodeGraph, target: &str, max_depth: usize) -> FlowContext {
    let start_indices = find_nodes_by_name(graph, target);
    if start_indices.is_empty() {
        return FlowContext::default();
    }

    let mut roots = Vec::new();
    let mut all_paths = Vec::new();

    for start_idx in start_indices {
        let node = &graph.graph[start_idx];
        roots.push(FlowPathNode {
            name: node.display_name(),
            file_path: node_file_path(graph, node),
            node_type: node_type_str(node).to_string(),
            depth: 0,
        });

        // BFS outgoing calls
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        visited.insert(start_idx);
        queue.push_back((start_idx, vec![node_to_flow_path(graph, node, 0)]));

        while let Some((current, path)) = queue.pop_front() {
            if path.len() > max_depth as usize {
                all_paths.push(path);
                continue;
            }

            let mut has_children = false;
            for edge in graph.graph.edges_directed(current, Direction::Outgoing) {
                if !matches!(edge.weight(), GraphEdgeKind::Calls) {
                    continue;
                }
                let target_idx = edge.target();
                if visited.contains(&target_idx) {
                    continue;
                }
                visited.insert(target_idx);
                has_children = true;

                let target_node = &graph.graph[target_idx];
                let mut new_path = path.clone();
                new_path.push(node_to_flow_path(graph, target_node, new_path.len()));
                queue.push_back((target_idx, new_path));
            }

            if !has_children && path.len() > 1 {
                all_paths.push(path);
            }
        }
    }

    FlowContext {
        roots,
        paths: all_paths,
    }
}

/// Get the impact of changing a target (reverse BFS on imports/calls).
///
/// Returns files that directly or transitively depend on the target.
pub fn get_impact(graph: &CodeGraph, target: &str, max_depth: usize) -> GraphContext {
    let start_indices = find_nodes_by_name(graph, target);
    if start_indices.is_empty() {
        return GraphContext::default();
    }

    let mut affected = HashSet::new();
    for start_idx in &start_indices {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        visited.insert(*start_idx);
        queue.push_back((*start_idx, 0usize));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            for edge in graph.graph.edges_directed(current, Direction::Incoming) {
                let kind = edge.weight();
                if !matches!(
                    kind,
                    GraphEdgeKind::Imports
                        | GraphEdgeKind::ImportsFrom { .. }
                        | GraphEdgeKind::Calls
                ) {
                    continue;
                }

                let source_idx = edge.source();
                if visited.contains(&source_idx) {
                    continue;
                }
                visited.insert(source_idx);

                let node = &graph.graph[source_idx];
                if let Some(path) = node_file_path(graph, node) {
                    affected.insert(path);
                }
                queue.push_back((source_idx, depth + 1));
            }
        }
    }

    GraphContext {
        affected_files: affected.into_iter().collect(),
        ..Default::default()
    }
}

/// Get dependencies of a target (what does it import/call).
pub fn get_dependencies(graph: &CodeGraph, target: &str) -> GraphContext {
    let start_indices = find_nodes_by_name(graph, target);
    if start_indices.is_empty() {
        return GraphContext::default();
    }

    let mut deps = HashSet::new();
    let mut lib_users = HashSet::new();

    for start_idx in start_indices {
        for edge in graph.graph.edges_directed(start_idx, Direction::Outgoing) {
            let target_idx = edge.target();
            let node = &graph.graph[target_idx];

            match edge.weight() {
                GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. } => {
                    deps.insert(node.display_name());
                }
                GraphEdgeKind::UsesLibrary => {
                    lib_users.insert(node.display_name());
                }
                _ => {}
            }
        }
    }

    GraphContext {
        dependencies: deps.into_iter().collect(),
        library_users: lib_users.into_iter().collect(),
        ..Default::default()
    }
}

/// Compute centrality (most connected/imported files).
///
/// Uses in-degree on import edges as a proxy for importance.
pub fn get_centrality(graph: &CodeGraph, top_n: usize) -> GraphContext {
    let mut scores: HashMap<String, f64> = HashMap::new();

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        if !node.is_file() {
            continue;
        }

        let in_degree = graph
            .graph
            .edges_directed(idx, Direction::Incoming)
            .filter(|e| {
                matches!(
                    e.weight(),
                    GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. }
                )
            })
            .count();

        if in_degree > 0 {
            if let Some(path) = node_file_path(graph, node) {
                scores.insert(path, in_degree as f64);
            }
        }
    }

    let mut ranked: Vec<(String, f64)> = scores.into_iter().collect();
    ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    ranked.truncate(top_n);

    GraphContext {
        central_files: ranked,
        ..Default::default()
    }
}

/// Enumerate entities in the graph (files, functions, routes, classes).
pub fn enumerate_entities(graph: &CodeGraph, entity_type: &str) -> EnumerateContext {
    let lower = entity_type.to_lowercase();
    let mut items = Vec::new();

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        let matches = match &lower {
            s if s.contains("route") || s.contains("endpoint") => matches!(
                node,
                GraphNode::FastApiRoute { .. }
                    | GraphNode::Function {
                        is_handler: true,
                        ..
                    }
            ),
            s if s.contains("function") || s.contains("method") => {
                matches!(node, GraphNode::Function { .. })
            }
            s if s.contains("file") => matches!(node, GraphNode::File { .. }),
            s if s.contains("class") || s.contains("type") || s.contains("struct") => {
                matches!(node, GraphNode::Class { .. })
            }
            s if s.contains("librar") || s.contains("module") || s.contains("dependency") => {
                matches!(node, GraphNode::ExternalModule { .. })
            }
            _ => false,
        };

        if matches {
            items.push(node.display_name());
        }
    }

    items.sort();

    EnumerateContext {
        entity_type: entity_type.to_string(),
        count: items.len(),
        items,
    }
}

/// Build a workspace overview from the graph.
pub fn workspace_overview(graph: &CodeGraph) -> WorkspaceContext {
    let mut languages = HashSet::new();
    let mut frameworks = HashSet::new();
    let mut file_count = 0;
    let mut function_count = 0;
    let mut entrypoints = Vec::new();
    let mut central_files = Vec::new();

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        match node {
            GraphNode::File { language, path, .. } => {
                file_count += 1;
                languages.insert(format!("{:?}", language));

                // Files with no importers and outgoing calls are likely entrypoints
                let incoming_imports = graph
                    .graph
                    .edges_directed(idx, Direction::Incoming)
                    .filter(|e| {
                        matches!(
                            e.weight(),
                            GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. }
                        )
                    })
                    .count();

                let outgoing_imports = graph
                    .graph
                    .edges_directed(idx, Direction::Outgoing)
                    .filter(|e| {
                        matches!(
                            e.weight(),
                            GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. }
                        )
                    })
                    .count();

                if incoming_imports == 0 && outgoing_imports > 0 {
                    entrypoints.push(path.clone());
                }

                if incoming_imports > 3 {
                    central_files.push(path.clone());
                }
            }
            GraphNode::Function { .. } => {
                function_count += 1;
            }
            GraphNode::ExternalModule { name, .. } => {
                // Detect frameworks from external modules
                let lower = name.to_lowercase();
                if matches!(
                    lower.as_str(),
                    "fastapi" | "flask" | "django" | "express" | "axum" | "gin" | "echo"
                ) {
                    frameworks.insert(name.clone());
                }
            }
            _ => {}
        }
    }

    WorkspaceContext {
        languages: languages.into_iter().collect(),
        frameworks: frameworks.into_iter().collect(),
        file_count,
        function_count,
        entrypoints,
        central_files,
    }
}

// --- Helpers ---

/// Find graph nodes whose display name matches the target (case-insensitive partial).
fn find_nodes_by_name(graph: &CodeGraph, target: &str) -> Vec<petgraph::graph::NodeIndex> {
    let lower_target = target.to_lowercase();
    let mut results = Vec::new();

    // Try exact path match first
    if let Some(&idx) = graph.path_to_file.get(target) {
        results.push(idx);
        return results;
    }

    // Then search all nodes
    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        let name = node.display_name().to_lowercase();

        if name == lower_target {
            results.push(idx);
        } else if name.ends_with(&lower_target)
            || name.contains(&format!("/{}", lower_target))
            || name.contains(&format!(".{}", lower_target))
        {
            results.push(idx);
        }
    }

    results
}

/// Get the file path for a node.
fn node_file_path(graph: &CodeGraph, node: &GraphNode) -> Option<String> {
    match node {
        GraphNode::File { path, .. } => Some(path.clone()),
        _ => node.file_id().and_then(|fid| {
            graph.file_nodes.get(&fid).map(|&idx| {
                if let GraphNode::File { path, .. } = &graph.graph[idx] {
                    path.clone()
                } else {
                    String::new()
                }
            })
        }),
    }
}

/// Convert a node to a FlowPathNode.
fn node_to_flow_path(graph: &CodeGraph, node: &GraphNode, depth: usize) -> FlowPathNode {
    FlowPathNode {
        name: node.display_name(),
        file_path: node_file_path(graph, node),
        node_type: node_type_str(node).to_string(),
        depth,
    }
}

/// Get a string representation of the node type.
fn node_type_str(node: &GraphNode) -> &str {
    match node {
        GraphNode::File { .. } => "file",
        GraphNode::Function {
            is_handler: true, ..
        } => "handler",
        GraphNode::Function { .. } => "function",
        GraphNode::Class { .. } => "class",
        GraphNode::ExternalModule { .. } => "library",
        GraphNode::FastApiApp { .. } => "app",
        GraphNode::FastApiRoute { .. } => "route",
        GraphNode::FastApiMiddleware { .. } => "middleware",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::GraphEdgeKind;
    use crate::parse::ast::FileId;
    use crate::types::context::Language;

    fn build_test_graph() -> CodeGraph {
        let mut graph = CodeGraph::new();

        // Add file nodes
        let f1 = graph.graph.add_node(GraphNode::File {
            file_id: FileId(1),
            path: "src/main.py".to_string(),
            language: Language::Python,
        });
        graph.file_nodes.insert(FileId(1), f1);
        graph.path_to_file.insert("src/main.py".to_string(), f1);

        let f2 = graph.graph.add_node(GraphNode::File {
            file_id: FileId(2),
            path: "src/auth.py".to_string(),
            language: Language::Python,
        });
        graph.file_nodes.insert(FileId(2), f2);
        graph.path_to_file.insert("src/auth.py".to_string(), f2);

        let f3 = graph.graph.add_node(GraphNode::File {
            file_id: FileId(3),
            path: "src/db.py".to_string(),
            language: Language::Python,
        });
        graph.file_nodes.insert(FileId(3), f3);
        graph.path_to_file.insert("src/db.py".to_string(), f3);

        // main imports auth, auth imports db
        graph.graph.add_edge(f1, f2, GraphEdgeKind::Imports);
        graph.graph.add_edge(f2, f3, GraphEdgeKind::Imports);

        // Add function nodes
        let fn1 = graph.graph.add_node(GraphNode::Function {
            file_id: FileId(1),
            name: "handle_login".to_string(),
            qualified_name: "handle_login".to_string(),
            is_async: true,
            is_handler: true,
            http_method: Some("POST".to_string()),
            http_path: Some("/login".to_string()),
        });

        let fn2 = graph.graph.add_node(GraphNode::Function {
            file_id: FileId(2),
            name: "verify_token".to_string(),
            qualified_name: "verify_token".to_string(),
            is_async: false,
            is_handler: false,
            http_method: None,
            http_path: None,
        });

        let fn3 = graph.graph.add_node(GraphNode::Function {
            file_id: FileId(3),
            name: "get_user".to_string(),
            qualified_name: "get_user".to_string(),
            is_async: true,
            is_handler: false,
            http_method: None,
            http_path: None,
        });

        // Contains edges
        graph.graph.add_edge(f1, fn1, GraphEdgeKind::Contains);
        graph.graph.add_edge(f2, fn2, GraphEdgeKind::Contains);
        graph.graph.add_edge(f3, fn3, GraphEdgeKind::Contains);

        // Call edges: handle_login -> verify_token -> get_user
        graph.graph.add_edge(fn1, fn2, GraphEdgeKind::Calls);
        graph.graph.add_edge(fn2, fn3, GraphEdgeKind::Calls);

        graph
    }

    #[test]
    fn test_extract_flow() {
        let graph = build_test_graph();
        let flow = extract_flow(&graph, "handle_login", 5);

        assert!(!flow.roots.is_empty());
        assert_eq!(flow.roots[0].name, "handle_login");
        assert!(!flow.paths.is_empty());
        // Path should go: handle_login -> verify_token -> get_user
        let longest_path = flow.paths.iter().max_by_key(|p| p.len()).unwrap();
        assert_eq!(longest_path.len(), 3);
        assert_eq!(longest_path[0].name, "handle_login");
        assert_eq!(longest_path[1].name, "verify_token");
        assert_eq!(longest_path[2].name, "get_user");
    }

    #[test]
    fn test_get_impact() {
        let graph = build_test_graph();
        let impact = get_impact(&graph, "src/db.py", 5);

        // Changing db.py should affect auth.py and main.py
        assert!(impact.affected_files.contains(&"src/auth.py".to_string()));
        assert!(impact.affected_files.contains(&"src/main.py".to_string()));
    }

    #[test]
    fn test_get_dependencies() {
        let graph = build_test_graph();
        let deps = get_dependencies(&graph, "src/main.py");

        assert!(deps.dependencies.contains(&"src/auth.py".to_string()));
    }

    #[test]
    fn test_get_centrality() {
        let graph = build_test_graph();
        let centrality = get_centrality(&graph, 10);

        // db.py has the most importers (auth imports it)
        // auth.py has main importing it
        assert!(!centrality.central_files.is_empty());
    }

    #[test]
    fn test_enumerate_functions() {
        let graph = build_test_graph();
        let result = enumerate_entities(&graph, "functions");

        assert_eq!(result.count, 3);
        assert!(result.items.contains(&"handle_login".to_string()));
        assert!(result.items.contains(&"verify_token".to_string()));
        assert!(result.items.contains(&"get_user".to_string()));
    }

    #[test]
    fn test_enumerate_files() {
        let graph = build_test_graph();
        let result = enumerate_entities(&graph, "files");

        assert_eq!(result.count, 3);
    }

    #[test]
    fn test_enumerate_routes() {
        let graph = build_test_graph();
        let result = enumerate_entities(&graph, "routes");

        // handle_login is a handler
        assert_eq!(result.count, 1);
        assert!(result.items.contains(&"handle_login".to_string()));
    }

    #[test]
    fn test_workspace_overview() {
        let graph = build_test_graph();
        let overview = workspace_overview(&graph);

        assert_eq!(overview.file_count, 3);
        assert_eq!(overview.function_count, 3);
        assert!(overview.languages.contains(&"Python".to_string()));
    }

    #[test]
    fn test_impact_unknown_target() {
        let graph = build_test_graph();
        let impact = get_impact(&graph, "nonexistent.py", 5);
        assert!(impact.affected_files.is_empty());
    }

    #[test]
    fn test_flow_unknown_target() {
        let graph = build_test_graph();
        let flow = extract_flow(&graph, "nonexistent_fn", 5);
        assert!(flow.roots.is_empty());
        assert!(flow.paths.is_empty());
    }
}
