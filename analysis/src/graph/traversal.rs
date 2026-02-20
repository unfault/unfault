//! Graph traversal queries.

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::visit::EdgeRef;
use petgraph::Direction;

use crate::graph::{CodeGraph, GraphEdgeKind, GraphNode};
use crate::types::graph_query::{
    EnumerateContext, FlowContext, FlowPathNode, GraphContext, WorkspaceContext,
};

pub fn extract_flow(graph: &CodeGraph, target: &str, max_depth: usize) -> FlowContext {
    let start_indices = find_nodes_by_name(graph, target);
    if start_indices.is_empty() {
        return FlowContext::default();
    }

    let mut roots = Vec::new();
    let mut all_paths = Vec::new();

    for start_idx in start_indices {
        let node = &graph.graph[start_idx];
        roots.push(node_to_flow_path(graph, node, 0));

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

fn find_nodes_by_name(graph: &CodeGraph, target: &str) -> Vec<petgraph::graph::NodeIndex> {
    let lower_target = target.to_lowercase();
    let mut results = Vec::new();

    if let Some(&idx) = graph.path_to_file.get(target) {
        results.push(idx);
        return results;
    }

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        let name = node.display_name().to_lowercase();
        if name == lower_target
            || name.ends_with(&lower_target)
            || name.contains(&format!("/{}", lower_target))
            || name.contains(&format!(".{}", lower_target))
        {
            results.push(idx);
        }
    }

    results
}

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

fn node_to_flow_path(graph: &CodeGraph, node: &GraphNode, depth: usize) -> FlowPathNode {
    FlowPathNode {
        name: node.display_name(),
        file_path: node_file_path(graph, node),
        node_type: node_type_str(node).to_string(),
        depth,
    }
}

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
