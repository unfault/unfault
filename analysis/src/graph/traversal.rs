//! Graph traversal queries.

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::Direction;
use petgraph::visit::EdgeRef;

use crate::graph::{CodeGraph, GraphEdgeKind, GraphNode};
use crate::types::graph_query::{
    CallerInfo, CallersContext, EnumerateContext, FlowContext, FlowPathNode, FunctionSuggestion,
    GraphContext, HandlerInfo, HandlersContext, PathContext, RouteInfo, WorkspaceContext,
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

/// Walk inbound `Calls` edges from `target` up to `max_depth` hops and collect
/// the callers together with any HTTP routes that anchor the call chain.
///
/// This is the "you are here" reverse-BFS: given a function name it finds every
/// function that (transitively) calls it, and which HTTP routes those callers are
/// reachable from.
pub fn get_callers(graph: &CodeGraph, target: &str, max_depth: usize) -> CallersContext {
    get_callers_impl(graph, target, None, max_depth)
}

/// Like `get_callers` but restricts the starting node search to a specific file.
/// Use this when the caller supplies `file.py:function_name` to avoid matching
/// same-named functions in other files.
pub fn get_callers_in_file(
    graph: &CodeGraph,
    target: &str,
    file_hint: &str,
    max_depth: usize,
) -> CallersContext {
    get_callers_impl(graph, target, Some(file_hint), max_depth)
}

fn get_callers_impl(
    graph: &CodeGraph,
    target: &str,
    file_hint: Option<&str>,
    max_depth: usize,
) -> CallersContext {
    let start_indices = find_nodes_by_name_in_file(graph, target, file_hint);
    if start_indices.is_empty() {
        return CallersContext::default();
    }

    // Collect all callers via reverse BFS over Calls edges.
    let mut all_callers: Vec<CallerInfo> = Vec::new();
    let mut routes: Vec<RouteInfo> = Vec::new();
    let mut seen_callers: HashSet<String> = HashSet::new();
    let mut seen_routes: HashSet<String> = HashSet::new();

    for start_idx in &start_indices {
        let mut visited: HashSet<petgraph::graph::NodeIndex> = HashSet::new();
        let mut queue: VecDeque<(petgraph::graph::NodeIndex, usize)> = VecDeque::new();

        visited.insert(*start_idx);
        queue.push_back((*start_idx, 0));

        while let Some((current, depth)) = queue.pop_front() {
            if depth >= max_depth {
                continue;
            }

            for edge in graph.graph.edges_directed(current, Direction::Incoming) {
                if !matches!(edge.weight(), GraphEdgeKind::Calls) {
                    continue;
                }
                let caller_idx = edge.source();
                if visited.contains(&caller_idx) {
                    continue;
                }
                visited.insert(caller_idx);

                let caller_node = &graph.graph[caller_idx];
                let caller_name = caller_node.display_name();

                // Collect the caller
                if !seen_callers.contains(&caller_name) {
                    seen_callers.insert(caller_name.clone());
                    let file_path = node_file_path(graph, caller_node);

                    // Check if this caller itself is an HTTP handler
                    if let GraphNode::Function {
                        is_handler: true,
                        http_method,
                        http_path: Some(path),
                        ..
                    } = caller_node
                    {
                        let route_key =
                            format!("{} {}", http_method.as_deref().unwrap_or("*"), path);
                        if !seen_routes.contains(&route_key) {
                            seen_routes.insert(route_key);
                            routes.push(RouteInfo {
                                method: http_method.clone().unwrap_or_else(|| "*".to_string()),
                                path: path.clone(),
                            });
                        }
                    }

                    all_callers.push(CallerInfo {
                        name: caller_name,
                        file: file_path,
                        depth: depth + 1,
                    });
                }

                queue.push_back((caller_idx, depth + 1));
            }

            // Also look for FastApiRoute nodes that contain (via Contains edge) the current
            // function — these represent the HTTP entry points for the chain.
            for edge in graph.graph.edges_directed(current, Direction::Incoming) {
                if !matches!(edge.weight(), GraphEdgeKind::Contains) {
                    continue;
                }
                let parent_idx = edge.source();
                let parent_node = &graph.graph[parent_idx];
                match parent_node {
                    GraphNode::FastApiRoute {
                        http_method, path, ..
                    } => {
                        let route_key = format!("{} {}", http_method, path);
                        if !seen_routes.contains(&route_key) {
                            seen_routes.insert(route_key);
                            routes.push(RouteInfo {
                                method: http_method.clone(),
                                path: path.clone(),
                            });
                        }
                    }
                    GraphNode::Function {
                        is_handler: true,
                        http_method,
                        http_path: Some(path),
                        ..
                    } => {
                        let route_key =
                            format!("{} {}", http_method.as_deref().unwrap_or("*"), path);
                        if !seen_routes.contains(&route_key) {
                            seen_routes.insert(route_key);
                            routes.push(RouteInfo {
                                method: http_method.clone().unwrap_or_else(|| "*".to_string()),
                                path: path.clone(),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Sort callers by depth ascending so the direct callers appear first.
    all_callers.sort_by_key(|c| c.depth);

    // Resolve target display name from the first matched node.
    let target_name = start_indices
        .first()
        .map(|&idx| graph.graph[idx].display_name())
        .unwrap_or_else(|| target.to_string());

    let target_file = start_indices
        .first()
        .and_then(|&idx| node_file_path(graph, &graph.graph[idx]));

    CallersContext {
        target: target_name,
        target_file,
        callers: all_callers,
        routes,
    }
}

/// Suggest candidate functions when a callers query returns no results.
///
/// Returns up to three lists:
/// - Fuzzy name matches (token overlap with the queried name) when the function
///   is not found in the graph at all.
/// - HTTP route handlers in the same file as the found function, when the
///   function exists but has no recorded call edges (cross-file calls are not
///   yet resolved by the graph builder).
/// - The most-called functions in the workspace as a fallback.
pub fn suggest_callers_candidates(
    graph: &CodeGraph,
    target: &str,
    target_file: Option<&str>,
) -> Vec<FunctionSuggestion> {
    let lower = target.to_lowercase();
    // Split on common separators to get meaningful tokens.
    let tokens: Vec<&str> = lower
        .split(|c: char| c == '_' || c == '-' || c == '.')
        .filter(|t| t.len() >= 3)
        .collect();

    let mut suggestions: Vec<FunctionSuggestion> = Vec::new();

    // ── Case 1: function not in graph → fuzzy name matches ────────────────────
    if target_file.is_none() {
        for idx in graph.graph.node_indices() {
            let node = &graph.graph[idx];
            let GraphNode::Function { name, .. } = node else {
                continue;
            };
            let node_lower = name.to_lowercase();
            // Score: how many query tokens appear in the function name.
            let score = tokens.iter().filter(|t| node_lower.contains(**t)).count();
            if score == 0 {
                continue;
            }
            let file = node_file_path(graph, node).unwrap_or_default();
            let (http_method, http_path) = if let GraphNode::Function {
                http_method,
                http_path,
                ..
            } = node
            {
                (http_method.clone(), http_path.clone())
            } else {
                (None, None)
            };
            suggestions.push(FunctionSuggestion {
                name: name.clone(),
                file,
                http_method,
                http_path,
                reason: format!("fuzzy_match (score {})", score),
            });
        }
        // Sort by score descending, then alphabetically.
        suggestions.sort_by(|a, b| {
            let sa: usize = a
                .reason
                .trim_start_matches("fuzzy_match (score ")
                .trim_end_matches(')')
                .parse()
                .unwrap_or(0);
            let sb: usize = b
                .reason
                .trim_start_matches("fuzzy_match (score ")
                .trim_end_matches(')')
                .parse()
                .unwrap_or(0);
            sb.cmp(&sa).then(a.name.cmp(&b.name))
        });
        suggestions.truncate(8);
        return suggestions;
    }

    // ── Case 2: function found but no call edges ───────────────────────────────
    // Show HTTP handlers in the same file — these are the routes that likely
    // call this function transitively but whose edges weren't resolved.
    let file = target_file.unwrap_or("");

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        if let GraphNode::Function {
            name,
            is_handler: true,
            http_method: Some(method),
            http_path: Some(path),
            ..
        } = node
        {
            let node_file = node_file_path(graph, node).unwrap_or_default();
            if node_file == file {
                suggestions.push(FunctionSuggestion {
                    name: name.clone(),
                    file: node_file,
                    http_method: Some(method.clone()),
                    http_path: Some(path.clone()),
                    reason: "same_file_handler".into(),
                });
            }
        }
    }

    // Also check FastApiRoute nodes contained in the same file.
    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        if let GraphNode::FastApiRoute {
            file_id,
            http_method,
            path,
        } = node
        {
            if let Some(&file_idx) = graph.file_nodes.get(file_id) {
                if let GraphNode::File {
                    path: ref file_path,
                    ..
                } = graph.graph[file_idx]
                {
                    if file_path == file {
                        suggestions.push(FunctionSuggestion {
                            name: format!("{} {}", http_method, path),
                            file: file_path.clone(),
                            http_method: Some(http_method.clone()),
                            http_path: Some(path.clone()),
                            reason: "same_file_handler".into(),
                        });
                    }
                }
            }
        }
    }

    // Deduplicate: prefer the Function entry over the FastApiRoute entry for the same route.
    // Key on (http_method, http_path) when both are set, otherwise on (name, file).
    {
        let mut seen_routes: HashSet<(String, String)> = HashSet::new();
        suggestions.retain(|s| {
            if let (Some(m), Some(p)) = (&s.http_method, &s.http_path) {
                seen_routes.insert((m.clone(), p.clone()))
            } else {
                true
            }
        });
    }

    // ── If no same-file handlers, look in sibling files (same directory) ──────
    if suggestions.is_empty() {
        // Derive the directory of the target file.
        let dir = file.rsplitn(2, '/').last().unwrap_or("");

        for idx in graph.graph.node_indices() {
            let node = &graph.graph[idx];
            if let GraphNode::Function {
                name,
                is_handler: true,
                http_method: Some(method),
                http_path: Some(path),
                ..
            } = node
            {
                let node_file = node_file_path(graph, node).unwrap_or_default();
                // Same directory prefix (e.g. reliably_app/assistant/).
                if !dir.is_empty() && node_file.starts_with(dir) {
                    suggestions.push(FunctionSuggestion {
                        name: name.clone(),
                        file: node_file,
                        http_method: Some(method.clone()),
                        http_path: Some(path.clone()),
                        reason: "sibling_file_handler".into(),
                    });
                }
            }
        }

        {
            let mut seen_routes: HashSet<(String, String)> = HashSet::new();
            suggestions.retain(|s| {
                if let (Some(m), Some(p)) = (&s.http_method, &s.http_path) {
                    seen_routes.insert((m.clone(), p.clone()))
                } else {
                    true
                }
            });
        }
    }

    suggestions
}

fn find_nodes_by_name(graph: &CodeGraph, target: &str) -> Vec<petgraph::graph::NodeIndex> {
    find_nodes_by_name_in_file(graph, target, None)
}

/// Find graph nodes matching `target`, optionally restricted to nodes whose
/// file path contains `file_hint` (suffix match).  When `file_hint` is
/// provided and yields matches, nodes from other files are excluded, so that
/// `service.py:get` doesn't pull in every `get` function across the workspace.
fn find_nodes_by_name_in_file(
    graph: &CodeGraph,
    target: &str,
    file_hint: Option<&str>,
) -> Vec<petgraph::graph::NodeIndex> {
    let lower_target = target.to_lowercase();

    // Fast path: exact file path lookup (no function involved).
    if file_hint.is_none() {
        if let Some(&idx) = graph.path_to_file.get(target) {
            return vec![idx];
        }
    }

    let mut all: Vec<petgraph::graph::NodeIndex> = Vec::new();

    // Also match names that differ only by a leading underscore prefix
    // (e.g. querying "my_function" should find "_my_function" in the graph).
    let lower_target_underscored = format!("_{}", lower_target);

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        let name = node.display_name().to_lowercase();
        let matches_name = name == lower_target
            || name == lower_target_underscored
            || name.ends_with(&format!(".{}", lower_target))
            || name.ends_with(&format!(".{}", lower_target_underscored))
            || name.contains(&format!("/{}", lower_target));
        if !matches_name {
            continue;
        }
        all.push(idx);
    }

    // If a file hint was given, prefer nodes whose file path ends with the hint.
    if let Some(hint) = file_hint {
        let lower_hint = hint.to_lowercase();
        let constrained: Vec<_> = all
            .iter()
            .copied()
            .filter(|&idx| {
                node_file_path(graph, &graph.graph[idx])
                    .map(|p| p.to_lowercase().ends_with(&lower_hint))
                    .unwrap_or(false)
            })
            .collect();
        // Only apply the constraint when it actually narrows results.
        if !constrained.is_empty() {
            return constrained;
        }
    }

    all
}

/// Public wrapper around `node_file_path` for use in CLI code.
pub fn node_file_path_pub(graph: &CodeGraph, node: &GraphNode) -> Option<String> {
    node_file_path(graph, node)
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
        GraphNode::Slo { .. } => "slo",
        GraphNode::RemoteService { .. } => "remote_service",
    }
}

/// Find the shortest call path from one named function to another.
///
/// Uses BFS over outgoing `Calls` edges from `from_name`, stopping as soon as
/// a node matching `to_name` is reached. Returns the path as an ordered list
/// of `FlowPathNode`s from `from` to `to` (inclusive).
///
/// Also resolves any HTTP routes that can trigger `from_name` (via reverse BFS)
/// so the caller knows the full ingress → egress chain.
pub fn find_path(
    graph: &CodeGraph,
    from_name: &str,
    from_hint: Option<&str>,
    to_name: &str,
    to_hint: Option<&str>,
) -> PathContext {
    let from_nodes = find_nodes_by_name_in_file(graph, from_name, from_hint);
    let to_nodes: HashSet<petgraph::graph::NodeIndex> =
        find_nodes_by_name_in_file(graph, to_name, to_hint)
            .into_iter()
            .collect();

    if from_nodes.is_empty() || to_nodes.is_empty() {
        return PathContext {
            from: from_name.to_string(),
            to: to_name.to_string(),
            found: false,
            ..Default::default()
        };
    }

    // BFS: each queue entry is (current_node, path_so_far)
    for start in &from_nodes {
        let mut visited: HashSet<petgraph::graph::NodeIndex> = HashSet::new();
        let mut queue: VecDeque<(petgraph::graph::NodeIndex, Vec<petgraph::graph::NodeIndex>)> =
            VecDeque::new();

        visited.insert(*start);
        queue.push_back((*start, vec![*start]));

        while let Some((current, path)) = queue.pop_front() {
            if to_nodes.contains(&current) && current != *start {
                // Found — convert node indices to FlowPathNodes.
                let flow_path: Vec<FlowPathNode> = path
                    .iter()
                    .enumerate()
                    .map(|(depth, &idx)| {
                        let node = &graph.graph[idx];
                        FlowPathNode {
                            name: node.display_name(),
                            file_path: node_file_path(graph, node),
                            node_type: node_type_str(node).to_string(),
                            depth,
                        }
                    })
                    .collect();

                // Resolve entry routes by walking inbound Calls edges from the
                // start node upward (same logic as get_callers, depth=1 only).
                let mut entry_routes: Vec<RouteInfo> = Vec::new();
                let mut seen_routes: HashSet<String> = HashSet::new();
                for edge in graph.graph.edges_directed(*start, Direction::Incoming) {
                    if !matches!(edge.weight(), GraphEdgeKind::Calls) {
                        continue;
                    }
                    let caller = &graph.graph[edge.source()];
                    if let GraphNode::Function {
                        is_handler: true,
                        http_method,
                        http_path: Some(p),
                        ..
                    } = caller
                    {
                        let key = format!("{} {}", http_method.as_deref().unwrap_or("*"), p);
                        if seen_routes.insert(key) {
                            entry_routes.push(RouteInfo {
                                method: http_method.clone().unwrap_or_else(|| "*".to_string()),
                                path: p.clone(),
                            });
                        }
                    }
                }

                return PathContext {
                    from: from_name.to_string(),
                    to: to_name.to_string(),
                    found: true,
                    path: flow_path,
                    entry_routes,
                };
            }

            for edge in graph.graph.edges_directed(current, Direction::Outgoing) {
                if !matches!(edge.weight(), GraphEdgeKind::Calls) {
                    continue;
                }
                let next = edge.target();
                if visited.insert(next) {
                    let mut new_path = path.clone();
                    new_path.push(next);
                    queue.push_back((next, new_path));
                }
            }
        }
    }

    PathContext {
        from: from_name.to_string(),
        to: to_name.to_string(),
        found: false,
        ..Default::default()
    }
}

/// Find all HTTP route handlers whose path matches a glob-style pattern.
///
/// Pattern rules:
/// - `*` matches any sequence of characters within a single path segment
/// - `**` matches across segment boundaries (like a path prefix)
/// - Plain strings match as substrings
///
/// Examples: `/users/*`, `/api/**`, `invite` (substring)
pub fn find_handlers(graph: &CodeGraph, pattern: &str) -> HandlersContext {
    let lower_pattern = pattern.to_lowercase();

    let mut handlers: Vec<HandlerInfo> = graph
        .graph
        .node_indices()
        .filter_map(|idx| {
            let node = &graph.graph[idx];
            if let GraphNode::Function {
                is_handler: true,
                http_method: Some(method),
                http_path: Some(path),
                name,
                is_async,
                ..
            } = node
            {
                if path_matches_pattern(path, &lower_pattern) {
                    let file = node_file_path(graph, node).unwrap_or_default();
                    Some(HandlerInfo {
                        method: method.clone(),
                        path: path.clone(),
                        handler: name.clone(),
                        file,
                        is_async: *is_async,
                    })
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    handlers.sort_by(|a, b| a.path.cmp(&b.path).then(a.method.cmp(&b.method)));

    HandlersContext {
        pattern: pattern.to_string(),
        handlers,
    }
}

/// Check whether a route `path` matches a `pattern`.
///
/// Supports:
/// - Exact substring match (no wildcards)
/// - `*` — any characters within one segment (no `/`)
/// - `**` — any characters including `/` (prefix/suffix)
fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    let lower_path = path.to_lowercase();

    // No wildcards — substring match.
    if !pattern.contains('*') {
        return lower_path.contains(pattern);
    }

    // `**` — treat pattern as a prefix/suffix glob by converting to a simple
    // check: split on `**` and verify each part appears in order.
    if pattern.contains("**") {
        let parts: Vec<&str> = pattern.split("**").collect();
        let mut remaining = lower_path.as_str();
        for part in &parts {
            if part.is_empty() {
                continue;
            }
            if let Some(pos) = remaining.find(*part) {
                remaining = &remaining[pos + part.len()..];
            } else {
                return false;
            }
        }
        return true;
    }

    // Single `*` — convert to a simple segment-aware match.
    // Split pattern on `*` and verify each part appears in order
    // without crossing a `/` boundary for single-star.
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut remaining = lower_path.as_str();
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = remaining.find(*part) {
            // For single `*`, the gap between parts must not contain `/`
            // unless we're at the boundary.
            let gap = &remaining[..pos];
            if i > 0 && gap.contains('/') {
                return false;
            }
            remaining = &remaining[pos + part.len()..];
        } else {
            return false;
        }
    }
    true
}
