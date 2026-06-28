//! Graph traversal queries.

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::Direction;
use petgraph::visit::EdgeRef;

use crate::graph::{CodeGraph, GraphEdgeKind, GraphNode};
use crate::types::graph_query::{
    BriefContext, BriefRoute, BriefSize, CallerInfo, CallerKind, CallersContext, EntryPoint,
    EntryPointReason, EnumerateContext, ExportedSymbol, FlowContext, FlowPathNode,
    FunctionSuggestion, GraphContext, HandlerInfo, HandlersContext, IncomingImport, PathContext,
    RouteInfo, SiblingInfo, WorkspaceContext,
};

pub fn extract_flow(
    graph: &CodeGraph,
    target: &str,
    file_hint: Option<&str>,
    max_depth: usize,
) -> FlowContext {
    let start_indices = find_nodes_by_name_in_file(graph, target, file_hint);
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

/// Heuristic: is this a wiring/bootstrap call rather than a business-logic call?
///
/// Returns `Some(CallerKind)` when the caller looks like infrastructure wiring;
/// `None` when it is normal business logic.
fn classify_caller_kind(caller_name: &str, caller_file: Option<&str>) -> CallerKind {
    let name_lower = caller_name.to_lowercase();
    let file_lower = caller_file.unwrap_or("").to_lowercase();

    // App-factory patterns
    if name_lower.contains("create_app")
        || name_lower.contains("create_server")
        || name_lower.contains("make_app")
        || name_lower.contains("build_app")
        || name_lower.contains("init_app")
    {
        return CallerKind::AppFactory;
    }

    // Blueprint / router registration
    if name_lower.contains("register_blueprint")
        || name_lower.contains("include_router")
        || name_lower.contains("add_url_rule")
        || name_lower.contains("mount")
    {
        return CallerKind::BlueprintWiring;
    }

    // Files that are structural entry-points: __init__.py, app.py, main.py,
    // bootstrap/*.py, apps/<component>/__init__.py, etc.
    let is_init = file_lower.ends_with("__init__.py");
    let is_main = file_lower.ends_with("app.py")
        || file_lower.ends_with("main.py")
        || file_lower.ends_with("wsgi.py");
    let is_bootstrap = file_lower.contains("/bootstrap/")
        || file_lower.contains("/components_config")
        || file_lower.contains("_config.py");

    if is_init || is_main || is_bootstrap {
        return CallerKind::AppEntrypoint;
    }

    CallerKind::BusinessLogic
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

    // Detect disambiguation situation: multiple functions share this name and no file
    // hint was provided.  Surface this as a caveat so the caller can act on it.
    let disambiguation_caveat: Option<String> = if file_hint.is_none() && start_indices.len() > 1 {
        let locations: Vec<String> = start_indices
            .iter()
            .filter_map(|&idx| node_file_path(graph, &graph.graph[idx]))
            .collect();
        Some(format!(
            "{} functions named '{}' found across {} files — results merged; use file:function syntax to disambiguate (e.g. {}:{})",
            start_indices.len(),
            target,
            locations.len(),
            locations.first().cloned().unwrap_or_default(),
            target,
        ))
    } else {
        None
    };

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

                    let kind = classify_caller_kind(&caller_name, file_path.as_deref());
                    let caller_is_writer =
                        if let GraphNode::Function { is_writer, .. } = caller_node {
                            *is_writer
                        } else {
                            false
                        };
                    all_callers.push(CallerInfo {
                        name: caller_name,
                        file: file_path,
                        depth: depth + 1,
                        kind,
                        is_writer: caller_is_writer,
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

    // Resolve target display name and location from the first matched node.
    let first_idx = start_indices.first().copied();
    let target_name = first_idx
        .map(|idx| graph.graph[idx].display_name())
        .unwrap_or_else(|| target.to_string());

    let target_file = first_idx.and_then(|idx| node_file_path(graph, &graph.graph[idx]));

    // Extract line/column from the target node if available.
    let (target_line, target_column) = first_idx
        .map(|idx| {
            if let GraphNode::Function { line, column, .. } = &graph.graph[idx] {
                (*line, *column)
            } else {
                (None, None)
            }
        })
        .unwrap_or((None, None));

    // Siblings: other functions in the same file as the target.
    let siblings: Vec<SiblingInfo> = target_file
        .as_deref()
        .map(|tf| {
            graph
                .graph
                .node_indices()
                .filter_map(|idx| {
                    // Skip the target itself.
                    if first_idx == Some(idx) {
                        return None;
                    }
                    let node = &graph.graph[idx];
                    if let GraphNode::Function {
                        name,
                        http_method,
                        http_path,
                        ..
                    } = node
                    {
                        if node_file_path(graph, node).as_deref() == Some(tf) {
                            return Some(SiblingInfo {
                                name: name.clone(),
                                http_method: http_method.clone(),
                                http_path: http_path.clone(),
                            });
                        }
                    }
                    None
                })
                .collect()
        })
        .unwrap_or_default();

    // Caveats: flag known static-analysis blind spots.
    let mut caveats: Vec<String> = disambiguation_caveat.into_iter().collect();

    // If the target file imports from event-pipeline modules, note the gap.
    if let Some(ref tf) = target_file {
        let file_imports_event_pipeline = graph.graph.node_indices().any(|idx| {
            if let GraphNode::File { path, .. } = &graph.graph[idx] {
                if path != tf {
                    return false;
                }
            } else {
                return false;
            }
            // Check UsesLibrary edges for event-pipeline modules.
            graph
                .graph
                .edges_directed(idx, Direction::Outgoing)
                .any(|e| {
                    if !matches!(e.weight(), GraphEdgeKind::UsesLibrary) {
                        return false;
                    }
                    if let GraphNode::ExternalModule { name, .. } = &graph.graph[e.target()] {
                        let n = name.to_lowercase();
                        n.contains("events_pipeline")
                            || n.contains("event_pipeline")
                            || n.contains("kafka")
                            || n.contains("celery")
                            || n.contains("dramatiq")
                            || n.contains("rq")
                            || n.contains("huey")
                    } else {
                        false
                    }
                })
        });

        if file_imports_event_pipeline {
            caveats.push(
                "event-pipeline consumers not traced: callers via message queue are invisible to the static graph".to_string(),
            );
        }
    }

    CallersContext {
        target: target_name,
        target_file,
        target_line,
        target_column,
        callers: all_callers,
        routes,
        siblings,
        caveats,
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

    let mut seen: HashSet<(String, String, String, String)> = HashSet::new();

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
                decorators,
                is_writer,
                line,
                column,
                request_schema,
                response_schema,
                ..
            } = node
            {
                if path_matches_pattern(path, &lower_pattern) {
                    let file = node_file_path(graph, node).unwrap_or_default();
                    let key = (method.clone(), path.clone(), name.clone(), file.clone());
                    if !seen.insert(key) {
                        return None;
                    }
                    Some(HandlerInfo {
                        method: method.clone(),
                        path: path.clone(),
                        handler: name.clone(),
                        file,
                        is_async: *is_async,
                        line: *line,
                        column: *column,
                        decorators: decorators.clone(),
                        is_writer: *is_writer,
                        request_schema: request_schema.clone(),
                        response_schema: response_schema.clone(),
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

/// Produce a structural brief for all code within a subtree path prefix.
///
/// `subtree` is matched as a path prefix/substring against every file node's
/// path (same semantics as `routes --file`).  A file is considered "inside"
/// when its path contains `subtree` as a substring, so both relative prefixes
/// (`apps/payroll_tool`) and bare component names (`payroll_tool`) work.
pub fn get_brief(graph: &CodeGraph, subtree: &str) -> BriefContext {
    // ── Classify every file node as inside / outside ─────────────────────────
    // inside_files: set of NodeIndex for File nodes inside the subtree.
    // inside_paths: set of path strings inside the subtree (for quick membership).
    let mut inside_file_ids: HashSet<crate::parse::ast::FileId> = HashSet::new();
    let mut inside_paths: HashSet<String> = HashSet::new();

    for idx in graph.graph.node_indices() {
        if let GraphNode::File { file_id, path, .. } = &graph.graph[idx] {
            if path.contains(subtree) {
                inside_file_ids.insert(*file_id);
                inside_paths.insert(path.clone());
            }
        }
    }

    if inside_file_ids.is_empty() {
        return BriefContext {
            path: subtree.to_string(),
            ..Default::default()
        };
    }

    // ── Size ─────────────────────────────────────────────────────────────────
    let mut size = BriefSize {
        files: 0,
        functions: 0,
    };
    for idx in graph.graph.node_indices() {
        match &graph.graph[idx] {
            GraphNode::File { file_id, .. } if inside_file_ids.contains(file_id) => {
                size.files += 1;
            }
            GraphNode::Function { file_id, .. } if inside_file_ids.contains(file_id) => {
                size.functions += 1;
            }
            _ => {}
        }
    }

    // ── Routes ───────────────────────────────────────────────────────────────
    let mut routes: Vec<BriefRoute> = Vec::new();
    for idx in graph.graph.node_indices() {
        if let GraphNode::Function {
            file_id,
            name,
            is_handler: true,
            http_method: Some(method),
            http_path: Some(path),
            decorators,
            is_writer,
            line,
            request_schema,
            response_schema,
            ..
        } = &graph.graph[idx]
        {
            if inside_file_ids.contains(file_id) {
                let file = node_file_path(graph, &graph.graph[idx]).unwrap_or_default();
                routes.push(BriefRoute {
                    method: method.clone(),
                    path: path.clone(),
                    handler: name.clone(),
                    file,
                    line: *line,
                    decorators: decorators.clone(),
                    is_writer: *is_writer,
                    request_schema: request_schema.clone(),
                    response_schema: response_schema.clone(),
                });
            }
        }
    }
    routes.sort_by(|a, b| a.file.cmp(&b.file).then(a.path.cmp(&b.path)));

    // ── Outgoing exports: symbols defined inside, imported from outside ───────
    // Walk every ImportsFrom / Imports edge.  Source = importing file (outside),
    // target = imported file (inside) → the items are exported symbols.
    //
    // key: (defined_in_path, symbol_name) → Vec<importer_path>
    let mut exports_map: HashMap<(String, String), Vec<String>> = HashMap::new();

    for edge_idx in graph.graph.edge_indices() {
        let (source_idx, target_idx) = graph.graph.edge_endpoints(edge_idx).unwrap();
        let edge = graph.graph.edge_weight(edge_idx).unwrap();

        let source_path = match &graph.graph[source_idx] {
            GraphNode::File { path, .. } => path.clone(),
            _ => continue,
        };
        let target_path = match &graph.graph[target_idx] {
            GraphNode::File { path, .. } => path.clone(),
            _ => continue,
        };

        let source_inside = inside_paths.contains(&source_path);
        let target_inside = inside_paths.contains(&target_path);

        match edge {
            GraphEdgeKind::ImportsFrom { items } if !source_inside && target_inside => {
                // Outside code imports specific symbols from inside.
                for sym in items {
                    exports_map
                        .entry((target_path.clone(), sym.clone()))
                        .or_default()
                        .push(source_path.clone());
                }
            }
            GraphEdgeKind::Imports if !source_inside && target_inside => {
                // Outside code does a whole-module import of an inside file.
                // Treat the file itself as an exported symbol named "*".
                exports_map
                    .entry((target_path.clone(), "*".to_string()))
                    .or_default()
                    .push(source_path.clone());
            }
            _ => {}
        }
    }

    let mut outgoing_exports: Vec<ExportedSymbol> = exports_map
        .into_iter()
        .map(|((defined_in, name), mut imported_by)| {
            imported_by.sort();
            imported_by.dedup();
            ExportedSymbol {
                name,
                defined_in,
                imported_by,
            }
        })
        .collect();
    outgoing_exports.sort_by(|a, b| a.defined_in.cmp(&b.defined_in).then(a.name.cmp(&b.name)));

    // ── Incoming imports: outside deps imported into the subtree ─────────────
    // Walk edges where source is inside, target is outside (or ExternalModule).
    // key: source_display (file path or module name) → (symbols, importers)
    let mut imports_map: HashMap<String, (Vec<String>, Vec<String>)> = HashMap::new();

    for edge_idx in graph.graph.edge_indices() {
        let (source_idx, target_idx) = graph.graph.edge_endpoints(edge_idx).unwrap();
        let edge = graph.graph.edge_weight(edge_idx).unwrap();

        // Source must be a file inside the subtree.
        let source_path = match &graph.graph[source_idx] {
            GraphNode::File { path, .. } => path.clone(),
            _ => continue,
        };
        if !inside_paths.contains(&source_path) {
            continue;
        }

        match edge {
            GraphEdgeKind::ImportsFrom { items } => {
                let dep_name = match &graph.graph[target_idx] {
                    GraphNode::File { path, .. } if !inside_paths.contains(path) => path.clone(),
                    GraphNode::ExternalModule { name, .. } => name.clone(),
                    _ => continue,
                };
                let entry = imports_map.entry(dep_name).or_default();
                for sym in items {
                    if !entry.0.contains(sym) {
                        entry.0.push(sym.clone());
                    }
                }
                if !entry.1.contains(&source_path) {
                    entry.1.push(source_path.clone());
                }
            }
            GraphEdgeKind::Imports => {
                let dep_name = match &graph.graph[target_idx] {
                    GraphNode::File { path, .. } if !inside_paths.contains(path) => path.clone(),
                    GraphNode::ExternalModule { name, .. } => name.clone(),
                    _ => continue,
                };
                let entry = imports_map.entry(dep_name).or_default();
                if !entry.1.contains(&source_path) {
                    entry.1.push(source_path.clone());
                }
            }
            GraphEdgeKind::UsesLibrary => {
                let lib_name = match &graph.graph[target_idx] {
                    GraphNode::ExternalModule { name, .. } => name.clone(),
                    _ => continue,
                };
                let entry = imports_map.entry(lib_name).or_default();
                if !entry.1.contains(&source_path) {
                    entry.1.push(source_path.clone());
                }
            }
            _ => {}
        }
    }

    let mut incoming_imports: Vec<IncomingImport> = imports_map
        .into_iter()
        .map(|(source, (mut symbols, mut imported_by))| {
            symbols.sort();
            symbols.dedup();
            imported_by.sort();
            imported_by.dedup();
            IncomingImport {
                source,
                symbols,
                imported_by,
            }
        })
        .collect();
    incoming_imports.sort_by(|a, b| a.source.cmp(&b.source));

    // ── Internal entry points ─────────────────────────────────────────────────
    // A function inside the subtree is an entry point when:
    //   (a) it is an HTTP handler (is_handler: true), OR
    //   (b) it has inbound Calls edges exclusively from outside the subtree, OR
    //   (c) it has no inbound Calls edges at all but is exported (appears in outgoing_exports).
    let exported_names: HashSet<String> = outgoing_exports.iter().map(|e| e.name.clone()).collect();

    let mut entry_points: Vec<EntryPoint> = Vec::new();

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        let (file_id, name, is_handler, http_method, http_path, line) = match node {
            GraphNode::Function {
                file_id,
                name,
                is_handler,
                http_method,
                http_path,
                line,
                ..
            } => (file_id, name, *is_handler, http_method, http_path, line),
            _ => continue,
        };

        if !inside_file_ids.contains(file_id) {
            continue;
        }

        let file = node_file_path(graph, node).unwrap_or_default();

        // (a) HTTP handler — already in routes, but also surface as entry point.
        if is_handler {
            entry_points.push(EntryPoint {
                name: name.clone(),
                file,
                line: *line,
                reason: EntryPointReason::HttpHandler,
                http_method: http_method.clone(),
                http_path: http_path.clone(),
            });
            continue;
        }

        // Examine inbound Calls edges.
        let mut inside_callers = 0usize;
        let mut outside_callers = 0usize;
        for edge in graph.graph.edges_directed(idx, Direction::Incoming) {
            if !matches!(edge.weight(), GraphEdgeKind::Calls) {
                continue;
            }
            let caller_node = &graph.graph[edge.source()];
            let caller_inside = caller_node
                .file_id()
                .map(|fid| inside_file_ids.contains(&fid))
                .unwrap_or(false);
            if caller_inside {
                inside_callers += 1;
            } else {
                outside_callers += 1;
            }
        }

        // (b) Has outside callers and no inside callers.
        if outside_callers > 0 && inside_callers == 0 {
            entry_points.push(EntryPoint {
                name: name.clone(),
                file,
                line: *line,
                reason: EntryPointReason::ExternalCallersOnly,
                http_method: None,
                http_path: None,
            });
            continue;
        }

        // (c) No callers at all but is exported.
        if inside_callers == 0 && outside_callers == 0 && exported_names.contains(name.as_str()) {
            entry_points.push(EntryPoint {
                name: name.clone(),
                file,
                line: *line,
                reason: EntryPointReason::ExportedUnused,
                http_method: None,
                http_path: None,
            });
        }
    }

    entry_points.sort_by(|a, b| a.file.cmp(&b.file).then(a.name.cmp(&b.name)));

    BriefContext {
        path: subtree.to_string(),
        routes,
        outgoing_exports,
        incoming_imports,
        internal_entry_points: entry_points,
        size,
    }
}
