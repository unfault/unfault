//! Trace enricher — links local code graph nodes to remote services seen
//! in distributed traces.
//!
//! ## What it does
//!
//! 1. Takes the `RemoteCallPattern`s extracted by `GcpTraceProvider`
//!    (or any future trace provider).
//! 2. For each pattern, creates or retrieves a `GraphNode::RemoteService`
//!    node in the `CodeGraph`.
//! 3. Finds local files that make outbound HTTP/RPC calls (using existing
//!    `HttpCall` semantics or local caller names from the trace span data).
//! 4. Creates `GraphEdgeKind::RemoteCall` edges: local file → RemoteService.
//!
//! ## Matching strategy
//!
//! The local caller names extracted from traces (parent span names like
//! "POST /checkout" or "PaymentService.charge") are matched against:
//! - HTTP handler names in the graph (`Function.http_path` / `http_method`)
//! - File paths that contain `HttpCall` patterns (from `RuntimeDependency`)
//!
//! When no match is found, we fall back to linking ALL files that make
//! outbound HTTP calls to the remote service — a conservative over-
//! approximation that never misses a real edge.

use anyhow::Result;
use unfault_core::graph::CodeGraph;

use crate::integration::gcp::trace::RemoteCallPattern;

/// Result of a trace enrichment pass.
#[derive(Debug, Default)]
pub struct TraceEnrichmentResult {
    /// Number of `RemoteService` nodes added to the graph.
    pub remote_services_added: usize,
    /// Number of `RemoteCall` edges created.
    pub edges_added: usize,
    /// Names of remote services that were linked.
    pub linked_services: Vec<String>,
}

/// Enrich a `CodeGraph` with `RemoteService` nodes and `RemoteCall` edges
/// derived from distributed trace data.
///
/// `http_caller_files` is a list of local file paths that are known to make
/// outbound HTTP/RPC calls (typically derived from `RuntimeDependency` records
/// extracted during the analysis pipeline). These are the candidates to link
/// to remote services.
///
/// If `http_caller_files` is empty, no edges are created (conservative — we
/// don't want to link every file speculatively).
pub fn enrich_graph(
    graph: &mut CodeGraph,
    patterns: &[RemoteCallPattern],
    http_caller_files: &[String],
    verbose: bool,
) -> Result<TraceEnrichmentResult> {
    let mut result = TraceEnrichmentResult::default();

    for pattern in patterns {
        if pattern.remote_service_name.is_empty() {
            continue;
        }

        // Add or retrieve the RemoteService node
        let svc_idx = graph.get_or_create_remote_service(
            &pattern.remote_service_name,
            &pattern.remote_endpoint,
            pattern.observed_count,
            pattern.p99_latency_ms,
        );
        result.remote_services_added += 1;
        result
            .linked_services
            .push(pattern.remote_service_name.clone());

        if verbose {
            eprintln!(
                "  trace: remote service '{}' ({} calls{})",
                pattern.remote_service_name,
                pattern.observed_count,
                pattern
                    .p99_latency_ms
                    .map(|p| format!(", p99={:.0}ms", p))
                    .unwrap_or_default()
            );
        }

        // Determine which local files to link to this service.
        // Priority 1: match by local caller names from trace spans.
        let matched_files = match_caller_files(pattern, http_caller_files, graph);

        // Priority 2: if no match found, fall back to all known HTTP callers.
        let files_to_link: Vec<&str> = if matched_files.is_empty() {
            http_caller_files.iter().map(|s| s.as_str()).collect()
        } else {
            matched_files.to_vec()
        };

        for file_path in files_to_link {
            if graph.add_remote_call_edge(file_path, svc_idx) {
                result.edges_added += 1;
                if verbose {
                    eprintln!(
                        "    → {} --[RemoteCall]--> {}",
                        file_path.rsplit('/').next().unwrap_or(file_path),
                        pattern.remote_service_name
                    );
                }
            }
        }
    }

    Ok(result)
}

// ── Caller file matching ──────────────────────────────────────────────────────

/// Try to match the trace-derived local caller names to actual file paths in
/// the graph.
///
/// A caller name like "POST /checkout" is matched against graph Function nodes
/// that have `http_path` containing "checkout". A caller name like
/// "PaymentService.charge" is matched against files containing that function.
fn match_caller_files<'a>(
    pattern: &RemoteCallPattern,
    http_caller_files: &'a [String],
    graph: &CodeGraph,
) -> Vec<&'a str> {
    use unfault_core::graph::GraphNode;

    if pattern.local_callers.is_empty() {
        return vec![];
    }

    let mut matched: Vec<&str> = Vec::new();

    for caller_name in &pattern.local_callers {
        // Try to match against HTTP handler nodes
        for idx in graph.graph.node_indices() {
            let node = &graph.graph[idx];
            if let GraphNode::Function {
                http_path: Some(path),
                name,
                ..
            } = node
            {
                // Match if the caller name contains the route path or function name
                let caller_lower = caller_name.to_lowercase();
                let path_fragment = path.split('/').find(|s| s.len() > 2).unwrap_or(path);
                if caller_lower.contains(path_fragment)
                    || caller_lower.contains(&name.to_lowercase())
                {
                    // Find which file this handler belongs to
                    if let Some(file_path) = find_file_for_function(idx, graph, http_caller_files)
                        && !matched.contains(&file_path)
                    {
                        matched.push(file_path);
                    }
                }
            }
        }
    }

    matched
}

/// Find the file path for a function node, limited to known HTTP caller files.
fn find_file_for_function<'a>(
    func_idx: unfault_core::graph::GraphNodeIndex,
    graph: &CodeGraph,
    candidates: &'a [String],
) -> Option<&'a str> {
    use petgraph::Direction;
    use petgraph::visit::EdgeRef;
    use unfault_core::graph::{GraphEdgeKind, GraphNode};

    // Walk incoming Contains edges to find the parent file
    for edge in graph.graph.edges_directed(func_idx, Direction::Incoming) {
        if !matches!(edge.weight(), GraphEdgeKind::Contains) {
            continue;
        }
        if let GraphNode::File { path, .. } = &graph.graph[edge.source()] {
            // Only return if it's in our candidate set
            if let Some(candidate) = candidates.iter().find(|c| *c == path) {
                return Some(candidate.as_str());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use unfault_core::graph::{CodeGraph, GraphEdgeKind, GraphNode, GraphNodeIndex};
    use unfault_core::parse::ast::FileId;
    use unfault_core::types::context::Language;

    fn make_graph_with_handler() -> (CodeGraph, GraphNodeIndex) {
        let mut graph = CodeGraph::new();

        let file_idx = graph.graph.add_node(GraphNode::File {
            file_id: FileId(1),
            path: "src/checkout.py".to_string(),
            language: Language::Python,
        });
        graph.file_nodes.insert(FileId(1), file_idx);
        graph
            .path_to_file
            .insert("src/checkout.py".to_string(), file_idx);

        let fn_idx = graph.graph.add_node(GraphNode::Function {
            file_id: FileId(1),
            name: "process_checkout".to_string(),
            qualified_name: "process_checkout".to_string(),
            is_async: true,
            is_handler: true,
            http_method: Some("POST".to_string()),
            http_path: Some("/checkout".to_string()),
            decorators: vec![],
            is_writer: false,
            line: None,
            column: None,
            request_schema: None,
            response_schema: None,
            raw_calls: vec![],
        });
        graph
            .graph
            .add_edge(file_idx, fn_idx, GraphEdgeKind::Contains);

        (graph, file_idx)
    }

    #[test]
    fn enrich_creates_remote_service_and_edge() {
        let (mut graph, _) = make_graph_with_handler();
        let patterns = vec![RemoteCallPattern {
            remote_service_name: "inventory-service".to_string(),
            remote_endpoint: "https://inventory-svc:8080".to_string(),
            observed_count: 42,
            p99_latency_ms: Some(12.5),
            local_callers: vec![],
        }];
        let http_callers = vec!["src/checkout.py".to_string()];

        let result = enrich_graph(&mut graph, &patterns, &http_callers, false).unwrap();

        assert_eq!(result.remote_services_added, 1);
        assert_eq!(result.edges_added, 1);
        assert_eq!(result.linked_services[0], "inventory-service");

        // Verify the RemoteService node exists
        let remote_nodes = graph.get_remote_services();
        assert_eq!(remote_nodes.len(), 1);
    }

    #[test]
    fn enrich_no_callers_no_edges() {
        let (mut graph, _) = make_graph_with_handler();
        let patterns = vec![RemoteCallPattern {
            remote_service_name: "payments".to_string(),
            remote_endpoint: String::new(),
            observed_count: 5,
            p99_latency_ms: None,
            local_callers: vec![],
        }];
        // No http_caller_files → no edges (conservative)
        let result = enrich_graph(&mut graph, &patterns, &[], false).unwrap();
        assert_eq!(result.edges_added, 0);
        assert_eq!(result.remote_services_added, 1);
    }

    #[test]
    fn enrich_deduplicates_edges() {
        let (mut graph, _) = make_graph_with_handler();
        let pattern = RemoteCallPattern {
            remote_service_name: "inventory-service".to_string(),
            remote_endpoint: String::new(),
            observed_count: 1,
            p99_latency_ms: None,
            local_callers: vec![],
        };
        let http_callers = vec!["src/checkout.py".to_string()];

        enrich_graph(
            &mut graph,
            std::slice::from_ref(&pattern),
            &http_callers,
            false,
        )
        .unwrap();
        let result2 = enrich_graph(&mut graph, &[pattern], &http_callers, false).unwrap();

        // Second call should add 0 new edges (duplicate)
        assert_eq!(result2.edges_added, 0);
    }
}
