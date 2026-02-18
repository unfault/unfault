//! RAG query orchestrator.
//!
//! Combines intent routing, graph-based retrieval, and vector search
//! into a unified query pipeline.

use unfault_analysis::graph::CodeGraph;

use crate::embeddings::EmbeddingProvider;
use crate::error::RagError;
use crate::retrieval;
use crate::routing;
use crate::store::VectorStore;
use crate::types::{RagResponse, RouteIntent};

/// Configuration for a RAG query.
pub struct QueryConfig {
    /// Maximum depth for graph traversals (flow, impact)
    pub max_depth: usize,
    /// Maximum findings to return from vector search
    pub max_findings: usize,
    /// Top-N for centrality
    pub top_n_centrality: usize,
    /// Workspace ID for scoping vector search
    pub workspace_id: Option<String>,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_findings: 10,
            top_n_centrality: 10,
            workspace_id: None,
        }
    }
}

/// Execute a RAG query against a CodeGraph and optional vector store.
///
/// This is the main entry point for the RAG system. It:
/// 1. Parses the query and classifies intent
/// 2. Routes to graph-based retrieval for structural queries
/// 3. Falls back to vector search for semantic queries
/// 4. Assembles a response with all available context
pub async fn execute_query(
    query_text: &str,
    graph: Option<&CodeGraph>,
    store: Option<&VectorStore>,
    embedding_provider: Option<&dyn EmbeddingProvider>,
    config: &QueryConfig,
) -> Result<RagResponse, RagError> {
    let parsed = routing::parse_query(query_text);
    let mut response = RagResponse {
        intent: format!("{:?}", parsed.intent),
        ..Default::default()
    };

    match parsed.intent {
        RouteIntent::Flow => {
            if let (Some(graph), Some(target)) = (graph, &parsed.target) {
                let flow = retrieval::extract_flow(graph, target, config.max_depth);
                if !flow.roots.is_empty() {
                    response.context_summary =
                        format!("Found {} flow path(s) from '{}'", flow.paths.len(), target);
                    response.flow_context = Some(flow);
                } else {
                    response.context_summary =
                        format!("Could not find '{}' in the code graph", target);
                }
            } else if parsed.target.is_none() {
                response.context_summary =
                    "Flow analysis requires a target. Try: \"how does <function_name> work?\"".to_string();
            } else {
                response.context_summary = "No code graph available for flow analysis".to_string();
            }
        }

        RouteIntent::Impact => {
            if let (Some(graph), Some(target)) = (graph, &parsed.target) {
                let impact = retrieval::get_impact(graph, target, config.max_depth);
                if !impact.affected_files.is_empty() {
                    response.context_summary = format!(
                        "Changing '{}' affects {} file(s)",
                        target,
                        impact.affected_files.len()
                    );
                    response.graph_context = Some(impact);
                } else {
                    response.context_summary =
                        format!("No downstream dependencies found for '{}'", target);
                }
            } else if parsed.target.is_none() {
                response.context_summary =
                    "Impact analysis requires a target. Try: \"what breaks if I change <file>?\""
                        .to_string();
            } else {
                response.context_summary =
                    "No code graph available for impact analysis".to_string();
            }
        }

        RouteIntent::Usage => {
            if let (Some(graph), Some(target)) = (graph, &parsed.target) {
                // Usage is reverse of dependencies: who imports/calls this?
                let impact = retrieval::get_impact(graph, target, 1);
                if !impact.affected_files.is_empty() {
                    response.context_summary = format!(
                        "'{}' is used by {} file(s)",
                        target,
                        impact.affected_files.len()
                    );
                    response.graph_context = Some(impact);
                } else {
                    response.context_summary =
                        format!("No usages found for '{}'", target);
                }
            } else if parsed.target.is_none() {
                response.context_summary =
                    "Usage analysis requires a target. Try: \"who calls <function_name>?\""
                        .to_string();
            } else {
                response.context_summary = "No code graph available for usage analysis".to_string();
            }
        }

        RouteIntent::Dependencies => {
            if let (Some(graph), Some(target)) = (graph, &parsed.target) {
                let deps = retrieval::get_dependencies(graph, target);
                let total = deps.dependencies.len() + deps.library_users.len();
                if total > 0 {
                    response.context_summary = format!(
                        "'{}' depends on {} internal module(s) and {} external library/libraries",
                        target,
                        deps.dependencies.len(),
                        deps.library_users.len()
                    );
                    response.graph_context = Some(deps);
                } else {
                    response.context_summary =
                        format!("No dependencies found for '{}'", target);
                }
            } else if parsed.target.is_none() {
                response.context_summary =
                    "Dependency analysis requires a target. Try: \"what does <file> depend on?\""
                        .to_string();
            } else {
                response.context_summary =
                    "No code graph available for dependency analysis".to_string();
            }
        }

        RouteIntent::Centrality => {
            if let Some(graph) = graph {
                let centrality = retrieval::get_centrality(graph, config.top_n_centrality);
                if !centrality.central_files.is_empty() {
                    response.context_summary = format!(
                        "Top {} most central files by import count",
                        centrality.central_files.len()
                    );
                    response.graph_context = Some(centrality);
                } else {
                    response.context_summary =
                        "No import relationships found in the code graph".to_string();
                }
            } else {
                response.context_summary =
                    "No code graph available for centrality analysis".to_string();
            }
        }

        RouteIntent::Enumerate => {
            if let Some(graph) = graph {
                // Guess what to enumerate from the query
                let entity_type = guess_entity_type(query_text);
                let enumerate = retrieval::enumerate_entities(graph, &entity_type);
                response.context_summary = format!(
                    "Found {} {}",
                    enumerate.count, enumerate.entity_type
                );
                response.enumerate_context = Some(enumerate);
            } else {
                response.context_summary =
                    "No code graph available for enumeration".to_string();
            }
        }

        RouteIntent::Overview => {
            if let Some(graph) = graph {
                let overview = retrieval::workspace_overview(graph);
                response.context_summary = format!(
                    "Workspace: {} files, {} functions, languages: {}",
                    overview.file_count,
                    overview.function_count,
                    overview.languages.join(", ")
                );
                response.workspace_context = Some(overview);
            } else {
                response.context_summary =
                    "No code graph available for workspace overview".to_string();
            }
        }

        RouteIntent::Semantic => {
            // Vector search path: embed query and search
            if let (Some(store), Some(provider)) = (store, embedding_provider) {
                let query_embedding = provider.embed(query_text).await?;
                let findings = store
                    .search(
                        &query_embedding,
                        config.max_findings,
                        config.workspace_id.as_deref(),
                    )
                    .await?;

                if !findings.is_empty() {
                    response.context_summary = format!(
                        "Found {} relevant finding(s) matching your query",
                        findings.len()
                    );
                    response.findings = findings;
                } else {
                    response.context_summary =
                        "No findings matched your query. Try running `unfault review` first."
                            .to_string();
                }
            } else {
                response.context_summary =
                    "No embedding provider configured. Set up an LLM provider in .unfault.toml"
                        .to_string();
            }
        }
    }

    Ok(response)
}

/// Guess what entity type to enumerate from the query text.
fn guess_entity_type(query: &str) -> String {
    let lower = query.to_lowercase();

    if lower.contains("route") || lower.contains("endpoint") {
        "routes".to_string()
    } else if lower.contains("function") || lower.contains("method") {
        "functions".to_string()
    } else if lower.contains("class") || lower.contains("struct") || lower.contains("type") {
        "classes".to_string()
    } else if lower.contains("file") || lower.contains("module") {
        "files".to_string()
    } else if lower.contains("librar") || lower.contains("dependenc") || lower.contains("package")
    {
        "libraries".to_string()
    } else {
        // Default to files
        "files".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_graph() -> CodeGraph {
        let mut graph = CodeGraph::new();
        use unfault_analysis::graph::{GraphEdgeKind, GraphNode};
        use unfault_analysis::parse::ast::FileId;
        use unfault_analysis::types::context::Language;

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

        graph.graph.add_edge(f1, f2, GraphEdgeKind::Imports);
        graph.graph.add_edge(f2, f3, GraphEdgeKind::Imports);

        let fn1 = graph.graph.add_node(GraphNode::Function {
            file_id: FileId(1),
            name: "handle_login".to_string(),
            qualified_name: "handle_login".to_string(),
            is_async: true,
            is_handler: true,
            http_method: Some("POST".to_string()),
            http_path: Some("/login".to_string()),
        });
        graph.graph.add_edge(f1, fn1, GraphEdgeKind::Contains);

        graph
    }

    #[tokio::test]
    async fn test_execute_overview_query() {
        let graph = build_test_graph();
        let config = QueryConfig::default();

        let response = execute_query(
            "describe this project",
            Some(&graph),
            None,
            None,
            &config,
        )
        .await
        .unwrap();

        assert_eq!(response.intent, "Overview");
        assert!(response.workspace_context.is_some());
        let ws = response.workspace_context.unwrap();
        assert_eq!(ws.file_count, 3);
    }

    #[tokio::test]
    async fn test_execute_impact_query() {
        let graph = build_test_graph();
        let config = QueryConfig::default();

        let response = execute_query(
            "what breaks if I change src/db.py?",
            Some(&graph),
            None,
            None,
            &config,
        )
        .await
        .unwrap();

        assert_eq!(response.intent, "Impact");
        assert!(response.graph_context.is_some());
        let ctx = response.graph_context.unwrap();
        assert!(!ctx.affected_files.is_empty());
    }

    #[tokio::test]
    async fn test_execute_enumerate_query() {
        let graph = build_test_graph();
        let config = QueryConfig::default();

        let response = execute_query(
            "how many files do we have?",
            Some(&graph),
            None,
            None,
            &config,
        )
        .await
        .unwrap();

        assert_eq!(response.intent, "Enumerate");
        assert!(response.enumerate_context.is_some());
        let ctx = response.enumerate_context.unwrap();
        assert_eq!(ctx.count, 3);
    }

    #[tokio::test]
    async fn test_execute_semantic_no_provider() {
        let config = QueryConfig::default();

        let response = execute_query(
            "are there security issues?",
            None,
            None,
            None,
            &config,
        )
        .await
        .unwrap();

        assert_eq!(response.intent, "Semantic");
        assert!(response.context_summary.contains("No embedding provider"));
    }

    #[test]
    fn test_guess_entity_type() {
        assert_eq!(guess_entity_type("how many routes?"), "routes");
        assert_eq!(guess_entity_type("list all functions"), "functions");
        assert_eq!(guess_entity_type("how many files?"), "files");
        assert_eq!(guess_entity_type("list all classes"), "classes");
        assert_eq!(guess_entity_type("count dependencies"), "libraries");
    }
}
