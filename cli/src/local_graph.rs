//! Local graph building helper.
//!
//! Builds an in-memory CodeGraph from the current workspace using unfault-core
//! for parsing and unfault-analysis for graph construction.

use anyhow::{Context, Result};
use colored::Colorize;

/// Build a CodeGraph and the per-file semantics together.
///
/// Like `build_analysis_graph` but also returns the semantics entries so
/// callers can inspect `http_calls`, `orm_queries`, etc. per file.
pub fn build_analysis_graph_with_semantics(
    workspace_path: &std::path::Path,
    verbose: bool,
) -> Result<(
    unfault_analysis::graph::CodeGraph,
    Vec<unfault_core::semantics::SourceSemantics>,
)> {
    use crate::session::ir_builder::build_ir_cached;

    let build_result = build_ir_cached(workspace_path, None, verbose)
        .context("Failed to build IR for graph analysis")?;

    let semantics = build_result.ir.semantics;
    let graph = unfault_analysis::graph::CodeGraph::from(build_result.ir.graph);

    Ok((graph, semantics))
}

/// Build a CodeGraph from the workspace by parsing all source files.
///
/// This builds the same IR that the review command uses, then extracts
/// the graph from it. The graph can be queried for impact, dependencies,
/// centrality, etc.
pub fn build_analysis_graph(
    workspace_path: &std::path::Path,
    verbose: bool,
) -> Result<unfault_analysis::graph::CodeGraph> {
    use crate::session::ir_builder::{build_ir_cached, try_load_code_graph_only};

    if verbose {
        eprintln!(
            "{} Building code graph for: {}",
            "→".cyan(),
            workspace_path.display()
        );
    }

    if let Some(graph) =
        try_load_code_graph_only(workspace_path, verbose).context("Failed to check graph cache")?
    {
        let graph = unfault_analysis::graph::CodeGraph::from(graph);

        if verbose {
            eprintln!(
                "{} Graph: {} files, {} functions",
                "✓".green(),
                graph.file_nodes.len(),
                graph.function_nodes.len()
            );
        }

        return Ok(graph);
    }

    // Build IR (parses files, builds semantics, constructs graph)
    let build_result = build_ir_cached(workspace_path, None, verbose)
        .context("Failed to build IR for graph analysis")?;

    // Convert core's CodeGraph directly into the analysis CodeGraph — zero copies,
    // no serialization. GraphNode and GraphEdgeKind are now the same types in both
    // crates (analysis/src/graph/mod.rs re-exports them from unfault-core).
    let graph = unfault_analysis::graph::CodeGraph::from(build_result.ir.graph);

    if verbose {
        eprintln!(
            "{} Graph: {} files, {} functions",
            "✓".green(),
            graph.file_nodes.len(),
            graph.function_nodes.len(),
        );
    }

    Ok(graph)
}
