//! Local graph building helper.
//!
//! Builds an in-memory CodeGraph from the current workspace using unfault-core
//! for parsing and unfault-analysis for graph construction.

use anyhow::{Context, Result};
use colored::Colorize;

/// Build a CodeGraph from the workspace by parsing all source files.
///
/// This builds the same IR that the review command uses, then extracts
/// the graph from it. The graph can be queried for impact, dependencies,
/// centrality, etc.
pub fn build_analysis_graph(
    workspace_path: &std::path::Path,
    verbose: bool,
) -> Result<unfault_analysis::graph::CodeGraph> {
    use crate::session::ir_builder::build_ir_cached;

    if verbose {
        eprintln!(
            "{} Building code graph for: {}",
            "→".cyan(),
            workspace_path.display()
        );
    }

    // Build IR (parses files, builds semantics, constructs graph)
    let build_result = build_ir_cached(workspace_path, None, verbose)
        .context("Failed to build IR for graph analysis")?;

    // Convert from core's IR type to the analysis crate's IR type.
    // Use msgpack (rmp_serde) instead of JSON — same round-trip but
    // ~10x faster serialization and a fraction of the allocations.
    let ir_bytes =
        rmp_serde::to_vec(&build_result.ir).context("Failed to serialize IR (msgpack)")?;
    let mut ir: unfault_analysis::ir::IntermediateRepresentation =
        rmp_serde::from_slice(&ir_bytes).context("Failed to deserialize IR (msgpack)")?;

    // Rebuild indexes (needed after deserialization)
    ir.rebuild_indexes();

    if verbose {
        eprintln!(
            "{} Graph: {} files, {} functions",
            "✓".green(),
            ir.graph.file_nodes.len(),
            ir.graph.function_nodes.len(),
        );
    }

    Ok(ir.graph)
}
