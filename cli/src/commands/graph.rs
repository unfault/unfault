//! # Graph Command
//!
//! Implements the graph command for querying the code graph.
//!
//! Note: The code graph is automatically built when you run `unfault review`.
//! These commands query the graph that was built during the last review session.
//!
//! ## Usage
//!
//! ```bash
//! # First, run review to build the graph (with functions, classes, calls)
//! unfault review
//!
//! # Impact analysis: "What breaks if I change this file?"
//! # Workspace auto-detected from current directory
//! unfault graph impact auth/middleware.py
//!
//! # Or specify a workspace explicitly
//! unfault graph impact auth/middleware.py --workspace /path/to/project
//!
//! # Find files using a library
//! unfault graph library requests
//!
//! # Find external dependencies for a file
//! unfault graph deps main.py
//!
//! # Find the most critical files in the codebase
//! unfault graph critical --limit 10
//!
//! # Get graph statistics
//! unfault graph stats
//!
//! # Override with session ID (advanced usage)
//! unfault graph stats --session abc123
//! ```

use anyhow::Result;
use colored::Colorize;

use crate::exit_codes::*;

/// Build the analysis graph with a spinner on stderr when not in verbose or
/// JSON mode. The spinner is cleared before any output is printed, so it
/// never interleaves with results.
fn build_graph_with_spinner(
    workspace_path: &std::path::Path,
    verbose: bool,
    json: bool,
) -> Result<unfault_analysis::graph::CodeGraph, String> {
    if verbose || json {
        // Verbose already prints timing lines; JSON output must be clean.
        return crate::local_graph::build_analysis_graph(workspace_path, verbose)
            .map_err(|e| e.to_string());
    }

    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.set_message("Building graph…");
    spinner.enable_steady_tick(Duration::from_millis(80));

    let result =
        crate::local_graph::build_analysis_graph(workspace_path, false).map_err(|e| e.to_string());

    spinner.finish_and_clear();
    result
}

/// Arguments for the graph impact command
#[derive(Debug)]
pub struct ImpactArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// File path to analyze
    pub file_path: String,
    /// Maximum depth for transitive import analysis
    pub max_depth: i32,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

/// Arguments for the graph library command (files using a library)
#[derive(Debug)]
pub struct LibraryArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Library name to search for
    pub library_name: String,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

/// Arguments for the graph deps command (external dependencies of a file)
#[derive(Debug)]
pub struct DepsArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// File path to analyze
    pub file_path: String,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

/// Arguments for the graph critical command (centrality analysis)
#[derive(Debug)]
pub struct CriticalArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Maximum number of files to return
    pub limit: i32,
    /// Metric to sort by
    pub sort_by: String,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

#[derive(Debug)]
pub struct FunctionImpactArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Function in format file:function
    pub function: String,
    /// Maximum depth for transitive call analysis
    pub max_depth: i32,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

/// Arguments for the graph stats command
#[derive(Debug)]
pub struct StatsArgs {
    /// Session ID (optional, overrides workspace_id if provided)
    pub session_id: Option<String>,
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
}

// =============================================================================
// Workspace ID Resolution
// =============================================================================

/// Resolved identifier for graph queries
pub async fn execute_impact(args: ImpactArgs) -> Result<i32> {
    // Determine workspace path
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    if args.verbose {
        eprintln!("{} Analyzing impact of: {}", "→".cyan(), args.file_path);
    }

    // Build local graph
    let graph = match build_graph_with_spinner(&workspace_path, args.verbose, args.json) {
        Ok(g) => g,
        Err(e) => {
            eprintln!(
                "{} Failed to build code graph: {}",
                "Error:".red().bold(),
                e
            );
            return Ok(EXIT_ERROR);
        }
    };

    // Query impact using rag retrieval
    let impact = unfault_analysis::graph::traversal::get_impact(
        &graph,
        &args.file_path,
        args.max_depth as usize,
    );

    if impact.affected_files.is_empty() {
        eprintln!(
            "{} No downstream dependencies found for '{}'",
            "ℹ".cyan(),
            args.file_path
        );
        return Ok(EXIT_SUCCESS);
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&impact)?);
    } else {
        println!(
            "\n{} Impact analysis for {}",
            "📊".bright_blue(),
            args.file_path.bright_blue()
        );
        println!(
            "  {} {} file(s) affected:\n",
            "→".cyan(),
            impact.affected_files.len()
        );
        for file in &impact.affected_files {
            println!("    {}", file);
        }
        println!();
    }

    Ok(EXIT_SUCCESS)
}

/// Execute the graph library command
///
/// Shows files that use a specific library.
pub async fn execute_library(args: LibraryArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    if args.verbose {
        eprintln!("{} Finding files using: {}", "→".cyan(), args.library_name);
    }

    let graph = match build_graph_with_spinner(&workspace_path, args.verbose, args.json) {
        Ok(g) => g,
        Err(e) => {
            eprintln!(
                "{} Failed to build code graph: {}",
                "Error:".red().bold(),
                e
            );
            return Ok(EXIT_ERROR);
        }
    };

    // Find all files that use this library via UsesLibrary edges
    let deps = unfault_analysis::graph::traversal::get_dependencies(&graph, &args.library_name);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&deps)?);
    } else {
        println!(
            "\n{} Files using '{}':",
            "📦".bright_blue(),
            args.library_name.bright_blue()
        );
        if deps.library_users.is_empty() && deps.dependencies.is_empty() {
            println!("  No files found using '{}'", args.library_name);
        } else {
            for file in &deps.library_users {
                println!("    {}", file);
            }
            for file in &deps.dependencies {
                println!("    {}", file);
            }
        }
        println!();
    }

    Ok(EXIT_SUCCESS)
}

/// Execute the graph deps command
///
/// Shows external dependencies of a file.
pub async fn execute_deps(args: DepsArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    if args.verbose {
        eprintln!("{} Finding dependencies of: {}", "→".cyan(), args.file_path);
    }

    let graph = match build_graph_with_spinner(&workspace_path, args.verbose, args.json) {
        Ok(g) => g,
        Err(e) => {
            eprintln!(
                "{} Failed to build code graph: {}",
                "Error:".red().bold(),
                e
            );
            return Ok(EXIT_ERROR);
        }
    };

    let deps = unfault_analysis::graph::traversal::get_dependencies(&graph, &args.file_path);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&deps)?);
    } else {
        println!(
            "\n{} Dependencies of {}",
            "📦".bright_blue(),
            args.file_path.bright_blue()
        );
        if !deps.dependencies.is_empty() {
            println!("  Internal modules:");
            for dep in &deps.dependencies {
                println!("    {}", dep);
            }
        }
        if !deps.library_users.is_empty() {
            println!("  External libraries:");
            for lib in &deps.library_users {
                println!("    {}", lib);
            }
        }
        if deps.dependencies.is_empty() && deps.library_users.is_empty() {
            println!("  No dependencies found for '{}'", args.file_path);
        }
        println!();
    }

    Ok(EXIT_SUCCESS)
}

/// Execute the graph critical command
///
/// Shows the most critical/hub files in the codebase.
pub async fn execute_critical(args: CriticalArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    if args.verbose {
        eprintln!(
            "{} Finding top {} critical files (sorted by {})",
            "→".cyan(),
            args.limit,
            args.sort_by
        );
    }

    let graph = match build_graph_with_spinner(&workspace_path, args.verbose, args.json) {
        Ok(g) => g,
        Err(e) => {
            eprintln!(
                "{} Failed to build code graph: {}",
                "Error:".red().bold(),
                e
            );
            return Ok(EXIT_ERROR);
        }
    };

    // When sort_by == "importance_score", use the composite Ranker.
    // For all other sort metrics, fall back to the existing centrality query.
    if args.sort_by == "importance_score" {
        let ranked = unfault_analysis::sre::ranker::top_n(&graph, &[], args.limit as usize);

        if args.json {
            println!("{}", serde_json::to_string_pretty(&ranked)?);
        } else {
            println!(
                "\n{} Most critical files (composite importance score):\n",
                "📊".bright_blue()
            );
            if ranked.is_empty() {
                println!("  No files found in graph.");
            } else {
                for (i, rf) in ranked.iter().enumerate() {
                    println!(
                        "  {}. {} (score: {:.2}  centrality: {:.2}  lib-risk: {:.2}  debt: {:.2})",
                        i + 1,
                        rf.file_path.bright_blue(),
                        rf.importance_score,
                        rf.centrality_score,
                        rf.library_risk_score,
                        rf.finding_density_score,
                    );
                }
            }
            println!();
        }
    } else {
        let centrality =
            unfault_analysis::graph::traversal::get_centrality(&graph, args.limit as usize);

        if args.json {
            println!("{}", serde_json::to_string_pretty(&centrality)?);
        } else {
            println!(
                "\n{} Most critical files (by import count):\n",
                "📊".bright_blue()
            );
            if centrality.central_files.is_empty() {
                println!("  No import relationships found.");
            } else {
                for (i, (path, score)) in centrality.central_files.iter().enumerate() {
                    println!(
                        "  {}. {} (imported {} times)",
                        i + 1,
                        path.bright_blue(),
                        (*score as i32).to_string().yellow()
                    );
                }
            }
            println!();
        }
    }

    Ok(EXIT_SUCCESS)
}

/// Execute the graph stats command
///
/// Shows statistics about the code graph.
pub async fn execute_stats(args: StatsArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    if args.verbose {
        eprintln!("{} Building graph statistics...", "→".cyan());
    }

    let graph = match build_graph_with_spinner(&workspace_path, args.verbose, args.json) {
        Ok(g) => g,
        Err(e) => {
            eprintln!(
                "{} Failed to build code graph: {}",
                "Error:".red().bold(),
                e
            );
            return Ok(EXIT_ERROR);
        }
    };

    let overview = unfault_analysis::graph::traversal::workspace_overview(&graph);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&overview)?);
    } else {
        println!("\n{} Graph Statistics\n", "📊".bright_blue());
        println!("  Files:      {}", overview.file_count.to_string().yellow());
        println!(
            "  Functions:  {}",
            overview.function_count.to_string().yellow()
        );
        println!("  Languages:  {}", overview.languages.join(", ").cyan());
        if !overview.frameworks.is_empty() {
            println!("  Frameworks: {}", overview.frameworks.join(", ").cyan());
        }
        println!(
            "  Nodes:      {}",
            graph.graph.node_count().to_string().yellow()
        );
        println!(
            "  Edges:      {}",
            graph.graph.edge_count().to_string().yellow()
        );
        if !overview.entrypoints.is_empty() {
            println!("\n  Entrypoints:");
            for ep in &overview.entrypoints {
                println!("    {}", ep);
            }
        }
        println!();
    }

    Ok(EXIT_SUCCESS)
}

// =============================================================================
// Routes
// =============================================================================

/// Arguments for the graph routes command
#[derive(Debug)]
pub struct RoutesArgs {
    pub workspace_path: Option<String>,
    /// Optional HTTP method filter (e.g. "GET", "POST")
    pub method: Option<String>,
    /// Optional file path filter (substring match)
    pub file: Option<String>,
    pub json: bool,
    pub verbose: bool,
}

#[derive(Debug, serde::Serialize)]
pub struct RouteEntry {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub file: String,
}

pub async fn execute_routes(args: RoutesArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    if args.verbose {
        eprintln!("{} Building code graph...", "→".cyan());
    }

    let graph = match build_graph_with_spinner(&workspace_path, args.verbose, args.json) {
        Ok(g) => g,
        Err(e) => {
            eprintln!(
                "{} Failed to build code graph: {}",
                "Error:".red().bold(),
                e
            );
            return Ok(EXIT_ERROR);
        }
    };

    // Collect all route entries from the graph.
    let mut routes: Vec<RouteEntry> = Vec::new();

    for node_idx in graph.graph.node_indices() {
        let node = &graph.graph[node_idx];
        match node {
            unfault_analysis::graph::GraphNode::Function {
                is_handler: true,
                http_method: Some(method),
                http_path: Some(path),
                name,
                ..
            } => {
                let file = unfault_analysis::graph::traversal::node_file_path_pub(&graph, node)
                    .unwrap_or_default();
                routes.push(RouteEntry {
                    method: method.clone(),
                    path: path.clone(),
                    handler: name.clone(),
                    file,
                });
            }
            // FastApiRoute nodes carry method+path but not the handler name —
            // those are already captured via their companion Function node above,
            // so skip them to avoid duplicates.
            _ => {}
        }
    }

    // Apply filters.
    if let Some(ref method_filter) = args.method {
        let upper = method_filter.to_uppercase();
        routes.retain(|r| r.method.to_uppercase() == upper);
    }
    if let Some(ref file_filter) = args.file {
        routes.retain(|r| r.file.contains(file_filter.as_str()));
    }

    // Sort: file, then path, then method.
    routes.sort_by(|a, b| {
        a.file
            .cmp(&b.file)
            .then(a.path.cmp(&b.path))
            .then(a.method.cmp(&b.method))
    });

    if routes.is_empty() {
        if args.json {
            println!("[]");
        } else {
            println!("\n{} No routes detected.\n", "→".cyan());
        }
        return Ok(EXIT_SUCCESS);
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&routes)?);
    } else {
        println!(
            "\n{} {} route{} detected\n",
            "→".cyan(),
            routes.len().to_string().yellow(),
            if routes.len() == 1 { "" } else { "s" }
        );

        // Group by file for readability.
        let mut current_file = String::new();
        for route in &routes {
            if route.file != current_file {
                current_file = route.file.clone();
                println!("  {}", current_file.bright_blue());
            }
            println!(
                "    {:<8} {}  {}",
                route.method.green(),
                route.path,
                format!("({})", route.handler).dimmed()
            );
        }
        println!();
    }

    Ok(EXIT_SUCCESS)
}

// =============================================================================
// Error Handling
// =============================================================================
pub async fn execute_function_impact(args: FunctionImpactArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    // Parse function argument (file:function)
    let (_file_path, function_name) = match args.function.split_once(':') {
        Some((file, func)) => (file.to_string(), func.to_string()),
        None => {
            eprintln!(
                "{} Function must be in format file:function (e.g., main.py:process_user)",
                "Error:".red().bold()
            );
            return Ok(EXIT_ERROR);
        }
    };

    if args.verbose {
        eprintln!("{} Analyzing call flow of: {}", "→".cyan(), args.function);
    }

    let graph = match build_graph_with_spinner(&workspace_path, args.verbose, args.json) {
        Ok(g) => g,
        Err(e) => {
            eprintln!(
                "{} Failed to build code graph: {}",
                "Error:".red().bold(),
                e
            );
            return Ok(EXIT_ERROR);
        }
    };

    // Use flow extraction (BFS from function through call edges)
    let flow = unfault_analysis::graph::traversal::extract_flow(
        &graph,
        &function_name,
        args.max_depth as usize,
    );

    if args.json {
        println!("{}", serde_json::to_string_pretty(&flow)?);
    } else {
        println!();
        println!(
            "{} {} {}",
            "🔗".cyan(),
            "Function Call Graph:".bold(),
            function_name.bright_white()
        );
        println!();

        if flow.paths.is_empty() {
            println!("  {} No call paths found from this function.", "ℹ".blue());
            println!();
            return Ok(EXIT_SUCCESS);
        }

        println!(
            "  {} Found {} call path(s)",
            "→".cyan(),
            flow.paths.len().to_string().bold()
        );
        println!();

        // Display call paths
        for (i, path) in flow.paths.iter().enumerate() {
            println!("  Path {}:", i + 1);
            for node in path {
                let indent = "  ".repeat(node.depth + 2);
                let file_info = node
                    .file_path
                    .as_deref()
                    .map(|p| format!(" ({})", p))
                    .unwrap_or_default();
                println!(
                    "{}{} {}{}",
                    indent,
                    "→".cyan(),
                    node.name.bright_white(),
                    file_info.dimmed()
                );
            }
            println!();
        }
    }

    Ok(EXIT_SUCCESS)
}
// =============================================================================
// Graph Dump Command (Local)
// =============================================================================

/// Arguments for the graph callers command
#[derive(Debug)]
pub struct CallersArgs {
    /// Workspace path to auto-detect workspace_id from (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Function in format file:function
    pub function: String,
    /// Maximum depth for reverse call chain traversal
    pub max_depth: i32,
    /// Output JSON instead of formatted text
    pub json: bool,
    /// Verbose output
    pub verbose: bool,
    /// Print raw graph diagnostics for the target node (edges, duplicates, etc.)
    pub debug: bool,
}

/// Execute the graph callers command
///
/// Shows the inbound call chain for a function: who calls it, and which HTTP
/// routes anchor that call chain — the "you are here" view.
pub async fn execute_callers(args: CallersArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    // Parse function argument (file:function or just function_name)
    let (file_hint, function_name) = match args.function.split_once(':') {
        Some((file, func)) => (Some(file.to_string()), func.to_string()),
        None => (None, args.function.clone()),
    };

    if args.verbose {
        eprintln!("{} Tracing callers of: {}", "→".cyan(), args.function);
    }

    let graph = match build_graph_with_spinner(&workspace_path, args.verbose, args.json) {
        Ok(g) => g,
        Err(e) => {
            eprintln!(
                "{} Failed to build code graph: {}",
                "Error:".red().bold(),
                e
            );
            return Ok(EXIT_ERROR);
        }
    };

    // Debug mode: dump raw graph information about the target node before
    // running the callers query, so the user can see what's actually in the
    // graph and whether Calls edges exist.
    if args.debug {
        use petgraph::Direction;
        use petgraph::visit::EdgeRef;
        use unfault_analysis::graph::{GraphEdgeKind, GraphNode};

        eprintln!("\n{} Debug: nodes matching '{}'", "→".cyan(), function_name);

        let lower = function_name.to_lowercase();
        let mut found = false;
        for idx in graph.graph.node_indices() {
            let node = &graph.graph[idx];
            let name = node.display_name().to_lowercase();
            if name == lower
                || name.ends_with(&format!(".{}", lower))
                || name.contains(&format!("/{}", lower))
            {
                found = true;
                let file = unfault_analysis::graph::traversal::node_file_path_pub(&graph, node)
                    .unwrap_or_else(|| "<no file>".to_string());
                let handler_info = if let GraphNode::Function {
                    is_handler,
                    http_method,
                    http_path,
                    ..
                } = node
                {
                    if *is_handler {
                        format!(
                            " [handler: {} {}]",
                            http_method.as_deref().unwrap_or("?"),
                            http_path.as_deref().unwrap_or("?")
                        )
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };

                let incoming_calls = graph
                    .graph
                    .edges_directed(idx, Direction::Incoming)
                    .filter(|e| matches!(e.weight(), GraphEdgeKind::Calls))
                    .count();
                let outgoing_calls = graph
                    .graph
                    .edges_directed(idx, Direction::Outgoing)
                    .filter(|e| matches!(e.weight(), GraphEdgeKind::Calls))
                    .count();

                eprintln!(
                    "  node {:?}  name={}  file={}{}\n    incoming Calls edges: {}  outgoing Calls edges: {}",
                    idx,
                    node.display_name(),
                    file,
                    handler_info,
                    incoming_calls,
                    outgoing_calls
                );

                if incoming_calls > 0 {
                    for edge in graph
                        .graph
                        .edges_directed(idx, Direction::Incoming)
                        .filter(|e| matches!(e.weight(), GraphEdgeKind::Calls))
                    {
                        let caller = &graph.graph[edge.source()];
                        let caller_file =
                            unfault_analysis::graph::traversal::node_file_path_pub(&graph, caller)
                                .unwrap_or_default();
                        eprintln!("      ← {} ({})", caller.display_name(), caller_file);
                    }
                }
            }
        }
        if !found {
            eprintln!("  (no nodes found with that name)");
        }

        // Also show what the expected handler calls — find any handler node whose
        // name starts with '_' followed by the target name, and print its outgoing edges.
        let handler_name = format!("_{}", lower);
        eprintln!(
            "\n{} Debug: outgoing Calls edges from nodes matching '{}'",
            "→".cyan(),
            handler_name
        );
        let mut found_handler = false;
        for idx in graph.graph.node_indices() {
            let node = &graph.graph[idx];
            let name = node.display_name().to_lowercase();
            if name == handler_name {
                found_handler = true;
                let file = unfault_analysis::graph::traversal::node_file_path_pub(&graph, node)
                    .unwrap_or_else(|| "<no file>".to_string());
                let outgoing: Vec<_> = graph
                    .graph
                    .edges_directed(idx, Direction::Outgoing)
                    .filter(|e| matches!(e.weight(), GraphEdgeKind::Calls))
                    .collect();
                eprintln!(
                    "  node {:?}  name={}  file={}\n    outgoing Calls edges: {}",
                    idx,
                    node.display_name(),
                    file,
                    outgoing.len()
                );
                for edge in &outgoing {
                    let callee = &graph.graph[edge.target()];
                    let callee_file =
                        unfault_analysis::graph::traversal::node_file_path_pub(&graph, callee)
                            .unwrap_or_default();
                    eprintln!("      → {} ({})", callee.display_name(), callee_file);
                }
            }
        }
        if !found_handler {
            eprintln!("  (no nodes found with that name)");
        }
        eprintln!();
    }

    let ctx = if let Some(ref hint) = file_hint {
        unfault_analysis::graph::traversal::get_callers_in_file(
            &graph,
            &function_name,
            hint,
            args.max_depth as usize,
        )
    } else {
        unfault_analysis::graph::traversal::get_callers(
            &graph,
            &function_name,
            args.max_depth as usize,
        )
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&ctx)?);
        return Ok(EXIT_SUCCESS);
    }

    println!();

    if ctx.callers.is_empty() && ctx.routes.is_empty() {
        let not_in_graph = ctx.target_file.is_none();

        if not_in_graph {
            println!(
                "  {} '{}' was not found in the code graph.",
                "ℹ".cyan(),
                function_name
            );
        } else {
            println!(
                "  {} '{}' is in the graph ({}) but no call edges were resolved.",
                "ℹ".cyan(),
                function_name,
                ctx.target_file.as_deref().unwrap_or("").dimmed()
            );
            println!(
                "  {}  Cross-file calls are not yet tracked — try targeting a route handler",
                " ".dimmed()
            );
            println!("  {}  in the same file directly.", " ".dimmed());
        }

        let suggestions = unfault_analysis::graph::traversal::suggest_callers_candidates(
            &graph,
            &function_name,
            ctx.target_file.as_deref(),
        );

        if !suggestions.is_empty() {
            println!();
            let has_handlers = suggestions.iter().any(|s| s.http_method.is_some());
            if not_in_graph {
                println!("  Did you mean one of these?");
            } else if has_handlers {
                let location = if suggestions.iter().any(|s| s.reason == "same_file_handler") {
                    "same file"
                } else {
                    "same module"
                };
                println!(
                    "  Route handlers in the {} — likely entry points for this function:",
                    location
                );
            } else {
                println!("  Most-called functions in the workspace:");
            }
            println!();

            for s in &suggestions {
                if let (Some(method), Some(path)) = (&s.http_method, &s.http_path) {
                    let method_colored = match method.as_str() {
                        "GET" => method.bright_green(),
                        "POST" => method.bright_yellow(),
                        "PUT" | "PATCH" => method.bright_cyan(),
                        "DELETE" => method.bright_red(),
                        _ => method.normal(),
                    };
                    println!(
                        "    {} {}  {} {}",
                        method_colored,
                        path,
                        "→".dimmed(),
                        s.name.bright_white()
                    );
                    println!("      {}", s.file.dimmed());
                } else {
                    println!("    {}", s.name.bright_white());
                    if !s.file.is_empty() {
                        println!("      {}", s.file.dimmed());
                    }
                }
                println!();
            }

            if not_in_graph {
                println!(
                    "  Use {} to target a specific file:",
                    "file.py:function_name".bold()
                );
                if let Some(first) = suggestions.first() {
                    println!("    unfault graph callers {}:{}", first.file, first.name);
                }
            } else if let Some(first) = suggestions.iter().find(|s| s.http_method.is_some()) {
                println!(
                    "  Run {} or {} on one of the handlers above:",
                    "graph callers".bold(),
                    "fault".bold()
                );
                println!("    unfault graph callers {}:{}", first.file, first.name);
                println!("    unfault fault {}:{}", first.file, first.name);
            }
        }

        println!();
        return Ok(EXIT_SUCCESS);
    }

    // ── Header ────────────────────────────────────────────────────────────────
    println!(
        "{} {}",
        "Call path to".bold(),
        function_name.bright_white().bold()
    );
    if let Some(ref f) = ctx.target_file {
        println!("  {}", f.dimmed());
    }
    println!();

    // ── Routes at the top ─────────────────────────────────────────────────────
    for route in &ctx.routes {
        let method_colored = match route.method.as_str() {
            "GET" => route.method.bright_green(),
            "POST" => route.method.bright_yellow(),
            "PUT" | "PATCH" => route.method.bright_cyan(),
            "DELETE" => route.method.bright_red(),
            _ => route.method.normal(),
        };
        println!("  {} {}", method_colored, route.path.bold());
    }

    if !ctx.routes.is_empty() {
        println!();
    }

    // ── Call chain tree ───────────────────────────────────────────────────────
    // Build a parent → children map keyed on caller name.
    // depth=1 callers are direct callers of the target; depth=2 call depth=1, etc.
    // We render the tree top-down: deepest callers first, branching at each level.

    use std::collections::HashMap;
    use unfault_analysis::types::graph_query::CallerInfo;

    let max_depth = ctx.callers.iter().map(|c| c.depth).max().unwrap_or(0);

    // Group callers by depth for lookup.
    let mut by_depth: HashMap<usize, Vec<&CallerInfo>> = HashMap::new();
    for c in &ctx.callers {
        by_depth.entry(c.depth).or_insert_with(Vec::new).push(c);
    }

    let _top_callers: &[&CallerInfo] = by_depth
        .get(&max_depth)
        .map(|v| v.as_slice())
        .unwrap_or(&[]);

    // Render each top-level caller as a root, with depth-1 callers as their children, etc.
    // We walk depth descending: max_depth → 1 → target.
    // Since we don't track parent-child relationships explicitly, we show the structure
    // as: all callers at depth N, then under them all callers at depth N-1, down to target.
    // This is accurate for chains; for branching graphs it shows all branches.

    fn render_level(
        depth: usize,
        by_depth: &HashMap<usize, Vec<&CallerInfo>>,
        target: &str,
        target_file: Option<&str>,
        prefix: &str,
    ) {
        let nodes = by_depth.get(&depth).map(|v| v.as_slice()).unwrap_or(&[]);

        for (i, node) in nodes.iter().enumerate() {
            let is_last_at_level = i == nodes.len() - 1;
            let connector = if is_last_at_level { "└─" } else { "├─" };
            let file_info = node
                .file
                .as_deref()
                .map(|p| format!(" ({})", p))
                .unwrap_or_default();
            println!(
                "{}{} {}{}",
                prefix,
                connector.dimmed(),
                node.name.bright_white(),
                file_info.dimmed()
            );

            // Child prefix: extend with vertical bar if there are siblings below.
            let child_prefix = if is_last_at_level {
                format!("{}   ", prefix)
            } else {
                format!("{}│  ", prefix)
            };

            if depth > 1 {
                render_level(depth - 1, by_depth, target, target_file, &child_prefix);
            } else {
                // Leaf: next is the target itself.
                let target_file_info = target_file.map(|p| format!(" ({})", p)).unwrap_or_default();
                println!(
                    "{}└─ {}{}  {}",
                    child_prefix,
                    target.bright_blue().bold(),
                    target_file_info.dimmed(),
                    "← you are here".cyan().dimmed()
                );
            }
        }
    }

    // If there are no intermediate depths — all callers are at depth 1 — render flat.
    if max_depth == 0 {
        // Only the target, no callers (shouldn't reach here but guard anyway).
        let target_file_info = ctx
            .target_file
            .as_deref()
            .map(|p| format!(" ({})", p))
            .unwrap_or_default();
        println!(
            "  └─ {}{}  {}",
            ctx.target.bright_blue().bold(),
            target_file_info.dimmed(),
            "← you are here".cyan().dimmed()
        );
    } else {
        render_level(
            max_depth,
            &by_depth,
            &ctx.target,
            ctx.target_file.as_deref(),
            "  ",
        );
    }

    println!();
    Ok(EXIT_SUCCESS)
}

/// Arguments for the graph dump command
#[derive(Debug)]
pub struct DumpArgs {
    /// Workspace path to analyze (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Output only call edges
    pub calls_only: bool,
    /// Output only specific file's information
    pub file: Option<String>,
    /// Verbose output
    pub verbose: bool,
}

/// Execute the graph dump command - builds local graph and outputs JSON
pub fn execute_dump(args: DumpArgs) -> Result<i32> {
    use crate::session::graph_builder::build_local_graph;

    // Determine workspace path
    let workspace_path = match &args.workspace_path {
        Some(path) => std::path::PathBuf::from(path),
        None => std::env::current_dir()?,
    };

    if args.verbose {
        eprintln!(
            "{} Building local code graph for: {}",
            "→".cyan(),
            workspace_path.display()
        );
    }

    // Build the local graph
    let graph = build_local_graph(&workspace_path, None, args.verbose)?;

    if args.verbose {
        eprintln!(
            "{} Graph built: {} files, {} functions, {} call edges",
            "✓".green(),
            graph.files.len(),
            graph.functions.len(),
            graph.calls.len()
        );
        eprintln!();
    }

    // Filter and output
    if args.calls_only {
        // Output only call edges, optionally filtered by file
        let calls: Vec<_> = if let Some(ref file_filter) = args.file {
            graph
                .calls
                .iter()
                .filter(|c| c.caller_file.contains(file_filter))
                .collect()
        } else {
            graph.calls.iter().collect()
        };

        println!("{}", serde_json::to_string_pretty(&calls)?);
    } else if let Some(ref file_filter) = args.file {
        // Output everything related to a specific file
        #[derive(serde::Serialize)]
        struct FileGraph {
            file: Option<crate::session::graph_builder::FileNode>,
            functions: Vec<crate::session::graph_builder::FunctionNode>,
            outgoing_calls: Vec<crate::session::graph_builder::CallEdge>,
            incoming_calls: Vec<crate::session::graph_builder::CallEdge>,
            imports: Vec<crate::session::graph_builder::ImportEdge>,
        }

        let file_graph = FileGraph {
            file: graph
                .files
                .iter()
                .find(|f| f.path.contains(file_filter))
                .cloned(),
            functions: graph
                .functions
                .iter()
                .filter(|f| f.file_path.contains(file_filter))
                .cloned()
                .collect(),
            outgoing_calls: graph
                .calls
                .iter()
                .filter(|c| c.caller_file.contains(file_filter))
                .cloned()
                .collect(),
            incoming_calls: graph
                .calls
                .iter()
                .filter(|c| {
                    // Find the callee's file
                    graph
                        .functions
                        .iter()
                        .any(|f| f.qualified_name == c.callee && f.file_path.contains(file_filter))
                })
                .cloned()
                .collect(),
            imports: graph
                .imports
                .iter()
                .filter(|i| i.from_file.contains(file_filter) || i.to_file.contains(file_filter))
                .cloned()
                .collect(),
        };

        println!("{}", serde_json::to_string_pretty(&file_graph)?);
    } else {
        // Output full graph
        println!("{}", serde_json::to_string_pretty(&graph)?);
    }

    Ok(EXIT_SUCCESS)
}
