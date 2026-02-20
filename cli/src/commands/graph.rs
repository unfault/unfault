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
    let graph = match crate::local_graph::build_analysis_graph(&workspace_path, args.verbose) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("{} Failed to build code graph: {}", "Error:".red().bold(), e);
            return Ok(EXIT_ERROR);
        }
    };

    // Query impact using rag retrieval
    let impact = unfault_core::graph::traversal::get_impact(&graph, &args.file_path, args.max_depth as usize);

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

    let graph = match crate::local_graph::build_analysis_graph(&workspace_path, args.verbose) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("{} Failed to build code graph: {}", "Error:".red().bold(), e);
            return Ok(EXIT_ERROR);
        }
    };

    // Find all files that use this library via UsesLibrary edges
    let deps = unfault_core::graph::traversal::get_dependencies(&graph, &args.library_name);

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

    let graph = match crate::local_graph::build_analysis_graph(&workspace_path, args.verbose) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("{} Failed to build code graph: {}", "Error:".red().bold(), e);
            return Ok(EXIT_ERROR);
        }
    };

    let deps = unfault_core::graph::traversal::get_dependencies(&graph, &args.file_path);

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

    let graph = match crate::local_graph::build_analysis_graph(&workspace_path, args.verbose) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("{} Failed to build code graph: {}", "Error:".red().bold(), e);
            return Ok(EXIT_ERROR);
        }
    };

    let centrality = unfault_core::graph::traversal::get_centrality(&graph, args.limit as usize);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&centrality)?);
    } else {
        println!("\n{} Most critical files (by import count):\n", "📊".bright_blue());
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

    let graph = match crate::local_graph::build_analysis_graph(&workspace_path, args.verbose) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("{} Failed to build code graph: {}", "Error:".red().bold(), e);
            return Ok(EXIT_ERROR);
        }
    };

    let overview = unfault_core::graph::traversal::workspace_overview(&graph);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&overview)?);
    } else {
        println!("\n{} Graph Statistics\n", "📊".bright_blue());
        println!("  Files:      {}", overview.file_count.to_string().yellow());
        println!("  Functions:  {}", overview.function_count.to_string().yellow());
        println!("  Languages:  {}", overview.languages.join(", ").cyan());
        if !overview.frameworks.is_empty() {
            println!("  Frameworks: {}", overview.frameworks.join(", ").cyan());
        }
        println!("  Nodes:      {}", graph.graph.node_count().to_string().yellow());
        println!("  Edges:      {}", graph.graph.edge_count().to_string().yellow());
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

    let graph = match crate::local_graph::build_analysis_graph(&workspace_path, args.verbose) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("{} Failed to build code graph: {}", "Error:".red().bold(), e);
            return Ok(EXIT_ERROR);
        }
    };

    // Use flow extraction (BFS from function through call edges)
    let flow = unfault_core::graph::traversal::extract_flow(&graph, &function_name, args.max_depth as usize);

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
            println!(
                "  {} No call paths found from this function.",
                "ℹ".blue()
            );
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
            file: graph.files.iter().find(|f| f.path.contains(file_filter)).cloned(),
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
                    graph.functions.iter().any(|f| {
                        f.qualified_name == c.callee && f.file_path.contains(file_filter)
                    })
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

