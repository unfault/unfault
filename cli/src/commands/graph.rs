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

    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);

    if !args.verbose {
        if let Some(impact) = crate::session::query_cache::get_impact(
            &workspace_path,
            &args.file_path,
            args.max_depth as usize,
            &commit_sha,
        ) {
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
            return Ok(EXIT_SUCCESS);
        }
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

    crate::session::query_cache::set_impact(
        &workspace_path,
        &args.file_path,
        args.max_depth as usize,
        &commit_sha,
        &impact,
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

    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);
    if !args.verbose {
        if let Some(deps) = crate::session::query_cache::get_library(
            &workspace_path,
            &args.library_name,
            &commit_sha,
        ) {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&deps)?);
                return Ok(EXIT_SUCCESS);
            }
            println!(
                "\n{} Files using '{}':",
                "📦".bright_blue(),
                args.library_name.bright_blue()
            );
            if deps.library_users.is_empty() && deps.dependencies.is_empty() {
                println!("  No files found using '{}'", args.library_name);
            } else {
                for f in &deps.library_users {
                    println!("    {}", f);
                }
                for f in &deps.dependencies {
                    println!("    {}", f);
                }
            }
            println!();
            return Ok(EXIT_SUCCESS);
        }
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
    crate::session::query_cache::set_library(
        &workspace_path,
        &args.library_name,
        &commit_sha,
        &deps,
    );

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

    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);
    if !args.verbose {
        if let Some(deps) =
            crate::session::query_cache::get_deps(&workspace_path, &args.file_path, &commit_sha)
        {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&deps)?);
                return Ok(EXIT_SUCCESS);
            }
            println!(
                "\n{} Dependencies of {}",
                "📦".bright_blue(),
                args.file_path.bright_blue()
            );
            if !deps.dependencies.is_empty() {
                println!("  Internal modules:");
                for d in &deps.dependencies {
                    println!("    {}", d);
                }
            }
            if !deps.library_users.is_empty() {
                println!("  External libraries:");
                for l in &deps.library_users {
                    println!("    {}", l);
                }
            }
            if deps.dependencies.is_empty() && deps.library_users.is_empty() {
                println!("  No dependencies found for '{}'", args.file_path);
            }
            println!();
            return Ok(EXIT_SUCCESS);
        }
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
    crate::session::query_cache::set_deps(&workspace_path, &args.file_path, &commit_sha, &deps);

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

    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);

    // Cache the centrality path (importance_score uses a different return type — skip).
    if !args.verbose && args.sort_by != "importance_score" {
        if let Some(centrality) = crate::session::query_cache::get_critical(
            &workspace_path,
            &args.sort_by,
            args.limit as usize,
            &commit_sha,
        ) {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&centrality)?);
                return Ok(EXIT_SUCCESS);
            }
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
            return Ok(EXIT_SUCCESS);
        }
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

        crate::session::query_cache::set_critical(
            &workspace_path,
            &args.sort_by,
            args.limit as usize,
            &commit_sha,
            &centrality,
        );

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

    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);
    if !args.verbose {
        if let Some(overview) = crate::session::query_cache::get_stats(&workspace_path, &commit_sha)
        {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&overview)?);
                return Ok(EXIT_SUCCESS);
            }
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
            println!();
            return Ok(EXIT_SUCCESS);
        }
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
    crate::session::query_cache::set_stats(&workspace_path, &commit_sha, &overview);

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

/// Arguments for the graph coverage command
#[derive(Debug)]
pub struct CoverageArgs {
    pub workspace_path: Option<String>,
    /// Route path (e.g. "/api/orders") or function name to start from.
    pub target: String,
    /// Optional HTTP method filter when target is a route (e.g. "GET").
    pub method: Option<String>,
    /// Maximum call-tree depth in each direction (default: unlimited until
    /// a library boundary).
    pub max_depth: Option<usize>,
    /// Output as JSON
    pub json: bool,
    /// Force a live refresh of observability data
    pub refresh_cache: bool,
    /// Use cached observability data only
    pub offline: bool,
    /// Enable verbose output
    pub verbose: bool,
}

// ── Coverage types ────────────────────────────────────────────────────────────

/// What kind of observability signal a single function node carries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanSignal {
    /// Function carries a recognised tracing decorator (@trace, @instrument,
    /// @span, context manager, etc.).  `name` is whatever we can extract from
    /// the decorator detail string, or None if only the presence is detected.
    Decorator {
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    /// The file this function lives in imports an OTel / tracing SDK
    /// (opentelemetry, ddtrace, sentry-sdk, …).
    SdkImported {
        /// The library name (e.g. "opentelemetry", "ddtrace").
        library: String,
    },
    /// No instrumentation signal detected on this node.
    None,
}

/// The semantic "role" of a function node — what kind of work does it do?
/// Derived from UsesLibrary → ExternalModule → ModuleCategory edges on the
/// file that contains the function.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Entry point: HTTP route handler.
    HttpHandler { method: String, path: String },
    /// Makes outbound HTTP calls (HttpClient library).
    HttpClient,
    /// Queries a database (Database/ORM library).
    Database,
    /// Cross-service call via RemoteCall graph edge.
    RemoteCall { service: String },
    /// Regular business logic — no special boundary role detected.
    Logic,
}

/// A single node in the coverage call tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageNode {
    /// Display name of the function.
    pub name: String,
    /// Source file path, relative to workspace root.
    pub file: String,
    /// 1-based line number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// How deep this node is from the root (0 = root).
    pub depth: i32,
    /// Direction from the anchor point: "up" (caller), "down" (callee), or
    /// "root" (the anchor itself).
    pub direction: String,
    /// What instrumentation signal we found on this node.
    pub span: SpanSignal,
    /// Semantic role inferred from library edges.
    pub role: NodeRole,
    /// Callees of this node (only populated for downward nodes).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<CoverageNode>,
}

/// Summary counts across the entire tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageTreeSummary {
    pub total_nodes: usize,
    pub instrumented: usize,
    pub uninstrumented: usize,
    pub db_boundaries: usize,
    pub http_boundaries: usize,
    pub remote_calls: usize,
}

/// Top-level result returned by execute_coverage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageContext {
    /// The original target string supplied by the user.
    pub target: String,
    /// How we resolved the target.
    pub resolved_as: String,
    /// Callers above the anchor (upward walk), root-first order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<CoverageNode>,
    /// The anchor node itself (route handler or named function).
    pub anchor: CoverageNode,
    /// Callees below the anchor (downward walk).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callees: Vec<CoverageNode>,
    /// Summary counts.
    pub summary: CoverageTreeSummary,
}

// ── Route entry (used by routes command, kept here) ───────────────────────────

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct RouteEntry {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub file: String,
    /// 1-based line number of the handler definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Semantic roles of the decorators on this handler (auth, rate_limit, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub decorators: Vec<unfault_core::graph::DecoratorSemantic>,
    /// True if the handler contains ORM write operations.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_writer: bool,
    /// Request body / query schema from `@blp.arguments(SchemaX)` or `@use_args`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_schema: Option<String>,
    /// Response schema from `@blp.response(200, SchemaY)` or `@marshal_with`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<String>,
}

fn collect_route_entries(graph: &unfault_analysis::graph::CodeGraph) -> Vec<RouteEntry> {
    let mut routes: Vec<RouteEntry> = Vec::new();

    for node_idx in graph.graph.node_indices() {
        let node = &graph.graph[node_idx];
        if let unfault_analysis::graph::GraphNode::Function {
            is_handler: true,
            http_method: Some(method),
            http_path: Some(path),
            name,
            decorators,
            is_writer,
            line,
            request_schema,
            response_schema,
            ..
        } = node
        {
            let file = unfault_analysis::graph::traversal::node_file_path_pub(graph, node)
                .unwrap_or_default();
            routes.push(RouteEntry {
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

    routes
}

pub async fn execute_routes(args: RoutesArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    if args.verbose {
        eprintln!("{} Building code graph...", "→".cyan());
    }

    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);
    let cache_params = format!(
        "{}|{}",
        args.method.as_deref().unwrap_or(""),
        args.file.as_deref().unwrap_or("")
    );

    if !args.verbose {
        if let Some(routes) = crate::session::query_cache::get::<Vec<RouteEntry>>(
            &workspace_path,
            "routes",
            &cache_params,
            &commit_sha,
        ) {
            return render_routes_output(routes, args.json);
        }
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

    let mut routes = collect_route_entries(&graph);

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

    crate::session::query_cache::set::<Vec<RouteEntry>>(
        &workspace_path,
        "routes",
        &cache_params,
        &commit_sha,
        &routes,
    );

    render_routes_output(routes, args.json)
}

fn render_routes_output(routes: Vec<RouteEntry>, json: bool) -> Result<i32> {
    if routes.is_empty() {
        if json {
            println!("[]");
        } else {
            println!("\n{} No routes detected.\n", "→".cyan());
        }
        return Ok(EXIT_SUCCESS);
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&routes)?);
    } else {
        println!(
            "\n{} {} route{} detected\n",
            "→".cyan(),
            routes.len().to_string().yellow(),
            if routes.len() == 1 { "" } else { "s" }
        );
        let mut current_file = String::new();
        for route in &routes {
            if route.file != current_file {
                current_file = route.file.clone();
                println!("  {}", current_file.bright_blue());
            }
            let method_colored = match route.method.as_str() {
                "GET" => route.method.bright_green(),
                "POST" => route.method.bright_yellow(),
                "PUT" | "PATCH" => route.method.bright_cyan(),
                "DELETE" => route.method.bright_red(),
                _ => route.method.normal(),
            };
            let handler_loc = match route.line {
                Some(l) => format!("({}:{})", route.handler, l),
                None => format!("({})", route.handler),
            };
            println!(
                "    {:<8} {}  {}",
                method_colored,
                route.path,
                handler_loc.dimmed()
            );
            render_route_annotations(
                &route.decorators,
                route.is_writer,
                route.request_schema.as_deref(),
                route.response_schema.as_deref(),
            );
        }
        println!();
    }
    Ok(EXIT_SUCCESS)
}

/// Print decorator badges, writer flag, and schema info under a route line.
fn render_route_annotations(
    decorators: &[unfault_core::graph::DecoratorSemantic],
    is_writer: bool,
    request_schema: Option<&str>,
    response_schema: Option<&str>,
) {
    use unfault_core::graph::DecoratorSemantic;

    let has_badges = !decorators.is_empty() || is_writer;
    let has_schemas = request_schema.is_some() || response_schema.is_some();

    if !has_badges && !has_schemas {
        return;
    }

    if has_badges {
        let mut badges: Vec<colored::ColoredString> = decorators
            .iter()
            .map(|d| match d {
                DecoratorSemantic::Auth { .. } => "auth".bright_red(),
                DecoratorSemantic::Permission { .. } => "permission".red(),
                DecoratorSemantic::RateLimit { .. } => "rate-limit".yellow(),
                DecoratorSemantic::Cache { .. } => "cache".cyan(),
                DecoratorSemantic::Retry { .. } => "retry".yellow(),
                DecoratorSemantic::Tracing { .. } => "tracing".blue(),
                DecoratorSemantic::Validation { .. } => "validation".cyan(),
                DecoratorSemantic::Transaction { .. } => "transaction".magenta(),
                DecoratorSemantic::FeatureFlag { .. } => "feature-flag".bright_blue(),
                DecoratorSemantic::Deprecated { .. } => "deprecated".bright_red(),
                DecoratorSemantic::Other { name, .. } => name.as_str().dimmed(),
            })
            .collect();

        if is_writer {
            badges.push("writes-db".bright_magenta());
        }

        let badge_line: Vec<String> = badges.iter().map(|b| format!("[{}]", b)).collect();
        println!("             {}", badge_line.join(" "));
    }

    if has_schemas {
        let mut parts: Vec<String> = Vec::new();
        if let Some(req) = request_schema {
            parts.push(format!("in:{}", req.cyan()));
        }
        if let Some(resp) = response_schema {
            parts.push(format!("out:{}", resp.cyan()));
        }
        println!("             {}", parts.join("  ").dimmed());
    }
}

pub async fn execute_coverage(args: CoverageArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    // Query-cache key
    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);
    let cache_params = format!(
        "{}|{}|{}",
        args.target,
        args.method.as_deref().unwrap_or(""),
        if args.refresh_cache { "refresh" } else { "" },
    );

    if !args.verbose && !args.refresh_cache {
        if let Some(ctx) = crate::session::query_cache::get::<CoverageContext>(
            &workspace_path,
            "coverage",
            &cache_params,
            &commit_sha,
        ) {
            return render_coverage_output(&ctx, args.json);
        }
    }

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

    // Resolve the target to an anchor node.
    let target = &args.target;
    let max_depth = args.max_depth;
    let method_filter = args.method.as_deref();

    let Some(ctx) = build_coverage_context(&graph, target, method_filter, max_depth, args.verbose)
    else {
        if args.json {
            println!("null");
        } else {
            eprintln!(
                "{} Could not resolve '{}' to a route or function in the graph.",
                "error:".red().bold(),
                target
            );
            eprintln!(
                "  Try: unfault graph routes  or  unfault graph handlers {}",
                target
            );
        }
        return Ok(EXIT_ERROR);
    };

    crate::session::query_cache::set::<CoverageContext>(
        &workspace_path,
        "coverage",
        &cache_params,
        &commit_sha,
        &ctx,
    );

    render_coverage_output(&ctx, args.json)
}

// ── Coverage graph walk ───────────────────────────────────────────────────────

/// Build a full `CoverageContext` by resolving `target` (route path or function
/// name) to an anchor node, then walking callers upward and callees downward.
///
/// Returns `None` when the target cannot be resolved.
fn build_coverage_context(
    graph: &unfault_analysis::graph::CodeGraph,
    target: &str,
    method_filter: Option<&str>,
    max_depth: Option<usize>,
    verbose: bool,
) -> Option<CoverageContext> {
    use unfault_analysis::graph::GraphNode;

    // ── Resolve anchor ────────────────────────────────────────────────────────
    // First try: HTTP route path (starts with '/' or contains '/')
    // Second try: function name substring match
    let anchor_idx = if target.starts_with('/') || target.contains('/') {
        find_handler_by_route(graph, target, method_filter)
    } else {
        find_function_by_name(graph, target)
    };

    let anchor_idx = anchor_idx.or_else(|| find_function_by_name(graph, target))?;

    let anchor_node = &graph.graph[anchor_idx];
    let (anchor_name, anchor_file, anchor_line, resolved_as) = match anchor_node {
        GraphNode::Function {
            name,
            http_method: Some(method),
            http_path: Some(path),
            line,
            ..
        } => {
            let file = unfault_analysis::graph::traversal::node_file_path_pub(graph, anchor_node)
                .unwrap_or_default();
            let desc = format!("route {} {}", method.to_uppercase(), path);
            (name.clone(), file, *line, desc)
        }
        GraphNode::Function { name, line, .. } => {
            let file = unfault_analysis::graph::traversal::node_file_path_pub(graph, anchor_node)
                .unwrap_or_default();
            let desc = format!("function {}", name);
            (name.clone(), file, *line, desc)
        }
        _ => return None,
    };

    if verbose {
        eprintln!("  coverage anchor: {} ({})", anchor_name, resolved_as);
    }

    // Build per-file library category index once — used when classifying roles.
    let file_libs = build_file_library_index(graph);

    // ── Walk callees (downward) ───────────────────────────────────────────────
    let mut callees = walk_callees(graph, anchor_idx, max_depth, &file_libs, 1);

    // Fallback: if the graph walk found no callees (cross-file calls that weren't
    // resolved into Calls edges), synthesise stub nodes from the anchor's raw_calls
    // list so the tree isn't empty and gaps are still visible.
    if callees.is_empty() {
        callees = stub_callees_from_raw_calls(graph, anchor_node, &file_libs);
    }

    // ── Walk callers (upward) ─────────────────────────────────────────────────
    let callers = walk_callers(graph, anchor_idx, max_depth, &file_libs, 1);

    // ── Build anchor node ─────────────────────────────────────────────────────
    let anchor_role = node_role(graph, anchor_idx, anchor_node, &file_libs);
    let anchor_span = node_span_signal(graph, anchor_node, &file_libs);

    let anchor = CoverageNode {
        name: anchor_name.clone(),
        file: anchor_file,
        line: anchor_line,
        depth: 0,
        direction: "root".to_string(),
        span: anchor_span,
        role: anchor_role,
        children: callees.clone(),
    };

    // ── Summary ───────────────────────────────────────────────────────────────
    let mut all_nodes: Vec<&CoverageNode> = Vec::new();
    collect_nodes(&anchor, &mut all_nodes);
    for n in &callers {
        collect_nodes(n, &mut all_nodes);
    }

    let summary = CoverageTreeSummary {
        total_nodes: all_nodes.len(),
        instrumented: all_nodes
            .iter()
            .filter(|n| n.span != SpanSignal::None)
            .count(),
        uninstrumented: all_nodes
            .iter()
            .filter(|n| n.span == SpanSignal::None)
            .count(),
        db_boundaries: all_nodes
            .iter()
            .filter(|n| matches!(n.role, NodeRole::Database))
            .count(),
        http_boundaries: all_nodes
            .iter()
            .filter(|n| matches!(n.role, NodeRole::HttpClient))
            .count(),
        remote_calls: all_nodes
            .iter()
            .filter(|n| matches!(n.role, NodeRole::RemoteCall { .. }))
            .count(),
    };

    Some(CoverageContext {
        target: target.to_string(),
        resolved_as,
        callers,
        anchor,
        callees,
        summary,
    })
}

fn collect_nodes<'a>(node: &'a CoverageNode, out: &mut Vec<&'a CoverageNode>) {
    out.push(node);
    for child in &node.children {
        collect_nodes(child, out);
    }
}

/// Walk Calls edges downward (callees), stopping at library boundaries.
fn walk_callees(
    graph: &unfault_analysis::graph::CodeGraph,
    from: unfault_analysis::graph::GraphNodeIndex,
    max_depth: Option<usize>,
    file_libs: &FileLibIndex,
    depth: i32,
) -> Vec<CoverageNode> {
    let mut result = Vec::new();
    let mut visited = std::collections::HashSet::new();
    walk_callees_inner(
        graph,
        from,
        max_depth,
        file_libs,
        depth,
        &mut visited,
        &mut result,
        "down",
    );
    result
}

#[allow(clippy::too_many_arguments)]
fn walk_callees_inner(
    graph: &unfault_analysis::graph::CodeGraph,
    from: unfault_analysis::graph::GraphNodeIndex,
    max_depth: Option<usize>,
    file_libs: &std::collections::HashMap<
        String,
        Vec<(String, unfault_core::graph::ModuleCategory)>,
    >,
    depth: i32,
    visited: &mut std::collections::HashSet<unfault_analysis::graph::GraphNodeIndex>,
    out: &mut Vec<CoverageNode>,
    direction: &str,
) {
    use petgraph::Direction;
    use petgraph::visit::EdgeRef as _;
    use unfault_analysis::graph::{GraphEdgeKind, GraphNode};

    if visited.contains(&from) {
        return;
    }
    if let Some(max) = max_depth {
        if depth as usize > max {
            return;
        }
    }
    visited.insert(from);

    for edge in graph.graph.edges_directed(from, Direction::Outgoing) {
        if !matches!(edge.weight(), GraphEdgeKind::Calls) {
            continue;
        }
        let callee_idx = edge.target();
        let callee_node = &graph.graph[callee_idx];

        let (name, file, line) = match callee_node {
            GraphNode::Function { name, line, .. } => {
                let f = unfault_analysis::graph::traversal::node_file_path_pub(graph, callee_node)
                    .unwrap_or_default();
                (name.clone(), f, *line)
            }
            _ => continue,
        };

        let role = node_role(graph, callee_idx, callee_node, file_libs);
        let span = node_span_signal(graph, callee_node, file_libs);

        // Stop recursing at library-boundary nodes but still emit the node.
        let is_boundary = matches!(
            role,
            NodeRole::Database | NodeRole::HttpClient | NodeRole::RemoteCall { .. }
        );

        let mut children = Vec::new();
        if !is_boundary {
            walk_callees_inner(
                graph,
                callee_idx,
                max_depth,
                file_libs,
                depth + 1,
                visited,
                &mut children,
                direction,
            );
        }

        out.push(CoverageNode {
            name,
            file,
            line,
            depth,
            direction: direction.to_string(),
            span,
            role,
            children,
        });
    }
}

/// Walk Calls edges upward (callers), stopping at max_depth hops.
fn walk_callers(
    graph: &unfault_analysis::graph::CodeGraph,
    from: unfault_analysis::graph::GraphNodeIndex,
    max_depth: Option<usize>,
    file_libs: &FileLibIndex,
    depth: i32,
) -> Vec<CoverageNode> {
    let mut result = Vec::new();
    let mut visited = std::collections::HashSet::new();
    visited.insert(from);
    walk_callers_inner(
        graph,
        from,
        max_depth,
        file_libs,
        depth,
        &mut visited,
        &mut result,
    );
    result
}

#[allow(clippy::too_many_arguments)]
fn walk_callers_inner(
    graph: &unfault_analysis::graph::CodeGraph,
    from: unfault_analysis::graph::GraphNodeIndex,
    max_depth: Option<usize>,
    file_libs: &std::collections::HashMap<
        String,
        Vec<(String, unfault_core::graph::ModuleCategory)>,
    >,
    depth: i32,
    visited: &mut std::collections::HashSet<unfault_analysis::graph::GraphNodeIndex>,
    out: &mut Vec<CoverageNode>,
) {
    use petgraph::Direction;
    use petgraph::visit::EdgeRef as _;
    use unfault_analysis::graph::{GraphEdgeKind, GraphNode};

    if let Some(max) = max_depth {
        if depth as usize > max {
            return;
        }
    }

    for edge in graph.graph.edges_directed(from, Direction::Incoming) {
        if !matches!(edge.weight(), GraphEdgeKind::Calls) {
            continue;
        }
        let caller_idx = edge.source();
        if visited.contains(&caller_idx) {
            continue;
        }
        visited.insert(caller_idx);

        let caller_node = &graph.graph[caller_idx];
        let (name, file, line) = match caller_node {
            GraphNode::Function { name, line, .. } => {
                let f = unfault_analysis::graph::traversal::node_file_path_pub(graph, caller_node)
                    .unwrap_or_default();
                (name.clone(), f, *line)
            }
            _ => continue,
        };

        let role = node_role(graph, caller_idx, caller_node, file_libs);
        let span = node_span_signal(graph, caller_node, file_libs);

        out.push(CoverageNode {
            name,
            file,
            line,
            depth,
            direction: "up".to_string(),
            span,
            role,
            children: Vec::new(),
        });

        walk_callers_inner(
            graph,
            caller_idx,
            max_depth,
            file_libs,
            depth + 1,
            visited,
            out,
        );
    }
}

// ── Signal detection ──────────────────────────────────────────────────────────

/// Extract a `SpanSignal` for a function.
/// When the graph walk finds no `Calls` edges from the anchor (common for
/// cross-file async calls whose imports weren't resolved), synthesise stub
/// `CoverageNode`s from the `raw_calls` field baked into the graph node at
/// build time.  These stubs have `SpanSignal::None` and `NodeRole::Logic` by
/// default — they show up in the tree and in the nudge list so the developer
/// can see the gap.
fn stub_callees_from_raw_calls(
    graph: &unfault_analysis::graph::CodeGraph,
    anchor_node: &unfault_analysis::graph::GraphNode,
    file_libs: &FileLibIndex,
) -> Vec<CoverageNode> {
    use unfault_analysis::graph::GraphNode;

    let GraphNode::Function {
        raw_calls, file_id, ..
    } = anchor_node
    else {
        return vec![];
    };

    // Deduplicate and skip trivial / noise names.
    let mut seen = std::collections::HashSet::new();
    let mut result = Vec::new();

    for call_expr in raw_calls {
        // Skip method calls on `self`, injected deps like `db_session.get`,
        // built-ins, and very short names.
        let name = call_expr.split('.').last().unwrap_or(call_expr.as_str());
        if name.len() < 3 || name.starts_with('_') && name.ends_with('_') {
            continue;
        }
        // Skip the obvious SQLAlchemy / FastAPI dependency calls
        const SKIP: &[&str] = &[
            "get",
            "add",
            "commit",
            "rollback",
            "flush",
            "execute",
            "scalar",
            "scalars",
            "close",
            "depends",
            "HTTPException",
        ];
        if SKIP.contains(&name) {
            continue;
        }
        if !seen.insert(name.to_string()) {
            continue;
        }

        // See if there's a resolved Function node in the graph with this name
        // (could be same file or cross-file that was resolved).
        let resolved = graph.graph.node_indices().find(|&idx| {
            if let GraphNode::Function {
                name: fn_name,
                file_id: fid,
                ..
            } = &graph.graph[idx]
            {
                fn_name == name && fid == file_id
            } else {
                false
            }
        });

        let (file, line, span, role) = if let Some(idx) = resolved {
            let node = &graph.graph[idx];
            let f = unfault_analysis::graph::traversal::node_file_path_pub(graph, node)
                .unwrap_or_default();
            let l = if let GraphNode::Function { line, .. } = node {
                *line
            } else {
                None
            };
            let s = node_span_signal(graph, node, file_libs);
            let r = node_role(graph, idx, node, file_libs);
            (f, l, s, r)
        } else {
            (String::new(), None, SpanSignal::None, NodeRole::Logic)
        };

        result.push(CoverageNode {
            name: name.to_string(),
            file,
            line,
            depth: 1,
            direction: "down".to_string(),
            span,
            role,
            children: vec![],
        });
    }

    result
}

///
/// Priority:
/// 1. A tracing decorator / context manager (`@trace`, `@instrument`, etc.)
///    → `SpanSignal::Decorator` with the extracted span name if any.
/// 2. The file that contains the function imports an OTel / tracing SDK
///    → `SpanSignal::SdkImported` with the library name.
/// 3. Neither → `SpanSignal::None`.
fn node_span_signal(
    graph: &unfault_analysis::graph::CodeGraph,
    node: &unfault_analysis::graph::GraphNode,
    file_libs: &FileLibIndex,
) -> SpanSignal {
    use unfault_analysis::graph::GraphNode;
    use unfault_core::graph::{DecoratorSemantic, ModuleCategory};

    if let GraphNode::Function { decorators, .. } = node {
        for dec in decorators {
            if let DecoratorSemantic::Tracing { detail } = dec {
                let span_name = extract_span_name_from_detail(detail);
                return SpanSignal::Decorator { name: span_name };
            }
        }
    }

    let file =
        unfault_analysis::graph::traversal::node_file_path_pub(graph, node).unwrap_or_default();
    if let Some(libs) = file_libs.get(&file) {
        for (lib_name, cat) in libs {
            if matches!(cat, ModuleCategory::Observability) {
                return SpanSignal::SdkImported {
                    library: lib_name.clone(),
                };
            }
        }
    }

    SpanSignal::None
}

/// Heuristically extract a span name from a decorator/context-manager detail
/// string such as `@trace("my-span")` or `with tracer.start_as_current_span("checkout")`.
fn extract_span_name_from_detail(detail: &str) -> Option<String> {
    // Look for a quoted string argument anywhere in the detail.
    for quote in ['"', '\''] {
        if let Some(start) = detail.find(quote) {
            let rest = &detail[start + 1..];
            if let Some(end) = rest.find(quote) {
                let candidate = &rest[..end];
                if !candidate.is_empty() && !candidate.contains('\n') {
                    return Some(candidate.to_string());
                }
            }
        }
    }
    None
}

/// Classify the semantic role of a function using its file's library imports.
fn node_role(
    graph: &unfault_analysis::graph::CodeGraph,
    _idx: unfault_analysis::graph::GraphNodeIndex,
    node: &unfault_analysis::graph::GraphNode,
    file_libs: &std::collections::HashMap<
        String,
        Vec<(String, unfault_core::graph::ModuleCategory)>,
    >,
) -> NodeRole {
    use unfault_analysis::graph::GraphNode;
    use unfault_core::graph::ModuleCategory;

    // HTTP route handler?
    if let GraphNode::Function {
        is_handler: true,
        http_method: Some(method),
        http_path: Some(path),
        ..
    } = node
    {
        return NodeRole::HttpHandler {
            method: method.clone(),
            path: path.clone(),
        };
    }

    // Check file-level library edges.
    let file =
        unfault_analysis::graph::traversal::node_file_path_pub(graph, node).unwrap_or_default();
    if let Some(libs) = file_libs.get(&file) {
        let mut has_db = false;
        let mut has_http = false;
        let mut has_obs = false;
        for (_, cat) in libs {
            match cat {
                ModuleCategory::Database => has_db = true,
                ModuleCategory::HttpClient => has_http = true,
                ModuleCategory::Observability => has_obs = true,
                _ => {}
            }
        }
        // Observability library import → the span signal handles this; the role
        // is still the underlying boundary type if both are present.
        if has_db {
            return NodeRole::Database;
        }
        if has_http {
            return NodeRole::HttpClient;
        }
        let _ = has_obs; // signal is in SpanSignal, not NodeRole
    }

    NodeRole::Logic
}

// ── File → library index ──────────────────────────────────────────────────────

type FileLibIndex =
    std::collections::HashMap<String, Vec<(String, unfault_core::graph::ModuleCategory)>>;

/// Build a map from file path → list of (library name, category) for all
/// UsesLibrary edges in the graph.  Built once per execute_coverage call.
fn build_file_library_index(graph: &unfault_analysis::graph::CodeGraph) -> FileLibIndex {
    use petgraph::Direction;
    use petgraph::visit::EdgeRef as _;
    use unfault_analysis::graph::{GraphEdgeKind, GraphNode};

    let mut index: FileLibIndex = std::collections::HashMap::new();

    for node_idx in graph.graph.node_indices() {
        if let GraphNode::File { path, .. } = &graph.graph[node_idx] {
            for edge in graph.graph.edges_directed(node_idx, Direction::Outgoing) {
                if !matches!(edge.weight(), GraphEdgeKind::UsesLibrary) {
                    continue;
                }
                if let GraphNode::ExternalModule { name, category, .. } =
                    &graph.graph[edge.target()]
                {
                    index
                        .entry(path.clone())
                        .or_default()
                        .push((name.clone(), category.clone()));
                }
            }
        }
    }

    index
}

// ── Target resolution ─────────────────────────────────────────────────────────

fn find_handler_by_route(
    graph: &unfault_analysis::graph::CodeGraph,
    route: &str,
    method_filter: Option<&str>,
) -> Option<unfault_analysis::graph::GraphNodeIndex> {
    use unfault_analysis::graph::GraphNode;

    let normalized = crate::slo::matcher::normalize_route_path(route);

    graph.graph.node_indices().find(|&idx| {
        if let GraphNode::Function {
            is_handler: true,
            http_path: Some(path),
            http_method,
            ..
        } = &graph.graph[idx]
        {
            let path_match = crate::slo::matcher::normalize_route_path(path) == normalized;
            let method_match = method_filter
                .map(|m| {
                    http_method
                        .as_deref()
                        .map(|hm| hm.eq_ignore_ascii_case(m))
                        .unwrap_or(false)
                })
                .unwrap_or(true);
            path_match && method_match
        } else {
            false
        }
    })
}

fn find_function_by_name(
    graph: &unfault_analysis::graph::CodeGraph,
    name: &str,
) -> Option<unfault_analysis::graph::GraphNodeIndex> {
    use unfault_analysis::graph::GraphNode;

    let lower = name.to_lowercase();
    // Exact match first, then substring.
    graph
        .graph
        .node_indices()
        .find(|&idx| {
            if let GraphNode::Function { name: fn_name, .. } = &graph.graph[idx] {
                fn_name.to_lowercase() == lower
            } else {
                false
            }
        })
        .or_else(|| {
            graph.graph.node_indices().find(|&idx| {
                if let GraphNode::Function { name: fn_name, .. } = &graph.graph[idx] {
                    fn_name.to_lowercase().contains(&lower)
                } else {
                    false
                }
            })
        })
}

// ── Renderer ──────────────────────────────────────────────────────────────────

fn render_coverage_output(ctx: &CoverageContext, json: bool) -> Result<i32> {
    if json {
        println!("{}", serde_json::to_string_pretty(ctx)?);
        return Ok(EXIT_SUCCESS);
    }

    // ── Header ────────────────────────────────────────────────────────────────
    println!();
    println!(
        "  {} Observability coverage  {}",
        "→".cyan(),
        ctx.resolved_as.bright_white().bold()
    );
    println!();

    // ── Legend (one line, compact) ────────────────────────────────────────────
    println!(
        "  {} span  {} sdk  {} uninstrumented  {} boundary",
        "●".green(),
        "◑".yellow(),
        "○".normal(),
        "[db/http/remote]".cyan()
    );
    println!();

    // ── Call tree ─────────────────────────────────────────────────────────────
    // Fixed left margin so callers/anchor/callees all sit at the same column.
    const BASE: usize = 4;

    // Callers — sort deepest first (oldest ancestor at top, direct caller just above anchor)
    if !ctx.callers.is_empty() {
        let mut sorted: Vec<&CoverageNode> = ctx.callers.iter().collect();
        sorted.sort_by(|a, b| b.depth.cmp(&a.depth).then(a.name.cmp(&b.name)));
        let max_depth = sorted[0].depth as usize;

        for caller in &sorted {
            // Indent each caller proportionally: oldest = BASE, direct = BASE + (max-1)*2
            let extra = (max_depth - caller.depth as usize) * 2;
            print_node_row(caller, BASE + extra, None);
        }
        // Connector: vertical bar running from the direct caller down to the anchor
        let connector_indent = BASE + (max_depth - 1) * 2;
        println!("{}│", " ".repeat(connector_indent + 2)); // +2 to align under the icon
    }

    // Anchor — printed at BASE
    print_node_row(&ctx.anchor, BASE, None);

    // Callees — tree hanging below the anchor
    if !ctx.callees.is_empty() {
        print_callee_tree(&ctx.callees, BASE, "");
    }

    println!();

    // ── Summary ───────────────────────────────────────────────────────────────
    let s = &ctx.summary;
    let pct = if s.total_nodes > 0 {
        (s.instrumented * 100) / s.total_nodes
    } else {
        0
    };
    let pct_str = format!("{}%", pct);
    let pct_colored = if pct >= 80 {
        pct_str.green().to_string()
    } else if pct >= 40 {
        pct_str.yellow().to_string()
    } else {
        pct_str.red().to_string()
    };

    println!(
        "  {pct} of {} functions carry span signal  ·  {} boundaries ({} db, {} http-client, {} remote)",
        s.total_nodes,
        s.db_boundaries + s.http_boundaries + s.remote_calls,
        s.db_boundaries,
        s.http_boundaries,
        s.remote_calls,
        pct = pct_colored,
    );
    println!();

    // ── Category-based coverage breakdown ────────────────────────────────────
    // Group all nodes in the tree by their semantic category, then report
    // coverage at the category level rather than per-function.  This lets the
    // engineer reason at the right level: "I have a blind spot in db queries"
    // rather than "these three function names are uninstrumented".

    let mut all_nodes: Vec<&CoverageNode> = Vec::new();
    collect_nodes(&ctx.anchor, &mut all_nodes);
    for c in &ctx.callers {
        collect_nodes(c, &mut all_nodes);
    }

    render_category_breakdown(&all_nodes, &ctx.anchor.name);

    Ok(EXIT_SUCCESS)
}

/// A grouping of nodes that share the same semantic category.
struct CategoryGroup<'a> {
    label: &'static str,
    /// Hint shown when coverage is 0% — tells the engineer what they'll miss.
    blind_spot_hint: &'static str,
    /// Hint shown when coverage is partial.
    partial_hint: &'static str,
    nodes: Vec<&'a CoverageNode>,
}

impl<'a> CategoryGroup<'a> {
    fn covered(&self) -> Vec<&CoverageNode> {
        self.nodes
            .iter()
            .copied()
            .filter(|n| n.span != SpanSignal::None)
            .collect()
    }

    fn uncovered(&self) -> Vec<&CoverageNode> {
        self.nodes
            .iter()
            .copied()
            .filter(|n| n.span == SpanSignal::None)
            .collect()
    }
}

fn render_category_breakdown(all_nodes: &[&CoverageNode], anchor_name: &str) {
    // Partition nodes into categories.  A node can only be in one.
    let mut db: Vec<&CoverageNode> = Vec::new();
    let mut remote: Vec<&CoverageNode> = Vec::new();
    let mut http_client: Vec<&CoverageNode> = Vec::new();
    let mut auth: Vec<&CoverageNode> = Vec::new();
    let mut logic: Vec<&CoverageNode> = Vec::new();

    for &node in all_nodes {
        match &node.role {
            NodeRole::Database => db.push(node),
            NodeRole::RemoteCall { .. } => remote.push(node),
            NodeRole::HttpClient => http_client.push(node),
            NodeRole::Logic => {
                // Auth / middleware: functions whose decorators include Auth.
                let has_auth = matches!(node.role, NodeRole::Logic)
                    && node.name.to_lowercase().contains("auth")
                    || node.name.to_lowercase().contains("permission")
                    || node.name.to_lowercase().contains("middleware");
                if has_auth {
                    auth.push(node);
                } else {
                    logic.push(node);
                }
            }
            NodeRole::HttpHandler { .. } => {} // anchor itself — skip
        }
    }

    let groups: Vec<CategoryGroup> = vec![
        CategoryGroup {
            label: "db queries",
            blind_spot_hint: "wrap db calls in a span to catch timeouts and query errors",
            partial_hint: "some db calls are untraced — you may miss slow queries",
            nodes: db,
        },
        CategoryGroup {
            label: "remote calls",
            blind_spot_hint: "wrap remote calls in a span to catch downstream failures",
            partial_hint: "some remote calls are untraced — partial visibility into downstream",
            nodes: remote,
        },
        CategoryGroup {
            label: "http-client calls",
            blind_spot_hint: "wrap outbound http calls in a span to catch connection errors",
            partial_hint: "some outbound http calls are untraced",
            nodes: http_client,
        },
        CategoryGroup {
            label: "auth / middleware",
            blind_spot_hint: "wrap auth checks in a span to see permission failures",
            partial_hint: "some auth checks are untraced",
            nodes: auth,
        },
        CategoryGroup {
            label: "business logic",
            blind_spot_hint: "core logic is uninstrumented — failures will have no trace context",
            partial_hint: "partial logic coverage — some code paths will be dark",
            nodes: logic,
        },
    ];

    // Only render categories that have at least one node.
    let active: Vec<&CategoryGroup> = groups.iter().filter(|g| !g.nodes.is_empty()).collect();

    if active.is_empty() {
        println!(
            "  {} No calls detected from {} — nothing to evaluate.",
            "·".bright_black(),
            anchor_name.bright_white()
        );
        println!();
        return;
    }

    println!(
        "  Coverage breakdown for {}\n",
        anchor_name.bright_white().bold()
    );

    let all_full = active.iter().all(|g| g.uncovered().is_empty());
    if all_full {
        println!(
            "  {} All categories fully covered — good trust awareness.",
            "✓".green()
        );
        println!();
        return;
    }

    for group in &active {
        let covered = group.covered();
        let uncovered = group.uncovered();
        let total = group.nodes.len();

        let (icon, ratio_colored, hint) = if uncovered.is_empty() {
            // Full coverage
            let ratio = format!("{} / {}", total, total).green().to_string();
            ("●".green().to_string(), ratio, None)
        } else if covered.is_empty() {
            // Zero coverage — blind spot
            let ratio = format!("0 / {}", total).red().to_string();
            ("○".normal().to_string(), ratio, Some(group.blind_spot_hint))
        } else {
            // Partial
            let ratio = format!("{} / {}", covered.len(), total)
                .yellow()
                .to_string();
            ("◑".yellow().to_string(), ratio, Some(group.partial_hint))
        };

        // Names inline only when ≤ 3 nodes total
        let names = if total <= 3 {
            let names_str = group
                .nodes
                .iter()
                .map(|n| n.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            format!("  {}", names_str.bright_black())
        } else {
            String::new()
        };

        println!(
            "  {}  {:<18}  {}{}",
            icon, group.label, ratio_colored, names,
        );

        if let Some(h) = hint {
            println!("     {}", h.bright_black());
        }
    }

    println!();
}

// ── Tree drawing helpers ──────────────────────────────────────────────────────

/// Print a single node row (icon  name  [badge]  file:line).
/// `prefix` is a box-drawing prefix like "├─ " inserted between indent and icon.
fn print_node_row(node: &CoverageNode, indent: usize, prefix: Option<&str>) {
    let icon = span_icon(&node.span);
    let name = node_name_str(node);
    let badge = role_badge_str(&node.role);
    let badge_part = if badge.is_empty() {
        String::new()
    } else {
        format!("  {}", badge.cyan())
    };
    let loc = node_loc(node);

    if let Some(p) = prefix {
        println!(
            "{}{}{} {}{}  {}",
            " ".repeat(indent),
            p,
            icon,
            name,
            badge_part,
            loc.bright_black()
        );
    } else {
        println!(
            "{}{} {}{}  {}",
            " ".repeat(indent),
            icon,
            name,
            badge_part,
            loc.bright_black()
        );
    }
}

/// Recursively render callees as a box-drawing tree.
/// `pad` is the accumulated vertical-bar prefix for deeper levels,
/// e.g. "│  │  " for the third level.
fn print_callee_tree(nodes: &[CoverageNode], indent: usize, pad: &str) {
    for (i, node) in nodes.iter().enumerate() {
        let last = i == nodes.len() - 1;
        let branch = if last { "└─ " } else { "├─ " };
        let child_pad = format!("{}{}", pad, if last { "   " } else { "│  " });
        let full_prefix = format!("{}{}", pad, branch);
        print_node_row(node, indent, Some(&full_prefix));
        if !node.children.is_empty() {
            print_callee_tree(&node.children, indent, &child_pad);
        }
    }
}

// ── Node formatting helpers ───────────────────────────────────────────────────

fn span_icon(signal: &SpanSignal) -> colored::ColoredString {
    match signal {
        SpanSignal::Decorator { .. } => "●".green(),
        SpanSignal::SdkImported { .. } => "◑".yellow(),
        SpanSignal::None => "○".normal(),
    }
}

fn node_name_str(node: &CoverageNode) -> String {
    match &node.span {
        SpanSignal::Decorator {
            name: Some(span_name),
        } => format!(
            "{}  {}",
            node.name.bright_white(),
            format!("\"{}\"", span_name).green()
        ),
        SpanSignal::Decorator { name: None } => node.name.bright_white().to_string(),
        SpanSignal::SdkImported { library } => format!(
            "{}  {}",
            node.name.bright_white(),
            format!("sdk:{}", library).yellow()
        ),
        SpanSignal::None => node.name.normal().to_string(),
    }
}

fn role_badge_str(role: &NodeRole) -> String {
    match role {
        NodeRole::HttpHandler { method, path } => format!("{} {}", method, path),
        NodeRole::Database => "db".to_string(),
        NodeRole::HttpClient => "http-client".to_string(),
        NodeRole::RemoteCall { service } => format!("remote:{}", service),
        NodeRole::Logic => String::new(),
    }
}

fn node_loc(node: &CoverageNode) -> String {
    node.line
        .map(|l| format!("{}:{}", node.file, l))
        .unwrap_or_else(|| node.file.clone())
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn extract_span_name_double_quoted() {
        assert_eq!(
            extract_span_name_from_detail("@trace(\"checkout\")"),
            Some("checkout".to_string())
        );
    }

    #[test]
    fn extract_span_name_single_quoted() {
        assert_eq!(
            extract_span_name_from_detail("with tracer.start_as_current_span('place-order')"),
            Some("place-order".to_string())
        );
    }

    #[test]
    fn extract_span_name_none_when_no_quotes() {
        assert_eq!(extract_span_name_from_detail("@instrument"), None);
    }
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
    let (file_hint, function_name) = match args.function.split_once(':') {
        Some((file, func)) => (Some(file.to_string()), func.to_string()),
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

    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);
    if !args.verbose {
        if let Some(flow) = crate::session::query_cache::get_function_impact(
            &workspace_path,
            &args.function,
            args.max_depth as usize,
            &commit_sha,
        ) {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&flow)?);
                return Ok(EXIT_SUCCESS);
            }
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
            for (i, path) in flow.paths.iter().enumerate() {
                println!("  Path {}:", i + 1);
                for node in path {
                    let indent = "  ".repeat(node.depth + 2);
                    let fi = node
                        .file_path
                        .as_deref()
                        .map(|p| format!(" ({})", p))
                        .unwrap_or_default();
                    println!(
                        "{}{} {}{}",
                        indent,
                        "→".cyan(),
                        node.name.bright_white(),
                        fi.dimmed()
                    );
                }
                println!();
            }
            return Ok(EXIT_SUCCESS);
        }
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
        file_hint.as_deref(),
        args.max_depth as usize,
    );
    crate::session::query_cache::set_function_impact(
        &workspace_path,
        &args.function,
        args.max_depth as usize,
        &commit_sha,
        &flow,
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
    /// Exclude wiring/bootstrap callers (blueprint registration, app factories,
    /// __init__.py entry-points) from the output.
    pub exclude_wiring: bool,
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

    // ── Query cache fast path ─────────────────────────────────────────────────
    // Skip when --debug is set (debug needs the live graph) or --verbose
    // (user wants timing info, so they want the full run).
    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);

    let cached_ctx = if !args.debug && !args.verbose {
        crate::session::query_cache::get_callers(
            &workspace_path,
            &function_name,
            file_hint.as_deref(),
            &commit_sha,
        )
    } else {
        None
    };

    if let Some(ctx) = cached_ctx {
        if args.verbose {
            eprintln!(
                "{} Query cache hit (commit {})",
                "→".cyan(),
                &commit_sha[..8.min(commit_sha.len())]
            );
        }
        return render_callers_output(ctx, &function_name, None, args.json, args.exclude_wiring);
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

    // Debug mode — dump raw graph diagnostics.
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

    if !args.debug {
        crate::session::query_cache::set_callers(
            &workspace_path,
            &function_name,
            file_hint.as_deref(),
            &commit_sha,
            &ctx,
        );
    }

    render_callers_output(
        ctx,
        &function_name,
        Some(&graph),
        args.json,
        args.exclude_wiring,
    )
}

// =============================================================================
// Brief
// =============================================================================

/// Arguments for `graph brief <path>`.
#[derive(Debug)]
pub struct BriefArgs {
    pub workspace_path: Option<String>,
    /// Subtree path prefix / substring to analyse (e.g. `apps/payroll_tool`).
    pub path: String,
    pub json: bool,
    pub verbose: bool,
}

/// Execute `unfault graph brief <path>`.
pub async fn execute_brief(args: BriefArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);

    if !args.verbose {
        if let Some(ctx) = crate::session::query_cache::get::<
            unfault_core::types::graph_query::BriefContext,
        >(&workspace_path, "brief", &args.path, &commit_sha)
        {
            return render_brief_output(ctx, args.json);
        }
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

    let ctx = unfault_analysis::graph::traversal::get_brief(&graph, &args.path);

    crate::session::query_cache::set::<unfault_core::types::graph_query::BriefContext>(
        &workspace_path,
        "brief",
        &args.path,
        &commit_sha,
        &ctx,
    );

    render_brief_output(ctx, args.json)
}

fn render_brief_output(
    ctx: unfault_core::types::graph_query::BriefContext,
    json: bool,
) -> Result<i32> {
    use unfault_core::types::graph_query::EntryPointReason;

    if json {
        println!("{}", serde_json::to_string_pretty(&ctx)?);
        return Ok(EXIT_SUCCESS);
    }

    if ctx.size.files == 0 {
        println!(
            "\n  {} No files found matching '{}'.\n",
            "ℹ".cyan(),
            ctx.path
        );
        return Ok(EXIT_SUCCESS);
    }

    println!(
        "\n{} Brief: {}\n",
        "→".cyan(),
        ctx.path.bright_white().bold()
    );
    println!(
        "  {} files  {} functions\n",
        ctx.size.files.to_string().yellow(),
        ctx.size.functions.to_string().yellow(),
    );

    // ── Routes ────────────────────────────────────────────────────────────────
    if !ctx.routes.is_empty() {
        println!("{}", "  Routes".bold());
        let mut current_file = String::new();
        for r in &ctx.routes {
            if r.file != current_file {
                current_file = r.file.clone();
                println!("    {}", current_file.bright_blue());
            }
            let method_colored = match r.method.as_str() {
                "GET" => r.method.bright_green(),
                "POST" => r.method.bright_yellow(),
                "PUT" | "PATCH" => r.method.bright_cyan(),
                "DELETE" => r.method.bright_red(),
                _ => r.method.normal(),
            };
            let handler_loc = match r.line {
                Some(l) => format!("({}:{})", r.handler, l),
                None => format!("({})", r.handler),
            };
            println!(
                "      {:<8} {}  {}",
                method_colored,
                r.path,
                handler_loc.dimmed()
            );
            render_route_annotations(
                &r.decorators,
                r.is_writer,
                r.request_schema.as_deref(),
                r.response_schema.as_deref(),
            );
        }
        println!();
    }

    // ── Internal entry points (non-HTTP) ──────────────────────────────────────
    let non_http_entries: Vec<_> = ctx
        .internal_entry_points
        .iter()
        .filter(|e| !matches!(e.reason, EntryPointReason::HttpHandler))
        .collect();

    if !non_http_entries.is_empty() {
        println!("{}", "  Internal entry points".bold());
        for ep in &non_http_entries {
            let reason_label = match ep.reason {
                EntryPointReason::ExternalCallersOnly => "external callers only",
                EntryPointReason::ExportedUnused => "exported, no callers",
                EntryPointReason::HttpHandler => unreachable!(),
            };
            let loc = match ep.line {
                Some(l) => format!("{}:{}", ep.file, l),
                None => ep.file.clone(),
            };
            println!(
                "    {}  {}  {}",
                ep.name.bright_white(),
                loc.dimmed(),
                format!("[{}]", reason_label).dimmed()
            );
        }
        println!();
    }

    // ── Outgoing exports ──────────────────────────────────────────────────────
    if !ctx.outgoing_exports.is_empty() {
        println!(
            "{}",
            "  Outgoing exports  (used outside this subtree)".bold()
        );
        let mut current_file = String::new();
        for ex in &ctx.outgoing_exports {
            if ex.defined_in != current_file {
                current_file = ex.defined_in.clone();
                println!("    {}", current_file.bright_blue());
            }
            let importers = if ex.imported_by.len() == 1 {
                ex.imported_by[0].clone()
            } else {
                format!("{} files", ex.imported_by.len())
            };
            println!(
                "      {}  {}",
                ex.name.bright_white(),
                format!("← {}", importers).dimmed()
            );
        }
        println!();
    }

    // ── Incoming imports ──────────────────────────────────────────────────────
    if !ctx.incoming_imports.is_empty() {
        println!(
            "{}",
            "  Incoming imports  (dependencies from outside)".bold()
        );
        for imp in &ctx.incoming_imports {
            let sym_part = if imp.symbols.is_empty() {
                String::new()
            } else if imp.symbols.len() <= 4 {
                format!("  {}", imp.symbols.join(", ").dimmed())
            } else {
                format!("  {} symbols", imp.symbols.len())
                    .dimmed()
                    .to_string()
            };
            println!("    {}{}", imp.source.bright_white(), sym_part);
        }
        println!();
    }

    Ok(EXIT_SUCCESS)
}

// =============================================================================
// Path
// =============================================================================

#[derive(Debug)]
pub struct PathArgs {
    pub workspace_path: Option<String>,
    pub from: String,
    pub to: String,
    pub json: bool,
    pub verbose: bool,
}

/// Find the shortest call path between two named functions.
pub async fn execute_path(args: PathArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    let (from_hint, from_name) = match args.from.split_once(':') {
        Some((f, n)) => (Some(f.to_string()), n.to_string()),
        None => (None, args.from.clone()),
    };
    let (to_hint, to_name) = match args.to.split_once(':') {
        Some((f, n)) => (Some(f.to_string()), n.to_string()),
        None => (None, args.to.clone()),
    };

    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);
    let cache_key = format!("{}|{}", args.from, args.to);

    if !args.verbose {
        if let Some(ctx) =
            crate::session::query_cache::get_path(&workspace_path, &cache_key, "", &commit_sha)
        {
            return render_path_output(ctx, args.json);
        }
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

    let ctx = unfault_analysis::graph::traversal::find_path(
        &graph,
        &from_name,
        from_hint.as_deref(),
        &to_name,
        to_hint.as_deref(),
    );

    crate::session::query_cache::set_path(&workspace_path, &cache_key, "", &commit_sha, &ctx);

    render_path_output(ctx, args.json)
}

fn render_path_output(
    ctx: unfault_core::types::graph_query::PathContext,
    json: bool,
) -> Result<i32> {
    if json {
        println!("{}", serde_json::to_string_pretty(&ctx)?);
        return Ok(EXIT_SUCCESS);
    }

    println!();

    if !ctx.found {
        println!(
            "  {} No call path found from {} to {}.",
            "ℹ".cyan(),
            ctx.from.bright_white(),
            ctx.to.bright_white()
        );
        println!();
        return Ok(EXIT_SUCCESS);
    }

    println!(
        "{} Call path  {} → {}",
        "→".cyan(),
        ctx.from.bright_white().bold(),
        ctx.to.bright_white().bold()
    );
    println!();

    // Render entry routes if any.
    if !ctx.entry_routes.is_empty() {
        println!("  Reachable from:");
        for route in &ctx.entry_routes {
            let method_colored = match route.method.as_str() {
                "GET" => route.method.bright_green(),
                "POST" => route.method.bright_yellow(),
                "PUT" | "PATCH" => route.method.bright_cyan(),
                "DELETE" => route.method.bright_red(),
                _ => route.method.normal(),
            };
            println!("    {} {}", method_colored, route.path.bold());
        }
        println!();
    }

    // Render the path as a chain.
    for (i, node) in ctx.path.iter().enumerate() {
        let is_last = i == ctx.path.len() - 1;
        let connector = if is_last { "└─" } else { "├─" };
        let file_info = node
            .file_path
            .as_deref()
            .map(|p| format!("  ({})", p))
            .unwrap_or_default();
        let label = if i == 0 {
            node.name.bright_white().bold().to_string()
        } else if is_last {
            node.name.bright_blue().bold().to_string()
        } else {
            node.name.white().to_string()
        };
        println!("  {} {}{}", connector.dimmed(), label, file_info.dimmed());
    }

    println!();
    Ok(EXIT_SUCCESS)
}

// =============================================================================
// Handlers
// =============================================================================

#[derive(Debug)]
pub struct HandlersArgs {
    pub workspace_path: Option<String>,
    pub pattern: String,
    pub json: bool,
    pub verbose: bool,
}

/// Find all HTTP route handlers matching a path pattern.
pub async fn execute_handlers(args: HandlersArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    let commit_sha = crate::session::query_cache::current_commit_sha(&workspace_path);

    if !args.verbose {
        if let Some(ctx) =
            crate::session::query_cache::get_handlers(&workspace_path, &args.pattern, &commit_sha)
        {
            return render_handlers_output(ctx, args.json);
        }
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

    let ctx = unfault_analysis::graph::traversal::find_handlers(&graph, &args.pattern);

    crate::session::query_cache::set_handlers(&workspace_path, &args.pattern, &commit_sha, &ctx);

    render_handlers_output(ctx, args.json)
}

fn render_handlers_output(
    ctx: unfault_core::types::graph_query::HandlersContext,
    json: bool,
) -> Result<i32> {
    if json {
        println!("{}", serde_json::to_string_pretty(&ctx)?);
        return Ok(EXIT_SUCCESS);
    }

    println!();

    if ctx.handlers.is_empty() {
        println!(
            "  {} No handlers found matching '{}'.",
            "ℹ".cyan(),
            ctx.pattern
        );
        println!();
        return Ok(EXIT_SUCCESS);
    }

    println!(
        "{} {} handler{} matching '{}'\n",
        "→".cyan(),
        ctx.handlers.len().to_string().yellow(),
        if ctx.handlers.len() == 1 { "" } else { "s" },
        ctx.pattern.bright_white()
    );

    let mut current_file = String::new();
    for h in &ctx.handlers {
        if h.file != current_file {
            current_file = h.file.clone();
            println!("  {}", current_file.bright_blue());
        }
        let method_colored = match h.method.as_str() {
            "GET" => h.method.bright_green(),
            "POST" => h.method.bright_yellow(),
            "PUT" | "PATCH" => h.method.bright_cyan(),
            "DELETE" => h.method.bright_red(),
            _ => h.method.normal(),
        };
        let async_marker = if h.is_async { " async" } else { "" };
        let handler_loc = match h.line {
            Some(l) => format!("({}:{}){}", h.handler, l, async_marker),
            None => format!("({}){}", h.handler, async_marker),
        };
        println!(
            "    {:<8} {}  {}",
            method_colored,
            h.path,
            handler_loc.dimmed()
        );
        render_route_annotations(
            &h.decorators,
            h.is_writer,
            h.request_schema.as_deref(),
            h.response_schema.as_deref(),
        );
    }
    println!();
    Ok(EXIT_SUCCESS)
}

/// Render the callers output — shared by the cache-hit and live-graph paths.
///
/// `graph` is `None` on a cache hit — suggestions are skipped in that case
/// since we don't have the graph resident. The cache only hits when callers
/// were found, so the "no results" suggestion path is never reached on a hit.
fn render_callers_output(
    mut ctx: unfault_core::types::graph_query::CallersContext,
    function_name: &str,
    graph: Option<&unfault_analysis::graph::CodeGraph>,
    json: bool,
    exclude_wiring: bool,
) -> Result<i32> {
    use unfault_core::types::graph_query::CallerKind;

    // Apply wiring filter before JSON serialisation so the JSON is also clean.
    if exclude_wiring {
        ctx.callers.retain(|c| c.kind == CallerKind::BusinessLogic);
    }

    if json {
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

        let suggestions = if let Some(g) = graph {
            unfault_analysis::graph::traversal::suggest_callers_candidates(
                g,
                function_name,
                ctx.target_file.as_deref(),
            )
        } else {
            vec![]
        };

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
        let loc = match (ctx.target_line, ctx.target_column) {
            (Some(l), Some(c)) => format!("{}:{}:{}", f, l, c),
            (Some(l), None) => format!("{}:{}", f, l),
            _ => f.clone(),
        };
        println!("  {}", loc.dimmed());
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

    // ── Siblings ──────────────────────────────────────────────────────────────
    if !ctx.siblings.is_empty() {
        println!("  {} Siblings in same file:", "ℹ".cyan().dimmed());
        for sib in &ctx.siblings {
            if let (Some(m), Some(p)) = (&sib.http_method, &sib.http_path) {
                let method_colored = match m.as_str() {
                    "GET" => m.bright_green(),
                    "POST" => m.bright_yellow(),
                    "PUT" | "PATCH" => m.bright_cyan(),
                    "DELETE" => m.bright_red(),
                    _ => m.normal(),
                };
                println!("    {} {} ({})", method_colored, p, sib.name.dimmed());
            } else {
                println!("    {}", sib.name.dimmed());
            }
        }
        println!();
    }

    // ── Caveats ───────────────────────────────────────────────────────────────
    if !ctx.caveats.is_empty() {
        for caveat in &ctx.caveats {
            println!("  {} {}", "⚠".yellow(), caveat.dimmed());
        }
        println!();
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

// =============================================================================
// Refresh
// =============================================================================

#[derive(Debug)]
pub struct RefreshArgs {
    pub workspace_path: Option<String>,
    pub verbose: bool,
}

/// Clear all caches (query + graph) and rebuild the graph from scratch.
///
/// Use this after significant refactors, branch switches, or any time you
/// want to ensure the graph and all cached query results are fully up to date.
pub async fn execute_refresh(args: RefreshArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    // ── Clear query cache ────────────────────────────────────────────────────
    eprintln!("{} Clearing query cache…", "→".cyan());
    match crate::session::query_cache::clear(&workspace_path) {
        Ok(()) => eprintln!("{} Query cache cleared.", "✓".green()),
        Err(e) => eprintln!("{} Could not clear query cache: {}", "!".yellow(), e),
    }

    // ── Clear graph cache ────────────────────────────────────────────────────
    let graph_cache = workspace_path
        .join(".unfault")
        .join("cache")
        .join("graph.msgpack");
    if graph_cache.exists() {
        eprintln!("{} Clearing graph cache…", "→".cyan());
        match std::fs::remove_file(&graph_cache) {
            Ok(()) => eprintln!("{} Graph cache cleared.", "✓".green()),
            Err(e) => eprintln!("{} Could not clear graph cache: {}", "!".yellow(), e),
        }
    }

    // ── Rebuild graph ────────────────────────────────────────────────────────
    eprintln!("{} Rebuilding graph…", "→".cyan());

    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let spinner = if !args.verbose {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message("Parsing and building graph…");
        pb.enable_steady_tick(Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    match crate::local_graph::build_analysis_graph(&workspace_path, args.verbose) {
        Ok(graph) => {
            if let Some(pb) = spinner {
                pb.finish_and_clear();
            }
            let commit = crate::session::query_cache::current_commit_sha(&workspace_path);
            eprintln!(
                "{} Graph ready — {} files, {} functions  (HEAD: {})",
                "✓".green(),
                graph.file_nodes.len(),
                graph.function_nodes.len(),
                &commit[..8.min(commit.len())]
            );
        }
        Err(e) => {
            if let Some(pb) = spinner {
                pb.finish_and_clear();
            }
            eprintln!("{} Failed to build graph: {}", "Error:".red().bold(), e);
            return Ok(EXIT_ERROR);
        }
    }

    Ok(EXIT_SUCCESS)
}
