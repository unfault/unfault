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
pub(crate) fn build_graph_with_spinner(
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
    spinner.set_message("Loading graph cache…");
    spinner.enable_steady_tick(Duration::from_millis(80));

    // Changing a graph query target bypasses the per-query result cache, but
    // the shared graph cache can still satisfy the request. Show cache-loading
    // progress first, and only switch to a build message if that cache misses.
    if let Ok(Some(graph)) =
        crate::session::ir_builder::try_load_code_graph_only(workspace_path, false)
    {
        spinner.finish_and_clear();
        return Ok(unfault_analysis::graph::CodeGraph::from(graph));
    }

    spinner.set_message("Building graph…");

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

    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);

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

    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);
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

    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);
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

    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);

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

    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);
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
/// What kind of observability signal the instrumentation produces.
/// Used to select distinct display icons so engineers can distinguish
/// trace spans from error capture from metrics at a glance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// Distributed trace span (OTel, ddtrace, Jaeger, Zipkin, …).
    Trace,
    /// Structured log emission (structlog, loguru, zap, …).
    Log,
    /// Metric recording (Prometheus, StatsD, Datadog metrics, …).
    Metric,
    /// Error / exception capture (Sentry, Rollbar, Bugsnag, …).
    Error,
}

impl SignalKind {
    /// Unicode icon that represents this signal kind in the terminal.
    ///
    /// - `◉` trace  (filled circle, distinctive from coverage icons)
    /// - `≡` log    (three horizontal lines, like a log stream)
    /// - `⬡` metric (hexagon, like a gauge)
    /// - `✖` error  (cross, like an error event)
    pub fn icon(&self) -> &'static str {
        match self {
            SignalKind::Trace => "◉",
            SignalKind::Log => "≡",
            SignalKind::Metric => "⬡",
            SignalKind::Error => "✖",
        }
    }

    /// Default for serde — most signals are traces.
    pub fn trace_default() -> Self {
        SignalKind::Trace
    }

    /// Infer the kind from a library or framework name.
    pub fn from_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        // Error trackers
        if lower.contains("sentry") || lower.contains("rollbar") || lower.contains("bugsnag") {
            return SignalKind::Error;
        }
        // Metrics
        if lower.contains("prometheus")
            || lower.contains("statsd")
            || lower.contains("influx")
            || lower.contains("graphite")
            || lower.contains("metric")
        {
            return SignalKind::Metric;
        }
        // Structured logging
        if lower.contains("loguru")
            || lower.contains("structlog")
            || lower.contains("zap")
            || lower.contains("zerolog")
            || lower.contains("logrus")
            || lower.contains("winston")
            || lower.contains("bunyan")
        {
            return SignalKind::Log;
        }
        // Default: distributed tracing
        SignalKind::Trace
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanSignal {
    /// Function carries a recognised tracing decorator (@trace, @instrument,
    /// @span, context manager, etc.).  `name` is whatever we can extract from
    /// the decorator detail string, or None if only the presence is detected.
    Decorator {
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// What kind of observability signal this decorator produces.
        #[serde(default = "SignalKind::trace_default")]
        kind: SignalKind,
    },
    /// The file this function lives in imports an OTel / tracing SDK
    /// (opentelemetry, ddtrace, sentry-sdk, …).
    SdkImported {
        /// The library name (e.g. "opentelemetry", "ddtrace").
        library: String,
        /// What kind of observability signal this SDK provides.
        #[serde(default = "SignalKind::trace_default")]
        kind: SignalKind,
    },
    /// A framework auto-instrumentation was detected elsewhere in the codebase
    /// (e.g. FastAPIInstrumentor.instrument_app(app), ddtrace.patch_all(),
    /// SentryAsgiMiddleware, otelgin.Middleware, etc.).  The server span for
    /// this handler is created automatically — no explicit decorator needed.
    AutoInstrumented {
        /// Human-readable framework name, e.g. "fastapi", "sqlalchemy".
        framework: String,
        /// Source file where the auto-instrumentation call was found.
        #[serde(skip_serializing_if = "Option::is_none")]
        source_file: Option<String>,
        /// 1-based line number of the instrumentor call.
        #[serde(skip_serializing_if = "Option::is_none")]
        source_line: Option<u32>,
        /// True when this function is the HTTP entry boundary that directly
        /// receives the auto-instrumented server span.  False for inner
        /// functions that are covered transitively.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        is_boundary: bool,
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

/// A resolved source location.  `line` may be None when the parser didn't
/// record it; `file` is never empty (falls back to the caller's file).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Location {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

impl Location {
    pub fn new(file: impl Into<String>, line: Option<u32>) -> Self {
        Self {
            file: file.into(),
            line,
        }
    }
}

/// A single callee that produces no signal — useful for agents hunting for
/// observability gaps that could hinder debugging.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnobservedCallee {
    pub name: String,
    pub location: Location,
    /// What kind of work (db, http, remote, logic).
    pub role: NodeRole,
    /// How far from the anchor (1 = direct callee of the handler).
    pub depth: i32,
    /// Full call path from the anchor as location-bearing hops.
    pub path: Vec<PathHop>,
}

/// A single hop in an unobserved call path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PathHop {
    pub name: String,
    pub location: Location,
}

/// Flattened inventory of every unobserved callee in the coverage tree.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UnobservedByRole {
    #[serde(default)]
    pub database: Vec<UnobservedCallee>,
    #[serde(default)]
    pub http: Vec<UnobservedCallee>,
    #[serde(default)]
    pub remote: Vec<UnobservedCallee>,
    #[serde(default)]
    pub logic: Vec<UnobservedCallee>,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UnobservedPaths {
    pub total: usize,
    pub anchor_unobserved: bool,
    pub by_role: UnobservedByRole,
    /// Path from anchor to the deepest unobserved callee.
    #[serde(default)]
    pub deepest: Vec<PathHop>,
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
    /// Flattened inventory of every unobserved callee — one field access for agents.
    #[serde(default)]
    pub unobserved_paths: UnobservedPaths,
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

    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);
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
    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);
    let cache_params = format!(
        "{}|{}|{}|{}",
        args.target,
        args.method.as_deref().unwrap_or(""),
        if args.refresh_cache { "refresh" } else { "" },
        env!("CARGO_PKG_VERSION"),
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
pub(crate) fn build_coverage_context(
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

    // Build auto-instrumentation index once — scan the whole graph for global
    // OTel / ddtrace / sentry instrumentation activation calls.
    let auto_instruments = build_auto_instrument_set(graph);

    // ── Walk callees (downward) ───────────────────────────────────────────────
    let mut callees = walk_callees(
        graph,
        anchor_idx,
        max_depth,
        &file_libs,
        &auto_instruments,
        1,
    );

    // Fallback: if the graph walk found no callees (cross-file calls that weren't
    // resolved into Calls edges), synthesise stub nodes from the anchor's raw_calls
    // list so the tree isn't empty and gaps are still visible.
    if callees.is_empty() {
        callees = stub_callees_from_raw_calls(graph, anchor_node, &file_libs, &auto_instruments);
    }

    // ── Walk callers (upward) ─────────────────────────────────────────────────
    let mut callers = walk_callers(
        graph,
        anchor_idx,
        max_depth,
        &file_libs,
        &auto_instruments,
        1,
    );

    // Fallback: if the graph walk found no callers (cross-file Calls edges
    // weren't resolved), scan every route handler in the graph and surface
    // any whose raw_calls list contains the anchor's name.
    if callers.is_empty() {
        callers =
            stub_route_callers_via_raw_calls(graph, &anchor_name, &file_libs, &auto_instruments);
    }

    // ── Build anchor node ─────────────────────────────────────────────────────
    let anchor_role = node_role(graph, anchor_idx, anchor_node, &file_libs);
    let anchor_span = node_span_signal(graph, anchor_node, &file_libs, &auto_instruments);

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

    let unobserved_paths = build_unobserved_paths(&anchor);

    Some(CoverageContext {
        target: target.to_string(),
        resolved_as,
        callers,
        anchor,
        callees,
        summary,
        unobserved_paths,
    })
}

fn collect_nodes<'a>(node: &'a CoverageNode, out: &mut Vec<&'a CoverageNode>) {
    out.push(node);
    for child in &node.children {
        collect_nodes(child, out);
    }
}

fn build_unobserved_paths(anchor: &CoverageNode) -> UnobservedPaths {
    let anchor_file = anchor.file.clone();
    let mut by_role = UnobservedByRole::default();
    let mut deepest_depth: i32 = 0;
    let mut deepest_path: Vec<PathHop> = Vec::new();

    let mut path_so_far = vec![PathHop {
        name: anchor.name.clone(),
        location: Location::new(anchor.file.clone(), anchor.line),
    }];
    walk_unobserved_callees(
        &anchor.children,
        &anchor_file,
        &mut path_so_far,
        1,
        &mut by_role,
        &mut deepest_depth,
        &mut deepest_path,
    );

    let total =
        by_role.database.len() + by_role.http.len() + by_role.remote.len() + by_role.logic.len();
    let anchor_unobserved = matches!(anchor.span, SpanSignal::None);

    UnobservedPaths {
        total,
        anchor_unobserved,
        by_role,
        deepest: deepest_path,
    }
}

fn walk_unobserved_callees(
    children: &[CoverageNode],
    fallback_file: &str,
    path_so_far: &mut Vec<PathHop>,
    depth: i32,
    by_role: &mut UnobservedByRole,
    deepest_depth: &mut i32,
    deepest_path: &mut Vec<PathHop>,
) {
    for child in children {
        let file = if child.file.is_empty() {
            fallback_file.to_string()
        } else {
            child.file.clone()
        };
        let mut child_path = path_so_far.clone();
        child_path.push(PathHop {
            name: child.name.clone(),
            location: Location::new(file.clone(), child.line),
        });

        if matches!(child.span, SpanSignal::None) {
            let callee = UnobservedCallee {
                name: child.name.clone(),
                location: Location::new(file.clone(), child.line),
                role: child.role.clone(),
                depth,
                path: child_path.clone(),
            };
            match &child.role {
                NodeRole::Database => by_role.database.push(callee),
                NodeRole::HttpClient => by_role.http.push(callee),
                NodeRole::RemoteCall { .. } => by_role.remote.push(callee),
                _ => by_role.logic.push(callee),
            }
            if depth > *deepest_depth {
                *deepest_depth = depth;
                *deepest_path = child_path.clone();
            }
        }

        walk_unobserved_callees(
            &child.children,
            &file,
            &mut child_path,
            depth + 1,
            by_role,
            deepest_depth,
            deepest_path,
        );
    }
}

// ── Auto-instrumentation index ────────────────────────────────────────────────

/// Location and framework recorded for a single global auto-instrumentation
/// activation call (e.g. `FastAPIInstrumentor.instrument_app(app)`).
#[derive(Debug, Clone)]
pub struct AutoInstrumentEntry {
    /// Human-readable framework name, e.g. "fastapi", "sqlalchemy".
    pub framework: String,
    /// Source file where the instrumentor call was found.
    pub file: String,
    /// 1-based line number of the function that contains the call, if known.
    pub line: Option<u32>,
}

/// Map from framework name → location of its global instrumentation call.
///
/// Examples:
/// - `{"fastapi" → (file, line)}` when `FastAPIInstrumentor.instrument_app(app)` is detected
/// - `{"all" → …}` when `ddtrace.patch_all()` is detected
/// - empty when no auto-instrumentation is detected
pub type AutoInstrumentSet = std::collections::HashMap<String, AutoInstrumentEntry>;

/// Scan the code graph once and return the set of frameworks that have a
/// global OTel / tracing auto-instrumentation enabled.
///
/// Strategy:
/// 1. Find every `File` node that has a `UsesLibrary` edge to an
///    `Observability` `ExternalModule`.
/// 2. For each such file, inspect the raw call expressions belonging to
///    any function in that file.  Match against known instrumentor patterns.
///
/// This is intentionally conservative: we only claim auto-instrumentation
/// when we see an explicit `.instrument_app()` / `.instrument()` / `.patch()`
/// / `patch_all()` call — NOT just from an import.
pub fn build_auto_instrument_set(graph: &unfault_analysis::graph::CodeGraph) -> AutoInstrumentSet {
    use petgraph::Direction;
    use petgraph::visit::EdgeRef as _;
    use unfault_analysis::graph::{GraphEdgeKind, GraphNode};
    use unfault_core::graph::ModuleCategory;

    let mut result = AutoInstrumentSet::new();

    // Collect files that import an Observability module.
    let observability_files: std::collections::HashSet<String> = graph
        .graph
        .node_indices()
        .filter_map(|idx| {
            if let GraphNode::File { path, .. } = &graph.graph[idx] {
                let has_obs = graph
                    .graph
                    .edges_directed(idx, Direction::Outgoing)
                    .any(|e| {
                        matches!(e.weight(), GraphEdgeKind::UsesLibrary)
                            && matches!(
                                &graph.graph[e.target()],
                                GraphNode::ExternalModule {
                                    category: ModuleCategory::Observability,
                                    ..
                                }
                            )
                    });
                if has_obs { Some(path.clone()) } else { None }
            } else {
                None
            }
        })
        .collect();

    if observability_files.is_empty() {
        return result;
    }

    // Walk every Function node in those files and inspect raw_calls.
    // Record the source file and line of the function containing the call.
    for idx in graph.graph.node_indices() {
        if let GraphNode::Function {
            line, raw_calls, ..
        } = &graph.graph[idx]
        {
            let file =
                unfault_analysis::graph::traversal::node_file_path_pub(graph, &graph.graph[idx])
                    .unwrap_or_default();
            if !observability_files.contains(&file) {
                continue;
            }
            for call in raw_calls {
                if let Some(framework) = classify_instrumentor_call(&call.expr) {
                    // Keep first entry found for each framework (arbitrary but stable).
                    // Prefer the call's own line over the enclosing function's line
                    // when available — it points at the activation site itself.
                    let call_line = if call.line > 0 {
                        Some(call.line)
                    } else {
                        *line
                    };
                    result
                        .entry(framework.clone())
                        .or_insert_with(|| AutoInstrumentEntry {
                            framework,
                            file: file.clone(),
                            line: call_line,
                        });
                }
            }
        }
    }

    result
}

/// Map a raw call expression to a framework name if it looks like a global
/// auto-instrumentation activation call.
///
/// Patterns recognised (case-insensitive):
///
/// Python OTel:
///   FastAPIInstrumentor.instrument_app(...)     → "fastapi"
///   FastAPIInstrumentor().instrument_app(...)   → "fastapi"
///   FlaskInstrumentor().instrument_app(...)     → "flask"
///   DjangoInstrumentor().instrument(...)        → "django"
///   SQLAlchemyInstrumentor().instrument(...)    → "sqlalchemy"
///   RequestsInstrumentor().instrument(...)      → "requests"
///   AioHttpClientInstrumentor().instrument(...) → "aiohttp"
///   GrpcInstrumentorClient().instrument(...)    → "grpc"
///   ddtrace.patch_all()                         → "all"
///   ddtrace.patch(fastapi=True, ...)            → "fastapi" (best effort)
///   sentry_sdk.init(integrations=[...])         → "sentry"
///
/// Go OTel:
///   otelhttp.NewHandler / otelgin.Middleware / otelecho.Middleware
///   → "http" / "gin" / "echo"
///
/// Rust:
///   tower_http::trace::TraceLayer / axum_tracing_opentelemetry
///   → "http"
fn classify_instrumentor_call(call_expr: &str) -> Option<String> {
    let lower = call_expr.to_lowercase();

    // OTel Python instrumentors — keyed by last non-method segment.
    // e.g. "fastapiinstrumentor.instrument_app" → "fastapi"
    if lower.ends_with("instrument_app")
        || lower.ends_with("instrument")
        || lower.ends_with("instrument_all")
    {
        return Some(infer_framework_from_instrumentor(&lower));
    }

    // ddtrace
    if lower == "patch_all" || lower.ends_with(".patch_all") {
        return Some("all".to_string());
    }
    if lower == "patch" || lower.ends_with(".patch") {
        return Some("ddtrace".to_string());
    }

    // sentry_sdk.init — not an OTel instrumentor per se but carries
    // the same "framework is globally observed" guarantee.
    if (lower.ends_with(".init") || lower == "init")
        && (lower.contains("sentry") || lower.contains("sentry_sdk"))
    {
        return Some("sentry".to_string());
    }

    // Go / Rust middleware wrappers stored as callee_expr in raw_calls.
    for (pattern, framework) in &[
        ("otelhttp", "http"),
        ("otelgin", "gin"),
        ("otelecho", "echo"),
        ("otelchi", "chi"),
        ("otelfasthttp", "fasthttp"),
        ("tracelayer", "http"),
        ("tracing_opentelemetry", "http"),
    ] {
        if lower.contains(pattern) {
            return Some(framework.to_string());
        }
    }

    None
}

/// Infer a framework name from an OTel Python instrumentor class name.
///
/// `FastAPIInstrumentor` → `"fastapi"`,
/// `SQLAlchemyInstrumentor` → `"sqlalchemy"`, etc.
fn infer_framework_from_instrumentor(lower_expr: &str) -> String {
    // The class name is the first dot-separated segment.
    let class = lower_expr.split('.').next().unwrap_or(lower_expr);

    // Strip common suffixes to isolate the framework name.
    let stripped = class
        .trim_end_matches("instrumentor")
        .trim_end_matches("instrumentation");

    match stripped {
        "fastapi" | "starlette" => "fastapi".to_string(),
        "flask" => "flask".to_string(),
        "django" => "django".to_string(),
        "sqlalchemy" => "sqlalchemy".to_string(),
        "requests" => "requests".to_string(),
        "aiohttp" | "aiohttpclient" => "aiohttp".to_string(),
        "grpc" | "grpcclient" | "grpcserver" => "grpc".to_string(),
        "redis" => "redis".to_string(),
        "pymongo" => "mongodb".to_string(),
        "elasticsearch" => "elasticsearch".to_string(),
        "celery" => "celery".to_string(),
        "boto" | "botocore" => "aws".to_string(),
        other => other.to_string(),
    }
}

/// Walk Calls edges downward (callees), stopping at library boundaries.
fn walk_callees(
    graph: &unfault_analysis::graph::CodeGraph,
    from: unfault_analysis::graph::GraphNodeIndex,
    max_depth: Option<usize>,
    file_libs: &FileLibIndex,
    auto_instruments: &AutoInstrumentSet,
    depth: i32,
) -> Vec<CoverageNode> {
    let mut result = Vec::new();
    let mut visited = std::collections::HashSet::new();
    walk_callees_inner(
        graph,
        from,
        max_depth,
        file_libs,
        auto_instruments,
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
    auto_instruments: &AutoInstrumentSet,
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
        let span = node_span_signal(graph, callee_node, file_libs, &auto_instruments);

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
                auto_instruments,
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
    auto_instruments: &AutoInstrumentSet,
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
        auto_instruments,
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
    auto_instruments: &AutoInstrumentSet,
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
        let span = node_span_signal(graph, caller_node, file_libs, &auto_instruments);

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
            auto_instruments,
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
/// When `walk_callers` returns nothing (cross-file `Calls` edges weren't
/// resolved), scan every HTTP route handler in the graph and check whether
/// the handler's body — captured in `raw_calls` — references this anchor by
/// name. Each match becomes a synthesised caller node so the user sees which
/// routes actually reach this function.
fn stub_route_callers_via_raw_calls(
    graph: &unfault_analysis::graph::CodeGraph,
    anchor_name: &str,
    file_libs: &FileLibIndex,
    auto_instruments: &AutoInstrumentSet,
) -> Vec<CoverageNode> {
    use unfault_analysis::graph::GraphNode;

    let mut result = Vec::new();

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        let GraphNode::Function {
            is_handler: true,
            name,
            raw_calls,
            line,
            ..
        } = node
        else {
            continue;
        };

        // Match the anchor name against the last segment of each raw call.
        let hit = raw_calls.iter().any(|call| {
            let last = call.expr.split('.').last().unwrap_or(call.expr.as_str());
            last == anchor_name
        });
        if !hit {
            continue;
        }

        let file =
            unfault_analysis::graph::traversal::node_file_path_pub(graph, node).unwrap_or_default();
        let span = node_span_signal(graph, node, file_libs, &auto_instruments);
        let role = node_role(graph, idx, node, file_libs);

        result.push(CoverageNode {
            name: name.clone(),
            file,
            line: *line,
            depth: 1,
            direction: "up".to_string(),
            span,
            role,
            children: vec![],
        });
    }

    result
}

/// default — they show up in the tree and in the nudge list so the developer
/// can see the gap.
fn stub_callees_from_raw_calls(
    graph: &unfault_analysis::graph::CodeGraph,
    anchor_node: &unfault_analysis::graph::GraphNode,
    file_libs: &FileLibIndex,
    auto_instruments: &AutoInstrumentSet,
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

    for call in raw_calls {
        let call_expr = &call.expr;
        // Classify the call expression FIRST.  If it's a recognised db /
        // http-client boundary we keep it regardless of receiver shape —
        // this is the whole point of category-based coverage.
        let inferred_role = if is_db_call_expr(call_expr) {
            NodeRole::Database
        } else if is_http_client_call_expr(call_expr) {
            NodeRole::HttpClient
        } else {
            NodeRole::Logic
        };

        // For display purposes the node name is the last segment of the call.
        let name = call_expr.split('.').last().unwrap_or(call_expr.as_str());

        // Skip rules that apply ONLY to plain logic calls (never to known
        // boundaries — db_session.get must survive).
        if matches!(inferred_role, NodeRole::Logic) {
            // Drop dunder methods and very short names.
            if name.len() < 3 || (name.starts_with('_') && name.ends_with('_')) {
                continue;
            }
            // Drop Python/JS builtins, framework markers, response constructors.
            // Capitalized single-word names are almost always constructors or
            // type references (Response, PublishResponse, HTTPException, Any).
            let first_char = name.chars().next().unwrap_or('a');
            if first_char.is_uppercase() {
                continue;
            }
            const LOGIC_SKIP: &[&str] = &[
                // Python builtins
                "any",
                "all",
                "map",
                "filter",
                "zip",
                "sorted",
                "reversed",
                "enumerate",
                "range",
                "iter",
                "next",
                "len",
                "str",
                "int",
                "float",
                "bool",
                "list",
                "dict",
                "tuple",
                "set",
                "type",
                "print",
                "repr",
                "hash",
                "id",
                "callable",
                "getattr",
                "setattr",
                "hasattr",
                "delattr",
                "super",
                "vars",
                "dir",
                // FastAPI / Starlette markers
                "depends",
                "depend",
                // Common JS/TS globals
                "console",
                "promise",
                "object",
                "array",
                "json",
            ];
            let name_lower = name.to_lowercase();
            if LOGIC_SKIP.contains(&name_lower.as_str()) {
                continue;
            }
        }

        // Deduplicate by the displayed name + role pair so that two distinct
        // db calls aren't collapsed into one logic call.
        let dedup_key = format!("{}|{:?}", name, std::mem::discriminant(&inferred_role));
        if !seen.insert(dedup_key) {
            continue;
        }

        // See if there's a resolved Function node in the graph with this name.
        // First try same-file resolution; if that fails, try a global search
        // and use the result only when unambiguous (exactly one match).
        let resolved = {
            let same_file = graph.graph.node_indices().find(|&idx| {
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
            if same_file.is_some() {
                same_file
            } else {
                // Global search — only use if unambiguous.
                let matches: Vec<_> = graph
                    .graph
                    .node_indices()
                    .filter(|&idx| {
                        if let GraphNode::Function { name: fn_name, .. } = &graph.graph[idx] {
                            fn_name == name
                        } else {
                            false
                        }
                    })
                    .collect();
                if matches.len() == 1 {
                    Some(matches[0])
                } else {
                    None
                }
            }
        };

        // Capture the call-site line from the raw_calls entry. This is the
        // line the call APPEARS on inside the caller's body — distinct from
        // the callee's definition line. Used as a fallback for bound-method
        // and unresolved cross-module calls where no definition line exists.
        let call_site_line = if call.line > 0 { Some(call.line) } else { None };

        let (file, line, span, role) = if let Some(idx) = resolved {
            let node = &graph.graph[idx];
            let f = unfault_analysis::graph::traversal::node_file_path_pub(graph, node)
                .unwrap_or_default();
            // Prefer the resolved function's definition line; fall back to
            // the call-site line so the user always has a useful location.
            let l = if let GraphNode::Function { line, .. } = node {
                line.or(call_site_line)
            } else {
                call_site_line
            };
            let s = node_span_signal(graph, node, file_libs, &auto_instruments);
            // If the resolved function has its own classification, prefer it.
            // Otherwise keep the role we inferred from the call expression
            // (so unresolved db_session.get stays Database).
            let resolved_role = node_role(graph, idx, node, file_libs);
            let r = match (&resolved_role, &inferred_role) {
                (NodeRole::Logic, NodeRole::Database) => NodeRole::Database,
                (NodeRole::Logic, NodeRole::HttpClient) => NodeRole::HttpClient,
                _ => resolved_role,
            };
            (f, l, s, r)
        } else {
            // Unresolved (bound method, dynamic import, cross-module ambiguous).
            // The call-site line lets the caller still locate the boundary.
            (
                String::new(),
                call_site_line,
                SpanSignal::None,
                inferred_role,
            )
        };

        // For db / http-client boundary calls we display the full expression
        // (db_session.get) rather than just the last segment ("get") so the
        // user can see what was actually called.
        let display_name = match &role {
            NodeRole::Database | NodeRole::HttpClient => call_expr.clone(),
            _ => name.to_string(),
        };

        result.push(CoverageNode {
            name: display_name,
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
    auto_instruments: &AutoInstrumentSet,
) -> SpanSignal {
    use unfault_analysis::graph::GraphNode;
    use unfault_core::graph::{DecoratorSemantic, ModuleCategory};

    // Priority 1: explicit tracing decorator / context manager on this function.
    if let GraphNode::Function { decorators, .. } = node {
        for dec in decorators {
            if let DecoratorSemantic::Tracing { detail } = dec {
                let span_name = extract_span_name_from_detail(detail);
                let kind = SignalKind::from_name(detail);
                return SpanSignal::Decorator {
                    name: span_name,
                    kind,
                };
            }
        }
    }

    // Priority 2: global auto-instrumentation detected in the workspace.
    // HTTP route handlers are the direct entry boundary where the server span
    // is created.  Inner functions are transitively covered by that same span.
    // We report AutoInstrumented for both — is_boundary distinguishes them.
    if !auto_instruments.is_empty() {
        let is_boundary = matches!(
            node,
            GraphNode::Function {
                is_handler: true,
                ..
            }
        );

        // "all" is emitted by ddtrace.patch_all() — covers every framework.
        if let Some(entry) = auto_instruments.get("all") {
            return SpanSignal::AutoInstrumented {
                framework: "ddtrace (patch_all)".to_string(),
                source_file: Some(entry.file.clone()),
                source_line: entry.line,
                is_boundary,
            };
        }
        // Pick the first (or only) matching entry.
        if let Some(entry) = auto_instruments.values().next() {
            return SpanSignal::AutoInstrumented {
                framework: entry.framework.clone(),
                source_file: Some(entry.file.clone()),
                source_line: entry.line,
                is_boundary,
            };
        }
    }

    // Priority 3: the file imports an OTel / tracing SDK.
    let file =
        unfault_analysis::graph::traversal::node_file_path_pub(graph, node).unwrap_or_default();
    if let Some(libs) = file_libs.get(&file) {
        for (lib_name, cat) in libs {
            if matches!(cat, ModuleCategory::Observability) {
                let kind = SignalKind::from_name(lib_name);
                return SpanSignal::SdkImported {
                    library: lib_name.clone(),
                    kind,
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
    _graph: &unfault_analysis::graph::CodeGraph,
    _idx: unfault_analysis::graph::GraphNodeIndex,
    node: &unfault_analysis::graph::GraphNode,
    _file_libs: &std::collections::HashMap<
        String,
        Vec<(String, unfault_core::graph::ModuleCategory)>,
    >,
) -> NodeRole {
    use unfault_analysis::graph::GraphNode;

    // HTTP route handler — the only signal that overrides everything else.
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

    // Classify by what the function ACTUALLY DOES — i.e. its body calls.
    // File-level library imports are deliberately ignored here: a function
    // sitting next to a SQLAlchemy import doesn't make it a db function.
    if let GraphNode::Function { raw_calls, .. } = node {
        if raw_calls.iter().any(|c| is_db_call_expr(&c.expr)) {
            return NodeRole::Database;
        }
        if raw_calls.iter().any(|c| is_http_client_call_expr(&c.expr)) {
            return NodeRole::HttpClient;
        }
    }

    NodeRole::Logic
}

/// Returns true when a call expression looks like a database / ORM call.
///
/// Recognised patterns (case-insensitive on the method name):
/// - SQLAlchemy ORM:    session.execute, session.scalar, session.scalars,
///                      session.add, session.delete, session.merge,
///                      session.commit, session.rollback, session.flush,
///                      session.refresh, session.query, session.get
/// - SQLAlchemy Core:   conn.execute, engine.execute, select(...),
///                      insert(...), update(...), delete(...)
/// - Django ORM:        .objects.get, .objects.filter, .objects.create,
///                      .objects.all, .objects.update, .objects.delete,
///                      .save(), .delete() on a model instance
/// - Generic SQL/DB:    db.query, db.execute, db.fetchone, db.fetchall,
///                      cursor.execute, cursor.fetchone
fn is_db_call_expr(expr: &str) -> bool {
    let lower = expr.to_lowercase();
    let last = lower.rsplit('.').next().unwrap_or(lower.as_str());

    // Top-level Python function calls in the SQLAlchemy Core style.
    if matches!(
        last,
        "select" | "insert" | "update" | "delete" | "exists" | "text"
    ) && !lower.contains('.')
    {
        // Heuristic: standalone select(...) etc. is likely SQLA Core.
        // Avoid false positives — only flag when expression is exactly the call name.
        return true;
    }

    // Helper to extract the receiver (everything before the final method name).
    // For "self.db_session.execute" the receiver is "self.db_session".
    let receiver: String = {
        let parts: Vec<&str> = lower.split('.').collect();
        if parts.len() <= 1 {
            String::new()
        } else {
            parts[..parts.len() - 1].join(".")
        }
    };

    // ORM session / cursor methods.  Match on the last segment of the chain.
    const DB_METHODS: &[&str] = &[
        "execute",
        "scalar",
        "scalars",
        "fetchone",
        "fetchall",
        "fetchmany",
        "commit",
        "rollback",
        "flush",
        "refresh",
        "merge",
        "bulk_save_objects",
        "bulk_insert_mappings",
        "bulk_update_mappings",
    ];
    if DB_METHODS.contains(&last) {
        if receiver.contains("session")
            || receiver.contains("db")
            || receiver.contains("conn")
            || receiver.contains("engine")
            || receiver.contains("cursor")
        {
            return true;
        }
    }

    // session.add / session.get / session.query / session.delete on Session-typed receivers.
    if matches!(last, "add" | "get" | "query" | "delete" | "save") {
        if receiver.ends_with("session")
            || receiver.ends_with("db_session")
            || receiver.ends_with("db")
            || receiver.contains(".session")
            || receiver.contains("session.")
        {
            return true;
        }
    }

    // Django: .objects.<anything>
    if lower.contains(".objects.") {
        return true;
    }

    false
}

/// Returns true when a call expression looks like an outbound HTTP client call.
fn is_http_client_call_expr(expr: &str) -> bool {
    let lower = expr.to_lowercase();
    let last = lower.rsplit('.').next().unwrap_or(lower.as_str());

    // Top-level requests.get / httpx.post / etc.
    if matches!(
        last,
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "request"
    ) {
        // Receiver is everything before the final method.
        let receiver: String = {
            let parts: Vec<&str> = lower.split('.').collect();
            if parts.len() <= 1 {
                String::new()
            } else {
                parts[..parts.len() - 1].join(".")
            }
        };
        if receiver == "requests"
            || receiver == "httpx"
            || receiver == "aiohttp"
            || receiver.starts_with("requests.")
            || receiver.starts_with("httpx.")
            || receiver.starts_with("aiohttp.")
            || receiver.ends_with("client")
            || receiver.ends_with(".client")
        {
            return true;
        }
    }

    // Common standalone fetch / urlopen / urlretrieve
    if matches!(last, "fetch" | "urlopen" | "urlretrieve") {
        return true;
    }

    false
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

/// Short human-readable label for a `SignalKind`, used in display lines.
fn kind_label(kind: &SignalKind) -> &'static str {
    match kind {
        SignalKind::Trace => "trace",
        SignalKind::Log => "log",
        SignalKind::Metric => "metric",
        SignalKind::Error => "error",
    }
}

fn render_coverage_output(ctx: &CoverageContext, json: bool) -> Result<i32> {
    if json {
        println!("{}", serde_json::to_string_pretty(ctx)?);
        return Ok(EXIT_SUCCESS);
    }

    // Header — colourise route handlers as "[METHOD] path".
    println!();
    let header = match &ctx.anchor.role {
        NodeRole::HttpHandler { method, path } => {
            format!("{} {}", method.magenta().bold(), path.bright_yellow())
        }
        _ => format!("function {}", ctx.anchor.name.bright_white().bold()),
    };
    println!("  {} Coverage for {}", "→".cyan(), header);

    // Show instrumentation status on the anchor.
    // Icons distinguish signal type:
    //   ◉  trace span (explicit decorator)
    //   ◐  trace span via auto-instrumentation (server boundary)
    //   ⋯  trace span via auto-instrumentation (inner, covered transitively)
    //   ◑  observability SDK imported (manual usage likely)
    match &ctx.anchor.span {
        SpanSignal::AutoInstrumented {
            framework,
            source_file,
            source_line,
            is_boundary,
        } => {
            let (icon, label) = if *is_boundary {
                ("◐".yellow().to_string(), "server span from")
            } else {
                ("⋯".bright_black().to_string(), "covered by")
            };
            print!(
                "  {} {} {} auto-instrumentation",
                icon,
                label,
                framework.bright_white()
            );
            // Show where the instrumentation is registered, dimmed.
            if let Some(file) = source_file {
                let loc = match source_line {
                    Some(l) => format!("{}:{}", file, l),
                    None => file.clone(),
                };
                print!("  {}", loc.bright_black());
            }
            println!();
        }
        SpanSignal::Decorator {
            name: Some(n),
            kind,
        } => {
            println!(
                "  {} {} span  \"{}\"",
                kind.icon().green(),
                kind_label(kind),
                n.green()
            );
        }
        SpanSignal::Decorator { name: None, kind } => {
            println!(
                "  {} {} span (decorator)",
                kind.icon().green(),
                kind_label(kind)
            );
        }
        SpanSignal::SdkImported { library, kind } => {
            println!(
                "  {} {} sdk: {}",
                kind.icon().yellow(),
                kind_label(kind),
                library.bright_black()
            );
        }
        SpanSignal::None => {}
    }
    println!();

    // ── Reached by ──
    // Show route handlers that reach this anchor.  Only relevant when the
    // anchor is NOT itself a route handler.
    if !matches!(ctx.anchor.role, NodeRole::HttpHandler { .. }) && !ctx.callers.is_empty() {
        let route_callers: Vec<&CoverageNode> = ctx
            .callers
            .iter()
            .filter(|c| matches!(c.role, NodeRole::HttpHandler { .. }))
            .collect();

        if !route_callers.is_empty() {
            println!(
                "  Reached by {} route{}:",
                route_callers.len(),
                if route_callers.len() == 1 { "" } else { "s" }
            );
            for caller in route_callers.iter().take(5) {
                if let NodeRole::HttpHandler { method, path } = &caller.role {
                    println!(
                        "    {} {}  via {}",
                        method.magenta().bold(),
                        path.bright_yellow(),
                        caller.name.bright_black()
                    );
                }
            }
            if route_callers.len() > 5 {
                println!("    … and {} more", route_callers.len() - 5);
            }
            println!();
        }
    }

    // Category-based coverage breakdown.
    let mut all_nodes: Vec<&CoverageNode> = Vec::new();
    collect_nodes(&ctx.anchor, &mut all_nodes);
    for c in &ctx.callers {
        collect_nodes(c, &mut all_nodes);
    }

    // Detect whether any node in the tree is covered by global auto-instrumentation.
    let has_global_instrumentation = all_nodes
        .iter()
        .any(|n| matches!(n.span, SpanSignal::AutoInstrumented { .. }));

    render_category_breakdown(&all_nodes, &ctx.anchor.name, has_global_instrumentation);

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

fn render_category_breakdown(
    all_nodes: &[&CoverageNode],
    anchor_name: &str,
    has_global_instrumentation: bool,
) {
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

    let logic_blind_spot_hint = if has_global_instrumentation {
        "instrumentation may be too broad — errors inside will lack granular span context"
    } else {
        "core logic is uninstrumented — errors will have no trace context"
    };
    let logic_partial_hint = if has_global_instrumentation {
        "partial logic coverage — some code paths rely only on the outer auto-instrumented span"
    } else {
        "partial logic coverage — some code paths will be dark"
    };

    let groups: Vec<CategoryGroup> = vec![
        CategoryGroup {
            label: "db queries",
            blind_spot_hint: "wrap db calls in a span to catch timeouts and query errors",
            partial_hint: "some db calls are untraced — you may miss slow queries",
            nodes: db,
        },
        CategoryGroup {
            label: "remote calls",
            blind_spot_hint: "wrap remote calls in a span to catch downstream errors",
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
            blind_spot_hint: "wrap auth checks in a span to see permission errors",
            partial_hint: "some auth checks are untraced",
            nodes: auth,
        },
        CategoryGroup {
            label: "business logic",
            blind_spot_hint: logic_blind_spot_hint,
            partial_hint: logic_partial_hint,
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

    // ── is_db_call_expr ────────────────────────────────────────────────────────

    #[test]
    fn db_classification_recognises_sqlalchemy_session_calls() {
        assert!(is_db_call_expr("db_session.execute"));
        assert!(is_db_call_expr("session.scalar"));
        assert!(is_db_call_expr("self.db_session.scalars"));
        assert!(is_db_call_expr("db_session.commit"));
        assert!(is_db_call_expr("db_session.add"));
        assert!(is_db_call_expr("db_session.get"));
        assert!(is_db_call_expr("session.query"));
    }

    #[test]
    fn db_classification_recognises_django_orm() {
        assert!(is_db_call_expr("User.objects.get"));
        assert!(is_db_call_expr("Order.objects.filter"));
    }

    #[test]
    fn db_classification_recognises_sqlalchemy_core() {
        assert!(is_db_call_expr("select"));
        assert!(is_db_call_expr("insert"));
        assert!(is_db_call_expr("update"));
        assert!(is_db_call_expr("delete"));
    }

    #[test]
    fn db_classification_rejects_plain_business_logic() {
        // The bug we are guarding against: a function that builds a response
        // and just happens to receive a SQLAlchemy model object as an argument
        // must NOT be flagged as a db function.
        assert!(!is_db_call_expr("_build_structured_output_response"));
        assert!(!is_db_call_expr("validate_input"));
        assert!(!is_db_call_expr("self._serialize"));
        assert!(!is_db_call_expr("logger.info"));
        // .get() on a dict / cache / context is not the db.
        assert!(!is_db_call_expr("cache.get"));
        assert!(!is_db_call_expr("settings.get"));
    }

    #[test]
    fn http_client_classification_recognises_common_libraries() {
        assert!(is_http_client_call_expr("requests.get"));
        assert!(is_http_client_call_expr("httpx.post"));
        assert!(is_http_client_call_expr("aiohttp.request"));
        assert!(is_http_client_call_expr("self.client.get"));
        assert!(is_http_client_call_expr("fetch"));
    }

    #[test]
    fn http_client_classification_rejects_db_get() {
        assert!(!is_http_client_call_expr("db_session.get"));
        assert!(!is_http_client_call_expr("cache.get"));
    }

    // ── stub_callees_from_raw_calls integration ──────────────────────────────
    //
    // Regression: previously a SKIP list dropped "get", "commit", "execute"
    // before they were ever classified — so db_session.get(...) inside a
    // FastAPI handler never appeared in the db queries category.

    fn make_handler_with_raw_calls(raw: Vec<&str>) -> unfault_analysis::graph::GraphNode {
        use unfault_core::graph::RawCall;
        unfault_analysis::graph::GraphNode::Function {
            file_id: unfault_core::parse::ast::FileId(1),
            name: "h".to_string(),
            qualified_name: "h".to_string(),
            is_async: true,
            is_handler: true,
            http_method: Some("GET".to_string()),
            http_path: Some("/x".to_string()),
            decorators: vec![],
            is_writer: false,
            line: None,
            column: None,
            request_schema: None,
            response_schema: None,
            // Synthetic test fixture: line 0 means "unknown" (legacy entry).
            raw_calls: raw.into_iter().map(RawCall::lineless).collect(),
        }
    }

    #[test]
    fn stub_callees_keeps_db_session_get_in_database_category() {
        let graph = unfault_analysis::graph::CodeGraph::default();
        let anchor = make_handler_with_raw_calls(vec!["db_session.get", "build_response"]);
        let file_libs = std::collections::HashMap::new();

        let nodes =
            stub_callees_from_raw_calls(&graph, &anchor, &file_libs, &AutoInstrumentSet::new());

        assert!(
            nodes
                .iter()
                .any(|n| matches!(n.role, NodeRole::Database) && n.name == "db_session.get"),
            "db_session.get must be present as a Database node, got: {:?}",
            nodes
                .iter()
                .map(|n| (n.name.clone(), format!("{:?}", n.role)))
                .collect::<Vec<_>>()
        );
        assert!(
            nodes
                .iter()
                .any(|n| matches!(n.role, NodeRole::Logic) && n.name == "build_response"),
            "build_response must remain as a Logic node"
        );
    }

    #[test]
    fn stub_callees_keeps_db_session_commit_and_execute() {
        let graph = unfault_analysis::graph::CodeGraph::default();
        let anchor = make_handler_with_raw_calls(vec![
            "db_session.commit",
            "db_session.execute",
            "db_session.scalars",
        ]);
        let file_libs = std::collections::HashMap::new();

        let nodes =
            stub_callees_from_raw_calls(&graph, &anchor, &file_libs, &AutoInstrumentSet::new());

        let db_count = nodes
            .iter()
            .filter(|n| matches!(n.role, NodeRole::Database))
            .count();
        assert_eq!(
            db_count, 3,
            "all three db_session calls must be Database, got: {:?}",
            nodes
        );
    }

    #[test]
    fn stub_callees_drops_only_noise_not_real_calls() {
        let graph = unfault_analysis::graph::CodeGraph::default();
        let anchor = make_handler_with_raw_calls(vec![
            "Depends",        // FastAPI DI marker — drop
            "HTTPException",  // error constructor — drop
            "__init__",       // dunder — drop
            "db_session.get", // real db call — keep
            "validate_input", // logic — keep
        ]);
        let file_libs = std::collections::HashMap::new();

        let nodes =
            stub_callees_from_raw_calls(&graph, &anchor, &file_libs, &AutoInstrumentSet::new());

        let names: Vec<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
        assert!(
            names.contains(&"db_session.get"),
            "expected db_session.get, got {:?}",
            names
        );
        assert!(
            names.contains(&"validate_input"),
            "expected validate_input, got {:?}",
            names
        );
        assert!(!names.contains(&"Depends"));
        assert!(!names.contains(&"HTTPException"));
        assert!(!names.contains(&"__init__"));
    }

    // ── build_auto_instrument_set ─────────────────────────────────────────────

    #[test]
    fn classify_instrumentor_call_recognises_fastapi() {
        assert_eq!(
            classify_instrumentor_call("fastapiinstrumentor.instrument_app"),
            Some("fastapi".to_string())
        );
        assert_eq!(
            classify_instrumentor_call("FastAPIInstrumentor.instrument_app"),
            Some("fastapi".to_string())
        );
    }

    #[test]
    fn classify_instrumentor_call_recognises_sqlalchemy() {
        assert_eq!(
            classify_instrumentor_call("sqlalchemyinstrumentor.instrument"),
            Some("sqlalchemy".to_string())
        );
    }

    #[test]
    fn classify_instrumentor_call_recognises_ddtrace_patch_all() {
        assert_eq!(
            classify_instrumentor_call("patch_all"),
            Some("all".to_string())
        );
        assert_eq!(
            classify_instrumentor_call("ddtrace.patch_all"),
            Some("all".to_string())
        );
    }

    #[test]
    fn classify_instrumentor_call_ignores_regular_calls() {
        assert_eq!(classify_instrumentor_call("validate_input"), None);
        assert_eq!(classify_instrumentor_call("db_session.get"), None);
        assert_eq!(classify_instrumentor_call("fetch_user"), None);
    }

    #[test]
    fn build_auto_instrument_set_from_graph_with_fastapi_instrumentor() {
        use crate::session::ir_builder::build_ir_cached;

        // Build a tiny two-file workspace:
        //   tracing.py  — imports opentelemetry.instrumentation.fastapi and calls instrument_app
        //   routes.py   — a FastAPI route handler (no OTel import)
        let temp = tempfile::TempDir::new().unwrap();

        std::fs::write(
            temp.path().join("tracing.py"),
            r#"
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

def setup_tracing(app):
    FastAPIInstrumentor.instrument_app(app)
"#,
        )
        .unwrap();

        std::fs::write(
            temp.path().join("routes.py"),
            r#"
from fastapi import APIRouter

router = APIRouter()

@router.get("/items")
async def list_items():
    return []
"#,
        )
        .unwrap();

        let build = build_ir_cached(temp.path(), None, false).unwrap();
        let graph = unfault_analysis::graph::CodeGraph::from(build.ir.graph);

        let instruments = build_auto_instrument_set(&graph);

        assert!(
            instruments.contains_key("fastapi"),
            "expected fastapi in auto_instruments, got {:?}",
            instruments.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn build_auto_instrument_set_empty_when_no_instrumentor() {
        use crate::session::ir_builder::build_ir_cached;

        let temp = tempfile::TempDir::new().unwrap();
        std::fs::write(
            temp.path().join("routes.py"),
            r#"
from fastapi import APIRouter
router = APIRouter()

@router.get("/items")
async def list_items():
    return []
"#,
        )
        .unwrap();

        let build = build_ir_cached(temp.path(), None, false).unwrap();
        let graph = unfault_analysis::graph::CodeGraph::from(build.ir.graph);

        let instruments = build_auto_instrument_set(&graph);
        assert!(
            instruments.is_empty(),
            "expected no auto-instrumentation, got {:?}",
            instruments
        );
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

    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);
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
    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);

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

    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);

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

    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);
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

    let commit_sha = crate::session::query_cache::workspace_state_key(&workspace_path);

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
