use anyhow::Result;
use colored::Colorize;

use crate::commands::graph::{
    CoverageContext, CoverageNode, NodeRole, SignalKind, SpanSignal, UnobservedPaths,
    build_coverage_context, build_graph_with_spinner,
};
use crate::exit_codes::*;

use unfault_analysis::graph::traversal::node_file_path_pub;
use unfault_analysis::graph::{
    CodeGraph, GraphEdgeKind, GraphNode, GraphNodeIndex, ModuleCategory,
};

use petgraph::Direction;
use petgraph::visit::EdgeRef;

// ── Public interface ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct TelemetryArgs {
    pub target: String,
    pub workspace_path: Option<String>,
    pub json: bool,
    pub compact: bool,
    pub summary: bool,
    pub verbose: bool,
    pub offline: bool,
    pub refresh_cache: bool,
}

pub async fn execute(args: TelemetryArgs) -> Result<i32> {
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

    let target = args.target.trim();
    let target_kind = resolve_target(target, &graph);
    let report = match target_kind {
        TargetKind::Route {
            ref method,
            ref path,
        } => analyze_route(&graph, path, method.as_deref(), args.verbose),
        TargetKind::Function => analyze_function(&graph, target, args.verbose),
        TargetKind::File => analyze_file(&graph, target, args.verbose),
        TargetKind::Directory => analyze_directory(&graph, target, args.verbose),
    };

    let report = match report {
        Some(r) => r,
        None => {
            eprintln!(
                "{} Could not resolve '{}' in the code graph.",
                "Error:".red().bold(),
                target
            );
            return Ok(EXIT_ERROR);
        }
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if args.compact {
        render_compact(&report);
    } else if args.summary {
        match target_kind {
            TargetKind::Directory => render_summary(&report),
            _ => match target_kind {
                TargetKind::Route { .. } | TargetKind::Function => render_merged(&report),
                _ => render_sections(&report),
            },
        }
    } else {
        match target_kind {
            TargetKind::Directory => render_catalog(&report),
            TargetKind::Route { .. } | TargetKind::Function => render_merged(&report),
            _ => render_sections(&report),
        }
    }

    Ok(EXIT_SUCCESS)
}

// ── Target resolution ─────────────────────────────────────────────────────────

enum TargetKind {
    Route {
        method: Option<String>,
        path: String,
    },
    File,
    Directory,
    Function,
}

fn resolve_target(target: &str, graph: &CodeGraph) -> TargetKind {
    // 1. Route: starts with /
    if target.starts_with('/') {
        return TargetKind::Route {
            method: None,
            path: target.to_string(),
        };
    }

    // 2. Route: "METHOD /path" pattern
    let upper = target.to_uppercase();
    if let Some(rest) = upper
        .strip_prefix("GET ")
        .or_else(|| upper.strip_prefix("POST "))
        .or_else(|| upper.strip_prefix("PUT "))
        .or_else(|| upper.strip_prefix("PATCH "))
        .or_else(|| upper.strip_prefix("DELETE "))
        .or_else(|| upper.strip_prefix("HEAD "))
        .or_else(|| upper.strip_prefix("OPTIONS "))
    {
        if rest.starts_with('/') {
            return TargetKind::Route {
                method: Some(target[..target.find(' ').unwrap_or(0)].to_string()),
                path: rest.to_string(),
            };
        }
    }

    // 3. File: contains a dot and matches a file in the graph
    if target.contains('.') && graph.find_file_by_path(target).is_some() {
        return TargetKind::File;
    }

    // 4. Directory: ends with / or matches as path prefix of file nodes
    if target.ends_with('/') || has_file_with_prefix(graph, target) {
        return TargetKind::Directory;
    }

    // 5. Could be file without matching (also has dot) — treat as file path heuristic
    if target.contains('.') {
        return TargetKind::File;
    }

    // 6. Fallback: function
    TargetKind::Function
}

fn has_file_with_prefix(graph: &CodeGraph, prefix: &str) -> bool {
    for idx in graph.graph.node_indices() {
        if let GraphNode::File { path, .. } = &graph.graph[idx] {
            if path.starts_with(prefix) || path.contains(&format!("/{}", prefix)) {
                return true;
            }
        }
    }
    false
}

// ── Quality levels ────────────────────────────────────────────────────────────

/// What kind of span, if any, the anchor function carries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    /// Explicit decorator or SDK call on this function.
    Explicit,
    /// Framework-level auto-instrumentation (e.g. FastAPIInstrumentor).
    FrameworkAuto,
    /// No span detected.
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoggingQuality {
    Structured,
    Plain,
    #[serde(rename = "none")]
    None_,
}

impl LoggingQuality {
    fn icon(&self) -> &'static str {
        match self {
            LoggingQuality::Structured => "◉",
            LoggingQuality::Plain => "○",
            LoggingQuality::None_ => "·",
        }
    }
}

// ── Report types ──────────────────────────────────────────────────────────────

/// A single callee in the route's call tree, with its instrumentation state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CalleeInfo {
    pub name: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub role: NodeRole,
    /// How deep from the handler (1 = direct callee).
    pub depth: i32,
    pub anchor_kind: AnchorKind,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteTelemetry {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// What kind of span the handler itself carries.
    pub anchor_kind: AnchorKind,
    pub total_callees: usize,
    pub instrumented_callees: usize,
    /// Flat list of all callees with their instrumentation state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callees: Vec<CalleeInfo>,
    /// All callees with no span, grouped by role.
    pub unobserved: UnobservedPaths,
    /// Logging quality for the file this handler lives in.
    pub logging: LoggingQuality,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging_library: Option<String>,
    /// Whether the handler's file emits metrics.
    pub metrics: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metrics_library: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileLogging {
    pub file: String,
    pub quality: LoggingQuality,
    pub library: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileMetrics {
    pub file: String,
    pub present: bool,
    pub library: Option<String>,
}

/// A single boundary call site with location, for the flat aggregator view.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BoundaryCallSite {
    /// Call expression or function name.
    pub name: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// The route handler that contains this call.
    pub in_route: String,
    /// The direct enclosing function (may equal in_route for shallow calls).
    pub in_function: String,
    pub anchor_kind: AnchorKind,
}

/// Flat inventory of all boundary call sites across the report, grouped by
/// kind. Lets an agent answer "all unobserved http calls" without walking
/// every route.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Boundaries {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub db: Vec<BoundaryCallSite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http: Vec<BoundaryCallSite>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote: Vec<BoundaryCallSite>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TelemetryReport {
    pub target: String,
    pub target_kind: String,
    pub routes: Vec<RouteTelemetry>,
    /// Per-file logging, used for directory-level catalog view.
    pub logging: Vec<FileLogging>,
    /// Per-file metrics, used for directory-level catalog view.
    pub metrics: Vec<FileMetrics>,
    /// Flat aggregator view of all boundary call sites across all routes.
    pub boundaries: Boundaries,
}

// ── Analysis: scope (directory / file) ────────────────────────────────────────

fn analyze_directory(graph: &CodeGraph, dir: &str, verbose: bool) -> Option<TelemetryReport> {
    let target = dir.trim_end_matches('/');
    let files: Vec<String> = graph
        .graph
        .node_indices()
        .filter_map(|idx| {
            if let GraphNode::File { path, .. } = &graph.graph[idx] {
                if path.starts_with(target) || path.contains(&format!("/{}", target)) {
                    Some(path.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    if files.is_empty() {
        return None;
    }

    analyze_file_list(graph, dir, "directory", &files, verbose)
}

fn analyze_file(graph: &CodeGraph, file_path: &str, verbose: bool) -> Option<TelemetryReport> {
    let files = vec![file_path.to_string()];
    analyze_file_list(graph, file_path, "file", &files, verbose)
}

fn analyze_file_list(
    graph: &CodeGraph,
    target: &str,
    kind: &str,
    files: &[String],
    verbose: bool,
) -> Option<TelemetryReport> {
    let mut routes: Vec<RouteTelemetry> = Vec::new();

    for file_path in files {
        let handlers: Vec<(String, String, String, Option<u32>)> = graph
            .graph
            .node_indices()
            .filter_map(|idx| {
                if let GraphNode::Function {
                    is_handler: true,
                    http_method: Some(method),
                    http_path: Some(path),
                    name,
                    line,
                    ..
                } = &graph.graph[idx]
                {
                    let f = node_file_path_pub(graph, &graph.graph[idx]).unwrap_or_default();
                    if f == *file_path || f.ends_with(file_path.as_str()) {
                        Some((method.clone(), path.clone(), name.clone(), *line))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        let fl = file_logging_quality(graph, file_path);
        let fm = file_metrics(graph, file_path);
        for (method, path, handler, line) in &handlers {
            if routes.iter().any(|r: &RouteTelemetry| r.method == *method && r.path == *path && r.handler == *handler) {
                continue;
            }
            if let Some(rt) = analyze_single_route(graph, path, Some(method), verbose) {
                routes.push(RouteTelemetry {
                    method: method.clone(),
                    path: path.clone(),
                    handler: handler.clone(),
                    file: file_path.clone(),
                    line: *line,
                    anchor_kind: rt.anchor_kind,
                    total_callees: rt.total_callees,
                    instrumented_callees: rt.instrumented_callees,
                    callees: rt.callees,
                    unobserved: rt.unobserved,
                    logging: fl.quality.clone(),
                    logging_library: if fl.library.is_empty() { None } else { Some(fl.library.clone()) },
                    metrics: fm.present,
                    metrics_library: fm.library.clone(),
                });
            }
        }
    }

    let logging: Vec<FileLogging> = files
        .iter()
        .map(|f| file_logging_quality(graph, f))
        .collect();

    let metrics: Vec<FileMetrics> = files.iter().map(|f| file_metrics(graph, f)).collect();
    let boundaries = build_boundaries(&routes);

    Some(TelemetryReport {
        target: target.to_string(),
        target_kind: kind.to_string(),
        routes,
        logging,
        metrics,
        boundaries,
    })
}

// ── Analysis: single route / function ─────────────────────────────────────────

struct RouteTraversal {
    anchor_kind: AnchorKind,
    total_callees: usize,
    instrumented_callees: usize,
    callees: Vec<CalleeInfo>,
    unobserved: UnobservedPaths,
}

fn analyze_route(
    graph: &CodeGraph,
    path: &str,
    method: Option<&str>,
    verbose: bool,
) -> Option<TelemetryReport> {
    let ctx = build_coverage_context(graph, path, method, None, verbose)?;
    let rt = traversal_from_context(&ctx);
    let anchor_idx = find_anchor(graph, path, method)?;
    let anchor_node = &graph.graph[anchor_idx];
    let anchor_file = node_file_path_pub(graph, anchor_node).unwrap_or_default();

    let fl = file_logging_quality(graph, &anchor_file);
    let fm = file_metrics(graph, &anchor_file);
    let routes_vec = vec![RouteTelemetry {
        method: ctx.anchor.role.method_str().unwrap_or_default().to_string(),
        path: ctx.anchor.role.path_str().unwrap_or_default().to_string(),
        handler: ctx.anchor.name.clone(),
        file: anchor_file.clone(),
        line: ctx.anchor.line,
        anchor_kind: rt.anchor_kind,
        total_callees: rt.total_callees,
        instrumented_callees: rt.instrumented_callees,
        callees: rt.callees,
        unobserved: rt.unobserved,
        logging: fl.quality,
        logging_library: if fl.library.is_empty() { None } else { Some(fl.library) },
        metrics: fm.present,
        metrics_library: fm.library,
    }];
    let report = TelemetryReport {
        target: format!("{} {}", ctx.anchor.role.method_str().unwrap_or(""), path)
            .trim()
            .to_string(),
        target_kind: "route".to_string(),
        logging: vec![file_logging_quality(graph, &anchor_file)],
        metrics: vec![file_metrics(graph, &anchor_file)],
        boundaries: build_boundaries(&routes_vec),
        routes: routes_vec,
    };

    Some(report)
}

fn analyze_function(graph: &CodeGraph, name: &str, verbose: bool) -> Option<TelemetryReport> {
    let ctx = build_coverage_context(graph, name, None, None, verbose)?;
    let rt = traversal_from_context(&ctx);
    let anchor_idx = find_function_anchor(graph, name)?;
    let anchor_node = &graph.graph[anchor_idx];
    let anchor_file = node_file_path_pub(graph, anchor_node).unwrap_or_default();

    let fl = file_logging_quality(graph, &anchor_file);
    let fm = file_metrics(graph, &anchor_file);
    let routes_vec = vec![RouteTelemetry {
        method: ctx.anchor.role.method_str().unwrap_or_default().to_string(),
        path: ctx.anchor.role.path_str().unwrap_or_default().to_string(),
        handler: ctx.anchor.name.clone(),
        file: anchor_file.clone(),
        line: ctx.anchor.line,
        anchor_kind: rt.anchor_kind,
        total_callees: rt.total_callees,
        instrumented_callees: rt.instrumented_callees,
        callees: rt.callees,
        unobserved: rt.unobserved,
        logging: fl.quality,
        logging_library: if fl.library.is_empty() { None } else { Some(fl.library) },
        metrics: fm.present,
        metrics_library: fm.library,
    }];
    let report = TelemetryReport {
        target: name.to_string(),
        target_kind: "function".to_string(),
        logging: vec![file_logging_quality(graph, &anchor_file)],
        metrics: vec![file_metrics(graph, &anchor_file)],
        boundaries: build_boundaries(&routes_vec),
        routes: routes_vec,
    };

    Some(report)
}

fn analyze_single_route(
    graph: &CodeGraph,
    path: &str,
    method: Option<&str>,
    verbose: bool,
) -> Option<RouteTraversal> {
    let ctx = build_coverage_context(graph, path, method, None, verbose)?;
    Some(traversal_from_context(&ctx))
}

fn traversal_from_context(ctx: &CoverageContext) -> RouteTraversal {
    let mut all_nodes: Vec<&CoverageNode> = Vec::new();
    collect_nodes(&ctx.anchor, &mut all_nodes);
    for c in &ctx.callers {
        collect_nodes(c, &mut all_nodes);
    }

    // Build flat callee list (exclude anchor itself)
    let callees: Vec<CalleeInfo> = all_nodes
        .iter()
        .filter(|n| n.depth != 0)
        .map(|n| CalleeInfo {
            name: n.name.clone(),
            file: n.file.clone(),
            line: n.line,
            role: n.role.clone(),
            depth: n.depth,
            anchor_kind: span_to_anchor_kind(&n.span),
        })
        .collect();

    let total_callees = callees.len();
    let instrumented_callees = callees
        .iter()
        .filter(|c| c.anchor_kind != AnchorKind::None)
        .count();

    RouteTraversal {
        anchor_kind: span_to_anchor_kind(&ctx.anchor.span),
        total_callees,
        instrumented_callees,
        callees,
        unobserved: ctx.unobserved_paths.clone(),
    }
}

fn span_to_anchor_kind(span: &SpanSignal) -> AnchorKind {
    match span {
        SpanSignal::Decorator { .. } | SpanSignal::SdkImported { .. } => AnchorKind::Explicit,
        SpanSignal::AutoInstrumented { .. } => AnchorKind::FrameworkAuto,
        SpanSignal::None => AnchorKind::None,
    }
}

/// Build the flat cross-route boundary inventory from the assembled route list.
fn build_boundaries(routes: &[RouteTelemetry]) -> Boundaries {
    let mut db: Vec<BoundaryCallSite> = Vec::new();
    let mut http: Vec<BoundaryCallSite> = Vec::new();
    let mut remote: Vec<BoundaryCallSite> = Vec::new();

    for route in routes {
        let route_label = if route.method.is_empty() {
            route.path.clone()
        } else {
            format!("{} {}", route.method, route.path)
        };
        for callee in &route.callees {
            let site = BoundaryCallSite {
                name: callee.name.clone(),
                file: callee.file.clone(),
                line: callee.line,
                in_route: route_label.clone(),
                in_function: route.handler.clone(),
                anchor_kind: callee.anchor_kind.clone(),
            };
            match &callee.role {
                NodeRole::Database => db.push(site),
                NodeRole::HttpClient => http.push(site),
                NodeRole::RemoteCall { .. } => remote.push(site),
                _ => {}
            }
        }
    }

    Boundaries { db, http, remote }
}

// ── Helpers: find nodes ───────────────────────────────────────────────────────

fn find_anchor(graph: &CodeGraph, path: &str, method: Option<&str>) -> Option<GraphNodeIndex> {
    let normalized = crate::slo::matcher::normalize_route_path(path);
    graph.graph.node_indices().find(|&idx| {
        if let GraphNode::Function {
            is_handler: true,
            http_path: Some(p),
            http_method,
            ..
        } = &graph.graph[idx]
        {
            let path_match = crate::slo::matcher::normalize_route_path(p) == normalized;
            let method_match = method
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

fn find_function_anchor(graph: &CodeGraph, name: &str) -> Option<GraphNodeIndex> {
    let lower = name.to_lowercase();
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

fn collect_nodes<'a>(node: &'a CoverageNode, out: &mut Vec<&'a CoverageNode>) {
    out.push(node);
    for child in &node.children {
        collect_nodes(child, out);
    }
}

// ── Helpers: logging quality ─────────────────────────────────────────────────

/// Structured logging libs we recognise.
const STRUCTURED_LOGGING_LIBS: &[&str] = &[
    "structlog",
    "loguru",
    "zap",
    "zerolog",
    "logrus",
    "winston",
    "bunyan",
    "slog",
];

fn file_logging_quality(graph: &CodeGraph, file_path: &str) -> FileLogging {
    let file_idx = graph.find_file_by_path(file_path);
    let file_idx = match file_idx {
        Some(i) => i,
        None => {
            return FileLogging {
                file: file_path.to_string(),
                quality: LoggingQuality::None_,
                library: String::new(),
            };
        }
    };

    // Direct import check
    for edge in graph.graph.edges_directed(file_idx, Direction::Outgoing) {
        if matches!(edge.weight(), GraphEdgeKind::UsesLibrary) {
            if let GraphNode::ExternalModule {
                name,
                category: ModuleCategory::Logging,
                ..
            } = &graph.graph[edge.target()]
            {
                let (quality, lib) = classify_logging_lib(name);
                return FileLogging {
                    file: file_path.to_string(),
                    quality,
                    library: lib,
                };
            }
        }
    }

    // Re-export chase: follow ImportsFrom -> check target file's UsesLibrary
    for edge in graph.graph.edges_directed(file_idx, Direction::Outgoing) {
        if matches!(edge.weight(), GraphEdgeKind::ImportsFrom { .. }) {
            let target_idx = edge.target();
            for inner in graph.graph.edges_directed(target_idx, Direction::Outgoing) {
                if matches!(inner.weight(), GraphEdgeKind::UsesLibrary) {
                    if let GraphNode::ExternalModule {
                        name,
                        category: ModuleCategory::Logging,
                        ..
                    } = &graph.graph[inner.target()]
                    {
                        let (quality, lib) = classify_logging_lib(name);
                        return FileLogging {
                            file: file_path.to_string(),
                            quality,
                            library: lib,
                        };
                    }
                }
            }
        }
    }

    FileLogging {
        file: file_path.to_string(),
        quality: LoggingQuality::None_,
        library: String::new(),
    }
}

fn classify_logging_lib(name: &str) -> (LoggingQuality, String) {
    let lower = name.to_lowercase();
    if STRUCTURED_LOGGING_LIBS.iter().any(|l| lower.contains(l)) {
        (LoggingQuality::Structured, name.to_string())
    } else if lower.contains("logging") || lower.contains("log") {
        (LoggingQuality::Plain, name.to_string())
    } else {
        (LoggingQuality::None_, name.to_string())
    }
}

// ── Helpers: metrics ─────────────────────────────────────────────────────────

const METRIC_LIBS: &[&str] = &[
    "prometheus",
    "prometheus_client",
    "statsd",
    "dogstatsd",
    "datadog",
    "influxdb",
    "graphite",
    "metric",
];

fn file_metrics(graph: &CodeGraph, file_path: &str) -> FileMetrics {
    let file_idx = graph.find_file_by_path(file_path);
    let file_idx = match file_idx {
        Some(i) => i,
        None => {
            return FileMetrics {
                file: file_path.to_string(),
                present: false,
                library: None,
            };
        }
    };

    for edge in graph.graph.edges_directed(file_idx, Direction::Outgoing) {
        if matches!(edge.weight(), GraphEdgeKind::UsesLibrary) {
            if let GraphNode::ExternalModule { name, .. } = &graph.graph[edge.target()] {
                let lower = name.to_lowercase();
                if METRIC_LIBS.iter().any(|m| lower.contains(m)) {
                    return FileMetrics {
                        file: file_path.to_string(),
                        present: true,
                        library: Some(name.clone()),
                    };
                }
            }
        }
    }

    FileMetrics {
        file: file_path.to_string(),
        present: false,
        library: None,
    }
}

// ── Helpers: NodeRole accessors (avoid pattern matching everywhere) ───────────

impl NodeRole {
    fn method_str(&self) -> Option<&str> {
        match self {
            NodeRole::HttpHandler { method, .. } => Some(method.as_str()),
            _ => None,
        }
    }
    fn path_str(&self) -> Option<&str> {
        match self {
            NodeRole::HttpHandler { path, .. } => Some(path.as_str()),
            _ => None,
        }
    }
}

// ── Rendering: sections (default for dir/file) ────────────────────────────────

fn render_sections(report: &TelemetryReport) {
    println!();
    println!(
        "Telemetry Coverage for {}",
        report.target.bright_white().bold()
    );
    println!();

    let total = report.routes.len();
    if total == 0 {
        println!("  {}Traces{}", "──".cyan(), "──".cyan());
        println!("  No routes in scope.");
    } else if report.target_kind == "directory" {
        println!("  {}Traces by Method{}", "──".cyan(), "──".cyan());
        let reads: Vec<&RouteTelemetry> = report
            .routes
            .iter()
            .filter(|r| !is_write_method(&r.method))
            .collect();
        let writes: Vec<&RouteTelemetry> = report
            .routes
            .iter()
            .filter(|r| is_write_method(&r.method))
            .collect();
        for (routes, label, methods) in [
            (&reads, "read ", "(GET)"),
            (&writes, "write", "(POST/PUT/PATCH/DELETE)"),
        ] {
            let n = routes.len();
            if n == 0 {
                continue;
            }
            let explicit = routes
                .iter()
                .filter(|r| r.anchor_kind == AnchorKind::Explicit)
                .count();
            let framework = routes
                .iter()
                .filter(|r| r.anchor_kind == AnchorKind::FrameworkAuto)
                .count();
            let unobserved = routes
                .iter()
                .filter(|r| r.anchor_kind == AnchorKind::None)
                .count();
            println!(
                "  {} ({:>3})   {} {} ({:>3}%)  {} {} ({:>3}%)  {} {} ({:>3}%)  {}",
                label,
                n,
                "●".green(),
                fmt_count(explicit, n),
                pct(explicit, n),
                "◐".yellow(),
                fmt_count(framework, n),
                pct(framework, n),
                "○".normal(),
                fmt_count(unobserved, n),
                pct(unobserved, n),
                methods.bright_black(),
            );
        }
    } else {
        println!("  {}Traces{}", "──".cyan(), "──".cyan());
        let explicit = report
            .routes
            .iter()
            .filter(|r| r.anchor_kind == AnchorKind::Explicit)
            .count();
        let framework = report
            .routes
            .iter()
            .filter(|r| r.anchor_kind == AnchorKind::FrameworkAuto)
            .count();
        let unobserved = report
            .routes
            .iter()
            .filter(|r| r.anchor_kind == AnchorKind::None)
            .count();
        println!(
            "  {} explicit       {} ({:>3}%)",
            "●".green(),
            fmt_count(explicit, total),
            pct(explicit, total)
        );
        println!(
            "  {} framework auto {} ({:>3}%)",
            "◐".yellow(),
            fmt_count(framework, total),
            pct(framework, total)
        );
        println!(
            "  {} unobserved     {} ({:>3}%)",
            "○".normal(),
            fmt_count(unobserved, total),
            pct(unobserved, total)
        );
        println!();

        // Per-route listing
        for r in &report.routes {
            let quality = match r.anchor_kind {
                AnchorKind::Explicit => "● explicit".green().to_string(),
                AnchorKind::FrameworkAuto => "◐ framework".yellow().to_string(),
                AnchorKind::None => "○ unobserved".normal().to_string(),
            };
            let loc = match r.line {
                Some(l) => format!("{}:{}", r.file, l).bright_black(),
                None => r.file.bright_black(),
            };
            println!(
                "  {:<8} {}  {}  {}",
                format!("{}{}", r.method.magenta().bold(), ":").dimmed(),
                r.path.bright_yellow(),
                quality,
                loc,
            );
        }
    }
    println!();

    // ── Logging section ──
    println!("  {}Logging{}", "──".cyan(), "──".cyan());
    let structured = report
        .logging
        .iter()
        .filter(|l| l.quality == LoggingQuality::Structured)
        .count();
    let plain = report
        .logging
        .iter()
        .filter(|l| l.quality == LoggingQuality::Plain)
        .count();
    let none = report
        .logging
        .iter()
        .filter(|l| l.quality == LoggingQuality::None_)
        .count();
    if structured > 0 {
        println!(
            "  {} structured      {} file{}",
            "◉".green(),
            structured,
            if structured == 1 { "" } else { "s" }
        );
    }
    if plain > 0 {
        println!(
            "  {} plain           {} file{}",
            "○".normal(),
            plain,
            if plain == 1 { "" } else { "s" }
        );
    }
    if none > 0 {
        println!(
            "  {} none            {} file{}",
            "·".dimmed(),
            none,
            if none == 1 { "" } else { "s" }
        );
    }

    if report.target_kind != "directory" {
        for fl in &report.logging {
            let icon = fl.quality.icon();
            let quality_str = match fl.quality {
                LoggingQuality::Structured => format!("{} {}", icon.green(), "structured".green()),
                LoggingQuality::Plain => format!("{} {}", icon.normal(), "plain".normal()),
                LoggingQuality::None_ => format!("{} {}", icon.dimmed(), "none".dimmed()),
            };
            let lib_str = if !fl.library.is_empty() {
                format!("  ({})", fl.library.bright_black())
            } else {
                String::new()
            };
            println!("  {}  {}{}", fl.file.bright_blue(), quality_str, lib_str);
        }
    }
    println!();

    // ── Metrics section ──
    println!("  {}Metrics{}", "──".cyan(), "──".cyan());
    let has_metrics = report.metrics.iter().any(|m| m.present);
    let present_count = report.metrics.iter().filter(|m| m.present).count();
    let absent_count = report.metrics.iter().filter(|m| !m.present).count();
    if has_metrics {
        println!(
            "  ◉ present         {} file{}",
            present_count,
            if present_count == 1 { "" } else { "s" }
        );
    }
    if absent_count > 0 {
        println!(
            "  ○ none            {} file{}",
            absent_count,
            if absent_count == 1 { "" } else { "s" }
        );
    }
    if report.target_kind != "directory" {
        for m in &report.metrics {
            let status = if m.present {
                format!(
                    "{} {}",
                    "◉".green(),
                    m.library.as_deref().unwrap_or("present").green()
                )
            } else {
                format!("{} {}", "○".normal(), "none".normal())
            };
            println!("  {}  {}", m.file.bright_blue(), status);
        }
    }
    println!();

    // ── Boundaries ──
    render_boundaries_section(report);
    render_legend();
}

// ── Rendering: merged (for single route / function) ───────────────────────────

fn render_merged(report: &TelemetryReport) {
    println!();
    if let Some(r) = report.routes.first() {
        let header = if !r.method.is_empty() {
            format!("{} {}", r.method.magenta().bold(), r.path.bright_yellow())
        } else {
            report.target.bright_white().bold().to_string()
        };
        println!("  Telemetry Coverage for {}", header);
        if let Some(line) = r.line {
            println!(
                "  {}  {}",
                "at".bright_black(),
                format!("{}:{}", r.file, line).bright_black()
            );
        }

        let trace_str = match r.anchor_kind {
            AnchorKind::Explicit => "● explicit".green(),
            AnchorKind::FrameworkAuto => "◐ framework auto".yellow(),
            AnchorKind::None => "○ unobserved".normal(),
        };
        println!("\n  trace: {}", trace_str);
    }

    // Show which routes reach this function (if function target)
    if report.target_kind == "function" && report.routes.len() <= 1 {
        // The callers info is inside the CoverageContext — but we don't have it here
        // because we only stored the aggregate.  For now, boundaries are the key signal.
    }

    // Logging
    if let Some(fl) = report.logging.first() {
        let quality_str = match fl.quality {
            LoggingQuality::Structured => format!("{} structured", "◉".green()),
            LoggingQuality::Plain => format!("{} plain", "○".normal()),
            LoggingQuality::None_ => format!("{} none", "·".dimmed()),
        };
        let lib_str = if !fl.library.is_empty() {
            format!("  ({})", fl.library.bright_black())
        } else {
            String::new()
        };
        println!("  logging: {}{}", quality_str, lib_str);
    }

    // Metrics
    if let Some(m) = report.metrics.first() {
        let status = if m.present {
            format!(
                "{} {}",
                "◉".green(),
                m.library.as_deref().unwrap_or("present").green()
            )
        } else {
            format!("{} {}", "○".normal(), "none".normal())
        };
        println!("  metrics: {}", status);
    }

    println!();
    render_boundaries_section(report);
    render_legend();
}

// ── Rendering: catalog (new default for directories) ─────────────────────────

fn render_catalog(report: &TelemetryReport) {
    let total_files = report.logging.len();
    let total_routes = report.routes.len();
    let reads = report
        .routes
        .iter()
        .filter(|r| !is_write_method(&r.method))
        .count();
    let writes = report
        .routes
        .iter()
        .filter(|r| is_write_method(&r.method))
        .count();
    let log_structured = report
        .logging
        .iter()
        .filter(|l| l.quality == LoggingQuality::Structured)
        .count();
    let log_plain = report
        .logging
        .iter()
        .filter(|l| l.quality == LoggingQuality::Plain)
        .count();
    let log_none_count = report
        .logging
        .iter()
        .filter(|l| l.quality == LoggingQuality::None_)
        .count();
    let metrics_present = report.metrics.iter().filter(|m| m.present).count();
    let metrics_total = report.metrics.len();
    let read_deep = report
        .routes
        .iter()
        .filter(|r| !is_write_method(&r.method) && r.anchor_kind == AnchorKind::Explicit)
        .count();
    let read_shallow = report
        .routes
        .iter()
        .filter(|r| !is_write_method(&r.method) && r.anchor_kind == AnchorKind::FrameworkAuto)
        .count();
    let read_none = report
        .routes
        .iter()
        .filter(|r| !is_write_method(&r.method) && r.anchor_kind == AnchorKind::None)
        .count();
    let write_deep = report
        .routes
        .iter()
        .filter(|r| is_write_method(&r.method) && r.anchor_kind == AnchorKind::Explicit)
        .count();
    let write_shallow = report
        .routes
        .iter()
        .filter(|r| is_write_method(&r.method) && r.anchor_kind == AnchorKind::FrameworkAuto)
        .count();
    let write_none = report
        .routes
        .iter()
        .filter(|r| is_write_method(&r.method) && r.anchor_kind == AnchorKind::None)
        .count();
    let db_total = report.boundaries.db.len();
    let db_covered = report.boundaries.db.iter().filter(|s| s.anchor_kind != AnchorKind::None).count();
    let http_total = report.boundaries.http.len();
    let http_covered = report.boundaries.http.iter().filter(|s| s.anchor_kind != AnchorKind::None).count();

    println!();
    println!("Telemetry in {}", report.target.bright_white().bold());
    println!(
        "{} files, {} routes ({} read, {} write)",
        total_files.to_string().yellow(),
        total_routes.to_string().yellow(),
        reads.to_string().yellow(),
        writes.to_string().yellow(),
    );
    println!();

    let fine_total = read_deep + write_deep;
    let shallow_total = read_shallow + write_shallow;
    let none_total = read_none + write_none;

    // ── Logging ──
    {
        let mut parts: Vec<String> = Vec::new();
        if log_structured > 0 {
            parts.push(format!(
                "structured logging in {} of {} file{}",
                log_structured,
                total_files,
                if total_files == 1 { "" } else { "s" }
            ));
        } else if log_plain > 0 {
            parts.push(format!(
                "plain logging in {} of {} file{}",
                log_plain,
                total_files,
                if total_files == 1 { "" } else { "s" }
            ));
        }
        if log_none_count > 0 {
            parts.push(format!(
                "{} file{} silent",
                log_none_count,
                if log_none_count == 1 { "" } else { "s" }
            ));
        }
        if metrics_total > 0 {
            if metrics_present == 0 {
                parts.push("no metrics".to_string());
            } else if metrics_present < metrics_total {
                parts.push(format!(
                    "metrics in {} of {} file{}",
                    metrics_present,
                    metrics_total,
                    if metrics_total == 1 { "" } else { "s" }
                ));
            }
        }
        if parts.is_empty() {
            println!("No logging or metrics detected.");
        } else {
            println!("Logging: {}.", parts.join(", "));
        }
    }

    // ── Tracing ──
    if total_routes > 0 {
        println!();
        if none_total == total_routes {
            println!("Spans: none. No route is instrumented.");
        } else if fine_total == total_routes {
            println!(
                "Spans: all {} route{} carry explicit attributes.",
                total_routes,
                if total_routes == 1 { "" } else { "s" }
            );
        } else {
            let mut parts: Vec<String> = Vec::new();
            if fine_total > 0 {
                parts.push(format!(
                    "{} fine (explicit attributes)",
                    fine_total
                ));
            }
            if shallow_total > 0 {
                parts.push(format!("{} coarse (framework only)", shallow_total));
            }
            if none_total > 0 {
                parts.push(format!("{} unobserved", none_total));
            }
            println!(
                "Spans: {} of {} routes — {}.",
                fine_total + shallow_total,
                total_routes,
                parts.join(", ")
            );
        }

        // Boundaries
        let has_boundaries = db_total > 0 || http_total > 0;
        if has_boundaries {
            let mut bound_parts: Vec<String> = Vec::new();
            if db_total > 0 {
                if db_covered == db_total {
                    bound_parts.push(format!("db {}/{}", db_covered, db_total));
                } else {
                    bound_parts.push(format!("db {}/{}", db_covered, db_total));
                }
            }
            if http_total > 0 {
                bound_parts.push(format!("http {}/{}", http_covered, http_total));
            }
            println!("Boundaries: {}.", bound_parts.join(", "));
        }
    }

    println!();
    println!(
        "{}",
        format!(
            "To see the same as an aggregate dashboard: unfault telemetry {} --summary",
            report.target
        )
        .bright_black()
    );
    println!();
}

// ── Rendering: summary (--summary flag for directories) ──────────────────────

fn render_summary(report: &TelemetryReport) {
    println!();
    println!("Telemetry summary, {}", report.target.bright_white().bold());
    println!();

    let total = report.routes.len();
    if total > 0 {
        println!("  Traces by method");
        let reads: Vec<&RouteTelemetry> = report
            .routes
            .iter()
            .filter(|r| !is_write_method(&r.method))
            .collect();
        let writes: Vec<&RouteTelemetry> = report
            .routes
            .iter()
            .filter(|r| is_write_method(&r.method))
            .collect();
        for (routes, label, methods) in [
            (&reads, "read", ""),
            (&writes, "write", "(POST/PUT/PATCH/DELETE)"),
        ] {
            let n = routes.len();
            if n == 0 {
                continue;
            }
            let explicit = routes
                .iter()
                .filter(|r| r.anchor_kind == AnchorKind::Explicit)
                .count();
            let framework = routes
                .iter()
                .filter(|r| r.anchor_kind == AnchorKind::FrameworkAuto)
                .count();
            let unobserved = routes
                .iter()
                .filter(|r| r.anchor_kind == AnchorKind::None)
                .count();
            println!(
                "  {} ({:>3})   explicit attrs {:>3}   framework auto {:>3}   no span {:>3}   {}",
                label,
                n,
                explicit,
                framework,
                unobserved,
                methods.bright_black(),
            );
        }
        println!();
    }

    let structured = report
        .logging
        .iter()
        .filter(|l| l.quality == LoggingQuality::Structured)
        .count();
    let plain = report
        .logging
        .iter()
        .filter(|l| l.quality == LoggingQuality::Plain)
        .count();
    let none = report
        .logging
        .iter()
        .filter(|l| l.quality == LoggingQuality::None_)
        .count();

    println!("  Logging");
    if structured > 0 {
        println!(
            "  structured     {} file{}",
            structured,
            if structured == 1 { "" } else { "s" }
        );
    }
    if plain > 0 {
        println!(
            "  plain          {} file{}",
            plain,
            if plain == 1 { "" } else { "s" }
        );
    }
    if none > 0 {
        println!(
            "  none           {} file{}",
            none,
            if none == 1 { "" } else { "s" }
        );
    }
    println!();

    let has_metrics = report.metrics.iter().any(|m| m.present);
    let absent_count = report.metrics.iter().filter(|m| !m.present).count();
    println!("  Metrics");
    if has_metrics {
        let present_count = report.metrics.iter().filter(|m| m.present).count();
        println!(
            "  present        {} file{}",
            present_count,
            if present_count == 1 { "" } else { "s" }
        );
    }
    if absent_count > 0 {
        println!(
            "  none           {} file{}",
            absent_count,
            if absent_count == 1 { "" } else { "s" }
        );
    }
    println!();
}


// ── Rendering: compact (--compact flag) ───────────────────────────────────────

fn render_compact(report: &TelemetryReport) {
    println!();
    println!(
        "  Telemetry Coverage for {}",
        report.target.bright_white().bold()
    );
    println!();

    for r in &report.routes {
        let quality = match r.anchor_kind {
            AnchorKind::Explicit => "● explicit".green(),
            AnchorKind::FrameworkAuto => "◐ framework".yellow(),
            AnchorKind::None => "○ none".normal(),
        };
        let loc: colored::ColoredString = match r.line {
            Some(l) => format!("  {}:{}", r.file, l).bright_black(),
            None => r.file.bright_black(),
        };
        println!(
            "  {:<8} {}  {}  {}",
            format!("{}{}", r.method.magenta().bold(), ":").dimmed(),
            r.path.bright_yellow(),
            quality,
            loc,
        );
    }

    println!();
    render_boundaries_line(report);
    render_legend();
}

// ── Legend ────────────────────────────────────────────────────────────────────

fn render_legend() {
    println!();
    println!("{}", "  ── Legend ──".bright_black());
    println!(
        "  {}  {}",
        "trace  ● explicit / ◐ framework auto / ○ unobserved".dimmed(),
        "— span kind".bright_black()
    );
    println!(
        "  {}  {}",
        "log    ◉ structured / ○ plain / · none".dimmed(),
        "— quality".bright_black()
    );
    println!();
}

// ── Shared rendering helpers ─────────────────────────────────────────────────

fn render_boundaries_section(report: &TelemetryReport) {
    let b = &report.boundaries;
    let has_boundaries = !b.db.is_empty() || !b.http.is_empty() || !b.remote.is_empty();

    println!("  {}Boundaries{}", "──".cyan(), "──".cyan());
    if !has_boundaries {
        println!("  No downstream calls detected.");
        return;
    }

    render_boundary_group("db queries", &b.db);
    render_boundary_group("http clients", &b.http);
    render_boundary_group("remote calls", &b.remote);
}

fn render_boundary_group(label: &str, sites: &[BoundaryCallSite]) {
    if sites.is_empty() {
        return;
    }
    let total = sites.len();
    let covered = sites.iter().filter(|s| s.anchor_kind != AnchorKind::None).count();
    let pct = (covered as f64 / total as f64 * 100.0) as usize;
    let icon = if pct == 100 { "●".green() } else if pct > 0 { "◐".yellow() } else { "○".normal() };
    let pct_str = format!("{}%", pct);
    let colored_pct = if pct == 100 { pct_str.green() } else if pct >= 50 { pct_str.yellow() } else { pct_str.red() };
    println!("  {}  {:<16} {:>2} / {:>2}  {}", icon, label, covered, total, colored_pct);
}

fn render_boundaries_line(report: &TelemetryReport) {
    let b = &report.boundaries;
    let db_total = b.db.len();
    let db_covered = b.db.iter().filter(|s| s.anchor_kind != AnchorKind::None).count();
    let http_total = b.http.len();
    let http_covered = b.http.iter().filter(|s| s.anchor_kind != AnchorKind::None).count();
    let remote_total = b.remote.len();
    let remote_covered = b.remote.iter().filter(|s| s.anchor_kind != AnchorKind::None).count();
    let parts: Vec<String> = vec![
        format!("db {} / {}", db_covered, db_total),
        format!("http {} / {}", http_covered, http_total),
        format!("remote {} / {}", remote_covered, remote_total),
    ];
    println!("  boundaries:  {}", parts.join("    ").bright_black());
}

fn is_write_method(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH" | "DELETE")
}


fn fmt_count(n: usize, total: usize) -> String {
    if total == 0 {
        "0".to_string()
    } else {
        n.to_string()
    }
}

fn pct(n: usize, total: usize) -> String {
    if total == 0 {
        "0".to_string()
    } else {
        format!("{}", ((n as f64 / total as f64) * 100.0) as usize)
    }
}

// ── SignalKind display ────────────────────────────────────────────────────────

impl SignalKind {
    fn label(&self) -> &'static str {
        match self {
            SignalKind::Trace => "trace",
            SignalKind::Log => "log",
            SignalKind::Metric => "metric",
            SignalKind::Error => "error",
        }
    }

    fn icon_colored(&self) -> colored::ColoredString {
        match self {
            SignalKind::Trace => "◉".green(),
            SignalKind::Log => "≡".cyan(),
            SignalKind::Metric => "⬡".yellow(),
            SignalKind::Error => "✖".red(),
        }
    }
}
