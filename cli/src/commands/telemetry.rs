use anyhow::Result;
use colored::Colorize;

use crate::commands::graph::{
    CoverageContext, CoverageNode, Location, NodeRole, PathHop, SpanSignal, UnobservedPaths,
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

/// Syntactic kind of a callee call site.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalleeKind {
    Function,
    Method,
    Builtin,
    Construct,
}

/// SQL-level statement kind inferred from the call expression.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementKind {
    Select,
    Insert,
    Update,
    Delete,
    Commit,
    Rollback,
    Raw,
    Other,
}

/// Per-route logging signal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteLogs {
    pub kind: LoggingQuality,
    pub library: Option<String>,
}

/// Per-route metrics signal.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteMetrics {
    pub present: bool,
    pub library: Option<String>,
}

/// A single callee in the route's call tree.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CalleeInfo {
    pub name: String,
    pub location: Location,
    pub role: NodeRole,
    /// Syntactic kind of the call site.
    pub kind: CalleeKind,
    /// How deep from the handler (1 = direct callee).
    pub depth: i32,
    pub anchor_kind: AnchorKind,
    /// Attributes/span-name when anchor_kind is explicit; empty array otherwise.
    #[serde(default)]
    pub anchor_attributes: Vec<String>,
    /// Call chain from the route handler down to (but not including) this
    /// callee. `via.len() == depth - 1` invariantly: depth 1 callees are
    /// reached directly from the handler, so `via` is empty; depth 2 has
    /// one intermediate; etc. Each hop carries `name` and `location` so an
    /// agent can verify reachability without re-walking the graph.
    ///
    /// Added to address the multi-route attribution confusion observed on
    /// hopper-backend (v1.0.55): the same callee appearing under several
    /// routes is correct substrate when those routes genuinely share
    /// downstream helpers, and `via` makes the chain explicit so the agent
    /// (or human) can confirm — vs. the prior output where the boundary
    /// said `in_function: serve_attachment` without any path, looking like
    /// a misattribution bug.
    #[serde(default)]
    pub via: Vec<PathHop>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RouteTelemetry {
    pub method: String,
    pub path: String,
    pub handler: String,
    pub location: Location,
    pub anchor_kind: AnchorKind,
    /// Attributes/span-name when anchor_kind is explicit; empty array otherwise.
    #[serde(default)]
    pub anchor_attributes: Vec<String>,
    /// Counts excluding builtins and constructors.
    pub total_callees: usize,
    pub instrumented_callees: usize,
    pub callees: Vec<CalleeInfo>,
    pub unobserved: UnobservedPaths,
    pub logs: RouteLogs,
    pub metrics: RouteMetrics,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileLogging {
    pub file: String,
    /// Logging signal kind for this file. Field is named `kind` for vocabulary
    /// consistency with `RouteLogs::kind` and `CalleeInfo::kind`. The internal
    /// Rust field stays `quality` to avoid churning all call sites; the
    /// serialized JSON name is what the contract specifies.
    #[serde(rename = "kind")]
    pub quality: LoggingQuality,
    pub library: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileMetrics {
    pub file: String,
    pub present: bool,
    pub library: Option<String>,
}

/// A logging cluster — files grouped by path prefix with quality breakdown.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggingCluster {
    pub path_prefix: String,
    pub file_count: usize,
    pub quality_breakdown: LoggingBreakdown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggingBreakdown {
    pub structured: usize,
    pub plain: usize,
    pub none: usize,
}

/// Logging section: flat file list + clusters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoggingSection {
    pub files: Vec<FileLogging>,
    pub clusters: Vec<LoggingCluster>,
}

/// Metrics cluster.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsCluster {
    pub path_prefix: String,
    pub file_count: usize,
    pub present_count: usize,
}

/// Metrics section: flat file list + clusters.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MetricsSection {
    pub files: Vec<FileMetrics>,
    pub clusters: Vec<MetricsCluster>,
}

/// A single boundary call site.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BoundaryCallSite {
    pub name: String,
    pub kind: CalleeKind,
    pub location: Location,
    /// The route that ultimately reaches this boundary, formatted as
    /// `"METHOD /path"` (e.g. `"POST /sites/{site_id}/publish"`).
    pub in_route: String,
    /// The route HANDLER function name (not the immediate enclosing
    /// function of the call site). Kept for backwards compatibility;
    /// use `via` to see the actual call chain when these differ.
    pub in_function: String,
    pub anchor_kind: AnchorKind,
    #[serde(default)]
    pub anchor_attributes: Vec<String>,
    /// SQL verb for db entries; HTTP method for http entries; null for remote.
    pub statement_kind: Option<StatementKind>,
    /// Call chain from the route handler down to (but not including) this
    /// boundary call site. Empty when the boundary is called directly from
    /// the handler. Each hop carries `name` and `location` so an agent can
    /// verify reachability without re-walking the graph.
    ///
    /// When the same boundary appears under several different routes, this
    /// field is what lets the agent confirm whether the substrate is
    /// correct (routes legitimately share a downstream helper) or whether
    /// further investigation is needed.
    #[serde(default)]
    pub via: Vec<PathHop>,
}

/// Corpus counts (derived from routes + logging).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Corpus {
    pub files: usize,
    pub routes_total: usize,
    pub routes_read: usize,
    pub routes_write: usize,
}

/// Flat aggregator of boundary call sites, always present even when empty.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Boundaries {
    #[serde(default)]
    pub db: Vec<BoundaryCallSite>,
    #[serde(default)]
    pub http: Vec<BoundaryCallSite>,
    #[serde(default)]
    pub remote: Vec<BoundaryCallSite>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TelemetryReport {
    pub target: String,
    pub target_kind: String,
    pub corpus: Corpus,
    pub routes: Vec<RouteTelemetry>,
    pub logging: LoggingSection,
    pub metrics: MetricsSection,
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
            // Dedup key is intentionally `(method, path, handler)` and NOT
            // `(method, path)`. When the same (method, path) is registered to
            // multiple handlers — class-based views, blueprint collisions,
            // multiple `app.add_url_rule` calls — every distinct handler is a
            // separate substrate fact and must surface. Collapsing them by
            // `(method, path)` alone would erase information the agent needs.
            // The same `(method, path, handler)` triple from two file_path
            // iterations IS deduped here, which is what we want.
            if routes.iter().any(|r: &RouteTelemetry| {
                r.method == *method && r.path == *path && r.handler == *handler
            }) {
                continue;
            }
            if let Some(rt) = analyze_single_route(graph, path, Some(method), verbose) {
                routes.push(RouteTelemetry {
                    method: method.clone(),
                    path: path.clone(),
                    handler: handler.clone(),
                    location: Location::new(file_path.clone(), *line),
                    anchor_kind: rt.anchor_kind,
                    anchor_attributes: rt.anchor_attributes,
                    total_callees: rt.total_callees,
                    instrumented_callees: rt.instrumented_callees,
                    callees: rt.callees,
                    unobserved: rt.unobserved,
                    logs: RouteLogs {
                        kind: fl.quality.clone(),
                        library: if fl.library.is_empty() {
                            None
                        } else {
                            Some(fl.library.clone())
                        },
                    },
                    metrics: RouteMetrics {
                        present: fm.present,
                        library: fm.library.clone(),
                    },
                });
            }
        }
    }

    let logging_files: Vec<FileLogging> = files
        .iter()
        .map(|f| file_logging_quality(graph, f))
        .collect();
    let metrics_files: Vec<FileMetrics> = files.iter().map(|f| file_metrics(graph, f)).collect();
    let boundaries = build_boundaries(&routes);

    let corpus = Corpus {
        files: logging_files.len(),
        routes_total: routes.len(),
        routes_read: routes
            .iter()
            .filter(|r| !is_write_method(&r.method))
            .count(),
        routes_write: routes.iter().filter(|r| is_write_method(&r.method)).count(),
    };

    Some(TelemetryReport {
        target: target.to_string(),
        target_kind: kind.to_string(),
        corpus,
        routes,
        logging: build_logging_section(logging_files),
        metrics: build_metrics_section(metrics_files),
        boundaries,
    })
}

// ── Analysis: single route / function ─────────────────────────────────────────

struct RouteTraversal {
    anchor_kind: AnchorKind,
    anchor_attributes: Vec<String>,
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
        location: Location::new(anchor_file.clone(), ctx.anchor.line),
        anchor_kind: rt.anchor_kind,
        anchor_attributes: rt.anchor_attributes,
        total_callees: rt.total_callees,
        instrumented_callees: rt.instrumented_callees,
        callees: rt.callees,
        unobserved: rt.unobserved,
        logs: RouteLogs {
            kind: fl.quality,
            library: if fl.library.is_empty() {
                None
            } else {
                Some(fl.library)
            },
        },
        metrics: RouteMetrics {
            present: fm.present,
            library: fm.library,
        },
    }];
    let logging_file = file_logging_quality(graph, &anchor_file);
    let metrics_file = file_metrics(graph, &anchor_file);
    let corpus = Corpus {
        files: 1,
        routes_total: routes_vec.len(),
        routes_read: routes_vec
            .iter()
            .filter(|r| !is_write_method(&r.method))
            .count(),
        routes_write: routes_vec
            .iter()
            .filter(|r| is_write_method(&r.method))
            .count(),
    };
    let report = TelemetryReport {
        target: format!("{} {}", ctx.anchor.role.method_str().unwrap_or(""), path)
            .trim()
            .to_string(),
        target_kind: "module".to_string(),
        corpus,
        logging: build_logging_section(vec![logging_file]),
        metrics: build_metrics_section(vec![metrics_file]),
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
        location: Location::new(anchor_file.clone(), ctx.anchor.line),
        anchor_kind: rt.anchor_kind,
        anchor_attributes: rt.anchor_attributes,
        total_callees: rt.total_callees,
        instrumented_callees: rt.instrumented_callees,
        callees: rt.callees,
        unobserved: rt.unobserved,
        logs: RouteLogs {
            kind: fl.quality,
            library: if fl.library.is_empty() {
                None
            } else {
                Some(fl.library)
            },
        },
        metrics: RouteMetrics {
            present: fm.present,
            library: fm.library,
        },
    }];
    let logging_file = file_logging_quality(graph, &anchor_file);
    let metrics_file = file_metrics(graph, &anchor_file);
    let corpus = Corpus {
        files: 1,
        routes_total: routes_vec.len(),
        routes_read: routes_vec
            .iter()
            .filter(|r| !is_write_method(&r.method))
            .count(),
        routes_write: routes_vec
            .iter()
            .filter(|r| is_write_method(&r.method))
            .count(),
    };
    let report = TelemetryReport {
        target: name.to_string(),
        target_kind: "module".to_string(),
        corpus,
        logging: build_logging_section(vec![logging_file]),
        metrics: build_metrics_section(vec![metrics_file]),
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
    let anchor_file = ctx.anchor.file.clone();
    // Walk the call tree with full path context so each callee can carry
    // its chain from the route handler. `via` lets agents verify
    // reachability without re-walking the graph and makes shared-helper
    // attribution across routes auditable.
    let mut all_nodes: Vec<(&CoverageNode, Vec<PathHop>)> = Vec::new();
    let mut path_buf: Vec<PathHop> = Vec::new();
    collect_nodes_with_path(&ctx.anchor, &mut path_buf, &mut all_nodes);
    for c in &ctx.callers {
        path_buf.clear();
        collect_nodes_with_path(c, &mut path_buf, &mut all_nodes);
    }

    // Build flat callee list (exclude anchor itself).
    // Builtins and constructors are tagged but excluded from counts.
    let callees: Vec<CalleeInfo> = all_nodes
        .iter()
        .filter(|(n, _)| n.depth != 0)
        .map(|(n, via)| {
            let ck = callee_kind_from_name(&n.name);
            // Fall back to anchor file when callee has no file resolved.
            let file = if n.file.is_empty() {
                anchor_file.clone()
            } else {
                n.file.clone()
            };
            CalleeInfo {
                name: n.name.clone(),
                location: Location::new(file, n.line),
                role: n.role.clone(),
                kind: ck,
                depth: n.depth,
                anchor_kind: span_to_anchor_kind(&n.span),
                anchor_attributes: span_to_attributes(&n.span),
                via: via.clone(),
            }
        })
        .collect();

    // Counts exclude builtins and constructors.
    let countable: Vec<&CalleeInfo> = callees
        .iter()
        .filter(|c| matches!(c.kind, CalleeKind::Function | CalleeKind::Method))
        .collect();
    let total_callees = countable.len();
    let instrumented_callees = countable
        .iter()
        .filter(|c| c.anchor_kind != AnchorKind::None)
        .count();

    RouteTraversal {
        anchor_kind: span_to_anchor_kind(&ctx.anchor.span),
        anchor_attributes: span_to_attributes(&ctx.anchor.span),
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

fn span_to_attributes(span: &SpanSignal) -> Vec<String> {
    match span {
        SpanSignal::Decorator { name: Some(n), .. } => vec![n.clone()],
        SpanSignal::SdkImported { library, .. } => vec![library.clone()],
        _ => vec![],
    }
}

fn callee_kind_from_name(name: &str) -> CalleeKind {
    // Capitalised first letter → constructor or type reference.
    if name
        .chars()
        .next()
        .map(|c| c.is_uppercase())
        .unwrap_or(false)
    {
        return CalleeKind::Construct;
    }
    // Known Python/JS builtins.
    const BUILTINS: &[&str] = &[
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
        "console",
        "promise",
        "object",
        "array",
        "json",
    ];
    if BUILTINS.contains(&name.to_lowercase().as_str()) {
        return CalleeKind::Builtin;
    }
    // Dot-notation → method call.
    if name.contains('.') {
        return CalleeKind::Method;
    }
    CalleeKind::Function
}

fn infer_http_method_kind(call_expr: &str) -> Option<StatementKind> {
    let last = call_expr
        .split('.')
        .last()
        .unwrap_or(call_expr)
        .to_lowercase();
    match last.as_str() {
        "get" | "head" | "options" => Some(StatementKind::Select),
        "post" => Some(StatementKind::Insert),
        "put" | "patch" => Some(StatementKind::Update),
        "delete" => Some(StatementKind::Delete),
        _ => None,
    }
}

/// Map a database / ORM call expression to a `StatementKind`.
///
/// Classification rules (case-insensitive on the final method segment):
///
/// **Select (read):**
///   `select`, `scalar`, `scalars`, `scalar_one`, `scalar_one_or_none`,
///   `fetchall`, `fetchone`, `fetchmany`, `all`, `first`, `one`,
///   `one_or_none`, `get`, `query`, `filter`, `filter_by`, `count`,
///   `exists`, `refresh`
///
/// **Insert:** `insert`, `add`, `add_all`, `bulk_insert_mappings`,
///   `bulk_save_objects`, `create` (Django `objects.create`)
///
/// **Update:** `update`, `bulk_update_mappings`, `merge` (SQLAlchemy
///   upsert — semantically update), `save` (Django/peewee instance save;
///   classification leans update because most `.save()` calls in route
///   bodies are mutations of an already-loaded instance)
///
/// **Delete:** `delete`, `remove`
///
/// **Commit/Rollback:** `commit`, `flush`, `rollback`
///
/// **Raw:** `execute`, `exec`, `executemany`, `raw`, `text`
///
/// **Django `.objects.X` short-circuit:** when the expression contains
/// `.objects.`, the queryset method is classified directly without
/// receiver heuristics (e.g. `User.objects.create` → insert).
///
/// Anything not recognised falls back to `Other`. This is intentionally
/// conservative — the receiver heuristic in `is_db_call_expr` is what
/// guarantees we only get here for genuine db calls, so reaching `Other`
/// usually means we encountered a less common method name. Audit the
/// telemetry output for `statement_kind: "other"` to find candidates
/// for this list.
fn infer_statement_kind(call_expr: &str) -> StatementKind {
    let lower = call_expr.to_lowercase();
    let last = lower.split('.').last().unwrap_or(lower.as_str());

    // Django queryset short-circuit: `.objects.<method>` is unambiguous.
    // (`is_db_call_expr` flags anything with `.objects.` as database.)
    if lower.contains(".objects.") {
        return match last {
            "get" | "filter" | "exclude" | "all" | "first" | "last" | "count" | "exists"
            | "values" | "values_list" | "select_related" | "prefetch_related" | "annotate"
            | "aggregate" | "earliest" | "latest" | "in_bulk" | "raw" | "only" | "defer" => {
                StatementKind::Select
            }
            "create" | "get_or_create" | "bulk_create" => StatementKind::Insert,
            "update" | "update_or_create" | "bulk_update" => StatementKind::Update,
            "delete" => StatementKind::Delete,
            _ => StatementKind::Other,
        };
    }

    match last {
        // ── Read ───────────────────────────────────────────────────────────
        "select" | "scalar" | "scalars" | "scalar_one" | "scalar_one_or_none" | "fetchall"
        | "fetchone" | "fetchmany" | "all" | "first" | "one" | "one_or_none" | "get" | "query"
        | "filter" | "filter_by" | "count" | "exists" | "refresh" => StatementKind::Select,

        // ── Insert ─────────────────────────────────────────────────────────
        "insert" | "add" | "add_all" | "bulk_insert_mappings" | "bulk_save_objects" | "create" => {
            StatementKind::Insert
        }

        // ── Update ─────────────────────────────────────────────────────────
        // `merge` is SQLAlchemy's upsert. `save` is ambiguous but most often
        // updates an already-loaded instance in route handler context.
        "update" | "bulk_update_mappings" | "merge" | "save" => StatementKind::Update,

        // ── Delete ─────────────────────────────────────────────────────────
        "delete" | "remove" => StatementKind::Delete,

        // ── Transaction control ────────────────────────────────────────────
        "commit" | "flush" => StatementKind::Commit,
        "rollback" => StatementKind::Rollback,

        // ── Raw SQL ────────────────────────────────────────────────────────
        "execute" | "exec" | "executemany" | "raw" | "text" => StatementKind::Raw,

        _ => StatementKind::Other,
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
            let kind = match callee.name.contains('.') {
                true => CalleeKind::Method,
                false => CalleeKind::Function,
            };
            let site = BoundaryCallSite {
                name: callee.name.clone(),
                kind,
                location: callee.location.clone(),
                in_route: route_label.clone(),
                in_function: route.handler.clone(),
                anchor_kind: callee.anchor_kind.clone(),
                anchor_attributes: callee.anchor_attributes.clone(),
                statement_kind: None, // filled below for db
                via: callee.via.clone(),
            };
            match &callee.role {
                NodeRole::Database => {
                    let mut s = site;
                    s.statement_kind = Some(infer_statement_kind(&callee.name));
                    db.push(s);
                }
                NodeRole::HttpClient => {
                    // Infer HTTP method from call expression (e.g. "requests.get" → Select-like).
                    // We map HTTP verbs to statement_kind for consistency.
                    let mut s = site;
                    s.statement_kind = infer_http_method_kind(&callee.name);
                    http.push(s);
                }
                NodeRole::RemoteCall { .. } => remote.push(site),
                _ => {}
            }
        }
    }

    Boundaries { db, http, remote }
}

/// Compute logging section with path-prefix clusters.
fn build_logging_section(files: Vec<FileLogging>) -> LoggingSection {
    let clusters = compute_logging_clusters(&files, 5);
    LoggingSection { files, clusters }
}

fn compute_logging_clusters(files: &[FileLogging], min_size: usize) -> Vec<LoggingCluster> {
    let mut prefix_map: std::collections::HashMap<String, Vec<&FileLogging>> =
        std::collections::HashMap::new();
    for f in files {
        let prefix = std::path::Path::new(&f.file)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        if !prefix.is_empty() {
            prefix_map.entry(prefix).or_default().push(f);
        }
    }
    let mut clusters: Vec<LoggingCluster> = prefix_map
        .into_iter()
        .filter(|(_, v)| v.len() >= min_size)
        .map(|(prefix, entries)| {
            let structured = entries
                .iter()
                .filter(|e| e.quality == LoggingQuality::Structured)
                .count();
            let plain = entries
                .iter()
                .filter(|e| e.quality == LoggingQuality::Plain)
                .count();
            let none = entries
                .iter()
                .filter(|e| e.quality == LoggingQuality::None_)
                .count();
            LoggingCluster {
                path_prefix: prefix,
                file_count: entries.len(),
                quality_breakdown: LoggingBreakdown {
                    structured,
                    plain,
                    none,
                },
            }
        })
        .collect();
    clusters.sort_by(|a, b| b.file_count.cmp(&a.file_count));
    clusters
}

/// Compute metrics section with path-prefix clusters.
fn build_metrics_section(files: Vec<FileMetrics>) -> MetricsSection {
    let clusters = compute_metrics_clusters(&files, 5);
    MetricsSection { files, clusters }
}

fn compute_metrics_clusters(files: &[FileMetrics], min_size: usize) -> Vec<MetricsCluster> {
    let mut prefix_map: std::collections::HashMap<String, Vec<&FileMetrics>> =
        std::collections::HashMap::new();
    for f in files {
        let prefix = std::path::Path::new(&f.file)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        if !prefix.is_empty() {
            prefix_map.entry(prefix).or_default().push(f);
        }
    }
    let mut clusters: Vec<MetricsCluster> = prefix_map
        .into_iter()
        .filter(|(_, v)| v.len() >= min_size)
        .map(|(prefix, entries)| {
            let present_count = entries.iter().filter(|e| e.present).count();
            MetricsCluster {
                path_prefix: prefix,
                file_count: entries.len(),
                present_count,
            }
        })
        .collect();
    clusters.sort_by(|a, b| b.file_count.cmp(&a.file_count));
    clusters
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

/// Recursively flatten a coverage subtree while recording the chain of
/// parents from the root down to (but not including) each visited node.
/// Used to build `CalleeInfo.via` so every callee carries a verifiable
/// path from the route handler.
///
/// The root node is emitted with an empty path; each descendant gets the
/// concatenation of its ancestors' `(name, location)` pairs.
fn collect_nodes_with_path<'a>(
    node: &'a CoverageNode,
    path: &mut Vec<PathHop>,
    out: &mut Vec<(&'a CoverageNode, Vec<PathHop>)>,
) {
    out.push((node, path.clone()));
    path.push(PathHop {
        name: node.name.clone(),
        location: Location::new(node.file.clone(), node.line),
    });
    for child in &node.children {
        collect_nodes_with_path(child, path, out);
    }
    path.pop();
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
            let loc = match r.location.line {
                Some(l) => format!("{}:{}", r.location.file, l).bright_black(),
                None => r.location.file.bright_black(),
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
        .files
        .iter()
        .filter(|l| l.quality == LoggingQuality::Structured)
        .count();
    let plain = report
        .logging
        .files
        .iter()
        .filter(|l| l.quality == LoggingQuality::Plain)
        .count();
    let none = report
        .logging
        .files
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
        for fl in &report.logging.files {
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
    let has_metrics = report.metrics.files.iter().any(|m| m.present);
    let present_count = report.metrics.files.iter().filter(|m| m.present).count();
    let absent_count = report.metrics.files.iter().filter(|m| !m.present).count();
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
        for m in &report.metrics.files {
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
        let loc_str = match r.location.line {
            Some(l) => format!("{}:{}", r.location.file, l),
            None => r.location.file.clone(),
        };
        if !loc_str.is_empty() {
            println!("  {}  {}", "at".bright_black(), loc_str.bright_black());
        }

        let trace_str = match r.anchor_kind {
            AnchorKind::Explicit => "● explicit".green(),
            AnchorKind::FrameworkAuto => "◐ framework auto".yellow(),
            AnchorKind::None => "○ unobserved".normal(),
        };
        println!("\n  trace: {}", trace_str);
    }

    // Show which routes reach this function (if function target)
    if report.target_kind == "module" && report.routes.len() <= 1 {
        // The callers info is inside the CoverageContext — but we don't have it here
        // because we only stored the aggregate.  For now, boundaries are the key signal.
    }

    // Logging
    if let Some(r) = report.routes.first() {
        let quality_str = match r.logs.kind {
            LoggingQuality::Structured => format!("{} structured", "◉".green()),
            LoggingQuality::Plain => format!("{} plain", "○".normal()),
            LoggingQuality::None_ => format!("{} none", "·".dimmed()),
        };
        let lib_str = r
            .logs
            .library
            .as_deref()
            .map(|l| format!("  ({})", l.bright_black()))
            .unwrap_or_default();
        println!("  logging: {}{}", quality_str, lib_str);

        // Metrics
        let metrics_status = if r.metrics.present {
            format!(
                "{} {}",
                "◉".green(),
                r.metrics.library.as_deref().unwrap_or("present").green()
            )
        } else {
            format!("{} {}", "○".normal(), "none".normal())
        };
        println!("  metrics: {}", metrics_status);
    }

    println!();
    render_boundaries_section(report);
    render_legend();
}

// ── Rendering: catalog (new default for directories) ─────────────────────────

fn render_catalog(report: &TelemetryReport) {
    let total_files = report.corpus.files;
    let total_routes = report.corpus.routes_total;
    let reads = report.corpus.routes_read;
    let writes = report.corpus.routes_write;
    let log_structured = report
        .logging
        .files
        .iter()
        .filter(|l| l.quality == LoggingQuality::Structured)
        .count();
    let log_plain = report
        .logging
        .files
        .iter()
        .filter(|l| l.quality == LoggingQuality::Plain)
        .count();
    let log_none_count = report
        .logging
        .files
        .iter()
        .filter(|l| l.quality == LoggingQuality::None_)
        .count();
    let metrics_present = report.metrics.files.iter().filter(|m| m.present).count();
    let metrics_total = report.metrics.files.len();
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
    let db_covered = report
        .boundaries
        .db
        .iter()
        .filter(|s| s.anchor_kind != AnchorKind::None)
        .count();
    let http_total = report.boundaries.http.len();
    let http_covered = report
        .boundaries
        .http
        .iter()
        .filter(|s| s.anchor_kind != AnchorKind::None)
        .count();

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
                parts.push(format!("{} fine (explicit attributes)", fine_total));
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
        .files
        .iter()
        .filter(|l| l.quality == LoggingQuality::Structured)
        .count();
    let plain = report
        .logging
        .files
        .iter()
        .filter(|l| l.quality == LoggingQuality::Plain)
        .count();
    let none = report
        .logging
        .files
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

    let has_metrics = report.metrics.files.iter().any(|m| m.present);
    let absent_count = report.metrics.files.iter().filter(|m| !m.present).count();
    println!("  Metrics");
    if has_metrics {
        let present_count = report.metrics.files.iter().filter(|m| m.present).count();
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
        let loc: colored::ColoredString = match r.location.line {
            Some(l) => format!("  {}:{}", r.location.file, l).bright_black(),
            None => r.location.file.as_str().bright_black(),
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
    let covered = sites
        .iter()
        .filter(|s| s.anchor_kind != AnchorKind::None)
        .count();
    let pct = (covered as f64 / total as f64 * 100.0) as usize;
    let icon = if pct == 100 {
        "●".green()
    } else if pct > 0 {
        "◐".yellow()
    } else {
        "○".normal()
    };
    let pct_str = format!("{}%", pct);
    let colored_pct = if pct == 100 {
        pct_str.green()
    } else if pct >= 50 {
        pct_str.yellow()
    } else {
        pct_str.red()
    };
    println!(
        "  {}  {:<16} {:>2} / {:>2}  {}",
        icon, label, covered, total, colored_pct
    );
}

fn render_boundaries_line(report: &TelemetryReport) {
    let b = &report.boundaries;
    let db_total = b.db.len();
    let db_covered =
        b.db.iter()
            .filter(|s| s.anchor_kind != AnchorKind::None)
            .count();
    let http_total = b.http.len();
    let http_covered = b
        .http
        .iter()
        .filter(|s| s.anchor_kind != AnchorKind::None)
        .count();
    let remote_total = b.remote.len();
    let remote_covered = b
        .remote
        .iter()
        .filter(|s| s.anchor_kind != AnchorKind::None)
        .count();
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── infer_statement_kind ─────────────────────────────────────────────────
    //
    // Regression: hopper-backend reported `db_session.get` (and several other
    // common ORM read methods) as `statement_kind: "other"`. The old matcher
    // only knew `select`/`scalars`/`fetchall`-style methods. The agent's
    // first-pass classification was less informative than it could be.

    #[test]
    fn statement_kind_sqlalchemy_session_get_is_select() {
        assert_eq!(
            infer_statement_kind("db_session.get"),
            StatementKind::Select
        );
        assert_eq!(infer_statement_kind("session.get"), StatementKind::Select);
        assert_eq!(
            infer_statement_kind("self.db_session.get"),
            StatementKind::Select
        );
    }

    #[test]
    fn statement_kind_sqlalchemy_query_chain_is_select() {
        assert_eq!(infer_statement_kind("session.query"), StatementKind::Select);
        assert_eq!(
            infer_statement_kind("session.filter"),
            StatementKind::Select
        );
        assert_eq!(
            infer_statement_kind("session.filter_by"),
            StatementKind::Select
        );
        assert_eq!(infer_statement_kind("session.count"), StatementKind::Select);
        assert_eq!(
            infer_statement_kind("session.exists"),
            StatementKind::Select
        );
    }

    #[test]
    fn statement_kind_sqlalchemy_writes() {
        assert_eq!(infer_statement_kind("session.add"), StatementKind::Insert);
        assert_eq!(
            infer_statement_kind("session.add_all"),
            StatementKind::Insert
        );
        assert_eq!(
            infer_statement_kind("session.bulk_save_objects"),
            StatementKind::Insert
        );
        // merge is upsert — classified as update.
        assert_eq!(infer_statement_kind("session.merge"), StatementKind::Update);
        assert_eq!(
            infer_statement_kind("session.delete"),
            StatementKind::Delete
        );
    }

    #[test]
    fn statement_kind_transaction_control() {
        assert_eq!(
            infer_statement_kind("db_session.commit"),
            StatementKind::Commit
        );
        assert_eq!(infer_statement_kind("session.flush"), StatementKind::Commit);
        assert_eq!(
            infer_statement_kind("session.rollback"),
            StatementKind::Rollback
        );
    }

    #[test]
    fn statement_kind_raw_sql() {
        assert_eq!(infer_statement_kind("session.execute"), StatementKind::Raw);
        assert_eq!(infer_statement_kind("conn.executemany"), StatementKind::Raw);
        assert_eq!(infer_statement_kind("text"), StatementKind::Raw);
        assert_eq!(infer_statement_kind("cursor.exec"), StatementKind::Raw);
    }

    #[test]
    fn statement_kind_django_queryset_methods() {
        // `.objects.X` short-circuit: classification is by queryset method.
        assert_eq!(
            infer_statement_kind("User.objects.get"),
            StatementKind::Select
        );
        assert_eq!(
            infer_statement_kind("User.objects.filter"),
            StatementKind::Select
        );
        assert_eq!(
            infer_statement_kind("User.objects.all"),
            StatementKind::Select
        );
        assert_eq!(
            infer_statement_kind("User.objects.first"),
            StatementKind::Select
        );
        assert_eq!(
            infer_statement_kind("User.objects.exists"),
            StatementKind::Select
        );
        assert_eq!(
            infer_statement_kind("User.objects.count"),
            StatementKind::Select
        );

        assert_eq!(
            infer_statement_kind("User.objects.create"),
            StatementKind::Insert
        );
        assert_eq!(
            infer_statement_kind("User.objects.bulk_create"),
            StatementKind::Insert
        );
        assert_eq!(
            infer_statement_kind("User.objects.get_or_create"),
            StatementKind::Insert
        );

        assert_eq!(
            infer_statement_kind("User.objects.update"),
            StatementKind::Update
        );
        assert_eq!(
            infer_statement_kind("User.objects.bulk_update"),
            StatementKind::Update
        );
        assert_eq!(
            infer_statement_kind("User.objects.delete"),
            StatementKind::Delete
        );
    }

    #[test]
    fn statement_kind_django_instance_save_classified_as_update() {
        // `.save()` on an instance most often updates an already-loaded row.
        // This is a deliberate lean — the alternative is `Other` which is
        // less informative.
        assert_eq!(infer_statement_kind("user.save"), StatementKind::Update);
    }

    #[test]
    fn statement_kind_sqlalchemy_core_standalone() {
        assert_eq!(infer_statement_kind("select"), StatementKind::Select);
        assert_eq!(infer_statement_kind("insert"), StatementKind::Insert);
        assert_eq!(infer_statement_kind("update"), StatementKind::Update);
        assert_eq!(infer_statement_kind("delete"), StatementKind::Delete);
    }

    #[test]
    fn statement_kind_unknown_falls_back_to_other() {
        assert_eq!(
            infer_statement_kind("session.some_custom_method"),
            StatementKind::Other
        );
        assert_eq!(infer_statement_kind(""), StatementKind::Other);
    }

    #[test]
    fn statement_kind_case_insensitive() {
        assert_eq!(
            infer_statement_kind("Session.COMMIT"),
            StatementKind::Commit
        );
        assert_eq!(
            infer_statement_kind("DB_Session.Get"),
            StatementKind::Select
        );
    }

    // ── collect_nodes_with_path ──────────────────────────────────────────────
    //
    // Regression: `BoundaryCallSite.in_function` was set to the route
    // handler name, not the immediate enclosing function of the call site.
    // When the same boundary appeared under several routes, the agent had
    // no way to tell whether attribution was correct (routes legitimately
    // share helpers) or a bug. `via` carries the chain from the handler so
    // the agent can audit the path themselves.

    fn make_node(
        name: &str,
        file: &str,
        line: Option<u32>,
        depth: i32,
        children: Vec<CoverageNode>,
    ) -> CoverageNode {
        CoverageNode {
            name: name.to_string(),
            file: file.to_string(),
            line,
            depth,
            direction: "down".to_string(),
            span: SpanSignal::None,
            role: NodeRole::Logic,
            children,
        }
    }

    #[test]
    fn collect_nodes_with_path_empty_for_root() {
        // Root node always has an empty path: nothing is upstream of it.
        let root = make_node("handler", "app.py", Some(1), 0, vec![]);
        let mut path = Vec::new();
        let mut out = Vec::new();
        collect_nodes_with_path(&root, &mut path, &mut out);

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.name, "handler");
        assert!(
            out[0].1.is_empty(),
            "root node must have empty via, got {:?}",
            out[0].1
        );
    }

    #[test]
    fn collect_nodes_with_path_records_ancestors() {
        // handler → service → helper → db_session.commit
        let tree = make_node(
            "handler",
            "app.py",
            Some(10),
            0,
            vec![make_node(
                "service",
                "service.py",
                Some(20),
                1,
                vec![make_node(
                    "helper",
                    "helper.py",
                    Some(30),
                    2,
                    vec![make_node(
                        "db_session.commit",
                        "helper.py",
                        Some(35),
                        3,
                        vec![],
                    )],
                )],
            )],
        );

        let mut path = Vec::new();
        let mut out = Vec::new();
        collect_nodes_with_path(&tree, &mut path, &mut out);

        // Four nodes, each carrying its depth-many ancestors.
        assert_eq!(out.len(), 4);

        // handler: depth 0, empty path
        assert_eq!(out[0].0.name, "handler");
        assert!(out[0].1.is_empty());

        // service: depth 1, path = [handler]
        assert_eq!(out[1].0.name, "service");
        assert_eq!(out[1].1.len(), 1);
        assert_eq!(out[1].1[0].name, "handler");

        // helper: depth 2, path = [handler, service]
        assert_eq!(out[2].0.name, "helper");
        assert_eq!(out[2].1.len(), 2);
        assert_eq!(out[2].1[0].name, "handler");
        assert_eq!(out[2].1[1].name, "service");

        // db_session.commit: depth 3, path = [handler, service, helper]
        assert_eq!(out[3].0.name, "db_session.commit");
        assert_eq!(out[3].1.len(), 3);
        assert_eq!(out[3].1[0].name, "handler");
        assert_eq!(out[3].1[1].name, "service");
        assert_eq!(out[3].1[2].name, "helper");
    }

    #[test]
    fn collect_nodes_with_path_invariant_via_len_equals_depth() {
        // Invariant: for any callee, via.len() == depth.
        // (Root has depth 0 and empty via; the documented contract on
        // `CalleeInfo.via` says via.len() == depth - 1 for non-root callees,
        // which is the same thing once you exclude the root from the filter.)
        let tree = make_node(
            "h",
            "f.py",
            Some(1),
            0,
            vec![make_node(
                "a",
                "f.py",
                Some(2),
                1,
                vec![make_node("b", "f.py", Some(3), 2, vec![])],
            )],
        );

        let mut path = Vec::new();
        let mut out = Vec::new();
        collect_nodes_with_path(&tree, &mut path, &mut out);

        for (node, via) in &out {
            assert_eq!(
                via.len() as i32,
                node.depth,
                "via.len() must equal depth for {}, got {} != {}",
                node.name,
                via.len(),
                node.depth,
            );
        }
    }

    #[test]
    fn collect_nodes_with_path_locations_preserved() {
        // Each hop must carry the parent's file and line so an agent can
        // open the file at the right spot.
        let tree = make_node(
            "outer",
            "outer.py",
            Some(100),
            0,
            vec![make_node("inner", "inner.py", Some(200), 1, vec![])],
        );

        let mut path = Vec::new();
        let mut out = Vec::new();
        collect_nodes_with_path(&tree, &mut path, &mut out);

        let inner_via = &out[1].1;
        assert_eq!(inner_via.len(), 1);
        assert_eq!(inner_via[0].name, "outer");
        assert_eq!(inner_via[0].location.file, "outer.py");
        assert_eq!(inner_via[0].location.line, Some(100));
    }
}
