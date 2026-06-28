//! # Fault Injection Command
//!
//! Generates `fault run` commands (https://fault-project.com) for injecting
//! network-level failure scenarios against HTTP endpoints reachable from a
//! given function.
//!
//! ## Usage
//!
//! ```bash
//! # List all templates for an endpoint reachable from a function
//! unfault fault services/orders.py:validate_order
//!
//! # Generate a specific template
//! unfault fault services/orders.py:validate_order --template latency-normal
//!
//! # Egress mode: inject faults on outbound calls made by the function
//! unfault fault services/orders.py:validate_order --template blackhole --mode egress --url https://payments.example.com
//!
//! # Override local app URL and proxy port
//! unfault fault services/orders.py:validate_order --template mobile-3g --url http://127.0.0.1:8080 --port 9090
//! ```

use anyhow::Result;
use colored::Colorize;

use crate::exit_codes::*;

// ─────────────────────────────────────────────────────────────────────────────
// Egress target
// ─────────────────────────────────────────────────────────────────────────────

/// An outbound dependency discovered by walking the call graph forward from
/// the target function.
#[derive(Debug, Clone)]
pub struct EgressTarget {
    /// Human-readable label, e.g. "requests.get(…)" or "SQLAlchemy query"
    pub label: String,
    /// Best-effort upstream URL for the `fault run --upstream` flag.
    /// None when the URL could not be statically determined.
    pub upstream_url: Option<String>,
    /// Category — used to pick sensible defaults when URL is absent.
    pub kind: EgressKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressKind {
    Http,
    Database(DatabaseKind),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatabaseKind {
    Postgres,
    Mysql,
    Other,
}

// ─────────────────────────────────────────────────────────────────────────────
// Template definitions
// ─────────────────────────────────────────────────────────────────────────────

/// All supported fault injection scenario templates, mirroring the VSCode extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultTemplate {
    LatencyNormal,
    LatencyPareto,
    LatencyWindow,
    JitterLight,
    JitterBidirectional,
    Bandwidth64k,
    Bandwidth48kLatency,
    Mobile3g,
    PacketLoss,
    PacketLossBurst,
    Blackhole,
    BlackholeWindow,
}

impl FaultTemplate {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "latency-normal" => Some(Self::LatencyNormal),
            "latency-pareto" => Some(Self::LatencyPareto),
            "latency-window" => Some(Self::LatencyWindow),
            "jitter-light" => Some(Self::JitterLight),
            "jitter-bidirectional" => Some(Self::JitterBidirectional),
            "bandwidth-64k" => Some(Self::Bandwidth64k),
            "bandwidth-48k-latency" => Some(Self::Bandwidth48kLatency),
            "mobile-3g" => Some(Self::Mobile3g),
            "packet-loss" => Some(Self::PacketLoss),
            "packet-loss-burst" => Some(Self::PacketLossBurst),
            "blackhole" => Some(Self::Blackhole),
            "blackhole-window" => Some(Self::BlackholeWindow),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::LatencyNormal => "latency-normal",
            Self::LatencyPareto => "latency-pareto",
            Self::LatencyWindow => "latency-window",
            Self::JitterLight => "jitter-light",
            Self::JitterBidirectional => "jitter-bidirectional",
            Self::Bandwidth64k => "bandwidth-64k",
            Self::Bandwidth48kLatency => "bandwidth-48k-latency",
            Self::Mobile3g => "mobile-3g",
            Self::PacketLoss => "packet-loss",
            Self::PacketLossBurst => "packet-loss-burst",
            Self::Blackhole => "blackhole",
            Self::BlackholeWindow => "blackhole-window",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::LatencyNormal => "350ms ± 50ms normal distribution latency",
            Self::LatencyPareto => "Pareto-distributed tail latency spikes",
            Self::LatencyWindow => {
                "Latency injection at 25%–75% of run duration (requires --duration)"
            }
            Self::JitterLight => "Light jitter: 30ms amplitude @ 5Hz",
            Self::JitterBidirectional => "Bidirectional jitter: 30ms @ 8Hz (both directions)",
            Self::Bandwidth64k => "Bandwidth throttle: 64 KBps download",
            Self::Bandwidth48kLatency => "48 KBps bandwidth + 200ms added latency",
            Self::Mobile3g => "Mobile 3G simulation: 48 KBps + 200ms + jitter",
            Self::PacketLoss => "Constant packet drop",
            Self::PacketLossBurst => "Packet loss at 25%–75% of run duration (requires --duration)",
            Self::Blackhole => "Blackhole: all traffic dropped (hang / timeout)",
            Self::BlackholeWindow => "Blackhole at 25%–75% of run duration (requires --duration)",
        }
    }

    /// One-line "why would I use this?" shown in the interactive selector.
    pub fn why(&self) -> &'static str {
        match self {
            Self::LatencyNormal => {
                "Test whether your timeouts, retries, and user-facing degradation handle predictable slowness."
            }
            Self::LatencyPareto => {
                "Reproduce the long-tail latency your p99 users actually experience."
            }
            Self::LatencyWindow => {
                "Inject slowness mid-request to catch race conditions and partial-response bugs."
            }
            Self::JitterLight => {
                "Simulate an unstable network without full packet loss — catches missing retry logic."
            }
            Self::JitterBidirectional => {
                "Stress both upload and download paths simultaneously; useful for streaming or bidirectional APIs."
            }
            Self::Bandwidth64k => {
                "Simulate a constrained pipe — catches missing pagination or oversized response bodies."
            }
            Self::Bandwidth48kLatency => {
                "Combine throughput limit + latency to mimic a degraded WAN link or a slow upstream API."
            }
            Self::Mobile3g => {
                "Reproduce mobile field conditions: slow + jittery + narrow bandwidth all at once."
            }
            Self::PacketLoss => {
                "Verify that TCP retransmission and application-level retries handle sustained loss."
            }
            Self::PacketLossBurst => {
                "Simulate a brief network brown-out mid-flow — catches requests that never retry."
            }
            Self::Blackhole => {
                "Confirm your circuit breaker opens, your timeout fires, and callers get a clear error."
            }
            Self::BlackholeWindow => {
                "Inject a temporary outage window to test recovery and re-connection behaviour."
            }
        }
    }

    /// One-line "what will I learn?" shown after the scenario is selected.
    pub fn expected_learning(&self) -> &'static str {
        match self {
            Self::LatencyNormal => {
                "Does the handler return a timeout error within the configured deadline?"
            }
            Self::LatencyPareto => "Does your p99 SLO hold, or do tail requests blow the budget?",
            Self::LatencyWindow => {
                "Are partial results handled gracefully when the upstream goes slow mid-flight?"
            }
            Self::JitterLight => {
                "Does your retry strategy absorb brief instability without hammering the upstream?"
            }
            Self::JitterBidirectional => {
                "Does bidirectional jitter cause checksum errors, stalls, or silent data corruption?"
            }
            Self::Bandwidth64k => {
                "Does the response size stay within acceptable bounds for slow consumers?"
            }
            Self::Bandwidth48kLatency => {
                "Does the combined pressure cause connection pool exhaustion or cascading timeouts?"
            }
            Self::Mobile3g => "Is your API usable from a mobile client on a poor connection?",
            Self::PacketLoss => {
                "Does the client retry and eventually succeed, or fail open/closed?"
            }
            Self::PacketLossBurst => "Does the application recover cleanly when the outage clears?",
            Self::Blackhole => {
                "Does the circuit breaker open fast enough to protect downstream callers?"
            }
            Self::BlackholeWindow => {
                "Does the system reconnect automatically once the blackhole lifts?"
            }
        }
    }

    /// Returns the `fault run` flags (excluding proxy/upstream/duration) for this template.
    pub fn fault_flags(&self, direction: &str) -> Vec<String> {
        match self {
            Self::LatencyNormal => vec![
                "--with-latency".into(),
                format!("--latency-direction {}", direction),
                "--latency-distribution normal".into(),
                "--latency-mean 350".into(),
                "--latency-stddev 50".into(),
            ],
            Self::LatencyPareto => vec![
                "--with-latency".into(),
                format!("--latency-direction {}", direction),
                "--latency-distribution pareto".into(),
                "--latency-shape 1.5".into(),
                "--latency-scale 20".into(),
            ],
            Self::LatencyWindow => vec![
                "--with-latency".into(),
                format!("--latency-direction {}", direction),
                "--latency-distribution normal".into(),
                "--latency-mean 500".into(),
                "--latency-stddev 100".into(),
                r#"--latency-sched "start:25%,duration:50%""#.into(),
            ],
            Self::JitterLight => vec![
                "--with-jitter".into(),
                "--jitter-amplitude 30".into(),
                "--jitter-frequency 5".into(),
            ],
            Self::JitterBidirectional => vec![
                "--with-jitter".into(),
                "--jitter-amplitude 30".into(),
                "--jitter-frequency 8".into(),
                "--jitter-direction both".into(),
            ],
            Self::Bandwidth64k => vec![
                "--with-bandwidth".into(),
                "--bandwidth-rate 64".into(),
                "--bandwidth-unit KBps".into(),
                "--bandwidth-direction ingress".into(),
            ],
            Self::Bandwidth48kLatency => vec![
                "--with-bandwidth".into(),
                "--bandwidth-rate 48".into(),
                "--bandwidth-unit KBps".into(),
                "--with-latency".into(),
                "--latency-direction both".into(),
                "--latency-distribution normal".into(),
                "--latency-mean 200".into(),
                "--latency-stddev 20".into(),
            ],
            Self::Mobile3g => vec![
                "--with-bandwidth".into(),
                "--bandwidth-rate 48".into(),
                "--bandwidth-unit KBps".into(),
                "--with-latency".into(),
                "--latency-direction both".into(),
                "--latency-distribution normal".into(),
                "--latency-mean 200".into(),
                "--latency-stddev 20".into(),
                "--with-jitter".into(),
                "--jitter-amplitude 30".into(),
                "--jitter-frequency 5".into(),
            ],
            Self::PacketLoss => vec![
                "--with-packet-loss".into(),
                format!("--packet-loss-direction {}", direction),
            ],
            Self::PacketLossBurst => vec![
                "--with-packet-loss".into(),
                format!("--packet-loss-direction {}", direction),
                r#"--packet-loss-sched "start:25%,duration:50%""#.into(),
            ],
            Self::Blackhole => vec![
                "--with-blackhole".into(),
                format!("--blackhole-direction {}", direction),
            ],
            Self::BlackholeWindow => vec![
                "--with-blackhole".into(),
                format!("--blackhole-direction {}", direction),
                r#"--blackhole-sched "start:25%,duration:50%""#.into(),
            ],
        }
    }

    pub fn all() -> &'static [FaultTemplate] {
        &[
            Self::LatencyNormal,
            Self::LatencyPareto,
            Self::LatencyWindow,
            Self::JitterLight,
            Self::JitterBidirectional,
            Self::Bandwidth64k,
            Self::Bandwidth48kLatency,
            Self::Mobile3g,
            Self::PacketLoss,
            Self::PacketLossBurst,
            Self::Blackhole,
            Self::BlackholeWindow,
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Command args
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct FaultArgs {
    /// Function to target in format file:function or just function_name
    pub function: String,
    /// Template name (optional; lists all if absent)
    pub template: Option<String>,
    /// Injection mode: "ingress" (default) or "egress"
    pub mode: String,
    /// Target URL.
    /// Ingress: local app base URL (default: http://127.0.0.1:8000).
    /// Egress: remote dependency base URL (required).
    pub url: Option<String>,
    /// Local proxy port (default: 9090)
    pub port: u16,
    /// Injection duration (default: 2m)
    pub duration: String,
    /// Workspace path (defaults to current directory)
    pub workspace_path: Option<String>,
    /// Verbose output
    pub verbose: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Execute
// ─────────────────────────────────────────────────────────────────────────────

pub async fn execute(args: FaultArgs) -> Result<i32> {
    let workspace_path = match &args.workspace_path {
        Some(p) => std::path::PathBuf::from(p),
        None => std::env::current_dir()?,
    };

    // Parse file:function — keep both parts for scoped graph lookup.
    let (file_hint, function_name) = match args.function.split_once(':') {
        Some((file, func)) => (Some(file.to_string()), func.to_string()),
        None => (None, args.function.clone()),
    };

    // ── Build graph (with spinner) ────────────────────────────────────────────
    use indicatif::{ProgressBar, ProgressStyle};
    use std::time::Duration;

    let spinner = if !args.verbose {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message("Analysing call graph…");
        pb.enable_steady_tick(Duration::from_millis(80));
        Some(pb)
    } else {
        None
    };

    let (graph, semantics) = match crate::local_graph::build_analysis_graph_with_semantics(
        &workspace_path,
        args.verbose,
    ) {
        Ok(r) => r,
        Err(e) => {
            if let Some(pb) = spinner {
                pb.finish_and_clear();
            }
            eprintln!(
                "{} Failed to build code graph: {}",
                "Error:".red().bold(),
                e
            );
            return Ok(EXIT_ERROR);
        }
    };

    if let Some(pb) = &spinner {
        pb.finish_and_clear();
    }

    // ── Resolve HTTP routes via the code graph ────────────────────────────────
    let routes = resolve_routes(&graph, &function_name, file_hint.as_deref());

    // ── Resolve egress targets (outbound HTTP + DB calls) ────────────────────
    let egress_targets =
        resolve_egress_targets(&graph, &semantics, &function_name, file_hint.as_deref());

    let proxy_port = args.port;
    let duration = &args.duration;
    let ingress_url = args
        .url
        .clone()
        .unwrap_or_else(|| "http://127.0.0.1:8000".to_string());

    // ── Non-interactive path: --template was supplied ─────────────────────────
    if let Some(template_name) = &args.template {
        let template = match FaultTemplate::parse(template_name) {
            Some(t) => t,
            None => {
                eprintln!(
                    "{} Unknown template '{}'. Available:",
                    "Error:".red().bold(),
                    template_name
                );
                print_template_list();
                return Ok(EXIT_ERROR);
            }
        };

        let is_egress = args.mode.to_lowercase() == "egress";
        let (upstream, port, direction) = if is_egress {
            let url = match &args.url {
                Some(u) => u.clone(),
                None => {
                    eprintln!(
                        "{} --url is required for egress mode.",
                        "Error:".red().bold()
                    );
                    return Ok(EXIT_ERROR);
                }
            };
            (url, proxy_port, "egress")
        } else {
            (ingress_url.clone(), proxy_port, "ingress")
        };

        let flags = template.fault_flags(direction);
        let cmd = build_fault_command(&upstream, port, duration, &flags);
        println!();
        println!("{}", cmd.bright_blue());
        println!();
        return Ok(EXIT_SUCCESS);
    }

    // ── Interactive path ──────────────────────────────────────────────────────
    use dialoguer::{Select, theme::ColorfulTheme};

    // Build the list of injection targets.
    // Each entry: (display label, upstream URL, port offset, fault direction, curl hint)
    struct InjectionTarget {
        label: String,
        upstream: String,
        port: u16,
        direction: &'static str,
        usage_hint: Option<String>,
    }

    let mut injection_targets: Vec<InjectionTarget> = Vec::new();

    // Ingress target
    let ingress_label = if routes.is_empty() {
        format!("Ingress  — {} (no route detected)", ingress_url)
    } else {
        let route_summary = routes
            .iter()
            .map(|(m, p)| format!("{} {}", m, p))
            .collect::<Vec<_>>()
            .join(", ");
        format!("Ingress  — {}", route_summary)
    };
    let ingress_curl = routes.first().map(|(method, path)| {
        format!(
            "curl -i -X {} http://127.0.0.1:{}/{}",
            method,
            proxy_port,
            path.trim_start_matches('/')
        )
    });
    injection_targets.push(InjectionTarget {
        label: ingress_label,
        upstream: ingress_url.clone(),
        port: proxy_port,
        direction: "ingress",
        usage_hint: ingress_curl,
    });

    // Egress targets
    for (i, target) in egress_targets.iter().enumerate() {
        let port = proxy_port + 1 + i as u16;
        let upstream = target
            .upstream_url
            .clone()
            .unwrap_or_else(|| default_upstream(&target.kind));
        let hint = match &target.kind {
            EgressKind::Http => Some(format!(
                "export SERVICE_URL=http://127.0.0.1:{}  # then restart your app",
                port
            )),
            EgressKind::Database(_) => Some(format!(
                "export DATABASE_URL=postgresql://127.0.0.1:{}  # then restart your app",
                port
            )),
        };
        injection_targets.push(InjectionTarget {
            label: format!("Egress   — {}", target.label),
            upstream,
            port,
            direction: "egress",
            usage_hint: hint,
        });
    }

    // ── Step 1: select target ─────────────────────────────────────────────────
    println!();
    println!(
        "{} Fault injection for {}",
        "⚡".bright_yellow(),
        function_name.bright_white().bold()
    );
    println!();

    let target_labels: Vec<&str> = injection_targets.iter().map(|t| t.label.as_str()).collect();

    let target_idx = match Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select injection target")
        .items(&target_labels)
        .default(0)
        .interact_opt()?
    {
        Some(i) => i,
        None => return Ok(EXIT_SUCCESS), // user pressed Escape/q
    };

    let selected_target = &injection_targets[target_idx];

    // ── Step 2: select scenario ───────────────────────────────────────────────
    let templates = FaultTemplate::all();

    // Build display strings: "name  — why"
    let scenario_labels: Vec<String> = templates
        .iter()
        .map(|t| format!("{:<22}  {}", t.name(), t.why()))
        .collect();

    println!();

    let scenario_idx = match Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select scenario")
        .items(&scenario_labels)
        .default(0)
        .interact_opt()?
    {
        Some(i) => i,
        None => return Ok(EXIT_SUCCESS),
    };

    let selected_template = &templates[scenario_idx];

    // ── Final output ──────────────────────────────────────────────────────────
    println!();
    println!(
        "{} {} — {}",
        "⚡".bright_yellow(),
        selected_template.name().bright_white().bold(),
        selected_target.label.dimmed()
    );
    println!();

    // What you'll learn
    println!("  {} {}", "→".cyan(), selected_template.expected_learning());
    println!();

    // The fault run command
    let flags = selected_template.fault_flags(selected_target.direction);
    let cmd = build_fault_command(
        &selected_target.upstream,
        selected_target.port,
        duration,
        &flags,
    );
    println!("{}", cmd.bright_blue());
    println!();

    // Usage hint (curl or export)
    if let Some(ref hint) = selected_target.usage_hint {
        println!("  {}", hint.bold());
        println!();
    }

    // Installation tip
    println!(
        "  {}  Install fault: {}",
        "tip".dimmed(),
        "https://fault-project.com".underline().dimmed()
    );
    println!();

    Ok(EXIT_SUCCESS)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build the full `fault run` command string.
fn build_fault_command(target_url: &str, port: u16, duration: &str, flags: &[String]) -> String {
    let mut parts = vec![
        "fault run".to_string(),
        format!("--proxy-address 127.0.0.1:{}", port),
        format!("--upstream {}", target_url),
        format!("--duration {}", duration),
    ];
    // Each entry in `flags` is a single logical flag with its value
    // (e.g. "--latency-mean 350"). Keep them together on one line.
    for flag in flags {
        parts.push(flag.clone());
    }
    parts.join(" \\\n      ")
}

/// Resolve HTTP routes reachable from a function using the pre-built graph.
/// Returns (method, path) pairs.
fn resolve_routes(
    graph: &unfault_analysis::graph::CodeGraph,
    function_name: &str,
    file_hint: Option<&str>,
) -> Vec<(String, String)> {
    let ctx = if let Some(hint) = file_hint {
        unfault_analysis::graph::traversal::get_callers_in_file(graph, function_name, hint, 10)
    } else {
        unfault_analysis::graph::traversal::get_callers(graph, function_name, 10)
    };

    let mut routes: Vec<(String, String)> =
        ctx.routes.into_iter().map(|r| (r.method, r.path)).collect();

    // Also check if the function itself is a handler (direct route).
    use petgraph::Direction;
    use petgraph::visit::EdgeRef;
    use unfault_analysis::graph::GraphEdgeKind;
    use unfault_analysis::graph::GraphNode;

    let lower_target = function_name.to_lowercase();
    let lower_hint = file_hint.map(|h| h.to_lowercase());

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        let name = node.display_name().to_lowercase();

        if let Some(ref hint) = lower_hint {
            let node_file = unfault_analysis::graph::traversal::node_file_path_pub(graph, node)
                .unwrap_or_default()
                .to_lowercase();
            if !node_file.ends_with(hint.as_str()) {
                continue;
            }
        }

        if name == lower_target
            || name.ends_with(&format!(".{}", lower_target))
            || name.ends_with(&format!("/{}", lower_target))
        {
            if let GraphNode::Function {
                is_handler: true,
                http_method: Some(method),
                http_path: Some(path),
                ..
            } = node
            {
                let entry = (method.clone(), path.clone());
                if !routes.contains(&entry) {
                    routes.push(entry);
                }
            }

            for edge in graph.graph.edges_directed(idx, Direction::Incoming) {
                if !matches!(edge.weight(), GraphEdgeKind::Contains) {
                    continue;
                }
                if let GraphNode::FastApiRoute {
                    http_method, path, ..
                } = &graph.graph[edge.source()]
                {
                    let entry = (http_method.clone(), path.clone());
                    if !routes.contains(&entry) {
                        routes.push(entry);
                    }
                }
            }
        }
    }

    routes
}

/// Walk forward from `function_name` through `Calls` edges, collecting
/// outbound HTTP calls and database queries from reachable functions.
///
/// Returns a de-duplicated list of `EgressTarget`s, each with the best
/// upstream URL we could determine statically.
fn resolve_egress_targets(
    graph: &unfault_analysis::graph::CodeGraph,
    semantics: &[unfault_core::semantics::SourceSemantics],
    function_name: &str,
    file_hint: Option<&str>,
) -> Vec<EgressTarget> {
    use petgraph::Direction;
    use petgraph::visit::EdgeRef;
    use std::collections::HashSet;
    use unfault_analysis::graph::GraphEdgeKind;
    use unfault_core::semantics::SourceSemantics;

    // Build a map from file_id → semantics for fast lookup.
    let sem_by_file: std::collections::HashMap<
        unfault_core::parse::ast::FileId,
        &unfault_core::semantics::SourceSemantics,
    > = semantics
        .iter()
        .map(|s| {
            let fid = match s {
                SourceSemantics::Python(py) => py.file_id,
                SourceSemantics::Go(go) => go.file_id,
                SourceSemantics::Rust(rs) => rs.file_id,
                SourceSemantics::Typescript(ts) => ts.file_id,
            };
            (fid, s)
        })
        .collect();

    // Find the start node(s) for the target function.
    let lower_target = function_name.to_lowercase();
    let lower_hint = file_hint.map(|h| h.to_lowercase());

    let start_nodes: Vec<petgraph::graph::NodeIndex> = graph
        .graph
        .node_indices()
        .filter(|&idx| {
            let node = &graph.graph[idx];
            let name = node.display_name().to_lowercase();
            if !matches!(node, unfault_analysis::graph::GraphNode::Function { .. }) {
                return false;
            }
            let name_matches = name == lower_target
                || name.ends_with(&format!(".{}", lower_target))
                || name.ends_with(&format!("/{}", lower_target));
            if !name_matches {
                return false;
            }
            if let Some(ref hint) = lower_hint {
                let file = unfault_analysis::graph::traversal::node_file_path_pub(graph, node)
                    .unwrap_or_default()
                    .to_lowercase();
                file.ends_with(hint.as_str())
            } else {
                true
            }
        })
        .collect();

    // Forward BFS through Calls edges, collecting file_ids of reachable nodes.
    let mut visited: HashSet<petgraph::graph::NodeIndex> = HashSet::new();
    let mut queue: std::collections::VecDeque<petgraph::graph::NodeIndex> =
        start_nodes.iter().copied().collect();
    visited.extend(start_nodes.iter().copied());

    while let Some(current) = queue.pop_front() {
        for edge in graph.graph.edges_directed(current, Direction::Outgoing) {
            if !matches!(edge.weight(), GraphEdgeKind::Calls) {
                continue;
            }
            let target = edge.target();
            if visited.insert(target) {
                queue.push_back(target);
            }
        }
    }

    // Collect file_ids of all visited function nodes.
    let reachable_file_ids: HashSet<unfault_core::parse::ast::FileId> = visited
        .iter()
        .filter_map(|&idx| graph.graph[idx].file_id())
        .collect();

    // For each reachable file, inspect http_calls and orm_queries.
    let mut targets: Vec<EgressTarget> = Vec::new();
    let mut seen_upstreams: HashSet<String> = HashSet::new();

    for file_id in &reachable_file_ids {
        let sem = match sem_by_file.get(file_id) {
            Some(s) => s,
            None => continue,
        };

        if let SourceSemantics::Python(py) = sem {
            // ── HTTP calls ────────────────────────────────────────────────────
            for call in &py.http_calls {
                let url = extract_url_from_call_text(&call.call_text);
                let upstream = url
                    .as_ref()
                    .and_then(|u| extract_origin(u))
                    .map(|o| o.to_string());

                // De-duplicate by upstream origin (or call_text if no URL).
                let dedup_key = upstream
                    .clone()
                    .unwrap_or_else(|| call.call_text.chars().take(60).collect());
                if !seen_upstreams.insert(dedup_key) {
                    continue;
                }

                let label = if let Some(ref u) = url {
                    format!(
                        "{}.{}(\"{}\")",
                        call.client_kind.as_str(),
                        call.method_name,
                        u
                    )
                } else {
                    format!("{}.{}(…)", call.client_kind.as_str(), call.method_name)
                };

                targets.push(EgressTarget {
                    label,
                    upstream_url: upstream,
                    kind: EgressKind::Http,
                });
            }

            // ── ORM / DB queries ──────────────────────────────────────────────
            for query in &py.orm_queries {
                let kind = orm_kind_from_library(&query.orm_kind);
                let dedup_key = format!("db:{:?}", kind);
                if !seen_upstreams.insert(dedup_key) {
                    continue;
                }
                let label = match &query.model_name {
                    Some(model) => {
                        format!("{} query on {}", orm_library_name(&query.orm_kind), model)
                    }
                    None => format!("{} query", orm_library_name(&query.orm_kind)),
                };
                targets.push(EgressTarget {
                    label,
                    upstream_url: None, // connection string not available statically
                    kind: EgressKind::Database(kind),
                });
            }
        }
    }

    targets
}

/// Try to extract a URL string literal from a raw call expression like
/// `requests.get("https://api.example.com/v1/users", timeout=5)`.
fn extract_url_from_call_text(call_text: &str) -> Option<String> {
    // Match the first quoted string argument.
    let re = regex::Regex::new(r#"["'](?P<url>https?://[^"']+)["']"#).ok()?;
    re.captures(call_text)
        .and_then(|c| c.name("url"))
        .map(|m| m.as_str().to_string())
}

/// Extract just the scheme+host[:port] from a URL, e.g.
/// "https://api.example.com/v1/users" → "https://api.example.com"
fn extract_origin(url: &str) -> Option<&str> {
    // Find the end of the authority: after "scheme://host[:port]"
    let after_scheme = url.find("://")?;
    let host_start = after_scheme + 3;
    let host_end = url[host_start..]
        .find('/')
        .map(|i| host_start + i)
        .unwrap_or(url.len());
    Some(&url[..host_end])
}

/// Default upstream URL when we couldn't extract one statically.
fn default_upstream(kind: &EgressKind) -> String {
    match kind {
        EgressKind::Http => "http://downstream-service".to_string(),
        EgressKind::Database(DatabaseKind::Postgres) => "postgresql://localhost:5432".to_string(),
        EgressKind::Database(DatabaseKind::Mysql) => "mysql://localhost:3306".to_string(),
        EgressKind::Database(DatabaseKind::Other) => "localhost:5432".to_string(),
    }
}

fn orm_kind_from_library(kind: &unfault_core::semantics::python::orm::OrmKind) -> DatabaseKind {
    use unfault_core::semantics::python::orm::OrmKind;
    match kind {
        OrmKind::SqlAlchemy | OrmKind::Django | OrmKind::Tortoise | OrmKind::SqlModel => {
            DatabaseKind::Postgres // sensible default for Python ORMs
        }
        OrmKind::Peewee => DatabaseKind::Mysql,
        _ => DatabaseKind::Other,
    }
}

fn orm_library_name(kind: &unfault_core::semantics::python::orm::OrmKind) -> &'static str {
    kind.as_str()
}

fn print_template_list() {
    for t in FaultTemplate::all() {
        eprintln!("    {:25} {}", t.name().bold(), t.description().dimmed());
    }
}
