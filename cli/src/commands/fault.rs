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
    pub fn from_str(s: &str) -> Option<Self> {
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

    // ── Resolve HTTP routes via the code graph ────────────────────────────────
    let routes = resolve_routes(
        &workspace_path,
        &function_name,
        file_hint.as_deref(),
        args.verbose,
    );

    // ── Template selection ────────────────────────────────────────────────────
    let templates: Vec<FaultTemplate> = match &args.template {
        Some(name) => match FaultTemplate::from_str(name) {
            Some(t) => vec![t],
            None => {
                eprintln!(
                    "{} Unknown template '{}'. Available templates:",
                    "Error:".red().bold(),
                    name
                );
                print_template_list();
                return Ok(EXIT_ERROR);
            }
        },
        None => FaultTemplate::all().to_vec(),
    };

    let is_egress = args.mode.to_lowercase() == "egress";
    let proxy_port = args.port;
    let duration = &args.duration;

    // ── Determine proxy target URL ────────────────────────────────────────────
    let target_url = if is_egress {
        match &args.url {
            Some(u) => u.clone(),
            None => {
                eprintln!(
                    "{} --url is required for egress mode (remote dependency base URL).",
                    "Error:".red().bold()
                );
                return Ok(EXIT_ERROR);
            }
        }
    } else {
        args.url
            .clone()
            .unwrap_or_else(|| "http://127.0.0.1:8000".to_string())
    };

    // ── Print header ──────────────────────────────────────────────────────────
    println!();
    println!(
        "{} Fault injection scenarios for {}",
        "⚡".bright_yellow(),
        function_name.bright_white().bold()
    );

    if !routes.is_empty() {
        println!();
        println!("  Reachable routes:");
        for (method, path) in &routes {
            let method_colored = match method.as_str() {
                "GET" => method.bright_green(),
                "POST" => method.bright_yellow(),
                "PUT" | "PATCH" => method.bright_cyan(),
                "DELETE" => method.bright_red(),
                _ => method.normal(),
            };
            println!("    {} {}", method_colored, path);
        }
    } else {
        println!();
        println!(
            "  {} No HTTP routes found for this function in the graph.",
            "ℹ".cyan()
        );
        println!(
            "  Generating commands anyway using proxy target: {}",
            target_url.cyan()
        );
    }

    println!();

    // ── Mode explanation ──────────────────────────────────────────────────────
    if is_egress {
        println!(
            "  Mode: {} (inject faults on outbound calls)",
            "egress".yellow().bold()
        );
        println!(
            "  Proxy: localhost:{} → {}",
            proxy_port.to_string().yellow(),
            target_url.cyan()
        );
        println!();
        println!("  To use egress mode, point your app's outbound base URL to the proxy:");
        println!(
            "    {}  (then restart your app and trigger the route normally)",
            format!("export SERVICE_URL=http://127.0.0.1:{}", proxy_port).bold()
        );
    } else {
        println!(
            "  Mode: {} (inject faults on inbound requests)",
            "ingress".yellow().bold()
        );
        println!(
            "  Proxy: localhost:{} → {}",
            proxy_port.to_string().yellow(),
            target_url.cyan()
        );

        if !routes.is_empty() {
            println!();
            println!("  Send test requests through the proxy:");
            for (method, path) in &routes {
                println!(
                    "    {}",
                    format!(
                        "curl -i -X {} http://127.0.0.1:{}/{}",
                        method,
                        proxy_port,
                        path.trim_start_matches('/')
                    )
                    .bold()
                );
            }
        }
    }

    println!();
    println!("{}", "─".repeat(60).dimmed());

    // ── Emit `fault run` commands ─────────────────────────────────────────────
    let direction = if is_egress { "egress" } else { "ingress" };

    for template in &templates {
        println!();
        println!(
            "  {} {}",
            template.name().bright_white().bold(),
            format!("— {}", template.description()).dimmed()
        );
        println!();

        let flags = template.fault_flags(direction);
        let cmd = build_fault_command(&target_url, proxy_port, duration, &flags);
        println!("    {}", cmd.bright_blue());
    }

    println!();

    // ── Installation hint ─────────────────────────────────────────────────────
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

/// Resolve HTTP routes reachable from a function using the code graph.
/// Returns (method, path) pairs. Falls back to empty vec on any error.
fn resolve_routes(
    workspace_path: &std::path::Path,
    function_name: &str,
    file_hint: Option<&str>,
    verbose: bool,
) -> Vec<(String, String)> {
    let graph = match crate::local_graph::build_analysis_graph(workspace_path, verbose) {
        Ok(g) => g,
        Err(_) => return vec![],
    };

    let ctx = if let Some(hint) = file_hint {
        unfault_analysis::graph::traversal::get_callers_in_file(&graph, function_name, hint, 10)
    } else {
        unfault_analysis::graph::traversal::get_callers(&graph, function_name, 10)
    };

    let mut routes: Vec<(String, String)> =
        ctx.routes.into_iter().map(|r| (r.method, r.path)).collect();

    // Also check if the function itself is a handler (direct route).
    // get_callers only traverses *inbound* edges; if the function IS the handler
    // it appears as the target, not a caller. So we inspect it directly.
    use petgraph::Direction;
    use petgraph::visit::EdgeRef;
    use unfault_analysis::graph::GraphEdgeKind;
    use unfault_analysis::graph::GraphNode;

    let lower_target = function_name.to_lowercase();
    let lower_hint = file_hint.map(|h| h.to_lowercase());

    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        let name = node.display_name().to_lowercase();

        // When a file hint is present, skip nodes from other files.
        if let Some(ref hint) = lower_hint {
            let node_file = unfault_analysis::graph::traversal::node_file_path_pub(&graph, node)
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
            // Check if this node is a handler with route info.
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

            // Check for FastApiRoute parent via Contains edge.
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

fn print_template_list() {
    for t in FaultTemplate::all() {
        eprintln!("    {:25} {}", t.name().bold(), t.description().dimmed());
    }
}
