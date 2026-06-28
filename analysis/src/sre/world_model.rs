//! World Model — failure propagation simulation across static and runtime graphs.
//!
//! This module implements all three tiers of the Hierarchical World Model (HWM)
//! adapted from Zhang et al. 2026 ("Hierarchical Planning with Latent World
//! Models") for system resilience analysis:
//!
//! ```text
//! Macro-Goals   ← SLO nodes         (GCP/Datadog/Dynatrace, via MonitoredBy edges)
//!      ↑ MonitoredBy
//! HTTP handlers ← local call chains  (Calls / Imports edges, reversed)
//!      ↑ Calls / Imports
//! Primitives    ← a Finding at a file (e.g. missing timeout on an HTTP call)
//!      ↓ RemoteCall
//! RemoteService ← cross-service boundary (GCP Cloud Trace RPC_CLIENT spans)
//! ```
//!
//! # Two-source world model
//!
//! The graph combines two complementary data sources:
//!
//! **Static analysis** (always present): the `CodeGraph` built by the Rust/
//! Tree-sitter parser. It captures file-level structure — imports, function
//! calls, HTTP handler declarations. This is the skeleton of the model.
//!
//! **Distributed traces** (opportunistic): `GraphNode::RemoteService` nodes and
//! `GraphEdgeKind::RemoteCall` edges injected by `cli::trace::TraceEnricher`
//! from GCP Cloud Trace `RPC_CLIENT` spans. These extend the propagation graph
//! *beyond the repository boundary* to services the code calls at runtime that
//! are not visible to static analysis. When traces are available, a finding in
//! a file that calls an external service can propagate all the way to that
//! service rather than stopping at an inferred entrypoint.
//!
//! # BFS propagation direction
//!
//! The BFS uses two traversal directions simultaneously:
//!
//! - **Reverse** along `Calls` and `Imports` edges: if file B breaks, every
//!   file that imports or calls B is affected. This is the blast-radius
//!   direction — we walk *against* the dependency arrows.
//!
//! - **Forward** along `MonitoredBy` and `RemoteCall` edges: these are
//!   "consequence" edges. `MonitoredBy` runs from an HTTP handler to its SLO;
//!   `RemoteCall` runs from a local file to the remote service it calls at
//!   runtime. Both point *toward* the thing that suffers if the origin breaks.
//!
//! # Risk model
//!
//! Each edge type carries a *propagation weight* in [0, 1] representing the
//! conditional probability that a failure at the source materialises at the
//! target:
//!
//! | Edge type     | Weight | Rationale |
//! |---------------|--------|-----------|
//! | `Calls`       | 0.80   | Direct invocation — caller blocks on callee |
//! | `Imports`     | 0.50   | Structural dependency — indirect, but real |
//! | `ImportsFrom` | 0.50   | Same as `Imports` |
//! | `Contains`    | 0.00   | File → Function structural link, traversed to reach `MonitoredBy`/`RemoteCall` |
//! | `RemoteCall`  | 0.90   | Cross-service — no local circuit breaker assumed |
//! | `MonitoredBy` | 1.00   | Reaching the SLO node confirms Macro-Goal impact |
//!
//! The **aggregate risk** is the complement probability product over all hops
//! on the path from origin to anchor:
//!
//! ```text
//! risk = 1 - ∏(1 - weight_i)
//! ```
//!
//! This is the "at least one failure propagates" probability under the
//! independence assumption, expressed as a percentage in [0, 100].
//!
//! # Anchor priority
//!
//! The BFS selects the best anchor in priority order:
//!
//! 1. **SLO node** — highest confidence. The finding's blast radius is
//!    quantified against a concrete availability target (e.g. 99.9%).
//! 2. **RemoteService node** — present when trace data is available. Signals
//!    that the failure crosses a service boundary, which is categorically
//!    worse than a local failure because there is no local recovery path.
//! 3. **Inferred entrypoint** — fallback when neither SLOs nor traces are
//!    available. The nearest file with no importers (a root of the import tree)
//!    is used as a proxy for the request entry point.
//!
//! # Output
//!
//! `compute_propagation` returns a [`PropagationPath`] for each finding:
//! - `hops`: ordered steps from origin → anchor, each with an edge label
//! - `aggregate_risk`: 0.0–100.0 risk score
//! - `macro_goal`: SLO name, `"remote:<service>"`, or entrypoint file path
//! - `anchored_to_slo`: true only when a real SLO node was reached

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::Direction;
use petgraph::visit::EdgeRef;

use crate::graph::{CodeGraph, GraphEdgeKind, GraphNode};
use crate::types::finding::Finding;
// Re-export the core types for consumers of this module
pub use crate::types::sre_diagnostic::{PropagationHop, PropagationPath};

/// Edge propagation weights for the risk model.
///
/// | Edge type     | Weight | Rationale |
/// |---------------|--------|-----------|
/// | `Calls`       | 0.80   | Direct invocation — failure almost certainly propagates |
/// | `Imports`     | 0.50   | Structural dependency — indirect but real |
/// | `ImportsFrom` | 0.50   | Same as Imports |
/// | `Contains`    | 0.00   | File→Function structural link — traversed to reach MonitoredBy/RemoteCall |
/// | `RemoteCall`  | 0.90   | Cross-service call — no local recovery path |
/// | `MonitoredBy` | 1.00   | SLO anchor — confirms Macro-Goal impact |
fn edge_weight(kind: &GraphEdgeKind) -> f64 {
    match kind {
        GraphEdgeKind::Calls => 0.80,
        GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. } => 0.50,
        GraphEdgeKind::RemoteCall => 0.90,
        GraphEdgeKind::MonitoredBy => 1.00,
        // Contains: weight 0 — traversed only to reach MonitoredBy/RemoteCall
        // on function nodes; adds no additional risk to the score.
        GraphEdgeKind::Contains => 0.0,
        // UsesLibrary, Inherits, FastApi* — not propagation-relevant
        _ => 0.0,
    }
}

/// Compute the failure propagation path for a single finding.
///
/// Runs a weighted BFS on the combined static + runtime graph:
///
/// - Traverses **reverse** along `Calls` and `Imports` edges to find
///   everything that depends on the finding's file.
/// - Traverses **forward** along `MonitoredBy` edges to reach SLO nodes, and
///   along `RemoteCall` edges (injected from Cloud Trace) to reach
///   `RemoteService` nodes beyond the repository boundary.
///
/// Returns the [`PropagationPath`] with the highest-priority anchor reachable:
/// SLO > RemoteService > inferred entrypoint.
pub fn compute_propagation(finding: &Finding, graph: &CodeGraph) -> PropagationPath {
    let origin = &finding.file_path;

    // ── Phase 1: Find the origin node index ──────────────────────────────
    let Some(&origin_idx) = graph.path_to_file.get(origin.as_str()) else {
        // File not in graph — return a trivial single-node path
        return PropagationPath {
            hops: vec![PropagationHop {
                node: origin.clone(),
                edge_label: String::new(),
            }],
            aggregate_risk: 0.0,
            macro_goal: None,
            anchored_to_slo: false,
        };
    };

    // ── Phase 2: BFS across static + runtime edges ────────────────────────
    // Each entry tracks the predecessor position in visited_order, the
    // human-readable edge label, and the cumulative no-failure probability
    // (risk = 1 - no_fail_prob at the anchor).

    struct BfsEntry {
        predecessor: Option<usize>, // index into `visited_order`
        edge_kind: String,
        no_fail_prob: f64,
    }

    let mut visited: HashSet<petgraph::graph::NodeIndex> = HashSet::new();
    let mut queue: VecDeque<petgraph::graph::NodeIndex> = VecDeque::new();
    let mut node_data: HashMap<petgraph::graph::NodeIndex, BfsEntry> = HashMap::new();
    let mut visited_order: Vec<petgraph::graph::NodeIndex> = Vec::new();

    visited.insert(origin_idx);
    queue.push_back(origin_idx);
    node_data.insert(
        origin_idx,
        BfsEntry {
            predecessor: None,
            edge_kind: String::new(),
            no_fail_prob: 1.0,
        },
    );
    visited_order.push(origin_idx);

    // Anchor candidates in priority order:
    //   best_slo        — SLO node (highest: ties finding to a concrete availability target)
    //   best_entrypoint — RemoteService or inferred entrypoint file (fallback)
    let mut best_slo: Option<(petgraph::graph::NodeIndex, f64, String)> = None;
    let mut best_entrypoint: Option<(petgraph::graph::NodeIndex, f64, String)> = None;

    while let Some(current) = queue.pop_front() {
        let current_no_fail = node_data[&current].no_fail_prob;

        // --- Reverse propagation: walk *incoming* Calls/Imports edges ---
        // "If current breaks, callers and importers of current are affected."
        // Imports edge: A→B means "A imports B". Incoming to B = files that import B.
        // Calls edge: fn_A→fn_B. Incoming to B = functions that call B.
        for edge in graph.graph.edges_directed(current, Direction::Incoming) {
            let edge_label = match edge.weight() {
                GraphEdgeKind::Calls => "called by",
                GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. } => "imported by",
                _ => continue,
            };
            let weight = edge_weight(edge.weight());

            let next_idx = edge.source(); // source of incoming edge = the dependent
            if visited.contains(&next_idx) {
                continue;
            }

            let next_no_fail = current_no_fail * (1.0 - weight);
            let predecessor_pos = visited_order
                .iter()
                .position(|&x| x == current)
                .unwrap_or(0);

            visited.insert(next_idx);
            visited_order.push(next_idx);
            node_data.insert(
                next_idx,
                BfsEntry {
                    predecessor: Some(predecessor_pos),
                    edge_kind: edge_label.to_string(),
                    no_fail_prob: next_no_fail,
                },
            );
            queue.push_back(next_idx);

            // Check if this is an entrypoint (no importers means it's a root)
            if let GraphNode::File { path, .. } = &graph.graph[next_idx] {
                let has_importers = graph
                    .graph
                    .edges_directed(next_idx, Direction::Incoming)
                    .any(|e| {
                        matches!(
                            e.weight(),
                            GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. }
                        )
                    });
                if !has_importers
                    && best_entrypoint
                        .as_ref()
                        .is_none_or(|(_, p, _)| next_no_fail < *p)
                {
                    best_entrypoint = Some((next_idx, next_no_fail, path.clone()));
                }
            }
        }

        // --- Forward: Contains (File → Function), then MonitoredBy / RemoteCall ---
        //
        // `Contains` edges link a File node to its Function/Class children.
        // We traverse them with weight 0.0 (no additional risk — a function
        // failing is the same blast as the file failing) so that we can
        // subsequently follow MonitoredBy or RemoteCall edges from function
        // nodes. Without this, a finding in `app/main.py` would never reach
        // the SLO linked to the `@app.get("/")` handler inside that file.
        //
        // MonitoredBy edges were added by SloEnricher (GCP/Datadog/Dynatrace).
        // RemoteCall edges were added by TraceEnricher (GCP Cloud Trace).
        // Slo/RemoteService targets are terminal — not enqueued further.
        for edge in graph.graph.edges_directed(current, Direction::Outgoing) {
            let edge_label: &str = match edge.weight() {
                GraphEdgeKind::Contains => "contains",
                GraphEdgeKind::MonitoredBy => "monitored by",
                GraphEdgeKind::RemoteCall => "calls remote",
                _ => continue,
            };
            let weight = edge_weight(edge.weight());

            let next_idx = edge.target();
            if visited.contains(&next_idx) {
                continue;
            }

            let next_no_fail = current_no_fail * (1.0 - weight);
            let predecessor_pos = visited_order
                .iter()
                .position(|&x| x == current)
                .unwrap_or(0);

            visited.insert(next_idx);
            visited_order.push(next_idx);
            node_data.insert(
                next_idx,
                BfsEntry {
                    predecessor: Some(predecessor_pos),
                    edge_kind: edge_label.to_string(),
                    no_fail_prob: next_no_fail,
                },
            );

            match &graph.graph[next_idx] {
                GraphNode::Slo { name, .. } => {
                    let slo_name = name.clone();
                    if best_slo.as_ref().is_none_or(|(_, p, _)| next_no_fail < *p) {
                        best_slo = Some((next_idx, next_no_fail, slo_name));
                    }
                    // Terminal — don't enqueue
                }
                GraphNode::RemoteService { name, .. } => {
                    // RemoteService is a cross-service anchor sourced from
                    // runtime traces. It ranks above an inferred entrypoint
                    // because it represents a real observed dependency rather
                    // than a structural inference. Stored as best_entrypoint
                    // so that it wins over file-based fallbacks but yields to
                    // any SLO node found in the same traversal.
                    let svc_label = format!("remote:{}", name);
                    if best_entrypoint
                        .as_ref()
                        .is_none_or(|(_, p, _)| next_no_fail < *p)
                    {
                        best_entrypoint = Some((next_idx, next_no_fail, svc_label));
                    }
                    // Terminal — RemoteService nodes have no outgoing edges
                }
                _ => {
                    // For any other node reachable via these edges, continue BFS
                    queue.push_back(next_idx);
                }
            }
        }
    }

    // ── Phase 3: Select anchor and reconstruct path ───────────────────────
    // Priority: SLO > RemoteService/entrypoint file > no anchor.

    let (anchor_idx, anchor_risk_no_fail, macro_goal, anchored_to_slo) =
        if let Some((idx, p, name)) = best_slo {
            (Some(idx), p, Some(name), true)
        } else if let Some((idx, p, path)) = best_entrypoint {
            (Some(idx), p, Some(path), false)
        } else {
            (None, 1.0_f64, None, false)
        };

    let aggregate_risk = (1.0 - anchor_risk_no_fail) * 100.0;

    // Reconstruct path from origin → anchor by following predecessors
    let mut path_nodes: Vec<petgraph::graph::NodeIndex> = Vec::new();
    if let Some(anchor) = anchor_idx {
        let mut current = anchor;
        loop {
            path_nodes.push(current);
            let entry = &node_data[&current];
            if let Some(pred_pos) = entry.predecessor {
                current = visited_order[pred_pos];
            } else {
                break;
            }
            if current == origin_idx {
                path_nodes.push(origin_idx);
                break;
            }
        }
        path_nodes.reverse();
    } else {
        path_nodes.push(origin_idx);
    }

    // Cap at 5 hops for display
    path_nodes.truncate(5);

    // Build hops with edge labels
    let hops: Vec<PropagationHop> = path_nodes
        .iter()
        .enumerate()
        .map(|(i, &idx)| {
            let node_name = match &graph.graph[idx] {
                GraphNode::File { path, .. } => path.clone(),
                GraphNode::Slo { name, .. } => format!("SLO: {}", name),
                GraphNode::RemoteService { name, .. } => format!("remote:{}", name),
                other => other.display_name(),
            };
            let edge_label = if i == 0 {
                String::new()
            } else {
                node_data
                    .get(&idx)
                    .map(|e| e.edge_kind.clone())
                    .unwrap_or_default()
            };
            PropagationHop {
                node: node_name,
                edge_label,
            }
        })
        .collect();

    PropagationPath {
        hops,
        aggregate_risk: aggregate_risk.clamp(0.0, 100.0),
        macro_goal,
        anchored_to_slo,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphEdgeKind, GraphNode};
    use crate::parse::ast::FileId;
    use crate::types::context::{Dimension, Language};
    use crate::types::finding::{Finding, FindingKind, Severity};

    fn make_finding(file: &str) -> Finding {
        Finding {
            id: "f1".to_string(),
            rule_id: "python.http.missing_timeout".to_string(),
            kind: FindingKind::StabilityRisk,
            title: "Missing timeout".to_string(),
            description: "No timeout on HTTP call".to_string(),
            severity: Severity::Medium,
            confidence: 0.9,
            dimension: Dimension::Reliability,
            file_path: file.to_string(),
            line: Some(10),
            column: None,
            end_line: None,
            end_column: None,
            byte_range: None,
            diff: None,
            fix_preview: None,
            applicability: None,
        }
    }

    fn build_test_graph() -> CodeGraph {
        let mut graph = CodeGraph::new();

        // db.py → auth.py → main.py (entrypoint)
        let f_db = graph.graph.add_node(GraphNode::File {
            file_id: FileId(1),
            path: "src/db.py".to_string(),
            language: Language::Python,
        });
        graph.file_nodes.insert(FileId(1), f_db);
        graph.path_to_file.insert("src/db.py".to_string(), f_db);

        let f_auth = graph.graph.add_node(GraphNode::File {
            file_id: FileId(2),
            path: "src/auth.py".to_string(),
            language: Language::Python,
        });
        graph.file_nodes.insert(FileId(2), f_auth);
        graph.path_to_file.insert("src/auth.py".to_string(), f_auth);

        let f_main = graph.graph.add_node(GraphNode::File {
            file_id: FileId(3),
            path: "src/main.py".to_string(),
            language: Language::Python,
        });
        graph.file_nodes.insert(FileId(3), f_main);
        graph.path_to_file.insert("src/main.py".to_string(), f_main);

        // main imports auth, auth imports db
        graph.graph.add_edge(f_auth, f_db, GraphEdgeKind::Imports);
        graph.graph.add_edge(f_main, f_auth, GraphEdgeKind::Imports);

        graph
    }

    #[test]
    fn propagation_reaches_entrypoint() {
        let graph = build_test_graph();
        let finding = make_finding("src/db.py");
        let path = compute_propagation(&finding, &graph);

        // Should reach main.py (which has no importers)
        assert!(path.macro_goal.is_some());
        assert!(
            path.macro_goal.as_deref().unwrap().contains("main.py"),
            "macro_goal should contain main.py, got {:?}",
            path.macro_goal
        );
        assert!(!path.anchored_to_slo);
        assert!(path.aggregate_risk > 0.0);
    }

    #[test]
    fn isolated_file_has_zero_risk() {
        let mut graph = CodeGraph::new();
        let f = graph.graph.add_node(GraphNode::File {
            file_id: FileId(99),
            path: "isolated.py".to_string(),
            language: Language::Python,
        });
        graph.file_nodes.insert(FileId(99), f);
        graph.path_to_file.insert("isolated.py".to_string(), f);

        let finding = make_finding("isolated.py");
        let path = compute_propagation(&finding, &graph);
        assert_eq!(path.aggregate_risk, 0.0);
        assert!(path.macro_goal.is_none());
    }

    #[test]
    fn unknown_file_returns_trivial_path() {
        let graph = build_test_graph();
        let finding = make_finding("nonexistent.py");
        let path = compute_propagation(&finding, &graph);
        assert_eq!(path.hops.len(), 1);
        assert_eq!(path.hops[0].node, "nonexistent.py");
    }

    #[test]
    fn risk_increases_with_hops() {
        let graph = build_test_graph();

        // db.py is 2 hops from main.py
        let p_db = compute_propagation(&make_finding("src/db.py"), &graph);
        // auth.py is 1 hop from main.py
        let p_auth = compute_propagation(&make_finding("src/auth.py"), &graph);

        // Both should reach main.py
        assert!(p_db.macro_goal.is_some());
        assert!(p_auth.macro_goal.is_some());

        // auth.py has higher risk (single hop * 0.5) vs db.py (two hops)
        // risk(auth→main) = 1 - (1-0.5) = 0.5 = 50%
        // risk(db→auth→main) = 1 - (1-0.5)*(1-0.5) = 0.75 = 75%
        // So db.py should have HIGHER risk (more hops = more propagation)
        assert!(
            p_db.aggregate_risk >= p_auth.aggregate_risk,
            "db.py risk ({:.1}) should be >= auth.py risk ({:.1})",
            p_db.aggregate_risk,
            p_auth.aggregate_risk
        );
    }
}
