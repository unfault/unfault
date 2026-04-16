//! Ranker — composite importance scoring for files in the code graph.
//!
//! This module formalizes the concept of "Critical Hub" files: files whose
//! failure would have the largest systemic blast radius. It goes beyond simple
//! in-degree centrality by combining three independent signals:
//!
//! 1. **Centrality** (0–1): How many other files import this file, normalized
//!    by the maximum in-degree in the graph. Captures structural SPOFs.
//!
//! 2. **Library risk** (0–1): How many high-risk external dependencies
//!    (`HttpClient`, `Database`) this file uses. Files that are both central
//!    AND call external services are doubly dangerous — a slow DB call here
//!    freezes everyone upstream.
//!
//! 3. **Finding density** (0–1): What fraction of all findings land in this
//!    file, normalized. Files that concentrate many known issues need the most
//!    attention.
//!
//! # Composite Score
//!
//! ```text
//! importance = centrality * 0.50
//!            + library_risk * 0.30
//!            + finding_density * 0.20
//! ```
//!
//! The weights reflect the System Design Interview principle: structural
//! position (centrality) is the primary predictor of blast radius; external
//! risk amplifies it; and known finding density provides a density-of-debt
//! signal independent of graph structure.
//!
//! # Output
//!
//! `rank_files()` returns `Vec<RankedFile>` sorted descending by score.
//! Each entry includes the decomposed sub-scores for explainability.

use std::collections::HashMap;

use petgraph::visit::EdgeRef;
use petgraph::Direction;
use serde::{Deserialize, Serialize};

use crate::graph::{CodeGraph, GraphEdgeKind, GraphNode, ModuleCategory};
use crate::types::finding::Finding;

/// A single file with its composite importance score and sub-scores.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedFile {
    /// Absolute or repo-relative file path.
    pub file_path: String,
    /// Composite importance score in [0.0, 1.0].
    pub importance_score: f64,
    /// Normalized in-degree (import count / max import count).
    pub centrality_score: f64,
    /// Normalized high-risk library usage.
    pub library_risk_score: f64,
    /// Normalized finding density (findings_in_file / max_findings_in_any_file).
    pub finding_density_score: f64,
    /// Raw in-degree count.
    pub in_degree: usize,
    /// Count of HttpClient or Database external libraries used.
    pub risky_library_count: usize,
    /// Number of findings in this file.
    pub finding_count: usize,
}

/// Rank all files in the graph by composite importance score.
///
/// `findings` may be empty — in that case the finding density component is
/// zero for all files, and ranking is purely graph-structural.
pub fn rank_files(graph: &CodeGraph, findings: &[Finding]) -> Vec<RankedFile> {
    // ── Step 1: compute raw per-file metrics ──────────────────────────────

    struct RawMetrics {
        in_degree: usize,
        risky_library_count: usize,
        finding_count: usize,
    }

    let mut per_file: HashMap<String, RawMetrics> = HashMap::new();

    // a) Graph-structural metrics from node iteration
    for idx in graph.graph.node_indices() {
        let node = &graph.graph[idx];
        let GraphNode::File { path, .. } = node else {
            continue;
        };

        let in_degree = graph
            .graph
            .edges_directed(idx, Direction::Incoming)
            .filter(|e| {
                matches!(
                    e.weight(),
                    GraphEdgeKind::Imports | GraphEdgeKind::ImportsFrom { .. }
                )
            })
            .count();

        // Count outbound UsesLibrary edges to HttpClient or Database modules
        let risky_library_count = graph
            .graph
            .edges_directed(idx, Direction::Outgoing)
            .filter(|e| matches!(e.weight(), GraphEdgeKind::UsesLibrary))
            .filter(|e| {
                matches!(
                    &graph.graph[e.target()],
                    GraphNode::ExternalModule {
                        category: ModuleCategory::HttpClient,
                        ..
                    } | GraphNode::ExternalModule {
                        category: ModuleCategory::Database,
                        ..
                    }
                )
            })
            .count();

        per_file.insert(
            path.clone(),
            RawMetrics {
                in_degree,
                risky_library_count,
                finding_count: 0, // filled below
            },
        );
    }

    // b) Finding density: count findings per file
    for finding in findings {
        if let Some(metrics) = per_file.get_mut(&finding.file_path) {
            metrics.finding_count += 1;
        }
    }

    // ── Step 2: compute normalization denominators ─────────────────────────

    let max_in_degree = per_file.values().map(|m| m.in_degree).max().unwrap_or(1);
    let max_risky = per_file
        .values()
        .map(|m| m.risky_library_count)
        .max()
        .unwrap_or(1);
    let max_findings = per_file
        .values()
        .map(|m| m.finding_count)
        .max()
        .unwrap_or(1);

    // Avoid division by zero if all values are 0
    let max_in_degree = max_in_degree.max(1);
    let max_risky = max_risky.max(1);
    let max_findings = max_findings.max(1);

    // ── Step 3: compute composite scores and build output ─────────────────

    let mut ranked: Vec<RankedFile> = per_file
        .into_iter()
        .map(|(file_path, m)| {
            let centrality_score = m.in_degree as f64 / max_in_degree as f64;
            let library_risk_score = m.risky_library_count as f64 / max_risky as f64;
            let finding_density_score = m.finding_count as f64 / max_findings as f64;

            let importance_score =
                centrality_score * 0.50 + library_risk_score * 0.30 + finding_density_score * 0.20;

            RankedFile {
                file_path,
                importance_score,
                centrality_score,
                library_risk_score,
                finding_density_score,
                in_degree: m.in_degree,
                risky_library_count: m.risky_library_count,
                finding_count: m.finding_count,
            }
        })
        .collect();

    // Sort: descending importance, then alphabetical for stable output
    ranked.sort_by(|a, b| {
        b.importance_score
            .partial_cmp(&a.importance_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.file_path.cmp(&b.file_path))
    });

    ranked
}

/// Return only the top-N files by importance score.
pub fn top_n(graph: &CodeGraph, findings: &[Finding], n: usize) -> Vec<RankedFile> {
    let mut all = rank_files(graph, findings);
    all.truncate(n);
    all
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{GraphEdgeKind, GraphNode};
    use crate::parse::ast::FileId;
    use crate::types::context::Language;

    fn build_test_graph() -> CodeGraph {
        let mut graph = CodeGraph::new();

        let f1 = graph.graph.add_node(GraphNode::File {
            file_id: FileId(1),
            path: "src/main.py".to_string(),
            language: Language::Python,
        });
        graph.file_nodes.insert(FileId(1), f1);
        graph.path_to_file.insert("src/main.py".to_string(), f1);

        let f2 = graph.graph.add_node(GraphNode::File {
            file_id: FileId(2),
            path: "src/auth.py".to_string(),
            language: Language::Python,
        });
        graph.file_nodes.insert(FileId(2), f2);
        graph.path_to_file.insert("src/auth.py".to_string(), f2);

        let f3 = graph.graph.add_node(GraphNode::File {
            file_id: FileId(3),
            path: "src/db.py".to_string(),
            language: Language::Python,
        });
        graph.file_nodes.insert(FileId(3), f3);
        graph.path_to_file.insert("src/db.py".to_string(), f3);

        // main and auth both import db → db has in_degree = 2
        graph.graph.add_edge(f1, f3, GraphEdgeKind::Imports);
        graph.graph.add_edge(f2, f3, GraphEdgeKind::Imports);

        // Add a Database external module that db.py uses
        let ext = graph.graph.add_node(GraphNode::ExternalModule {
            name: "sqlalchemy".to_string(),
            category: ModuleCategory::Database,
        });
        graph.external_modules.insert("sqlalchemy".to_string(), ext);
        graph.graph.add_edge(f3, ext, GraphEdgeKind::UsesLibrary);

        graph
    }

    #[test]
    fn db_is_ranked_highest() {
        let graph = build_test_graph();
        let ranked = rank_files(&graph, &[]);

        // db.py should be #1: highest in_degree (2) and uses a DB library
        assert_eq!(ranked[0].file_path, "src/db.py");
        assert!(ranked[0].importance_score > 0.0);
    }

    #[test]
    fn finding_density_shifts_rank() {
        use crate::types::context::Dimension;
        use crate::types::finding::{FindingKind, Severity};

        let graph = build_test_graph();

        // Give main.py many findings → should lift its rank
        let findings: Vec<Finding> = (0..5)
            .map(|i| Finding {
                id: format!("f{}", i),
                rule_id: "test.rule".to_string(),
                kind: FindingKind::StabilityRisk,
                title: "test".to_string(),
                description: "test".to_string(),
                severity: Severity::Medium,
                confidence: 0.9,
                dimension: Dimension::Reliability,
                file_path: "src/main.py".to_string(),
                line: None,
                column: None,
                end_line: None,
                end_column: None,
                byte_range: None,
                diff: None,
                fix_preview: None,
                applicability: None,
            })
            .collect();

        let ranked = rank_files(&graph, &findings);

        // db.py still top due to centrality, but main.py should be higher
        // than auth.py (which has no findings)
        let main_rank = ranked.iter().position(|r| r.file_path == "src/main.py");
        let auth_rank = ranked.iter().position(|r| r.file_path == "src/auth.py");
        assert!(main_rank.unwrap() < auth_rank.unwrap());
    }

    #[test]
    fn top_n_truncates() {
        let graph = build_test_graph();
        let top = top_n(&graph, &[], 2);
        assert_eq!(top.len(), 2);
    }

    #[test]
    fn empty_graph_does_not_panic() {
        let graph = CodeGraph::new();
        let ranked = rank_files(&graph, &[]);
        assert!(ranked.is_empty());
    }
}
