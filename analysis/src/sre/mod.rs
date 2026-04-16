//! SRE Synthesis — Pass 3 of the analysis pipeline.
//!
//! This module provides the "SRE hat" layer that runs after all rules have
//! fired (Pass 2). It consumes the flat `Finding` list and the `CodeGraph`
//! to produce `SystemHazard` entries: findings enriched with cross-file
//! blast radius context and SRE failure-mode classification.
//!
//! # Design
//!
//! The synthesis is intentionally a **lookup-and-tag** operation:
//! - Rule IDs are matched to failure modes via a static prefix table.
//! - Blast radius is computed with a single BFS per qualifying finding.
//! - The tree-sitter traversal in Passes 1–2 remains the performance bottleneck.
//!
//! # Glossary
//!
//! The `glossary` sub-module contains a static `OnceLock<HashMap>` with the
//! five canonical SRE failure mode entries. It is used both by the synthesizer
//! (for `aka` strings) and by the `unfault info <id>` CLI command (full text).

pub mod glossary;
pub mod ranker;
pub mod synthesizer;
pub mod world_model;

pub use glossary::{GlossaryEntry, lookup as lookup_glossary};
pub use ranker::{RankedFile, rank_files, top_n};
pub use synthesizer::synthesize;
pub use world_model::{PropagationHop, PropagationPath, compute_propagation};
