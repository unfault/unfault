//! Graph-based retrieval for RAG queries.
//!
//! Provides fast-path answers using the in-memory CodeGraph for:
//! - Flow/trace analysis (BFS traversal)
//! - Impact analysis (reverse BFS)
//! - Dependency analysis
//! - Centrality computation
//! - Enumeration (counting routes, functions, etc.)
//! - Workspace overview

pub mod graph_queries;

pub use graph_queries::{
    enumerate_entities, extract_flow, get_centrality, get_dependencies, get_impact,
    workspace_overview,
};
