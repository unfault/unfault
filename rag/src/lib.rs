//! unfault-rag: RAG (Retrieval-Augmented Generation) engine
//!
//! This crate provides the RAG functionality for unfault, including:
//! - LanceDB vector storage for embeddings
//! - Embedding generation via OpenAI/Ollama
//! - Semantic search over findings
//! - Query intent classification and routing
//! - Graph-based retrieval (flow, impact, dependencies, centrality)
//!
//! # Architecture
//!
//! The RAG system has three layers:
//!
//! 1. **Graph-based retrieval** - Fast path using in-memory CodeGraph for
//!    flow analysis, impact analysis, enumeration, and workspace overview.
//!    No embeddings needed.
//!
//! 2. **Vector search** - Semantic similarity search over embedded findings
//!    using LanceDB. Requires an embedding provider.
//!
//! 3. **LLM synthesis** - Optional LLM call to synthesize a natural language
//!    response from retrieved context (done by the CLI, not this crate).
//!
//! # Example
//!
//! ```ignore
//! use unfault_rag::{query, QueryConfig};
//! use unfault_analysis::graph::CodeGraph;
//!
//! let graph = build_code_graph();
//! let config = QueryConfig::default();
//! let response = query::execute_query(
//!     "what breaks if I change auth.py?",
//!     Some(&graph), None, None, &config,
//! ).await?;
//! ```

pub mod embeddings;
pub mod error;
pub mod query;
pub mod retrieval;
pub mod routing;
pub mod store;
pub mod types;

// Re-export main types
pub use error::RagError;
pub use query::{QueryConfig, execute_query};
pub use store::VectorStore;
pub use types::{RagQuery, RagResponse, RouteIntent};
