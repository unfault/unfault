//! unfault-rag: RAG (Retrieval-Augmented Generation) engine
//!
//! This crate provides the RAG functionality for unfault, including:
//! - LanceDB vector storage for embeddings
//! - Embedding generation via OpenAI/Ollama
//! - Semantic search over findings
//! - Query intent classification
//!
//! # Example
//!
//! ```ignore
//! use unfault_rag::RagEngine;
//!
//! let rag = RagEngine::new(".unfault/vectors.lance")?;
//! let results = rag.query("What are the security issues?").await?;
//! ```

// Re-export analysis types for convenience
pub use unfault_analysis::{CodeGraph, Engine as AnalysisEngine, FileId, SourceSemantics};

// Modules will be added as we port from API:
// pub mod vector_store;
// pub mod embeddings;
// pub mod query;
// pub mod intent;

/// Placeholder for the RAG engine
pub struct RagEngine;

impl RagEngine {
    /// Create a new RAG engine
    pub fn new() -> Self {
        Self
    }
}

impl Default for RagEngine {
    fn default() -> Self {
        Self::new()
    }
}
