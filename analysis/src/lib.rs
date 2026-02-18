//! unfault-analysis: Rule evaluation and analysis engine
//!
//! This crate provides the rule evaluation engine for unfault, including:
//! - 196 built-in rules across Python, Go, Rust, and TypeScript
//! - Profile-based rule selection
//! - Session orchestration for analysis runs
//!
//! # Example
//!
//! ```ignore
//! use unfault_analysis::Engine;
//!
//! let engine = Engine::new();
//! let results = engine.analyze(&files, &profiles).await?;
//! ```

// Re-export core types for convenience
pub use unfault_core::{
    graph::CodeGraph,
    parse::ast::FileId,
    semantics::SourceSemantics,
    types::context::{Language, SourceFile},
    IntermediateRepresentation,
};

// Modules will be added as we port from engine:
// pub mod rules;
// pub mod profiles;
// pub mod engine;
// pub mod session;

/// Placeholder for the analysis engine
pub struct Engine;

impl Engine {
    /// Create a new analysis engine with default configuration
    pub fn new() -> Self {
        Self
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}
