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
//! let engine = Engine::with_default_config();
//! let results = engine.analyze(&meta, contexts).await?;
//! ```

// Internal modules (from engine - will harmonize with core later)
pub mod dependencies;
pub mod graph;
pub mod parse;
pub mod semantics;
pub mod types;

// Analysis-specific modules
pub mod config;
pub mod engine;
pub mod error;
pub mod ir;
pub mod profiles;
pub mod rules;
pub mod session;
pub mod suppression;

// Re-export commonly used types
pub use graph::CodeGraph;
pub use parse::ast::FileId;
pub use semantics::SourceSemantics;
pub use types::context::{Dimension, Language, SessionContextInput, SourceFile};
pub use types::finding::{Finding, FindingApplicability, FindingKind, Severity};
pub use types::meta::ReviewSessionMeta;
pub use types::session_result::{ContextResult, ReviewSessionResult};

// Re-export main engine types
pub use config::EngineConfig;
pub use engine::Engine;
pub use error::EngineError;
pub use profiles::ProfileRegistry;
pub use rules::Rule;
pub use rules::registry::RuleRegistry;
