//! Types and utilities used by the CLI.
//!
//! - `graph` - Analysis result types (IrFinding, IrAnalyzeResponse, etc.)
//! - `llm` - LLM client for BYOLLM (Bring Your Own LLM)

pub mod graph;
pub mod llm;

pub use graph::*;
pub use llm::{LlmClient, LlmError};
