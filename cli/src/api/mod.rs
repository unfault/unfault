//! # API Module
//!
//! Contains the LLM client for BYOLLM (Bring Your Own LLM) and
//! legacy types used by the CLI for output formatting.

pub mod client;
pub mod graph;
pub mod llm;
pub mod rag;

// Re-export commonly used types
pub use client::{ApiClient, ApiError};
pub use graph::*;
pub use llm::{LlmClient, LlmError};
pub use rag::*;
