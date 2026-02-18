//! Embedding providers for generating vector representations of text.
//!
//! Supports OpenAI-compatible APIs (including Ollama) for embedding generation.

mod provider;
mod content;

pub use provider::{EmbeddingProvider, OllamaProvider, OpenAiProvider};
pub use content::build_finding_content;
