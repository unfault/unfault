//! Embedding provider trait and implementations.
//!
//! Supports OpenAI and Ollama embedding APIs. Both use the same OpenAI-compatible
//! interface, so the main difference is authentication.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::RagError;

/// Trait for embedding providers that convert text to vectors.
#[async_trait]
pub trait EmbeddingProvider: Send + Sync {
    /// Generate an embedding for a single text.
    async fn embed(&self, text: &str) -> Result<Vec<f32>, RagError>;

    /// Generate embeddings for a batch of texts.
    async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, RagError>;

    /// Return the dimensionality of embeddings produced.
    fn dimensions(&self) -> usize;

    /// Return the model name.
    fn model_name(&self) -> &str;
}

#[derive(Debug, Serialize)]
struct EmbeddingRequest {
    model: String,
    input: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
}

#[derive(Debug, Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
}

/// OpenAI embedding provider.
///
/// Works with OpenAI's API and any compatible endpoint.
pub struct OpenAiProvider {
    client: reqwest::Client,
    endpoint: String,
    api_key: String,
    model: String,
    dims: usize,
}

impl OpenAiProvider {
    /// Create a new OpenAI provider.
    ///
    /// # Arguments
    /// * `api_key` - OpenAI API key
    /// * `model` - Model name (e.g., "text-embedding-3-small")
    /// * `endpoint` - API endpoint (defaults to "https://api.openai.com/v1")
    /// * `dims` - Embedding dimensions (1536 for text-embedding-3-small)
    pub fn new(
        api_key: String,
        model: String,
        endpoint: Option<String>,
        dims: Option<usize>,
    ) -> Self {
        let dims = dims.unwrap_or(1536);
        Self {
            client: reqwest::Client::new(),
            endpoint: endpoint.unwrap_or_else(|| "https://api.openai.com/v1".to_string()),
            api_key,
            model,
            dims,
        }
    }
}

#[async_trait]
impl EmbeddingProvider for OpenAiProvider {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, RagError> {
        let results = self.embed_batch(&[text.to_string()]).await?;
        results
            .into_iter()
            .next()
            .ok_or_else(|| RagError::Embedding("Empty response from OpenAI".to_string()))
    }

    async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, RagError> {
        let url = format!("{}/embeddings", self.endpoint);
        let request = EmbeddingRequest {
            model: self.model.clone(),
            input: texts.to_vec(),
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_key))
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(RagError::Embedding(format!(
                "OpenAI API error {status}: {body}"
            )));
        }

        let result: EmbeddingResponse = response.json().await?;
        Ok(result.data.into_iter().map(|d| d.embedding).collect())
    }

    fn dimensions(&self) -> usize {
        self.dims
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

/// Ollama embedding provider.
///
/// Uses Ollama's local API which is OpenAI-compatible for embeddings.
pub struct OllamaProvider {
    client: reqwest::Client,
    endpoint: String,
    model: String,
    dims: usize,
}

#[derive(Debug, Serialize)]
struct OllamaEmbeddingRequest {
    model: String,
    input: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OllamaEmbeddingResponse {
    embeddings: Vec<Vec<f32>>,
}

impl OllamaProvider {
    /// Create a new Ollama provider.
    ///
    /// # Arguments
    /// * `model` - Model name (e.g., "nomic-embed-text")
    /// * `endpoint` - Ollama endpoint (defaults to "http://localhost:11434")
    /// * `dims` - Embedding dimensions (768 for nomic-embed-text)
    pub fn new(model: String, endpoint: Option<String>, dims: Option<usize>) -> Self {
        let dims = dims.unwrap_or(768);
        Self {
            client: reqwest::Client::new(),
            endpoint: endpoint.unwrap_or_else(|| "http://localhost:11434".to_string()),
            model,
            dims,
        }
    }
}

#[async_trait]
impl EmbeddingProvider for OllamaProvider {
    async fn embed(&self, text: &str) -> Result<Vec<f32>, RagError> {
        let results = self.embed_batch(&[text.to_string()]).await?;
        results
            .into_iter()
            .next()
            .ok_or_else(|| RagError::Embedding("Empty response from Ollama".to_string()))
    }

    async fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, RagError> {
        let url = format!("{}/api/embed", self.endpoint);
        let request = OllamaEmbeddingRequest {
            model: self.model.clone(),
            input: texts.to_vec(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(RagError::Embedding(format!(
                "Ollama API error {status}: {body}"
            )));
        }

        let result: OllamaEmbeddingResponse = response.json().await?;
        Ok(result.embeddings)
    }

    fn dimensions(&self) -> usize {
        self.dims
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_provider_creation() {
        let provider = OpenAiProvider::new(
            "test-key".to_string(),
            "text-embedding-3-small".to_string(),
            None,
            None,
        );
        assert_eq!(provider.dimensions(), 1536);
        assert_eq!(provider.model_name(), "text-embedding-3-small");
    }

    #[test]
    fn test_ollama_provider_creation() {
        let provider = OllamaProvider::new("nomic-embed-text".to_string(), None, None);
        assert_eq!(provider.dimensions(), 768);
        assert_eq!(provider.model_name(), "nomic-embed-text");
    }

    #[test]
    fn test_openai_provider_custom_endpoint() {
        let provider = OpenAiProvider::new(
            "key".to_string(),
            "custom-model".to_string(),
            Some("http://custom:8080/v1".to_string()),
            Some(384),
        );
        assert_eq!(provider.dimensions(), 384);
        assert_eq!(provider.endpoint, "http://custom:8080/v1");
    }
}
