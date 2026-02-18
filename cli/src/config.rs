//! # Configuration Management
//!
//! This module handles loading and saving CLI configuration.
//!
//! ## Configuration File Location
//!
//! All platforms: `$HOME/.config/unfault/config.json`
//!
//! On Windows, uses `%USERPROFILE%\.config\unfault\config.json` if `$HOME` is not set.
//!
//! ## Configuration Sections
//!
//! - **llm**: LLM provider for AI-powered insights (OpenAI, Anthropic, Ollama, custom)
//! - **embeddings**: Embedding provider for RAG semantic search (OpenAI, Ollama)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// LLM configuration for AI-powered insights.
///
/// # Supported Providers
///
/// - `openai`: OpenAI API (GPT-4o, o3, etc.)
/// - `anthropic`: Anthropic API (Claude)
/// - `ollama`: Local Ollama instance
/// - `custom`: Any OpenAI-compatible endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Provider name (openai, anthropic, ollama, custom)
    pub provider: String,
    /// API endpoint URL
    pub endpoint: String,
    /// Model name (e.g., gpt-4o, claude-sonnet-4-20250514)
    pub model: String,
    /// API key (plaintext)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Environment variable name for API key (preferred over api_key)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
}

impl LlmConfig {
    /// Create a new OpenAI configuration.
    pub fn openai(model: &str) -> Self {
        Self {
            provider: "openai".to_string(),
            endpoint: "https://api.openai.com/v1".to_string(),
            model: model.to_string(),
            api_key: None,
            api_key_env: Some("OPENAI_API_KEY".to_string()),
        }
    }

    /// Create a new Anthropic configuration.
    pub fn anthropic(model: &str) -> Self {
        Self {
            provider: "anthropic".to_string(),
            endpoint: "https://api.anthropic.com/v1".to_string(),
            model: model.to_string(),
            api_key: None,
            api_key_env: Some("ANTHROPIC_API_KEY".to_string()),
        }
    }

    /// Create a new Ollama configuration.
    pub fn ollama(endpoint: &str, model: &str) -> Self {
        Self {
            provider: "ollama".to_string(),
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            api_key: None,
            api_key_env: None,
        }
    }

    /// Create a custom configuration.
    pub fn custom(endpoint: &str, model: &str) -> Self {
        Self {
            provider: "custom".to_string(),
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            api_key: None,
            api_key_env: None,
        }
    }

    /// Get the API key from environment or config.
    pub fn get_api_key(&self) -> Option<String> {
        if let Some(ref env_var) = self.api_key_env {
            if let Ok(key) = std::env::var(env_var) {
                return Some(key);
            }
        }
        self.api_key.clone()
    }

    /// Check if the LLM is configured and ready to use.
    pub fn is_ready(&self) -> bool {
        if self.provider == "ollama" {
            return true;
        }
        self.get_api_key().is_some()
    }

    /// Get a masked version of the API key for display.
    pub fn masked_api_key(&self) -> Option<String> {
        self.get_api_key().map(|key| {
            if key.len() > 8 {
                format!("{}...{}", &key[..4], &key[key.len() - 4..])
            } else {
                "****".to_string()
            }
        })
    }
}

/// Embedding provider configuration for RAG semantic search.
///
/// # Supported Providers
///
/// - `openai`: OpenAI embeddings (text-embedding-3-small, etc.)
/// - `ollama`: Local Ollama embeddings (nomic-embed-text, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingConfig {
    /// Provider name (openai, ollama)
    pub provider: String,
    /// API endpoint URL
    pub endpoint: String,
    /// Model name (e.g., text-embedding-3-small, nomic-embed-text)
    pub model: String,
    /// Embedding dimensions (provider/model dependent)
    #[serde(default = "default_embedding_dims")]
    pub dimensions: usize,
    /// API key (plaintext)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    /// Environment variable name for API key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_env: Option<String>,
}

fn default_embedding_dims() -> usize {
    1536
}

impl EmbeddingConfig {
    /// Create a new OpenAI embedding configuration.
    pub fn openai(model: &str, dims: usize) -> Self {
        Self {
            provider: "openai".to_string(),
            endpoint: "https://api.openai.com/v1".to_string(),
            model: model.to_string(),
            dimensions: dims,
            api_key: None,
            api_key_env: Some("OPENAI_API_KEY".to_string()),
        }
    }

    /// Create a new Ollama embedding configuration.
    pub fn ollama(endpoint: &str, model: &str, dims: usize) -> Self {
        Self {
            provider: "ollama".to_string(),
            endpoint: endpoint.to_string(),
            model: model.to_string(),
            dimensions: dims,
            api_key: None,
            api_key_env: None,
        }
    }

    /// Get the API key from environment or config.
    pub fn get_api_key(&self) -> Option<String> {
        if let Some(ref env_var) = self.api_key_env {
            if let Ok(key) = std::env::var(env_var) {
                return Some(key);
            }
        }
        self.api_key.clone()
    }

    /// Check if the embedding provider is configured and ready.
    pub fn is_ready(&self) -> bool {
        if self.provider == "ollama" {
            return true;
        }
        self.get_api_key().is_some()
    }
}

/// CLI configuration.
///
/// Stored at `~/.config/unfault/config.json`.
///
/// # Example
///
/// ```json
/// {
///   "llm": {
///     "provider": "ollama",
///     "endpoint": "http://localhost:11434",
///     "model": "llama3.2"
///   },
///   "embeddings": {
///     "provider": "ollama",
///     "endpoint": "http://localhost:11434",
///     "model": "nomic-embed-text",
///     "dimensions": 768
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// LLM configuration for AI-powered insights (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<LlmConfig>,

    /// Embedding configuration for RAG semantic search (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<EmbeddingConfig>,
}

impl Config {
    /// Create an empty configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the LLM configuration.
    pub fn with_llm(mut self, llm_config: LlmConfig) -> Self {
        self.llm = Some(llm_config);
        self
    }

    /// Set the embedding configuration.
    pub fn with_embeddings(mut self, embedding_config: EmbeddingConfig) -> Self {
        self.embeddings = Some(embedding_config);
        self
    }

    /// Remove the LLM configuration.
    pub fn remove_llm(&mut self) {
        self.llm = None;
    }

    /// Remove the embedding configuration.
    pub fn remove_embeddings(&mut self) {
        self.embeddings = None;
    }

    /// Check if LLM is configured.
    pub fn has_llm(&self) -> bool {
        self.llm.is_some()
    }

    /// Check if LLM is configured and ready to use.
    pub fn llm_ready(&self) -> bool {
        self.llm.as_ref().is_some_and(|l| l.is_ready())
    }

    /// Check if embeddings are configured and ready.
    pub fn embeddings_ready(&self) -> bool {
        self.embeddings.as_ref().is_some_and(|e| e.is_ready())
    }

    /// Load configuration from the default config file.
    ///
    /// Returns a default (empty) config if the file doesn't exist.
    pub fn load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        Ok(config)
    }

    /// Save configuration to the default config file.
    pub fn save(&self) -> Result<()> {
        let path = config_path()?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create config directory: {}", parent.display())
            })?;
        }

        let contents = serde_json::to_string_pretty(self).context("Failed to serialize config")?;
        fs::write(&path, contents)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;

        Ok(())
    }

    /// Check if a configuration file exists.
    pub fn exists() -> bool {
        config_path().map(|p| p.exists()).unwrap_or(false)
    }

    /// Delete the configuration file.
    pub fn delete() -> Result<()> {
        let path = config_path()?;
        if path.exists() {
            fs::remove_file(&path)
                .with_context(|| format!("Failed to delete config file: {}", path.display()))?;
        }
        Ok(())
    }

    /// Get the path to the config directory.
    pub fn config_dir() -> Result<PathBuf> {
        let dir = dirs_config_dir().context("Could not determine config directory")?;
        Ok(dir.join("unfault"))
    }
}

/// Get the path to the configuration file.
fn config_path() -> Result<PathBuf> {
    let config_dir = dirs_config_dir().context("Could not determine config directory")?;
    Ok(config_dir.join("unfault").join("config.json"))
}

/// Get the config directory.
///
/// Uses `$HOME/.config` on all platforms for consistency.
fn dirs_config_dir() -> Option<PathBuf> {
    std::env::var("XDG_CONFIG_HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .or_else(|| std::env::var("USERPROFILE").ok())
                .map(|h| PathBuf::from(h).join(".config"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::new();
        assert!(config.llm.is_none());
        assert!(config.embeddings.is_none());
        assert!(!config.llm_ready());
        assert!(!config.embeddings_ready());
    }

    #[test]
    fn test_config_with_llm() {
        let config =
            Config::new().with_llm(LlmConfig::ollama("http://localhost:11434", "llama3.2"));
        assert!(config.has_llm());
        assert!(config.llm_ready()); // ollama doesn't need API key
    }

    #[test]
    fn test_config_with_embeddings() {
        let config = Config::new().with_embeddings(EmbeddingConfig::ollama(
            "http://localhost:11434",
            "nomic-embed-text",
            768,
        ));
        assert!(config.embeddings_ready());
        assert_eq!(config.embeddings.unwrap().dimensions, 768);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::new()
            .with_llm(LlmConfig::ollama("http://localhost:11434", "llama3.2"))
            .with_embeddings(EmbeddingConfig::openai("text-embedding-3-small", 1536));

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("ollama"));
        assert!(json.contains("llama3.2"));
        assert!(json.contains("text-embedding-3-small"));
    }

    #[test]
    fn test_config_deserialization() {
        let json = r#"{
            "llm": {
                "provider": "openai",
                "endpoint": "https://api.openai.com/v1",
                "model": "gpt-4o",
                "api_key_env": "OPENAI_API_KEY"
            }
        }"#;
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.has_llm());
        assert!(config.embeddings.is_none());
        assert_eq!(config.llm.unwrap().model, "gpt-4o");
    }

    #[test]
    fn test_config_deserialization_empty() {
        let json = "{}";
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.llm.is_none());
        assert!(config.embeddings.is_none());
    }

    #[test]
    fn test_config_backward_compat() {
        // Old config with api_key should deserialize without error (unknown fields ignored)
        let json = r#"{"api_key": "old_key", "llm": {"provider": "ollama", "endpoint": "http://localhost:11434", "model": "llama3.2"}}"#;
        // serde will ignore unknown fields with default config
        let config: Config = serde_json::from_str(json).unwrap();
        assert!(config.has_llm());
    }

    #[test]
    fn test_llm_openai() {
        let llm = LlmConfig::openai("gpt-4o");
        assert_eq!(llm.provider, "openai");
        assert_eq!(llm.api_key_env, Some("OPENAI_API_KEY".to_string()));
    }

    #[test]
    fn test_llm_anthropic() {
        let llm = LlmConfig::anthropic("claude-sonnet-4-20250514");
        assert_eq!(llm.provider, "anthropic");
        assert_eq!(llm.api_key_env, Some("ANTHROPIC_API_KEY".to_string()));
    }

    #[test]
    fn test_llm_ollama_ready() {
        let llm = LlmConfig::ollama("http://localhost:11434", "llama3.2");
        assert!(llm.is_ready()); // No API key needed
    }

    #[test]
    fn test_llm_openai_not_ready_without_key() {
        let llm = LlmConfig::openai("gpt-4o");
        // Without env var set, not ready
        assert!(!llm.is_ready() || std::env::var("OPENAI_API_KEY").is_ok());
    }

    #[test]
    fn test_embedding_openai() {
        let emb = EmbeddingConfig::openai("text-embedding-3-small", 1536);
        assert_eq!(emb.provider, "openai");
        assert_eq!(emb.dimensions, 1536);
    }

    #[test]
    fn test_embedding_ollama() {
        let emb = EmbeddingConfig::ollama("http://localhost:11434", "nomic-embed-text", 768);
        assert!(emb.is_ready());
        assert_eq!(emb.dimensions, 768);
    }

    #[test]
    fn test_masked_api_key() {
        let mut llm = LlmConfig::openai("gpt-4o");
        llm.api_key = Some("sk-1234567890abcdef".to_string());
        let masked = llm.masked_api_key().unwrap();
        assert!(masked.starts_with("sk-1"));
        assert!(masked.ends_with("cdef"));
        assert!(masked.contains("..."));
    }

    #[test]
    fn test_config_exists() {
        let _ = Config::exists(); // Should not panic
    }
}
