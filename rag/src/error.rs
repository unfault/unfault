use thiserror::Error;

/// Errors that can occur during RAG operations.
#[derive(Error, Debug)]
pub enum RagError {
    #[error("Embedding provider error: {0}")]
    Embedding(String),

    #[error("Vector store error: {0}")]
    Store(String),

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("LanceDB error: {0}")]
    LanceDb(String),

    #[error("No embedding provider configured")]
    NoProvider,

    #[error("Query routing error: {0}")]
    Routing(String),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl From<lancedb::Error> for RagError {
    fn from(e: lancedb::Error) -> Self {
        RagError::LanceDb(e.to_string())
    }
}
