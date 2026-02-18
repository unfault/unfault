//! Go HTTP framework types for IR deserialization.
//!
//! These types mirror the structures from the core crate used for Go web frameworks
//! like Gin, Echo, Fiber, and Chi. The engine only needs to deserialize these
//! structures - the actual extraction logic lives in the core crate.

use serde::{Deserialize, Serialize};

use crate::parse::ast::AstLocation;

/// Summary of Go HTTP framework usage in a file.
///
/// Extracted by the core crate during parsing and sent to the engine via IR.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GoFrameworkSummary {
    /// All routes found in this file
    pub routes: Vec<GoRoute>,
    /// Detected frameworks used
    pub frameworks: Vec<GoHttpFramework>,
}

impl GoFrameworkSummary {
    /// Check if any framework was detected.
    pub fn has_framework(&self) -> bool {
        !self.frameworks.is_empty() || !self.routes.is_empty()
    }
}

/// Supported Go HTTP frameworks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GoHttpFramework {
    Gin,
    Echo,
    Fiber,
    Chi,
    Mux,
    NetHttp,
}

/// A single HTTP route registration from any Go framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoRoute {
    /// Framework that registered this route
    pub framework: GoHttpFramework,
    /// HTTP method (GET, POST, PUT, DELETE, PATCH, etc.)
    pub http_method: String,
    /// Route path (e.g., "/users/:id")
    pub path: String,
    /// Handler function name (if identifiable)
    pub handler_name: Option<String>,
    /// Location in source
    pub location: AstLocation,
    /// Start byte offset
    pub start_byte: usize,
    /// End byte offset
    pub end_byte: usize,
}
