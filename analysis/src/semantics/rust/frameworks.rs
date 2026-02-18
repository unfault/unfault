//! Rust HTTP framework types for IR deserialization.
//!
//! These types mirror the core crate's framework types for deserializing
//! the IR sent by the CLI.

use serde::{Deserialize, Serialize};

use crate::parse::ast::AstLocation;

/// Summary of Rust HTTP framework usage in a file.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RustFrameworkSummary {
    /// Detected framework type
    pub framework: Option<RustFrameworkType>,

    /// HTTP routes registered in this file
    pub routes: Vec<RustFrameworkRoute>,

    /// Middleware registered in this file
    pub middleware: Vec<RustMiddlewareInfo>,

    /// Router/scope nesting
    pub route_scopes: Vec<RustRouteScope>,
}

impl RustFrameworkSummary {
    /// Check if any framework was detected.
    pub fn has_framework(&self) -> bool {
        self.framework.is_some()
    }
}

/// Supported Rust HTTP frameworks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RustFrameworkType {
    /// Axum (https://github.com/tokio-rs/axum)
    Axum,
    /// Actix-web (https://github.com/actix/actix-web)
    ActixWeb,
    /// Rocket (https://rocket.rs)
    Rocket,
    /// Warp (https://github.com/seanmonstar/warp)
    Warp,
    /// Poem (https://github.com/poem-web/poem)
    Poem,
    /// Tide (https://github.com/http-rs/tide)
    Tide,
}

/// A route registered with a Rust HTTP framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustFrameworkRoute {
    /// HTTP method (GET, POST, etc.) - may be empty for wildcard routes
    pub method: String,

    /// Route path pattern (e.g., "/users/:id" or "/users/{id}")
    pub path: String,

    /// Handler function name
    pub handler_name: String,

    /// Whether this route is async
    pub is_async: bool,

    /// Router scope/nest prefix if any
    pub scope_prefix: Option<String>,

    /// Source location
    pub location: AstLocation,
}

/// Information about registered middleware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustMiddlewareInfo {
    /// Middleware name or type
    pub name: String,

    /// Whether this is a layer (tower Layer for Axum)
    pub is_layer: bool,

    /// Whether this is global (applied to all routes)
    pub is_global: bool,

    /// Source location
    pub location: AstLocation,
}

/// A route scope/nest (for grouping routes with a prefix).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustRouteScope {
    /// Prefix path for this scope
    pub prefix: String,

    /// Parent scope prefix, if nested
    pub parent_prefix: Option<String>,

    /// Source location
    pub location: AstLocation,
}
