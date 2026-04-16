//! # Unfault CLI Library
//!
//! This crate provides the core functionality for the Unfault CLI,
//! a tool for analyzing code for production-readiness issues.
//!
//! ## Modules
//!
//! - [`commands`] - CLI command implementations
//! - [`config`] - Configuration management
//! - [`errors`] - Error handling and display
//! - [`exit_codes`] - Standard exit codes
//! - [`session`] - Session management for workspace scanning and analysis

pub mod analysis;
pub mod commands;
pub mod config;
pub mod enrichment_cache;
pub mod exit_codes;
pub mod fmt;
pub mod integration;
pub mod llm;
pub mod local_graph;
pub mod output;
pub mod session;
pub mod slo;
pub mod trace;

// Re-export commonly used types
pub use config::Config;
pub use session::{WorkspaceInfo, WorkspaceScanner};
