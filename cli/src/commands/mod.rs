//! # CLI Command Implementations
//!
//! This module contains the implementation of all CLI commands.
//! Each submodule represents a top-level command or command group.
//!
//! ## Available Commands
//!
//! - [`config`] - Manage CLI configuration (LLM settings, etc.)
//! - [`graph`] - Query the code graph for impact analysis, dependencies, and critical files
//! - [`lsp`] - Language Server Protocol server for IDE integration
//! - [`review`] - Analyze code for fault-tolerance issues

pub mod config;
pub mod graph;
pub mod lsp;
pub mod review;
