//! Rule suppression via inline comments.
//!
//! This module provides functionality for suppressing unfault rules using
//! inline comments in source code. Developers can add comments like:
//!
//! ```text
//! # unfault-ignore: python.bare_except, python.sql_injection
//! // unfault-ignore: typescript.global_mutable_state
//! ```
//!
//! Suppressions can be:
//! - **File-level**: Comment in first 10 lines suppresses rules for entire file
//! - **Line-level**: Comment before code suppresses rules for next line
//! - **Inline**: Comment at end of line suppresses rules for that line

mod filter;
mod model;
mod parser;

pub use filter::filter_suppressed_findings;
pub use model::{Suppression, SuppressionScope};
pub use parser::parse_suppressions;