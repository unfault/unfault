//! Parse module — re-exported from unfault-core.
//!
//! All parsing logic lives in `unfault-core`. This module re-exports it so
//! that existing `crate::parse::*` import paths throughout the analysis crate
//! continue to work unchanged.

pub use unfault_core::parse::ast;
pub use unfault_core::parse::go;
pub use unfault_core::parse::parse_source_file;
pub use unfault_core::parse::python;
pub use unfault_core::parse::rust;
pub use unfault_core::parse::typescript;
