//! FastAPI semantics — re-exported from `unfault-core`.
//!
//! All FastAPI extraction logic lives in `unfault-core`. This module
//! re-exports every public type and the `summarize_fastapi` entry point so
//! that existing `crate::semantics::python::fastapi::*` import paths
//! throughout the analysis crate continue to work unchanged.

pub use unfault_core::semantics::python::fastapi::{
    FastApiApp, FastApiExceptionHandler, FastApiFileSummary, FastApiMiddleware, FastApiRoute,
    FastApiRouter, RouteParam, summarize_fastapi,
};
