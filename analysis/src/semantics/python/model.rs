//! Python semantic model — re-exported from `unfault-core`.
//!
//! All parsing, semantic extraction, and framework analysis lives in
//! `unfault-core`. This module re-exports every public type so that
//! existing `crate::semantics::python::model::*` import paths throughout
//! the analysis crate continue to work unchanged.
//!
//! Benefits over the previous duplicated ~2800-line copy:
//! - Bug fixes (e.g. multi-line parenthesised import parsing) apply
//!   automatically to the analysis crate.
//! - New semantic fields (django, async_operations, decorators,
//!   PyFunction::start_byte / end_byte) are available immediately.
//! - `analyze_frameworks` runs all seven analyzers (FastAPI, Django,
//!   Flask, HTTP, ORM, async_ops, decorators) rather than just four.
//! - Single source of truth — no more schema drift causing JSON/msgpack
//!   round-trip failures.

pub use unfault_core::semantics::python::model::{
    AsyncOperation, AsyncOperationType, BareExceptClause, Decorator, ImportCategory,
    ImportInsertionType, ImportStyle, PyAssignment, PyCallArg, PyCallSite, PyClass,
    PyFileSemantics, PyFunction, PyImport, PyParam, PyRange, is_stdlib_module,
};
