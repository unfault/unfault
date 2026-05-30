// Re-export from unfault-core — the types are identical (with HTTP method filter fix applied to core).
pub use unfault_core::semantics::python::http::{
    HttpCallSite, HttpClientKind, RetrySource, summarize_http_clients,
};
