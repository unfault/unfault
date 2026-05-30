// Re-export from unfault-core — the types are identical.
pub use unfault_core::semantics::python::orm::{
    NPlusOnePattern, OrmKind, OrmQueryCall, OuterQueryInfo, QueryType, detect_n_plus_one_patterns,
    summarize_orm_queries,
};
