//! Dependency extraction from source semantics.
//!
//! This module provides functions to extract runtime dependencies from
//! parsed and analyzed source code.

use crate::parse::ast::FileId;
use crate::semantics::SourceSemantics;
use crate::types::dependency::{
    BlockType, DependencyProtocol, DependencySource, RuntimeDependency,
};

use super::url_parser::extract_url_from_call;

/// Extract runtime dependencies from source semantics.
///
/// This function analyzes the semantics of a source file and extracts
/// all detectable runtime dependencies such as HTTP calls, database
/// connections, and other network operations.
pub fn extract_dependencies(
    file_id: FileId,
    semantics: &SourceSemantics,
) -> Vec<RuntimeDependency> {
    let mut dependencies = Vec::new();

    match semantics {
        SourceSemantics::Python(py_sem) => {
            extract_python_dependencies(&mut dependencies, file_id, &py_sem.path, py_sem);
        }
        SourceSemantics::Go(go_sem) => {
            extract_go_dependencies(&mut dependencies, file_id, &go_sem.path, go_sem);
        }
        SourceSemantics::Rust(rust_sem) => {
            extract_rust_dependencies(&mut dependencies, file_id, &rust_sem.path, rust_sem);
        }
        SourceSemantics::Typescript(ts_sem) => {
            extract_typescript_dependencies(&mut dependencies, file_id, &ts_sem.path, ts_sem);
        }
    }

    dependencies
}

/// Extract dependencies from Python semantics.
fn extract_python_dependencies(
    dependencies: &mut Vec<RuntimeDependency>,
    file_id: FileId,
    file_path: &str,
    py_sem: &crate::semantics::python::model::PyFileSemantics,
) {
    // Extract from HTTP calls
    for http_call in &py_sem.http_calls {
        if let Some(extracted) = extract_url_from_call(&http_call.call_text) {
            let protocol = DependencyProtocol::from_uri(&extracted.raw_value);
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: http_call.location.range.start_line + 1, // Convert to 1-based
                column: http_call.location.range.start_col + 1,
                block_name: http_call.function_name.clone(),
                block_type: determine_block_type(&http_call.function_name),
            };

            let mut dep = RuntimeDependency::new(protocol, extracted.raw_value, source);

            // Add metadata
            dep = dep.with_metadata("library", format_http_client_kind(&http_call.client_kind));
            dep = dep.with_metadata("http_method", http_call.method_name.to_uppercase());

            dependencies.push(dep);
        }
    }

    // Extract from ORM queries (database connections)
    for orm_query in &py_sem.orm_queries {
        // ORM queries don't typically contain the connection string directly,
        // but we can track them as potential DB dependencies
        let source = DependencySource {
            file_path: file_path.to_string(),
            file_id,
            line: orm_query.location.range.start_line + 1,
            column: orm_query.location.range.start_col + 1,
            block_name: None, // ORM queries don't track function name directly
            block_type: BlockType::Unknown,
        };

        // For ORM queries, we mark as database but without a specific URI
        // The actual connection string is usually configured elsewhere
        let mut dep = RuntimeDependency::new(
            DependencyProtocol::Other("database".to_string()),
            format!(
                "[ORM query: {}]",
                orm_query.model_name.as_deref().unwrap_or("unknown")
            ),
            source,
        );

        dep = dep.with_metadata("library", format_orm_kind(&orm_query.orm_kind));
        dep = dep.with_metadata("operation", format_query_type(&orm_query.query_type));

        dependencies.push(dep);
    }
}

/// Extract dependencies from Go semantics.
fn extract_go_dependencies(
    dependencies: &mut Vec<RuntimeDependency>,
    file_id: FileId,
    file_path: &str,
    go_sem: &crate::semantics::go::model::GoFileSemantics,
) {
    // Extract from HTTP calls
    for http_call in &go_sem.http_calls {
        if let Some(extracted) = extract_url_from_call(&http_call.call_text) {
            let protocol = DependencyProtocol::from_uri(&extracted.raw_value);
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: http_call.location.range.start_line + 1,
                column: http_call.location.range.start_col + 1,
                block_name: http_call.function_name.clone(),
                block_type: determine_block_type(&http_call.function_name),
            };

            let mut dep = RuntimeDependency::new(protocol, extracted.raw_value, source);

            dep = dep.with_metadata("library", format_go_http_client(&http_call.client_kind));
            dep = dep.with_metadata("http_method", http_call.method_name.to_uppercase());

            dependencies.push(dep);
        }
    }

    // Extract from call sites that might be database/redis/etc connections
    for call in &go_sem.calls {
        if let Some(dep) = extract_go_call_dependency(file_id, file_path, call) {
            dependencies.push(dep);
        }
    }
}

/// Try to extract a dependency from a Go call site.
fn extract_go_call_dependency(
    file_id: FileId,
    file_path: &str,
    call: &crate::semantics::go::model::GoCallSite,
) -> Option<RuntimeDependency> {
    let callee = &call.function_call.callee_expr;

    // Database connections
    if callee.contains("sql.Open") || callee.contains("gorm.Open") || callee.contains("sqlx.Open") {
        if let Some(extracted) = extract_url_from_call(&call.args_repr) {
            let protocol = DependencyProtocol::from_uri(&extracted.raw_value);
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: call.function_call.location.line,
                column: call.function_call.location.column,
                block_name: None, // Call sites don't track enclosing function
                block_type: BlockType::Unknown,
            };

            let mut dep = RuntimeDependency::new(protocol, extracted.raw_value, source);
            dep = dep.with_metadata("library", extract_go_library(callee));
            return Some(dep);
        }
    }

    // Redis connections
    if callee.contains("redis.NewClient") || callee.contains("redis.NewClusterClient") {
        if let Some(extracted) = extract_url_from_call(&call.args_repr) {
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: call.function_call.location.line,
                column: call.function_call.location.column,
                block_name: None,
                block_type: BlockType::Unknown,
            };

            let mut dep =
                RuntimeDependency::new(DependencyProtocol::Redis, extracted.raw_value, source);
            dep = dep.with_metadata("library", "go-redis");
            return Some(dep);
        }
    }

    // gRPC connections
    if callee.contains("grpc.Dial") || callee.contains("grpc.DialContext") {
        if let Some(extracted) = extract_url_from_call(&call.args_repr) {
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: call.function_call.location.line,
                column: call.function_call.location.column,
                block_name: None,
                block_type: BlockType::Unknown,
            };

            let mut dep =
                RuntimeDependency::new(DependencyProtocol::Grpc, extracted.raw_value, source);
            dep = dep.with_metadata("library", "grpc-go");
            return Some(dep);
        }
    }

    None
}

/// Extract dependencies from Rust semantics.
fn extract_rust_dependencies(
    dependencies: &mut Vec<RuntimeDependency>,
    file_id: FileId,
    file_path: &str,
    rust_sem: &crate::semantics::rust::model::RustFileSemantics,
) {
    // Extract from call sites that might be HTTP/DB connections
    // Note: RustCallSite doesn't have args_repr, so we rely on the callee expression
    // which may contain URLs embedded in the call for some patterns like reqwest::get("url")
    for call in &rust_sem.calls {
        if let Some(dep) = extract_rust_call_dependency(file_id, file_path, call) {
            dependencies.push(dep);
        }
    }
}

/// Try to extract a dependency from a Rust call site.
fn extract_rust_call_dependency(
    file_id: FileId,
    file_path: &str,
    call: &crate::semantics::rust::model::RustCallSite,
) -> Option<RuntimeDependency> {
    let callee = &call.function_call.callee_expr;

    // Reqwest HTTP client - reqwest::get("url") or client.get("url")
    let is_reqwest = callee.contains("reqwest")
        || (call.method_name.as_ref().map_or(false, |m| {
            matches!(
                m.as_str(),
                "get" | "post" | "put" | "delete" | "patch" | "head"
            )
        }));

    if is_reqwest {
        // Try to extract URL from the callee expression itself
        // (for cases like reqwest::get("https://example.com"))
        if let Some(extracted) = extract_url_from_call(callee) {
            let protocol = DependencyProtocol::from_uri(&extracted.raw_value);
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: call.function_call.location.line,
                column: call.function_call.location.column,
                block_name: call.function_name.clone(),
                block_type: determine_block_type(&call.function_name),
            };

            let mut dep = RuntimeDependency::new(protocol, extracted.raw_value, source);
            dep = dep.with_metadata("library", "reqwest");
            if let Some(ref method) = call.method_name {
                dep = dep.with_metadata("http_method", method.to_uppercase());
            }
            return Some(dep);
        }
    }

    // sqlx database connections - PgPool::connect("url") or similar
    let is_sqlx = callee.contains("PgPool")
        || callee.contains("MySqlPool")
        || callee.contains("SqlitePool")
        || callee.contains("sqlx");

    if is_sqlx {
        if let Some(extracted) = extract_url_from_call(callee) {
            let protocol = DependencyProtocol::from_uri(&extracted.raw_value);
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: call.function_call.location.line,
                column: call.function_call.location.column,
                block_name: call.function_name.clone(),
                block_type: determine_block_type(&call.function_name),
            };

            let mut dep = RuntimeDependency::new(protocol, extracted.raw_value, source);
            dep = dep.with_metadata("library", "sqlx");
            return Some(dep);
        }
    }

    // Redis crate - redis::Client::open("url")
    if callee.contains("redis") && callee.contains("Client") {
        if let Some(extracted) = extract_url_from_call(callee) {
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: call.function_call.location.line,
                column: call.function_call.location.column,
                block_name: call.function_name.clone(),
                block_type: determine_block_type(&call.function_name),
            };

            let mut dep =
                RuntimeDependency::new(DependencyProtocol::Redis, extracted.raw_value, source);
            dep = dep.with_metadata("library", "redis");
            return Some(dep);
        }
    }

    // Tonic gRPC client connections
    if callee.contains("tonic") && callee.contains("connect") {
        if let Some(extracted) = extract_url_from_call(callee) {
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: call.function_call.location.line,
                column: call.function_call.location.column,
                block_name: call.function_name.clone(),
                block_type: determine_block_type(&call.function_name),
            };

            let mut dep =
                RuntimeDependency::new(DependencyProtocol::Grpc, extracted.raw_value, source);
            dep = dep.with_metadata("library", "tonic");
            return Some(dep);
        }
    }

    None
}

/// Extract dependencies from TypeScript semantics.
fn extract_typescript_dependencies(
    dependencies: &mut Vec<RuntimeDependency>,
    file_id: FileId,
    file_path: &str,
    ts_sem: &crate::semantics::typescript::model::TsFileSemantics,
) {
    // Extract from HTTP calls (analyzed by the http module)
    for http_call in &ts_sem.http_calls {
        // Get the URL either from the url field or try to extract from arguments
        let url = http_call.url.clone().unwrap_or_default();
        if url.is_empty() {
            continue;
        }

        let protocol = DependencyProtocol::from_uri(&url);
        let source = DependencySource {
            file_path: file_path.to_string(),
            file_id,
            line: http_call.location.range.start_line + 1,
            column: http_call.location.range.start_col + 1,
            block_name: http_call.function_name.clone(),
            block_type: determine_block_type(&http_call.function_name),
        };

        let mut dep = RuntimeDependency::new(protocol, url, source);
        dep = dep.with_metadata("library", format_ts_http_client(&http_call.client_kind));
        dep = dep.with_metadata("http_method", http_call.method.to_uppercase());

        dependencies.push(dep);
    }

    // Also extract from generic call sites for additional patterns
    for call in &ts_sem.calls {
        if let Some(dep) = extract_typescript_call_dependency(file_id, file_path, call) {
            dependencies.push(dep);
        }
    }
}

/// Try to extract a dependency from a TypeScript call site.
fn extract_typescript_call_dependency(
    file_id: FileId,
    file_path: &str,
    call: &crate::semantics::typescript::model::TsCallSite,
) -> Option<RuntimeDependency> {
    let callee = &call.callee;

    // Skip if this looks like it was already captured by http_calls
    // (fetch, axios are handled by http module)
    if callee == "fetch" || callee.contains("axios") {
        return None;
    }

    // Database connections - pg, mysql, mongodb, etc.
    if callee.contains("createPool") || callee.contains("createConnection") {
        if let Some(extracted) = extract_url_from_call(&call.args_repr) {
            let protocol = DependencyProtocol::from_uri(&extracted.raw_value);
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: call.location.range.start_line + 1,
                column: call.location.range.start_col + 1,
                block_name: None,
                block_type: BlockType::Unknown,
            };

            let library = if callee.contains("mysql") {
                "mysql2"
            } else if callee.contains("pg") {
                "pg"
            } else {
                "unknown-db"
            };

            let mut dep = RuntimeDependency::new(protocol, extracted.raw_value, source);
            dep = dep.with_metadata("library", library);
            return Some(dep);
        }
    }

    // MongoDB
    if callee.contains("MongoClient") && callee.contains("connect") {
        if let Some(extracted) = extract_url_from_call(&call.args_repr) {
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: call.location.range.start_line + 1,
                column: call.location.range.start_col + 1,
                block_name: None,
                block_type: BlockType::Unknown,
            };

            let mut dep = RuntimeDependency::new(
                DependencyProtocol::Other("mongodb".to_string()),
                extracted.raw_value,
                source,
            );
            dep = dep.with_metadata("library", "mongodb");
            return Some(dep);
        }
    }

    // Redis (ioredis, redis)
    if callee.contains("Redis") || callee.contains("createClient") {
        if let Some(extracted) = extract_url_from_call(&call.args_repr) {
            let source = DependencySource {
                file_path: file_path.to_string(),
                file_id,
                line: call.location.range.start_line + 1,
                column: call.location.range.start_col + 1,
                block_name: None,
                block_type: BlockType::Unknown,
            };

            let mut dep =
                RuntimeDependency::new(DependencyProtocol::Redis, extracted.raw_value, source);
            dep = dep.with_metadata("library", "ioredis");
            return Some(dep);
        }
    }

    None
}

/// Format TypeScript HTTP client kind for metadata.
fn format_ts_http_client(kind: &crate::semantics::typescript::http::HttpClientKind) -> String {
    use crate::semantics::typescript::http::HttpClientKind;
    match kind {
        HttpClientKind::Fetch => "fetch".to_string(),
        HttpClientKind::Axios => "axios".to_string(),
        HttpClientKind::Got => "got".to_string(),
        HttpClientKind::NodeHttp => "node-http".to_string(),
        HttpClientKind::NodeFetch => "node-fetch".to_string(),
        HttpClientKind::Undici => "undici".to_string(),
        HttpClientKind::Ky => "ky".to_string(),
        HttpClientKind::Superagent => "superagent".to_string(),
        HttpClientKind::Unknown => "unknown".to_string(),
    }
}

// ==================== Helper Functions ====================

/// Determine block type from function name.
fn determine_block_type(function_name: &Option<String>) -> BlockType {
    match function_name {
        Some(name) if name.starts_with("lambda") || name.starts_with("<lambda") => {
            BlockType::Lambda
        }
        Some(_) => BlockType::Function,
        None => BlockType::Module,
    }
}

/// Format Python HTTP client kind for metadata.
fn format_http_client_kind(kind: &crate::semantics::python::http::HttpClientKind) -> String {
    match kind {
        crate::semantics::python::http::HttpClientKind::Requests => "requests".to_string(),
        crate::semantics::python::http::HttpClientKind::Httpx => "httpx".to_string(),
        crate::semantics::python::http::HttpClientKind::Aiohttp => "aiohttp".to_string(),
        crate::semantics::python::http::HttpClientKind::Other(s) => s.clone(),
    }
}

/// Format Go HTTP client kind for metadata.
fn format_go_http_client(kind: &crate::semantics::go::http::HttpClientKind) -> String {
    match kind {
        crate::semantics::go::http::HttpClientKind::NetHttp => "net/http".to_string(),
        crate::semantics::go::http::HttpClientKind::Resty => "resty".to_string(),
        crate::semantics::go::http::HttpClientKind::Fasthttp => "fasthttp".to_string(),
        crate::semantics::go::http::HttpClientKind::Fiber => "fiber".to_string(),
        crate::semantics::go::http::HttpClientKind::Other(s) => s.clone(),
    }
}

/// Format ORM kind for metadata.
fn format_orm_kind(kind: &crate::semantics::python::orm::OrmKind) -> String {
    match kind {
        crate::semantics::python::orm::OrmKind::SqlAlchemy => "sqlalchemy".to_string(),
        crate::semantics::python::orm::OrmKind::Django => "django".to_string(),
        crate::semantics::python::orm::OrmKind::Tortoise => "tortoise".to_string(),
        crate::semantics::python::orm::OrmKind::SqlModel => "sqlmodel".to_string(),
        crate::semantics::python::orm::OrmKind::Peewee => "peewee".to_string(),
        crate::semantics::python::orm::OrmKind::Unknown => "unknown".to_string(),
    }
}

/// Format query type for metadata.
fn format_query_type(query_type: &crate::semantics::python::orm::QueryType) -> String {
    match query_type {
        crate::semantics::python::orm::QueryType::Select => "select".to_string(),
        crate::semantics::python::orm::QueryType::Insert => "insert".to_string(),
        crate::semantics::python::orm::QueryType::Update => "update".to_string(),
        crate::semantics::python::orm::QueryType::Delete => "delete".to_string(),
        crate::semantics::python::orm::QueryType::RelationshipAccess => "relationship".to_string(),
        crate::semantics::python::orm::QueryType::Unknown => "unknown".to_string(),
    }
}

/// Extract Go library name from callee.
fn extract_go_library(callee: &str) -> String {
    if callee.contains("gorm") {
        "gorm".to_string()
    } else if callee.contains("sqlx") {
        "sqlx".to_string()
    } else if callee.contains("sql.") {
        "database/sql".to_string()
    } else {
        "unknown".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determine_block_type_function() {
        assert_eq!(
            determine_block_type(&Some("my_function".to_string())),
            BlockType::Function
        );
    }

    #[test]
    fn test_determine_block_type_lambda() {
        assert_eq!(
            determine_block_type(&Some("lambda".to_string())),
            BlockType::Lambda
        );
    }

    #[test]
    fn test_determine_block_type_module() {
        assert_eq!(determine_block_type(&None), BlockType::Module);
    }

    #[test]
    fn test_extract_go_library_gorm() {
        assert_eq!(extract_go_library("gorm.Open"), "gorm");
    }

    #[test]
    fn test_extract_go_library_sql() {
        assert_eq!(extract_go_library("sql.Open"), "database/sql");
    }
}
