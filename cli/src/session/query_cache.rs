//! Query result cache — stores BFS/traversal outputs keyed on
//! (query parameters, git HEAD commit SHA) so repeated identical queries
//! return instantly without rebuilding the code graph.
//!
//! ## Key design
//!
//! Cache key = `query_type + "_" + xxh3(params) + "_" + commit_sha`
//! Cache value = msgpack-encoded result (any `Serialize + DeserializeOwned` type)
//!
//! ## Invalidation
//!
//! - Any change to `git HEAD` → key includes the SHA, so all entries for the
//!   previous commit are automatically stale and ignored on the next read.
//! - `unfault graph refresh` → deletes the entire query cache directory.
//! - If the workspace is not a git repository the SHA is the string "no-git",
//!   which means the cache is effectively per-session only.

use std::fs;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Serialize, de::DeserializeOwned};
use xxhash_rust::xxh3::xxh3_64;

const CACHE_VERSION: u8 = 1;

/// Return the HEAD commit SHA of the git repo containing `workspace_path`,
/// or a fallback string when not in a git repo.
pub fn current_commit_sha(workspace_path: &Path) -> String {
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(workspace_path)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "no-git".to_string())
}

/// Directory where query cache files are stored.
pub fn query_cache_dir(workspace_path: &Path) -> PathBuf {
    workspace_path.join(".unfault").join("cache").join("query")
}

/// Compute the cache file path for a given query.
///
/// `query_type` is a short ASCII tag identifying the command (e.g. "callers",
/// "impact", "routes"). `params` is the serialised query parameters string
/// whose xxh3 hash becomes part of the key.
fn cache_path(workspace_path: &Path, query_type: &str, params: &str, commit_sha: &str) -> PathBuf {
    let params_hash = xxh3_64(params.as_bytes());
    let filename = format!(
        "v{}_{query_type}_{params_hash:016x}_{commit_sha}.msgpack",
        CACHE_VERSION
    );
    query_cache_dir(workspace_path).join(filename)
}

/// Try to load a cached query result.
///
/// Returns `Some(value)` on a hit, `None` on any miss.
pub fn get<T: DeserializeOwned>(
    workspace_path: &Path,
    query_type: &str,
    params: &str,
    commit_sha: &str,
) -> Option<T> {
    let path = cache_path(workspace_path, query_type, params, commit_sha);
    let file = fs::File::open(&path).ok()?;
    rmp_serde::from_read(BufReader::new(file)).ok()
}

/// Store a query result in the cache.
pub fn set<T: Serialize>(
    workspace_path: &Path,
    query_type: &str,
    params: &str,
    commit_sha: &str,
    value: &T,
) {
    let dir = query_cache_dir(workspace_path);
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = cache_path(workspace_path, query_type, params, commit_sha);
    if let Ok(file) = fs::File::create(&path) {
        let mut writer = BufWriter::new(file);
        if rmp_serde::encode::write(&mut writer, value).is_ok() {
            let _ = writer.flush();
        }
    }
}

/// Delete all query cache entries (called by `unfault graph refresh`).
pub fn clear(workspace_path: &Path) -> std::io::Result<()> {
    let dir = query_cache_dir(workspace_path);
    if !dir.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.path().extension().map_or(false, |e| e == "msgpack") {
            fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

// ── Typed convenience wrappers ────────────────────────────────────────────────
// These encode the query_type tag and serialise the params to a string so call
// sites stay concise and the tag is never misspelled.

use unfault_core::types::graph_query::{
    CallersContext, FlowContext, GraphContext, WorkspaceContext,
};

pub fn get_callers(
    workspace_path: &Path,
    function_name: &str,
    file_hint: Option<&str>,
    commit_sha: &str,
) -> Option<CallersContext> {
    let params = format!("{}|{}", function_name, file_hint.unwrap_or(""));
    get(workspace_path, "callers", &params, commit_sha)
}

pub fn set_callers(
    workspace_path: &Path,
    function_name: &str,
    file_hint: Option<&str>,
    commit_sha: &str,
    ctx: &CallersContext,
) {
    let params = format!("{}|{}", function_name, file_hint.unwrap_or(""));
    set(workspace_path, "callers", &params, commit_sha, ctx);
}

pub fn get_impact(
    workspace_path: &Path,
    file_path: &str,
    max_depth: usize,
    commit_sha: &str,
) -> Option<GraphContext> {
    let params = format!("{}|{}", file_path, max_depth);
    get(workspace_path, "impact", &params, commit_sha)
}

pub fn set_impact(
    workspace_path: &Path,
    file_path: &str,
    max_depth: usize,
    commit_sha: &str,
    ctx: &GraphContext,
) {
    let params = format!("{}|{}", file_path, max_depth);
    set(workspace_path, "impact", &params, commit_sha, ctx);
}

pub fn get_function_impact(
    workspace_path: &Path,
    function: &str,
    max_depth: usize,
    commit_sha: &str,
) -> Option<FlowContext> {
    let params = format!("{}|{}", function, max_depth);
    get(workspace_path, "function_impact", &params, commit_sha)
}

pub fn set_function_impact(
    workspace_path: &Path,
    function: &str,
    max_depth: usize,
    commit_sha: &str,
    ctx: &FlowContext,
) {
    let params = format!("{}|{}", function, max_depth);
    set(workspace_path, "function_impact", &params, commit_sha, ctx);
}

pub fn get_deps(workspace_path: &Path, target: &str, commit_sha: &str) -> Option<GraphContext> {
    get(workspace_path, "deps", target, commit_sha)
}

pub fn set_deps(workspace_path: &Path, target: &str, commit_sha: &str, ctx: &GraphContext) {
    set(workspace_path, "deps", target, commit_sha, ctx);
}

pub fn get_library(
    workspace_path: &Path,
    library_name: &str,
    commit_sha: &str,
) -> Option<GraphContext> {
    get(workspace_path, "library", library_name, commit_sha)
}

pub fn set_library(
    workspace_path: &Path,
    library_name: &str,
    commit_sha: &str,
    ctx: &GraphContext,
) {
    set(workspace_path, "library", library_name, commit_sha, ctx);
}

pub fn get_stats(workspace_path: &Path, commit_sha: &str) -> Option<WorkspaceContext> {
    get(workspace_path, "stats", "workspace", commit_sha)
}

pub fn set_stats(workspace_path: &Path, commit_sha: &str, ctx: &WorkspaceContext) {
    set(workspace_path, "stats", "workspace", commit_sha, ctx);
}

pub fn get_critical(
    workspace_path: &Path,
    metric: &str,
    limit: usize,
    commit_sha: &str,
) -> Option<GraphContext> {
    let params = format!("{}|{}", metric, limit);
    get(workspace_path, "critical", &params, commit_sha)
}

pub fn set_critical(
    workspace_path: &Path,
    metric: &str,
    limit: usize,
    commit_sha: &str,
    ctx: &GraphContext,
) {
    let params = format!("{}|{}", metric, limit);
    set(workspace_path, "critical", &params, commit_sha, ctx);
}

use unfault_core::types::graph_query::{HandlersContext, PathContext};

pub fn get_path(
    workspace_path: &Path,
    from: &str,
    to: &str,
    commit_sha: &str,
) -> Option<PathContext> {
    let params = format!("{}|{}", from, to);
    get(workspace_path, "path", &params, commit_sha)
}

pub fn set_path(workspace_path: &Path, from: &str, to: &str, commit_sha: &str, ctx: &PathContext) {
    let params = format!("{}|{}", from, to);
    set(workspace_path, "path", &params, commit_sha, ctx);
}

pub fn get_handlers(
    workspace_path: &Path,
    pattern: &str,
    commit_sha: &str,
) -> Option<HandlersContext> {
    get(workspace_path, "handlers", pattern, commit_sha)
}

pub fn set_handlers(workspace_path: &Path, pattern: &str, commit_sha: &str, ctx: &HandlersContext) {
    set(workspace_path, "handlers", pattern, commit_sha, ctx);
}

// routes is a Vec<RouteEntry> which lives in the CLI crate, not core — use the
// generic get/set directly from the call site rather than a typed wrapper here.
