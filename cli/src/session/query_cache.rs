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
use std::time::SystemTime;

use serde::{de::DeserializeOwned, Serialize};
use xxhash_rust::xxh3::xxh3_64;

/// Bump when the encoding format changes incompatibly.
/// v1 → v2: switched to struct-map encoding so skip_serializing_if fields
///          round-trip correctly through rmp_serde.
const CACHE_VERSION: u8 = 2;

/// Path to the on-disk SHA cache file.
fn sha_cache_path(workspace_path: &Path) -> PathBuf {
    workspace_path
        .join(".unfault")
        .join("cache")
        .join("commit_sha")
}

/// Return the mtime (seconds since UNIX epoch) of a file, or 0 on any error.
fn mtime_secs(path: &Path) -> u64 {
    path.metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Return the HEAD commit SHA of the git repo containing `workspace_path`,
/// or a fallback string when not in a git repo.
///
/// On a warm cache the result is served from a small file without spawning
/// a subprocess. The cache is invalidated when `.git/HEAD` or
/// `.git/packed-refs` is newer than the cached file.
pub fn current_commit_sha(workspace_path: &Path) -> String {
    let cache_file = sha_cache_path(workspace_path);

    // Check whether the on-disk cache is still fresh.
    if cache_file.exists() {
        let cache_mtime = mtime_secs(&cache_file);
        let head_mtime = mtime_secs(&workspace_path.join(".git").join("HEAD"));
        // packed-refs is written when refs are compacted; guard against it too.
        let packed_mtime = mtime_secs(&workspace_path.join(".git").join("packed-refs"));
        let git_mtime = head_mtime.max(packed_mtime);

        if cache_mtime >= git_mtime && git_mtime > 0 {
            if let Ok(sha) = fs::read_to_string(&cache_file) {
                let sha = sha.trim().to_string();
                if !sha.is_empty() {
                    return sha;
                }
            }
        }
    }

    // Cache miss — run git and persist the result.
    let sha = Command::new("git")
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
        .unwrap_or_else(|| "no-git".to_string());

    // Persist for subsequent invocations (best-effort; ignore write errors).
    if let Some(parent) = cache_file.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&cache_file, &sha);

    sha
}

/// Return a workspace state key that incorporates both the HEAD commit SHA
/// and any workspace dirtiness (modified, staged, or untracked files).
///
/// ## Cache behaviour
///
/// - **Clean workspace** (no dirty/staged/untracked files): returns the bare
///   commit SHA, identical to `current_commit_sha`. Query cache entries remain
///   valid across repeated invocations with no workspace changes — this is the
///   fast path.
/// - **Dirty workspace**: appends a compact hex hash of `git status --porcelain`
///   output so that each distinct set of working-tree changes gets its own
///   cache bucket. As soon as the workspace returns to a clean state the key
///   reverts to the bare SHA and previously-cached clean results are reused.
///
/// The `git status --porcelain` call is cheap (milliseconds) and avoids the
/// expensive graph rebuild for unchanged workspaces.
pub fn workspace_state_key(workspace_path: &Path) -> String {
    let commit_sha = current_commit_sha(workspace_path);

    // Run `git status --porcelain` to detect any working-tree or index changes.
    // This single command covers: modified tracked files, staged changes, and
    // untracked files (the '?' lines). Ignored files are not included.
    let status_output = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(workspace_path)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout).ok()
            } else {
                None
            }
        });

    match status_output {
        // No git or command failed — fall back to commit SHA only.
        None => commit_sha,
        Some(status) if status.trim().is_empty() => {
            // Clean workspace: use bare commit SHA so cache entries are reused
            // across all invocations until a commit or file change occurs.
            commit_sha
        }
        Some(status) => {
            // Dirty workspace: hash the porcelain output and append it.
            // Each distinct working-tree state gets its own cache bucket,
            // so stale results are never served.
            let dirty_hash = xxh3_64(status.as_bytes());
            format!("{commit_sha}+dirty:{dirty_hash:016x}")
        }
    }
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
    // Struct-map decoding: structs were written as {field: value} maps so
    // that absent `#[serde(default, skip_serializing_if = …)]` fields are
    // filled from their Default impl on deserialization.
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
        // Use struct-map encoding: structs are written as {field: value}
        // maps instead of positional arrays. This makes fields with
        // `#[serde(default, skip_serializing_if = …)]` safely round-trip —
        // absent fields are filled from their Default impl on read.
        let mut ser = rmp_serde::Serializer::new(&mut writer).with_struct_map();
        if value.serialize(&mut ser).is_ok() {
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
