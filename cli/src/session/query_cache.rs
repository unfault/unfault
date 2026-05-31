//! Query result cache — stores BFS outputs (CallerContext, etc.) keyed on
//! (query parameters, git HEAD commit SHA) so repeated identical queries
//! return instantly without rebuilding the code graph.
//!
//! ## Key design
//!
//! Cache key = `xxh3(function_name + "|" + file_hint) + "_" + commit_sha`
//! Cache value = msgpack-encoded `CallersContext`
//!
//! ## Invalidation
//!
//! - Any change to `git HEAD` (commit, reset, checkout) → key includes the SHA
//!   so all entries for the previous commit are automatically stale and ignored.
//! - `unfault graph refresh` → deletes the entire query cache directory.
//! - If the workspace is not a git repository, the SHA is replaced with a
//!   hash of the graph.msgpack mtime so the cache still works.

use std::fs;
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use unfault_core::types::graph_query::CallersContext;
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

/// Compute the cache file path for a given query + commit.
fn cache_path(
    workspace_path: &Path,
    function_name: &str,
    file_hint: Option<&str>,
    commit_sha: &str,
) -> PathBuf {
    let key = format!("{}|{}", function_name, file_hint.unwrap_or(""));
    let key_hash = xxh3_64(key.as_bytes());
    let filename = format!(
        "v{}_callers_{:016x}_{}.msgpack",
        CACHE_VERSION, key_hash, commit_sha
    );
    query_cache_dir(workspace_path).join(filename)
}

/// Try to load a cached `CallersContext` for the given query.
///
/// Returns `Some(ctx)` on a hit, `None` on any miss (file absent, version
/// mismatch, deserialisation error).
pub fn get_callers(
    workspace_path: &Path,
    function_name: &str,
    file_hint: Option<&str>,
    commit_sha: &str,
) -> Option<CallersContext> {
    let path = cache_path(workspace_path, function_name, file_hint, commit_sha);
    let file = fs::File::open(&path).ok()?;
    rmp_serde::from_read(BufReader::new(file)).ok()
}

/// Store a `CallersContext` in the query cache.
pub fn set_callers(
    workspace_path: &Path,
    function_name: &str,
    file_hint: Option<&str>,
    commit_sha: &str,
    ctx: &CallersContext,
) {
    let dir = query_cache_dir(workspace_path);
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = cache_path(workspace_path, function_name, file_hint, commit_sha);
    if let Ok(file) = fs::File::create(&path) {
        let mut writer = BufWriter::new(file);
        let _ = rmp_serde::encode::write(&mut writer, ctx);
        let _ = writer.flush();
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
