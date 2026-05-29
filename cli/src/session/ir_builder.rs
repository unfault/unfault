//! Client-side IR (Intermediate Representation) builder.
//!
//! This module provides functionality to parse source files locally and build
//! a complete IR containing semantics and a code graph. The IR can then be
//! serialized and sent to the API for rule evaluation, without sending
//! source code over the wire.
//!
//! ## Architecture
//!
//! The client-side parsing flow:
//! 1. Discover source files in the workspace
//! 2. Parse each file using tree-sitter (via unfault-core)
//! 3. Extract language-specific semantics (imports, functions, calls, etc.)
//! 4. Build a unified code graph
//! 5. Package into IntermediateRepresentation
//! 6. Serialize to JSON and send to API
//!
//! ## Example
//!
//! ```rust,ignore
//! use unfault::session::ir_builder::build_ir;
//!
//! let ir = build_ir(&workspace_path, None, false)?;
//! let ir_json = serde_json::to_string(&ir)?;
//!
//! // Send ir_json to POST /v1/graph/analyze
//! ```

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use colored::Colorize;
use log::debug;
use rayon::prelude::*;

use unfault_core::IntermediateRepresentation;
use unfault_core::graph::build_code_graph;
use unfault_core::parse::ast::FileId;
use unfault_core::parse::{go, python, rust as rust_parse, typescript};
use unfault_core::semantics::SourceSemantics;
use unfault_core::semantics::go::model::GoFileSemantics;
use unfault_core::semantics::python::model::PyFileSemantics;
use unfault_core::semantics::rust::{build_rust_semantics, model::RustFileSemantics};
use unfault_core::semantics::typescript::model::TsFileSemantics;
use unfault_core::types::context::{Language, SourceFile};

use super::semantics_cache::{CacheStats, SemanticsCache};

/// Result of building IR with cache statistics
#[derive(Debug)]
pub struct IrBuildResult {
    /// The built intermediate representation
    pub ir: IntermediateRepresentation,
    /// Cache statistics (hits, misses, etc.)
    pub cache_stats: CacheStats,
}

/// Try to load a cached code graph from disk.
///
/// Returns `Some(graph)` if the cache file exists and its stored aggregate
/// hash matches `expected_hash`. Returns `None` otherwise.
fn try_load_graph_cache(
    path: &std::path::Path,
    expected_hash: u64,
    verbose: bool,
) -> Option<unfault_core::graph::CodeGraph> {
    use std::io::BufReader;

    // The file is: [aggregate_hash: u64 LE][msgpack graph bytes]
    let mut file = std::fs::File::open(path).ok()?;
    use std::io::Read;
    let mut header = [0u8; 8];
    file.read_exact(&mut header).ok()?;
    let stored_hash = u64::from_le_bytes(header);
    if stored_hash != expected_hash {
        return None;
    }

    let reader = BufReader::new(file);
    match rmp_serde::from_read::<_, unfault_core::graph::CodeGraph>(reader) {
        Ok(mut graph) => {
            graph.rebuild_indexes();
            if verbose {
                eprintln!("{} Graph loaded from cache", "TIMING".yellow());
            }
            Some(graph)
        }
        Err(_) => None,
    }
}

/// Save a code graph to the graph cache file.
fn save_graph_cache(
    path: &std::path::Path,
    aggregate_hash: u64,
    graph: &unfault_core::graph::CodeGraph,
    _verbose: bool,
) -> anyhow::Result<()> {
    use std::io::{BufWriter, Write};

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let file = std::fs::File::create(path)?;
    let mut writer = BufWriter::new(file);
    // Write 8-byte aggregate hash header, then msgpack graph
    writer.write_all(&aggregate_hash.to_le_bytes())?;
    rmp_serde::encode::write(&mut writer, graph)?;
    Ok(())
}

/// Build an Intermediate Representation from files in a directory.
///
/// This function:
/// 1. Discovers source files in the directory
/// 2. Parses each file using tree-sitter
/// 3. Extracts semantics (imports, functions, calls)
/// 4. Builds a unified code graph
/// 5. Returns a serializable IntermediateRepresentation
///
/// # Arguments
///
/// * `workspace_path` - Path to the workspace directory
/// * `file_paths` - Optional list of specific files to include (if None, discover all)
/// * `verbose` - Enable verbose logging
///
/// # Returns
///
/// An [`IntermediateRepresentation`] containing semantics for each file and
/// a code graph representing the relationships between code elements.
///
/// # Example
///
/// ```rust,ignore
/// use unfault::session::ir_builder::build_ir;
///
/// // Build IR for all files in workspace
/// let ir = build_ir(&workspace_path, None, false)?;
///
/// // Build IR for specific files only
/// let files = vec![PathBuf::from("src/main.py"), PathBuf::from("src/utils.py")];
/// let ir = build_ir(&workspace_path, Some(&files), true)?;
/// ```
pub fn build_ir(
    workspace_path: &Path,
    file_paths: Option<&[PathBuf]>,
    verbose: bool,
) -> Result<IntermediateRepresentation> {
    // Determine files to process
    let files = match file_paths {
        Some(paths) => paths.to_vec(),
        None => discover_source_files(workspace_path)?,
    };

    if verbose {
        eprintln!("Building IR from {} files...", files.len());
    }

    // Parse and extract semantics from each file in parallel
    let results: Vec<Option<(FileId, SourceSemantics)>> = files
        .par_iter()
        .enumerate()
        .map(|(index, file_path)| {
            let Some(language) = detect_language(file_path) else {
                return None;
            };

            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(e) => {
                    if verbose {
                        eprintln!("Warning: Could not read {}: {}", file_path.display(), e);
                    }
                    return None;
                }
            };

            let relative_path = file_path
                .strip_prefix(workspace_path)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let file_id = FileId((index + 1) as u64);

            let source_file = SourceFile {
                path: relative_path.clone(),
                language,
                content,
            };

            // Parse and build semantics based on language
            let semantics = match language {
                Language::Python => {
                    let parsed = match python::parse_python_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            return None;
                        }
                    };
                    let mut sem = PyFileSemantics::from_parsed(&parsed);
                    // Analyze frameworks (FastAPI, etc.)
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Python(sem)
                }
                Language::Go => {
                    let parsed = match go::parse_go_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            return None;
                        }
                    };
                    let mut sem = GoFileSemantics::from_parsed(&parsed);
                    // Analyze frameworks (Gin, etc.)
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Go(sem)
                }
                Language::Rust => {
                    let parsed = match rust_parse::parse_rust_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            return None;
                        }
                    };
                    let sem = match build_rust_semantics(&parsed) {
                        Ok(s) => s,
                        Err(_) => RustFileSemantics::from_parsed(&parsed),
                    };
                    SourceSemantics::Rust(sem)
                }
                Language::Typescript => {
                    let parsed = match typescript::parse_typescript_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            return None;
                        }
                    };
                    let mut sem = TsFileSemantics::from_parsed(&parsed);
                    // Analyze frameworks (Express, etc.)
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Typescript(sem)
                }
                _ => {
                    if verbose {
                        eprintln!(
                            "Skipping unsupported language for {}: {:?}",
                            relative_path, language
                        );
                    }
                    return None;
                }
            };

            Some((file_id, semantics))
        })
        .collect();

    let mut semantics_entries: Vec<(FileId, Arc<SourceSemantics>)> = Vec::new();
    let mut all_semantics: Vec<SourceSemantics> = Vec::new();

    for result in results {
        if let Some((file_id, semantics)) = result {
            all_semantics.push(semantics.clone());
            semantics_entries.push((file_id, Arc::new(semantics)));
        }
    }

    if verbose {
        eprintln!("Parsed {} files successfully", semantics_entries.len());
    }

    // Build the code graph
    let code_graph = build_code_graph(&semantics_entries);

    if verbose {
        let stats = code_graph.stats();
        eprintln!(
            "Built graph: {} files, {} functions, {} imports, {} library usages",
            stats.file_count,
            stats.function_count,
            stats.import_edge_count,
            stats.uses_library_edge_count
        );
    }

    Ok(IntermediateRepresentation::new(all_semantics, code_graph))
}

/// Build an Intermediate Representation with caching support.
///
/// Similar to [`build_ir`], but uses a file-based cache to skip re-parsing
/// files that haven't changed. On incremental runs, this can reduce parse
/// time from ~2000ms to ~50-100ms.
///
/// # Arguments
///
/// * `workspace_path` - Path to the workspace directory
/// * `file_paths` - Optional list of specific files to include
/// * `verbose` - Enable verbose logging
///
/// # Returns
///
/// An [`IrBuildResult`] containing the IR and cache statistics.
///
/// # Example
///
/// ```rust,ignore
/// use unfault::session::ir_builder::build_ir_cached;
///
/// let result = build_ir_cached(&workspace_path, None, false)?;
/// println!("Cache hit rate: {:.1}%", result.cache_stats.hit_rate());
/// let ir_json = serde_json::to_string(&result.ir)?;
/// ```
pub fn build_ir_cached(
    workspace_path: &Path,
    file_paths: Option<&[PathBuf]>,
    verbose: bool,
) -> Result<IrBuildResult> {
    let _total_start = Instant::now();

    // Open or create the cache
    let cache_start = Instant::now();
    let cache = SemanticsCache::open(workspace_path)?;
    let cache = Arc::new(Mutex::new(cache));
    let cache_open_ms = cache_start.elapsed().as_millis();

    // Determine files to process — test files are always excluded regardless
    // of whether the caller supplied an explicit list or we discover them.
    let discover_start = Instant::now();
    let files = match file_paths {
        Some(paths) => paths.iter().filter(|p| !is_test_file(p)).cloned().collect(),
        None => discover_source_files(workspace_path)?,
    };
    let discover_ms = discover_start.elapsed().as_millis();

    if verbose {
        eprintln!("Building IR from {} files (with cache)...", files.len());
        eprintln!(
            "{} Cache open: {}ms, File discovery: {}ms",
            "TIMING".yellow(),
            cache_open_ms,
            discover_ms
        );
    }

    // Parse and extract semantics from each file in parallel, using cache
    let parse_start = Instant::now();
    let results: Vec<Option<(FileId, SourceSemantics)>> = files
        .par_iter()
        .enumerate()
        .map(|(index, file_path)| {
            let Some(language) = detect_language(file_path) else {
                return None;
            };

            let relative_path = file_path
                .strip_prefix(workspace_path)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string();

            let file_id = FileId((index + 1) as u64);

            // Fast path: check mtime + size before reading file content.
            // Phase 1 (under lock): check index, get cache file path if match.
            // Phase 2 (outside lock): read msgpack — parallel I/O, no contention.
            if let Ok(meta) = std::fs::metadata(file_path) {
                let mtime_secs = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let file_size = meta.len();

                let cache_file_path = {
                    let mut cache_guard = cache.lock().unwrap();
                    cache_guard.check_metadata(&relative_path, mtime_secs, file_size)
                };

                if let Some((_hash, cache_path)) = cache_file_path {
                    // Read msgpack outside the lock — parallel across threads
                    if let Ok(file) = std::fs::File::open(&cache_path) {
                        let reader = std::io::BufReader::new(file);
                        if let Ok(semantics) = rmp_serde::from_read::<_, SourceSemantics>(reader) {
                            cache.lock().unwrap().record_metadata_hit();
                            return Some((file_id, semantics));
                        }
                    }
                }
            }

            // Slow path: read file, compute content hash, check cache.
            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(e) => {
                    if verbose {
                        eprintln!("Warning: Could not read {}: {}", file_path.display(), e);
                    }
                    return None;
                }
            };

            // Compute content hash
            let content_hash = SemanticsCache::hash_content(&content);

            // Try content-hash cache
            {
                let mut cache_guard = cache.lock().unwrap();
                if let Some(cached_semantics) = cache_guard.get(&relative_path, content_hash) {
                    return Some((file_id, cached_semantics));
                }
            }

            let source_file = SourceFile {
                path: relative_path.clone(),
                language,
                content: content.clone(),
            };

            // Parse and build semantics based on language
            let semantics = match language {
                Language::Python => {
                    let parsed = match python::parse_python_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            cache.lock().unwrap().record_miss();
                            return None;
                        }
                    };
                    let mut sem = PyFileSemantics::from_parsed(&parsed);
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Python(sem)
                }
                Language::Go => {
                    let parsed = match go::parse_go_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            cache.lock().unwrap().record_miss();
                            return None;
                        }
                    };
                    let mut sem = GoFileSemantics::from_parsed(&parsed);
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Go(sem)
                }
                Language::Rust => {
                    let parsed = match rust_parse::parse_rust_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            cache.lock().unwrap().record_miss();
                            return None;
                        }
                    };
                    let sem = match build_rust_semantics(&parsed) {
                        Ok(s) => s,
                        Err(_) => RustFileSemantics::from_parsed(&parsed),
                    };
                    SourceSemantics::Rust(sem)
                }
                Language::Typescript => {
                    let parsed = match typescript::parse_typescript_file(file_id, &source_file) {
                        Ok(p) => p,
                        Err(e) => {
                            if verbose {
                                eprintln!("Warning: Could not parse {}: {}", relative_path, e);
                            }
                            cache.lock().unwrap().record_miss();
                            return None;
                        }
                    };
                    let mut sem = TsFileSemantics::from_parsed(&parsed);
                    if let Err(e) = sem.analyze_frameworks(&parsed) {
                        if verbose {
                            eprintln!(
                                "Warning: Framework analysis failed for {}: {}",
                                relative_path, e
                            );
                        }
                    }
                    SourceSemantics::Typescript(sem)
                }
                _ => {
                    if verbose {
                        eprintln!(
                            "Skipping unsupported language for {}: {:?}",
                            relative_path, language
                        );
                    }
                    return None;
                }
            };

            // Store in cache (include mtime+size for fast metadata pre-check next run)
            {
                let (mtime_secs, file_size) = std::fs::metadata(file_path)
                    .ok()
                    .map(|m| {
                        let mtime = m
                            .modified()
                            .ok()
                            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        (mtime, m.len())
                    })
                    .unwrap_or((0, 0));
                let mut cache_guard = cache.lock().unwrap();
                cache_guard.set(
                    &relative_path,
                    content_hash,
                    mtime_secs,
                    file_size,
                    &semantics,
                );
            }

            Some((file_id, semantics))
        })
        .collect();
    let parse_ms = parse_start.elapsed().as_millis();

    let mut semantics_entries: Vec<(FileId, Arc<SourceSemantics>)> = Vec::new();
    let mut all_semantics: Vec<SourceSemantics> = Vec::new();
    let mut content_hashes: Vec<u64> = Vec::new();

    for result in results {
        if let Some((file_id, semantics)) = result {
            all_semantics.push(semantics.clone());
            semantics_entries.push((file_id, Arc::new(semantics)));
        }
    }

    // Get final cache stats
    let cache_stats = cache.lock().unwrap().stats().clone();

    if verbose {
        eprintln!(
            "Parsed {} files (cache: {} hits, {} misses, {:.1}% hit rate)",
            semantics_entries.len(),
            cache_stats.hits,
            cache_stats.misses,
            cache_stats.hit_rate()
        );
        eprintln!("{} File read + cache: {}ms", "TIMING".yellow(), parse_ms);
    }

    // Build or load the code graph.
    // If all files were cache hits, try to load a pre-built graph from disk
    // to avoid rebuilding petgraph (~1.3s on large workspaces).
    let graph_start = Instant::now();
    let all_cache_hits = cache_stats.misses == 0;
    let graph_cache_path = workspace_path
        .join(".unfault")
        .join("cache")
        .join("graph.msgpack");

    // Compute aggregate hash over sorted content hashes to key the graph cache.
    {
        let mut cache_guard = cache.lock().unwrap();
        content_hashes = files
            .iter()
            .filter_map(|f| {
                let rel = f
                    .strip_prefix(workspace_path)
                    .unwrap_or(f)
                    .to_string_lossy()
                    .to_string();
                let path_hash = xxhash_rust::xxh3::xxh3_64(rel.as_bytes());
                cache_guard.get_stored_content_hash(path_hash)
            })
            .collect();
    }
    content_hashes.sort_unstable();
    let aggregate_hash = {
        let bytes: Vec<u8> = content_hashes
            .iter()
            .flat_map(|h| h.to_le_bytes())
            .collect();
        xxhash_rust::xxh3::xxh3_64(&bytes)
    };

    let code_graph = if all_cache_hits {
        try_load_graph_cache(&graph_cache_path, aggregate_hash, verbose)
            .unwrap_or_else(|| build_code_graph(&semantics_entries))
    } else {
        build_code_graph(&semantics_entries)
    };

    // Save graph cache when all entries were cache hits (graph is stable)
    // and the cache file doesn't already match.
    if all_cache_hits {
        let _ = save_graph_cache(&graph_cache_path, aggregate_hash, &code_graph, verbose);
    }

    let graph_ms = graph_start.elapsed().as_millis();

    let stats = code_graph.stats();
    if verbose {
        eprintln!(
            "Built graph: {} files, {} functions, {} imports, {} library usages",
            stats.file_count,
            stats.function_count,
            stats.import_edge_count,
            stats.uses_library_edge_count
        );
        eprintln!("{} Graph build: {}ms", "TIMING".yellow(), graph_ms);
    }

    // Log detailed graph information
    debug!("[GRAPH] Graph statistics:");
    debug!("  - Total nodes: {}", code_graph.graph.node_count());
    debug!("  - Total edges: {}", code_graph.graph.edge_count());
    debug!("  - File nodes: {}", stats.file_count);
    debug!("  - Function nodes: {}", stats.function_count);
    debug!("  - Class nodes: {}", stats.class_count);
    debug!("  - Import edges: {}", stats.import_edge_count);
    debug!("  - Contains edges: {}", stats.contains_edge_count);
    debug!("  - Uses library edges: {}", stats.uses_library_edge_count);
    debug!("  - Calls edges: {}", stats.calls_edge_count);
    debug!("  - External modules: {}", stats.external_module_count);

    // Create IR and log serialization details
    let ir = IntermediateRepresentation::new(all_semantics, code_graph);

    let serialization_start = Instant::now();
    match serde_json::to_string(&ir) {
        Ok(json) => {
            let json_size = json.len();
            let json_size_mb = json_size as f64 / (1024.0 * 1024.0);
            let serialization_ms = serialization_start.elapsed().as_millis();
            debug!("[GRAPH] Serialization details:");
            debug!(
                "  - JSON size: {} bytes ({:.2} MB)",
                json_size, json_size_mb
            );
            debug!("  - Serialization time: {}ms", serialization_ms);
            debug!("  - Semantics count: {}", ir.semantics.len());
        }
        Err(e) => {
            debug!("[GRAPH] Failed to serialize IR: {}", e);
        }
    }

    Ok(IrBuildResult { ir, cache_stats })
}

/// Discover source files in a directory using ignore patterns.
///
/// Test files are automatically excluded — they consistently produce false
/// positives when unfault traces cross-file references back to test callers.
fn discover_source_files(workspace_path: &Path) -> Result<Vec<PathBuf>> {
    use ignore::WalkBuilder;

    let mut files = Vec::new();

    let walker = WalkBuilder::new(workspace_path)
        .hidden(true)
        .git_ignore(true)
        .git_exclude(true)
        .build();

    for entry in walker {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && detect_language(path).is_some() && !is_test_file(path) {
            files.push(path.to_path_buf());
        }
    }

    Ok(files)
}

/// Returns `true` if `path` looks like a test file for any supported language.
///
/// Patterns covered per language:
/// - **Python**: `test_*.py`, `*_test.py`, `*_tests.py`, `conftest.py`,
///   paths containing `/tests/` or `/test/`
/// - **Go**: `*_test.go`, paths containing `/testdata/` or `/test/`
/// - **TypeScript / JavaScript**: `*.test.{ts,tsx,js}`, `*.spec.{ts,tsx,js}`,
///   paths containing `/__tests__/`, `/test/`, or `/tests/`
/// - **Rust**: `test_*.rs`, `*_test.rs`, paths containing `/tests/`
///   (in-file `#[cfg(test)]` blocks are already suppressed by the analysis layer)
pub fn is_test_file(path: &Path) -> bool {
    // Build a forward-slash path string for portable pattern matching.
    let path_str = path.to_string_lossy();
    let path_norm = path_str.replace('\\', "/");

    let filename = path_norm.rsplit('/').next().unwrap_or(&path_norm);
    let filename_lower = filename.to_lowercase();

    // ── Python ──────────────────────────────────────────────────────────────
    if filename_lower.ends_with(".py") {
        return filename_lower.starts_with("test_")
            || filename_lower.ends_with("_test.py")
            || filename_lower.ends_with("_tests.py")
            || filename_lower == "conftest.py"
            || path_norm.contains("/tests/")
            || path_norm.contains("/test/");
    }

    // ── Go ──────────────────────────────────────────────────────────────────
    if filename_lower.ends_with(".go") {
        return filename_lower.ends_with("_test.go")
            || path_norm.contains("/testdata/")
            || path_norm.contains("/test/");
    }

    // ── TypeScript / JavaScript ──────────────────────────────────────────────
    if filename_lower.ends_with(".ts")
        || filename_lower.ends_with(".tsx")
        || filename_lower.ends_with(".js")
        || filename_lower.ends_with(".jsx")
        || filename_lower.ends_with(".mjs")
        || filename_lower.ends_with(".cjs")
    {
        return filename_lower.contains(".test.")
            || filename_lower.contains(".spec.")
            || path_norm.contains("/__tests__/")
            || path_norm.contains("/test/")
            || path_norm.contains("/tests/");
    }

    // ── Rust ────────────────────────────────────────────────────────────────
    if filename_lower.ends_with(".rs") {
        return filename_lower.starts_with("test_")
            || filename_lower.ends_with("_test.rs")
            || path_norm.contains("/tests/");
    }

    false
}

/// Detect language from file extension.
fn detect_language(path: &Path) -> Option<Language> {
    let ext = path.extension()?.to_str()?;
    match ext {
        "py" => Some(Language::Python),
        "go" => Some(Language::Go),
        "rs" => Some(Language::Rust),
        "ts" | "tsx" | "js" | "jsx" => Some(Language::Typescript),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── is_test_file ─────────────────────────────────────────────────────────

    #[test]
    fn is_test_file_python_prefix() {
        assert!(is_test_file(Path::new("test_auth.py")));
        assert!(is_test_file(Path::new("Test_Auth.py"))); // case-insensitive
        assert!(is_test_file(Path::new("src/test_router.py")));
    }

    #[test]
    fn is_test_file_python_suffix() {
        assert!(is_test_file(Path::new("auth_test.py")));
        assert!(is_test_file(Path::new("auth_tests.py")));
    }

    #[test]
    fn is_test_file_python_conftest() {
        assert!(is_test_file(Path::new("conftest.py")));
        assert!(is_test_file(Path::new("src/conftest.py")));
    }

    #[test]
    fn is_test_file_python_test_dir() {
        assert!(is_test_file(Path::new("project/tests/auth.py")));
        assert!(is_test_file(Path::new("src/test/helper.py")));
    }

    #[test]
    fn is_test_file_python_regular_files_pass() {
        assert!(!is_test_file(Path::new("router.py")));
        assert!(!is_test_file(Path::new("testing_utils.py"))); // 'testing_' is not 'test_'
        assert!(!is_test_file(Path::new("src/auth.py")));
    }

    #[test]
    fn is_test_file_go_suffix() {
        assert!(is_test_file(Path::new("handler_test.go")));
        assert!(is_test_file(Path::new("src/handler_test.go")));
    }

    #[test]
    fn is_test_file_go_testdata_dir() {
        assert!(is_test_file(Path::new("project/testdata/fixture.go")));
    }

    #[test]
    fn is_test_file_go_test_dir() {
        assert!(is_test_file(Path::new("project/test/helper.go")));
    }

    #[test]
    fn is_test_file_go_regular_files_pass() {
        assert!(!is_test_file(Path::new("handler.go")));
        assert!(!is_test_file(Path::new("testing.go"))); // common stdlib import file
    }

    #[test]
    fn is_test_file_ts_dot_test() {
        assert!(is_test_file(Path::new("handler.test.ts")));
        assert!(is_test_file(Path::new("handler.test.tsx")));
        assert!(is_test_file(Path::new("handler.test.js")));
    }

    #[test]
    fn is_test_file_ts_dot_spec() {
        assert!(is_test_file(Path::new("handler.spec.ts")));
        assert!(is_test_file(Path::new("handler.spec.tsx")));
        assert!(is_test_file(Path::new("handler.spec.js")));
    }

    #[test]
    fn is_test_file_ts_tests_dirs() {
        assert!(is_test_file(Path::new("src/__tests__/auth.ts")));
        assert!(is_test_file(Path::new("src/test/auth.ts")));
        assert!(is_test_file(Path::new("src/tests/auth.ts")));
    }

    #[test]
    fn is_test_file_ts_regular_files_pass() {
        assert!(!is_test_file(Path::new("handler.ts")));
        assert!(!is_test_file(Path::new("src/router.tsx")));
        // "testing-utils.ts" does NOT contain ".test." or ".spec."
        assert!(!is_test_file(Path::new("testing-utils.ts")));
    }

    #[test]
    fn is_test_file_rust_prefix() {
        assert!(is_test_file(Path::new("test_auth.rs")));
    }

    #[test]
    fn is_test_file_rust_suffix() {
        assert!(is_test_file(Path::new("auth_test.rs")));
    }

    #[test]
    fn is_test_file_rust_tests_dir() {
        // Integration tests live in <crate>/tests/
        assert!(is_test_file(Path::new("mylib/tests/integration.rs")));
    }

    #[test]
    fn is_test_file_rust_regular_files_pass() {
        assert!(!is_test_file(Path::new("handler.rs")));
        assert!(!is_test_file(Path::new("src/router.rs")));
        // src/lib.rs contains #[cfg(test)] but is not a test file
        assert!(!is_test_file(Path::new("src/lib.rs")));
    }

    #[test]
    fn is_test_file_non_source_files_pass() {
        assert!(!is_test_file(Path::new("test_config.json")));
        assert!(!is_test_file(Path::new("README.md")));
    }

    // ── detect_language ──────────────────────────────────────────────────────

    #[test]
    fn test_detect_language() {
        assert_eq!(
            detect_language(Path::new("test.py")),
            Some(Language::Python)
        );
        assert_eq!(detect_language(Path::new("test.go")), Some(Language::Go));
        assert_eq!(detect_language(Path::new("test.rs")), Some(Language::Rust));
        assert_eq!(
            detect_language(Path::new("test.ts")),
            Some(Language::Typescript)
        );
        assert_eq!(
            detect_language(Path::new("test.tsx")),
            Some(Language::Typescript)
        );
        assert_eq!(detect_language(Path::new("test.txt")), None);
    }

    #[test]
    fn test_build_ir_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.file_count(), 0);
    }

    #[test]
    fn test_build_ir_python_file() {
        let temp_dir = TempDir::new().unwrap();
        let py_file = temp_dir.path().join("test.py");
        fs::write(
            &py_file,
            r#"
def hello():
    pass

def caller():
    hello()
"#,
        )
        .unwrap();

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        // Should have 1 file
        assert_eq!(ir.file_count(), 1);

        // Should have functions in the graph
        let stats = ir.graph.stats();
        assert!(stats.function_count >= 2);
    }

    #[test]
    fn test_build_ir_with_imports() {
        let temp_dir = TempDir::new().unwrap();

        // Create a module structure
        let src_dir = temp_dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();

        fs::write(
            src_dir.join("main.py"),
            r#"
from src.utils import helper

def main():
    helper()
"#,
        )
        .unwrap();

        fs::write(
            src_dir.join("utils.py"),
            r#"
def helper():
    print("hello")
"#,
        )
        .unwrap();

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        // Should have 2 files
        assert_eq!(ir.file_count(), 2);

        // Should have functions
        let stats = ir.graph.stats();
        assert!(stats.function_count >= 2);
    }

    #[test]
    fn test_ir_serialization() {
        let temp_dir = TempDir::new().unwrap();
        let py_file = temp_dir.path().join("test.py");
        fs::write(
            &py_file,
            r#"
import requests

def fetch_data():
    return requests.get("http://example.com")
"#,
        )
        .unwrap();

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        // Should be serializable to JSON
        let json = serde_json::to_string(&ir);
        assert!(json.is_ok());
        let json_str = json.unwrap();

        // JSON should contain expected content
        assert!(json_str.contains("fetch_data"));
        assert!(json_str.contains("requests"));
    }

    #[test]
    fn test_ir_deserialization_and_rebuild() {
        let temp_dir = TempDir::new().unwrap();
        let py_file = temp_dir.path().join("test.py");
        fs::write(
            &py_file,
            r#"
import requests

def fetch_data():
    return requests.get("http://example.com")
"#,
        )
        .unwrap();

        let ir = build_ir(temp_dir.path(), None, false).unwrap();

        // Serialize
        let json = serde_json::to_string(&ir).unwrap();

        // Deserialize
        let mut ir_restored: IntermediateRepresentation = serde_json::from_str(&json).unwrap();

        // Rebuild indexes (required after deserialization)
        ir_restored.rebuild_graph_indexes();

        // Stats should match
        let stats_before = ir.graph.stats();
        let stats_after = ir_restored.graph.stats();
        assert_eq!(stats_before.file_count, stats_after.file_count);
        assert_eq!(stats_before.function_count, stats_after.function_count);
        assert_eq!(
            stats_before.external_module_count,
            stats_after.external_module_count
        );
    }

    #[test]
    fn test_build_ir_with_specific_files() {
        let temp_dir = TempDir::new().unwrap();

        // Create multiple files
        let file1 = temp_dir.path().join("include.py");
        let file2 = temp_dir.path().join("exclude.py");
        fs::write(&file1, "def included(): pass").unwrap();
        fs::write(&file2, "def excluded(): pass").unwrap();

        // Build IR with only specific files
        let files = vec![file1];
        let ir = build_ir(temp_dir.path(), Some(&files), false).unwrap();

        // Should only have 1 file
        assert_eq!(ir.file_count(), 1);

        // Check that only the included function is in the graph
        let stats = ir.graph.stats();
        assert_eq!(stats.function_count, 1);
    }

    #[test]
    fn test_build_ir_go_file() {
        let temp_dir = TempDir::new().unwrap();
        let go_file = temp_dir.path().join("main.go");
        fs::write(
            &go_file,
            r#"
package main

import "fmt"

func main() {
    fmt.Println("Hello")
}
"#,
        )
        .unwrap();

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        assert_eq!(ir.file_count(), 1);
        let stats = ir.graph.stats();
        assert!(stats.function_count >= 1);
    }

    #[test]
    fn test_build_ir_typescript_file() {
        let temp_dir = TempDir::new().unwrap();
        let ts_file = temp_dir.path().join("app.ts");
        fs::write(
            &ts_file,
            r#"
import express from 'express';

function handler(req: any, res: any) {
    res.json({ ok: true });
}
"#,
        )
        .unwrap();

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        assert_eq!(ir.file_count(), 1);
        let stats = ir.graph.stats();
        assert!(stats.function_count >= 1);
    }

    #[test]
    fn test_build_ir_rust_file() {
        let temp_dir = TempDir::new().unwrap();
        let rs_file = temp_dir.path().join("lib.rs");
        fs::write(
            &rs_file,
            r#"
use std::io;

fn process_data() -> io::Result<()> {
    Ok(())
}
"#,
        )
        .unwrap();

        let result = build_ir(temp_dir.path(), None, false);
        assert!(result.is_ok());
        let ir = result.unwrap();

        // Rust semantics builder currently uses from_parsed() which creates an empty structure.
        // The full Rust analyzer populates functions separately. For now, we just verify
        // that the file is parsed without error and included in the IR.
        assert_eq!(ir.file_count(), 1);
        let stats = ir.graph.stats();
        assert_eq!(stats.file_count, 1);
        // Note: stats.function_count may be 0 until Rust semantics extraction is fully implemented
    }
}
