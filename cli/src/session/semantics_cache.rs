//! Semantics cache for accelerating repeated analysis runs.
//!
//! ## Design
//!
//! - Cache key: (relative_path, content_hash_xxh3_64)
//! - Cache value: MessagePack-serialized SourceSemantics
//! - Storage: `.unfault/cache/semantics/<hash>.msgpack`
//! - Index: `.unfault/cache/semantics/index.msgpack` — persisted HashMap so
//!   `open()` does a single file read instead of a full `readdir` scan.
//! - Invalidation: Content hash mismatch or cache version bump
//!
//! ## Concurrency model
//!
//! After `open()` the index is immutable — reads need no synchronisation.
//! Hit/miss counters use `AtomicUsize` so they can be incremented from any
//! thread without a lock. Writes (`set`) happen only on cache misses and are
//! coordinated by the caller with a `Mutex<SemanticsCache>` that is only
//! contended on the rare slow path.

use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result};
use xxhash_rust::xxh3::xxh3_64;

use unfault_core::semantics::SourceSemantics;

/// Current cache format version. Bump this when semantics structure changes.
const CACHE_VERSION: u32 = 5;

/// Cache metadata stored in meta.json
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CacheMeta {
    version: u32,
    created_at: u64,
}

/// Serialisable form of a cache index entry, stored in `index.msgpack`.
///
/// Mirrors `CacheEntry` but uses owned types so it can be derived with serde.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IndexEntry {
    /// Relative filename inside the semantics cache directory.
    filename: String,
    content_hash: u64,
    mtime_secs: u64,
    file_size: u64,
}

/// Entry in the in-memory cache index
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Path to the cached msgpack file
    cache_path: PathBuf,
    /// Content hash of the source file
    content_hash: u64,
    /// Last-modified time of the source file (seconds since UNIX epoch).
    mtime_secs: u64,
    /// File size in bytes.
    file_size: u64,
}

/// Statistics about cache usage during a build.
///
/// Uses `AtomicUsize` so threads can update counts without holding any lock.
#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: AtomicUsize,
    pub misses: AtomicUsize,
}

impl CacheStats {
    pub fn hit_rate(&self) -> f64 {
        let h = self.hits.load(Ordering::Relaxed);
        let m = self.misses.load(Ordering::Relaxed);
        let total = h + m;
        if total == 0 {
            0.0
        } else {
            (h as f64 / total as f64) * 100.0
        }
    }

    /// Snapshot for display — cheap copy of the current values.
    pub fn snapshot(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }
}

/// A plain-data snapshot of `CacheStats` for display / logging.
#[derive(Debug, Clone, Default)]
pub struct CacheStatsSnapshot {
    pub hits: usize,
    pub misses: usize,
}

impl CacheStatsSnapshot {
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            (self.hits as f64 / total as f64) * 100.0
        }
    }
}

/// A file-based cache for parsed semantics.
///
/// The index is built once in `open()` and is never mutated on the hot read
/// path. All read methods take `&self` and are safe to call from multiple
/// threads simultaneously without any locking. `set()` takes `&mut self` and
/// is only called on cache misses (the slow path).
#[derive(Debug)]
pub struct SemanticsCache {
    /// Root directory of the cache
    cache_dir: PathBuf,
    /// Immutable after `open()` — no lock required for reads.
    index: HashMap<u64, CacheEntry>,
    /// Lock-free hit/miss counters.
    pub stats: CacheStats,
    /// Whether the cache is enabled.
    enabled: bool,
}

impl SemanticsCache {
    /// Path to the persisted index file inside the cache directory.
    fn index_path(cache_dir: &Path) -> PathBuf {
        cache_dir.join("index.msgpack")
    }

    /// Load the persisted index from disk into a `HashMap`.
    ///
    /// Returns `None` if the file is absent or corrupt — the caller falls
    /// back to the legacy `readdir` scan in that case.
    fn load_index(cache_dir: &Path) -> Option<HashMap<u64, CacheEntry>> {
        let path = Self::index_path(cache_dir);
        let file = fs::File::open(&path).ok()?;
        let entries: Vec<IndexEntry> = rmp_serde::from_read(BufReader::new(file)).ok()?;
        let mut map = HashMap::with_capacity(entries.len());
        for e in entries {
            // Derive path_hash from the filename — same scheme as set().
            // The filename is: <content_hash>_<path_hash>_... so we can
            // parse it back. But path_hash isn't stored explicitly in
            // IndexEntry, so we parse the filename instead.
            let stem = e.filename.strip_suffix(".msgpack").unwrap_or(&e.filename);
            let parts: Vec<&str> = stem.splitn(5, '_').collect();
            if parts.len() >= 2 {
                if let Ok(path_hash) = u64::from_str_radix(parts[1], 16) {
                    map.insert(
                        path_hash,
                        CacheEntry {
                            cache_path: cache_dir.join(&e.filename),
                            content_hash: e.content_hash,
                            mtime_secs: e.mtime_secs,
                            file_size: e.file_size,
                        },
                    );
                }
            }
        }
        Some(map)
    }

    /// Persist the current in-memory index to `index.msgpack`.
    fn save_index(&self) {
        let entries: Vec<IndexEntry> = self
            .index
            .values()
            .filter_map(|e| {
                e.cache_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(|filename| IndexEntry {
                        filename: filename.to_string(),
                        content_hash: e.content_hash,
                        mtime_secs: e.mtime_secs,
                        file_size: e.file_size,
                    })
            })
            .collect();

        let path = Self::index_path(&self.cache_dir);
        if let Ok(file) = fs::File::create(&path) {
            let mut writer = BufWriter::new(file);
            let _ = rmp_serde::encode::write(&mut writer, &entries);
        }
    }

    /// Open or create a cache in the given workspace directory.
    pub fn open(workspace_path: &Path) -> Result<Self> {
        let cache_dir = workspace_path
            .join(".unfault")
            .join("cache")
            .join("semantics");

        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir).context("Failed to create cache directory")?;
        }

        // Check cache version — clear on mismatch.
        let meta_path = cache_dir.join("meta.json");
        let should_clear = if meta_path.exists() {
            let meta: CacheMeta = serde_json::from_reader(BufReader::new(fs::File::open(
                &meta_path,
            )?))
            .unwrap_or(CacheMeta {
                version: 0,
                created_at: 0,
            });
            meta.version != CACHE_VERSION
        } else {
            false
        };

        if should_clear {
            for entry in fs::read_dir(&cache_dir)? {
                let entry = entry?;
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if ext == "msgpack" || path == meta_path {
                    let _ = fs::remove_file(&path);
                }
            }
        }

        let meta = CacheMeta {
            version: CACHE_VERSION,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        serde_json::to_writer(BufWriter::new(fs::File::create(&meta_path)?), &meta)?;

        // Fast path: load persisted index (one file read, no readdir).
        // Fall back to readdir scan only when the index is absent or corrupt,
        // then immediately persist it so the next open() is fast.
        let (index, needs_persist) = match Self::load_index(&cache_dir) {
            Some(map) => (map, false),
            None => {
                // Legacy / first-run: rebuild from filenames.
                // Filename: <content_hash>_<path_hash>_<mtime>_<size>_<truncated_path>.msgpack
                let mut map = HashMap::new();
                if let Ok(read_dir) = fs::read_dir(&cache_dir) {
                    for entry in read_dir.flatten() {
                        let path = entry.path();
                        if path.extension().map_or(false, |e| e == "msgpack") {
                            // Skip the index file itself.
                            if path.file_name().map_or(false, |n| n == "index.msgpack") {
                                continue;
                            }
                            let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                            let parts: Vec<&str> = filename.splitn(5, '_').collect();
                            if parts.len() >= 2 {
                                if let (Ok(content_hash), Ok(path_hash)) = (
                                    u64::from_str_radix(parts[0], 16),
                                    u64::from_str_radix(parts[1], 16),
                                ) {
                                    let mtime_secs = parts
                                        .get(2)
                                        .and_then(|s| u64::from_str_radix(s, 16).ok())
                                        .unwrap_or(0);
                                    let file_size = parts
                                        .get(3)
                                        .and_then(|s| u64::from_str_radix(s, 16).ok())
                                        .unwrap_or(0);
                                    map.insert(
                                        path_hash,
                                        CacheEntry {
                                            cache_path: path.clone(),
                                            content_hash,
                                            mtime_secs,
                                            file_size,
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
                (map, true)
            }
        };

        let cache = Self {
            cache_dir,
            index,
            stats: CacheStats::default(),
            enabled: true,
        };

        // Persist after a legacy readdir rebuild so subsequent opens are fast.
        if needs_persist {
            cache.save_index();
        }

        Ok(cache)
    }

    /// Create a disabled cache (always returns None for lookups).
    pub fn disabled() -> Self {
        Self {
            cache_dir: PathBuf::new(),
            index: HashMap::new(),
            stats: CacheStats::default(),
            enabled: false,
        }
    }

    /// Compute the content hash of file content.
    pub fn hash_content(content: &str) -> u64 {
        xxh3_64(content.as_bytes())
    }

    // ── Read methods — all `&self`, no locking required ─────────────────────

    /// Check whether a file's metadata (mtime + size) matches the cached entry.
    ///
    /// Returns `Some((content_hash, cache_path))` when the metadata matches.
    /// The caller should then read the msgpack file **without holding any lock**.
    pub fn check_metadata(
        &self,
        relative_path: &str,
        mtime_secs: u64,
        file_size: u64,
    ) -> Option<(u64, PathBuf)> {
        if !self.enabled {
            return None;
        }
        let path_hash = xxh3_64(relative_path.as_bytes());
        let entry = self.index.get(&path_hash)?;
        // mtime_secs == 0 means legacy entry without metadata.
        if entry.mtime_secs == 0
            || entry.file_size == 0
            || entry.mtime_secs != mtime_secs
            || entry.file_size != file_size
        {
            return None;
        }
        Some((entry.content_hash, entry.cache_path.clone()))
    }

    /// Try to get cached semantics by content hash.
    ///
    /// Returns `Some(semantics)` on a hit, `None` on a miss.
    /// Reads the msgpack file inline — only call this when you already have
    /// the file content and have computed its hash (the slow path).
    pub fn get(&self, relative_path: &str, content_hash: u64) -> Option<SourceSemantics> {
        if !self.enabled {
            return None;
        }
        let path_hash = xxh3_64(relative_path.as_bytes());
        let entry = match self.index.get(&path_hash) {
            Some(e) => e,
            None => {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        if entry.content_hash != content_hash {
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let file = fs::File::open(&entry.cache_path).ok()?;
        match rmp_serde::from_read(BufReader::new(file)) {
            Ok(semantics) => {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                Some(semantics)
            }
            Err(_) => {
                self.stats.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    /// Return the stored content hash for a path hash without doing any I/O.
    /// Used to compute the aggregate hash for graph cache keying.
    pub fn get_stored_content_hash(&self, path_hash: u64) -> Option<u64> {
        self.index.get(&path_hash).map(|e| e.content_hash)
    }

    /// Record a metadata-based cache hit (called after a successful parallel read).
    pub fn record_metadata_hit(&self) {
        self.stats.hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss.
    pub fn record_miss(&self) {
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Get a snapshot of cache statistics.
    pub fn stats_snapshot(&self) -> CacheStatsSnapshot {
        self.stats.snapshot()
    }

    // ── Write method — `&mut self`, call only on the slow (miss) path ────────

    /// Store semantics in the cache.
    pub fn set(
        &mut self,
        relative_path: &str,
        content_hash: u64,
        mtime_secs: u64,
        file_size: u64,
        semantics: &SourceSemantics,
    ) {
        if !self.enabled {
            return;
        }
        let path_hash = xxh3_64(relative_path.as_bytes());
        let safe_path = relative_path.replace(['/', '\\', ':'], "_");
        let truncated_path: String = safe_path.chars().take(40).collect();
        let filename = format!(
            "{:016x}_{:016x}_{:016x}_{:016x}_{}.msgpack",
            content_hash, path_hash, mtime_secs, file_size, truncated_path
        );
        let cache_path = self.cache_dir.join(&filename);
        if let Ok(file) = fs::File::create(&cache_path) {
            let mut writer = BufWriter::new(file);
            if rmp_serde::encode::write(&mut writer, semantics).is_ok() {
                self.index.insert(
                    path_hash,
                    CacheEntry {
                        cache_path,
                        content_hash,
                        mtime_secs,
                        file_size,
                    },
                );
                // Persist the updated index so the next open() is fast.
                self.save_index();
            }
        }
    }

    /// Clear all cached files (including the index).
    pub fn clear(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            if entry.path().extension().map_or(false, |e| e == "msgpack") {
                fs::remove_file(entry.path())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use unfault_core::parse::ast::FileId;
    use unfault_core::parse::python;
    use unfault_core::semantics::python::model::PyFileSemantics;
    use unfault_core::types::context::{Language, SourceFile};

    fn create_test_semantics() -> SourceSemantics {
        let source_file = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: "def hello():\n    pass\n".to_string(),
        };
        let parsed = python::parse_python_file(FileId(1), &source_file).unwrap();
        let sem = PyFileSemantics::from_parsed(&parsed);
        SourceSemantics::Python(sem)
    }

    #[test]
    fn test_hash_content() {
        let hash1 = SemanticsCache::hash_content("hello world");
        let hash2 = SemanticsCache::hash_content("hello world");
        let hash3 = SemanticsCache::hash_content("hello world!");
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_cache_miss_on_empty() {
        let temp_dir = TempDir::new().unwrap();
        let cache = SemanticsCache::open(temp_dir.path()).unwrap();
        let result = cache.get("test.py", 12345);
        assert!(result.is_none());
        assert_eq!(cache.stats.misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_cache_hit() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = SemanticsCache::open(temp_dir.path()).unwrap();
        let semantics = create_test_semantics();
        let content_hash = 12345u64;
        cache.set("test.py", content_hash, 1000, 512, &semantics);
        let result = cache.get("test.py", content_hash);
        assert!(result.is_some());
        assert_eq!(cache.stats.hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_cache_miss_on_hash_change() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = SemanticsCache::open(temp_dir.path()).unwrap();
        let semantics = create_test_semantics();
        cache.set("test.py", 12345, 1000, 512, &semantics);
        let result = cache.get("test.py", 99999);
        assert!(result.is_none());
        assert_eq!(cache.stats.misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_cache_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let content_hash = 12345u64;
        {
            let mut cache = SemanticsCache::open(temp_dir.path()).unwrap();
            let semantics = create_test_semantics();
            cache.set("test.py", content_hash, 1000, 512, &semantics);
        }
        {
            let cache = SemanticsCache::open(temp_dir.path()).unwrap();
            let result = cache.get("test.py", content_hash);
            assert!(result.is_some());
        }
    }

    #[test]
    fn test_hit_rate() {
        let stats = CacheStatsSnapshot {
            hits: 80,
            misses: 20,
        };
        assert!((stats.hit_rate() - 80.0).abs() < 0.01);
    }

    #[test]
    fn test_disabled_cache() {
        let mut cache = SemanticsCache::disabled();
        let semantics = create_test_semantics();
        cache.set("test.py", 12345, 1000, 512, &semantics);
        let result = cache.get("test.py", 12345);
        assert!(result.is_none());
    }

    #[test]
    fn check_metadata_matches() {
        let temp_dir = TempDir::new().unwrap();
        let mut cache = SemanticsCache::open(temp_dir.path()).unwrap();
        let semantics = create_test_semantics();
        cache.set("test.py", 99999, 1234567890, 1024, &semantics);
        // Matching metadata returns the cache path
        let result = cache.check_metadata("test.py", 1234567890, 1024);
        assert!(result.is_some());
        // Mismatched mtime returns None
        let result = cache.check_metadata("test.py", 1234567891, 1024);
        assert!(result.is_none());
        // Mismatched size returns None
        let result = cache.check_metadata("test.py", 1234567890, 1025);
        assert!(result.is_none());
    }
}
