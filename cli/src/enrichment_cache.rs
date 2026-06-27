//! Short-lived cache for SLO and trace enrichment data.
//!
//! Fetching SLOs from GCP Cloud Monitoring and spans from Cloud Trace takes
//! 5–15 seconds of network time. This data changes on the order of minutes
//! to hours — re-fetching it on every `unfault review` invocation is wasteful.
//!
//! ## Design
//!
//! - Storage: `.unfault/cache/enrichment/<cache_key>.json`
//! - TTL: configurable, default 5 minutes
//! - Cache key: SHA-256 of `(project_id + workspace_slug)`, truncated to 16 hex chars
//! - Format: JSON (human-readable, easy to inspect/delete)
//!
//! ## Invalidation
//!
//! The cache is invalidated by:
//! 1. TTL expiry (time-based, stored in the file)
//! 2. Deleting `.unfault/cache/enrichment/` manually
//! 3. Running `unfault config integrations verify` — intentionally does not
//!    update the cache so fresh data is fetched on the next review
//!
//! ## What is cached
//!
//! - `Vec<SloDefinition>` — SLO definitions from all configured providers
//! - `Vec<RemoteCallPattern>` — cross-service call patterns from Cloud Trace
//! - `Vec<ObservedRoute>` — inbound HTTP routes observed in recent traces
//!
//! Both are stored together in a single cache entry per (project, workspace)
//! pair. If either is missing (e.g. no trace credentials), only the available
//! data is cached.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::slo::types::SloDefinition;
use crate::trace::{ObservedRoute, RemoteCallPattern};

/// Default TTL for enrichment cache entries: 5 minutes.
pub const DEFAULT_TTL_SECS: u64 = 5 * 60;

/// A cached enrichment snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentSnapshot {
    /// Unix timestamp when this entry was created.
    pub created_at: u64,
    /// TTL in seconds — entry is stale after `created_at + ttl_secs`.
    pub ttl_secs: u64,
    /// GCP project ID this data was fetched for (for human inspection).
    pub project_id: String,
    /// Workspace slug this data was scoped to.
    pub workspace_slug: String,
    /// Fetched SLO definitions. Empty if no SLO provider was available.
    pub slos: Vec<SloDefinition>,
    /// Observed cross-service call patterns from traces. Empty if no traces.
    pub trace_patterns: Vec<CachedRemoteCallPattern>,
    /// Observed inbound HTTP routes from traces. Empty if unavailable.
    #[serde(default)]
    pub observed_routes: Vec<CachedObservedRoute>,
}

impl EnrichmentSnapshot {
    pub fn is_fresh(&self) -> bool {
        let now = now_unix_secs();
        now < self.created_at.saturating_add(self.ttl_secs)
    }

    pub fn age_secs(&self) -> u64 {
        now_unix_secs().saturating_sub(self.created_at)
    }
}

/// A serialisable mirror of `RemoteCallPattern`.
///
/// `RemoteCallPattern` lives in the CLI trace module and is not `Serialize` —
/// we mirror the fields here to keep the cache self-contained.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedRemoteCallPattern {
    pub remote_service_name: String,
    pub remote_endpoint: String,
    pub observed_count: u32,
    pub p99_latency_ms: Option<f64>,
    pub local_callers: Vec<String>,
}

impl From<&RemoteCallPattern> for CachedRemoteCallPattern {
    fn from(p: &RemoteCallPattern) -> Self {
        Self {
            remote_service_name: p.remote_service_name.clone(),
            remote_endpoint: p.remote_endpoint.clone(),
            observed_count: p.observed_count,
            p99_latency_ms: p.p99_latency_ms,
            local_callers: p.local_callers.clone(),
        }
    }
}

impl From<CachedRemoteCallPattern> for RemoteCallPattern {
    fn from(c: CachedRemoteCallPattern) -> Self {
        Self {
            remote_service_name: c.remote_service_name,
            remote_endpoint: c.remote_endpoint,
            observed_count: c.observed_count,
            p99_latency_ms: c.p99_latency_ms,
            local_callers: c.local_callers,
        }
    }
}

/// A serialisable mirror of `ObservedRoute`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedObservedRoute {
    pub http_method: Option<String>,
    pub route_path: String,
    pub observed_count: u32,
    pub sample_span_names: Vec<String>,
}

impl From<&ObservedRoute> for CachedObservedRoute {
    fn from(route: &ObservedRoute) -> Self {
        Self {
            http_method: route.http_method.clone(),
            route_path: route.route_path.clone(),
            observed_count: route.observed_count,
            sample_span_names: route.sample_span_names.clone(),
        }
    }
}

impl From<CachedObservedRoute> for ObservedRoute {
    fn from(route: CachedObservedRoute) -> Self {
        Self {
            http_method: route.http_method,
            route_path: route.route_path,
            observed_count: route.observed_count,
            sample_span_names: route.sample_span_names,
        }
    }
}

/// File-based enrichment cache.
pub struct EnrichmentCache {
    cache_dir: PathBuf,
    ttl_secs: u64,
}

impl EnrichmentCache {
    /// Open (or create) the enrichment cache at `workspace_root/.unfault/cache/enrichment/`.
    pub fn open(workspace_root: &Path, ttl_secs: u64) -> Result<Self> {
        let cache_dir = workspace_root
            .join(".unfault")
            .join("cache")
            .join("enrichment");

        std::fs::create_dir_all(&cache_dir)
            .context("Failed to create enrichment cache directory")?;

        Ok(Self {
            cache_dir,
            ttl_secs,
        })
    }

    /// Load a fresh cache entry for the given project + workspace, if one exists.
    ///
    /// Returns `None` if the cache entry is missing or stale.
    pub fn load(&self, project_id: &str, workspace_slug: &str) -> Option<EnrichmentSnapshot> {
        let path = self.cache_path(project_id, workspace_slug);
        let bytes = std::fs::read(&path).ok()?;
        let snapshot: EnrichmentSnapshot = serde_json::from_slice(&bytes).ok()?;
        if snapshot.is_fresh() {
            Some(snapshot)
        } else {
            // Stale — best-effort cleanup; ignore if the file is already gone.
            let _ = std::fs::remove_file(&path); // unfault-ignore: rust.ignored_result
            None
        }
    }

    /// Save an enrichment snapshot to the cache.
    pub fn save(
        &self,
        project_id: &str,
        workspace_slug: &str,
        slos: Vec<SloDefinition>,
        trace_patterns: Vec<CachedRemoteCallPattern>,
        observed_routes: Vec<CachedObservedRoute>,
    ) -> Result<()> {
        let snapshot = EnrichmentSnapshot {
            created_at: now_unix_secs(),
            ttl_secs: self.ttl_secs,
            project_id: project_id.to_string(),
            workspace_slug: workspace_slug.to_string(),
            slos,
            trace_patterns,
            observed_routes,
        };

        let path = self.cache_path(project_id, workspace_slug);
        let json = serde_json::to_string_pretty(&snapshot)
            .context("Failed to serialise enrichment snapshot")?;
        std::fs::write(&path, json).context("Failed to write enrichment cache file")?;

        Ok(())
    }

    /// Delete the cache entry for a given project + workspace, if it exists.
    ///
    /// Used by `--refresh-cache` to force a live fetch on the next run.
    pub fn invalidate(&self, project_id: &str, workspace_slug: &str) {
        let path = self.cache_path(project_id, workspace_slug);
        let _ = std::fs::remove_file(path); // unfault-ignore: rust.ignored_result — intentional best-effort delete
    }

    /// Derive a stable file path for a given (project_id, workspace_slug) pair.
    fn cache_path(&self, project_id: &str, workspace_slug: &str) -> PathBuf {
        let key = format!("{}-{}", project_id, workspace_slug);
        // Simple deterministic slug — no crypto needed, just stable and unique.
        let slug: String = key
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        // Truncate to keep filenames short
        let slug = &slug[..slug.len().min(48)];
        self.cache_dir.join(format!("{}.json", slug))
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn round_trip_empty_snapshot() {
        let dir = TempDir::new().unwrap();
        let cache = EnrichmentCache::open(dir.path(), 300).unwrap();

        cache
            .save("proj-123", "app-a", vec![], vec![], vec![])
            .unwrap();

        let snapshot = cache.load("proj-123", "app-a").unwrap();
        assert!(snapshot.is_fresh());
        assert_eq!(snapshot.project_id, "proj-123");
        assert_eq!(snapshot.workspace_slug, "app-a");
        assert!(snapshot.slos.is_empty());
        assert!(snapshot.trace_patterns.is_empty());
        assert!(snapshot.observed_routes.is_empty());
    }

    #[test]
    fn stale_entry_returns_none() {
        let dir = TempDir::new().unwrap();
        let cache = EnrichmentCache::open(dir.path(), 0).unwrap(); // TTL = 0s

        cache
            .save("proj-123", "app-a", vec![], vec![], vec![])
            .unwrap();

        // Sleep not needed — TTL=0 means any positive age is stale
        // (created_at + 0 <= now)
        let result = cache.load("proj-123", "app-a");
        assert!(result.is_none(), "TTL=0 entry should be stale immediately");
    }

    #[test]
    fn missing_entry_returns_none() {
        let dir = TempDir::new().unwrap();
        let cache = EnrichmentCache::open(dir.path(), 300).unwrap();
        assert!(cache.load("no-project", "no-workspace").is_none());
    }

    #[test]
    fn different_keys_dont_collide() {
        let dir = TempDir::new().unwrap();
        let cache = EnrichmentCache::open(dir.path(), 300).unwrap();

        cache
            .save("proj-123", "app-a", vec![], vec![], vec![])
            .unwrap();
        cache
            .save("proj-123", "app-b", vec![], vec![], vec![])
            .unwrap();

        assert!(cache.load("proj-123", "app-a").is_some());
        assert!(cache.load("proj-123", "app-b").is_some());
        assert!(cache.load("proj-123", "app-c").is_none());
    }
}
