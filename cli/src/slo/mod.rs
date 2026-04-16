//! SLO (Service Level Objective) discovery and graph enrichment.
//!
//! This module provides the top tier of the Hierarchical World Model:
//! Macro-Goals expressed as SLOs from real observability systems.
//!
//! When a user runs `unfault review`, this module:
//! 1. Detects available SLO providers from well-known credential locations
//! 2. Fetches SLO definitions from GCP Cloud Monitoring, Datadog, and Dynatrace
//! 3. Matches SLOs to HTTP route handlers in the code graph via path patterns
//! 4. Enriches the graph with SLO nodes and `MonitoredBy` edges
//!
//! The resulting graph is then used by the World Model (Phase 3) to anchor
//! propagation paths to concrete Macro-Goals rather than just inferred entrypoints.
//!
//! ## Credential detection
//!
//! - **GCP**: `GOOGLE_APPLICATION_CREDENTIALS`, `~/.config/gcloud/application_default_credentials.json`
//! - **Datadog**: `DD_API_KEY` + `DD_APP_KEY`
//! - **Dynatrace**: `DT_API_TOKEN` + `DT_ENVIRONMENT_URL`

pub mod matcher;
pub mod types;

use anyhow::Result;
use reqwest::Client;
use unfault_core::graph::CodeGraph;

pub use types::{SloDefinition, SloProviderKind};

use crate::integration::datadog::slo::DatadogSloProvider;
use crate::integration::dynatrace::slo::DynatraceSloProvider;
use crate::integration::gcp::slo::GcpSloProvider;

/// Result of fetching SLOs from all available providers.
#[derive(Default)]
pub struct SloFetchResult {
    /// SLOs successfully fetched
    pub slos: Vec<SloDefinition>,
    /// Whether any provider had expired/invalid credentials
    pub credentials_expired: bool,
}

/// SLO enricher that discovers, fetches, and links SLOs to the code graph.
pub struct SloEnricher {
    client: Client,
    verbose: bool,
}

impl SloEnricher {
    /// Create a new SLO enricher.
    pub fn new(verbose: bool) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self { client, verbose }
    }

    /// Check if any SLO provider credentials are available.
    pub fn any_provider_available(&self) -> bool {
        DatadogSloProvider::is_available()
            || GcpSloProvider::is_available()
            || DynatraceSloProvider::is_available()
    }

    /// Get a list of available provider names.
    pub fn available_providers(&self) -> Vec<&'static str> {
        let mut providers = Vec::new();
        if DatadogSloProvider::is_available() {
            providers.push("Datadog");
        }
        if GcpSloProvider::is_available() {
            providers.push("GCP");
        }
        if DynatraceSloProvider::is_available() {
            providers.push("Dynatrace");
        }
        providers
    }

    /// Fetch SLOs from all available providers.
    ///
    /// Errors from individual providers are logged but don't fail the overall
    /// fetch — partial results are better than no results.
    pub async fn fetch_all(&self) -> Result<SloFetchResult> {
        let mut result = SloFetchResult::default();

        if let Some(provider) = DatadogSloProvider::from_env() {
            match provider.fetch_slos(&self.client).await {
                Ok(slos) => {
                    if self.verbose {
                        eprintln!("  Fetched {} SLOs from Datadog", slos.len());
                    }
                    result.slos.extend(slos);
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("401") || msg.contains("403") {
                        result.credentials_expired = true;
                    }
                    if self.verbose {
                        eprintln!("  Warning: Failed to fetch Datadog SLOs: {}", e);
                    }
                }
            }
        }

        if let Some(provider) = GcpSloProvider::from_env() {
            match provider.fetch_slos(&self.client).await {
                Ok(slos) => {
                    if self.verbose {
                        eprintln!("  Fetched {} SLOs from GCP", slos.len());
                    }
                    result.slos.extend(slos);
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("expired")
                        || msg.contains("gcloud auth")
                        || msg.contains("401")
                    {
                        result.credentials_expired = true;
                    }
                    if self.verbose {
                        eprintln!("  Warning: Failed to fetch GCP SLOs: {}", e);
                    }
                }
            }
        }

        if let Some(provider) = DynatraceSloProvider::from_env() {
            match provider.fetch_slos(&self.client).await {
                Ok(slos) => {
                    if self.verbose {
                        eprintln!("  Fetched {} SLOs from Dynatrace", slos.len());
                    }
                    result.slos.extend(slos);
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("401") || msg.contains("403") {
                        result.credentials_expired = true;
                    }
                    if self.verbose {
                        eprintln!("  Warning: Failed to fetch Dynatrace SLOs: {}", e);
                    }
                }
            }
        }

        Ok(result)
    }

    /// Enrich a code graph with SLO nodes and `MonitoredBy` edges.
    ///
    /// For each SLO with a path pattern, finds matching HTTP route handlers
    /// and creates edges linking them.
    ///
    /// Returns the number of SLOs added to the graph.
    pub fn enrich_graph(&self, graph: &mut CodeGraph, slos: &[SloDefinition]) -> Result<usize> {
        let mut added = 0;

        for slo in slos {
            if !slo.has_path_pattern() {
                if self.verbose {
                    eprintln!("  Skipping SLO '{}' (no path pattern)", slo.name);
                }
                continue;
            }

            let matching_routes = matcher::find_matching_routes(slo, graph);

            if matching_routes.is_empty() {
                if self.verbose {
                    eprintln!(
                        "  SLO '{}' pattern '{}' matched no routes",
                        slo.name,
                        slo.path_pattern.as_deref().unwrap_or("?")
                    );
                }
                continue;
            }

            if self.verbose {
                eprintln!(
                    "  SLO '{}' matched {} route(s)",
                    slo.name,
                    matching_routes.len()
                );
            }

            graph.add_slo(
                slo.id.clone(),
                slo.name.clone(),
                slo.provider.to_graph_provider(),
                slo.path_pattern.clone().unwrap_or_default(),
                slo.http_method.clone(),
                slo.target_percent,
                slo.current_percent,
                slo.error_budget_remaining,
                slo.timeframe.clone(),
                slo.dashboard_url.clone(),
                matching_routes,
            );

            added += 1;
        }

        Ok(added)
    }

    /// Link a service-level SLO (no path pattern) to all HTTP route handlers.
    ///
    /// Used when an SLO covers an entire service rather than specific paths.
    pub fn link_service_slo_to_all_routes(
        &self,
        graph: &mut CodeGraph,
        slo: &SloDefinition,
    ) -> usize {
        let routes = graph.get_http_route_handlers();
        let route_count = routes.len();
        let route_indices: Vec<_> = routes.iter().map(|(idx, _, _)| *idx).collect();

        if route_indices.is_empty() {
            return 0;
        }

        if self.verbose {
            eprintln!(
                "  Linking service SLO '{}' to {} route(s)",
                slo.name, route_count
            );
        }

        graph.add_slo(
            slo.id.clone(),
            slo.name.clone(),
            slo.provider.to_graph_provider(),
            slo.path_pattern.clone().unwrap_or_else(|| "*".to_string()),
            slo.http_method.clone(),
            slo.target_percent,
            slo.current_percent,
            slo.error_budget_remaining,
            slo.timeframe.clone(),
            slo.dashboard_url.clone(),
            route_indices,
        );

        route_count
    }
}

/// Return service-level SLOs (those without a specific path pattern).
///
/// These are SLOs that apply to an entire service rather than specific paths.
pub fn get_service_level_slos(slos: &[SloDefinition]) -> Vec<&SloDefinition> {
    slos.iter().filter(|s| !s.has_path_pattern()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enricher_creation() {
        let enricher = SloEnricher::new(false);
        let _ = enricher.any_provider_available();
    }
}
