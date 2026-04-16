//! SLO type definitions shared across providers.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The provider source for an SLO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SloProviderKind {
    /// Google Cloud Monitoring
    Gcp,
    /// Datadog
    Datadog,
    /// Dynatrace
    Dynatrace,
}

impl fmt::Display for SloProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SloProviderKind::Gcp => write!(f, "GCP"),
            SloProviderKind::Datadog => write!(f, "Datadog"),
            SloProviderKind::Dynatrace => write!(f, "Dynatrace"),
        }
    }
}

impl SloProviderKind {
    /// Convert to the core graph's SloProvider type.
    pub fn to_graph_provider(&self) -> unfault_core::graph::SloProvider {
        match self {
            SloProviderKind::Gcp => unfault_core::graph::SloProvider::Gcp,
            SloProviderKind::Datadog => unfault_core::graph::SloProvider::Datadog,
            SloProviderKind::Dynatrace => unfault_core::graph::SloProvider::Dynatrace,
        }
    }
}

/// An SLO definition fetched from an observability provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloDefinition {
    /// Unique identifier from the provider
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// The provider source
    pub provider: SloProviderKind,
    /// URL path pattern this SLO monitors (e.g., "/api/users/*")
    /// None if the SLO doesn't specify a path pattern
    pub path_pattern: Option<String>,
    /// HTTP method if specific (e.g., "GET"), None for all methods
    pub http_method: Option<String>,
    /// Target percentage (e.g., 99.9)
    pub target_percent: f64,
    /// Current evaluated percentage (e.g., 99.85)
    pub current_percent: Option<f64>,
    /// Error budget remaining as percentage
    pub error_budget_remaining: Option<f64>,
    /// Evaluation timeframe (e.g., "30d", "7d")
    pub timeframe: String,
    /// Direct link to SLO in provider dashboard
    pub dashboard_url: Option<String>,
}

impl SloDefinition {
    /// Check if this SLO has a usable path pattern for matching.
    pub fn has_path_pattern(&self) -> bool {
        self.path_pattern
            .as_ref()
            .is_some_and(|p| !p.is_empty() && p != "*")
    }

    /// Extract the service slug this SLO belongs to, if derivable.
    ///
    /// For GCP SLOs, the `id` is the full resource name:
    /// `projects/{project}/services/{service-slug}/serviceLevelObjectives/{slo-id}`
    ///
    /// Returns `Some("app-b")` for a GCP SLO belonging to the `app-b` service.
    /// Returns `None` for providers where the id doesn't encode the service.
    pub fn service_slug(&self) -> Option<&str> {
        // GCP resource name: .../services/{slug}/serviceLevelObjectives/...
        let services_part = self.id.split("/services/").nth(1)?;
        let slug = services_part.split('/').next()?;
        if slug.is_empty() { None } else { Some(slug) }
    }

    /// Check whether this SLO plausibly belongs to the given local service name.
    ///
    /// Matching is case-insensitive and checks:
    /// 1. The service slug extracted from the SLO id (GCP resource name)
    /// 2. The SLO display name contains the local service name as a word
    ///
    /// When neither check is possible (e.g. Datadog/Dynatrace with opaque ids),
    /// returns `true` to preserve the previous behaviour of linking everything.
    pub fn matches_local_service(&self, local_service_name: &str) -> bool {
        let local = local_service_name.to_lowercase();

        // 1. Exact match on the GCP service slug
        if let Some(slug) = self.service_slug() {
            return slug.to_lowercase() == local;
        }

        // 2. Fallback: normalize both strings to alphanumeric-only and check
        // whether the SLO name contains the local service name as a substring.
        // Normalization collapses hyphens/spaces/underscores so that
        // "App A Availability SLO" → "appaavailabilityslo" matches "app-a" → "appa".
        //
        // Only apply when the local name is long enough to avoid false positives
        // (single characters like "a" would match everything).
        if local.len() >= 3 {
            let local_norm: String = local.chars().filter(|c| c.is_alphanumeric()).collect();
            let name_norm: String = self
                .name
                .to_lowercase()
                .chars()
                .filter(|c| c.is_alphanumeric())
                .collect();
            if local_norm.len() >= 3 {
                return name_norm.contains(&local_norm);
            }
        }

        // Cannot determine ownership — link it (safe fallback)
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_slo(id: &str, name: &str) -> SloDefinition {
        SloDefinition {
            id: id.to_string(),
            name: name.to_string(),
            provider: SloProviderKind::Gcp,
            path_pattern: None,
            http_method: None,
            target_percent: 99.9,
            current_percent: None,
            error_budget_remaining: None,
            timeframe: "30d".to_string(),
            dashboard_url: None,
        }
    }

    #[test]
    fn service_slug_extracted_from_gcp_resource_name() {
        let slo = make_slo(
            "projects/443814094407/services/app-b/serviceLevelObjectives/availability",
            "App B Availability SLO",
        );
        assert_eq!(slo.service_slug(), Some("app-b"));
    }

    #[test]
    fn service_slug_none_for_opaque_id() {
        let slo = make_slo("dd-slo-abc123", "My SLO");
        assert_eq!(slo.service_slug(), None);
    }

    #[test]
    fn matches_local_service_gcp_exact() {
        let slo = make_slo(
            "projects/443814094407/services/app-b/serviceLevelObjectives/availability",
            "App B Availability SLO",
        );
        assert!(slo.matches_local_service("app-b"));
        assert!(!slo.matches_local_service("app-a"));
    }

    #[test]
    fn matches_local_service_fallback_name() {
        let slo = make_slo("opaque-id-123", "App A Availability SLO");
        assert!(slo.matches_local_service("app-a"));
        assert!(!slo.matches_local_service("app-b"));
    }

    #[test]
    fn does_not_match_different_service() {
        // "app-a" should not match "App B Availability SLO"
        let slo = make_slo("opaque-id-456", "App B Availability SLO");
        assert!(!slo.matches_local_service("app-a"));
        assert!(slo.matches_local_service("app-b"));
    }
}
