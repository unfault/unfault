//! GCP Cloud Monitoring SLO provider.
//!
//! Fetches SLOs from the Cloud Monitoring API using Application Default
//! Credentials. Authentication is handled by the parent module
//! ([`super::GcpCredentials`]).
//!
//! ## API
//!
//! ```text
//! GET https://monitoring.googleapis.com/v3/projects/{project}/services
//! GET https://monitoring.googleapis.com/v3/{service}/serviceLevelObjectives
//! ```

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

use crate::slo::types::{SloDefinition, SloProviderKind};

use super::GcpCredentials;

/// GCP Cloud Monitoring SLO provider.
pub struct GcpSloProvider {
    project_id: String,
    credentials: GcpCredentials,
}

impl GcpSloProvider {
    /// Check if GCP credentials are available.
    pub fn is_available() -> bool {
        GcpCredentials::is_available()
    }

    /// Create a provider from Application Default Credentials.
    ///
    /// Returns `None` if credentials are not available.
    pub fn from_env() -> Option<Self> {
        let credentials = GcpCredentials::from_env()?;
        let project_id = credentials.project_id.clone();
        Some(Self {
            project_id,
            credentials,
        })
    }

    /// Fetch all SLOs from GCP Cloud Monitoring.
    pub async fn fetch_slos(&self, client: &Client) -> Result<Vec<SloDefinition>> {
        let token = self
            .credentials
            .access_token(client)
            .await
            .context("Failed to acquire GCP token for Cloud Monitoring")?;

        let mut all_slos = Vec::new();
        for service in self.list_services(client, &token).await? {
            all_slos.extend(
                self.list_service_slos(client, &token, &service.name)
                    .await?,
            );
        }
        Ok(all_slos)
    }

    // ── REST calls ──────────────────────────────────────────────────────────

    async fn list_services(&self, client: &Client, token: &str) -> Result<Vec<GcpService>> {
        let url = format!(
            "https://monitoring.googleapis.com/v3/projects/{}/services",
            self.project_id
        );

        let resp = client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to list GCP services")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GCP API error listing services: {} — {}", status, body);
        }

        let response: GcpServicesResponse = resp
            .json()
            .await
            .context("Failed to parse services response")?;
        Ok(response.services.unwrap_or_default())
    }

    async fn list_service_slos(
        &self,
        client: &Client,
        token: &str,
        service_name: &str,
    ) -> Result<Vec<SloDefinition>> {
        let url = format!(
            "https://monitoring.googleapis.com/v3/{}/serviceLevelObjectives",
            service_name
        );

        let resp = client
            .get(&url)
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to list SLOs")?;

        if !resp.status().is_success() {
            if resp.status().as_u16() == 404 {
                return Ok(vec![]);
            }
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GCP API error listing SLOs: {} — {}", status, body);
        }

        let response: GcpSlosResponse =
            resp.json().await.context("Failed to parse SLOs response")?;
        Ok(response
            .service_level_objectives
            .unwrap_or_default()
            .into_iter()
            .map(|slo| self.convert_slo(slo))
            .collect())
    }

    fn convert_slo(&self, slo: GcpSlo) -> SloDefinition {
        let path_pattern = slo.user_labels.as_ref().and_then(|labels| {
            labels
                .get("path")
                .or_else(|| labels.get("endpoint"))
                .cloned()
        });

        let http_method = slo
            .user_labels
            .as_ref()
            .and_then(|labels| labels.get("method").map(|m| m.to_uppercase()));

        let timeframe = slo
            .rolling_period
            .map(|p| format!("rolling_{}", p.trim_end_matches('s')))
            .or(slo.calendar_period.map(|p| p.to_lowercase()))
            .unwrap_or_else(|| "30d".to_string());

        let dashboard_url = Some(format!(
            "https://console.cloud.google.com/monitoring/services/{}?project={}",
            slo.name.split('/').next_back().unwrap_or(&slo.name),
            self.project_id
        ));

        SloDefinition {
            id: slo.name.clone(),
            name: slo.display_name.unwrap_or_else(|| slo.name.clone()),
            provider: SloProviderKind::Gcp,
            path_pattern,
            http_method,
            target_percent: slo.goal * 100.0,
            current_percent: None,
            error_budget_remaining: None,
            timeframe,
            dashboard_url,
        }
    }
}

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GcpServicesResponse {
    services: Option<Vec<GcpService>>,
}

#[derive(Debug, Deserialize)]
struct GcpService {
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpSlosResponse {
    service_level_objectives: Option<Vec<GcpSlo>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GcpSlo {
    name: String,
    display_name: Option<String>,
    goal: f64,
    rolling_period: Option<String>,
    calendar_period: Option<String>,
    user_labels: Option<std::collections::HashMap<String, String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_available_does_not_panic() {
        let _ = GcpSloProvider::is_available();
    }
}
