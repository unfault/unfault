//! Dynatrace SLO provider.

use std::env;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

use crate::slo::types::{SloDefinition, SloProviderKind};

/// Dynatrace SLO provider.
pub struct DynatraceSloProvider {
    api_token: String,
    environment_url: String,
}

impl DynatraceSloProvider {
    /// Check if Dynatrace credentials are available.
    pub fn is_available() -> bool {
        env::var("DT_API_TOKEN").is_ok() && env::var("DT_ENVIRONMENT_URL").is_ok()
    }

    /// Create a provider from environment variables.
    ///
    /// Returns `None` if credentials are not available.
    pub fn from_env() -> Option<Self> {
        let api_token = env::var("DT_API_TOKEN").ok()?;
        let environment_url = env::var("DT_ENVIRONMENT_URL")
            .ok()?
            .trim_end_matches('/')
            .to_string();
        Some(Self {
            api_token,
            environment_url,
        })
    }

    /// Fetch all SLOs from Dynatrace (paginated).
    pub async fn fetch_slos(&self, client: &Client) -> Result<Vec<SloDefinition>> {
        let mut all_slos = Vec::new();
        let mut next_page_key: Option<String> = None;

        loop {
            let url = match &next_page_key {
                Some(key) => format!(
                    "{}/api/v2/slo?nextPageKey={}",
                    self.environment_url, key
                ),
                None => format!(
                    "{}/api/v2/slo?pageSize=100&evaluate=true",
                    self.environment_url
                ),
            };

            let resp = client
                .get(&url)
                .header("Authorization", format!("Api-Token {}", self.api_token))
                .header("Accept", "application/json")
                .send()
                .await
                .context("Failed to send request to Dynatrace API")?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Dynatrace API error: {} — {}", status, body);
            }

            let response: DynatraceSloResponse =
                resp.json().await.context("Failed to parse Dynatrace SLO response")?;

            all_slos.extend(response.slo.into_iter().map(|s| self.convert_slo(s)));

            match response.next_page_key {
                Some(key) => next_page_key = Some(key),
                None => break,
            }
        }

        Ok(all_slos)
    }

    fn convert_slo(&self, slo: DynatraceSlo) -> SloDefinition {
        let path_pattern = extract_path_from_name(&slo.name).or_else(|| {
            slo.description
                .as_ref()
                .and_then(|d| extract_path_from_name(d))
        });

        let timeframe = slo
            .timeframe
            .as_ref()
            .map(|t| t.to_lowercase())
            .unwrap_or_else(|| "30d".to_string());

        SloDefinition {
            id: slo.id.clone(),
            name: slo.name,
            provider: SloProviderKind::Dynatrace,
            path_pattern,
            http_method: None,
            target_percent: slo.target,
            current_percent: slo.evaluated_percentage,
            error_budget_remaining: slo.error_budget,
            timeframe,
            dashboard_url: Some(format!(
                "{}/ui/settings/builtin:monitoring.slo/{}",
                self.environment_url, slo.id
            )),
        }
    }
}

/// Try to extract a URL path pattern from an SLO name or description.
///
/// Looks for patterns like "API /users availability" or "Latency for GET /orders".
fn extract_path_from_name(text: &str) -> Option<String> {
    for word in text.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '*');
        if clean.starts_with('/') && clean.len() > 1 {
            return Some(clean.to_string());
        }
    }
    None
}

// ── Wire types ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynatraceSloResponse {
    slo: Vec<DynatraceSlo>,
    next_page_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DynatraceSlo {
    id: String,
    name: String,
    description: Option<String>,
    target: f64,
    timeframe: Option<String>,
    evaluated_percentage: Option<f64>,
    error_budget: Option<f64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_path_from_name_works() {
        assert_eq!(
            extract_path_from_name("API /users availability"),
            Some("/users".to_string())
        );
        assert_eq!(
            extract_path_from_name("Service: /api/v1/users latency"),
            Some("/api/v1/users".to_string())
        );
        assert_eq!(extract_path_from_name("General availability SLO"), None);
    }

    #[test]
    fn is_available_checks_both_vars() {
        let has_token = env::var("DT_API_TOKEN").is_ok();
        let has_url = env::var("DT_ENVIRONMENT_URL").is_ok();
        assert_eq!(DynatraceSloProvider::is_available(), has_token && has_url);
    }
}
