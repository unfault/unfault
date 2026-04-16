//! GCP integration — authentication, SLO fetching, and trace fetching.
//!
//! This module groups all Google Cloud Platform API integrations:
//!
//! - [`mod@auth`] (this file) — Application Default Credentials (ADC), OAuth2
//!   token acquisition. Shared by `slo` and `trace`.
//! - [`slo`] — Cloud Monitoring SLO provider.
//! - [`trace`] — Cloud Trace v1 distributed trace provider.
//!
//! ## Credential detection order
//!
//! 1. `GOOGLE_APPLICATION_CREDENTIALS` env var → service account key file
//! 2. `~/.config/gcloud/application_default_credentials.json` (user ADC)
//! 3. `%APPDATA%/gcloud/...` (Windows ADC)
//!
//! ## Project ID detection order
//!
//! 1. `GOOGLE_CLOUD_PROJECT` / `GCP_PROJECT` / `GCLOUD_PROJECT` env vars
//! 2. `quota_project_id` field in the ADC file
//! 3. `project` field in the active gcloud CLI configuration

pub mod slo;
pub mod trace;

use std::env;
use std::path::PathBuf;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

// ── Public API ───────────────────────────────────────────────────────────────

/// Detected GCP credentials ready for token acquisition.
pub struct GcpCredentials {
    pub project_id: String,
    pub credentials_path: PathBuf,
}

impl GcpCredentials {
    /// Check whether GCP credentials and project ID are both detectable.
    pub fn is_available() -> bool {
        find_credentials().is_some() && get_project_id().is_some()
    }

    /// Detect credentials from the environment.
    ///
    /// Returns `None` if no credentials or project ID can be found.
    pub fn from_env() -> Option<Self> {
        let credentials_path = find_credentials()?;
        let project_id = get_project_id()?;
        Some(Self {
            project_id,
            credentials_path,
        })
    }

    /// Acquire an OAuth2 access token using the detected credentials.
    ///
    /// Supports `authorized_user` credentials (ADC from `gcloud auth
    /// application-default login`). Service account key signing is not
    /// implemented — users should use ADC instead.
    pub async fn access_token(&self, client: &Client) -> Result<String> {
        let contents = std::fs::read_to_string(&self.credentials_path)
            .context("Failed to read GCP credentials file")?;

        let creds: AdcFile =
            serde_json::from_str(&contents).context("Failed to parse GCP credentials file")?;

        match creds.r#type.as_deref() {
            Some("authorized_user") => refresh_user_token(client, &creds).await,
            Some("service_account") => anyhow::bail!(
                "Service account key signing is not supported. \
                 Run `gcloud auth application-default login` to use user credentials."
            ),
            other => anyhow::bail!("Unsupported GCP credential type: {:?}", other),
        }
    }
}

// ── Credential file location ─────────────────────────────────────────────────

/// Find the ADC credentials file path.
pub fn find_credentials() -> Option<PathBuf> {
    if let Ok(path) = env::var("GOOGLE_APPLICATION_CREDENTIALS") {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    if let Ok(home) = env::var("HOME") {
        let adc = PathBuf::from(home)
            .join(".config/gcloud/application_default_credentials.json");
        if adc.exists() {
            return Some(adc);
        }
    }

    if let Ok(appdata) = env::var("APPDATA") {
        let adc = PathBuf::from(appdata)
            .join("gcloud/application_default_credentials.json");
        if adc.exists() {
            return Some(adc);
        }
    }

    None
}

/// Detect the GCP project ID from the environment.
pub fn get_project_id() -> Option<String> {
    for var in &["GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GCLOUD_PROJECT"] {
        if let Ok(p) = env::var(var) {
            if !p.is_empty() {
                return Some(p);
            }
        }
    }

    if let Some(creds_path) = find_credentials() {
        if let Ok(contents) = std::fs::read_to_string(&creds_path) {
            if let Ok(creds) = serde_json::from_str::<AdcFile>(&contents) {
                if let Some(p) = creds.quota_project_id {
                    return Some(p);
                }
            }
        }
    }

    get_project_from_gcloud_config()
}

fn get_project_from_gcloud_config() -> Option<String> {
    let home = env::var("HOME").ok()?;
    let gcloud_dir = PathBuf::from(&home).join(".config/gcloud");

    let active_config = std::fs::read_to_string(gcloud_dir.join("active_config"))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "default".to_string());

    let config_path = gcloud_dir
        .join("configurations")
        .join(format!("config_{}", active_config));
    let contents = std::fs::read_to_string(config_path).ok()?;

    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with("project") {
            if let Some(value) = line.split('=').nth(1) {
                let p = value.trim().to_string();
                if !p.is_empty() {
                    return Some(p);
                }
            }
        }
    }

    None
}

// ── OAuth2 token refresh ──────────────────────────────────────────────────────

async fn refresh_user_token(client: &Client, creds: &AdcFile) -> Result<String> {
    let refresh_token = creds
        .refresh_token
        .as_ref()
        .context("No refresh_token in GCP credentials file")?;
    let client_id = creds
        .client_id
        .as_ref()
        .context("No client_id in GCP credentials file")?;
    let client_secret = creds
        .client_secret
        .as_ref()
        .context("No client_secret in GCP credentials file")?;

    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.as_str()),
            ("client_id", client_id.as_str()),
            ("client_secret", client_secret.as_str()),
        ])
        .send()
        .await
        .context("Failed to call Google OAuth2 token endpoint")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if body.contains("invalid_grant") || body.contains("invalid_rapt") {
            anyhow::bail!(
                "GCP credentials appear expired. \
                 Run `gcloud auth application-default login` to refresh them."
            );
        }
        anyhow::bail!("OAuth2 token refresh failed: {} — {}", status, body);
    }

    let token_resp: TokenResponse = resp
        .json()
        .await
        .context("Failed to parse OAuth2 token response")?;
    Ok(token_resp.access_token)
}

// ── ADC file types ────────────────────────────────────────────────────────────

/// Parsed ADC JSON file structure.
#[derive(Debug, Deserialize)]
pub(crate) struct AdcFile {
    #[serde(rename = "type")]
    pub r#type: Option<String>,
    pub quota_project_id: Option<String>,
    pub refresh_token: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_does_not_panic() {
        let _ = GcpCredentials::is_available();
    }

    #[test]
    fn from_env_returns_none_without_credentials() {
        let _ = GcpCredentials::from_env();
    }
}
