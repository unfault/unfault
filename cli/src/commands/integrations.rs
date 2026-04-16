//! `unfault config integrations` — inspect and verify observability integrations.
//!
//! ## Subcommands
//!
//! ```text
//! unfault config integrations show    — detect credentials, print status table
//! unfault config integrations verify  — detect + make live API calls, confirm auth works
//! ```
//!
//! Neither subcommand modifies any state. They are purely diagnostic.

use anyhow::Result;
use colored::Colorize;
use reqwest::Client;

use crate::exit_codes::*;
use crate::integration::datadog::slo::DatadogSloProvider;
use crate::integration::dynatrace::slo::DynatraceSloProvider;
use crate::integration::gcp::{GcpCredentials, get_project_id};

// ── Public entry points ───────────────────────────────────────────────────────

/// `unfault config integrations show`
///
/// Checks each integration for credential availability and prints a status
/// table. Does **not** make any network calls — purely filesystem/env checks.
pub fn execute_show() -> Result<i32> {
    println!();
    println!("{}", "Integrations".bold().underline());
    println!();

    let rows = detect_all();
    print_table(&rows);
    print_hints(&rows);

    println!();
    Ok(EXIT_SUCCESS)
}

/// `unfault config integrations verify`
///
/// Like `show`, but also fires a lightweight API call for each detected
/// integration to confirm the credentials actually work end-to-end.
/// Exits with `EXIT_ERROR` if any detected integration fails verification.
pub async fn execute_verify() -> Result<i32> {
    println!();
    println!("{}", "Verifying integrations…".bold());
    println!();

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default();

    let mut rows = detect_all();
    verify_all(&client, &mut rows).await;
    print_table(&rows);
    print_hints(&rows);

    let any_failed = rows
        .iter()
        .any(|r| matches!(r.state, State::VerifyFailed(_)));

    println!();
    if any_failed {
        Ok(EXIT_ERROR)
    } else {
        Ok(EXIT_SUCCESS)
    }
}

// ── Integration detection ─────────────────────────────────────────────────────

/// What we know about a single integration.
#[derive(Debug)]
struct IntegrationRow {
    /// Display name, e.g. "GCP Cloud Monitoring (SLOs)"
    name: &'static str,
    /// Provider enum tag used for hints
    kind: IntegrationKind,
    state: State,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntegrationKind {
    GcpSlo,
    GcpTrace,
    Datadog,
    Dynatrace,
}

#[derive(Debug)]
enum State {
    /// No credentials found.
    NotDetected,
    /// Credentials found — not yet verified.
    Detected { detail: String },
    /// Credentials found and API call succeeded.
    VerifyOk { detail: String },
    /// Credentials found but API call failed.
    VerifyFailed(String),
}

/// Detect credentials for all integrations without making network calls.
fn detect_all() -> Vec<IntegrationRow> {
    vec![
        detect_gcp_slo(),
        detect_gcp_trace(),
        detect_datadog(),
        detect_dynatrace(),
    ]
}

fn detect_gcp_slo() -> IntegrationRow {
    let state = if GcpCredentials::is_available() {
        let detail = get_project_id()
            .map(|p| format!("project: {}", p))
            .unwrap_or_else(|| "credentials found".to_string());
        State::Detected { detail }
    } else {
        State::NotDetected
    };
    IntegrationRow {
        name: "GCP Cloud Monitoring (SLOs)",
        kind: IntegrationKind::GcpSlo,
        state,
    }
}

fn detect_gcp_trace() -> IntegrationRow {
    // GCP Trace uses the same credentials as Cloud Monitoring — if one is
    // available, so is the other.
    let state = if GcpCredentials::is_available() {
        let detail = get_project_id()
            .map(|p| format!("project: {}", p))
            .unwrap_or_else(|| "credentials found".to_string());
        State::Detected { detail }
    } else {
        State::NotDetected
    };
    IntegrationRow {
        name: "GCP Cloud Trace",
        kind: IntegrationKind::GcpTrace,
        state,
    }
}

fn detect_datadog() -> IntegrationRow {
    let state = if DatadogSloProvider::is_available() {
        let site = std::env::var("DD_SITE").unwrap_or_else(|_| "datadoghq.com".to_string());
        State::Detected {
            detail: format!("site: {}", site),
        }
    } else {
        State::NotDetected
    };
    IntegrationRow {
        name: "Datadog (SLOs)",
        kind: IntegrationKind::Datadog,
        state,
    }
}

fn detect_dynatrace() -> IntegrationRow {
    let state = if DynatraceSloProvider::is_available() {
        let url = std::env::var("DT_ENVIRONMENT_URL").unwrap_or_default();
        // Strip scheme for brevity: "https://abc.live.dynatrace.com" → "abc.live.dynatrace.com"
        let host = url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        State::Detected {
            detail: format!("env: {}", host),
        }
    } else {
        State::NotDetected
    };
    IntegrationRow {
        name: "Dynatrace (SLOs)",
        kind: IntegrationKind::Dynatrace,
        state,
    }
}

// ── Live verification ─────────────────────────────────────────────────────────

async fn verify_all(client: &Client, rows: &mut Vec<IntegrationRow>) {
    for row in rows.iter_mut() {
        if matches!(row.state, State::NotDetected) {
            continue;
        }
        let result = verify_one(client, row.kind).await;
        row.state = result;
    }
}

async fn verify_one(client: &Client, kind: IntegrationKind) -> State {
    match kind {
        IntegrationKind::GcpSlo => verify_gcp_slo(client).await,
        IntegrationKind::GcpTrace => verify_gcp_trace(client).await,
        IntegrationKind::Datadog => verify_datadog(client).await,
        IntegrationKind::Dynatrace => verify_dynatrace(client).await,
    }
}

async fn verify_gcp_slo(client: &Client) -> State {
    let Some(creds) = GcpCredentials::from_env() else {
        return State::NotDetected;
    };

    let token = match creds.access_token(client).await {
        Ok(t) => t,
        Err(e) => return State::VerifyFailed(credential_hint(e.to_string())),
    };

    // Lightweight probe: list services (empty list is still a 200).
    let url = format!(
        "https://monitoring.googleapis.com/v3/projects/{}/services?pageSize=1",
        creds.project_id
    );
    match client.get(&url).bearer_auth(&token).send().await {
        Ok(resp) if resp.status().is_success() => State::VerifyOk {
            detail: format!("project: {}", creds.project_id),
        },
        Ok(resp) => State::VerifyFailed(format!(
            "API returned {}{}",
            resp.status().as_u16(),
            api_error_hint(resp.status().as_u16())
        )),
        Err(e) => State::VerifyFailed(format!("request failed: {}", e)),
    }
}

async fn verify_gcp_trace(client: &Client) -> State {
    let Some(creds) = GcpCredentials::from_env() else {
        return State::NotDetected;
    };

    let token = match creds.access_token(client).await {
        Ok(t) => t,
        Err(e) => return State::VerifyFailed(credential_hint(e.to_string())),
    };

    // Probe: list traces with pageSize=1 and a narrow time window.
    // A 200 with an empty traces list is expected in a new project — still valid.
    let end = now_rfc3339();
    let start = rfc3339_minus_minutes(&end, 5);
    let url = format!(
        "https://cloudtrace.googleapis.com/v1/projects/{}/traces?pageSize=1&startTime={}&endTime={}",
        creds.project_id, start, end
    );
    match client.get(&url).bearer_auth(&token).send().await {
        Ok(resp) if resp.status().is_success() => State::VerifyOk {
            detail: format!("project: {}", creds.project_id),
        },
        Ok(resp) => State::VerifyFailed(format!(
            "API returned {}{}",
            resp.status().as_u16(),
            api_error_hint(resp.status().as_u16())
        )),
        Err(e) => State::VerifyFailed(format!("request failed: {}", e)),
    }
}

async fn verify_datadog(client: &Client) -> State {
    let Some(provider) = DatadogSloProvider::from_env() else {
        return State::NotDetected;
    };

    // Probe: validate API keys with the Datadog validation endpoint.
    let site = std::env::var("DD_SITE").unwrap_or_else(|_| "datadoghq.com".to_string());
    let url = format!("https://api.{}/api/v1/validate", site);

    let api_key = std::env::var("DD_API_KEY").unwrap_or_default();
    let app_key = std::env::var("DD_APP_KEY").unwrap_or_default();

    // DatadogSloProvider doesn't expose these fields, read directly from env
    let _ = provider; // confirms is_available() was true

    match client
        .get(&url)
        .header("DD-API-KEY", &api_key)
        .header("DD-APPLICATION-KEY", &app_key)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => State::VerifyOk {
            detail: format!("site: {}", site),
        },
        Ok(resp) => State::VerifyFailed(format!(
            "API returned {}{}",
            resp.status().as_u16(),
            api_error_hint(resp.status().as_u16())
        )),
        Err(e) => State::VerifyFailed(format!("request failed: {}", e)),
    }
}

async fn verify_dynatrace(client: &Client) -> State {
    let Some(_provider) = DynatraceSloProvider::from_env() else {
        return State::NotDetected;
    };

    let environment_url = std::env::var("DT_ENVIRONMENT_URL")
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string();
    let api_token = std::env::var("DT_API_TOKEN").unwrap_or_default();

    // Probe: fetch the first SLO page (pageSize=1).
    let url = format!("{}/api/v2/slo?pageSize=1", environment_url);
    match client
        .get(&url)
        .header("Authorization", format!("Api-Token {}", api_token))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            let host = environment_url
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .to_string();
            State::VerifyOk {
                detail: format!("env: {}", host),
            }
        }
        Ok(resp) => State::VerifyFailed(format!(
            "API returned {}{}",
            resp.status().as_u16(),
            api_error_hint(resp.status().as_u16())
        )),
        Err(e) => State::VerifyFailed(format!("request failed: {}", e)),
    }
}

// ── Output ────────────────────────────────────────────────────────────────────

fn print_table(rows: &[IntegrationRow]) {
    // Column widths
    let name_col = rows.iter().map(|r| r.name.len()).max().unwrap_or(20);

    println!(
        "  {:<name_col$}  {}",
        "Integration".dimmed(),
        "Status".dimmed(),
        name_col = name_col,
    );
    println!("  {}", "─".repeat(name_col + 40).dimmed());

    for row in rows {
        let (icon, status_text) = match &row.state {
            State::NotDetected => ("✗".red().to_string(), "not detected".dimmed().to_string()),
            State::Detected { detail } => (
                "~".yellow().to_string(),
                format!("credentials found  ({})", detail).dimmed().to_string(),
            ),
            State::VerifyOk { detail } => (
                "✓".green().to_string(),
                format!("verified  ({})", detail).green().to_string(),
            ),
            State::VerifyFailed(msg) => (
                "✗".red().to_string(),
                format!("auth failed — {}", msg).red().to_string(),
            ),
        };

        println!(
            "  {:<name_col$}  {} {}",
            row.name,
            icon,
            status_text,
            name_col = name_col,
        );
    }
}

fn print_hints(rows: &[IntegrationRow]) {
    let not_detected: Vec<_> = rows
        .iter()
        .filter(|r| matches!(r.state, State::NotDetected))
        .collect();

    let failed: Vec<_> = rows
        .iter()
        .filter(|r| matches!(r.state, State::VerifyFailed(_)))
        .collect();

    if not_detected.is_empty() && failed.is_empty() {
        return;
    }

    println!();

    for row in &failed {
        println!("  {} {}:", "Fix:".yellow().bold(), row.name);
        for hint in setup_hints(row.kind) {
            println!("    {}", hint.dimmed());
        }
        println!();
    }

    if !not_detected.is_empty() {
        println!("  {} To enable missing integrations:", "→".cyan());
        for row in &not_detected {
            println!();
            println!("  {}  {}", "○".dimmed(), row.name.bold());
            for hint in setup_hints(row.kind) {
                println!("    {}", hint.dimmed());
            }
        }
    }
}

fn setup_hints(kind: IntegrationKind) -> &'static [&'static str] {
    match kind {
        IntegrationKind::GcpSlo | IntegrationKind::GcpTrace => &[
            "gcloud auth application-default login",
            "export GOOGLE_CLOUD_PROJECT=<your-project-id>",
            "  (or set quota_project_id in your ADC file)",
        ],
        IntegrationKind::Datadog => &[
            "export DD_API_KEY=<your-api-key>",
            "export DD_APP_KEY=<your-application-key>",
            "  (optional) export DD_SITE=datadoghq.eu  # for EU region",
        ],
        IntegrationKind::Dynatrace => &[
            "export DT_API_TOKEN=<your-api-token>  # requires slo.read scope",
            "export DT_ENVIRONMENT_URL=https://<env-id>.live.dynatrace.com",
        ],
    }
}

// ── Error message helpers ─────────────────────────────────────────────────────

fn api_error_hint(status: u16) -> &'static str {
    match status {
        401 => " — credentials invalid or expired",
        403 => " — credentials valid but missing required scope/permission",
        404 => " — project not found or API not enabled",
        429 => " — rate limited",
        _ => "",
    }
}

fn credential_hint(err: String) -> String {
    if err.contains("expired") || err.contains("invalid_grant") || err.contains("invalid_rapt") {
        format!(
            "{} — run `gcloud auth application-default login` to refresh",
            err
        )
    } else {
        err
    }
}

// ── Minimal time utilities (no chrono) ───────────────────────────────────────
// Reuse the same approach as integration/gcp/trace.rs to avoid a dependency.

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_to_rfc3339(secs)
}

fn rfc3339_minus_minutes(rfc: &str, minutes: u32) -> String {
    if let Some(secs) = parse_rfc3339_secs(rfc) {
        return unix_to_rfc3339(secs.saturating_sub((minutes as u64) * 60));
    }
    rfc.to_string()
}

fn unix_to_rfc3339(secs: u64) -> String {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, m, s)
}

fn parse_rfc3339_secs(s: &str) -> Option<u64> {
    let s = s.trim_end_matches('Z');
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 { return None; }
    let d: Vec<u64> = parts[0].split('-').filter_map(|x| x.parse().ok()).collect();
    let t: Vec<u64> = parts[1].split(':').filter_map(|x| x.parse().ok()).collect();
    if d.len() < 3 || t.len() < 3 { return None; }
    let mut days = 0u64;
    for yr in 1970..d[0] { days += if is_leap(yr) { 366 } else { 365 }; }
    let md: [u64; 12] = if is_leap(d[0]) {
        [31,29,31,30,31,30,31,31,30,31,30,31]
    } else {
        [31,28,31,30,31,30,31,31,30,31,30,31]
    };
    for i in 0..(d[1] as usize - 1) { days += md[i]; }
    days += d[2] - 1;
    Some(days * 86400 + t[0] * 3600 + t[1] * 60 + t[2])
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    loop {
        let yd = if is_leap(y) { 366 } else { 365 };
        if days < yd { break; }
        days -= yd;
        y += 1;
    }
    let md: [u64; 12] = if is_leap(y) {
        [31,29,31,30,31,30,31,31,30,31,30,31]
    } else {
        [31,28,31,30,31,30,31,31,30,31,30,31]
    };
    let mut mo = 1u64;
    for &m in &md { if days < m { break; } days -= m; mo += 1; }
    (y, mo, days + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_all_returns_four_rows() {
        let rows = detect_all();
        assert_eq!(rows.len(), 4);
    }

    #[test]
    fn setup_hints_non_empty() {
        for kind in [
            IntegrationKind::GcpSlo,
            IntegrationKind::GcpTrace,
            IntegrationKind::Datadog,
            IntegrationKind::Dynatrace,
        ] {
            assert!(!setup_hints(kind).is_empty());
        }
    }

    #[test]
    fn api_error_hint_known_codes() {
        assert!(!api_error_hint(401).is_empty());
        assert!(!api_error_hint(403).is_empty());
        assert!(api_error_hint(200).is_empty());
    }

    #[test]
    fn rfc3339_round_trip() {
        let base = "2026-04-15T12:00:00Z";
        let minus = rfc3339_minus_minutes(base, 60);
        assert_eq!(minus, "2026-04-15T11:00:00Z");
    }
}
