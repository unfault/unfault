//! GCP Cloud Trace v1 REST client.
//!
//! Fetches recent distributed traces from Google Cloud Trace to augment the
//! World Model with cross-service call patterns that static analysis cannot see.
//!
//! ## What we extract
//!
//! From each `RPC_CLIENT` span we extract:
//! - The remote service name (from `peer.service`, `/http/host`, or span name)
//! - The remote endpoint URL (from `/http/url` or `/http/host`)
//! - Latency (end_time − start_time, used to build p99 estimates)
//!
//! `RPC_SERVER` spans tell us the *name* of the current service — used to
//! verify we're looking at the right project's traces.
//!
//! ## API
//!
//! Cloud Trace v1 `ListTraces`:
//! ```text
//! GET https://cloudtrace.googleapis.com/v1/projects/{project}/traces
//!   ?view=COMPLETE
//!   &pageSize=200
//!   &startTime=<RFC3339>
//!   &endTime=<RFC3339>
//! ```
//! Auth: `trace.readonly` scope via OAuth2 ADC.
//!
//! Note: Cloud Trace v2 API is write-only. v1 is the only REST read path.

use std::collections::HashMap;

use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

use super::GcpCredentials;

// ── Public types ─────────────────────────────────────────────────────────────

/// A cross-service call pattern extracted from trace data.
#[derive(Debug, Clone)]
pub struct RemoteCallPattern {
    /// Canonical name of the remote service (e.g. "inventory-service",
    /// "pubsub.googleapis.com", "redis").
    pub remote_service_name: String,
    /// Endpoint seen in traces (e.g. "https://inventory-svc:8080").
    /// May be empty if only the service name was recoverable.
    pub remote_endpoint: String,
    /// Number of `RPC_CLIENT` spans observed calling this service.
    pub observed_count: u32,
    /// P99 latency in milliseconds, estimated from span durations.
    pub p99_latency_ms: Option<f64>,
    /// Local span names / operation names that made these calls.
    /// Used to correlate with local code graph nodes.
    pub local_callers: Vec<String>,
}

/// GCP Cloud Trace v1 provider.
pub struct GcpTraceProvider {
    project_id: String,
    credentials: GcpCredentials,
}

impl GcpTraceProvider {
    /// Check whether Cloud Trace credentials are available.
    pub fn is_available() -> bool {
        GcpCredentials::is_available()
    }

    /// Create a provider from Application Default Credentials.
    pub fn from_env() -> Option<Self> {
        let credentials = GcpCredentials::from_env()?;
        let project_id = credentials.project_id.clone();
        Some(Self {
            project_id,
            credentials,
        })
    }

    /// Fetch recent traces and extract cross-service call patterns.
    ///
    /// Looks back `lookback_minutes` (default 60) and fetches up to
    /// `page_size` (default 200) complete traces.
    pub async fn fetch_remote_calls(
        &self,
        client: &Client,
        lookback_minutes: u32,
        page_size: u32,
    ) -> Result<Vec<RemoteCallPattern>> {
        let token = self
            .credentials
            .access_token(client)
            .await
            .context("Failed to acquire GCP access token for Cloud Trace")?;

        let traces = self
            .list_traces(client, &token, lookback_minutes, page_size)
            .await?;

        Ok(extract_remote_call_patterns(traces))
    }

    // ── REST calls ──────────────────────────────────────────────────────────

    async fn list_traces(
        &self,
        client: &Client,
        token: &str,
        lookback_minutes: u32,
        page_size: u32,
    ) -> Result<Vec<TraceV1>> {
        // Build RFC3339 time window
        let end_time = chrono_like_now_rfc3339();
        let start_time = rfc3339_minus_minutes(&end_time, lookback_minutes);

        let url = format!(
            "https://cloudtrace.googleapis.com/v1/projects/{}/traces",
            self.project_id
        );

        let mut all_traces: Vec<TraceV1> = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let mut req = client.get(&url).bearer_auth(token).query(&[
                ("view", "COMPLETE"),
                ("pageSize", &page_size.to_string()),
                ("startTime", &start_time),
                ("endTime", &end_time),
            ]);

            if let Some(ref tok) = page_token {
                req = req.query(&[("pageToken", tok.as_str())]);
            }

            let resp = req
                .send()
                .await
                .context("Failed to call Cloud Trace v1 ListTraces API")?;

            if !resp.status().is_success() {
                let status = resp.status();
                // 403 / 404 → not enabled or no permission — soft-fail
                if status.as_u16() == 403 || status.as_u16() == 404 {
                    break;
                }
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Cloud Trace ListTraces error: {} — {}", status, body);
            }

            let response: ListTracesResponse = resp
                .json()
                .await
                .context("Failed to parse Cloud Trace response")?;

            all_traces.extend(response.traces.unwrap_or_default());

            match response.next_page_token {
                Some(t) if !t.is_empty() && all_traces.len() < page_size as usize * 3 => {
                    page_token = Some(t);
                }
                _ => break,
            }
        }

        Ok(all_traces)
    }
}

// ── Pattern extraction ────────────────────────────────────────────────────────

/// Extract cross-service `RemoteCallPattern`s from a batch of traces.
///
/// # Span selection strategy
///
/// We cannot rely on `kind == "RPC_CLIENT"` because:
/// - Cloud Run's OTEL exporter omits the `kind` field entirely in the v1 API.
/// - Many OTEL SDKs export client spans without setting the Zipkin kind.
///
/// Instead, we identify outbound spans by a two-tier heuristic:
///
/// **Tier 1 — Explicit kind:** If `kind` is `"RPC_CLIENT"` or `"CLIENT"`,
/// treat the span as an outbound call regardless of labels.
///
/// **Tier 2 — Host-based inference:** For spans with `/http/host` or
/// `/http/url` labels, check whether the host is external to the service.
/// We consider a host "external" if it does not appear in any `AppServer`
/// span in the same trace (i.e. it's not just the service calling itself).
/// This catches OTEL httpx/requests instrumentation on Cloud Run.
///
/// From each qualifying span we extract:
/// 1. **Remote service name** — `peer.service`, `/http/host`, span name
///    heuristics (`Sent.<Svc>`, gRPC), or URL host.
/// 2. **Remote endpoint** — `/http/url` normalised to scheme + host + port.
/// 3. **Local caller** — parent span name (route handler that initiated the call).
/// 4. **Latency** — span duration; p99 computed per remote service.
fn extract_remote_call_patterns(traces: Vec<TraceV1>) -> Vec<RemoteCallPattern> {
    // service_name → (count, latencies_ms, local_callers, endpoint)
    let mut aggregation: HashMap<String, (u32, Vec<f64>, Vec<String>, String)> = HashMap::new();

    for trace in &traces {
        // Build span_id → span map for parent lookup (span_id is a String now)
        let span_map: HashMap<&str, &TraceSpanV1> = trace
            .spans
            .iter()
            .map(|s| (s.span_id.as_str(), s))
            .collect();

        // Collect inbound host names (AppServer spans = the service itself)
        // so we can exclude them when checking for external calls.
        let own_hosts: std::collections::HashSet<String> = trace
            .spans
            .iter()
            .filter(|s| {
                s.labels
                    .get("/component")
                    .map(|c| c == "AppServer")
                    .unwrap_or(false)
            })
            .filter_map(|s| {
                s.labels
                    .get("/http/host")
                    .or_else(|| s.labels.get("http.host"))
                    .map(|h| h.split(':').next().unwrap_or(h).to_lowercase())
            })
            .collect();

        for span in &trace.spans {
            // Tier 1: explicit client kind
            let is_explicit_client = span
                .kind
                .as_deref()
                .map(|k| k == "RPC_CLIENT" || k == "CLIENT")
                .unwrap_or(false);

            // Tier 2: has an http host/url that is external to this service
            let is_external_http = if !is_explicit_client {
                let host = span
                    .labels
                    .get("/http/host")
                    .or_else(|| span.labels.get("http.host"))
                    .map(|h| h.split(':').next().unwrap_or(h).to_lowercase());

                host.as_ref().map(|h| !own_hosts.contains(h)).unwrap_or(false)
                    && host.is_some()
                    // Exclude pure inbound AppServer spans
                    && span.labels.get("/component").map(|c| c != "AppServer").unwrap_or(true)
            } else {
                false
            };

            if !is_explicit_client && !is_external_http {
                continue;
            }

            // Infer remote service name
            let remote_name = infer_remote_service_name(span);
            if remote_name.is_empty() {
                continue;
            }

            // Infer remote endpoint
            let remote_endpoint = span
                .labels
                .get("/http/url")
                .or_else(|| span.labels.get("http.url"))
                .map(|u| normalize_endpoint(u))
                .unwrap_or_default();

            // Infer local caller from parent span name
            let local_caller = span
                .parent_span_id
                .as_deref()
                .and_then(|pid| span_map.get(pid))
                .map(|p| p.name.clone())
                .unwrap_or_default();

            let latency_ms = compute_span_latency_ms(span);

            let entry = aggregation
                .entry(remote_name.clone())
                .or_insert_with(|| (0, Vec::new(), Vec::new(), remote_endpoint.clone()));
            entry.0 += 1;
            if let Some(lat) = latency_ms {
                entry.1.push(lat);
            }
            if !local_caller.is_empty() && !entry.2.contains(&local_caller) {
                entry.2.push(local_caller);
            }
            if entry.3.is_empty() && !remote_endpoint.is_empty() {
                entry.3 = remote_endpoint;
            }
        }
    }

    aggregation
        .into_iter()
        .map(|(name, (count, latencies, callers, endpoint))| {
            let p99 = compute_p99(&latencies);
            RemoteCallPattern {
                remote_service_name: name,
                remote_endpoint: endpoint,
                observed_count: count,
                p99_latency_ms: p99,
                local_callers: callers,
            }
        })
        .collect()
}

fn infer_remote_service_name(span: &TraceSpanV1) -> String {
    // 1. `peer.service` — standard OTEL attribute (Cloud Trace stores as label)
    if let Some(svc) = span
        .labels
        .get("peer.service")
        .or_else(|| span.labels.get("peer_service"))
    {
        return svc.clone();
    }

    // 2. `/http/host` — Cloud Trace conventional label for HTTP host
    if let Some(host) = span
        .labels
        .get("/http/host")
        .or_else(|| span.labels.get("http.host"))
    {
        return host_to_service_name(host);
    }

    // 3. `net.peer.name` — OTEL semantic convention
    if let Some(peer) = span.labels.get("net.peer.name") {
        return host_to_service_name(peer);
    }

    // 4. Span name heuristics:
    //    "Sent.<ServiceName>/<Method>" (Zipkin B3 format)
    //    "grpc.Call/<package>.<Service>/<Method>"
    let name = &span.name;
    if let Some(rest) = name.strip_prefix("Sent.") {
        // e.g. "Sent.inventory.InventoryService/CheckStock"
        return rest
            .split('/')
            .next()
            .unwrap_or(rest)
            .split('.')
            .next_back()
            .unwrap_or(rest)
            .to_string();
    }
    if name.starts_with("grpc.") || name.contains("grpc/") {
        // e.g. "grpc.Call/my.package.MyService/Method"
        if let Some(parts) = name.split('/').nth(1) {
            return parts.split('.').next_back().unwrap_or(parts).to_string();
        }
    }

    // 5. URL-based fallback from labels
    if let Some(url) = span
        .labels
        .get("/http/url")
        .or_else(|| span.labels.get("http.url"))
    {
        if let Some(host) = extract_host_from_url(url) {
            return host_to_service_name(&host);
        }
    }

    String::new()
}

/// Convert a host string to a meaningful service name.
///
/// Rules applied in order:
/// 1. Strip port suffix.
/// 2. Strip Kubernetes FQDN suffix (`.svc.cluster.local`, `.svc.*`).
/// 3. If the remaining host looks like a public domain (contains a recognised
///    public TLD: `.com`, `.io`, `.dev`, `.net`, `.org`, `.app`, `.run.app`)
///    keep it intact — `api.github.com`, `pubsub.googleapis.com`, etc.
/// 4. Otherwise treat the first DNS label as the service name
///    (e.g. `inventory-svc.prod` → `inventory-svc`).
fn host_to_service_name(host: &str) -> String {
    // 1. Strip port
    let host = host.split(':').next().unwrap_or(host);

    // 2. Strip Kubernetes FQDN suffix
    let host = host.split(".svc.").next().unwrap_or(host);

    // 3. If it looks like a public internet hostname, keep it whole.
    //    Heuristic: has more than one label AND ends with a known public TLD.
    const PUBLIC_TLDS: &[&str] = &[
        ".googleapis.com",
        ".google.com",
        ".github.com",
        ".github.io",
        ".amazonaws.com",
        ".azure.com",
        ".cloudflare.com",
        ".run.app", // Cloud Run public URLs
        ".com",
        ".io",
        ".dev",
        ".net",
        ".org",
        ".app",
    ];
    if PUBLIC_TLDS.iter().any(|tld| host.ends_with(tld)) {
        return host.to_string();
    }

    // 4. Internal hostname — first label is the service name
    host.split('.').next().unwrap_or(host).to_string()
}

fn extract_host_from_url(url: &str) -> Option<String> {
    // Simple URL host extraction: "https://host:port/path" → "host:port"
    let after_scheme = url.split("://").nth(1)?;
    let host_and_more = after_scheme.split('/').next()?;
    Some(host_and_more.to_string())
}

fn normalize_endpoint(url: &str) -> String {
    // Keep only scheme + host + port, strip path
    if let Some(after_scheme) = url.split("://").nth(1) {
        let scheme = url.split("://").next().unwrap_or("https");
        let host = after_scheme.split('/').next().unwrap_or(after_scheme);
        return format!("{}://{}", scheme, host);
    }
    url.to_string()
}

fn compute_span_latency_ms(span: &TraceSpanV1) -> Option<f64> {
    // RFC3339 timestamps — we do a simple string-based diff via Unix epoch ms
    let start = parse_rfc3339_ms(&span.start_time)?;
    let end = parse_rfc3339_ms(&span.end_time)?;
    if end >= start {
        Some((end - start) as f64)
    } else {
        None
    }
}

fn compute_p99(latencies: &[f64]) -> Option<f64> {
    if latencies.is_empty() {
        return None;
    }
    let mut sorted = latencies.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((sorted.len() as f64) * 0.99).ceil() as usize;
    sorted.get(idx.saturating_sub(1)).copied()
}

// ── Time utilities ────────────────────────────────────────────────────────────
// We avoid pulling in `chrono` for a single timestamp operation. Instead we
// implement minimal RFC3339 generation using standard library.

fn chrono_like_now_rfc3339() -> String {
    // Use std::time::SystemTime; produce a minimal RFC3339 string.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_secs_to_rfc3339(secs)
}

fn rfc3339_minus_minutes(rfc: &str, minutes: u32) -> String {
    // Parse the epoch seconds back from our own format, subtract, re-format.
    if let Some(secs) = parse_rfc3339_epoch_secs(rfc) {
        return unix_secs_to_rfc3339(secs.saturating_sub((minutes as u64) * 60));
    }
    rfc.to_string()
}

fn unix_secs_to_rfc3339(secs: u64) -> String {
    // Manual UTC conversion — avoids external time crate dependency.
    // Output format: "2026-04-15T12:34:56Z"
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;

    // Gregorian calendar computation
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, h, m, s
    )
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Days since Unix epoch (1970-01-01) → (year, month, day)
    let mut remaining = days;
    let mut year = 1970u64;

    loop {
        let year_days = if is_leap(year) { 366 } else { 365 };
        if remaining < year_days {
            break;
        }
        remaining -= year_days;
        year += 1;
    }

    let month_days: [u64; 12] = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u64;
    for &md in &month_days {
        if remaining < md {
            break;
        }
        remaining -= md;
        month += 1;
    }

    (year, month, remaining + 1)
}

fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Parse our own RFC3339 "YYYY-MM-DDTHH:MM:SSZ" → Unix epoch seconds.
fn parse_rfc3339_epoch_secs(s: &str) -> Option<u64> {
    let s = s.trim_end_matches('Z');
    let parts: Vec<&str> = s.split('T').collect();
    if parts.len() != 2 {
        return None;
    }
    let date_parts: Vec<u64> = parts[0].split('-').filter_map(|p| p.parse().ok()).collect();
    let time_parts: Vec<u64> = parts[1].split(':').filter_map(|p| p.parse().ok()).collect();
    if date_parts.len() < 3 || time_parts.len() < 3 {
        return None;
    }

    let (y, mo, d) = (date_parts[0], date_parts[1], date_parts[2]);
    let (h, mi, sec) = (time_parts[0], time_parts[1], time_parts[2]);

    // Days since epoch
    let mut days = 0u64;
    for yr in 1970..y {
        days += if is_leap(yr) { 366 } else { 365 };
    }
    let month_days: [u64; 12] = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    for mi_idx in 0..(mo as usize - 1) {
        days += month_days[mi_idx];
    }
    days += d - 1;

    Some(days * 86400 + h * 3600 + mi * 60 + sec)
}

/// Parse RFC3339 timestamp to Unix epoch milliseconds (for latency computation).
fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    // Handle optional sub-second part: "2026-04-15T12:34:56.789Z"
    let s_trimmed = s.trim_end_matches('Z');
    let (main_part, frac_part) = if let Some(dot_pos) = s_trimmed.rfind('.') {
        (&s_trimmed[..dot_pos], &s_trimmed[dot_pos + 1..])
    } else {
        (s_trimmed, "")
    };

    let epoch_secs = parse_rfc3339_epoch_secs(&format!("{}Z", main_part))?;
    let frac_ms = if frac_part.is_empty() {
        0u64
    } else {
        // Parse up to 3 digits of fractional seconds as milliseconds
        let digits = &frac_part[..frac_part.len().min(3)];
        let val: u64 = digits.parse().unwrap_or(0);
        // Pad to milliseconds
        val * 10u64.pow(3u32.saturating_sub(digits.len() as u32))
    };

    Some(epoch_secs * 1000 + frac_ms)
}

// ── Wire types (Cloud Trace v1 API response) ──────────────────────────────────
//
// Important: Cloud Trace v1 returns `spanId` and `parentSpanId` as decimal
// *strings* (e.g. "8686581962470036554"), not JSON numbers. Using u64 causes
// a deserialization failure on real API responses.
//
// Also: when there are no traces matching the time window, the API returns
// `{}` — an empty JSON object with no `traces` field at all. The
// `#[serde(default)]` on the struct handles this correctly.

#[derive(Debug, Deserialize, Default)]
struct ListTracesResponse {
    #[serde(default)]
    traces: Option<Vec<TraceV1>>,
    #[serde(rename = "nextPageToken", default)]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TraceV1 {
    #[serde(rename = "traceId", default)]
    _trace_id: String,
    #[serde(default)]
    spans: Vec<TraceSpanV1>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TraceSpanV1 {
    /// Decimal string, e.g. "8686581962470036554". Cloud Trace v1 never
    /// emits this as a JSON number despite what the proto definition implies.
    #[serde(default)]
    span_id: String,
    /// Cloud Run / OTEL exporters often omit `kind` entirely. Don't rely on
    /// it being `RPC_CLIENT` — use host/url label analysis instead.
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    start_time: String,
    #[serde(default)]
    end_time: String,
    /// Also a decimal string when present.
    #[serde(default)]
    parent_span_id: Option<String>,
    #[serde(default)]
    labels: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_to_service_name_strips_k8s_fqdn() {
        assert_eq!(
            host_to_service_name("inventory-svc.prod.svc.cluster.local:8080"),
            "inventory-svc"
        );
    }

    #[test]
    fn host_to_service_name_keeps_gcp_apis() {
        assert_eq!(
            host_to_service_name("pubsub.googleapis.com"),
            "pubsub.googleapis.com"
        );
    }

    #[test]
    fn host_to_service_name_strips_port() {
        assert_eq!(host_to_service_name("payments-svc:9090"), "payments-svc");
    }

    #[test]
    fn normalize_endpoint_strips_path() {
        assert_eq!(
            normalize_endpoint("https://inventory-svc:8080/api/v1/check"),
            "https://inventory-svc:8080"
        );
    }

    #[test]
    fn extract_host_from_url_works() {
        assert_eq!(
            extract_host_from_url("https://payments-svc:9090/pay"),
            Some("payments-svc:9090".to_string())
        );
    }

    #[test]
    fn unix_secs_to_rfc3339_round_trips() {
        // 2026-04-15T00:00:00Z
        let secs = parse_rfc3339_epoch_secs("2026-04-15T00:00:00Z").unwrap();
        let back = unix_secs_to_rfc3339(secs);
        assert_eq!(back, "2026-04-15T00:00:00Z");
    }

    #[test]
    fn rfc3339_minus_minutes_works() {
        let base = "2026-04-15T01:00:00Z";
        let result = rfc3339_minus_minutes(base, 60);
        assert_eq!(result, "2026-04-15T00:00:00Z");
    }

    #[test]
    fn parse_rfc3339_ms_with_fractional() {
        let ms = parse_rfc3339_ms("2026-01-01T00:00:01.500Z").unwrap();
        // Should be 1500 ms after epoch start of this minute
        let base_ms = parse_rfc3339_ms("2026-01-01T00:00:01Z").unwrap();
        assert_eq!(ms - base_ms, 500);
    }

    fn make_span(
        id: &str,
        kind: Option<&str>,
        name: &str,
        host: Option<&str>,
        url: Option<&str>,
        component: Option<&str>,
        parent: Option<&str>,
    ) -> TraceSpanV1 {
        let mut labels = HashMap::new();
        if let Some(h) = host {
            labels.insert("/http/host".to_string(), h.to_string());
        }
        if let Some(u) = url {
            labels.insert("/http/url".to_string(), u.to_string());
        }
        if let Some(c) = component {
            labels.insert("/component".to_string(), c.to_string());
        }
        TraceSpanV1 {
            span_id: id.to_string(),
            kind: kind.map(|s| s.to_string()),
            name: name.to_string(),
            start_time: "2026-04-15T00:00:00Z".to_string(),
            end_time: "2026-04-15T00:00:00.100Z".to_string(),
            parent_span_id: parent.map(|s| s.to_string()),
            labels,
        }
    }

    #[test]
    fn infer_remote_service_name_from_peer_service_label() {
        let mut labels = HashMap::new();
        labels.insert("peer.service".to_string(), "inventory-service".to_string());
        let span = TraceSpanV1 {
            span_id: "1".to_string(),
            kind: Some("RPC_CLIENT".to_string()),
            name: "HTTP POST".to_string(),
            start_time: "2026-04-15T00:00:00Z".to_string(),
            end_time: "2026-04-15T00:00:00.100Z".to_string(),
            parent_span_id: None,
            labels,
        };
        assert_eq!(infer_remote_service_name(&span), "inventory-service");
    }

    #[test]
    fn infer_remote_service_name_from_sent_prefix() {
        let span = TraceSpanV1 {
            span_id: "2".to_string(),
            kind: Some("RPC_CLIENT".to_string()),
            name: "Sent.payments.PaymentService/Charge".to_string(),
            start_time: "2026-04-15T00:00:00Z".to_string(),
            end_time: "2026-04-15T00:00:00.200Z".to_string(),
            parent_span_id: None,
            labels: HashMap::new(),
        };
        assert_eq!(infer_remote_service_name(&span), "PaymentService");
    }

    #[test]
    fn extract_remote_call_patterns_aggregates_by_explicit_kind() {
        let mut labels = HashMap::new();
        labels.insert("peer.service".to_string(), "inventory".to_string());
        labels.insert(
            "/http/url".to_string(),
            "https://inventory-svc:8080/check".to_string(),
        );

        let spans = vec![
            TraceSpanV1 {
                span_id: "10".to_string(),
                kind: Some("RPC_CLIENT".to_string()),
                name: "GET /check".to_string(),
                start_time: "2026-04-15T00:00:00Z".to_string(),
                end_time: "2026-04-15T00:00:00.050Z".to_string(),
                parent_span_id: None,
                labels: labels.clone(),
            },
            TraceSpanV1 {
                span_id: "11".to_string(),
                kind: Some("RPC_CLIENT".to_string()),
                name: "GET /check".to_string(),
                start_time: "2026-04-15T00:00:01Z".to_string(),
                end_time: "2026-04-15T00:00:01.200Z".to_string(),
                parent_span_id: None,
                labels,
            },
        ];

        let traces = vec![TraceV1 {
            _trace_id: "abc".to_string(),
            spans,
        }];
        let patterns = extract_remote_call_patterns(traces);
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].remote_service_name, "inventory");
        assert_eq!(patterns[0].observed_count, 2);
        assert!(patterns[0].p99_latency_ms.is_some());
    }

    #[test]
    fn extract_patterns_via_host_inference_excludes_own_service() {
        // AppServer span = this service's own inbound request
        let inbound = make_span(
            "1",
            None,
            "/",
            Some("my-service.run.app"),
            Some("https://my-service.run.app/"),
            Some("AppServer"),
            None,
        );
        // External call span — no kind, but host differs from AppServer
        let outbound = make_span(
            "2",
            None,
            "GET",
            Some("api.github.com"),
            Some("https://api.github.com/"),
            None,
            Some("1"),
        );

        let traces = vec![TraceV1 {
            _trace_id: "t1".to_string(),
            spans: vec![inbound, outbound],
        }];

        let patterns = extract_remote_call_patterns(traces);
        // Should find api.github.com as external, not my-service.run.app
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].remote_service_name, "api.github.com");
    }

    #[test]
    fn extract_patterns_does_not_emit_own_service_as_remote() {
        // Only inbound AppServer spans — no external calls
        let inbound = make_span(
            "1",
            None,
            "/",
            Some("my-service.run.app"),
            Some("https://my-service.run.app/"),
            Some("AppServer"),
            None,
        );
        let traces = vec![TraceV1 {
            _trace_id: "t2".to_string(),
            spans: vec![inbound],
        }];
        let patterns = extract_remote_call_patterns(traces);
        assert!(patterns.is_empty());
    }

    #[test]
    fn empty_response_deserializes() {
        // Cloud Trace returns `{}` when no traces match the time window
        let json = "{}";
        let resp: ListTracesResponse = serde_json::from_str(json).unwrap();
        assert!(resp.traces.is_none());
        assert!(resp.next_page_token.is_none());
    }

    #[test]
    fn span_id_as_string_deserializes() {
        // Real Cloud Trace v1 spanId is a decimal string, not a number
        let json = r#"{"spanId": "8686581962470036554", "name": "/"}"#;
        let span: TraceSpanV1 = serde_json::from_str(json).unwrap();
        assert_eq!(span.span_id, "8686581962470036554");
    }

    #[test]
    fn is_available_does_not_panic() {
        let _ = GcpTraceProvider::is_available();
    }
}
