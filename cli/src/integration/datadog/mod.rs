//! Datadog integration — SLO provider.
//!
//! Fetches SLOs from the Datadog API using API key authentication.
//!
//! ## Credentials
//!
//! - `DD_API_KEY` — Datadog API key
//! - `DD_APP_KEY` — Datadog application key
//! - `DD_SITE` — optional site override (default: `datadoghq.com`, use
//!   `datadoghq.eu` for EU region)

pub mod slo;
