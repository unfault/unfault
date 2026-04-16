//! Dynatrace integration — SLO provider.
//!
//! Fetches SLOs from the Dynatrace API using API token authentication.
//!
//! ## Credentials
//!
//! - `DT_API_TOKEN` — API token with `slo.read` scope
//! - `DT_ENVIRONMENT_URL` — environment base URL, e.g.
//!   `https://abc12345.live.dynatrace.com`

pub mod slo;
