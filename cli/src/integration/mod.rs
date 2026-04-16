//! Third-party observability integrations.
//!
//! This module groups all external platform integrations used by unfault
//! to augment the World Model with runtime data beyond static analysis:
//!
//! | Module | Provider | What it fetches |
//! |--------|----------|-----------------|
//! | [`gcp`] | Google Cloud | SLOs (Cloud Monitoring) + distributed traces (Cloud Trace) |
//! | [`datadog`] | Datadog | SLOs |
//! | [`dynatrace`] | Dynatrace | SLOs |
//!
//! ## Design principle
//!
//! Every integration is opportunistic — if credentials are absent or the API
//! call fails, the review continues without that data. No integration is
//! required for `unfault review` to produce useful output.
//!
//! Each provider exposes `is_available() -> bool` and `from_env() -> Option<Self>`,
//! which is the standard detection contract used by [`crate::slo::SloEnricher`]
//! and [`crate::trace`].

pub mod datadog;
pub mod dynatrace;
pub mod gcp;
