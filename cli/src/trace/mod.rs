//! Distributed trace enrichment — provider-agnostic orchestration.
//!
//! This module owns the enricher that converts trace data into graph edges.
//! The actual provider implementations live under [`crate::integration`]:
//!
//! - [`crate::integration::gcp::trace::GcpTraceProvider`] — Cloud Trace v1
//!
//! ## Future providers
//!
//! - OTEL Collector (Jaeger, Tempo, Zipkin)
//! - Datadog APM
//! - AWS X-Ray
//!
//! ## Output
//!
//! Each provider produces `RemoteCallPattern`s, which the `TraceEnricher`
//! converts into `GraphNode::RemoteService` nodes and `GraphEdgeKind::RemoteCall`
//! edges in the `CodeGraph`. The World Model's BFS then traverses these at
//! weight 0.90, propagating risk across service boundaries.

pub mod enricher;

pub use crate::integration::gcp::trace::{GcpTraceProvider, RemoteCallPattern};
pub use enricher::{enrich_graph, TraceEnrichmentResult};
