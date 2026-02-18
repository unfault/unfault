//! gRPC framework-specific rules for Go.
//!
//! Contains rules for detecting production-readiness issues in gRPC usage.

pub mod missing_deadline;

pub use missing_deadline::GrpcMissingDeadlineRule;

/// Returns all gRPC rules
pub fn all_rules() -> Vec<Box<dyn crate::rules::Rule>> {
    vec![
        Box::new(GrpcMissingDeadlineRule::new()),
    ]
}