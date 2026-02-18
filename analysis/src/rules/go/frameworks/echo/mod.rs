//! Echo framework-specific rules for Go.
//!
//! Contains rules for detecting production-readiness issues in Echo web framework usage.

pub mod missing_middleware;
pub mod request_validation;

pub use missing_middleware::EchoMissingMiddlewareRule;
pub use request_validation::EchoRequestValidationRule;

/// Returns all Echo rules
pub fn all_rules() -> Vec<Box<dyn crate::rules::Rule>> {
    vec![
        Box::new(EchoMissingMiddlewareRule::new()),
        Box::new(EchoRequestValidationRule::new()),
    ]
}