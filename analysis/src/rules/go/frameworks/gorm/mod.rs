//! GORM framework-specific rules for Go.
//!
//! Contains rules for detecting production-readiness issues in GORM usage.

pub mod connection_pool;
pub mod n_plus_one;
pub mod query_timeout;
pub mod session_management;

pub use connection_pool::GormConnectionPoolRule;
pub use n_plus_one::GormNPlusOneRule;
pub use query_timeout::GormQueryTimeoutRule;
pub use session_management::GormSessionManagementRule;

/// Returns all GORM rules
pub fn all_rules() -> Vec<Box<dyn crate::rules::Rule>> {
    vec![
        Box::new(GormConnectionPoolRule::new()),
        Box::new(GormNPlusOneRule::new()),
        Box::new(GormQueryTimeoutRule::new()),
        Box::new(GormSessionManagementRule::new()),
    ]
}