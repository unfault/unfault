use serde::{Deserialize, Serialize};

use crate::types::dependency::RuntimeDependency;
use crate::types::finding::Finding;
use crate::types::meta::ReviewSessionMeta;
use crate::types::sre_diagnostic::SystemHazard;

/// Result of a full review session.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReviewSessionResult {
    pub meta: ReviewSessionMeta,
    pub contexts: Vec<ContextResult>,
    /// Runtime dependencies extracted from all analyzed files.
    /// These represent external service connections detected in the code.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_dependencies: Vec<RuntimeDependency>,

    /// System-level hazards produced by the SRE synthesis pass (Pass 3).
    /// These enrich individual findings with cross-file blast radius context.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_hazards: Vec<SystemHazard>,
}

/// Result of analyzing a single context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextResult {
    pub context_id: String,
    pub label: String,
    pub findings: Vec<Finding>,
}
