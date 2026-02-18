use serde::{Deserialize, Serialize};

use crate::types::context::Dimension;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestmentLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStage {
    Prototype,
    Product,
    Production,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionLevel {
    Code,
    Config,
    ApiContract,
    Architecture,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Benefit {
    Reliability,
    Operability,
    Latency,
    Correctness,
    Performance,
    Security,
}

/// Guidance metadata that helps consumers (including LLM agents) decide whether a
/// recommendation is worth implementing for the current context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingApplicability {
    pub investment_level: InvestmentLevel,
    pub min_stage: LifecycleStage,
    pub decision_level: DecisionLevel,
    #[serde(default)]
    pub benefits: Vec<Benefit>,
    #[serde(default)]
    pub prerequisites: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Core finding type produced by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub kind: FindingKind,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: f32,
    pub dimension: Dimension,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub applicability: Option<FindingApplicability>,

    /// File path where this finding was detected
    pub file_path: String,

    /// Line number (1-based) where the finding starts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,

    /// Column number (1-based) where the finding starts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,

    /// Line number (1-based) where the finding ends
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,

    /// Column number (1-based) where the finding ends
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,

    /// Byte range for precise location (start_byte, end_byte).
    /// Enables exact code extraction from source files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_range: Option<(usize, usize)>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_preview: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FindingKind {
    BehaviorThreat,
    PerformanceSmell,
    StabilityRisk,
    AntiPattern,
    ResourceLeak,
    ReliabilityRisk,
    SecurityVulnerability,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
