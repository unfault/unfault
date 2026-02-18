// src/rules/finding.rs
use serde::{Deserialize, Serialize};

use crate::parse::ast::FileId;
use crate::types::context::Dimension;
use crate::types::finding::{Finding, FindingKind, Severity};
use crate::types::patch::FilePatch;

/// A lightweight final finding produced by a rule (engine-internal).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFinding {
    /// The ID of the rule that produced this.
    pub rule_id: String,

    /// A human-readable title.
    pub title: String,

    /// Optional description.
    pub description: Option<String>,

    /// Classification for this finding.
    pub kind: FindingKind,

    /// Severity of the issue.
    pub severity: Severity,

    /// Confidence score [0.0, 1.0].
    pub confidence: f32,

    /// Dimension this finding belongs to.
    pub dimension: Dimension,

    /// Where in the code this finding comes from.
    pub file_id: FileId,
    pub file_path: String,

    /// Optional line + column for primary location.
    pub line: Option<u32>,
    pub column: Option<u32>,

    /// Optional end line + column for the range.
    pub end_line: Option<u32>,
    pub end_column: Option<u32>,

    /// Optional byte range for precise location (start_byte, end_byte).
    /// This enables exact code extraction from source files.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_range: Option<(usize, usize)>,

    /// Optional structured patch applied to this file
    /// (possibly multiple hunks).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch: Option<FilePatch>,

    /// Optional human-readable preview of the suggested code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_preview: Option<String>,

    /// Tags for filtering / UI.
    #[serde(default)]
    pub tags: Vec<String>,
}

impl From<RuleFinding> for Finding {
    fn from(rf: RuleFinding) -> Self {
        let applicability = crate::rules::metadata::applicability_for_rule_id(&rf.rule_id);
        Self {
            id: format!("{}:{}:{}", rf.rule_id, rf.file_path, rf.line.unwrap_or(0)),
            rule_id: rf.rule_id,
            kind: rf.kind,
            title: rf.title,
            description: rf.description.unwrap_or_default(),
            severity: rf.severity,
            confidence: rf.confidence,
            dimension: rf.dimension,
            applicability,
            file_path: rf.file_path,
            line: rf.line,
            column: rf.column,
            end_line: rf.end_line,
            end_column: rf.end_column,
            byte_range: rf.byte_range,
            diff: None, // will be filled by session.rs
            fix_preview: rf.fix_preview,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::patch::{PatchHunk, PatchRange};

    // ==================== Helper Functions ====================

    fn create_basic_rule_finding() -> RuleFinding {
        RuleFinding {
            rule_id: "test.rule".to_string(),
            title: "Test Finding".to_string(),
            description: Some("Test description".to_string()),
            kind: FindingKind::BehaviorThreat,
            severity: Severity::Medium,
            confidence: 0.85,
            dimension: Dimension::Correctness,
            file_id: FileId(1),
            file_path: "src/test.py".to_string(),
            line: Some(10),
            column: Some(5),
            end_line: Some(10),
            end_column: Some(20),
            byte_range: None,
            patch: None,
            fix_preview: None,
            tags: vec!["test".to_string(), "example".to_string()],
        }
    }

    fn create_minimal_rule_finding() -> RuleFinding {
        RuleFinding {
            rule_id: "minimal.rule".to_string(),
            title: "Minimal Finding".to_string(),
            description: None,
            kind: FindingKind::AntiPattern,
            severity: Severity::Low,
            confidence: 0.5,
            dimension: Dimension::Stability,
            file_id: FileId(0),
            file_path: "test.py".to_string(),
            line: None,
            column: None,
            end_line: None,
            end_column: None,
            byte_range: None,
            patch: None,
            fix_preview: None,
            tags: vec![],
        }
    }

    // ==================== RuleFinding Field Tests ====================

    #[test]
    fn rule_finding_stores_rule_id() {
        let finding = create_basic_rule_finding();
        assert_eq!(finding.rule_id, "test.rule");
    }

    #[test]
    fn rule_finding_stores_title() {
        let finding = create_basic_rule_finding();
        assert_eq!(finding.title, "Test Finding");
    }

    #[test]
    fn rule_finding_stores_description() {
        let finding = create_basic_rule_finding();
        assert_eq!(finding.description, Some("Test description".to_string()));
    }

    #[test]
    fn rule_finding_stores_none_description() {
        let finding = create_minimal_rule_finding();
        assert!(finding.description.is_none());
    }

    #[test]
    fn rule_finding_stores_kind() {
        let finding = create_basic_rule_finding();
        assert!(matches!(finding.kind, FindingKind::BehaviorThreat));
    }

    #[test]
    fn rule_finding_stores_severity() {
        let finding = create_basic_rule_finding();
        assert!(matches!(finding.severity, Severity::Medium));
    }

    #[test]
    fn rule_finding_stores_confidence() {
        let finding = create_basic_rule_finding();
        assert!((finding.confidence - 0.85).abs() < f32::EPSILON);
    }

    #[test]
    fn rule_finding_stores_dimension() {
        let finding = create_basic_rule_finding();
        assert_eq!(finding.dimension, Dimension::Correctness);
    }

    #[test]
    fn rule_finding_stores_file_id() {
        let finding = create_basic_rule_finding();
        assert_eq!(finding.file_id, FileId(1));
    }

    #[test]
    fn rule_finding_stores_file_path() {
        let finding = create_basic_rule_finding();
        assert_eq!(finding.file_path, "src/test.py");
    }

    #[test]
    fn rule_finding_stores_line() {
        let finding = create_basic_rule_finding();
        assert_eq!(finding.line, Some(10));
    }

    #[test]
    fn rule_finding_stores_none_line() {
        let finding = create_minimal_rule_finding();
        assert!(finding.line.is_none());
    }

    #[test]
    fn rule_finding_stores_column() {
        let finding = create_basic_rule_finding();
        assert_eq!(finding.column, Some(5));
    }

    #[test]
    fn rule_finding_stores_none_column() {
        let finding = create_minimal_rule_finding();
        assert!(finding.column.is_none());
    }

    #[test]
    fn rule_finding_stores_tags() {
        let finding = create_basic_rule_finding();
        assert_eq!(finding.tags, vec!["test", "example"]);
    }

    #[test]
    fn rule_finding_stores_empty_tags() {
        let finding = create_minimal_rule_finding();
        assert!(finding.tags.is_empty());
    }

    // ==================== RuleFinding with Patch Tests ====================

    #[test]
    fn rule_finding_stores_patch() {
        let patch = FilePatch {
            file_id: FileId(1),
            hunks: vec![PatchHunk {
                range: PatchRange::InsertBeforeLine { line: 1 },
                replacement: "import os\n".to_string(),
            }],
        };

        let finding = RuleFinding {
            patch: Some(patch),
            ..create_basic_rule_finding()
        };

        assert!(finding.patch.is_some());
        let p = finding.patch.unwrap();
        assert_eq!(p.hunks.len(), 1);
    }

    #[test]
    fn rule_finding_stores_fix_preview() {
        let finding = RuleFinding {
            fix_preview: Some("# Add this import\nimport os".to_string()),
            ..create_basic_rule_finding()
        };

        assert_eq!(
            finding.fix_preview,
            Some("# Add this import\nimport os".to_string())
        );
    }

    // ==================== From<RuleFinding> for Finding Tests ====================

    #[test]
    fn from_rule_finding_creates_finding() {
        let rule_finding = create_basic_rule_finding();
        let finding: Finding = rule_finding.into();

        assert!(!finding.id.is_empty());
    }

    #[test]
    fn from_rule_finding_generates_correct_id_format() {
        let rule_finding = create_basic_rule_finding();
        let finding: Finding = rule_finding.into();

        // ID format: "rule_id:file_path:line"
        assert_eq!(finding.id, "test.rule:src/test.py:10");
    }

    #[test]
    fn from_rule_finding_uses_zero_for_none_line() {
        let rule_finding = create_minimal_rule_finding();
        let finding: Finding = rule_finding.into();

        // When line is None, it should use 0
        assert!(finding.id.ends_with(":0"));
    }

    #[test]
    fn from_rule_finding_preserves_rule_id() {
        let rule_finding = create_basic_rule_finding();
        let finding: Finding = rule_finding.into();

        assert_eq!(finding.rule_id, "test.rule");
    }

    #[test]
    fn from_rule_finding_preserves_kind() {
        let rule_finding = create_basic_rule_finding();
        let finding: Finding = rule_finding.into();

        assert!(matches!(finding.kind, FindingKind::BehaviorThreat));
    }

    #[test]
    fn from_rule_finding_preserves_title() {
        let rule_finding = create_basic_rule_finding();
        let finding: Finding = rule_finding.into();

        assert_eq!(finding.title, "Test Finding");
    }

    #[test]
    fn from_rule_finding_converts_description_some_to_string() {
        let rule_finding = create_basic_rule_finding();
        let finding: Finding = rule_finding.into();

        assert_eq!(finding.description, "Test description");
    }

    #[test]
    fn from_rule_finding_converts_description_none_to_empty_string() {
        let rule_finding = create_minimal_rule_finding();
        let finding: Finding = rule_finding.into();

        assert_eq!(finding.description, "");
    }

    #[test]
    fn from_rule_finding_preserves_severity() {
        let rule_finding = create_basic_rule_finding();
        let finding: Finding = rule_finding.into();

        assert!(matches!(finding.severity, Severity::Medium));
    }

    #[test]
    fn from_rule_finding_preserves_confidence() {
        let rule_finding = create_basic_rule_finding();
        let finding: Finding = rule_finding.into();

        assert!((finding.confidence - 0.85).abs() < f32::EPSILON);
    }

    #[test]
    fn from_rule_finding_preserves_dimension() {
        let rule_finding = create_basic_rule_finding();
        let finding: Finding = rule_finding.into();

        assert_eq!(finding.dimension, Dimension::Correctness);
    }

    #[test]
    fn from_rule_finding_sets_diff_to_none() {
        let rule_finding = create_basic_rule_finding();
        let finding: Finding = rule_finding.into();

        // diff is always None initially (filled by session.rs later)
        assert!(finding.diff.is_none());
    }

    #[test]
    fn from_rule_finding_preserves_fix_preview() {
        let rule_finding = RuleFinding {
            fix_preview: Some("# Fix preview".to_string()),
            ..create_basic_rule_finding()
        };
        let finding: Finding = rule_finding.into();

        assert_eq!(finding.fix_preview, Some("# Fix preview".to_string()));
    }

    #[test]
    fn from_rule_finding_preserves_none_fix_preview() {
        let rule_finding = create_basic_rule_finding();
        let finding: Finding = rule_finding.into();

        assert!(finding.fix_preview.is_none());
    }

    // ==================== Clone Tests ====================

    #[test]
    fn rule_finding_can_be_cloned() {
        let original = create_basic_rule_finding();
        let cloned = original.clone();

        assert_eq!(original.rule_id, cloned.rule_id);
        assert_eq!(original.title, cloned.title);
        assert_eq!(original.file_path, cloned.file_path);
    }

    #[test]
    fn cloned_rule_finding_is_independent() {
        let original = create_basic_rule_finding();
        let mut cloned = original.clone();

        cloned.title = "Modified Title".to_string();

        assert_eq!(original.title, "Test Finding");
        assert_eq!(cloned.title, "Modified Title");
    }

    // ==================== Debug Tests ====================

    #[test]
    fn rule_finding_implements_debug() {
        let finding = create_basic_rule_finding();
        let debug_str = format!("{:?}", finding);

        assert!(debug_str.contains("RuleFinding"));
        assert!(debug_str.contains("test.rule"));
    }

    // ==================== Serialization Tests ====================

    #[test]
    fn rule_finding_can_be_serialized_to_json() {
        let finding = create_basic_rule_finding();
        let json = serde_json::to_string(&finding);

        assert!(json.is_ok());
    }

    #[test]
    fn rule_finding_serialization_includes_required_fields() {
        let finding = create_basic_rule_finding();
        let json = serde_json::to_string(&finding).unwrap();

        assert!(json.contains("rule_id"));
        assert!(json.contains("title"));
        assert!(json.contains("kind"));
        assert!(json.contains("severity"));
    }

    #[test]
    fn rule_finding_serialization_skips_none_patch() {
        let finding = create_basic_rule_finding();
        let json = serde_json::to_string(&finding).unwrap();

        // patch should be skipped when None
        assert!(!json.contains("\"patch\""));
    }

    #[test]
    fn rule_finding_serialization_skips_none_fix_preview() {
        let finding = create_basic_rule_finding();
        let json = serde_json::to_string(&finding).unwrap();

        // fix_preview should be skipped when None
        assert!(!json.contains("\"fix_preview\""));
    }

    #[test]
    fn rule_finding_can_be_deserialized_from_json() {
        let finding = create_basic_rule_finding();
        let json = serde_json::to_string(&finding).unwrap();
        let deserialized: RuleFinding = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.rule_id, finding.rule_id);
        assert_eq!(deserialized.title, finding.title);
    }

    #[test]
    fn rule_finding_roundtrip_serialization() {
        let original = create_basic_rule_finding();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: RuleFinding = serde_json::from_str(&json).unwrap();

        assert_eq!(original.rule_id, deserialized.rule_id);
        assert_eq!(original.title, deserialized.title);
        assert_eq!(original.description, deserialized.description);
        assert_eq!(original.file_path, deserialized.file_path);
        assert_eq!(original.line, deserialized.line);
        assert_eq!(original.column, deserialized.column);
        assert_eq!(original.tags, deserialized.tags);
    }

    // ==================== Edge Cases ====================

    #[test]
    fn rule_finding_with_empty_strings() {
        let finding = RuleFinding {
            rule_id: "".to_string(),
            title: "".to_string(),
            description: Some("".to_string()),
            kind: FindingKind::AntiPattern,
            severity: Severity::Info,
            confidence: 0.0,
            dimension: Dimension::Scalability,
            file_id: FileId(0),
            file_path: "".to_string(),
            line: None,
            column: None,
            end_line: None,
            end_column: None,
            byte_range: None,
            patch: None,
            fix_preview: Some("".to_string()),
            tags: vec!["".to_string()],
        };

        assert_eq!(finding.rule_id, "");
        assert_eq!(finding.title, "");
        assert_eq!(finding.file_path, "");
    }

    #[test]
    fn rule_finding_with_max_confidence() {
        let finding = RuleFinding {
            confidence: 1.0,
            ..create_basic_rule_finding()
        };

        assert!((finding.confidence - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn rule_finding_with_min_confidence() {
        let finding = RuleFinding {
            confidence: 0.0,
            ..create_basic_rule_finding()
        };

        assert!((finding.confidence - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn rule_finding_with_large_line_number() {
        let finding = RuleFinding {
            line: Some(u32::MAX),
            ..create_basic_rule_finding()
        };

        assert_eq!(finding.line, Some(u32::MAX));
    }

    #[test]
    fn rule_finding_with_many_tags() {
        let tags: Vec<String> = (0..100).map(|i| format!("tag{}", i)).collect();
        let finding = RuleFinding {
            tags: tags.clone(),
            ..create_basic_rule_finding()
        };

        assert_eq!(finding.tags.len(), 100);
    }

    // ==================== All FindingKind Variants ====================

    #[test]
    fn rule_finding_with_behavior_threat_kind() {
        let finding = RuleFinding {
            kind: FindingKind::BehaviorThreat,
            ..create_basic_rule_finding()
        };
        assert!(matches!(finding.kind, FindingKind::BehaviorThreat));
    }

    #[test]
    fn rule_finding_with_performance_smell_kind() {
        let finding = RuleFinding {
            kind: FindingKind::PerformanceSmell,
            ..create_basic_rule_finding()
        };
        assert!(matches!(finding.kind, FindingKind::PerformanceSmell));
    }

    #[test]
    fn rule_finding_with_stability_risk_kind() {
        let finding = RuleFinding {
            kind: FindingKind::StabilityRisk,
            ..create_basic_rule_finding()
        };
        assert!(matches!(finding.kind, FindingKind::StabilityRisk));
    }

    #[test]
    fn rule_finding_with_anti_pattern_kind() {
        let finding = RuleFinding {
            kind: FindingKind::AntiPattern,
            ..create_basic_rule_finding()
        };
        assert!(matches!(finding.kind, FindingKind::AntiPattern));
    }

    // ==================== All Severity Variants ====================

    #[test]
    fn rule_finding_with_info_severity() {
        let finding = RuleFinding {
            severity: Severity::Info,
            ..create_basic_rule_finding()
        };
        assert!(matches!(finding.severity, Severity::Info));
    }

    #[test]
    fn rule_finding_with_low_severity() {
        let finding = RuleFinding {
            severity: Severity::Low,
            ..create_basic_rule_finding()
        };
        assert!(matches!(finding.severity, Severity::Low));
    }

    #[test]
    fn rule_finding_with_medium_severity() {
        let finding = RuleFinding {
            severity: Severity::Medium,
            ..create_basic_rule_finding()
        };
        assert!(matches!(finding.severity, Severity::Medium));
    }

    #[test]
    fn rule_finding_with_high_severity() {
        let finding = RuleFinding {
            severity: Severity::High,
            ..create_basic_rule_finding()
        };
        assert!(matches!(finding.severity, Severity::High));
    }

    #[test]
    fn rule_finding_with_critical_severity() {
        let finding = RuleFinding {
            severity: Severity::Critical,
            ..create_basic_rule_finding()
        };
        assert!(matches!(finding.severity, Severity::Critical));
    }

    // ==================== All Dimension Variants ====================

    #[test]
    fn rule_finding_with_stability_dimension() {
        let finding = RuleFinding {
            dimension: Dimension::Stability,
            ..create_basic_rule_finding()
        };
        assert_eq!(finding.dimension, Dimension::Stability);
    }

    #[test]
    fn rule_finding_with_performance_dimension() {
        let finding = RuleFinding {
            dimension: Dimension::Performance,
            ..create_basic_rule_finding()
        };
        assert_eq!(finding.dimension, Dimension::Performance);
    }

    #[test]
    fn rule_finding_with_correctness_dimension() {
        let finding = RuleFinding {
            dimension: Dimension::Correctness,
            ..create_basic_rule_finding()
        };
        assert_eq!(finding.dimension, Dimension::Correctness);
    }

    #[test]
    fn rule_finding_with_scalability_dimension() {
        let finding = RuleFinding {
            dimension: Dimension::Scalability,
            ..create_basic_rule_finding()
        };
        assert_eq!(finding.dimension, Dimension::Scalability);
    }
}
