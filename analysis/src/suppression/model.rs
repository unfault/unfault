//! Data structures for rule suppression.

use serde::{Deserialize, Serialize};

/// A rule suppression directive found in source code.
///
/// Suppressions allow developers to acknowledge findings and mark them
/// as intentional or reviewed, preventing them from appearing in analysis results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suppression {
    /// The rule IDs to suppress.
    ///
    /// - Empty vec means suppress all rules
    /// - "*" means suppress all rules
    /// - "python.*" means suppress all Python rules
    /// - "python.bare_except" means suppress that specific rule
    /// - Short form "bare_except" is also supported for backward compatibility
    pub rule_ids: Vec<String>,

    /// The scope of this suppression.
    pub scope: SuppressionScope,

    /// Line number where the suppression comment appears (1-indexed).
    pub comment_line: u32,

    /// Optional reason provided after the rule IDs (text after `-` or `--`).
    pub reason: Option<String>,
}

/// The scope of a suppression directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SuppressionScope {
    /// Suppresses rules for the entire file.
    ///
    /// Applied when the comment is in the first 10 lines of the file
    /// (excluding shebang and encoding declarations).
    File,

    /// Suppresses rules for the next line only.
    ///
    /// Applied when the comment is on its own line (no code before it).
    NextLine,

    /// Suppresses rules for the same line (inline comment).
    ///
    /// Applied when there's code before the comment on the same line.
    SameLine,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suppression_can_be_created() {
        let suppression = Suppression {
            rule_ids: vec!["python.bare_except".to_string()],
            scope: SuppressionScope::NextLine,
            comment_line: 10,
            reason: Some("intentional catch-all".to_string()),
        };

        assert_eq!(suppression.rule_ids.len(), 1);
        assert_eq!(suppression.rule_ids[0], "python.bare_except");
        assert_eq!(suppression.scope, SuppressionScope::NextLine);
        assert_eq!(suppression.comment_line, 10);
        assert_eq!(
            suppression.reason,
            Some("intentional catch-all".to_string())
        );
    }

    #[test]
    fn suppression_can_be_cloned() {
        let original = Suppression {
            rule_ids: vec!["rule1".to_string(), "rule2".to_string()],
            scope: SuppressionScope::File,
            comment_line: 5,
            reason: None,
        };

        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn suppression_scope_equality() {
        assert_eq!(SuppressionScope::File, SuppressionScope::File);
        assert_eq!(SuppressionScope::NextLine, SuppressionScope::NextLine);
        assert_eq!(SuppressionScope::SameLine, SuppressionScope::SameLine);
        assert_ne!(SuppressionScope::File, SuppressionScope::NextLine);
    }

    #[test]
    fn suppression_can_be_serialized() {
        let suppression = Suppression {
            rule_ids: vec!["python.bare_except".to_string()],
            scope: SuppressionScope::File,
            comment_line: 1,
            reason: None,
        };

        let json = serde_json::to_string(&suppression).unwrap();
        assert!(json.contains("python.bare_except"));
        assert!(json.contains("File"));
    }

    #[test]
    fn suppression_can_be_deserialized() {
        let json = r#"{
            "rule_ids": ["python.bare_except"],
            "scope": "File",
            "comment_line": 1,
            "reason": null
        }"#;

        let suppression: Suppression = serde_json::from_str(json).unwrap();
        assert_eq!(suppression.rule_ids, vec!["python.bare_except"]);
        assert_eq!(suppression.scope, SuppressionScope::File);
    }

    #[test]
    fn suppression_with_empty_rule_ids() {
        let suppression = Suppression {
            rule_ids: vec![],
            scope: SuppressionScope::File,
            comment_line: 1,
            reason: Some("suppress all".to_string()),
        };

        assert!(suppression.rule_ids.is_empty());
    }

    #[test]
    fn suppression_with_multiple_rule_ids() {
        let suppression = Suppression {
            rule_ids: vec![
                "python.bare_except".to_string(),
                "python.sql_injection".to_string(),
                "python.global_mutable_state".to_string(),
            ],
            scope: SuppressionScope::NextLine,
            comment_line: 42,
            reason: None,
        };

        assert_eq!(suppression.rule_ids.len(), 3);
    }

    #[test]
    fn suppression_scope_debug() {
        let scope = SuppressionScope::File;
        let debug_str = format!("{:?}", scope);
        assert!(debug_str.contains("File"));
    }
}
