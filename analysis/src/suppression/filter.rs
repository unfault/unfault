//! Filtering of suppressed findings.

use crate::rules::finding::RuleFinding;
use crate::suppression::model::{Suppression, SuppressionScope};

/// Filter findings based on suppressions.
///
/// Removes any finding that matches a suppression directive based on
/// rule ID and location (file-level, line-level, or same-line).
///
/// # Arguments
/// * `findings` - The findings to filter
/// * `suppressions` - The suppression directives from the same file
///
/// # Returns
/// A vector of findings that were not suppressed.
pub fn filter_suppressed_findings(
    findings: Vec<RuleFinding>,
    suppressions: &[Suppression],
) -> Vec<RuleFinding> {
    if suppressions.is_empty() {
        return findings;
    }

    findings
        .into_iter()
        .filter(|finding| !is_finding_suppressed(finding, suppressions))
        .collect()
}

/// Check if a finding is suppressed by any of the given suppressions.
fn is_finding_suppressed(finding: &RuleFinding, suppressions: &[Suppression]) -> bool {
    for suppression in suppressions {
        // Check if rule ID matches
        if !matches_rule_id(&finding.rule_id, &suppression.rule_ids) {
            continue;
        }

        // Check scope
        match suppression.scope {
            SuppressionScope::File => {
                // File-level suppression applies to all findings in the file
                return true;
            }
            SuppressionScope::NextLine => {
                // Next-line suppression: finding must be on the line after the comment
                if let Some(finding_line) = finding.line {
                    if finding_line == suppression.comment_line + 1 {
                        return true;
                    }
                }
            }
            SuppressionScope::SameLine => {
                // Same-line suppression: finding must be on the same line as the comment
                if let Some(finding_line) = finding.line {
                    if finding_line == suppression.comment_line {
                        return true;
                    }
                }
            }
        }
    }

    false
}

/// Check if a finding's rule ID matches any of the suppression patterns.
///
/// Supports:
/// - Exact match: `python.bare_except` matches `python.bare_except`
/// - Wildcard all: `*` matches any rule
/// - Language wildcard: `python.*` matches any rule starting with `python.`
/// - Short form (backward compat): `bare_except` matches `python.bare_except`
fn matches_rule_id(finding_rule_id: &str, suppression_rule_ids: &[String]) -> bool {
    if suppression_rule_ids.is_empty() {
        // Empty means suppress all
        return true;
    }

    for pattern in suppression_rule_ids {
        // Wildcard for all rules
        if pattern == "*" {
            return true;
        }

        // Language wildcard: `python.*` matches `python.anything`
        if pattern.ends_with(".*") {
            let prefix = &pattern[..pattern.len() - 1]; // Keep the dot
            if finding_rule_id.starts_with(prefix) {
                return true;
            }
        }

        // Exact match
        if pattern == finding_rule_id {
            return true;
        }

        // Short form backward compatibility:
        // `global_mutable_state` should match `typescript.global_mutable_state`
        // Check if the finding rule ID ends with the pattern (after a dot)
        if !pattern.contains('.') {
            let suffix = format!(".{}", pattern);
            if finding_rule_id.ends_with(&suffix) {
                return true;
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::types::context::Dimension;
    use crate::types::finding::{FindingKind, Severity};

    fn make_finding(rule_id: &str, line: u32) -> RuleFinding {
        RuleFinding {
            rule_id: rule_id.to_string(),
            title: "Test Finding".to_string(),
            description: None,
            kind: FindingKind::AntiPattern,
            severity: Severity::Medium,
            confidence: 0.9,
            dimension: Dimension::Correctness,
            file_id: FileId(1),
            file_path: "test.py".to_string(),
            line: Some(line),
            column: Some(1),
            end_line: None,
            end_column: None,
            byte_range: None,
            patch: None,
            fix_preview: None,
            tags: vec![],
        }
    }

    fn make_suppression(
        rule_ids: Vec<&str>,
        scope: SuppressionScope,
        comment_line: u32,
    ) -> Suppression {
        Suppression {
            rule_ids: rule_ids.into_iter().map(|s| s.to_string()).collect(),
            scope,
            comment_line,
            reason: None,
        }
    }

    // ==================== filter_suppressed_findings Tests ====================

    #[test]
    fn filter_empty_suppressions() {
        let findings = vec![make_finding("python.bare_except", 10)];
        let suppressions: Vec<Suppression> = vec![];

        let result = filter_suppressed_findings(findings, &suppressions);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filter_empty_findings() {
        let findings: Vec<RuleFinding> = vec![];
        let suppressions = vec![make_suppression(
            vec!["python.bare_except"],
            SuppressionScope::File,
            1,
        )];

        let result = filter_suppressed_findings(findings, &suppressions);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_file_level_suppression() {
        let findings = vec![
            make_finding("python.bare_except", 10),
            make_finding("python.bare_except", 20),
            make_finding("python.bare_except", 30),
        ];
        let suppressions = vec![make_suppression(
            vec!["python.bare_except"],
            SuppressionScope::File,
            1,
        )];

        let result = filter_suppressed_findings(findings, &suppressions);
        assert!(result.is_empty(), "File-level should suppress all findings");
    }

    #[test]
    fn filter_next_line_suppression() {
        let findings = vec![
            make_finding("python.bare_except", 10),
            make_finding("python.bare_except", 11),
            make_finding("python.bare_except", 12),
        ];
        let suppressions = vec![make_suppression(
            vec!["python.bare_except"],
            SuppressionScope::NextLine,
            10, // Suppresses line 11
        )];

        let result = filter_suppressed_findings(findings, &suppressions);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].line, Some(10));
        assert_eq!(result[1].line, Some(12));
    }

    #[test]
    fn filter_same_line_suppression() {
        let findings = vec![
            make_finding("typescript.global_mutable_state", 10),
            make_finding("typescript.global_mutable_state", 11),
        ];
        let suppressions = vec![make_suppression(
            vec!["typescript.global_mutable_state"],
            SuppressionScope::SameLine,
            10, // Suppresses line 10
        )];

        let result = filter_suppressed_findings(findings, &suppressions);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].line, Some(11));
    }

    #[test]
    fn filter_wildcard_suppression() {
        let findings = vec![
            make_finding("python.bare_except", 10),
            make_finding("python.sql_injection", 20),
            make_finding("typescript.global_mutable_state", 30),
        ];
        let suppressions = vec![make_suppression(vec!["*"], SuppressionScope::File, 1)];

        let result = filter_suppressed_findings(findings, &suppressions);
        assert!(result.is_empty(), "Wildcard should suppress all rules");
    }

    #[test]
    fn filter_language_wildcard() {
        let findings = vec![
            make_finding("python.bare_except", 10),
            make_finding("python.sql_injection", 20),
            make_finding("typescript.global_mutable_state", 30),
        ];
        let suppressions = vec![make_suppression(
            vec!["python.*"],
            SuppressionScope::File,
            1,
        )];

        let result = filter_suppressed_findings(findings, &suppressions);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].rule_id, "typescript.global_mutable_state");
    }

    #[test]
    fn filter_multiple_suppressions() {
        let findings = vec![
            make_finding("python.bare_except", 10),
            make_finding("python.sql_injection", 20),
        ];
        let suppressions = vec![
            make_suppression(vec!["python.bare_except"], SuppressionScope::NextLine, 9),
            make_suppression(vec!["python.sql_injection"], SuppressionScope::NextLine, 19),
        ];

        let result = filter_suppressed_findings(findings, &suppressions);
        assert!(result.is_empty());
    }

    #[test]
    fn filter_non_matching_suppression() {
        let findings = vec![make_finding("python.bare_except", 10)];
        let suppressions = vec![make_suppression(
            vec!["python.sql_injection"],
            SuppressionScope::File,
            1,
        )];

        let result = filter_suppressed_findings(findings, &suppressions);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn filter_non_matching_line() {
        let findings = vec![make_finding("python.bare_except", 10)];
        let suppressions = vec![make_suppression(
            vec!["python.bare_except"],
            SuppressionScope::NextLine,
            20, // Wrong line - would suppress line 21
        )];

        let result = filter_suppressed_findings(findings, &suppressions);
        assert_eq!(result.len(), 1);
    }

    // ==================== matches_rule_id Tests ====================

    #[test]
    fn matches_exact_rule_id() {
        assert!(matches_rule_id(
            "python.bare_except",
            &["python.bare_except".to_string()]
        ));
    }

    #[test]
    fn matches_wildcard_all() {
        assert!(matches_rule_id("python.bare_except", &["*".to_string()]));
    }

    #[test]
    fn matches_language_wildcard() {
        assert!(matches_rule_id(
            "python.bare_except",
            &["python.*".to_string()]
        ));
        assert!(!matches_rule_id(
            "typescript.global_mutable_state",
            &["python.*".to_string()]
        ));
    }

    #[test]
    fn matches_short_form_backward_compat() {
        // Existing code uses short forms like "global_mutable_state"
        assert!(matches_rule_id(
            "typescript.global_mutable_state",
            &["global_mutable_state".to_string()]
        ));
        assert!(matches_rule_id(
            "python.bare_except",
            &["bare_except".to_string()]
        ));
    }

    #[test]
    fn matches_empty_means_all() {
        assert!(matches_rule_id("any.rule", &[]));
    }

    #[test]
    fn matches_multiple_patterns() {
        assert!(matches_rule_id(
            "python.bare_except",
            &["typescript.*".to_string(), "python.bare_except".to_string()]
        ));
    }

    #[test]
    fn no_match_different_rule() {
        assert!(!matches_rule_id(
            "python.bare_except",
            &["python.sql_injection".to_string()]
        ));
    }

    #[test]
    fn no_match_partial_name() {
        // "bare" should not match "python.bare_except"
        assert!(!matches_rule_id(
            "python.bare_except",
            &["bare".to_string()]
        ));
    }

    // ==================== is_finding_suppressed Tests ====================

    #[test]
    fn is_suppressed_file_level() {
        let finding = make_finding("rule", 100);
        let suppressions = vec![make_suppression(vec!["rule"], SuppressionScope::File, 1)];

        assert!(is_finding_suppressed(&finding, &suppressions));
    }

    #[test]
    fn is_suppressed_next_line_correct() {
        let finding = make_finding("rule", 11);
        let suppressions = vec![make_suppression(
            vec!["rule"],
            SuppressionScope::NextLine,
            10,
        )];

        assert!(is_finding_suppressed(&finding, &suppressions));
    }

    #[test]
    fn is_not_suppressed_next_line_wrong() {
        let finding = make_finding("rule", 12); // Wrong line
        let suppressions = vec![make_suppression(
            vec!["rule"],
            SuppressionScope::NextLine,
            10, // Would suppress line 11
        )];

        assert!(!is_finding_suppressed(&finding, &suppressions));
    }

    #[test]
    fn is_suppressed_same_line() {
        let finding = make_finding("rule", 10);
        let suppressions = vec![make_suppression(
            vec!["rule"],
            SuppressionScope::SameLine,
            10,
        )];

        assert!(is_finding_suppressed(&finding, &suppressions));
    }

    #[test]
    fn is_not_suppressed_different_rule() {
        let finding = make_finding("rule_a", 10);
        let suppressions = vec![make_suppression(vec!["rule_b"], SuppressionScope::File, 1)];

        assert!(!is_finding_suppressed(&finding, &suppressions));
    }
}
