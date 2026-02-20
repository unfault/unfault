//! Parser for suppression comments in source code.

use crate::suppression::model::{Suppression, SuppressionScope};
use crate::types::context::Language;

/// The suppression comment marker.
const SUPPRESSION_MARKER: &str = "unfault-ignore:";

/// Maximum line number for file-level suppressions.
const FILE_LEVEL_MAX_LINE: u32 = 10;

/// Parse suppression comments from source code.
///
/// Scans the source for comments containing `unfault-ignore:` and extracts
/// the rule IDs and scope for each suppression directive.
///
/// # Arguments
/// * `source` - The source code to scan
/// * `language` - The programming language (determines comment syntax)
///
/// # Returns
/// A vector of suppression directives found in the source.
///
/// # Example
/// ```ignore
/// let source = "# unfault-ignore: python.bare_except\ntry:\n    pass\nexcept:\n    pass";
/// let suppressions = parse_suppressions(source, Language::Python);
/// assert_eq!(suppressions.len(), 1);
/// ```
pub fn parse_suppressions(source: &str, language: Language) -> Vec<Suppression> {
    let mut suppressions = Vec::new();

    for (line_idx, line) in source.lines().enumerate() {
        let line_num = (line_idx + 1) as u32; // 1-indexed

        if let Some(pos) = line.find(SUPPRESSION_MARKER) {
            // Verify it's actually in a comment for this language
            if !is_in_comment(line, pos, language) {
                continue;
            }

            let after_marker = &line[pos + SUPPRESSION_MARKER.len()..];
            let (rule_ids, reason) = parse_rule_ids_and_reason(after_marker);

            let scope = determine_scope(line_num, pos, line, source);

            suppressions.push(Suppression {
                rule_ids,
                scope,
                comment_line: line_num,
                reason,
            });
        }
    }

    suppressions
}

/// Check if the suppression marker is within a comment for the given language.
fn is_in_comment(line: &str, marker_pos: usize, language: Language) -> bool {
    let before_marker = &line[..marker_pos];

    match language {
        Language::Python => {
            // Python: # comment
            before_marker.contains('#')
        }
        Language::Typescript | Language::Go | Language::Rust => {
            // C-style: // comment or /* comment */
            before_marker.contains("//") || before_marker.contains("/*")
        }
        _ => {
            // For unsupported languages, be permissive
            before_marker.contains('#')
                || before_marker.contains("//")
                || before_marker.contains("/*")
        }
    }
}

/// Determine the scope of a suppression based on its position.
fn determine_scope(
    line_num: u32,
    comment_pos: usize,
    line: &str,
    source: &str,
) -> SuppressionScope {
    // Same-line: there's code before the comment - check this FIRST
    // because inline suppression takes priority over file-level position
    let before_comment = &line[..comment_pos];
    let trimmed = before_comment.trim();

    // Check if there's actual code before the comment (not just another comment start)
    if !trimmed.is_empty()
        && !trimmed.starts_with('#')
        && !trimmed.starts_with("//")
        && !trimmed.starts_with("/*")
        && !trimmed.starts_with('*')
    {
        return SuppressionScope::SameLine;
    }

    // File-level: comment in first N lines (excluding shebang/encoding)
    // AND the comment is on its own line (no code before it)
    if line_num <= FILE_LEVEL_MAX_LINE && is_file_level_context(source, line_num) {
        return SuppressionScope::File;
    }

    // Default: next-line suppression (comment on its own line, but not at file top)
    SuppressionScope::NextLine
}

/// Check if this is a valid file-level context (not inside a function, class, etc.).
///
/// A suppression is considered file-level if:
/// - It's in the first N lines
/// - It's not preceded by lines that look like function/class definitions
fn is_file_level_context(source: &str, line_num: u32) -> bool {
    // Simple heuristic: check if any previous line starts a block
    let lines: Vec<&str> = source.lines().take((line_num - 1) as usize).collect();

    for line in lines {
        let trimmed = line.trim();
        // Skip empty lines, comments, and common header patterns
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
            || trimmed.starts_with("\"\"\"")
            || trimmed.starts_with("'''")
            || trimmed.starts_with("import ")
            || trimmed.starts_with("from ")
            || trimmed.starts_with("use ")
            || trimmed.starts_with("package ")
            || trimmed.starts_with("pub mod ")
            || trimmed.starts_with("mod ")
            || trimmed.starts_with("extern ")
        {
            continue;
        }

        // If we see something that looks like code, it's not file-level
        if trimmed.starts_with("def ")
            || trimmed.starts_with("class ")
            || trimmed.starts_with("async def ")
            || trimmed.starts_with("fn ")
            || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("async fn ")
            || trimmed.starts_with("function ")
            || trimmed.starts_with("const ")
            || trimmed.starts_with("let ")
            || trimmed.starts_with("var ")
            || trimmed.starts_with("type ")
            || trimmed.starts_with("struct ")
            || trimmed.starts_with("enum ")
            || trimmed.starts_with("impl ")
            || trimmed.starts_with("interface ")
        {
            return false;
        }
    }

    true
}

/// Parse rule IDs and optional reason from the text after the marker.
///
/// Format: `rule1, rule2, rule3 - reason text` or `rule1, rule2 -- reason`
fn parse_rule_ids_and_reason(text: &str) -> (Vec<String>, Option<String>) {
    let text = text.trim();

    // Split on `-` or `--` for reason
    let (rules_part, reason) = if let Some(pos) = text.find(" - ") {
        let (rules, reason) = text.split_at(pos);
        (rules.trim(), Some(reason[3..].trim().to_string()))
    } else if let Some(pos) = text.find(" -- ") {
        let (rules, reason) = text.split_at(pos);
        (rules.trim(), Some(reason[4..].trim().to_string()))
    } else {
        (text, None)
    };

    // Parse rule IDs (comma-separated)
    let rule_ids: Vec<String> = rules_part
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Filter out empty reasons
    let reason = reason.filter(|r| !r.is_empty());

    (rule_ids, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== parse_suppressions Tests ====================

    #[test]
    fn parse_single_rule_python() {
        // A comment at line 1 (within first 10 lines, no code before) is file-level
        let source = "# unfault-ignore: python.bare_except\nx = 1";
        let suppressions = parse_suppressions(source, Language::Python);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_ids, vec!["python.bare_except"]);
        assert_eq!(suppressions[0].scope, SuppressionScope::File);
        assert_eq!(suppressions[0].comment_line, 1);
    }

    #[test]
    fn parse_next_line_suppression() {
        // A comment after line 10 or after code definitions is next-line
        let source = "def foo():\n    pass\n\n# unfault-ignore: python.bare_except\nx = 1";
        let suppressions = parse_suppressions(source, Language::Python);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_ids, vec!["python.bare_except"]);
        assert_eq!(suppressions[0].scope, SuppressionScope::NextLine);
        assert_eq!(suppressions[0].comment_line, 4);
    }

    #[test]
    fn parse_single_rule_typescript() {
        let source = "// unfault-ignore: typescript.global_mutable_state\nlet x = {};";
        let suppressions = parse_suppressions(source, Language::Typescript);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(
            suppressions[0].rule_ids,
            vec!["typescript.global_mutable_state"]
        );
    }

    #[test]
    fn parse_multiple_rules() {
        let source = "# unfault-ignore: rule1, rule2, rule3\ncode()";
        let suppressions = parse_suppressions(source, Language::Python);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_ids, vec!["rule1", "rule2", "rule3"]);
    }

    #[test]
    fn parse_with_reason() {
        let source = "# unfault-ignore: python.bare_except - intentional catch-all\ncode()";
        let suppressions = parse_suppressions(source, Language::Python);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(
            suppressions[0].reason,
            Some("intentional catch-all".to_string())
        );
    }

    #[test]
    fn parse_with_double_dash_reason() {
        let source = "# unfault-ignore: rule1 -- this is the reason\ncode()";
        let suppressions = parse_suppressions(source, Language::Python);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(
            suppressions[0].reason,
            Some("this is the reason".to_string())
        );
    }

    #[test]
    fn parse_file_level_suppression() {
        let source = "#!/usr/bin/env python\n# unfault-ignore: python.bare_except\nimport os";
        let suppressions = parse_suppressions(source, Language::Python);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].scope, SuppressionScope::File);
    }

    #[test]
    fn parse_inline_suppression() {
        let source = "let cache = new Map();  // unfault-ignore: typescript.global_mutable_state";
        let suppressions = parse_suppressions(source, Language::Typescript);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].scope, SuppressionScope::SameLine);
    }

    #[test]
    fn parse_multiple_suppressions_in_file() {
        let source = r#"# unfault-ignore: rule1
def foo():
    # unfault-ignore: rule2
    pass
"#;
        let suppressions = parse_suppressions(source, Language::Python);

        assert_eq!(suppressions.len(), 2);
        assert_eq!(suppressions[0].rule_ids, vec!["rule1"]);
        assert_eq!(suppressions[1].rule_ids, vec!["rule2"]);
    }

    #[test]
    fn parse_wildcard_suppression() {
        let source = "# unfault-ignore: *\ncode()";
        let suppressions = parse_suppressions(source, Language::Python);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_ids, vec!["*"]);
    }

    #[test]
    fn parse_language_wildcard() {
        let source = "# unfault-ignore: python.*\ncode()";
        let suppressions = parse_suppressions(source, Language::Python);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_ids, vec!["python.*"]);
    }

    #[test]
    fn parse_go_comment() {
        let source = "// unfault-ignore: go.unchecked_error\nfunc main() {}";
        let suppressions = parse_suppressions(source, Language::Go);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_ids, vec!["go.unchecked_error"]);
    }

    #[test]
    fn parse_rust_comment() {
        let source = "// unfault-ignore: rust.unsafe_unwrap\nfn main() {}";
        let suppressions = parse_suppressions(source, Language::Rust);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_ids, vec!["rust.unsafe_unwrap"]);
    }

    #[test]
    fn parse_ignores_non_comment_marker() {
        let source = "let msg = \"unfault-ignore: fake\";\n// unfault-ignore: real";
        let suppressions = parse_suppressions(source, Language::Typescript);

        assert_eq!(suppressions.len(), 1);
        assert_eq!(suppressions[0].rule_ids, vec!["real"]);
    }

    #[test]
    fn parse_empty_source() {
        let source = "";
        let suppressions = parse_suppressions(source, Language::Python);

        assert!(suppressions.is_empty());
    }

    #[test]
    fn parse_no_suppressions() {
        let source = "def foo():\n    return 42";
        let suppressions = parse_suppressions(source, Language::Python);

        assert!(suppressions.is_empty());
    }

    // ==================== parse_rule_ids_and_reason Tests ====================

    #[test]
    fn parse_rule_ids_single() {
        let (ids, reason) = parse_rule_ids_and_reason("rule1");
        assert_eq!(ids, vec!["rule1"]);
        assert!(reason.is_none());
    }

    #[test]
    fn parse_rule_ids_multiple() {
        let (ids, reason) = parse_rule_ids_and_reason("rule1, rule2, rule3");
        assert_eq!(ids, vec!["rule1", "rule2", "rule3"]);
        assert!(reason.is_none());
    }

    #[test]
    fn parse_rule_ids_with_reason() {
        let (ids, reason) = parse_rule_ids_and_reason("rule1 - this is why");
        assert_eq!(ids, vec!["rule1"]);
        assert_eq!(reason, Some("this is why".to_string()));
    }

    #[test]
    fn parse_rule_ids_whitespace() {
        let (ids, _) = parse_rule_ids_and_reason("  rule1 ,  rule2  ");
        assert_eq!(ids, vec!["rule1", "rule2"]);
    }

    #[test]
    fn parse_rule_ids_empty() {
        let (ids, reason) = parse_rule_ids_and_reason("");
        assert!(ids.is_empty());
        assert!(reason.is_none());
    }

    // ==================== determine_scope Tests ====================

    #[test]
    fn scope_file_level_line_1() {
        let source = "# unfault-ignore: rule\ncode()";
        let scope = determine_scope(1, 0, "# unfault-ignore: rule", source);
        assert_eq!(scope, SuppressionScope::File);
    }

    #[test]
    fn scope_file_level_after_shebang() {
        let source = "#!/usr/bin/env python\n# unfault-ignore: rule\ncode()";
        let scope = determine_scope(2, 0, "# unfault-ignore: rule", source);
        assert_eq!(scope, SuppressionScope::File);
    }

    #[test]
    fn scope_next_line() {
        let source = "def foo():\n    # unfault-ignore: rule\n    pass";
        let scope = determine_scope(
            11,
            4,
            "    # unfault-ignore: rule",
            &format!("{}\n{}", "line\n".repeat(10), source),
        );
        assert_eq!(scope, SuppressionScope::NextLine);
    }

    #[test]
    fn scope_same_line() {
        let source = "x = 1  # unfault-ignore: rule";
        // marker is at position 7 (after "x = 1  ")
        let scope = determine_scope(15, 7, source, "");
        assert_eq!(scope, SuppressionScope::SameLine);
    }

    // ==================== is_file_level_context Tests ====================

    #[test]
    fn file_level_context_empty_before() {
        assert!(is_file_level_context("", 1));
    }

    #[test]
    fn file_level_context_with_imports() {
        let source = "import os\nimport sys\n";
        assert!(is_file_level_context(source, 3));
    }

    #[test]
    fn file_level_context_after_function() {
        let source = "def foo():\n    pass\n";
        assert!(!is_file_level_context(source, 3));
    }

    #[test]
    fn file_level_context_after_class() {
        let source = "class Foo:\n    pass\n";
        assert!(!is_file_level_context(source, 3));
    }

    // ==================== is_in_comment Tests ====================

    #[test]
    fn is_in_comment_python_hash() {
        assert!(is_in_comment("# unfault-ignore: rule", 2, Language::Python));
    }

    #[test]
    fn is_in_comment_typescript_double_slash() {
        assert!(is_in_comment(
            "// unfault-ignore: rule",
            3,
            Language::Typescript
        ));
    }

    #[test]
    fn is_in_comment_not_in_comment() {
        assert!(!is_in_comment("unfault-ignore: rule", 0, Language::Python));
    }

    #[test]
    fn is_in_comment_inline() {
        assert!(is_in_comment(
            "let x = 1; // unfault-ignore: rule",
            14,
            Language::Typescript
        ));
    }
}
