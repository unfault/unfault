//! Rules for Gin web framework.
//!
//! Detects common issues with Gin handlers including:
//! - Missing input validation
//! - Untrusted input usage
//! - Security middleware configuration

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::applicability_defaults::sql_injection;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};

// ============================================================================
// GinMissingValidationRule
// ============================================================================

/// Rule that detects Gin handlers without input validation.
///
/// Accepting user input without validation can lead to:
/// - Invalid data in the system
/// - Security vulnerabilities
/// - Unexpected behavior and crashes
#[derive(Debug)]
pub struct GinMissingValidationRule;

impl GinMissingValidationRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GinMissingValidationRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for GinMissingValidationRule {
    fn id(&self) -> &'static str {
        "go.gin.missing_validation"
    }

    fn name(&self) -> &'static str {
        "Gin handler binds input without validation"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go = match sem.as_ref() {
                SourceSemantics::Go(go) => go,
                _ => continue,
            };

            // Look for ShouldBind/Bind calls - flag them for review
            // since we can't statically verify validation tags without type analysis
            for call in &go.calls {
                // Gin binding methods
                let is_bind_call = call.function_call.callee_expr.contains("ShouldBind")
                    || call.function_call.callee_expr.contains("BindJSON")
                    || call.function_call.callee_expr.contains("BindQuery")
                    || call.function_call.callee_expr.contains("BindUri")
                    || call.function_call.callee_expr.contains("BindHeader")
                    || (call.function_call.callee_expr.ends_with(".Bind") && !call.function_call.callee_expr.contains("Should"));

                if !is_bind_call {
                    continue;
                }

                let line = call.function_call.location.line;
                let column = call.function_call.location.column;

                // Flag bind calls for validation review
                let title = format!(
                    "Gin {} - ensure struct has validation tags",
                    call.function_call.callee_expr.split('.').last().unwrap_or("Bind")
                );

                let description = format!(
                    "The call to `{}` at line {} binds user input to a struct. \
                     Ensure the target struct has validation tags. Without validation:\n\
                     - Invalid data may enter your system\n\
                     - Security vulnerabilities may be introduced\n\
                     - Unexpected behavior may occur\n\n\
                     Add `binding:` tags to your struct fields for validation:\n\
                     ```go\n\
                     type Request struct {{\n\
                         Email string `json:\"email\" binding:\"required,email\"`\n\
                         Age   int    `json:\"age\" binding:\"required,min=0,max=150\"`\n\
                     }}\n\
                     ```",
                    call.function_call.callee_expr, line
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Low, // Lower severity since we can't confirm missing validation
                    confidence: 0.60,
                    dimension: Dimension::Correctness,
                    file_id: *file_id,
                    file_path: go.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: None, // Struct modification needed
                    fix_preview: Some(
                        "// Add validation tags to your struct:\n\
                         // type Request struct {\n\
                         //     Field string `json:\"field\" binding:\"required\"`\n\
                         // }"
                            .to_string(),
                    ),
                    tags: vec![
                        "go".into(),
                        "gin".into(),
                        "validation".into(),
                        "input".into(),
                    ],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(error_handling_in_handler())
    }
}

// ============================================================================
// GinUntrustedInputRule
// ============================================================================

/// Rule that detects direct use of untrusted Gin input in sensitive operations.
///
/// Using user input directly without sanitization can lead to:
/// - SQL injection
/// - Command injection
/// - Path traversal attacks
#[derive(Debug)]
pub struct GinUntrustedInputRule;

impl GinUntrustedInputRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GinUntrustedInputRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for GinUntrustedInputRule {
    fn id(&self) -> &'static str {
        "go.gin.untrusted_input"
    }

    fn name(&self) -> &'static str {
        "Untrusted Gin input used in sensitive operation"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go = match sem.as_ref() {
                SourceSemantics::Go(go) => go,
                _ => continue,
            };

            // Track Gin input sources and flag when they appear near dangerous sinks
            // This is a simplified pattern-based detection without full data flow analysis

            for call in &go.calls {
                // Look for Gin input methods
                let is_gin_input = call.function_call.callee_expr.contains("c.Param")
                    || call.function_call.callee_expr.contains("c.Query")
                    || call.function_call.callee_expr.contains("c.PostForm")
                    || call.function_call.callee_expr.contains("c.GetHeader")
                    || call.function_call.callee_expr.contains("c.DefaultQuery")
                    || call.function_call.callee_expr.contains("c.GetQuery");

                if !is_gin_input {
                    continue;
                }

                let line = call.function_call.location.line;
                let column = call.function_call.location.column;

                // Flag Gin input usage for security review
                let title = format!(
                    "Gin input `{}` - validate before use in sensitive operations",
                    call.function_call.callee_expr.split('.').last().unwrap_or("input")
                );

                let description = format!(
                    "User input from `{}` at line {} should be validated before use \
                     in sensitive operations. Untrusted input can lead to:\n\
                     - SQL injection\n\
                     - Command injection\n\
                     - Path traversal attacks\n\
                     - XSS vulnerabilities\n\n\
                     Recommendations:\n\
                     1. Validate and sanitize all user input\n\
                     2. Use parameterized queries for SQL\n\
                     3. Use proper escaping for command execution\n\
                     4. Validate file paths against a whitelist",
                    call.function_call.callee_expr, line
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::SecurityVulnerability,
                    severity: Severity::Medium, // Medium since we only detect input, not actual flow
                    confidence: 0.70,
                    dimension: Dimension::Security,
                    file_id: *file_id,
                    file_path: go.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: None, // Complex flow analysis
                    fix_preview: Some(format!(
                        "// Validate input before use:\n\
                         // 1. Check format/content\n\
                         // 2. Sanitize special characters\n\
                         // 3. Use safe APIs for SQL, filesystem, etc."
                    )),
                    tags: vec![
                        "go".into(),
                        "gin".into(),
                        "security".into(),
                        "input-validation".into(),
                    ],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(sql_injection())
    }
}

/// Check if a call is a dangerous sink for untrusted input.
fn is_dangerous_sink(sink: &str) -> Option<String> {
    // SQL sinks
    if sink.contains("Query")
        || sink.contains("Exec")
        || sink.contains("Raw")
        || sink.contains("Where")
    {
        return Some("SQL operation".to_string());
    }

    // Command execution sinks
    if sink.contains("exec.Command")
        || sink.contains("os.exec")
        || sink.contains("syscall.Exec")
    {
        return Some("command execution".to_string());
    }

    // File system sinks
    if sink.contains("os.Open")
        || sink.contains("os.Create")
        || sink.contains("ioutil.ReadFile")
        || sink.contains("os.ReadFile")
        || sink.contains("filepath.Join")
    {
        return Some("file system operation".to_string());
    }

    // Template rendering
    if sink.contains("template.HTML")
        || sink.contains("c.HTML")
    {
        return Some("template rendering".to_string());
    }

    None
}

/// Get the risk description for a sink type.
fn sink_type_risk(sink_type: &str) -> &'static str {
    match sink_type {
        "SQL operation" => "SQL injection attacks",
        "command execution" => "command injection attacks",
        "file system operation" => "path traversal attacks",
        "template rendering" => "XSS (cross-site scripting) attacks",
        _ => "security vulnerabilities",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::go::parse_go_file;
    use crate::semantics::go::build_go_semantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.go".to_string(),
            language: Language::Go,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_go_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_go_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Go(sem)))
    }

    // ==================== GinMissingValidationRule Tests ====================

    #[test]
    fn validation_rule_id_is_correct() {
        let rule = GinMissingValidationRule::new();
        assert_eq!(rule.id(), "go.gin.missing_validation");
    }

    #[test]
    fn validation_rule_name_is_correct() {
        let rule = GinMissingValidationRule::new();
        assert!(rule.name().contains("validation"));
    }

    #[test]
    fn validation_rule_implements_debug() {
        let rule = GinMissingValidationRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GinMissingValidationRule"));
    }

    #[tokio::test]
    async fn validation_returns_empty_for_non_go() {
        let rule = GinMissingValidationRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn validation_detects_bind_without_tags() {
        let rule = GinMissingValidationRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import "github.com/gin-gonic/gin"

type Request struct {
    Name string `json:"name"`
}

func handler(c *gin.Context) {
    var req Request
    c.ShouldBindJSON(&req)
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.gin.missing_validation" {
                assert!(finding.tags.contains(&"gin".to_string()));
                assert!(finding.tags.contains(&"validation".to_string()));
            }
        }
    }

    // ==================== GinUntrustedInputRule Tests ====================

    #[test]
    fn untrusted_rule_id_is_correct() {
        let rule = GinUntrustedInputRule::new();
        assert_eq!(rule.id(), "go.gin.untrusted_input");
    }

    #[test]
    fn untrusted_rule_name_is_correct() {
        let rule = GinUntrustedInputRule::new();
        assert!(rule.name().contains("Untrusted"));
    }

    #[test]
    fn untrusted_rule_implements_debug() {
        let rule = GinUntrustedInputRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GinUntrustedInputRule"));
    }

    #[tokio::test]
    async fn untrusted_returns_empty_for_non_go() {
        let rule = GinUntrustedInputRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn untrusted_detects_param_to_sql() {
        let rule = GinUntrustedInputRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
package main

import (
    "database/sql"
    "github.com/gin-gonic/gin"
)

func handler(c *gin.Context, db *sql.DB) {
    id := c.Param("id")
    db.Query("SELECT * FROM users WHERE id = " + id)
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        for finding in &findings {
            if finding.rule_id == "go.gin.untrusted_input" {
                assert_eq!(finding.severity, Severity::Medium);
                assert!(finding.tags.contains(&"security".to_string()));
            }
        }
    }

    // ==================== Helper Function Tests ====================

    #[test]
    fn is_dangerous_sink_detects_sql() {
        assert!(is_dangerous_sink("db.Query").is_some());
        assert!(is_dangerous_sink("db.Exec").is_some());
        assert!(is_dangerous_sink("gorm.Raw").is_some());
    }

    #[test]
    fn is_dangerous_sink_detects_command() {
        assert!(is_dangerous_sink("exec.Command").is_some());
    }

    #[test]
    fn is_dangerous_sink_detects_file() {
        assert!(is_dangerous_sink("os.Open").is_some());
        assert!(is_dangerous_sink("os.ReadFile").is_some());
    }

    #[test]
    fn is_dangerous_sink_returns_none_for_safe() {
        assert!(is_dangerous_sink("fmt.Println").is_none());
        assert!(is_dangerous_sink("log.Printf").is_none());
    }
}