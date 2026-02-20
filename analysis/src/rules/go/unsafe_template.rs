//! Rule: Unsafe template in Go
//!
//! Detects template injection vulnerabilities from using text/template with user input.

use async_trait::async_trait;
use std::sync::Arc;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::sql_injection;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unsafe template usage.
#[derive(Debug, Default)]
pub struct GoUnsafeTemplateRule;

impl GoUnsafeTemplateRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoUnsafeTemplateRule {
    fn id(&self) -> &'static str {
        "go.unsafe_template"
    }

    fn name(&self) -> &'static str {
        "Unsafe template usage"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(sql_injection())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let go = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Check imports for text/template vs html/template
            let uses_text_template = go.imports.iter().any(|imp| imp.path == "text/template");
            let uses_html_template = go.imports.iter().any(|imp| imp.path == "html/template");

            // Flag handlers using text/template for HTML content
            if uses_text_template && !uses_html_template {
                // Check if any HTTP handlers exist
                for func in &go.functions {
                    let is_http_handler = func.params.iter().any(|p| {
                        p.param_type.contains("http.ResponseWriter")
                            || p.param_type.contains("*gin.Context")
                            || p.param_type.contains("echo.Context")
                    });

                    if is_http_handler {
                        // Check if template.Execute is called in this file
                        let has_template_execute = go.calls.iter().any(|call| {
                            call.function_call.callee_expr.contains("Execute")
                                || call.function_call.callee_expr.contains("ExecuteTemplate")
                        });

                        if has_template_execute {
                            let line = func.location.range.start_line + 1;
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "text/template used in HTTP handler".to_string(),
                                description: Some(
                                    "text/template does not escape HTML output, making it \
                                     vulnerable to XSS attacks. Use html/template instead \
                                     for web content, which auto-escapes HTML characters.".to_string()
                                ),
                                kind: FindingKind::SecurityVulnerability,
                                severity: Severity::Critical,
                                confidence: 0.90,
                                dimension: Dimension::Security,
                                file_id: *file_id,
                                file_path: go.path.clone(),
                                line: Some(line),
                                column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                                patch: Some(FilePatch {
                                    file_id: *file_id,
                                    hunks: vec![PatchHunk {
                                        range: PatchRange::InsertBeforeLine { line: 1 },
                                        replacement: "// Replace text/template with html/template for XSS protection\n// import \"html/template\" instead of \"text/template\"".to_string(),
                                    }],
                                }),
                                fix_preview: Some("Use html/template".to_string()),
                                tags: vec!["go".into(), "security".into(), "xss".into(), "template".into()],
                            });
                            break;
                        }
                    }
                }
            }

            // Check for unsafe template type casts (template.HTML, template.JS, etc.)
            for call in &go.calls {
                if call.function_call.callee_expr.contains("template.HTML")
                    || call.function_call.callee_expr.contains("template.JS")
                    || call.function_call.callee_expr.contains("template.CSS")
                    || call.function_call.callee_expr.contains("template.URL")
                {
                    let line = call.function_call.location.line;
                    let column = call.function_call.location.column;

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Unsafe template type cast".to_string(),
                        description: Some(
                            "Casting to template.HTML/JS/CSS/URL bypasses Go's automatic \
                             escaping. Only use these with trusted, static content - never \
                             with user input. Validate and sanitize before casting."
                                .to_string(),
                        ),
                        kind: FindingKind::SecurityVulnerability,
                        severity: Severity::High,
                        confidence: 0.85,
                        dimension: Dimension::Security,
                        file_id: *file_id,
                        file_path: go.path.clone(),
                        line: Some(line),
                        column: Some(column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: Some(FilePatch {
                            file_id: *file_id,
                            hunks: vec![PatchHunk {
                                range: PatchRange::InsertBeforeLine { line },
                                replacement:
                                    "// WARNING: template.HTML/JS/CSS/URL bypasses escaping
// Only use with trusted, validated content:
// - Sanitize user input before casting
// - Use a sanitization library like bluemonday for HTML"
                                        .to_string(),
                            }],
                        }),
                        fix_preview: Some("Validate before unsafe cast".to_string()),
                        tags: vec![
                            "go".into(),
                            "security".into(),
                            "xss".into(),
                            "template".into(),
                        ],
                    });
                }
            }

            // Check for dynamic template construction via calls
            for call in &go.calls {
                if call.function_call.callee_expr.contains("template.Must")
                    || call.function_call.callee_expr.contains("template.New")
                {
                    // Check if arguments contain string concatenation patterns
                    if call.args_repr.contains("+") || call.args_repr.contains("fmt.Sprintf") {
                        let line = call.function_call.location.line;
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Dynamic template construction".to_string(),
                            description: Some(
                                "Building templates by string concatenation can lead to \
                                 template injection vulnerabilities. Templates should be \
                                 static and defined at compile time.".to_string()
                            ),
                            kind: FindingKind::SecurityVulnerability,
                            severity: Severity::High,
                            confidence: 0.75,
                            dimension: Dimension::Security,
                            file_id: *file_id,
                            file_path: go.path.clone(),
                            line: Some(line),
                            column: None,
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(FilePatch {
                                file_id: *file_id,
                                hunks: vec![PatchHunk {
                                    range: PatchRange::InsertBeforeLine { line },
                                    replacement: "// Use static template definitions instead of string concatenation\n// Use template.ParseFiles() or embed templates with //go:embed".to_string(),
                                }],
                            }),
                            fix_preview: Some("Use static templates".to_string()),
                            tags: vec!["go".into(), "security".into(), "template-injection".into()],
                        });
                    }
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_metadata() {
        let rule = GoUnsafeTemplateRule::new();
        assert_eq!(rule.id(), "go.unsafe_template");
        assert!(!rule.name().is_empty());
    }
}
