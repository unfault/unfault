//! Rule A6: Missing structured logging
//!
//! Detects use of print() or basic logging without structured logging
//! (structlog, json logging, etc.) which makes log aggregation and
//! analysis difficult in production.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::structured_logging;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::{ImportInsertionType, PyImport};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unstructured logging in Python code.
///
/// Production applications should use structured logging (JSON format,
/// structlog, etc.) to enable log aggregation, searching, and analysis.
/// Plain print() statements and basic logging.info() calls make it
/// difficult to parse and analyze logs at scale.
#[derive(Debug)]
pub struct PythonMissingStructuredLoggingRule;

impl PythonMissingStructuredLoggingRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonMissingStructuredLoggingRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about an unstructured logging call
#[derive(Debug, Clone)]
struct UnstructuredLoggingCall {
    /// The function being called (e.g., "print", "logging.info")
    function_name: String,
    /// Line number (1-based)
    line: u32,
    /// Column number (1-based)
    column: u32,
    /// The type of logging issue
    issue_type: LoggingIssueType,
    /// Start byte offset
    start_byte: usize,
    /// End byte offset
    end_byte: usize,
    /// Arguments representation for reconstruction
    args_repr: String,
    /// Existing imports in the file (for avoiding duplicate imports)
    imports: Vec<PyImport>,
    /// The logging level (info, warning, error, etc.)
    log_level: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum LoggingIssueType {
    /// print() statement used for logging
    PrintStatement,
    /// Basic logging without structured format
    BasicLogging,
}

impl LoggingIssueType {
    fn description(&self) -> &'static str {
        match self {
            LoggingIssueType::PrintStatement => {
                "print() statements should not be used for logging in production code"
            }
            LoggingIssueType::BasicLogging => {
                "Basic logging should be replaced with structured logging (structlog, JSON format)"
            }
        }
    }

    fn severity(&self) -> Severity {
        match self {
            LoggingIssueType::PrintStatement => Severity::Medium,
            LoggingIssueType::BasicLogging => Severity::Low,
        }
    }
}

#[async_trait]
impl Rule for PythonMissingStructuredLoggingRule {
    fn id(&self) -> &'static str {
        "python.missing_structured_logging"
    }

    fn name(&self) -> &'static str {
        "Missing structured logging"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(structured_logging())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        // ========== GLOBAL PASS ==========
        // Check if ANY file in the context has structured logging configured.
        // This handles cross-file scenarios like:
        // - app/logging.py: imports structlog and defines get_logger()
        // - app/main.py: from .logging import get_logger; logger.info(...)
        //
        // In this case, we should NOT flag app/main.py because structured
        // logging is configured in the project.
        let context_has_structured_logging = semantics.iter().any(|(_, sem)| {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => return false,
            };

            // Check if this file imports/configures structured logging
            py.imports.iter().any(|imp| {
                imp.module == "structlog"
                    || imp.module.contains("json_logging")
                    || imp.names.iter().any(|n| n == "structlog")
            })
        });

        // If ANY file in the context has structured logging, skip all findings
        if context_has_structured_logging {
            return findings;
        }

        // ========== PER-FILE PASS ==========
        // Only if no file has structured logging configured, check each file
        for (file_id, sem) in semantics {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => continue,
            };

            // Also skip files that import get_logger from a custom logging module
            // This pattern (from .logging import get_logger) suggests the project
            // has its own logging module that likely wraps structured logging
            let imports_custom_get_logger = py.imports.iter().any(|imp| {
                (imp.module.ends_with(".logging")
                    || (imp.module.ends_with("logging") && imp.module.contains('.')))
                    && imp.names.iter().any(|n| n == "get_logger")
            });

            if imports_custom_get_logger {
                continue;
            }

            // Check for print() calls
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;

                if callee == "print" {
                    let unstructured = UnstructuredLoggingCall {
                        function_name: callee.clone(),
                        line: call.function_call.location.line,
                        column: call.function_call.location.column,
                        issue_type: LoggingIssueType::PrintStatement,
                        start_byte: call.start_byte,
                        end_byte: call.end_byte,
                        args_repr: call.args_repr.clone(),
                        imports: py.imports.clone(),
                        log_level: Some("info".to_string()),
                    };

                    // Use stdlib_import for the import, but logger setup goes after all imports
                    let finding = create_finding(
                        self.id(),
                        &unstructured,
                        *file_id,
                        &py.path,
                        py.import_insertion_line_for(ImportInsertionType::stdlib_import()),
                        py.import_insertion_line(),
                    );
                    findings.push(finding);
                }

                // Check for basic logging calls
                if callee.starts_with("logging.") || callee.starts_with("logger.") {
                    // Check if it's a logging method and extract the level
                    let log_level = if callee.ends_with(".debug") {
                        Some("debug")
                    } else if callee.ends_with(".info") {
                        Some("info")
                    } else if callee.ends_with(".warning") || callee.ends_with(".warn") {
                        Some("warning")
                    } else if callee.ends_with(".error") {
                        Some("error")
                    } else if callee.ends_with(".critical") {
                        Some("critical")
                    } else if callee.ends_with(".exception") {
                        Some("exception")
                    } else {
                        None
                    };

                    if let Some(level) = log_level {
                        let unstructured = UnstructuredLoggingCall {
                            function_name: callee.clone(),
                            line: call.function_call.location.line,
                            column: call.function_call.location.column,
                            issue_type: LoggingIssueType::BasicLogging,
                            start_byte: call.start_byte,
                            end_byte: call.end_byte,
                            args_repr: call.args_repr.clone(),
                            imports: py.imports.clone(),
                            log_level: Some(level.to_string()),
                        };

                        let finding = create_finding(
                            self.id(),
                            &unstructured,
                            *file_id,
                            &py.path,
                            py.import_insertion_line_for(ImportInsertionType::stdlib_import()),
                            py.import_insertion_line(),
                        );
                        findings.push(finding);
                    }
                }
            }
        }

        findings
    }
}

fn create_finding(
    rule_id: &str,
    unstructured: &UnstructuredLoggingCall,
    file_id: FileId,
    file_path: &str,
    import_line: u32,
    logger_setup_line: u32,
) -> RuleFinding {
    let title = format!("Unstructured logging: {}", unstructured.function_name);

    let description = format!(
        "{}. Structured logging enables better log aggregation, searching, \
         and analysis in production environments. Consider using structlog \
         or configuring JSON log formatting.",
        unstructured.issue_type.description()
    );

    let patch =
        generate_structured_logging_patch(unstructured, file_id, import_line, logger_setup_line);

    let fix_preview = match unstructured.issue_type {
        LoggingIssueType::PrintStatement => "# Replace print() with structured logging:\n\
             # import structlog\n\
             # logger = structlog.get_logger()\n\
             # logger.info(\"message\", key=\"value\")"
            .to_string(),
        LoggingIssueType::BasicLogging => {
            // Show a concrete example of the transformation
            let level = unstructured.log_level.as_deref().unwrap_or("info");
            format!(
                "# Rewrite with structlog keyword arguments:\n\
                 # Before: logger.{}(f\"Message {{var}}\")\n\
                 # After:  logger.{}(\"message\", var=var)",
                level, level
            )
        }
    };

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::AntiPattern,
        severity: unstructured.issue_type.severity(),
        confidence: 0.85,
        dimension: Dimension::Observability,
        file_id,
        file_path: file_path.to_string(),
        line: Some(unstructured.line),
        column: Some(unstructured.column),
        end_line: None,
        end_column: None,
        byte_range: None,
        patch: Some(patch),
        fix_preview: Some(fix_preview),
        tags: vec![
            "python".into(),
            "logging".into(),
            "observability".into(),
            "structured-logging".into(),
        ],
    }
}

/// Check if logging is already imported
fn has_logging_import(imports: &[PyImport]) -> bool {
    imports
        .iter()
        .any(|imp| imp.module == "logging" || imp.names.iter().any(|n| n == "logging"))
}

/// Extract f-string interpolation expressions from a string.
/// Returns a list of (expression, suggested_key_name) pairs.
fn extract_fstring_expressions(args_repr: &str) -> Vec<(String, String)> {
    let mut expressions = Vec::new();
    let mut depth = 0;
    let mut current_expr = String::new();
    let mut in_expr = false;

    for c in args_repr.chars() {
        match c {
            '{' if !in_expr => {
                // Check if it's an escaped brace {{
                if depth == 0 {
                    in_expr = true;
                    current_expr.clear();
                }
                depth += 1;
            }
            '{' if in_expr => {
                // Nested brace (like in dict comprehension)
                depth += 1;
                current_expr.push(c);
            }
            '}' if in_expr => {
                depth -= 1;
                if depth == 0 {
                    // End of expression
                    in_expr = false;
                    let expr = current_expr.trim().to_string();
                    if !expr.is_empty() && !expr.starts_with('{') {
                        // Generate a sensible key name from the expression
                        let key = expression_to_key(&expr);
                        expressions.push((expr, key));
                    }
                    current_expr.clear();
                } else {
                    current_expr.push(c);
                }
            }
            _ if in_expr => {
                current_expr.push(c);
            }
            _ => {}
        }
    }

    expressions
}

/// Convert an expression like `r.status_code` to a key name like `status_code`
fn expression_to_key(expr: &str) -> String {
    // Handle format specifiers like {value:.2f}
    let expr = expr.split(':').next().unwrap_or(expr);
    let expr = expr.split('!').next().unwrap_or(expr); // Handle !r, !s, !a

    // If it's a simple attribute access like `r.status_code`, use the last part
    if let Some(dot_pos) = expr.rfind('.') {
        let last_part = &expr[dot_pos + 1..];
        // If the last part is a method call, use the method name without parens
        let key = last_part.split('(').next().unwrap_or(last_part);
        return snake_case(key);
    }

    // If it's a method call like `get_id()`, use the method name
    if let Some(paren_pos) = expr.find('(') {
        let method = &expr[..paren_pos];
        // Handle chained calls like `obj.get_id()`
        if let Some(dot_pos) = method.rfind('.') {
            return snake_case(&method[dot_pos + 1..]);
        }
        return snake_case(method);
    }

    // If it's a subscript like `data["key"]` or `data['key']`, extract the key
    if expr.contains('[') {
        if let Some(start) = expr.find('[') {
            let prefix = &expr[..start];
            // If there's a dot, use the part after the last dot
            if let Some(dot_pos) = prefix.rfind('.') {
                return snake_case(&prefix[dot_pos + 1..]);
            }
            return snake_case(prefix);
        }
    }

    // Simple variable name
    snake_case(expr)
}

/// Convert a string to snake_case
fn snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(c.to_ascii_lowercase());
        } else if c.is_alphanumeric() || c == '_' {
            result.push(c);
        }
    }
    result
}

/// Extract a clean message from a logging string by removing f-string interpolations
fn extract_static_message(args_repr: &str) -> String {
    // Try to extract the first string argument
    let args_content = args_repr.trim();
    let args_content = args_content.strip_prefix('(').unwrap_or(args_content);
    let args_content = args_content.strip_suffix(')').unwrap_or(args_content);

    // Find the message part (before any commas that aren't in strings)
    let message_part = extract_first_string_arg(args_content);

    // Remove f-string prefix if present
    let message = message_part.trim();
    let message = message.strip_prefix("f\"").unwrap_or(message);
    let message = message.strip_prefix("f'").unwrap_or(message);
    let message = message.strip_prefix('"').unwrap_or(message);
    let message = message.strip_prefix('\'').unwrap_or(message);
    let message = message.strip_suffix('"').unwrap_or(message);
    let message = message.strip_suffix('\'').unwrap_or(message);

    // Remove all {expression} parts and clean up the message
    let mut result = String::new();
    let mut in_expr = false;
    let mut depth = 0;

    for c in message.chars() {
        match c {
            '{' => {
                if depth == 0 && !in_expr {
                    in_expr = true;
                }
                depth += 1;
            }
            '}' => {
                depth -= 1;
                if depth == 0 {
                    in_expr = false;
                }
            }
            _ if !in_expr => {
                result.push(c);
            }
            _ => {}
        }
    }

    // Clean up multiple spaces (from removed interpolations) to single space
    let result = result.split_whitespace().collect::<Vec<_>>().join(" ");

    // Remove space before punctuation (e.g., " ." -> ".")
    let result = result
        .replace(" .", ".")
        .replace(" ,", ",")
        .replace(" :", ":")
        .replace(" ;", ";")
        .replace(" !", "!")
        .replace(" ?", "?");

    // Clean up the message
    let result = result.trim();
    // Remove trailing punctuation and whitespace that was before the interpolation
    let result = result.trim_end_matches(|c: char| {
        c == ':' || c == '=' || c == '>' || c == '-' || c.is_whitespace()
    });
    let result = result.trim();

    result.to_string()
}

/// Extract the first string argument from a function call arguments
fn extract_first_string_arg(args: &str) -> String {
    let args = args.trim();

    // Handle concatenated strings: "part1" "part2" or "part1" f"part2"
    let mut result = String::new();
    let mut in_string = false;
    let mut string_char = '"';
    let mut escape_next = false;

    for c in args.chars() {
        if escape_next {
            result.push(c);
            escape_next = false;
            continue;
        }

        match c {
            '\\' if in_string => {
                result.push(c);
                escape_next = true;
            }
            '"' | '\'' if !in_string => {
                in_string = true;
                string_char = c;
                result.push(c);
            }
            c if c == string_char && in_string => {
                in_string = false;
                result.push(c);
            }
            ',' if !in_string => {
                // End of first argument
                break;
            }
            'f' if !in_string => {
                // f-string prefix, add it
                result.push(c);
            }
            _ => {
                result.push(c);
            }
        }
    }

    result.trim().to_string()
}

fn generate_structured_logging_patch(
    unstructured: &UnstructuredLoggingCall,
    file_id: FileId,
    import_line: u32,
    logger_setup_line: u32,
) -> FilePatch {
    let mut hunks = Vec::new();

    match unstructured.issue_type {
        LoggingIssueType::PrintStatement => {
            // Only add logging import and logger setup if logging is not already imported
            if !has_logging_import(&unstructured.imports) {
                // Add the import statement at the proper import location (among stdlib imports)
                hunks.push(PatchHunk {
                    range: PatchRange::InsertBeforeLine { line: import_line },
                    replacement: "import logging  # Added by unfault\n".to_string(),
                });
                // Add the logger setup AFTER all imports (with a blank line for separation)
                hunks.push(PatchHunk {
                    range: PatchRange::InsertBeforeLine {
                        line: logger_setup_line,
                    },
                    replacement: "\nlogger = logging.getLogger(__name__)  # Added by unfault\n"
                        .to_string(),
                });
            }

            // Replace print(...) with logger.info(...) using byte positions
            let replacement = format!("logger.info({})", unstructured.args_repr);
            hunks.push(PatchHunk {
                range: PatchRange::ReplaceBytes {
                    start: unstructured.start_byte,
                    end: unstructured.end_byte,
                },
                replacement,
            });
        }
        LoggingIssueType::BasicLogging => {
            // Extract f-string expressions and generate structlog-style call
            let expressions = extract_fstring_expressions(&unstructured.args_repr);
            let level = unstructured.log_level.as_deref().unwrap_or("info");

            if expressions.is_empty() {
                // No f-string interpolations found - check for % or .format() style
                // For now, just add a helpful comment showing the pattern
                let static_msg = extract_static_message(&unstructured.args_repr);
                let replacement = format!(
                    "logger.{}(\"{}\")  # structlog: use keyword args like logger.{}(\"{}\", key=value)",
                    level, static_msg, level, static_msg
                );
                hunks.push(PatchHunk {
                    range: PatchRange::ReplaceBytes {
                        start: unstructured.start_byte,
                        end: unstructured.end_byte,
                    },
                    replacement,
                });
            } else {
                // Generate structlog-style call with keyword arguments
                let static_msg = extract_static_message(&unstructured.args_repr);

                let kwargs: Vec<String> = expressions
                    .iter()
                    .map(|(expr, key)| format!("{}={}", key, expr))
                    .collect();

                let replacement = format!(
                    "logger.{}(\"{}\", {})",
                    level,
                    static_msg,
                    kwargs.join(", ")
                );

                hunks.push(PatchHunk {
                    range: PatchRange::ReplaceBytes {
                        start: unstructured.start_byte,
                        end: unstructured.end_byte,
                    },
                    replacement,
                });
            }
        }
    }

    FilePatch { file_id, hunks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    // ==================== Helper Functions ====================

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let sem = PyFileSemantics::from_parsed(&parsed);
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    // ==================== Rule Metadata Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonMissingStructuredLoggingRule::new();
        assert_eq!(rule.id(), "python.missing_structured_logging");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonMissingStructuredLoggingRule::new();
        assert!(rule.name().contains("logging"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonMissingStructuredLoggingRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonMissingStructuredLoggingRule::default();
        assert_eq!(rule.id(), "python.missing_structured_logging");
    }

    // ==================== LoggingIssueType Tests ====================

    #[test]
    fn issue_type_descriptions_are_meaningful() {
        assert!(
            LoggingIssueType::PrintStatement
                .description()
                .contains("print")
        );
        assert!(
            LoggingIssueType::BasicLogging
                .description()
                .contains("structured")
        );
    }

    #[test]
    fn issue_type_severities_are_correct() {
        assert!(matches!(
            LoggingIssueType::PrintStatement.severity(),
            Severity::Medium
        ));
        assert!(matches!(
            LoggingIssueType::BasicLogging.severity(),
            Severity::Low
        ));
    }

    // ==================== evaluate Tests - Detects Issues ====================

    #[tokio::test]
    async fn evaluate_detects_print_statement() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let src = r#"
def handler():
    print("Processing request")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());
        assert!(findings[0].title.contains("print"));
    }

    #[tokio::test]
    async fn evaluate_detects_basic_logging() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let src = r#"
import logging

logger = logging.getLogger(__name__)

def handler():
    logger.info("Processing request")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());
    }

    // ==================== evaluate Tests - No Findings ====================

    #[tokio::test]
    async fn evaluate_ignores_when_structlog_imported() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let src = r#"
import structlog

logger = structlog.get_logger()

def handler():
    print("Debug info")  # Should be ignored when structlog is present
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_when_custom_logging_module_with_get_logger() {
        let rule = PythonMissingStructuredLoggingRule::new();
        // Simulate importing get_logger from a custom logging module
        // This pattern is common when structlog is configured in a separate module
        let src = r#"
from ..logging import get_logger

logger = get_logger(__name__)

def handler():
    logger.info("Processing request")  # Should NOT trigger - using custom structured logger
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "Should not flag logger.info when get_logger is imported from custom .logging module"
        );
    }

    #[tokio::test]
    async fn evaluate_ignores_when_app_logging_module_with_get_logger() {
        let rule = PythonMissingStructuredLoggingRule::new();
        // Test absolute import pattern: from app.logging import get_logger
        let src = r#"
from myapp.logging import get_logger

logger = get_logger(__name__)

def handler():
    logger.info("Processing request")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "Should not flag logger.info when get_logger is imported from app.logging module"
        );
    }

    // ==================== Cross-File Analysis Tests ====================

    fn parse_multiple_files(sources: &[(&str, &str)]) -> Vec<(FileId, Arc<SourceSemantics>)> {
        sources
            .iter()
            .enumerate()
            .map(|(i, (path, content))| {
                let sf = SourceFile {
                    path: path.to_string(),
                    language: Language::Python,
                    content: content.to_string(),
                };
                let file_id = FileId(i as u64 + 1);
                let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
                let sem = PyFileSemantics::from_parsed(&parsed);
                (file_id, Arc::new(SourceSemantics::Python(sem)))
            })
            .collect()
    }

    #[tokio::test]
    async fn evaluate_ignores_when_structlog_in_separate_logging_module() {
        // This simulates the real-world scenario from the unfault API:
        // - unfault/logging.py imports structlog and provides get_logger()
        // - unfault/routers/lsp.py uses get_logger() from that module
        //
        // When analyzing both files together, since logging.py has structlog,
        // we should NOT flag lsp.py for using logger.info()
        let rule = PythonMissingStructuredLoggingRule::new();

        let sources = vec![
            (
                "unfault/logging.py",
                r#"
import structlog

def get_logger(name=None):
    return structlog.get_logger(name)
"#,
            ),
            (
                "unfault/routers/lsp.py",
                r#"
from ..logging import get_logger

logger = get_logger(__name__)

def handler():
    logger.info("Processing request")  # Should NOT trigger
"#,
            ),
        ];
        let semantics = parse_multiple_files(&sources);

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "Should not flag logger.info when structlog is configured in another file in the context. Found: {:?}",
            findings.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn evaluate_detects_when_no_structured_logging_in_context() {
        // When neither file has structlog, we SHOULD flag the logger.info call
        let rule = PythonMissingStructuredLoggingRule::new();

        let sources = vec![
            (
                "app/utils.py",
                r#"
def helper():
    pass
"#,
            ),
            (
                "app/main.py",
                r#"
import logging

logger = logging.getLogger(__name__)

def handler():
    logger.info("Processing request")  # SHOULD trigger - no structlog anywhere
"#,
            ),
        ];
        let semantics = parse_multiple_files(&sources);

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            !findings.is_empty(),
            "Should flag logger.info when no structured logging is found in the context"
        );
    }

    // ==================== Edge Cases ====================

    #[tokio::test]
    async fn evaluate_handles_empty_semantics() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_handles_empty_file() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    // ==================== Finding Properties Tests ====================

    #[tokio::test]
    async fn evaluate_finding_has_correct_properties() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let src = "print('hello')";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());

        let finding = &findings[0];
        assert_eq!(finding.rule_id, "python.missing_structured_logging");
        assert_eq!(finding.dimension, Dimension::Observability);
        assert!(finding.patch.is_some());
        assert!(finding.fix_preview.is_some());
        assert!(finding.tags.contains(&"logging".to_string()));
    }

    // ==================== F-String Parsing Tests ====================

    #[test]
    fn extract_fstring_expressions_simple_variable() {
        let result = extract_fstring_expressions(r#"(f"User {user_id} logged in")"#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "user_id");
        assert_eq!(result[0].1, "user_id");
    }

    #[test]
    fn extract_fstring_expressions_attribute_access() {
        let result = extract_fstring_expressions(r#"(f"Status: {r.status_code}")"#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "r.status_code");
        assert_eq!(result[0].1, "status_code");
    }

    #[test]
    fn extract_fstring_expressions_multiple() {
        let result = extract_fstring_expressions(
            r#"(f"Failed from env {e.id}: {r.status_code} => {r.text}")"#,
        );
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, "e.id");
        assert_eq!(result[0].1, "id");
        assert_eq!(result[1].0, "r.status_code");
        assert_eq!(result[1].1, "status_code");
        assert_eq!(result[2].0, "r.text");
        assert_eq!(result[2].1, "text");
    }

    #[test]
    fn extract_fstring_expressions_with_format_spec() {
        let result = extract_fstring_expressions(r#"(f"Value: {amount:.2f}")"#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "amount:.2f");
        assert_eq!(result[0].1, "amount");
    }

    #[test]
    fn extract_fstring_expressions_method_call() {
        let result = extract_fstring_expressions(r#"(f"ID: {obj.get_id()}")"#);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "obj.get_id()");
        assert_eq!(result[0].1, "get_id");
    }

    #[test]
    fn extract_fstring_expressions_no_fstring() {
        let result = extract_fstring_expressions(r#"("Static message")"#);
        assert!(result.is_empty());
    }

    // ==================== Expression to Key Tests ====================

    #[test]
    fn expression_to_key_simple_variable() {
        assert_eq!(expression_to_key("user_id"), "user_id");
    }

    #[test]
    fn expression_to_key_attribute_access() {
        assert_eq!(expression_to_key("response.status_code"), "status_code");
    }

    #[test]
    fn expression_to_key_nested_attribute() {
        assert_eq!(expression_to_key("request.user.id"), "id");
    }

    #[test]
    fn expression_to_key_method_call() {
        assert_eq!(expression_to_key("obj.get_name()"), "get_name");
    }

    #[test]
    fn expression_to_key_subscript() {
        assert_eq!(expression_to_key("data[\"key\"]"), "data");
    }

    #[test]
    fn expression_to_key_with_format_spec() {
        assert_eq!(expression_to_key("value:.2f"), "value");
    }

    #[test]
    fn expression_to_key_camel_case() {
        assert_eq!(expression_to_key("statusCode"), "status_code");
    }

    // ==================== Snake Case Tests ====================

    #[test]
    fn snake_case_simple() {
        assert_eq!(snake_case("simple"), "simple");
    }

    #[test]
    fn snake_case_camel() {
        assert_eq!(snake_case("camelCase"), "camel_case");
    }

    #[test]
    fn snake_case_pascal() {
        assert_eq!(snake_case("PascalCase"), "pascal_case");
    }

    #[test]
    fn snake_case_already_snake() {
        assert_eq!(snake_case("already_snake"), "already_snake");
    }

    #[test]
    fn snake_case_with_numbers() {
        assert_eq!(snake_case("value123"), "value123");
    }

    // ==================== Static Message Extraction Tests ====================

    #[test]
    fn extract_static_message_simple_fstring() {
        let result = extract_static_message(r#"(f"User {user_id} logged in")"#);
        assert_eq!(result, "User logged in");
    }

    #[test]
    fn extract_static_message_removes_trailing_colon() {
        let result = extract_static_message(r#"(f"Error: {error_msg}")"#);
        assert_eq!(result, "Error");
    }

    #[test]
    fn extract_static_message_regular_string() {
        let result = extract_static_message(r#"("Simple message")"#);
        assert_eq!(result, "Simple message");
    }

    #[test]
    fn extract_static_message_preserves_punctuation() {
        let result = extract_static_message(
            r#"(f"Failed to join organization {org_name}. It does not exist.")"#,
        );
        assert_eq!(result, "Failed to join organization. It does not exist.");
    }

    // ==================== Patch Generation Tests ====================

    #[tokio::test]
    async fn patch_for_basic_logging_with_fstring_generates_kwargs() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let src = r#"
import logging
logger = logging.getLogger(__name__)

def handler():
    logger.warning(f"Request failed with status {response.status_code}")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());

        let finding = &findings[0];
        let patch = finding.patch.as_ref().expect("Should have a patch");

        // The patch should generate a structlog-style call with kwargs
        assert!(!patch.hunks.is_empty());
        let replacement = &patch.hunks[0].replacement;

        // Should contain keyword argument style
        assert!(replacement.contains("logger.warning"));
        assert!(replacement.contains("status_code="));
    }

    #[tokio::test]
    async fn patch_for_basic_logging_preserves_level() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let src = r#"
import logging
logger = logging.getLogger(__name__)

def handler():
    logger.error(f"Failed: {error}")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());

        let finding = &findings[0];
        let patch = finding.patch.as_ref().expect("Should have a patch");

        // The patch should preserve the error level
        let replacement = &patch.hunks[0].replacement;
        assert!(replacement.contains("logger.error"));
    }

    #[tokio::test]
    async fn patch_for_basic_logging_without_fstring_adds_comment() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let src = r#"
import logging
logger = logging.getLogger(__name__)

def handler():
    logger.info("Processing request")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());

        let finding = &findings[0];
        let patch = finding.patch.as_ref().expect("Should have a patch");

        // The patch should add a helpful comment since no f-string was detected
        let replacement = &patch.hunks[0].replacement;
        assert!(replacement.contains("logger.info"));
        assert!(replacement.contains("structlog"));
    }

    #[tokio::test]
    async fn patch_extracts_multiple_variables() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let src = r#"
import logging
logger = logging.getLogger(__name__)

def handler():
    logger.warning(f"Failed from {env.id}: {r.status_code} => {r.text}")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());

        let finding = &findings[0];
        let patch = finding.patch.as_ref().expect("Should have a patch");
        let replacement = &patch.hunks[0].replacement;

        // Should extract all three variables as kwargs
        assert!(replacement.contains("id=env.id") || replacement.contains("id="));
        assert!(replacement.contains("status_code="));
        assert!(replacement.contains("text="));
    }

    // ==================== Fix Preview Tests ====================

    #[tokio::test]
    async fn fix_preview_shows_transformation_pattern() {
        let rule = PythonMissingStructuredLoggingRule::new();
        let src = r#"
import logging
logger = logging.getLogger(__name__)

def handler():
    logger.error(f"Error: {msg}")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty());

        let finding = &findings[0];
        let fix_preview = finding
            .fix_preview
            .as_ref()
            .expect("Should have fix_preview");

        // Fix preview should show the pattern for the detected log level
        assert!(fix_preview.contains("error"));
        assert!(fix_preview.contains("structlog"));
    }

    // ==================== Logger Placement Tests ====================

    #[tokio::test]
    async fn patch_places_logger_setup_after_all_imports() {
        // This test verifies the fix for the logger placement issue:
        // The logger = logging.getLogger(__name__) line should be placed
        // AFTER all imports, not right after the import logging statement.
        let rule = PythonMissingStructuredLoggingRule::new();
        let src = r#""""Sample module docstring."""

from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import stripe
import requests
from datetime import datetime

def handler():
    print("hello")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty(), "Should detect print statement");

        let finding = &findings[0];
        let patch = finding.patch.as_ref().expect("Should have a patch");

        // Should have 3 hunks: import logging, logger setup, and print replacement
        assert_eq!(
            patch.hunks.len(),
            3,
            "Expected 3 hunks for print replacement with logging import"
        );

        // First hunk should be the import statement (at stdlib position, near datetime)
        let import_hunk = &patch.hunks[0];
        assert!(
            import_hunk.replacement.contains("import logging"),
            "First hunk should be import logging"
        );

        // Second hunk should be the logger setup (AFTER all imports on line 10)
        let logger_setup_hunk = &patch.hunks[1];
        assert!(
            logger_setup_hunk
                .replacement
                .contains("logger = logging.getLogger"),
            "Second hunk should be logger setup: {:?}",
            logger_setup_hunk.replacement
        );

        // Verify the logger setup is inserted at a line AFTER the imports
        // The last import (datetime) is on line 9 (0-based: 8), so logger setup should be on line 10 or later
        match &logger_setup_hunk.range {
            PatchRange::InsertBeforeLine { line } => {
                // import_insertion_line() returns after last import, which is line 10 (1-based)
                // datetime is on 0-based line 8, so end_line + 2 = 10
                assert!(
                    *line >= 10,
                    "Logger setup should be after all imports (line >= 10), but got line {}",
                    line
                );
            }
            _ => panic!("Expected InsertBeforeLine for logger setup hunk"),
        }

        // Third hunk should be the print replacement
        let print_hunk = &patch.hunks[2];
        assert!(
            print_hunk.replacement.contains("logger.info"),
            "Third hunk should replace print: {:?}",
            print_hunk.replacement
        );
    }

    #[tokio::test]
    async fn patch_import_line_differs_from_logger_setup_line() {
        // This test verifies that import_line and logger_setup_line are different
        // when there are multiple imports in different categories
        let rule = PythonMissingStructuredLoggingRule::new();
        let src = r#"from fastapi import FastAPI
import requests
from datetime import datetime

def handler():
    print("hello")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty(), "Should detect print statement");

        let finding = &findings[0];
        let patch = finding.patch.as_ref().expect("Should have a patch");

        // Should have 3 hunks
        assert_eq!(patch.hunks.len(), 3);

        // Get the lines from the two insert hunks
        let import_line = match &patch.hunks[0].range {
            PatchRange::InsertBeforeLine { line } => *line,
            _ => panic!("Expected InsertBeforeLine for import hunk"),
        };

        let logger_setup_line = match &patch.hunks[1].range {
            PatchRange::InsertBeforeLine { line } => *line,
            _ => panic!("Expected InsertBeforeLine for logger setup hunk"),
        };

        // The import should be at line 1 (before fastapi, among stdlib)
        // The logger setup should be at line 4 or 5 (after all imports)
        assert!(
            import_line < logger_setup_line,
            "Import line ({}) should be before logger setup line ({})",
            import_line,
            logger_setup_line
        );

        // Logger setup should be AFTER all imports - the last import is datetime on line 3
        assert!(
            logger_setup_line >= 4,
            "Logger setup should be at line 4 or later, got {}",
            logger_setup_line
        );
    }
}
