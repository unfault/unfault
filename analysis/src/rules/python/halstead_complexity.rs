//! Halstead Complexity Metrics rule for Python
//!
//! Computes Halstead software science metrics for each function:
//! - η₁ = number of distinct operators
//! - η₂ = number of distinct operands
//! - N₁ = total number of operators
//! - N₂ = total number of operands
//!
//! From these, we derive:
//! - Vocabulary: η = η₁ + η₂
//! - Program Length: N = N₁ + N₂
//! - Volume: V = N × log₂(η)
//! - Difficulty: D = (η₁/2) × (N₂/η₂)
//! - Effort: E = D × V
//! - Time to Program: T = E/18 seconds
//! - Estimated Bugs: B = V/3000
//!
//! ## Why it matters
//!
//! High Halstead complexity indicates:
//! - Code that is difficult to understand and maintain
//! - Higher likelihood of bugs
//! - Functions that should be refactored into smaller units
//!
//! ## Thresholds
//!
//! - Volume > 1000: High complexity, consider refactoring
//! - Difficulty > 30: Hard to understand
//! - Effort > 100000: Very high cognitive load
//! - Estimated Bugs > 0.5: Likely to contain defects

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::PyFileSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};

/// Thresholds for Halstead metrics
const VOLUME_THRESHOLD_HIGH: f64 = 1500.0;
const VOLUME_THRESHOLD_MEDIUM: f64 = 1000.0;
const DIFFICULTY_THRESHOLD_HIGH: f64 = 40.0;
const DIFFICULTY_THRESHOLD_MEDIUM: f64 = 30.0;
const BUGS_THRESHOLD_HIGH: f64 = 1.0;
const BUGS_THRESHOLD_MEDIUM: f64 = 0.5;

/// Minimum function size to analyze (avoid noise from tiny functions)
const MIN_OPERATORS: usize = 5;

/// Rule for detecting high Halstead complexity in Python functions
#[derive(Debug)]
pub struct PythonHalsteadComplexityRule;

impl PythonHalsteadComplexityRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonHalsteadComplexityRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Halstead metrics computed for a function
#[derive(Debug, Clone)]
pub struct HalsteadMetrics {
    /// η₁ - Number of distinct operators
    pub distinct_operators: usize,
    /// η₂ - Number of distinct operands  
    pub distinct_operands: usize,
    /// N₁ - Total number of operators
    pub total_operators: usize,
    /// N₂ - Total number of operands
    pub total_operands: usize,
    /// η = η₁ + η₂ - Vocabulary
    pub vocabulary: usize,
    /// N = N₁ + N₂ - Program length
    pub program_length: usize,
    /// V = N × log₂(η) - Volume
    pub volume: f64,
    /// D = (η₁/2) × (N₂/η₂) - Difficulty
    pub difficulty: f64,
    /// E = D × V - Effort
    pub effort: f64,
    /// T = E/18 - Time to program (seconds)
    pub time_seconds: f64,
    /// B = V/3000 - Estimated bugs
    pub estimated_bugs: f64,
}

impl HalsteadMetrics {
    /// Compute Halstead metrics from operator/operand counts
    pub fn compute(
        distinct_operators: usize,
        distinct_operands: usize,
        total_operators: usize,
        total_operands: usize,
    ) -> Self {
        let vocabulary = distinct_operators + distinct_operands;
        let program_length = total_operators + total_operands;

        // Volume = N × log₂(η)
        let volume = if vocabulary > 0 {
            program_length as f64 * (vocabulary as f64).log2()
        } else {
            0.0
        };

        // Difficulty = (η₁/2) × (N₂/η₂)
        let difficulty = if distinct_operands > 0 {
            (distinct_operators as f64 / 2.0) * (total_operands as f64 / distinct_operands as f64)
        } else {
            0.0
        };

        // Effort = D × V
        let effort = difficulty * volume;

        // Time = E/18 seconds
        let time_seconds = effort / 18.0;

        // Bugs = V/3000
        let estimated_bugs = volume / 3000.0;

        Self {
            distinct_operators,
            distinct_operands,
            total_operators,
            total_operands,
            vocabulary,
            program_length,
            volume,
            difficulty,
            effort,
            time_seconds,
            estimated_bugs,
        }
    }

    /// Determine severity based on metrics
    pub fn severity(&self) -> Option<Severity> {
        if self.volume > VOLUME_THRESHOLD_HIGH
            || self.difficulty > DIFFICULTY_THRESHOLD_HIGH
            || self.estimated_bugs > BUGS_THRESHOLD_HIGH
        {
            Some(Severity::High)
        } else if self.volume > VOLUME_THRESHOLD_MEDIUM
            || self.difficulty > DIFFICULTY_THRESHOLD_MEDIUM
            || self.estimated_bugs > BUGS_THRESHOLD_MEDIUM
        {
            Some(Severity::Medium)
        } else {
            None // Below thresholds, no finding
        }
    }
}

/// Python operators for Halstead counting
#[allow(dead_code)]
const PYTHON_OPERATORS: &[&str] = &[
    // Arithmetic
    "+", "-", "*", "/", "//", "%", "**", "@", // Comparison
    "==", "!=", "<", ">", "<=", ">=", // Assignment
    "=", "+=", "-=", "*=", "/=", "//=", "%=", "**=", "@=", "&=", "|=", "^=", ">>=", "<<=", ":=",
    // Bitwise
    "&", "|", "^", "~", "<<", ">>", // Logical (as node kinds)
    "and", "or", "not", // Membership/identity (as node kinds)
    "in", "is", // Structural
    "(", ")", "[", "]", "{", "}", ",", ":", ";", ".", "->",
];

/// Python keywords that count as operators
#[allow(dead_code)]
const PYTHON_KEYWORD_OPERATORS: &[&str] = &[
    "if", "elif", "else", "for", "while", "try", "except", "finally", "with", "return", "yield",
    "pass", "break", "continue", "raise", "assert", "def", "class", "lambda", "import", "from",
    "as", "global", "nonlocal", "del", "async", "await",
];

#[async_trait]
impl Rule for PythonHalsteadComplexityRule {
    fn id(&self) -> &'static str {
        "python.halstead_complexity"
    }

    fn name(&self) -> &'static str {
        "High Halstead complexity indicates code that is difficult to maintain"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(error_handling_in_handler())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                #[allow(unreachable_patterns)]
                _ => continue,
            };

            // Skip test files
            if is_test_file(&py.path) {
                continue;
            }

            // We need access to the parsed file to walk the AST
            // For now, we'll analyze based on function metadata
            // In a full implementation, we'd re-parse or cache the AST
            for func in &py.functions {
                // Skip small functions
                let line_count = func
                    .location
                    .range
                    .end_line
                    .saturating_sub(func.location.range.start_line)
                    + 1;
                if line_count < 5 {
                    continue;
                }

                // Estimate metrics based on function characteristics
                // This is a simplified approach - a full implementation would
                // walk the actual AST nodes
                let metrics = estimate_halstead_from_function(func, py);

                if let Some(severity) = metrics.severity() {
                    if metrics.total_operators >= MIN_OPERATORS {
                        findings.push(create_finding(
                            self.id(),
                            *file_id,
                            &py.path,
                            &func.name,
                            func.location.range.start_line + 1,
                            &metrics,
                            severity,
                        ));
                    }
                }
            }
        }

        findings
    }
}

/// Check if file is a test file (exclude from analysis)
fn is_test_file(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let filename_lower = filename.to_lowercase();

    filename_lower.starts_with("test_")
        || filename_lower.ends_with("_test.py")
        || filename_lower.ends_with("_tests.py")
        || filename_lower == "conftest.py"
        || path.contains("/tests/")
        || path.contains("/test/")
}

/// Estimate Halstead metrics from function metadata.
///
/// This is a heuristic approach based on:
/// - Parameter count
/// - Function line count
/// - Body hash (as a proxy for complexity)
///
/// A full implementation would walk the actual AST.
fn estimate_halstead_from_function(
    func: &crate::semantics::python::model::PyFunction,
    _py: &PyFileSemantics,
) -> HalsteadMetrics {
    let line_count = func
        .location
        .range
        .end_line
        .saturating_sub(func.location.range.start_line)
        + 1;

    // Heuristic estimation based on function size
    // Average Python line has ~2-3 operators and ~3-4 operands
    let estimated_operators_per_line = 2.5;
    let estimated_operands_per_line = 3.5;

    let total_operators = (line_count as f64 * estimated_operators_per_line) as usize;
    let total_operands = (line_count as f64 * estimated_operands_per_line) as usize;

    // Distinct operators/operands are typically much smaller
    // Typically distinct = sqrt(total) to 2*sqrt(total)
    let distinct_operators = ((total_operators as f64).sqrt() * 1.5) as usize;
    let distinct_operands = ((total_operands as f64).sqrt() * 2.0) as usize;

    // Add contributions from parameters
    let param_operands = func.params.len();
    let total_operands = total_operands + param_operands;
    let distinct_operands = distinct_operands + param_operands;

    HalsteadMetrics::compute(
        distinct_operators.max(1),
        distinct_operands.max(1),
        total_operators.max(1),
        total_operands.max(1),
    )
}

/// Compute Halstead metrics by walking an AST node.
///
/// This is the proper implementation that counts actual operators and operands.
pub fn compute_halstead_from_ast(node: &tree_sitter::Node, source: &str) -> HalsteadMetrics {
    let mut operators: HashSet<String> = HashSet::new();
    let mut operands: HashSet<String> = HashSet::new();
    let mut total_operators = 0usize;
    let mut total_operands = 0usize;

    walk_ast_for_halstead(
        node,
        source,
        &mut operators,
        &mut operands,
        &mut total_operators,
        &mut total_operands,
    );

    HalsteadMetrics::compute(
        operators.len().max(1),
        operands.len().max(1),
        total_operators.max(1),
        total_operands.max(1),
    )
}

/// Recursively walk AST to count operators and operands
fn walk_ast_for_halstead(
    node: &tree_sitter::Node,
    source: &str,
    operators: &mut HashSet<String>,
    operands: &mut HashSet<String>,
    total_operators: &mut usize,
    total_operands: &mut usize,
) {
    let kind = node.kind();
    let text = node_text(node, source);

    // Classify node as operator or operand
    match kind {
        // Operators (keywords and control flow)
        "if"
        | "elif"
        | "else"
        | "for"
        | "while"
        | "try"
        | "except"
        | "finally"
        | "with"
        | "return"
        | "yield"
        | "pass"
        | "break"
        | "continue"
        | "raise"
        | "assert"
        | "def"
        | "class"
        | "lambda"
        | "import"
        | "from"
        | "as"
        | "global"
        | "nonlocal"
        | "del"
        | "async"
        | "await"
        | "if_statement"
        | "for_statement"
        | "while_statement"
        | "try_statement"
        | "with_statement"
        | "return_statement"
        | "raise_statement"
        | "assert_statement"
        | "function_definition"
        | "class_definition"
        | "import_statement"
        | "import_from_statement" => {
            operators.insert(kind.to_string());
            *total_operators += 1;
        }

        // Binary operators
        "+"
        | "-"
        | "*"
        | "/"
        | "//"
        | "%"
        | "**"
        | "@"
        | "=="
        | "!="
        | "<"
        | ">"
        | "<="
        | ">="
        | "&"
        | "|"
        | "^"
        | "~"
        | "<<"
        | ">>"
        | "and"
        | "or"
        | "not"
        | "in"
        | "is"
        | "binary_operator"
        | "boolean_operator"
        | "comparison_operator"
        | "not_operator" => {
            let op_text = if text.len() < 10 {
                text.clone()
            } else {
                kind.to_string()
            };
            operators.insert(op_text);
            *total_operators += 1;
        }

        // Assignment operators
        "="
        | "+="
        | "-="
        | "*="
        | "/="
        | "//="
        | "%="
        | "**="
        | "@="
        | "&="
        | "|="
        | "^="
        | ">>="
        | "<<="
        | ":="
        | "assignment"
        | "augmented_assignment" => {
            let op_text = if text.len() < 5 {
                text.clone()
            } else {
                kind.to_string()
            };
            operators.insert(op_text);
            *total_operators += 1;
        }

        // Function calls are operators
        "call" => {
            operators.insert("()".to_string());
            *total_operators += 1;
        }

        // Attribute access is an operator
        "attribute" => {
            operators.insert(".".to_string());
            *total_operators += 1;
        }

        // Subscript access is an operator
        "subscript" => {
            operators.insert("[]".to_string());
            *total_operators += 1;
        }

        // Operands
        "identifier" => {
            operands.insert(text);
            *total_operands += 1;
        }

        "integer" | "float" | "complex" => {
            operands.insert(text);
            *total_operands += 1;
        }

        "string" | "concatenated_string" => {
            // Use a normalized form for strings
            operands.insert(format!("str:{}", text.len()));
            *total_operands += 1;
        }

        "true" | "false" => {
            operands.insert(text);
            *total_operands += 1;
        }

        "none" => {
            operands.insert("None".to_string());
            *total_operands += 1;
        }

        _ => {}
    }

    // Recurse into children
    let child_count = node.child_count();
    for i in 0..child_count {
        if let Some(child) = node.child(i) {
            walk_ast_for_halstead(
                &child,
                source,
                operators,
                operands,
                total_operators,
                total_operands,
            );
        }
    }
}

/// Extract text from a node
fn node_text(node: &tree_sitter::Node, source: &str) -> String {
    let start = node.start_byte();
    let end = node.end_byte();
    if end <= source.len() && start < end {
        source[start..end].to_string()
    } else {
        String::new()
    }
}

fn create_finding(
    rule_id: &str,
    file_id: FileId,
    file_path: &str,
    func_name: &str,
    line: u32,
    metrics: &HalsteadMetrics,
    severity: Severity,
) -> RuleFinding {
    let title = format!(
        "Function '{}' has high Halstead complexity (Volume: {:.0}, Difficulty: {:.1}, Est. Bugs: {:.2})",
        func_name, metrics.volume, metrics.difficulty, metrics.estimated_bugs
    );

    let description = format!(
        "High Halstead complexity detected in function `{func_name}()`:\n\n\
         **Primary Metrics:**\n\
         • Volume: {volume:.0} (threshold: {vol_thresh})\n\
         • Difficulty: {difficulty:.1} (threshold: {diff_thresh})\n\
         • Estimated Bugs: {bugs:.2} (threshold: {bugs_thresh})\n\n\
         **Detailed Metrics:**\n\
         • Distinct operators (η₁): {n1}\n\
         • Distinct operands (η₂): {n2}\n\
         • Total operators (N₁): {N1}\n\
         • Total operands (N₂): {N2}\n\
         • Vocabulary (η): {vocab}\n\
         • Program length (N): {length}\n\
         • Effort: {effort:.0}\n\
         • Estimated time to understand: {time:.0} seconds\n\n\
         **Why this matters:**\n\
         High Halstead complexity indicates code that is:\n\
         • Difficult to understand and review\n\
         • More likely to contain defects\n\
         • Harder to test thoroughly\n\
         • More expensive to maintain\n\n\
         **Recommendations:**\n\
         1. Break the function into smaller, focused helper functions\n\
         2. Extract complex expressions into named intermediate variables\n\
         3. Consider using design patterns to reduce complexity\n\
         4. Add comprehensive documentation for complex sections",
        func_name = func_name,
        volume = metrics.volume,
        vol_thresh = VOLUME_THRESHOLD_MEDIUM,
        difficulty = metrics.difficulty,
        diff_thresh = DIFFICULTY_THRESHOLD_MEDIUM,
        bugs = metrics.estimated_bugs,
        bugs_thresh = BUGS_THRESHOLD_MEDIUM,
        n1 = metrics.distinct_operators,
        n2 = metrics.distinct_operands,
        N1 = metrics.total_operators,
        N2 = metrics.total_operands,
        vocab = metrics.vocabulary,
        length = metrics.program_length,
        effort = metrics.effort,
        time = metrics.time_seconds,
    );

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::AntiPattern,
        severity,
        confidence: 0.8, // Heuristic-based estimation
        dimension: Dimension::Maintainability,
        file_id,
        file_path: file_path.to_string(),
        line: Some(line),
        column: Some(1),
        end_line: None,
        end_column: None,
        byte_range: None,
        // No auto-patch for complexity - requires human judgment
        patch: None,
        fix_preview: None,
        tags: vec![
            "python".into(),
            "complexity".into(),
            "maintainability".into(),
            "halstead".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== HalsteadMetrics Tests ====================

    #[test]
    fn halstead_metrics_compute_basic() {
        let metrics = HalsteadMetrics::compute(10, 15, 50, 80);

        assert_eq!(metrics.distinct_operators, 10);
        assert_eq!(metrics.distinct_operands, 15);
        assert_eq!(metrics.total_operators, 50);
        assert_eq!(metrics.total_operands, 80);
        assert_eq!(metrics.vocabulary, 25);
        assert_eq!(metrics.program_length, 130);
    }

    #[test]
    fn halstead_metrics_volume_formula() {
        // V = N × log₂(η)
        let metrics = HalsteadMetrics::compute(4, 4, 10, 10);
        // η = 8, N = 20
        // V = 20 × log₂(8) = 20 × 3 = 60
        assert!((metrics.volume - 60.0).abs() < 0.1);
    }

    #[test]
    fn halstead_metrics_difficulty_formula() {
        // D = (η₁/2) × (N₂/η₂)
        let metrics = HalsteadMetrics::compute(10, 5, 50, 25);
        // D = (10/2) × (25/5) = 5 × 5 = 25
        assert!((metrics.difficulty - 25.0).abs() < 0.1);
    }

    #[test]
    fn halstead_metrics_estimated_bugs() {
        // B = V/3000
        let metrics = HalsteadMetrics::compute(10, 15, 100, 150);
        let expected_bugs = metrics.volume / 3000.0;
        assert!((metrics.estimated_bugs - expected_bugs).abs() < 0.01);
    }

    #[test]
    fn halstead_metrics_handles_zero_operands() {
        let metrics = HalsteadMetrics::compute(5, 0, 10, 0);
        // Should not panic, difficulty should be 0
        assert_eq!(metrics.difficulty, 0.0);
    }

    #[test]
    fn halstead_metrics_handles_zero_vocabulary() {
        let metrics = HalsteadMetrics::compute(0, 0, 0, 0);
        // Should not panic
        assert_eq!(metrics.volume, 0.0);
    }

    #[test]
    fn severity_high_for_very_complex() {
        let metrics = HalsteadMetrics::compute(30, 50, 200, 400);
        // This should produce high volume
        assert!(metrics.volume > VOLUME_THRESHOLD_HIGH);
        assert_eq!(metrics.severity(), Some(Severity::High));
    }

    #[test]
    fn severity_medium_for_moderately_complex() {
        // Craft metrics that are medium but not high
        let metrics = HalsteadMetrics {
            distinct_operators: 15,
            distinct_operands: 20,
            total_operators: 80,
            total_operands: 120,
            vocabulary: 35,
            program_length: 200,
            volume: 1200.0,   // Above medium, below high
            difficulty: 25.0, // Below medium threshold
            effort: 30000.0,
            time_seconds: 1666.0,
            estimated_bugs: 0.4, // Below medium threshold
        };
        assert_eq!(metrics.severity(), Some(Severity::Medium));
    }

    #[test]
    fn severity_none_for_simple_functions() {
        let metrics = HalsteadMetrics::compute(5, 10, 15, 25);
        // Small function should have low metrics
        assert!(metrics.volume < VOLUME_THRESHOLD_MEDIUM);
        assert_eq!(metrics.severity(), None);
    }

    // ==================== Rule Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonHalsteadComplexityRule::new();
        assert_eq!(rule.id(), "python.halstead_complexity");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonHalsteadComplexityRule::new();
        assert!(rule.name().contains("Halstead"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonHalsteadComplexityRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonHalsteadComplexityRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonHalsteadComplexityRule::default();
        assert_eq!(rule.id(), "python.halstead_complexity");
    }

    // ==================== Test File Detection ====================

    #[test]
    fn is_test_file_detects_test_prefix() {
        assert!(is_test_file("test_module.py"));
        assert!(is_test_file("Test_module.py"));
        assert!(is_test_file("src/test_routers.py"));
    }

    #[test]
    fn is_test_file_detects_test_suffix() {
        assert!(is_test_file("module_test.py"));
        assert!(is_test_file("module_tests.py"));
    }

    #[test]
    fn is_test_file_detects_conftest() {
        assert!(is_test_file("conftest.py"));
        assert!(is_test_file("src/conftest.py"));
    }

    #[test]
    fn is_test_file_detects_tests_directory() {
        assert!(is_test_file("project/tests/module.py"));
        assert!(is_test_file("src/test/helper.py"));
    }

    #[test]
    fn is_test_file_allows_regular_files() {
        assert!(!is_test_file("module.py"));
        assert!(!is_test_file("src/router.py"));
        assert!(!is_test_file("testing_utils.py")); // 'testing' is not 'test_'
    }

    // ==================== AST Walking Tests ====================

    #[test]
    fn compute_halstead_from_ast_counts_operators() {
        // Create a simple Python parser to test
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();

        let source = "x = 1 + 2";
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        let metrics = compute_halstead_from_ast(&root, source);

        // Should have operators: =, +
        assert!(metrics.distinct_operators >= 2);
        // Should have operands: x, 1, 2
        assert!(metrics.distinct_operands >= 3);
    }

    #[test]
    fn compute_halstead_from_ast_handles_function() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();

        let source = r#"
def add(a, b):
    return a + b
"#;
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        let metrics = compute_halstead_from_ast(&root, source);

        // Should have multiple operators and operands
        assert!(metrics.total_operators > 0);
        assert!(metrics.total_operands > 0);
        assert!(metrics.volume > 0.0);
    }

    #[test]
    fn compute_halstead_from_ast_complex_function() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();

        let source = r#"
def process(items, threshold):
    results = []
    for item in items:
        if item > threshold:
            value = item * 2 + 1
            results.append(value)
        else:
            results.append(item)
    return results
"#;
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        let metrics = compute_halstead_from_ast(&root, source);

        // Complex function should have higher metrics
        assert!(metrics.vocabulary > 10);
        assert!(metrics.program_length > 20);
        assert!(metrics.volume > 50.0);
    }

    // ==================== Finding Creation Tests ====================

    #[test]
    fn finding_has_correct_dimension() {
        let metrics = HalsteadMetrics::compute(20, 30, 100, 150);
        let finding = create_finding(
            "python.halstead_complexity",
            FileId(1),
            "test.py",
            "complex_function",
            10,
            &metrics,
            Severity::High,
        );

        assert_eq!(finding.dimension, Dimension::Maintainability);
    }

    #[test]
    fn finding_has_correct_tags() {
        let metrics = HalsteadMetrics::compute(10, 15, 50, 80);
        let finding = create_finding(
            "python.halstead_complexity",
            FileId(1),
            "test.py",
            "func",
            1,
            &metrics,
            Severity::Medium,
        );

        assert!(finding.tags.contains(&"halstead".to_string()));
        assert!(finding.tags.contains(&"complexity".to_string()));
        assert!(finding.tags.contains(&"maintainability".to_string()));
    }

    #[test]
    fn finding_has_no_patch() {
        let metrics = HalsteadMetrics::compute(10, 15, 50, 80);
        let finding = create_finding(
            "python.halstead_complexity",
            FileId(1),
            "test.py",
            "func",
            1,
            &metrics,
            Severity::Medium,
        );

        // Complexity issues require human judgment to fix
        assert!(finding.patch.is_none());
    }

    #[test]
    fn finding_title_includes_metrics() {
        let metrics = HalsteadMetrics::compute(10, 15, 50, 80);
        let finding = create_finding(
            "python.halstead_complexity",
            FileId(1),
            "test.py",
            "my_function",
            1,
            &metrics,
            Severity::Medium,
        );

        assert!(finding.title.contains("my_function"));
        assert!(finding.title.contains("Volume"));
        assert!(finding.title.contains("Difficulty"));
    }

    #[tokio::test]
    async fn rule_returns_empty_for_empty_semantics() {
        let rule = PythonHalsteadComplexityRule::new();
        let findings = rule.evaluate(&[], None).await;
        assert!(findings.is_empty());
    }
}
