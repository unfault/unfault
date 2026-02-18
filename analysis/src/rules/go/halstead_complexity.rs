//! Halstead Complexity Metrics rule for Go
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

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::go::model::GoFileSemantics;
use crate::semantics::SourceSemantics;
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

/// Rule for detecting high Halstead complexity in Go functions
#[derive(Debug)]
pub struct GoHalsteadComplexityRule;

impl GoHalsteadComplexityRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GoHalsteadComplexityRule {
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

#[async_trait]
impl Rule for GoHalsteadComplexityRule {
    fn id(&self) -> &'static str {
        "go.halstead_complexity"
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
            let go = match sem.as_ref() {
                SourceSemantics::Go(go) => go,
                #[allow(unreachable_patterns)]
                _ => continue,
            };

            // Skip test files
            if is_test_file(&go.path) {
                continue;
            }

            // Analyze functions
            for func in &go.functions {
                let line_count = func.location.range.end_line
                    .saturating_sub(func.location.range.start_line) + 1;
                if line_count < 5 {
                    continue;
                }

                let metrics = estimate_halstead_from_function(func, go);

                if let Some(severity) = metrics.severity() {
                    if metrics.total_operators >= MIN_OPERATORS {
                        findings.push(create_finding(
                            self.id(),
                            *file_id,
                            &go.path,
                            &func.name,
                            func.location.range.start_line + 1,
                            &metrics,
                            severity,
                        ));
                    }
                }
            }

            // Analyze methods
            for method in &go.methods {
                let line_count = method.location.range.end_line
                    .saturating_sub(method.location.range.start_line) + 1;
                if line_count < 5 {
                    continue;
                }

                let metrics = estimate_halstead_from_method(method, go);

                if let Some(severity) = metrics.severity() {
                    if metrics.total_operators >= MIN_OPERATORS {
                        let full_name = format!("{}.{}", method.receiver_type, method.name);
                        findings.push(create_finding(
                            self.id(),
                            *file_id,
                            &go.path,
                            &full_name,
                            method.location.range.start_line + 1,
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
    filename.ends_with("_test.go")
        || path.contains("/testdata/")
        || path.contains("/test/")
}

/// Estimate Halstead metrics from function metadata.
fn estimate_halstead_from_function(
    func: &crate::semantics::go::model::GoFunction,
    _go: &GoFileSemantics,
) -> HalsteadMetrics {
    let line_count = func.location.range.end_line
        .saturating_sub(func.location.range.start_line) + 1;
    
    // Heuristic estimation based on function size
    // Go tends to be more verbose than Python
    let estimated_operators_per_line = 3.0;
    let estimated_operands_per_line = 4.0;
    
    let total_operators = (line_count as f64 * estimated_operators_per_line) as usize;
    let total_operands = (line_count as f64 * estimated_operands_per_line) as usize;
    
    let distinct_operators = ((total_operators as f64).sqrt() * 1.5) as usize;
    let distinct_operands = ((total_operands as f64).sqrt() * 2.0) as usize;
    
    // Add contributions from parameters
    let param_operands = func.params.len();
    let total_operands = total_operands + param_operands;
    let distinct_operands = distinct_operands + param_operands;
    
    // Add contributions from return types
    let return_operands = func.return_types.len();
    let distinct_operands = distinct_operands + return_operands;
    
    HalsteadMetrics::compute(
        distinct_operators.max(1),
        distinct_operands.max(1),
        total_operators.max(1),
        total_operands.max(1),
    )
}

/// Estimate Halstead metrics from method metadata.
fn estimate_halstead_from_method(
    method: &crate::semantics::go::model::GoMethod,
    _go: &GoFileSemantics,
) -> HalsteadMetrics {
    let line_count = method.location.range.end_line
        .saturating_sub(method.location.range.start_line) + 1;
    
    let estimated_operators_per_line = 3.0;
    let estimated_operands_per_line = 4.0;
    
    let total_operators = (line_count as f64 * estimated_operators_per_line) as usize;
    let total_operands = (line_count as f64 * estimated_operands_per_line) as usize;
    
    let distinct_operators = ((total_operators as f64).sqrt() * 1.5) as usize;
    let distinct_operands = ((total_operands as f64).sqrt() * 2.0) as usize;
    
    let param_operands = method.params.len();
    let total_operands = total_operands + param_operands;
    let distinct_operands = distinct_operands + param_operands;
    
    // Add receiver as an operand
    let distinct_operands = distinct_operands + 1;
    let return_operands = method.return_types.len();
    let distinct_operands = distinct_operands + return_operands;
    
    HalsteadMetrics::compute(
        distinct_operators.max(1),
        distinct_operands.max(1),
        total_operators.max(1),
        total_operands.max(1),
    )
}

/// Compute Halstead metrics by walking an AST node.
pub fn compute_halstead_from_ast(
    node: &tree_sitter::Node,
    source: &str,
) -> HalsteadMetrics {
    let mut operators: HashSet<String> = HashSet::new();
    let mut operands: HashSet<String> = HashSet::new();
    let mut total_operators = 0usize;
    let mut total_operands = 0usize;

    walk_ast_for_halstead(node, source, &mut operators, &mut operands, &mut total_operators, &mut total_operands);

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

    #[allow(unreachable_patterns)]
    match kind {
        // Control flow operators
        "if_statement" | "for_statement" | "switch_statement" | "select_statement"
        | "return_statement" | "go_statement" | "defer_statement" | "break_statement"
        | "continue_statement" | "goto_statement" | "fallthrough_statement"
        | "function_declaration" | "method_declaration" | "type_declaration" => {
            operators.insert(kind.to_string());
            *total_operators += 1;
        }

        // Binary operators
        "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "<<" | ">>"
        | "==" | "!=" | "<" | ">" | "<=" | ">="
        | "&&" | "||" | "&^"
        | "binary_expression" => {
            let op_text = if text.len() < 5 { text.clone() } else { kind.to_string() };
            operators.insert(op_text);
            *total_operators += 1;
        }

        // Unary operators
        "!" | "^" | "-" | "*" | "&" | "<-"
        | "unary_expression" => {
            operators.insert(kind.to_string());
            *total_operators += 1;
        }

        // Assignment operators
        "=" | ":=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>=" | "&^="
        | "assignment_statement" | "short_var_declaration" => {
            operators.insert(kind.to_string());
            *total_operators += 1;
        }

        // Function calls
        "call_expression" => {
            operators.insert("()".to_string());
            *total_operators += 1;
        }

        // Field/selector access
        "selector_expression" => {
            operators.insert(".".to_string());
            *total_operators += 1;
        }

        // Index access
        "index_expression" => {
            operators.insert("[]".to_string());
            *total_operators += 1;
        }

        // Slice expression
        "slice_expression" => {
            operators.insert("[:]".to_string());
            *total_operators += 1;
        }

        // Type assertion
        "type_assertion_expression" => {
            operators.insert(".(type)".to_string());
            *total_operators += 1;
        }

        // Operands - identifiers
        "identifier" | "field_identifier" | "package_identifier" => {
            operands.insert(text);
            *total_operands += 1;
        }

        // Operands - literals
        "int_literal" | "float_literal" | "imaginary_literal" => {
            operands.insert(text);
            *total_operands += 1;
        }

        "interpreted_string_literal" | "raw_string_literal" | "rune_literal" => {
            operands.insert(format!("str:{}", text.len()));
            *total_operands += 1;
        }

        "true" | "false" => {
            operands.insert(text);
            *total_operands += 1;
        }

        "nil" => {
            operands.insert("nil".to_string());
            *total_operands += 1;
        }

        _ => {}
    }

    // Recurse into children
    let child_count = node.child_count();
    for i in 0..child_count {
        if let Some(child) = node.child(i) {
            walk_ast_for_halstead(&child, source, operators, operands, total_operators, total_operands);
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
        confidence: 0.8,
        dimension: Dimension::Maintainability,
        file_id,
        file_path: file_path.to_string(),
        line: Some(line),
        column: Some(1),
        end_line: None,
        end_column: None,
            byte_range: None,
        patch: None,
        fix_preview: None,
        tags: vec![
            "go".into(),
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
        let metrics = HalsteadMetrics::compute(4, 4, 10, 10);
        // η = 8, N = 20, V = 20 × log₂(8) = 20 × 3 = 60
        assert!((metrics.volume - 60.0).abs() < 0.1);
    }

    #[test]
    fn halstead_metrics_difficulty_formula() {
        let metrics = HalsteadMetrics::compute(10, 5, 50, 25);
        // D = (10/2) × (25/5) = 5 × 5 = 25
        assert!((metrics.difficulty - 25.0).abs() < 0.1);
    }

    #[test]
    fn halstead_metrics_handles_zero_operands() {
        let metrics = HalsteadMetrics::compute(5, 0, 10, 0);
        assert_eq!(metrics.difficulty, 0.0);
    }

    #[test]
    fn severity_high_for_very_complex() {
        let metrics = HalsteadMetrics::compute(30, 50, 200, 400);
        assert!(metrics.volume > VOLUME_THRESHOLD_HIGH);
        assert_eq!(metrics.severity(), Some(Severity::High));
    }

    #[test]
    fn severity_medium_for_moderately_complex() {
        let metrics = HalsteadMetrics {
            distinct_operators: 15,
            distinct_operands: 20,
            total_operators: 80,
            total_operands: 120,
            vocabulary: 35,
            program_length: 200,
            volume: 1200.0,
            difficulty: 25.0,
            effort: 30000.0,
            time_seconds: 1666.0,
            estimated_bugs: 0.4,
        };
        assert_eq!(metrics.severity(), Some(Severity::Medium));
    }

    #[test]
    fn severity_none_for_simple_functions() {
        let metrics = HalsteadMetrics::compute(5, 10, 15, 25);
        assert!(metrics.volume < VOLUME_THRESHOLD_MEDIUM);
        assert_eq!(metrics.severity(), None);
    }

    // ==================== Rule Tests ====================

    #[test]
    fn rule_id_is_correct() {
        let rule = GoHalsteadComplexityRule::new();
        assert_eq!(rule.id(), "go.halstead_complexity");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = GoHalsteadComplexityRule::new();
        assert!(rule.name().contains("Halstead"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = GoHalsteadComplexityRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("GoHalsteadComplexityRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = GoHalsteadComplexityRule::default();
        assert_eq!(rule.id(), "go.halstead_complexity");
    }

    // ==================== Test File Detection ====================

    #[test]
    fn is_test_file_detects_test_suffix() {
        assert!(is_test_file("handler_test.go"));
        assert!(is_test_file("src/handler_test.go"));
    }

    #[test]
    fn is_test_file_detects_testdata() {
        assert!(is_test_file("project/testdata/fixture.go"));
    }

    #[test]
    fn is_test_file_detects_test_directory() {
        assert!(is_test_file("project/test/helper.go"));
    }

    #[test]
    fn is_test_file_allows_regular_files() {
        assert!(!is_test_file("handler.go"));
        assert!(!is_test_file("src/router.go"));
        assert!(!is_test_file("testing.go"));
    }

    // ==================== AST Walking Tests ====================

    #[test]
    fn compute_halstead_from_ast_counts_operators() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&tree_sitter_go::LANGUAGE.into()).unwrap();
        
        let source = "package main\nfunc main() { x := 1 + 2 }";
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        
        let metrics = compute_halstead_from_ast(&root, source);
        
        // Should have operators: :=, +, func declaration
        assert!(metrics.distinct_operators >= 2);
        // Should have operands: x, 1, 2, main
        assert!(metrics.distinct_operands >= 3);
    }

    #[test]
    fn compute_halstead_from_ast_handles_function() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&tree_sitter_go::LANGUAGE.into()).unwrap();
        
        let source = r#"
package main

func add(a, b int) int {
    return a + b
}
"#;
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        
        let metrics = compute_halstead_from_ast(&root, source);
        
        assert!(metrics.total_operators > 0);
        assert!(metrics.total_operands > 0);
        assert!(metrics.volume > 0.0);
    }

    #[test]
    fn compute_halstead_from_ast_complex_function() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&tree_sitter_go::LANGUAGE.into()).unwrap();
        
        let source = r#"
package main

func process(items []int, threshold int) []int {
    results := make([]int, 0)
    for _, item := range items {
        if item > threshold {
            value := item * 2 + 1
            results = append(results, value)
        } else {
            results = append(results, item)
        }
    }
    return results
}
"#;
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        
        let metrics = compute_halstead_from_ast(&root, source);
        
        assert!(metrics.vocabulary > 10);
        assert!(metrics.program_length > 20);
        assert!(metrics.volume > 50.0);
    }

    // ==================== Finding Tests ====================

    #[test]
    fn finding_has_correct_dimension() {
        let metrics = HalsteadMetrics::compute(20, 30, 100, 150);
        let finding = create_finding(
            "go.halstead_complexity",
            FileId(1),
            "test.go",
            "complexFunction",
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
            "go.halstead_complexity",
            FileId(1),
            "test.go",
            "func",
            1,
            &metrics,
            Severity::Medium,
        );
        
        assert!(finding.tags.contains(&"halstead".to_string()));
        assert!(finding.tags.contains(&"complexity".to_string()));
        assert!(finding.tags.contains(&"maintainability".to_string()));
        assert!(finding.tags.contains(&"go".to_string()));
    }

    #[test]
    fn finding_has_no_patch() {
        let metrics = HalsteadMetrics::compute(10, 15, 50, 80);
        let finding = create_finding(
            "go.halstead_complexity",
            FileId(1),
            "test.go",
            "func",
            1,
            &metrics,
            Severity::Medium,
        );
        
        // Complexity issues require human judgment to fix
        assert!(finding.patch.is_none());
    }

    #[tokio::test]
    async fn rule_returns_empty_for_empty_semantics() {
        let rule = GoHalsteadComplexityRule::new();
        let findings = rule.evaluate(&[], None).await;
        assert!(findings.is_empty());
    }
}