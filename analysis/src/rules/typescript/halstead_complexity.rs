//! Halstead Complexity Metrics rule for TypeScript
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

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::typescript::model::TsFileSemantics;
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

/// Minimum function size to analyze
const MIN_OPERATORS: usize = 5;

/// Rule for detecting high Halstead complexity in TypeScript functions
#[derive(Debug)]
pub struct TypescriptHalsteadComplexityRule;

impl TypescriptHalsteadComplexityRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptHalsteadComplexityRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Halstead metrics computed for a function
#[derive(Debug, Clone)]
pub struct HalsteadMetrics {
    pub distinct_operators: usize,
    pub distinct_operands: usize,
    pub total_operators: usize,
    pub total_operands: usize,
    pub vocabulary: usize,
    pub program_length: usize,
    pub volume: f64,
    pub difficulty: f64,
    pub effort: f64,
    pub time_seconds: f64,
    pub estimated_bugs: f64,
}

impl HalsteadMetrics {
    pub fn compute(
        distinct_operators: usize,
        distinct_operands: usize,
        total_operators: usize,
        total_operands: usize,
    ) -> Self {
        let vocabulary = distinct_operators + distinct_operands;
        let program_length = total_operators + total_operands;

        let volume = if vocabulary > 0 {
            program_length as f64 * (vocabulary as f64).log2()
        } else {
            0.0
        };

        let difficulty = if distinct_operands > 0 {
            (distinct_operators as f64 / 2.0) * (total_operands as f64 / distinct_operands as f64)
        } else {
            0.0
        };

        let effort = difficulty * volume;
        let time_seconds = effort / 18.0;
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
            None
        }
    }
}

#[async_trait]
impl Rule for TypescriptHalsteadComplexityRule {
    fn id(&self) -> &'static str {
        "typescript.halstead_complexity"
    }

    fn name(&self) -> &'static str {
        "High Halstead complexity indicates code that is difficult to maintain"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let ts = match sem.as_ref() {
                SourceSemantics::Typescript(ts) => ts,
                #[allow(unreachable_patterns)]
                _ => continue,
            };

            if is_test_file(&ts.path) {
                continue;
            }

            for func in &ts.functions {
                let line_count = func.location.range.end_line
                    .saturating_sub(func.location.range.start_line) + 1;
                if line_count < 5 {
                    continue;
                }

                let metrics = estimate_halstead_from_function(func, ts);

                if let Some(severity) = metrics.severity() {
                    if metrics.total_operators >= MIN_OPERATORS {
                        findings.push(create_finding(
                            self.id(),
                            *file_id,
                            &ts.path,
                            &func.name,
                            func.location.range.start_line + 1,
                            &metrics,
                            severity,
                        ));
                    }
                }
            }

            // Analyze class methods
            for class in &ts.classes {
                for method in &class.methods {
                    let line_count = method.location.range.end_line
                        .saturating_sub(method.location.range.start_line) + 1;
                    if line_count < 5 {
                        continue;
                    }

                    let metrics = estimate_halstead_from_method(method, ts);

                    if let Some(severity) = metrics.severity() {
                        if metrics.total_operators >= MIN_OPERATORS {
                            let full_name = format!("{}.{}", class.name, method.name);
                            findings.push(create_finding(
                                self.id(),
                                *file_id,
                                &ts.path,
                                &full_name,
                                method.location.range.start_line + 1,
                                &metrics,
                                severity,
                            ));
                        }
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
    }
}

fn is_test_file(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let filename_lower = filename.to_lowercase();
    
    filename_lower.ends_with(".test.ts")
        || filename_lower.ends_with(".test.tsx")
        || filename_lower.ends_with(".spec.ts")
        || filename_lower.ends_with(".spec.tsx")
        || filename_lower.ends_with(".test.js")
        || filename_lower.ends_with(".spec.js")
        || path.contains("/__tests__/")
        || path.contains("/test/")
        || path.contains("/tests/")
}

fn estimate_halstead_from_function(
    func: &crate::semantics::typescript::model::TsFunction,
    _ts: &TsFileSemantics,
) -> HalsteadMetrics {
    let line_count = func.location.range.end_line
        .saturating_sub(func.location.range.start_line) + 1;
    
    // TypeScript/JavaScript tends to be verbose
    let estimated_operators_per_line = 2.5;
    let estimated_operands_per_line = 3.5;
    
    let total_operators = (line_count as f64 * estimated_operators_per_line) as usize;
    let total_operands = (line_count as f64 * estimated_operands_per_line) as usize;
    
    let distinct_operators = ((total_operators as f64).sqrt() * 1.5) as usize;
    let distinct_operands = ((total_operands as f64).sqrt() * 2.0) as usize;
    
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

fn estimate_halstead_from_method(
    method: &crate::semantics::typescript::model::TsMethod,
    _ts: &TsFileSemantics,
) -> HalsteadMetrics {
    let line_count = method.location.range.end_line
        .saturating_sub(method.location.range.start_line) + 1;
    
    let estimated_operators_per_line = 2.5;
    let estimated_operands_per_line = 3.5;
    
    let total_operators = (line_count as f64 * estimated_operators_per_line) as usize;
    let total_operands = (line_count as f64 * estimated_operands_per_line) as usize;
    
    let distinct_operators = ((total_operators as f64).sqrt() * 1.5) as usize;
    let distinct_operands = ((total_operands as f64).sqrt() * 2.0) as usize;
    
    let param_operands = method.params.len();
    let total_operands = total_operands + param_operands;
    let distinct_operands = distinct_operands + param_operands + 1; // +1 for this
    
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

    match kind {
        // Control flow operators
        "if_statement" | "switch_statement" | "for_statement" | "for_in_statement"
        | "for_of_statement" | "while_statement" | "do_statement" | "try_statement"
        | "throw_statement" | "return_statement" | "break_statement" | "continue_statement"
        | "function_declaration" | "function_expression" | "arrow_function"
        | "class_declaration" | "method_definition" | "async" | "await_expression" => {
            operators.insert(kind.to_string());
            *total_operators += 1;
        }

        // Binary operators
        "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "<<" | ">>" | ">>>"
        | "==" | "!=" | "===" | "!==" | "<" | ">" | "<=" | ">="
        | "&&" | "||" | "??" | "in" | "instanceof"
        | "binary_expression" => {
            let op_text = if text.len() < 5 { text.clone() } else { kind.to_string() };
            operators.insert(op_text);
            *total_operators += 1;
        }

        // Unary operators
        "!" | "-" | "~" | "typeof" | "void" | "delete"
        | "unary_expression" | "update_expression" => {
            operators.insert(kind.to_string());
            *total_operators += 1;
        }

        // Assignment operators
        "=" | "+=" | "-=" | "*=" | "/=" | "%=" | "&=" | "|=" | "^=" | "<<=" | ">>=" | ">>>="
        | "??=" | "&&=" | "||="
        | "assignment_expression" | "augmented_assignment_expression" => {
            operators.insert(kind.to_string());
            *total_operators += 1;
        }

        // Function calls
        "call_expression" => {
            operators.insert("()".to_string());
            *total_operators += 1;
        }

        // Member access
        "member_expression" => {
            operators.insert(".".to_string());
            *total_operators += 1;
        }

        // Subscript access
        "subscript_expression" => {
            operators.insert("[]".to_string());
            *total_operators += 1;
        }

        // Ternary operator
        "ternary_expression" | "conditional_expression" => {
            operators.insert("?:".to_string());
            *total_operators += 1;
        }

        // Optional chaining
        "optional_chain" => {
            operators.insert("?.".to_string());
            *total_operators += 1;
        }

        // Spread operator
        "spread_element" => {
            operators.insert("...".to_string());
            *total_operators += 1;
        }

        // Operands - identifiers
        "identifier" | "property_identifier" | "shorthand_property_identifier" => {
            operands.insert(text);
            *total_operands += 1;
        }

        // Operands - literals
        "number" | "float" => {
            operands.insert(text);
            *total_operands += 1;
        }

        "string" | "template_string" | "template_literal" => {
            operands.insert(format!("str:{}", text.len()));
            *total_operands += 1;
        }

        "true" | "false" => {
            operands.insert(text);
            *total_operands += 1;
        }

        "null" | "undefined" => {
            operands.insert(kind.to_string());
            *total_operands += 1;
        }

        "this" => {
            operands.insert("this".to_string());
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
         **Recommendations:**\n\
         1. Break the function into smaller, focused helper functions\n\
         2. Extract complex expressions into named intermediate variables\n\
         3. Use functional patterns (map, filter, reduce) to simplify logic\n\
         4. Consider extracting functionality into separate modules",
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
            "typescript".into(),
            "complexity".into(),
            "maintainability".into(),
            "halstead".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn halstead_metrics_compute_basic() {
        let metrics = HalsteadMetrics::compute(10, 15, 50, 80);
        assert_eq!(metrics.distinct_operators, 10);
        assert_eq!(metrics.distinct_operands, 15);
        assert_eq!(metrics.vocabulary, 25);
        assert_eq!(metrics.program_length, 130);
    }

    #[test]
    fn halstead_metrics_volume_formula() {
        let metrics = HalsteadMetrics::compute(4, 4, 10, 10);
        assert!((metrics.volume - 60.0).abs() < 0.1);
    }

    #[test]
    fn halstead_metrics_difficulty_formula() {
        let metrics = HalsteadMetrics::compute(10, 5, 50, 25);
        assert!((metrics.difficulty - 25.0).abs() < 0.1);
    }

    #[test]
    fn severity_high_for_very_complex() {
        let metrics = HalsteadMetrics::compute(30, 50, 200, 400);
        assert!(metrics.volume > VOLUME_THRESHOLD_HIGH);
        assert_eq!(metrics.severity(), Some(Severity::High));
    }

    #[test]
    fn severity_none_for_simple_functions() {
        let metrics = HalsteadMetrics::compute(5, 10, 15, 25);
        assert!(metrics.volume < VOLUME_THRESHOLD_MEDIUM);
        assert_eq!(metrics.severity(), None);
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = TypescriptHalsteadComplexityRule::new();
        assert_eq!(rule.id(), "typescript.halstead_complexity");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = TypescriptHalsteadComplexityRule::new();
        assert!(rule.name().contains("Halstead"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = TypescriptHalsteadComplexityRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("TypescriptHalsteadComplexityRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = TypescriptHalsteadComplexityRule::default();
        assert_eq!(rule.id(), "typescript.halstead_complexity");
    }

    #[test]
    fn is_test_file_detects_test_patterns() {
        assert!(is_test_file("handler.test.ts"));
        assert!(is_test_file("handler.spec.ts"));
        assert!(is_test_file("project/__tests__/handler.ts"));
    }

    #[test]
    fn is_test_file_allows_regular_files() {
        assert!(!is_test_file("handler.ts"));
        assert!(!is_test_file("src/router.ts"));
        assert!(!is_test_file("testing-utils.ts"));
    }

    #[test]
    fn compute_halstead_from_ast_counts_operators() {
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()).unwrap();
        
        let source = "const x = 1 + 2;";
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();
        
        let metrics = compute_halstead_from_ast(&root, source);
        assert!(metrics.distinct_operators >= 1);
        assert!(metrics.distinct_operands >= 2);
    }

    #[test]
    fn finding_has_correct_dimension() {
        let metrics = HalsteadMetrics::compute(20, 30, 100, 150);
        let finding = create_finding(
            "typescript.halstead_complexity",
            FileId(1),
            "test.ts",
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
            "typescript.halstead_complexity",
            FileId(1),
            "test.ts",
            "func",
            1,
            &metrics,
            Severity::Medium,
        );
        assert!(finding.tags.contains(&"halstead".to_string()));
        assert!(finding.tags.contains(&"typescript".to_string()));
    }

    #[tokio::test]
    async fn rule_returns_empty_for_empty_semantics() {
        let rule = TypescriptHalsteadComplexityRule::new();
        let findings = rule.evaluate(&[], None).await;
        assert!(findings.is_empty());
    }
}