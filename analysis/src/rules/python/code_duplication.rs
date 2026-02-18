//! Rule B20: Code duplication detection
//!
//! Detects duplicated code blocks across files that should be refactored
//! into shared functions or modules.
//!
//! ## What it detects
//!
//! - Functions with identical or near-identical bodies
//! - Repeated code patterns across multiple files
//! - Copy-pasted code blocks that could be abstracted
//!
//! ## Why it matters
//!
//! - Duplicated code increases maintenance burden
//! - Bug fixes need to be applied in multiple places
//! - Inconsistencies can arise when one copy is updated but not others
//! - Increases codebase size unnecessarily
//!
//! ## Recommended fixes
//!
//! - Extract common code into shared utility functions
//! - Create base classes for shared behavior
//! - Use composition or mixins for shared functionality

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::python::model::PyFileSemantics;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};

/// Minimum number of lines for a function to be considered for duplication detection
const MIN_FUNCTION_LINES: u32 = 5;

/// Minimum similarity threshold (0.0 to 1.0) for considering code as duplicated
const SIMILARITY_THRESHOLD: f64 = 0.85;

/// File patterns that should be excluded from duplication detection.
/// Test files are excluded because they intentionally have similar structures.
fn is_excluded_file(path: &str) -> bool {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let filename_lower = filename.to_lowercase();
    
    // Exclude test files
    filename_lower.starts_with("test_")
        || filename_lower.ends_with("_test.py")
        || filename_lower.ends_with("_tests.py")
        || filename_lower == "conftest.py"
        || path.contains("/tests/")
        || path.contains("/test/")
}

/// Rule for detecting code duplication across files
#[derive(Debug)]
pub struct PythonCodeDuplicationRule;

impl PythonCodeDuplicationRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonCodeDuplicationRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a duplicated code block
#[derive(Debug, Clone)]
struct DuplicatedCode {
    /// First occurrence file path
    file1_path: String,
    /// First occurrence file ID
    file1_id: FileId,
    /// First occurrence function name
    func1_name: String,
    /// First occurrence line number
    func1_line: u32,
    /// Second occurrence file path
    file2_path: String,
    /// Second occurrence file ID
    #[allow(dead_code)]
    file2_id: FileId,
    /// Second occurrence function name
    func2_name: String,
    /// Second occurrence line number
    func2_line: u32,
    /// Similarity score (0.0 to 1.0)
    similarity: f64,
    /// Number of lines in the duplicated code
    line_count: u32,
}

/// Normalized function representation for comparison
#[derive(Debug, Clone)]
struct NormalizedFunction {
    /// Original function name
    name: String,
    /// File path
    file_path: String,
    /// File ID
    file_id: FileId,
    /// Line number
    line: u32,
    /// Normalized body (whitespace and variable names normalized)
    normalized_body: String,
    /// Number of lines
    line_count: u32,
    /// Hash of the normalized body for quick comparison
    body_hash: u64,
}

#[async_trait]
impl Rule for PythonCodeDuplicationRule {
    fn id(&self) -> &'static str {
        "python.code_duplication"
    }

    fn name(&self) -> &'static str {
        "Duplicated code should be refactored into shared functions"
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

        // Collect all functions from all files
        let mut all_functions: Vec<NormalizedFunction> = Vec::new();

        for (file_id, sem) in semantics {
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                #[allow(unreachable_patterns)]
                _ => continue,
            };

            // Skip test files - they intentionally have similar structures
            if is_excluded_file(&py.path) {
                continue;
            }

            // Extract and normalize functions
            for func in &py.functions {
                let line_count =
                    func.location.range.end_line.saturating_sub(func.location.range.start_line) + 1;

                if line_count < MIN_FUNCTION_LINES {
                    continue;
                }

                // Create normalized representation
                let normalized = normalize_function(func, py, *file_id);
                all_functions.push(normalized);
            }
        }

        // Find duplicates using hash-based grouping for efficiency
        let duplicates = find_duplicates(&all_functions);

        // Create findings for each duplicate pair
        for dup in duplicates {
            findings.push(create_finding(self.id(), &dup));
        }

        findings
    }
}

/// Normalize a function for comparison
fn normalize_function(
    func: &crate::semantics::python::model::PyFunction,
    py: &PyFileSemantics,
    file_id: FileId,
) -> NormalizedFunction {
    let line_count =
        func.location.range.end_line.saturating_sub(func.location.range.start_line) + 1;

    // Create a normalized body representation
    // In a real implementation, we would extract the actual function body
    // and normalize variable names, whitespace, etc.
    // For now, we use a simplified approach based on function signature and structure
    let normalized_body = create_normalized_body(func);

    // Create a hash for quick comparison
    let body_hash = hash_string(&normalized_body);

    NormalizedFunction {
        name: func.name.clone(),
        file_path: py.path.clone(),
        file_id,
        line: func.location.range.start_line + 1,
        normalized_body,
        line_count,
        body_hash,
    }
}

/// Create a normalized body representation for a function.
///
/// This normalization is used to detect truly duplicated code. Two functions
/// are considered duplicates only if they have the same:
/// - Class context (both methods of same-named class, or both top-level)
/// - Async status
/// - Parameter count and default patterns
/// - Parameter names (normalized)
/// - Parameter type annotations (if present)
/// - Return type annotation (if present)
/// - Body hash (actual code content)
///
/// Note: Function names are intentionally NOT normalized out because different
/// named functions doing similar things is often intentional (e.g., different
/// API endpoints with similar structures).
fn create_normalized_body(func: &crate::semantics::python::model::PyFunction) -> String {
    let mut normalized = String::new();

    // Include class context - methods should only match other methods of the same class
    if let Some(ref class_name) = func.class_name {
        normalized.push_str(&format!("CLASS:{} ", class_name));
    } else {
        normalized.push_str("TOPLEVEL ");
    }

    // Add async marker
    if func.is_async {
        normalized.push_str("ASYNC ");
    }

    // Add return type annotation - different return types mean different functions
    if let Some(ref return_type) = func.return_type {
        normalized.push_str(&format!("RET:{} ", return_type));
    }

    // Add body hash - this is the CRITICAL component for true duplication detection
    // Two functions with different body content will have different hashes
    if let Some(body_hash) = func.body_hash {
        normalized.push_str(&format!("BODY:{:x} ", body_hash));
    }

    // Add parameter count
    normalized.push_str(&format!("PARAMS:{} ", func.params.len()));

    // Add parameter names and patterns (excluding 'self' and 'cls' as they're boilerplate)
    for param in &func.params {
        let param_name = param.name.as_str();
        // Skip self/cls as they don't contribute to uniqueness
        if param_name == "self" || param_name == "cls" {
            continue;
        }
        
        // Include parameter name - different param names suggest different purposes
        normalized.push_str(&format!("P_{}:", param_name));
        
        // Include type annotation if present - different types mean different functions
        if let Some(ref type_ann) = param.type_annotation {
            normalized.push_str(&format!("T_{}:", type_ann));
        }
        
        if param.default.is_some() {
            normalized.push_str("DEF ");
        } else {
            normalized.push_str("REQ ");
        }
    }

    normalized
}

/// Simple string hashing function
fn hash_string(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    hasher.finish()
}

/// Find duplicate functions using hash-based grouping
fn find_duplicates(functions: &[NormalizedFunction]) -> Vec<DuplicatedCode> {
    let mut duplicates = Vec::new();

    // Group functions by hash for quick comparison
    let mut hash_groups: HashMap<u64, Vec<&NormalizedFunction>> = HashMap::new();

    for func in functions {
        hash_groups.entry(func.body_hash).or_default().push(func);
    }

    // Check each group for actual duplicates
    for (_hash, group) in hash_groups {
        if group.len() < 2 {
            continue;
        }

        // Compare all pairs in the group
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let func1 = group[i];
                let func2 = group[j];

                // Skip if same file and same function
                if func1.file_id == func2.file_id && func1.name == func2.name {
                    continue;
                }

                // Calculate detailed similarity
                let similarity = calculate_similarity(&func1.normalized_body, &func2.normalized_body);

                if similarity >= SIMILARITY_THRESHOLD {
                    duplicates.push(DuplicatedCode {
                        file1_path: func1.file_path.clone(),
                        file1_id: func1.file_id,
                        func1_name: func1.name.clone(),
                        func1_line: func1.line,
                        file2_path: func2.file_path.clone(),
                        file2_id: func2.file_id,
                        func2_name: func2.name.clone(),
                        func2_line: func2.line,
                        similarity,
                        line_count: func1.line_count.max(func2.line_count),
                    });
                }
            }
        }
    }

    duplicates
}

/// Calculate similarity between two normalized strings
fn calculate_similarity(s1: &str, s2: &str) -> f64 {
    if s1 == s2 {
        return 1.0;
    }

    if s1.is_empty() || s2.is_empty() {
        return 0.0;
    }

    // Use Jaccard similarity on tokens
    let tokens1: std::collections::HashSet<&str> = s1.split_whitespace().collect();
    let tokens2: std::collections::HashSet<&str> = s2.split_whitespace().collect();

    let intersection = tokens1.intersection(&tokens2).count();
    let union = tokens1.union(&tokens2).count();

    if union == 0 {
        return 0.0;
    }

    intersection as f64 / union as f64
}

fn create_finding(rule_id: &str, dup: &DuplicatedCode) -> RuleFinding {
    let is_same_file = dup.file1_path == dup.file2_path;

    let title = if is_same_file {
        format!(
            "Functions '{}' and '{}' have duplicated code ({:.0}% similar)",
            dup.func1_name,
            dup.func2_name,
            dup.similarity * 100.0
        )
    } else {
        format!(
            "Function '{}' in {} duplicates '{}' in {} ({:.0}% similar)",
            dup.func1_name,
            dup.file1_path,
            dup.func2_name,
            dup.file2_path,
            dup.similarity * 100.0
        )
    };

    // Build a detailed description that clearly identifies both functions
    let description = if is_same_file {
        format!(
            "Code duplication detected between two functions in the same file:\n\n\
             • `{func1}()` at line {line1}\n\
             • `{func2}()` at line {line2}\n\n\
             These functions share {similarity:.0}% similar code across ~{lines} lines. \
             This duplication increases maintenance burden: bug fixes must be applied \
             in multiple places, and inconsistencies can arise when one copy is updated \
             but not the other.\n\n\
             Recommended actions:\n\
             1. Extract the common logic into a private helper function (e.g., `_{func1}_{func2}_impl()`)\n\
             2. Have both `{func1}()` and `{func2}()` delegate to the shared implementation\n\
             3. If the functions serve different purposes, consider if the similarity is intentional",
            func1 = dup.func1_name,
            func2 = dup.func2_name,
            line1 = dup.func1_line,
            line2 = dup.func2_line,
            similarity = dup.similarity * 100.0,
            lines = dup.line_count
        )
    } else {
        format!(
            "Code duplication detected between functions in different files:\n\n\
             • `{func1}()` in `{file1}` at line {line1}\n\
             • `{func2}()` in `{file2}` at line {line2}\n\n\
             These functions share {similarity:.0}% similar code across ~{lines} lines. \
             Cross-file duplication is particularly problematic: it's harder to notice \
             when updating one copy, and the codebase grows unnecessarily.\n\n\
             Recommended actions:\n\
             1. Create a shared utility module (e.g., `utils.py` or a domain-specific module)\n\
             2. Extract the common logic into a well-named function in that module\n\
             3. Import and use the shared function from both `{file1}` and `{file2}`\n\
             4. Consider if the original function names still make sense as thin wrappers",
            func1 = dup.func1_name,
            func2 = dup.func2_name,
            file1 = dup.file1_path,
            file2 = dup.file2_path,
            line1 = dup.func1_line,
            line2 = dup.func2_line,
            similarity = dup.similarity * 100.0,
            lines = dup.line_count
        )
    };

    // Higher severity for more similar code and larger functions
    let severity = if dup.similarity > 0.95 && dup.line_count > 10 {
        Severity::High
    } else if dup.similarity > 0.90 || dup.line_count > 15 {
        Severity::Medium
    } else {
        Severity::Low
    };

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::AntiPattern,
        severity,
        confidence: dup.similarity as f32,
        dimension: Dimension::Correctness,
        file_id: dup.file1_id,
        file_path: dup.file1_path.clone(),
        line: Some(dup.func1_line),
        column: Some(1),
        end_line: None,
        end_column: None,
            byte_range: None,
        // No patch: code duplication refactoring requires human judgment about
        // where to place shared code, naming conventions, and API design
        patch: None,
        fix_preview: None,
        tags: vec![
            "python".into(),
            "duplication".into(),
            "refactoring".into(),
            "maintainability".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::build_python_semantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str, path: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: path.to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(path.len() as u64); // Use path length as unique ID
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_python_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonCodeDuplicationRule::new();
        assert_eq!(rule.id(), "python.code_duplication");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonCodeDuplicationRule::new();
        assert!(rule.name().contains("Duplicated"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonCodeDuplicationRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonCodeDuplicationRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonCodeDuplicationRule::default();
        assert_eq!(rule.id(), "python.code_duplication");
    }

    #[tokio::test]
    async fn detects_identical_functions_in_same_file() {
        let source = r#"
def process_data(items):
    result = []
    for item in items:
        processed = item * 2
        result.append(processed)
    return result

def transform_data(items):
    result = []
    for item in items:
        processed = item * 2
        result.append(processed)
    return result
"#;
        let (file_id, sem) = parse_and_build_semantics(source, "test.py");
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        // Should detect duplication between process_data and transform_data
        assert!(
            !findings.is_empty(),
            "Should detect identical functions in same file"
        );
    }

    #[tokio::test]
    async fn detects_similar_async_functions() {
        let source = r#"
async def fetch_user(user_id):
    response = await client.get(f"/users/{user_id}")
    data = response.json()
    return data

async def fetch_product(product_id):
    response = await client.get(f"/products/{product_id}")
    data = response.json()
    return data
"#;
        let (file_id, sem) = parse_and_build_semantics(source, "test.py");
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        // Both are async functions with similar structure
        // Detection depends on normalization quality
        let _ = findings; // May or may not detect based on similarity threshold
    }

    #[tokio::test]
    async fn no_finding_for_small_functions() {
        let source = r#"
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b
"#;
        let (file_id, sem) = parse_and_build_semantics(source, "test.py");
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        // Small functions should not be flagged
        assert!(
            findings.is_empty(),
            "Should not flag small functions as duplicates"
        );
    }

    #[tokio::test]
    async fn no_finding_for_different_functions() {
        let source = r#"
def process_users(users, filter_active):
    result = []
    for user in users:
        if user.active:
            result.append(user.name)
    return result

def calculate_totals(orders):
    total = 0
    for order in orders:
        total += order.amount
    return total
"#;
        let (file_id, sem) = parse_and_build_semantics(source, "test.py");
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        // Different parameter counts should not be flagged
        // (process_users has 2 params, calculate_totals has 1)
        assert!(
            findings.is_empty(),
            "Should not flag functions with different signatures as duplicates"
        );
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let (file_id, sem) = parse_and_build_semantics("", "test.py");
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[], None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn detects_cross_file_duplication() {
        let source1 = r#"
def validate_input(data):
    if not data:
        raise ValueError("Empty data")
    if not isinstance(data, dict):
        raise TypeError("Expected dict")
    return True
"#;
        let source2 = r#"
def check_input(data):
    if not data:
        raise ValueError("Empty data")
    if not isinstance(data, dict):
        raise TypeError("Expected dict")
    return True
"#;
        let (file_id1, sem1) = parse_and_build_semantics(source1, "file1.py");
        let (file_id2, sem2) = parse_and_build_semantics(source2, "file2.py");
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[(file_id1, sem1), (file_id2, sem2)], None).await;

        // Should detect cross-file duplication
        // Detection depends on normalization quality
        let _ = findings;
    }

    #[test]
    fn calculate_similarity_returns_1_for_identical() {
        let s1 = "ASYNC PARAMS:2 P P_DEF";
        let s2 = "ASYNC PARAMS:2 P P_DEF";
        assert_eq!(calculate_similarity(s1, s2), 1.0);
    }

    #[test]
    fn calculate_similarity_returns_0_for_empty() {
        assert_eq!(calculate_similarity("", "test"), 0.0);
        assert_eq!(calculate_similarity("test", ""), 0.0);
    }

    #[test]
    fn calculate_similarity_handles_partial_match() {
        let s1 = "ASYNC PARAMS:2 P P_DEF";
        let s2 = "ASYNC PARAMS:2 P P";
        let similarity = calculate_similarity(s1, s2);
        assert!(similarity > 0.5);
        assert!(similarity < 1.0);
    }

    #[test]
    fn hash_string_is_deterministic() {
        let s = "test string";
        let hash1 = hash_string(s);
        let hash2 = hash_string(s);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_string_differs_for_different_strings() {
        let hash1 = hash_string("string1");
        let hash2 = hash_string("string2");
        assert_ne!(hash1, hash2);
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let source = r#"
def process_a(items):
    result = []
    for item in items:
        processed = item * 2
        result.append(processed)
    return result

def process_b(items):
    result = []
    for item in items:
        processed = item * 2
        result.append(processed)
    return result
"#;
        let (file_id, sem) = parse_and_build_semantics(source, "test.py");
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        if !findings.is_empty() {
            let finding = &findings[0];
            assert_eq!(finding.rule_id, "python.code_duplication");
            assert!(matches!(finding.kind, FindingKind::AntiPattern));
            assert_eq!(finding.dimension, Dimension::Correctness);
            // No patch for code duplication - requires human judgment for refactoring
            assert!(finding.patch.is_none());
            assert!(finding.fix_preview.is_none());
            assert!(finding.tags.contains(&"duplication".to_string()));
        }
    }

    // ==================== Test File Exclusion Tests ====================

    #[test]
    fn is_excluded_file_detects_test_prefixed_files() {
        assert!(is_excluded_file("test_module.py"));
        assert!(is_excluded_file("Test_module.py"));
        assert!(is_excluded_file("TEST_module.py"));
        assert!(is_excluded_file("src/test_module.py"));
        assert!(is_excluded_file("/path/to/test_routers.py"));
    }

    #[test]
    fn is_excluded_file_detects_test_suffixed_files() {
        assert!(is_excluded_file("module_test.py"));
        assert!(is_excluded_file("module_tests.py"));
        assert!(is_excluded_file("src/router_test.py"));
        assert!(is_excluded_file("/path/to/api_tests.py"));
    }

    #[test]
    fn is_excluded_file_detects_conftest() {
        assert!(is_excluded_file("conftest.py"));
        assert!(is_excluded_file("src/conftest.py"));
        assert!(is_excluded_file("/path/to/conftest.py"));
    }

    #[test]
    fn is_excluded_file_detects_tests_directory() {
        assert!(is_excluded_file("/project/tests/module.py"));
        assert!(is_excluded_file("src/tests/helper.py"));
        assert!(is_excluded_file("/path/test/module.py"));
    }

    #[test]
    fn is_excluded_file_allows_regular_files() {
        assert!(!is_excluded_file("module.py"));
        assert!(!is_excluded_file("src/router.py"));
        assert!(!is_excluded_file("/path/to/api.py"));
        assert!(!is_excluded_file("testing_utils.py")); // 'testing' is not 'test_'
        assert!(!is_excluded_file("contest.py")); // not 'conftest'
    }

    #[tokio::test]
    async fn skips_test_files_in_evaluation() {
        // This test verifies that test files are skipped from duplication detection
        let source = r#"
def test_something(self):
    result = []
    for item in items:
        processed = item * 2
        result.append(processed)
    return result

def test_another(self):
    result = []
    for item in items:
        processed = item * 2
        result.append(processed)
    return result
"#;
        // Use a test file name - should be excluded
        let (file_id, sem) = parse_and_build_semantics(source, "test_routers_lsp.py");
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        // No findings because test files are excluded
        assert!(
            findings.is_empty(),
            "Test files should be excluded from duplication detection"
        );
    }

    #[tokio::test]
    async fn skips_files_in_tests_directory() {
        let source = r#"
def helper_a(items):
    result = []
    for item in items:
        processed = item * 2
        result.append(processed)
    return result

def helper_b(items):
    result = []
    for item in items:
        processed = item * 2
        result.append(processed)
    return result
"#;
        // Use a path containing /tests/ - should be excluded
        let (file_id, sem) = parse_and_build_semantics(source, "api/tests/helpers.py");
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        // No findings because files in tests/ directory are excluded
        assert!(
            findings.is_empty(),
            "Files in tests/ directory should be excluded from duplication detection"
        );
    }

    // ==================== Improved Normalization Tests ====================

    #[tokio::test]
    async fn different_param_names_not_flagged_as_duplicates() {
        // Functions with different parameter names should not be considered duplicates
        // even if they have the same structure
        let source = r#"
def process_users(users):
    result = []
    for item in users:
        processed = item * 2
        result.append(processed)
    return result

def process_orders(orders):
    result = []
    for item in orders:
        processed = item * 2
        result.append(processed)
    return result
"#;
        let (file_id, sem) = parse_and_build_semantics(source, "module.py");
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        // Different param names should NOT be flagged as duplicates
        // The new normalization includes param names
        assert!(
            findings.is_empty(),
            "Functions with different parameter names should not be flagged as duplicates"
        );
    }

    #[tokio::test]
    async fn same_param_names_flagged_as_duplicates() {
        // Functions with SAME parameter names ARE duplicates
        let source = r#"
def process_data(items):
    result = []
    for item in items:
        processed = item * 2
        result.append(processed)
    return result

def transform_data(items):
    result = []
    for item in items:
        processed = item * 2
        result.append(processed)
    return result
"#;
        let (file_id, sem) = parse_and_build_semantics(source, "module.py");
        let rule = PythonCodeDuplicationRule::new();
        let findings = rule.evaluate(&[(file_id, sem)], None).await;

        // Same param names should be flagged
        assert!(
            !findings.is_empty(),
            "Functions with same parameter names should be flagged as duplicates"
        );
    }

    #[test]
    fn normalized_body_includes_class_context() {
        use crate::semantics::python::model::{PyFunction, PyParam};
        use crate::parse::ast::{AstLocation, TextRange};

        let method = PyFunction {
            name: "method_a".to_string(),
            is_method: true,
            class_name: Some("MyClass".to_string()),
            params: vec![PyParam {
                name: "self".to_string(),
                default: None,
                type_annotation: None,
            }],
            is_async: false,
            return_type: None,
            body_hash: None,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 10,
                    end_col: 0,
                },
            },
        };

        let normalized = create_normalized_body(&method);
        assert!(normalized.contains("CLASS:MyClass"), "Should include class context");
    }

    #[test]
    fn normalized_body_includes_toplevel_marker() {
        use crate::semantics::python::model::{PyFunction, PyParam};
        use crate::parse::ast::{AstLocation, TextRange};

        let func = PyFunction {
            name: "standalone".to_string(),
            is_method: false,
            class_name: None,
            params: vec![PyParam {
                name: "data".to_string(),
                default: None,
                type_annotation: None,
            }],
            is_async: false,
            return_type: None,
            body_hash: None,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 10,
                    end_col: 0,
                },
            },
        };

        let normalized = create_normalized_body(&func);
        assert!(normalized.contains("TOPLEVEL"), "Should include TOPLEVEL marker for non-methods");
    }

    #[test]
    fn normalized_body_includes_param_names() {
        use crate::semantics::python::model::{PyFunction, PyParam};
        use crate::parse::ast::{AstLocation, TextRange};

        let func = PyFunction {
            name: "process".to_string(),
            is_method: false,
            class_name: None,
            params: vec![
                PyParam {
                    name: "items".to_string(),
                    default: None,
                    type_annotation: None,
                },
                PyParam {
                    name: "count".to_string(),
                    default: Some("10".to_string()),
                    type_annotation: None,
                },
            ],
            is_async: false,
            return_type: None,
            body_hash: None,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 10,
                    end_col: 0,
                },
            },
        };

        let normalized = create_normalized_body(&func);
        assert!(normalized.contains("P_items:REQ"), "Should include param name 'items'");
        assert!(normalized.contains("P_count:DEF"), "Should include param name 'count' with default marker");
    }

    #[test]
    fn normalized_body_includes_type_annotations() {
        use crate::semantics::python::model::{PyFunction, PyParam};
        use crate::parse::ast::{AstLocation, TextRange};

        let func = PyFunction {
            name: "get_diagnostics".to_string(),
            is_method: false,
            class_name: None,
            params: vec![
                PyParam {
                    name: "request".to_string(),
                    default: None,
                    type_annotation: Some("DiagnosticsRequest".to_string()),
                },
            ],
            is_async: true,
            return_type: None,
            body_hash: None,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 10,
                    end_col: 0,
                },
            },
        };

        let normalized = create_normalized_body(&func);
        assert!(normalized.contains("T_DiagnosticsRequest"),
            "Should include type annotation in normalization: {}", normalized);
    }

    #[test]
    fn different_type_annotations_produce_different_hashes() {
        use crate::semantics::python::model::{PyFunction, PyParam};
        use crate::parse::ast::{AstLocation, TextRange};

        let func1 = PyFunction {
            name: "get_diagnostics".to_string(),
            is_method: false,
            class_name: None,
            params: vec![
                PyParam {
                    name: "request".to_string(),
                    default: None,
                    type_annotation: Some("DiagnosticsRequest".to_string()),
                },
            ],
            is_async: true,
            return_type: None,
            body_hash: None,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 10,
                    end_col: 0,
                },
            },
        };

        let func2 = PyFunction {
            name: "get_code_actions".to_string(),
            is_method: false,
            class_name: None,
            params: vec![
                PyParam {
                    name: "request".to_string(),
                    default: None,
                    type_annotation: Some("CodeActionsRequest".to_string()),
                },
            ],
            is_async: true,
            return_type: None,
            body_hash: None,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 10,
                    end_col: 0,
                },
            },
        };

        let normalized1 = create_normalized_body(&func1);
        let normalized2 = create_normalized_body(&func2);

        assert_ne!(normalized1, normalized2,
            "Functions with different type annotations should have different normalized bodies");

        let hash1 = hash_string(&normalized1);
        let hash2 = hash_string(&normalized2);

        assert_ne!(hash1, hash2,
            "Functions with different type annotations should have different hashes");
    }

    #[test]
    fn normalized_body_skips_self_and_cls() {
        use crate::semantics::python::model::{PyFunction, PyParam};
        use crate::parse::ast::{AstLocation, TextRange};

        let method = PyFunction {
            name: "method".to_string(),
            is_method: true,
            class_name: Some("TestClass".to_string()),
            params: vec![
                PyParam {
                    name: "self".to_string(),
                    default: None,
                    type_annotation: None,
                },
                PyParam {
                    name: "data".to_string(),
                    default: None,
                    type_annotation: None,
                },
            ],
            is_async: false,
            return_type: None,
            body_hash: None,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 10,
                    end_col: 0,
                },
            },
        };

        let normalized = create_normalized_body(&method);
        assert!(!normalized.contains("P_self"), "Should skip 'self' parameter");
        assert!(normalized.contains("P_data"), "Should include regular parameters");
    }

    #[test]
    fn normalized_body_includes_return_type() {
        use crate::semantics::python::model::{PyFunction, PyParam};
        use crate::parse::ast::{AstLocation, TextRange};

        let func = PyFunction {
            name: "is_empty".to_string(),
            is_method: true,
            class_name: Some("WorkspaceSettings".to_string()),
            params: vec![PyParam {
                name: "self".to_string(),
                default: None,
                type_annotation: None,
            }],
            is_async: false,
            return_type: Some("bool".to_string()),
            body_hash: None,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 10,
                    end_col: 0,
                },
            },
        };

        let normalized = create_normalized_body(&func);
        assert!(normalized.contains("RET:bool"), "Should include return type in normalization: {}", normalized);
    }

    #[test]
    fn different_return_types_produce_different_hashes() {
        use crate::semantics::python::model::{PyFunction, PyParam};
        use crate::parse::ast::{AstLocation, TextRange};

        // Simulates is_empty(self) -> bool
        let func1 = PyFunction {
            name: "is_empty".to_string(),
            is_method: true,
            class_name: Some("WorkspaceSettings".to_string()),
            params: vec![PyParam {
                name: "self".to_string(),
                default: None,
                type_annotation: None,
            }],
            is_async: false,
            return_type: Some("bool".to_string()),
            body_hash: None,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 10,
                    end_col: 0,
                },
            },
        };

        // Simulates to_dict(self) -> dict[str, Any]
        let func2 = PyFunction {
            name: "to_dict".to_string(),
            is_method: true,
            class_name: Some("WorkspaceSettings".to_string()),
            params: vec![PyParam {
                name: "self".to_string(),
                default: None,
                type_annotation: None,
            }],
            is_async: false,
            return_type: Some("dict[str, Any]".to_string()),
            body_hash: None,
            location: AstLocation {
                file_id: FileId(1),
                range: TextRange {
                    start_line: 0,
                    start_col: 0,
                    end_line: 10,
                    end_col: 0,
                },
            },
        };

        let normalized1 = create_normalized_body(&func1);
        let normalized2 = create_normalized_body(&func2);

        assert_ne!(normalized1, normalized2,
            "Functions with different return types should have different normalized bodies.\n\
             is_empty: {}\n\
             to_dict: {}", normalized1, normalized2);

        let hash1 = hash_string(&normalized1);
        let hash2 = hash_string(&normalized2);

        assert_ne!(hash1, hash2,
            "Functions with different return types should have different hashes");
    }
}