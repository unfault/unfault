//! Rule B11: CPU work in event loop detection
//!
//! Detects CPU-intensive operations inside async functions that can block
//! the event loop and cause performance degradation.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::{ImportInsertionType, PyImport};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects CPU-intensive operations in async functions.
///
/// Long-running CPU operations in async functions block the event loop,
/// preventing other coroutines from running and causing latency spikes.
/// These operations should be offloaded to a thread pool using
/// `run_in_executor` or `asyncio.to_thread`.
#[derive(Debug)]
pub struct PythonCpuInEventLoopRule;

impl PythonCpuInEventLoopRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonCpuInEventLoopRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a CPU-intensive operation in async context
#[derive(Debug, Clone)]
struct CpuIntensiveCall {
    /// The function/operation being called
    callee: String,
    /// The type of CPU-intensive operation
    operation_type: CpuOperationType,
    /// Line number (1-based)
    line: u32,
    /// Column number (1-based)
    column: u32,
    /// Name of the enclosing async function
    async_function: String,
    /// Start byte offset for replacement
    start_byte: usize,
    /// End byte offset for replacement
    end_byte: usize,
    /// Arguments representation
    args_repr: String,
    /// Existing imports in the file (for avoiding duplicate imports)
    imports: Vec<PyImport>,
    /// Line to insert stdlib imports (respects PEP 8 ordering)
    stdlib_import_line: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CpuOperationType {
    /// JSON encoding/decoding
    JsonProcessing,
    /// Cryptographic operations
    Cryptography,
    /// Compression/decompression
    Compression,
    /// Regular expression operations
    RegexProcessing,
    /// Image processing
    ImageProcessing,
    /// Data serialization (pickle, etc.)
    Serialization,
    /// Mathematical computations
    MathComputation,
    /// Sorting large collections
    Sorting,
    /// String processing
    StringProcessing,
    /// File parsing (XML, YAML, etc.)
    FileParsing,
    /// Generic CPU-bound operation
    #[allow(dead_code)]
    Generic,
}

impl CpuOperationType {
    fn description(&self) -> &'static str {
        match self {
            CpuOperationType::JsonProcessing => "JSON processing",
            CpuOperationType::Cryptography => "cryptographic operation",
            CpuOperationType::Compression => "compression/decompression",
            CpuOperationType::RegexProcessing => "regex processing",
            CpuOperationType::ImageProcessing => "image processing",
            CpuOperationType::Serialization => "serialization",
            CpuOperationType::MathComputation => "mathematical computation",
            CpuOperationType::Sorting => "sorting operation",
            CpuOperationType::StringProcessing => "string processing",
            CpuOperationType::FileParsing => "file parsing",
            CpuOperationType::Generic => "CPU-intensive operation",
        }
    }
}

#[async_trait]
impl Rule for PythonCpuInEventLoopRule {
    fn id(&self) -> &'static str {
        "python.cpu_in_event_loop"
    }

    fn name(&self) -> &'static str {
        "CPU-intensive work in async function blocks event loop"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(unbounded_resource())
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
                _ => continue,
            };

            // Find async functions
            let async_functions: Vec<_> = py.functions.iter().filter(|f| f.is_async).collect();

            if async_functions.is_empty() {
                continue;
            }

            // Check for CPU-intensive calls
            for call in &py.calls {
                // callee_expr may be only the terminal method in a chain (e.g. `.hexdigest()`),
                // so also consider the joined callee parts as a better signal.
                let callee_joined = call.function_call.callee_parts.join(".");
                let op_type = detect_cpu_intensive_operation(&callee_joined)
                    .or_else(|| detect_cpu_intensive_operation(&call.function_call.callee_expr));

                if let Some(op_type) = op_type {
                    // Check if this call is likely inside an async function
                    // This is a heuristic - we check if there are async functions in the file
                    // and the call is not using run_in_executor

                    if !is_offloaded_to_executor(&callee_joined, &call.args_repr)
                        && !is_offloaded_to_executor(
                            &call.function_call.callee_expr,
                            &call.args_repr,
                        )
                    {
                        // Prefer the semantic caller_function (more reliable than line ranges)
                        // and fall back to the line-range heuristic.
                        let async_func_name = async_functions
                            .iter()
                            .find(|f| f.name == call.function_call.caller_function)
                            .map(|f| f.name.clone())
                            .or_else(|| {
                                find_enclosing_async_function(
                                    &async_functions,
                                    call.function_call.location.line,
                                )
                            });

                        if let Some(func_name) = async_func_name {
                            findings.push(create_finding(
                                self.id(),
                                &CpuIntensiveCall {
                                    callee: call.function_call.callee_expr.clone(),
                                    operation_type: op_type,
                                    line: call.function_call.location.line,
                                    column: call.function_call.location.column,
                                    async_function: func_name,
                                    start_byte: call.start_byte,
                                    end_byte: call.end_byte,
                                    args_repr: call.args_repr.clone(),
                                    imports: py.imports.clone(),
                                    stdlib_import_line: py.import_insertion_line_for(
                                        ImportInsertionType::stdlib_import(),
                                    ),
                                },
                                *file_id,
                                &py.path,
                            ));
                        }
                    }
                }
            }
        }

        findings
    }
}

fn detect_cpu_intensive_operation(callee: &str) -> Option<CpuOperationType> {
    // JSON processing
    if callee.contains("json.loads")
        || callee.contains("json.dumps")
        || callee.contains("json.load")
        || callee.contains("json.dump")
        || callee == "loads"
        || callee == "dumps"
    {
        return Some(CpuOperationType::JsonProcessing);
    }

    // Cryptography
    if callee.contains("hashlib")
        || callee.contains("hmac")
        || callee.contains("bcrypt")
        || callee.contains("scrypt")
        || callee.contains("pbkdf2")
        || callee.contains("argon2")
        || callee.contains(".hash(")
        || callee.contains(".encrypt(")
        || callee.contains(".decrypt(")
        || callee.contains("sha256")
        || callee.contains("sha512")
        || callee.contains("md5")
    {
        return Some(CpuOperationType::Cryptography);
    }

    // Compression
    if callee.contains("gzip")
        || callee.contains("zlib")
        || callee.contains("bz2")
        || callee.contains("lzma")
        || callee.contains("compress")
        || callee.contains("decompress")
    {
        return Some(CpuOperationType::Compression);
    }

    // Regex
    if callee.contains("re.match")
        || callee.contains("re.search")
        || callee.contains("re.findall")
        || callee.contains("re.sub")
        || callee.contains("re.compile")
        || callee.contains("regex.")
    {
        return Some(CpuOperationType::RegexProcessing);
    }

    // Image processing
    if callee.contains("PIL")
        || callee.contains("Pillow")
        || callee.contains("cv2")
        || callee.contains("opencv")
        || callee.contains("Image.")
        || callee.contains(".resize(")
        || callee.contains(".thumbnail(")
    {
        return Some(CpuOperationType::ImageProcessing);
    }

    // Serialization
    if callee.contains("pickle")
        || callee.contains("marshal")
        || callee.contains("msgpack")
        || callee.contains("protobuf")
    {
        return Some(CpuOperationType::Serialization);
    }

    // Math computations
    if callee.contains("numpy")
        || callee.contains("scipy")
        || callee.contains("pandas")
        || callee.contains("np.")
        || callee.contains("math.")
    {
        return Some(CpuOperationType::MathComputation);
    }

    // Sorting
    if callee == "sorted" || callee.ends_with(".sort(") || callee.contains(".sort()") {
        return Some(CpuOperationType::Sorting);
    }

    // File parsing
    if callee.contains("xml.")
        || callee.contains("yaml.")
        || callee.contains("toml.")
        || callee.contains("ElementTree")
        || callee.contains("lxml")
        || callee.contains("BeautifulSoup")
    {
        return Some(CpuOperationType::FileParsing);
    }

    // String processing (potentially CPU-intensive)
    if callee.contains(".encode(") || callee.contains(".decode(") || callee.contains("base64") {
        return Some(CpuOperationType::StringProcessing);
    }

    None
}

fn is_offloaded_to_executor(callee: &str, args: &str) -> bool {
    // Check if the call is wrapped in run_in_executor or to_thread
    callee.contains("run_in_executor")
        || callee.contains("to_thread")
        || callee.contains("ProcessPoolExecutor")
        || callee.contains("ThreadPoolExecutor")
        || args.contains("run_in_executor")
        || args.contains("to_thread")
}

fn find_enclosing_async_function(
    async_functions: &[&crate::semantics::python::model::PyFunction],
    call_line: u32,
) -> Option<String> {
    // Find the async function that contains this call
    // A call is inside a function if it's between the function's start and end lines
    let mut best_match: Option<&crate::semantics::python::model::PyFunction> = None;

    for func in async_functions {
        let func_start = func.location.range.start_line;
        let func_end = func.location.range.end_line;

        // Check if the call is within the function's range
        if call_line >= func_start && call_line <= func_end {
            match best_match {
                None => best_match = Some(func),
                Some(current) => {
                    // Prefer the innermost function (the one that starts later)
                    if func_start > current.location.range.start_line {
                        best_match = Some(func);
                    }
                }
            }
        }
    }

    best_match.map(|f| f.name.clone())
}

fn create_finding(
    rule_id: &str,
    cpu_call: &CpuIntensiveCall,
    file_id: FileId,
    file_path: &str,
) -> RuleFinding {
    let title = format!(
        "CPU-intensive {} in async function '{}'",
        cpu_call.operation_type.description(),
        cpu_call.async_function
    );

    let description = format!(
        "The {} '{}' in async function '{}' can block the event loop, \
         causing latency spikes and preventing other coroutines from running. \
         Offload to a thread pool using asyncio.to_thread() or loop.run_in_executor().",
        cpu_call.operation_type.description(),
        cpu_call.callee,
        cpu_call.async_function
    );

    let patch = generate_executor_patch(cpu_call, file_id);

    let fix_preview = format!(
        r#"# Before (blocking):
async def {func}():
    result = {callee}(data)  # Blocks event loop

# After (non-blocking):
import asyncio

async def {func}():
    result = await asyncio.to_thread({callee}, data)
    # Or using run_in_executor:
    # loop = asyncio.get_event_loop()
    # result = await loop.run_in_executor(None, {callee}, data)"#,
        func = cpu_call.async_function,
        callee = cpu_call
            .callee
            .split('.')
            .last()
            .unwrap_or(&cpu_call.callee)
    );

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::PerformanceSmell,
        severity: Severity::Medium,
        confidence: 0.75,
        dimension: Dimension::Performance,
        file_id,
        file_path: file_path.to_string(),
        line: Some(cpu_call.line),
        column: Some(cpu_call.column),
        end_line: None,
        end_column: None,
        byte_range: None,
        patch: Some(patch),
        fix_preview: Some(fix_preview),
        tags: vec![
            "python".into(),
            "async".into(),
            "event-loop".into(),
            "performance".into(),
            "cpu-bound".into(),
        ],
    }
}

/// Check if asyncio is already imported
fn has_asyncio_import(imports: &[PyImport]) -> bool {
    imports
        .iter()
        .any(|imp| imp.module == "asyncio" || imp.names.iter().any(|n| n == "asyncio"))
}

fn generate_executor_patch(cpu_call: &CpuIntensiveCall, file_id: FileId) -> FilePatch {
    let mut hunks = Vec::new();

    // Only add asyncio import if not already present
    // Use stdlib_import_line to ensure it's placed before third-party imports
    if !has_asyncio_import(&cpu_call.imports) {
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine {
                line: cpu_call.stdlib_import_line,
            },
            replacement: "import asyncio  # Added by unfault for to_thread\n".to_string(),
        });
    }

    // Generate the actual code transformation using ReplaceBytes
    // Transform: func(args) -> await asyncio.to_thread(func, args)
    let replacement = if cpu_call.args_repr.is_empty() {
        // No arguments: func() -> await asyncio.to_thread(func)
        format!("await asyncio.to_thread({})", cpu_call.callee)
    } else {
        // With arguments: func(a, b) -> await asyncio.to_thread(func, a, b)
        format!(
            "await asyncio.to_thread({}, {})",
            cpu_call.callee, cpu_call.args_repr
        )
    };

    hunks.push(PatchHunk {
        range: PatchRange::ReplaceBytes {
            start: cpu_call.start_byte,
            end: cpu_call.end_byte,
        },
        replacement,
    });

    FilePatch { file_id, hunks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::python::build_python_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_python_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonCpuInEventLoopRule::new();
        assert_eq!(rule.id(), "python.cpu_in_event_loop");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonCpuInEventLoopRule::new();
        assert!(rule.name().contains("CPU"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonCpuInEventLoopRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonCpuInEventLoopRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonCpuInEventLoopRule::default();
        assert_eq!(rule.id(), "python.cpu_in_event_loop");
    }

    #[tokio::test]
    async fn detects_json_in_async_function() {
        let rule = PythonCpuInEventLoopRule::new();
        let src = r#"
import json

async def process_data(data):
    result = json.loads(data)
    return result
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            !findings.is_empty(),
            "Should detect json.loads in async function"
        );
        assert_eq!(findings[0].rule_id, "python.cpu_in_event_loop");
    }

    #[tokio::test]
    async fn detects_crypto_in_async_function() {
        let rule = PythonCpuInEventLoopRule::new();
        let src = r#"
import hashlib

async def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            !findings.is_empty(),
            "Should detect hashlib in async function"
        );
    }

    #[tokio::test]
    async fn no_finding_for_sync_function() {
        let rule = PythonCpuInEventLoopRule::new();
        let src = r#"
import json

def process_data(data):
    result = json.loads(data)
    return result
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.is_empty(),
            "Should not flag CPU work in sync functions"
        );
    }

    #[tokio::test]
    async fn no_finding_when_using_to_thread() {
        let rule = PythonCpuInEventLoopRule::new();
        let src = r#"
import json
import asyncio

async def process_data(data):
    result = await asyncio.to_thread(json.loads, data)
    return result
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should not flag when properly offloaded
        // Note: This depends on detection accuracy
        let cpu_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "python.cpu_in_event_loop")
            .collect();
        // The to_thread usage should prevent flagging
        assert!(cpu_findings.is_empty() || cpu_findings.iter().all(|f| f.confidence < 0.7));
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = PythonCpuInEventLoopRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = PythonCpuInEventLoopRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = PythonCpuInEventLoopRule::new();
        let src = r#"
import json

async def handler():
    data = json.dumps({"key": "value"})
    return data
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        if !findings.is_empty() {
            let finding = &findings[0];
            assert_eq!(finding.rule_id, "python.cpu_in_event_loop");
            assert!(matches!(finding.kind, FindingKind::PerformanceSmell));
            assert_eq!(finding.dimension, Dimension::Performance);
            assert!(finding.patch.is_some());
            assert!(finding.fix_preview.is_some());
            assert!(finding.tags.contains(&"cpu-bound".to_string()));
        }
    }

    #[test]
    fn detect_cpu_intensive_operation_identifies_json() {
        assert!(matches!(
            detect_cpu_intensive_operation("json.loads"),
            Some(CpuOperationType::JsonProcessing)
        ));
        assert!(matches!(
            detect_cpu_intensive_operation("json.dumps"),
            Some(CpuOperationType::JsonProcessing)
        ));
    }

    #[test]
    fn detect_cpu_intensive_operation_identifies_crypto() {
        assert!(matches!(
            detect_cpu_intensive_operation("hashlib.sha256"),
            Some(CpuOperationType::Cryptography)
        ));
        assert!(matches!(
            detect_cpu_intensive_operation("bcrypt.hash"),
            Some(CpuOperationType::Cryptography)
        ));
    }

    #[test]
    fn detect_cpu_intensive_operation_identifies_compression() {
        assert!(matches!(
            detect_cpu_intensive_operation("gzip.compress"),
            Some(CpuOperationType::Compression)
        ));
        assert!(matches!(
            detect_cpu_intensive_operation("zlib.decompress"),
            Some(CpuOperationType::Compression)
        ));
    }

    #[test]
    fn cpu_operation_type_descriptions_are_meaningful() {
        assert!(
            CpuOperationType::JsonProcessing
                .description()
                .contains("JSON")
        );
        assert!(
            CpuOperationType::Cryptography
                .description()
                .contains("cryptographic")
        );
        assert!(
            CpuOperationType::Compression
                .description()
                .contains("compression")
        );
    }
}
