//! Rule: CPU-intensive work in async context detection
//!
//! Detects CPU-bound operations inside async functions that can block
//! the async runtime's worker threads and cause performance degradation.
//!
//! # Examples
//!
//! Bad:
//! ```rust,ignore
//! async fn process_data(data: &[u8]) {
//!     let hash = sha256::digest(data);  // Blocks worker thread
//!     let parsed = serde_json::from_slice::<Data>(data)?;  // CPU-bound
//! }
//! ```
//!
//! Good:
//! ```rust,ignore
//! async fn process_data(data: Vec<u8>) {
//!     let hash = tokio::task::spawn_blocking(move || {
//!         sha256::digest(&data)
//!     }).await?;
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects CPU-intensive operations in async functions.
///
/// Long-running CPU operations in async functions block the runtime's
/// worker threads, preventing other async tasks from making progress.
/// These operations should be offloaded using `spawn_blocking`.
#[derive(Debug, Default)]
pub struct RustCpuInAsyncRule;

impl RustCpuInAsyncRule {
    pub fn new() -> Self {
        Self
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
    /// Start byte offset
    #[allow(dead_code)]
    start_byte: usize,
    /// End byte offset
    #[allow(dead_code)]
    end_byte: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CpuOperationType {
    /// JSON serialization/deserialization
    JsonProcessing,
    /// Cryptographic operations
    Cryptography,
    /// Compression/decompression
    Compression,
    /// Regular expression operations
    RegexProcessing,
    /// Image processing
    ImageProcessing,
    /// Data serialization (bincode, msgpack, etc.)
    Serialization,
    /// Sorting large collections
    Sorting,
    /// File parsing (XML, YAML, TOML)
    FileParsing,
    /// Base64 encoding/decoding
    Base64Processing,
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
            CpuOperationType::Sorting => "sorting operation",
            CpuOperationType::FileParsing => "file parsing",
            CpuOperationType::Base64Processing => "base64 encoding/decoding",
            CpuOperationType::Generic => "CPU-intensive operation",
        }
    }
}

/// Detect CPU-intensive operations from the callee name
fn detect_cpu_intensive_operation(callee: &str) -> Option<CpuOperationType> {
    // JSON processing (serde_json)
    if callee.contains("serde_json::from_")
        || callee.contains("serde_json::to_")
        || callee.contains("from_str")
        || callee.contains("from_slice")
        || callee.contains("to_string")
        || callee.contains("to_vec")
    {
        // Only flag if it looks like serialization
        if callee.contains("serde") || callee.contains("json") {
            return Some(CpuOperationType::JsonProcessing);
        }
    }

    // Cryptography
    if callee.contains("sha256")
        || callee.contains("sha512")
        || callee.contains("sha1")
        || callee.contains("md5")
        || callee.contains("bcrypt")
        || callee.contains("argon2")
        || callee.contains("scrypt")
        || callee.contains("pbkdf2")
        || callee.contains("hmac")
        || callee.contains("encrypt")
        || callee.contains("decrypt")
        || callee.contains("digest")
        || callee.contains("hash(")
        || callee.contains("::hash")
    {
        return Some(CpuOperationType::Cryptography);
    }

    // Compression
    if callee.contains("gzip")
        || callee.contains("flate2")
        || callee.contains("zstd")
        || callee.contains("lz4")
        || callee.contains("brotli")
        || callee.contains("compress")
        || callee.contains("decompress")
        || callee.contains("GzEncoder")
        || callee.contains("GzDecoder")
    {
        return Some(CpuOperationType::Compression);
    }

    // Regex
    if callee.contains("Regex::new")
        || callee.contains("regex::Regex")
        || callee.contains(".is_match(")
        || callee.contains(".find(")
        || callee.contains(".captures(")
        || callee.contains(".replace_all(")
    {
        return Some(CpuOperationType::RegexProcessing);
    }

    // Image processing
    if callee.contains("image::")
        || callee.contains("ImageBuffer")
        || callee.contains("DynamicImage")
        || callee.contains("resize")
        || callee.contains("thumbnail")
    {
        return Some(CpuOperationType::ImageProcessing);
    }

    // Serialization (bincode, msgpack, etc.)
    if callee.contains("bincode")
        || callee.contains("rmp_serde")
        || callee.contains("ciborium")
        || callee.contains("postcard")
        || callee.contains("serialize")
        || callee.contains("deserialize")
    {
        return Some(CpuOperationType::Serialization);
    }

    // Sorting
    if callee.contains(".sort(")
        || callee.contains(".sort_by(")
        || callee.contains(".sort_unstable(")
    {
        return Some(CpuOperationType::Sorting);
    }

    // File parsing
    if callee.contains("serde_yaml")
        || callee.contains("toml::from_str")
        || callee.contains("quick_xml")
        || callee.contains("roxmltree")
    {
        return Some(CpuOperationType::FileParsing);
    }

    // Base64
    if callee.contains("base64::encode")
        || callee.contains("base64::decode")
        || callee.contains("base64::engine")
    {
        return Some(CpuOperationType::Base64Processing);
    }

    None
}

/// Check if the call is properly offloaded to spawn_blocking
fn is_offloaded_to_blocking(callee: &str, context_calls: &[&str]) -> bool {
    // Check if spawn_blocking is in the surrounding context
    context_calls.iter().any(|c| {
        c.contains("spawn_blocking") || c.contains("block_in_place") || c.contains("rayon::")
    }) || callee.contains("spawn_blocking")
}

#[async_trait]
impl Rule for RustCpuInAsyncRule {
    fn id(&self) -> &'static str {
        "rust.cpu_in_async"
    }

    fn name(&self) -> &'static str {
        "CPU-intensive work in async function blocks runtime"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let rust = match sem.as_ref() {
                SourceSemantics::Rust(r) => r,
                _ => continue,
            };

            // Find async functions
            let async_functions: Vec<_> = rust
                .functions
                .iter()
                .filter(|f| f.is_async && !f.is_test)
                .collect();

            if async_functions.is_empty() {
                continue;
            }

            // Check calls for CPU-intensive operations
            for call in &rust.calls {
                if !call.in_async {
                    continue;
                }

                if let Some(op_type) =
                    detect_cpu_intensive_operation(&call.function_call.callee_expr)
                {
                    // Get surrounding calls for context check
                    let context_calls: Vec<&str> = rust
                        .calls
                        .iter()
                        .filter(|c| c.function_name == call.function_name)
                        .map(|c| c.function_call.callee_expr.as_str())
                        .collect();

                    if is_offloaded_to_blocking(&call.function_call.callee_expr, &context_calls) {
                        continue;
                    }

                    let func_name = call
                        .function_name
                        .clone()
                        .unwrap_or_else(|| "async function".to_string());

                    let cpu_call = CpuIntensiveCall {
                        callee: call.function_call.callee_expr.clone(),
                        operation_type: op_type,
                        line: call.function_call.location.line,
                        column: call.function_call.location.column,
                        async_function: func_name.clone(),
                        start_byte: call.start_byte,
                        end_byte: call.end_byte,
                    };

                    findings.push(create_finding(self.id(), &cpu_call, *file_id, &rust.path));
                }
            }
        }

        findings
    }
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
        "The {} '{}' in async function '{}' can block the async runtime's worker thread, \
         preventing other tasks from making progress.\n\n\
         **Why this is problematic:**\n\
         - Async runtimes have limited worker threads\n\
         - Blocking one thread affects all tasks on that thread\n\
         - Can cause latency spikes and throughput degradation\n\
         - May starve other async tasks of execution time\n\n\
         **Recommended fix:**\n\
         Use `tokio::task::spawn_blocking` to run CPU-bound work on a dedicated thread pool:\n\
         ```rust\n\
         let result = tokio::task::spawn_blocking(move || {{\n\
             // CPU-intensive work here\n\
         }}).await?;\n\
         ```",
        cpu_call.operation_type.description(),
        cpu_call.callee,
        cpu_call.async_function
    );

    let fix_preview = format!(
        r#"// Before (blocking worker thread):
async fn {func}() {{
    let result = {callee}(data);
}}

// After (offloaded to blocking thread):
async fn {func}() {{
    let result = tokio::task::spawn_blocking(move || {{
        {callee}(data)
    }}).await?;
}}"#,
        func = cpu_call.async_function,
        callee = cpu_call
            .callee
            .split("::")
            .last()
            .unwrap_or(&cpu_call.callee)
    );

    let patch = FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine {
                line: cpu_call.line,
            },
            replacement: format!(
                "// TODO: Offload to spawn_blocking: tokio::task::spawn_blocking(move || {{ ... }})\n"
            ),
        }],
    };

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
            "rust".into(),
            "async".into(),
            "performance".into(),
            "cpu-bound".into(),
            "blocking".into(),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::rust::parse_rust_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::rust::build_rust_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "async_code.rs".to_string(),
            language: Language::Rust,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_rust_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_rust_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Rust(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = RustCpuInAsyncRule::new();
        assert_eq!(rule.id(), "rust.cpu_in_async");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = RustCpuInAsyncRule::new();
        assert!(rule.name().contains("CPU"));
    }

    #[test]
    fn detect_cpu_intensive_identifies_json() {
        assert!(matches!(
            detect_cpu_intensive_operation("serde_json::from_str"),
            Some(CpuOperationType::JsonProcessing)
        ));
    }

    #[test]
    fn detect_cpu_intensive_identifies_crypto() {
        assert!(matches!(
            detect_cpu_intensive_operation("sha256::digest"),
            Some(CpuOperationType::Cryptography)
        ));
        assert!(matches!(
            detect_cpu_intensive_operation("bcrypt::hash"),
            Some(CpuOperationType::Cryptography)
        ));
    }

    #[test]
    fn detect_cpu_intensive_identifies_compression() {
        assert!(matches!(
            detect_cpu_intensive_operation("flate2::compress"),
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

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = RustCpuInAsyncRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn no_finding_for_sync_functions() {
        let rule = RustCpuInAsyncRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            r#"
fn sync_fn() {
    let hash = sha256::digest("data");
}
"#,
        );
        let semantics = vec![(file_id, sem)];
        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }
}
