//! TypeScript CPU in Event Loop Detection Rule
//!
//! Detects CPU-intensive operations that block the Node.js event loop.
//!
//! This rule focuses on:
//! - Synchronous crypto operations (always flagged - intentionally slow)
//! - Synchronous file I/O in loops or server handlers
//! - Synchronous compression in loops or server handlers
//! - Large JSON operations in loops or server handlers
//!
//! Does NOT flag:
//! - VS Code extensions, CLI tools, test files (different context)
//! - Small/bounded JSON operations outside hot paths
//! - One-time operations at startup (config loading, etc.)

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::typescript::model::{is_server_side_code, TsFileSemantics};
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

#[derive(Debug)]
pub struct TypescriptCpuInEventLoopRule;

impl TypescriptCpuInEventLoopRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptCpuInEventLoopRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptCpuInEventLoopRule {
    fn id(&self) -> &'static str {
        "typescript.cpu_in_event_loop"
    }

    fn name(&self) -> &'static str {
        "CPU-Intensive Operation in Event Loop"
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
                _ => continue,
            };

            // Determine the context for this file
            let is_server = is_server_side_code(ts);
            let is_hot_path_context = is_server || has_request_handler(ts);

            // Check for CPU-intensive operations
            for call in &ts.calls {
                let callee_lower = call.callee.to_lowercase();

                // Detect CPU-intensive patterns with context awareness
                let detection = detect_cpu_operation(&callee_lower, call.in_loop, is_hot_path_context);
                let detection = match detection {
                    Some(d) => d,
                    None => continue,
                };

                let line = call.location.range.start_line + 1;
                let column = call.location.range.start_col + 1;

                let (patch, fix_preview) = generate_patch(*file_id, line, &detection);

                let description = if call.in_loop {
                    format!(
                        "{} at line {} inside a loop blocks the event loop on each iteration. {}",
                        detection.description, line, detection.suggestion
                    )
                } else if is_hot_path_context {
                    format!(
                        "{} at line {} blocks the event loop in a request handler. {}",
                        detection.description, line, detection.suggestion
                    )
                } else {
                    format!(
                        "{} at line {} blocks the event loop. {}",
                        detection.description, line, detection.suggestion
                    )
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: format!("CPU-intensive {} in event loop", detection.operation_type),
                    description: Some(description),
                    kind: FindingKind::PerformanceSmell,
                    severity: detection.severity,
                    confidence: detection.confidence,
                    dimension: Dimension::Performance,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec!["performance".into(), "event-loop".into(), detection.tag.into()],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
    }
}

/// Detection result with context-aware severity and confidence.
struct CpuOperationDetection {
    operation_type: &'static str,
    description: &'static str,
    suggestion: &'static str,
    tag: &'static str,
    severity: Severity,
    confidence: f32,
}

/// Check if the file has request handler patterns (Express, Fastify, etc.)
fn has_request_handler(ts: &TsFileSemantics) -> bool {
    // Check for Express routes
    if let Some(ref express) = ts.express {
        if !express.routes.is_empty() {
            return true;
        }
    }

    // Check for HTTP handler imports
    for import in &ts.imports {
        let module = import.module.as_str();
        if matches!(
            module,
            "express" | "fastify" | "koa" | "hapi" | "@hapi/hapi" |
            "@nestjs/common" | "restify" | "polka" | "micro"
        ) {
            return true;
        }
    }

    false
}

/// Detect CPU-intensive operations with context awareness.
///
/// Returns None if the operation is safe in the current context.
fn detect_cpu_operation(
    callee: &str,
    in_loop: bool,
    is_hot_path_context: bool,
) -> Option<CpuOperationDetection> {
    // Synchronous crypto operations - ALWAYS flag (intentionally CPU-intensive)
    if callee.contains("crypto.pbkdf2sync")
        || callee.contains("crypto.scryptsync")
        || callee.contains("crypto.randomfillsync")
        || callee.contains("crypto.generatekeypairsync")
    {
        return Some(CpuOperationDetection {
            operation_type: "synchronous crypto",
            description: "Synchronous cryptographic operation",
            suggestion: "Use the async version (e.g., crypto.pbkdf2, crypto.scrypt) instead.",
            tag: "crypto",
            severity: Severity::High,
            confidence: 0.95,
        });
    }

    // Synchronous compression - ALWAYS flag (CPU-intensive by nature)
    if callee.contains("zlib.deflatesync")
        || callee.contains("zlib.inflatesync")
        || callee.contains("zlib.gunzipsync")
        || callee.contains("zlib.gzipsync")
        || callee.contains("zlib.brotlicompresssync")
        || callee.contains("zlib.brotlidecompresssync")
    {
        return Some(CpuOperationDetection {
            operation_type: "synchronous compression",
            description: "Synchronous compression operation",
            suggestion: "Use async compression (zlib.deflate, zlib.inflate) or streaming APIs.",
            tag: "compression",
            severity: Severity::High,
            confidence: 0.90,
        });
    }

    // Synchronous file I/O - only flag in loops or hot paths
    if callee.contains("fs.readfilesync")
        || callee.contains("fs.writefilesync")
        || callee.contains("fs.readdirsync")
        || callee.contains("fs.statsync")
        || callee.contains("fs.existssync")
        || callee.contains("fs.mkdirsync")
    {
        if in_loop {
            return Some(CpuOperationDetection {
                operation_type: "synchronous file I/O",
                description: "Synchronous file I/O inside a loop",
                suggestion: "Use async fs methods (fs.promises.readFile) or batch operations.",
                tag: "file-io",
                severity: Severity::High,
                confidence: 0.95,
            });
        } else if is_hot_path_context {
            return Some(CpuOperationDetection {
                operation_type: "synchronous file I/O",
                description: "Synchronous file I/O in a request handler",
                suggestion: "Use async fs methods (fs.promises.readFile, fs.promises.writeFile).",
                tag: "file-io",
                severity: Severity::Medium,
                confidence: 0.85,
            });
        }
        // Don't flag sync file I/O in CLI tools, VS Code extensions, startup code
        return None;
    }

    // JSON operations - only flag in loops (small JSON at startup is fine)
    if callee.contains("json.parse") || callee.contains("json.stringify") {
        if in_loop {
            return Some(CpuOperationDetection {
                operation_type: "JSON operation",
                description: "JSON parsing/stringification inside a loop",
                suggestion: "Consider streaming JSON (JSONStream) or processing in a worker thread.",
                tag: "json",
                severity: Severity::Medium,
                confidence: 0.80,
            });
        }
        // Don't flag JSON outside loops - small config objects are fine
        return None;
    }

    None
}

/// Generate patch and fix preview based on the detection type.
fn generate_patch(file_id: FileId, line: u32, detection: &CpuOperationDetection) -> (FilePatch, String) {
    let (replacement, fix_preview) = match detection.tag {
        "crypto" => (
            "// Use async crypto APIs:\n\
             // const { promisify } = require('util');\n\
             // const pbkdf2 = promisify(crypto.pbkdf2);\n\
             // const key = await pbkdf2(password, salt, iterations, keylen, 'sha512');\n"
                .to_string(),
            "Use async crypto APIs".to_string(),
        ),
        "compression" => (
            "// Use async compression:\n\
             // const { promisify } = require('util');\n\
             // const deflate = promisify(zlib.deflate);\n\
             // const compressed = await deflate(data);\n"
                .to_string(),
            "Use async compression".to_string(),
        ),
        "file-io" => (
            "// Use async file operations:\n\
             // import { readFile, writeFile } from 'fs/promises';\n\
             // const data = await readFile(path, 'utf-8');\n"
                .to_string(),
            "Use async file operations (fs/promises)".to_string(),
        ),
        "json" => (
            "// For large JSON in loops, consider:\n\
             // 1. Move JSON processing to a worker thread\n\
             // 2. Use streaming JSON parsers (JSONStream, stream-json)\n\
             // 3. Process in batches with setImmediate() breaks\n"
                .to_string(),
            "Process JSON in worker or use streaming".to_string(),
        ),
        _ => (
            "// Move CPU-intensive work off the event loop:\n\
             // import { Worker } from 'worker_threads';\n"
                .to_string(),
            "Move to worker_threads".to_string(),
        ),
    };

    let patch = FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line },
            replacement,
        }],
    };

    (patch, fix_preview)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::finding::Severity;

    #[test]
    fn test_rule_id() {
        let rule = TypescriptCpuInEventLoopRule::new();
        assert_eq!(rule.id(), "typescript.cpu_in_event_loop");
    }

    // ========== Crypto operations (always flagged) ==========

    #[test]
    fn test_crypto_always_flagged() {
        // Sync crypto should always be flagged regardless of context
        let detection = detect_cpu_operation("crypto.pbkdf2sync", false, false);
        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.tag, "crypto");
        assert_eq!(d.severity, Severity::High);
    }

    #[test]
    fn test_crypto_scrypt_flagged() {
        let detection = detect_cpu_operation("crypto.scryptsync", false, false);
        assert!(detection.is_some());
        assert_eq!(detection.unwrap().tag, "crypto");
    }

    // ========== Compression operations (always flagged) ==========

    #[test]
    fn test_compression_always_flagged() {
        // Sync compression should always be flagged
        let detection = detect_cpu_operation("zlib.deflatesync", false, false);
        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.tag, "compression");
        assert_eq!(d.severity, Severity::High);
    }

    #[test]
    fn test_brotli_compression_flagged() {
        let detection = detect_cpu_operation("zlib.brotlicompresssync", false, false);
        assert!(detection.is_some());
        assert_eq!(detection.unwrap().tag, "compression");
    }

    // ========== File I/O operations (context-dependent) ==========

    #[test]
    fn test_file_io_in_loop_flagged() {
        // File I/O in loops should always be flagged
        let detection = detect_cpu_operation("fs.readfilesync", true, false);
        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.tag, "file-io");
        assert_eq!(d.severity, Severity::High);
        assert!(d.confidence > 0.9);
    }

    #[test]
    fn test_file_io_in_handler_flagged() {
        // File I/O in request handlers should be flagged
        let detection = detect_cpu_operation("fs.writefilesync", false, true);
        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.tag, "file-io");
        assert_eq!(d.severity, Severity::Medium);
    }

    #[test]
    fn test_file_io_at_startup_not_flagged() {
        // File I/O outside loops/handlers is fine (config loading, CLI tools)
        let detection = detect_cpu_operation("fs.readfilesync", false, false);
        assert!(detection.is_none());
    }

    #[test]
    fn test_writefilesync_at_startup_not_flagged() {
        // Writing config at startup is fine
        let detection = detect_cpu_operation("fs.writefilesync", false, false);
        assert!(detection.is_none());
    }

    #[test]
    fn test_existssync_at_startup_not_flagged() {
        // Checking file existence at startup is fine
        let detection = detect_cpu_operation("fs.existssync", false, false);
        assert!(detection.is_none());
    }

    // ========== JSON operations (only in loops) ==========

    #[test]
    fn test_json_parse_in_loop_flagged() {
        // JSON.parse in loops is flagged
        let detection = detect_cpu_operation("json.parse", true, false);
        assert!(detection.is_some());
        let d = detection.unwrap();
        assert_eq!(d.tag, "json");
        assert_eq!(d.severity, Severity::Medium);
    }

    #[test]
    fn test_json_stringify_in_loop_flagged() {
        // JSON.stringify in loops is flagged
        let detection = detect_cpu_operation("json.stringify", true, true);
        assert!(detection.is_some());
        assert_eq!(detection.unwrap().tag, "json");
    }

    #[test]
    fn test_json_parse_at_startup_not_flagged() {
        // JSON.parse outside loops is fine (config parsing)
        let detection = detect_cpu_operation("json.parse", false, false);
        assert!(detection.is_none());
    }

    #[test]
    fn test_json_stringify_at_startup_not_flagged() {
        // JSON.stringify outside loops is fine (e.g., saving config)
        let detection = detect_cpu_operation("json.stringify", false, false);
        assert!(detection.is_none());
    }

    #[test]
    fn test_json_in_handler_but_not_loop_not_flagged() {
        // Even in handlers, single JSON ops without loops are fine
        let detection = detect_cpu_operation("json.parse", false, true);
        assert!(detection.is_none());
    }

    // ========== Unknown operations ==========

    #[test]
    fn test_unknown_operation_not_flagged() {
        let detection = detect_cpu_operation("console.log", false, false);
        assert!(detection.is_none());
    }

    #[test]
    fn test_async_operations_not_flagged() {
        // Async operations should not be flagged
        let detection = detect_cpu_operation("fs.readfile", false, true);
        assert!(detection.is_none());

        let detection = detect_cpu_operation("crypto.pbkdf2", false, true);
        assert!(detection.is_none());
    }
}