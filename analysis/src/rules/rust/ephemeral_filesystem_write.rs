//! Rule: Writing to ephemeral filesystem in cloud environments.
//!
//! Writing to /tmp or local filesystem in cloud environments may cause
//! data loss on container restarts.

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

/// Rule that detects writes to ephemeral filesystem.
#[derive(Debug, Default)]
pub struct RustEphemeralFilesystemWriteRule;

impl RustEphemeralFilesystemWriteRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for RustEphemeralFilesystemWriteRule {
    fn id(&self) -> &'static str {
        "rust.ephemeral_filesystem_write"
    }

    fn name(&self) -> &'static str {
        "Writing to ephemeral filesystem that may lose data"
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

            // Build a set of test function names for fast lookup.
            let test_fn_names: std::collections::HashSet<&str> = rust
                .functions
                .iter()
                .filter(|f| f.is_test || f.has_test_attribute)
                .map(|f| f.name.as_str())
                .collect();

            // Track which (callee, line) pairs we've already emitted to prevent
            // duplicates from nested call_expression nodes (e.g. fs::write(...).unwrap()).
            let mut seen: std::collections::HashSet<(String, u32)> =
                std::collections::HashSet::new();

            // Look for file write operations with ephemeral paths
            for call in &rust.calls {
                // Skip test code — ephemeral writes in tests are expected.
                if let Some(ref fn_name) = call.function_name {
                    if test_fn_names.contains(fn_name.as_str()) {
                        continue;
                    }
                }

                // Only match the direct write call, not chained method calls whose
                // callee_expr string happens to contain the write function name.
                // A direct call has a callee_expr that IS the function path (no receiver).
                if call.is_method_call {
                    continue;
                }

                let callee_lower = call.function_call.callee_expr.to_lowercase();

                let is_write_op = callee_lower == "file::create"
                    || callee_lower == "write_all"
                    || callee_lower == "openoptions"
                    || callee_lower == "fs::write"
                    || callee_lower == "std::fs::write"
                    || callee_lower == "fs::copy"
                    || callee_lower == "std::fs::copy"
                    || callee_lower == "create_dir"
                    || callee_lower == "fs::create_dir"
                    || callee_lower == "fs::create_dir_all"
                    || callee_lower == "rename"
                    || callee_lower == "fs::rename";

                if !is_write_op {
                    continue;
                }

                // Check for ephemeral paths in callee expression or related calls
                let has_ephemeral_path = callee_lower.contains("/tmp")
                    || callee_lower.contains("/var/tmp")
                    || callee_lower.contains("temp_dir")
                    || callee_lower.contains("tempfile")
                    || callee_lower.contains("tempdir")
                    || rust
                        .uses
                        .iter()
                        .any(|u| u.path.contains("tempfile") || u.path.contains("tempdir"));

                if !has_ephemeral_path {
                    continue;
                }

                let line = call.function_call.location.line;

                // Deduplicate: skip if we've already emitted for this (callee, line).
                if !seen.insert((callee_lower.clone(), line)) {
                    continue;
                }

                let title = "Writing to ephemeral filesystem".to_string();

                let description = format!(
                    "A file write at line {} targets ephemeral storage (/tmp, temp directories).\n\n\
                     **Why this matters:**\n\
                     - Data lost on container/pod restart\n\
                     - Not shared across replicas\n\
                     - Limited space in ephemeral storage\n\
                     - Files may be deleted by system cleanup\n\n\
                     **Recommendations:**\n\
                     - Use object storage (S3, GCS, Azure Blob)\n\
                     - Use persistent volumes in Kubernetes\n\
                     - Use database for structured data\n\
                     - If temp files needed, ensure cleanup\n\n\
                     **Example:**\n\
                     ```rust\n\
                     // Instead of local files:\n\
                     // fs::write(\"/tmp/data.json\", data)?;\n\
                     \n\
                     // Use object storage:\n\
                     use aws_sdk_s3::Client;\n\
                     \n\
                     client.put_object()\n    \
                         .bucket(\"my-bucket\")\n    \
                         .key(\"data.json\")\n    \
                         .body(data.into())\n    \
                         .send()\n    \
                         .await?;\n\
                     ```",
                    line
                );

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// TODO: Consider using persistent storage instead of ephemeral filesystem".to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::StabilityRisk,
                    severity: Severity::Medium,
                    confidence: 0.70,
                    dimension: Dimension::Reliability,
                    file_id: *file_id,
                    file_path: rust.path.clone(),
                    line: Some(line),
                    column: None,
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(
                        "// Use object storage (S3, GCS) or persistent volumes".to_string(),
                    ),
                    tags: vec![
                        "rust".into(),
                        "filesystem".into(),
                        "cloud".into(),
                        "reliability".into(),
                    ],
                });
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_id_is_correct() {
        let rule = RustEphemeralFilesystemWriteRule::new();
        assert_eq!(rule.id(), "rust.ephemeral_filesystem_write");
    }
}
