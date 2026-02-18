//! Rule: Ephemeral filesystem write in Go
//!
//! Detects writes to filesystem in containerized environments where storage is ephemeral.

use std::sync::Arc;
use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects ephemeral filesystem writes.
#[derive(Debug, Default)]
pub struct GoEphemeralFilesystemWriteRule;

impl GoEphemeralFilesystemWriteRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for GoEphemeralFilesystemWriteRule {
    fn id(&self) -> &'static str {
        "go.ephemeral_filesystem_write"
    }

    fn name(&self) -> &'static str {
        "Ephemeral filesystem write"
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
            let go = match sem.as_ref() {
                SourceSemantics::Go(g) => g,
                _ => continue,
            };

            // Check if using proper external storage
            let has_external_storage = go.imports.iter().any(|imp| {
                imp.path.contains("cloud.google.com/go/storage") ||
                imp.path.contains("github.com/aws/aws-sdk-go") ||
                imp.path.contains("s3") ||
                imp.path.contains("minio") ||
                imp.path.contains("azure") ||
                imp.path.contains("blob")
            });

            if has_external_storage {
                continue; // File uses proper external storage
            }

            // Look for file write calls
            for call in &go.calls {
                let callee = &call.function_call.callee_expr;
                
                let is_file_write = 
                    callee == "os.Create" ||
                    callee == "os.OpenFile" ||
                    callee == "os.WriteFile" ||
                    callee == "ioutil.WriteFile" ||
                    callee.ends_with(".Write") ||
                    callee.ends_with(".WriteString");

                if !is_file_write {
                    continue;
                }

                // Check if the call argument contains ephemeral path patterns
                let args = &call.args_repr;
                let writes_ephemeral = 
                    args.contains("\"/tmp") ||
                    args.contains("\"./") ||
                    args.contains("\"../") ||
                    args.contains("\"/var/") ||
                    args.contains("\"/app/") ||
                    args.contains("\"/data/");

                if writes_ephemeral || callee == "os.Create" || callee == "os.WriteFile" || callee == "ioutil.WriteFile" {
                    let line = call.function_call.location.line;
                    let column = call.function_call.location.column;

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Writing to potentially ephemeral filesystem".to_string(),
                        description: Some(
                            "In containerized environments (Docker, Kubernetes), local \
                             filesystem writes are ephemeral and lost on restart. Use \
                             external storage (S3, GCS, mounted volumes) for persistent data.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.70,
                        dimension: Dimension::Reliability,
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
"// Use external storage for persistent data in containers:
// 
// Option 1: Cloud storage (S3, GCS, Azure Blob)
// import \"cloud.google.com/go/storage\"
// client, _ := storage.NewClient(ctx)
// wc := client.Bucket(\"my-bucket\").Object(\"file\").NewWriter(ctx)
// 
// Option 2: Environment-aware paths
// dataDir := os.Getenv(\"DATA_DIR\") // Set to mounted volume in Kubernetes
// if dataDir == \"\" { dataDir = \"/tmp\" }
// 
// Option 3: For temp files, use os.CreateTemp and clean up
// tmpFile, _ := os.CreateTemp(\"\", \"prefix-*.txt\")
// defer os.Remove(tmpFile.Name())".to_string(),
                            }],
                        }),
                        fix_preview: Some("Use external/mounted storage".to_string()),
                        tags: vec!["go".into(), "container".into(), "storage".into()],
                    });
                }

                // Check for state stored in local files (common anti-pattern)
                let stores_state = 
                    args.contains("state.json") ||
                    args.contains("cache.json") ||
                    args.contains(".db\"") ||
                    args.contains("sqlite");

                if stores_state {
                    let line = call.function_call.location.line;
                    let column = call.function_call.location.column;

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Application state stored in local file".to_string(),
                        description: Some(
                            "Storing application state in local files doesn't work in \
                             distributed/containerized environments. Use Redis, database, \
                             or distributed cache for state.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::High,
                        confidence: 0.80,
                        dimension: Dimension::Scalability,
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
"// Use distributed storage for application state:
// - Redis for session/cache state
// - PostgreSQL/MySQL for persistent state  
// - etcd for configuration state
// 
// Example with Redis:
// import \"github.com/redis/go-redis/v9\"
// rdb := redis.NewClient(&redis.Options{Addr: \"localhost:6379\"})
// rdb.Set(ctx, \"key\", value, time.Hour)".to_string(),
                            }],
                        }),
                        fix_preview: Some("Use distributed state storage".to_string()),
                        tags: vec!["go".into(), "container".into(), "state".into(), "distributed".into()],
                    });
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
        let rule = GoEphemeralFilesystemWriteRule::new();
        assert_eq!(rule.id(), "go.ephemeral_filesystem_write");
        assert!(!rule.name().is_empty());
    }
}