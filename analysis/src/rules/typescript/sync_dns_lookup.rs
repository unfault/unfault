//! TypeScript Sync DNS Lookup Detection Rule
//!
//! Detects synchronous DNS lookups that can block the event loop.

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

#[derive(Debug)]
pub struct TypescriptSyncDnsLookupRule;

impl TypescriptSyncDnsLookupRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TypescriptSyncDnsLookupRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for TypescriptSyncDnsLookupRule {
    fn id(&self) -> &'static str {
        "typescript.sync_dns_lookup"
    }

    fn name(&self) -> &'static str {
        "Synchronous DNS Lookup"
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
            let ts = match sem.as_ref() {
                SourceSemantics::Typescript(ts) => ts,
                _ => continue,
            };

            // Check for dns module import
            let has_dns = ts.imports.iter().any(|imp| imp.module == "dns");
            if !has_dns {
                continue;
            }

            // Look for sync DNS methods
            for call in &ts.calls {
                let is_sync_dns = call.callee.contains("dns.lookupSync")
                    || call.callee.contains("dns.resolveSync")
                    || (call.callee.contains("dns.lookup")
                        && !call.callee.contains("lookupService"));

                if !is_sync_dns {
                    continue;
                }

                // Check if it's actually the async version (with callback)
                if call.args.len() >= 2 {
                    // If last arg is likely a callback, it's async
                    continue;
                }

                let line = call.location.range.start_line + 1;
                let column = call.location.range.start_col + 1;

                let patch = FilePatch {
                    file_id: *file_id,
                    hunks: vec![PatchHunk {
                        range: PatchRange::InsertBeforeLine { line },
                        replacement: "// Use async DNS lookup:\n\
                             // import { promises as dnsPromises } from 'dns';\n\
                             // const addresses = await dnsPromises.lookup(hostname);\n"
                            .to_string(),
                    }],
                };

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "Synchronous DNS lookup blocks event loop".to_string(),
                    description: Some(format!(
                        "DNS call '{}' at line {} may block the event loop. \
                         Use dns.promises.lookup() or dns.lookup() with callback instead.",
                        call.callee, line
                    )),
                    kind: FindingKind::PerformanceSmell,
                    severity: Severity::Medium,
                    confidence: 0.7,
                    dimension: Dimension::Performance,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(line),
                    column: Some(column),
                    end_line: None,
                    end_column: None,
                    byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some("Use async dns.promises.lookup()".to_string()),
                    tags: vec!["performance".into(), "dns".into(), "blocking".into()],
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
    fn test_rule_id() {
        let rule = TypescriptSyncDnsLookupRule::new();
        assert_eq!(rule.id(), "typescript.sync_dns_lookup");
    }
}
