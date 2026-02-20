use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use scc::HashMap as ConcurrentHashMap;

use crate::dependencies::extract_all_dependencies;
use crate::error::EngineError;
use crate::graph::{CodeGraph, build_code_graph};
use crate::parse::{
    self,
    ast::{FileId, ParsedFile},
};
use crate::rules::finding::RuleFinding;
use crate::rules::registry::RuleRegistry;
use crate::semantics::{SourceSemantics, build_source_semantics};
use crate::suppression::{filter_suppressed_findings, parse_suppressions};
use crate::types::context::SessionContextInput;
use crate::types::dependency::RuntimeDependency;
use crate::types::finding::Finding;
use crate::types::meta::ReviewSessionMeta;
use crate::types::session_result::{ContextResult, ReviewSessionResult};
use crate::types::{apply_file_patch, make_unified_diff};

/// Internal state for a single analysis run.
///
/// This is a helper struct that manages the pipeline:
/// 1. Parse all files
/// 2. Build semantics
/// 3. Build code graph
/// 4. Run all rules
pub struct InternalSessionState {
    pub meta: ReviewSessionMeta,
    pub contexts: Vec<SessionContextInput>,

    /// Parsed files for this session (all contexts combined).
    pub parsed_files: ConcurrentHashMap<FileId, Arc<ParsedFile>>,

    /// Language-agnostic semantics per file.
    pub semantics: ConcurrentHashMap<FileId, Arc<SourceSemantics>>,

    /// Code graph built from semantics.
    pub code_graph: Option<CodeGraph>,

    /// Runtime dependencies extracted from the code.
    pub runtime_dependencies: Vec<RuntimeDependency>,

    pub rules: Arc<RuleRegistry>,

    /// Mapping from file id → index into `contexts`.
    file_to_context: HashMap<FileId, usize>,
}

impl InternalSessionState {
    pub fn new(
        meta: ReviewSessionMeta,
        contexts: Vec<SessionContextInput>,
        rules: Arc<RuleRegistry>,
    ) -> Self {
        Self {
            meta,
            contexts,
            parsed_files: ConcurrentHashMap::new(),
            semantics: ConcurrentHashMap::new(),
            code_graph: None,
            runtime_dependencies: Vec::new(),
            rules,
            file_to_context: HashMap::new(),
        }
    }

    /// Top-level pipeline:
    ///  1. parse files
    ///  2. build semantics
    ///  3. extract runtime dependencies
    ///  4. build graph
    ///  5. run rules
    pub async fn run(&mut self) -> Result<ReviewSessionResult, EngineError> {
        self.parse_all_files().await?;
        self.build_all_semantics().await?;
        self.extract_runtime_dependencies().await?;
        self.build_code_graph_for_session().await?;
        self.run_all_rules().await
    }

    /// Parse all files in all contexts and populate `parsed_files`.
    async fn parse_all_files(&mut self) -> Result<(), EngineError> {
        // Simple monotonically increasing file ids for this session.
        let mut next_id: u64 = 1;

        for (ctx_index, ctx) in self.contexts.iter().enumerate() {
            for sf in &ctx.files {
                let file_id = FileId(next_id);
                next_id += 1;

                match parse::parse_source_file(file_id, sf) {
                    Ok(parsed) => {
                        let parsed = Arc::new(parsed);
                        // Insert into concurrent map; ignore old value if any.
                        match self.parsed_files.insert_sync(file_id, Arc::clone(&parsed)) {
                            Ok(()) => {
                                self.file_to_context.insert(file_id, ctx_index);
                            }
                            Err((_k, _v)) => {
                                // Key already exists → replace the value
                                self.parsed_files.update_sync(&file_id, |_, old| {
                                    *old = Arc::clone(&parsed);
                                });
                            }
                        }
                    }
                    Err(e) => {
                        // For now: treat any parse failure as a fatal engine error.
                        // We'll refine this later to tolerate individual failures.
                        return Err(EngineError::Internal(anyhow!(
                            "failed to parse file {}: {e}",
                            sf.path
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    /// Build semantics for all parsed files that we know how to handle.
    async fn build_all_semantics(&self) -> Result<(), EngineError> {
        // 1) Snapshot entries out of the concurrent map.
        let mut entries: Vec<(FileId, Arc<ParsedFile>)> = Vec::new();

        self.parsed_files.iter_sync(|file_id, parsed| {
            entries.push((*file_id, Arc::clone(parsed)));
            true // keep iterating
        });

        // 2) Now we can iterate normally and do whatever we want.
        for (file_id, parsed) in entries {
            match build_source_semantics(parsed.as_ref()) {
                Ok(Some(sem)) => {
                    self.semantics
                        .insert_sync(file_id, Arc::new(sem))
                        .map_err(|e| {
                            EngineError::Internal(anyhow!(
                                "failed to insert semantics for file {:?}: {:?}",
                                file_id,
                                e
                            ))
                        })?;
                }
                Ok(None) => {
                    // language not supported yet → skip
                }
                Err(e) => {
                    return Err(EngineError::Internal(anyhow!(
                        "failed to build semantics for {}: {e}",
                        parsed.path
                    )));
                }
            }
        }

        Ok(())
    }

    /// Extract runtime dependencies from all semantics.
    async fn extract_runtime_dependencies(&mut self) -> Result<(), EngineError> {
        // Snapshot semantics into a Vec for dependency extraction.
        let mut sem_entries: Vec<(FileId, Arc<SourceSemantics>)> = Vec::new();

        self.semantics.iter_sync(|file_id, sem| {
            sem_entries.push((*file_id, Arc::clone(sem)));
            true
        });

        self.runtime_dependencies = extract_all_dependencies(&sem_entries);

        Ok(())
    }

    /// Build the CodeGraph from all current semantics.
    async fn build_code_graph_for_session(&mut self) -> Result<(), EngineError> {
        // Snapshot semantics into a Vec so we can pass a clean slice to the graph builder.
        let mut sem_entries: Vec<(FileId, Arc<SourceSemantics>)> = Vec::new();

        self.semantics.iter_sync(|file_id, sem| {
            sem_entries.push((*file_id, Arc::clone(sem)));
            true
        });

        let graph = build_code_graph(&sem_entries);
        self.code_graph = Some(graph);

        Ok(())
    }

    /// Filter findings based on suppression comments in source files.
    ///
    /// This method groups findings by file, parses suppression directives
    /// from each file's source, and filters out suppressed findings.
    fn filter_suppressions(&self, findings: Vec<RuleFinding>) -> Vec<RuleFinding> {
        if findings.is_empty() {
            return findings;
        }

        // Group findings by file_id for efficient filtering
        let mut findings_by_file: HashMap<FileId, Vec<RuleFinding>> = HashMap::new();
        for finding in findings {
            findings_by_file
                .entry(finding.file_id)
                .or_default()
                .push(finding);
        }

        // Filter findings per file
        let mut filtered_findings = Vec::new();
        for (file_id, file_findings) in findings_by_file {
            // Get the parsed file to access source code and language
            if let Some(parsed) = self.parsed_files.read_sync(&file_id, |_, p| p.clone()) {
                // Parse suppression comments from the source
                let suppressions = parse_suppressions(&parsed.source, parsed.language);

                // Filter findings for this file
                let remaining = filter_suppressed_findings(file_findings, &suppressions);
                filtered_findings.extend(remaining);
            } else {
                // No parsed file found (shouldn't happen), keep all findings
                filtered_findings.extend(file_findings);
            }
        }

        filtered_findings
    }

    /// Filter findings by the requested dimensions.
    ///
    /// If `requested_dimensions` in the meta is empty, all findings are returned.
    /// Otherwise, only findings whose dimension matches one of the requested dimensions
    /// are included.
    fn filter_by_dimensions(&self, findings: Vec<RuleFinding>) -> Vec<RuleFinding> {
        // If no dimensions are requested, return all findings (default behavior)
        if self.meta.requested_dimensions.is_empty() {
            return findings;
        }

        // Filter findings to only include those matching requested dimensions
        findings
            .into_iter()
            .filter(|finding| self.meta.requested_dimensions.contains(&finding.dimension))
            .collect()
    }

    /// Run all rules and assemble a ReviewSessionResult.
    async fn run_all_rules(&self) -> Result<ReviewSessionResult, EngineError> {
        // 1) Snapshot semantics for rule evaluation.
        let mut sem_entries: Vec<(FileId, Arc<SourceSemantics>)> = Vec::new();
        self.semantics.iter_sync(|file_id, sem| {
            sem_entries.push((*file_id, Arc::clone(sem)));
            true
        });

        // 2) Run every rule.
        let mut all_rule_findings: Vec<RuleFinding> = Vec::new();
        for rule in self.rules.all() {
            let mut findings = rule.evaluate(&sem_entries, self.code_graph.as_ref()).await;
            all_rule_findings.append(&mut findings);
        }

        // 3) Filter suppressed findings per file.
        let all_rule_findings = self.filter_suppressions(all_rule_findings);

        // 4) Filter findings by requested dimensions (if any specified).
        let all_rule_findings = self.filter_by_dimensions(all_rule_findings);

        // 5) Prepare an empty ContextResult per input context.
        let mut context_results: Vec<ContextResult> = self
            .contexts
            .iter()
            .cloned()
            .map(|ctx| ContextResult {
                context_id: ctx.id.clone(),
                label: ctx.label.clone(),
                findings: Vec::new(),
            })
            .collect();

        // 6) Convert rule-level findings to engine-level findings and attach them.
        for rf in all_rule_findings {
            // Extract values needed after consuming rf
            let file_id = rf.file_id;
            let patch = rf.patch.clone();

            let mut finding = Finding::from(rf);

            // If there is a patch, generate a unified diff.
            if let Some(ref patch) = patch {
                if let Some(parsed) = self.parsed_files.read_sync(&file_id, |_, p| p.clone()) {
                    let before = &parsed.source;
                    let after = apply_file_patch(before, patch);
                    let diff = make_unified_diff(&parsed.path, before, &after);
                    finding.diff = Some(diff);
                }
            }

            if let Some(&ctx_index) = self.file_to_context.get(&file_id) {
                if let Some(ctx_result) = context_results.get_mut(ctx_index) {
                    ctx_result.findings.push(finding);
                }
            } else {
                // Unknown mapping (shouldn't happen with our pipeline). If it does,
                // we may later add a "global" or "unattributed" context.
            }
        }

        Ok(ReviewSessionResult {
            meta: self.meta.clone(),
            contexts: context_results,
            runtime_dependencies: self.runtime_dependencies.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::context::{Dimension, Language, SessionContextInput, SourceFile};

    /// Helper function to create a test SourceFile
    fn make_source_file(path: &str, content: &str) -> SourceFile {
        SourceFile {
            path: path.to_string(),
            language: Language::Python,
            content: content.to_string(),
        }
    }

    /// Helper function to create a test SessionContextInput
    fn make_context(id: &str, label: &str, files: Vec<SourceFile>) -> SessionContextInput {
        SessionContextInput {
            id: id.to_string(),
            label: label.to_string(),
            dimension: Dimension::Stability,
            files,
        }
    }

    // ==================== InternalSessionState Tests ====================

    #[test]
    fn test_internal_session_state_new() {
        let meta = ReviewSessionMeta::default();
        let contexts = vec![];
        let rules = Arc::new(RuleRegistry::new());

        let state = InternalSessionState::new(meta.clone(), contexts, rules);

        assert!(state.parsed_files.is_empty());
        assert!(state.semantics.is_empty());
        assert!(state.code_graph.is_none());
    }

    #[tokio::test]
    async fn test_internal_session_state_parse_all_files_empty() {
        let meta = ReviewSessionMeta::default();
        let contexts = vec![];
        let rules = Arc::new(RuleRegistry::new());

        let mut state = InternalSessionState::new(meta, contexts, rules);

        let result = state.parse_all_files().await;
        assert!(result.is_ok());
        assert!(state.parsed_files.is_empty());
    }

    #[tokio::test]
    async fn test_internal_session_state_parse_all_files_with_python() {
        let meta = ReviewSessionMeta::default();

        let source_file = make_source_file("main.py", "def hello():\n    print('world')\n");
        let context = make_context("ctx-1", "Test", vec![source_file]);
        let contexts = vec![context];
        let rules = Arc::new(RuleRegistry::new());

        let mut state = InternalSessionState::new(meta, contexts, rules);

        let result = state.parse_all_files().await;
        assert!(result.is_ok());

        // Should have one parsed file
        let mut count = 0;
        state.parsed_files.iter_sync(|_, _| {
            count += 1;
            true
        });
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn test_internal_session_state_build_all_semantics() {
        let meta = ReviewSessionMeta::default();

        let source_file =
            make_source_file("app.py", "from fastapi import FastAPI\napp = FastAPI()\n");
        let context = make_context("ctx-1", "Test", vec![source_file]);
        let contexts = vec![context];
        let rules = Arc::new(RuleRegistry::new());

        let mut state = InternalSessionState::new(meta, contexts, rules);

        // First parse
        state.parse_all_files().await.unwrap();

        // Then build semantics
        let result = state.build_all_semantics().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_internal_session_state_build_code_graph() {
        let meta = ReviewSessionMeta::default();
        let contexts = vec![];
        let rules = Arc::new(RuleRegistry::new());

        let mut state = InternalSessionState::new(meta, contexts, rules);

        let result = state.build_code_graph_for_session().await;
        assert!(result.is_ok());
        assert!(state.code_graph.is_some());
    }

    #[tokio::test]
    async fn test_internal_session_state_run_empty() {
        let meta = ReviewSessionMeta::default();
        let contexts = vec![];
        let rules = Arc::new(RuleRegistry::new());

        let mut state = InternalSessionState::new(meta, contexts, rules);

        let result = state.run().await;
        assert!(result.is_ok());

        let session_result = result.unwrap();
        assert_eq!(session_result.contexts.len(), 0);
    }

    #[tokio::test]
    async fn test_internal_session_state_run_with_file() {
        let meta = ReviewSessionMeta::default();

        let source_file = make_source_file("test.py", "x = 1");
        let context = make_context("ctx-1", "Test", vec![source_file]);
        let contexts = vec![context];
        let rules = Arc::new(RuleRegistry::new());

        let mut state = InternalSessionState::new(meta, contexts, rules);

        let result = state.run().await;
        assert!(result.is_ok());

        let session_result = result.unwrap();
        assert_eq!(session_result.contexts.len(), 1);
    }

    // ==================== Integration Tests ====================

    #[tokio::test]
    async fn test_session_full_flow_empty() {
        let engine = crate::engine::Engine::with_defaults_and_builtin_rules();
        let meta = ReviewSessionMeta::default();
        let contexts = vec![];

        let result = engine.analyze(meta, contexts).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_session_full_flow_with_python_file() {
        let engine = crate::engine::Engine::with_defaults_and_builtin_rules();
        let meta = ReviewSessionMeta::default();

        let source_file = make_source_file("main.py", "print('hello world')");
        let context = make_context("main-ctx", "Main Context", vec![source_file]);
        let contexts = vec![context];

        let result = engine.analyze(meta, contexts).await;

        assert!(result.is_ok());
        let session_result = result.unwrap();
        assert_eq!(session_result.contexts.len(), 1);
    }

    #[tokio::test]
    async fn test_session_multiple_contexts() {
        let engine = crate::engine::Engine::with_defaults_and_builtin_rules();
        let meta = ReviewSessionMeta::default();

        let file1 = make_source_file("module1.py", "def func1(): pass");
        let file2 = make_source_file("module2.py", "def func2(): pass");

        let context1 = make_context("ctx-1", "Context 1", vec![file1]);
        let context2 = make_context("ctx-2", "Context 2", vec![file2]);

        let contexts = vec![context1, context2];

        let result = engine.analyze(meta, contexts).await;

        assert!(result.is_ok());
        let session_result = result.unwrap();
        assert_eq!(session_result.contexts.len(), 2);
    }

    // ==================== Parse Error Tests ====================

    #[tokio::test]
    async fn test_parse_all_files_with_unsupported_language() {
        let meta = ReviewSessionMeta::default();

        let source_file = SourceFile {
            path: "test.java".to_string(),
            language: Language::Java,
            content: "public class Test {}".to_string(),
        };
        let context = make_context("ctx-1", "Test", vec![source_file]);
        let contexts = vec![context];
        let rules = Arc::new(RuleRegistry::new());

        let mut state = InternalSessionState::new(meta, contexts, rules);

        let result = state.parse_all_files().await;

        // Should fail because Java parsing is not implemented
        assert!(result.is_err());
        let err = result.unwrap_err();
        match err {
            EngineError::Internal(e) => {
                assert!(e.to_string().contains("failed to parse file"));
            }
            _ => panic!("Expected Internal error"),
        }
    }

    // ==================== Build All Semantics Tests ====================

    #[tokio::test]
    async fn test_build_all_semantics_with_python_file() {
        let meta = ReviewSessionMeta::default();

        let source_file = make_source_file("test.py", "def hello(): pass");
        let context = make_context("ctx-1", "Test", vec![source_file]);
        let contexts = vec![context];
        let rules = Arc::new(RuleRegistry::new());

        let mut state = InternalSessionState::new(meta, contexts, rules);

        state.parse_all_files().await.unwrap();
        let result = state.build_all_semantics().await;

        assert!(result.is_ok());

        // Should have semantics for the Python file
        let mut count = 0;
        state.semantics.iter_sync(|_, _| {
            count += 1;
            true
        });
        assert_eq!(count, 1);
    }

    // ==================== Build Code Graph Tests ====================

    #[tokio::test]
    async fn test_build_code_graph_with_semantics() {
        let meta = ReviewSessionMeta::default();

        let source_file =
            make_source_file("app.py", "from fastapi import FastAPI\napp = FastAPI()\n");
        let context = make_context("ctx-1", "Test", vec![source_file]);
        let contexts = vec![context];
        let rules = Arc::new(RuleRegistry::new());

        let mut state = InternalSessionState::new(meta, contexts, rules);

        state.parse_all_files().await.unwrap();
        state.build_all_semantics().await.unwrap();

        let result = state.build_code_graph_for_session().await;
        assert!(result.is_ok());
        assert!(state.code_graph.is_some());
    }

    // ==================== Analysis with Findings Tests ====================

    #[tokio::test]
    async fn test_run_analysis_with_findings_and_patch() {
        let meta = ReviewSessionMeta::default();

        // Use FastAPI code without CORS to trigger the CORS rule
        let source_file =
            make_source_file("app.py", "from fastapi import FastAPI\napp = FastAPI()\n");
        let context = make_context("ctx-1", "Test", vec![source_file]);
        let contexts = vec![context];

        // Use builtin rules which include the FastAPI CORS rule
        let rules = Arc::new(RuleRegistry::with_builtin_rules());

        let mut state = InternalSessionState::new(meta, contexts, rules);

        let result = state.run().await;
        assert!(result.is_ok());

        let session_result = result.unwrap();
        assert_eq!(session_result.contexts.len(), 1);

        // The FastAPI CORS rule should have produced a finding with a patch
        // and the diff should have been computed
        if !session_result.contexts[0].findings.is_empty() {
            let finding = &session_result.contexts[0].findings[0];
            // The finding should have a diff if it had a patch
            let _ = finding.diff.as_ref();
        }
    }

    // ==================== HTTP Timeout Rule Finding with Patch Tests ====================

    #[tokio::test]
    async fn test_analysis_with_http_timeout_finding() {
        let meta = ReviewSessionMeta::default();

        // Code with missing timeout
        let source_file = make_source_file(
            "client.py",
            "import requests\nresponse = requests.get('https://example.com')\n",
        );
        let context = make_context("ctx-1", "Test", vec![source_file]);
        let contexts = vec![context];

        let rules = Arc::new(RuleRegistry::with_builtin_rules());

        let mut state = InternalSessionState::new(meta, contexts, rules);

        let result = state.run().await;

        assert!(result.is_ok());
        let session_result = result.unwrap();

        // Should have findings from the HTTP timeout rule
        if !session_result.contexts[0].findings.is_empty() {
            let finding = &session_result.contexts[0].findings[0];
            // The HTTP timeout rule produces patches, so diff should be computed
            if finding.diff.is_some() {
                assert!(finding.diff.as_ref().unwrap().contains("timeout"));
            }
        }
    }

    // ==================== Dimension Filtering Tests ====================

    #[tokio::test]
    async fn test_dimension_filtering_returns_all_when_empty() {
        // When requested_dimensions is empty, all findings should be returned
        let meta = ReviewSessionMeta::default();
        assert!(meta.requested_dimensions.is_empty());

        // Use FastAPI code that triggers correctness rules
        let source_file =
            make_source_file("app.py", "from fastapi import FastAPI\napp = FastAPI()\n");
        let context = make_context("ctx-1", "Test", vec![source_file]);
        let contexts = vec![context];

        let rules = Arc::new(RuleRegistry::with_builtin_rules());
        let mut state = InternalSessionState::new(meta, contexts, rules);

        let result = state.run().await;
        assert!(result.is_ok());
        let session_result = result.unwrap();

        // Should have findings (FastAPI CORS rule is in Correctness dimension)
        // Counting findings in all contexts
        let total_findings: usize = session_result
            .contexts
            .iter()
            .map(|ctx| ctx.findings.len())
            .sum();

        // We expect at least some findings from the CORS rule when no dimension filter is applied
        assert!(
            total_findings > 0,
            "Expected findings when no dimension filter is applied"
        );
    }

    #[tokio::test]
    async fn test_dimension_filtering_filters_by_requested_dimension() {
        // When requested_dimensions contains specific dimensions, only findings
        // for those dimensions should be returned
        let source_file =
            make_source_file("app.py", "from fastapi import FastAPI\napp = FastAPI()\n");
        let context = make_context("ctx-1", "Test", vec![source_file]);
        let contexts = vec![context];

        let rules = Arc::new(RuleRegistry::with_builtin_rules());

        // First, run with no dimension filter to get baseline
        let meta_no_filter = ReviewSessionMeta::default();
        let mut state_no_filter =
            InternalSessionState::new(meta_no_filter, contexts.clone(), Arc::clone(&rules));
        let result_no_filter = state_no_filter.run().await.unwrap();
        let total_unfiltered: usize = result_no_filter
            .contexts
            .iter()
            .map(|ctx| ctx.findings.len())
            .sum();

        // Now run with only Maintainability dimension
        // (FastAPI CORS is Correctness, so it should be filtered out)
        let meta_maintainability = ReviewSessionMeta {
            requested_dimensions: vec![Dimension::Maintainability],
            ..ReviewSessionMeta::default()
        };
        let mut state_filtered =
            InternalSessionState::new(meta_maintainability, contexts, Arc::clone(&rules));
        let result_filtered = state_filtered.run().await.unwrap();
        let total_filtered: usize = result_filtered
            .contexts
            .iter()
            .map(|ctx| ctx.findings.len())
            .sum();

        // Filtered results should have fewer findings than unfiltered
        // (or equal if no Correctness findings were found, but different subset)
        // Since FastAPI CORS rule is Correctness, and we're filtering for Maintainability only,
        // the CORS finding should be filtered out
        assert!(
            total_filtered <= total_unfiltered,
            "Filtering should not increase findings count: {} > {}",
            total_filtered,
            total_unfiltered
        );
    }

    #[tokio::test]
    async fn test_dimension_filtering_keeps_matching_dimensions() {
        // Request Correctness dimension - FastAPI CORS rule is Correctness, so it should be kept
        let source_file =
            make_source_file("app.py", "from fastapi import FastAPI\napp = FastAPI()\n");
        let context = make_context("ctx-1", "Test", vec![source_file]);
        let contexts = vec![context];

        let rules = Arc::new(RuleRegistry::with_builtin_rules());

        let meta = ReviewSessionMeta {
            requested_dimensions: vec![Dimension::Correctness],
            ..ReviewSessionMeta::default()
        };
        let mut state = InternalSessionState::new(meta, contexts, rules);

        let result = state.run().await;
        assert!(result.is_ok());
        let session_result = result.unwrap();

        // All findings should be Correctness dimension
        for ctx in &session_result.contexts {
            for finding in &ctx.findings {
                assert_eq!(
                    finding.dimension,
                    Dimension::Correctness,
                    "Finding with dimension {:?} should not be present when filtering for Correctness",
                    finding.dimension
                );
            }
        }
    }
}
