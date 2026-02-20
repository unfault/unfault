//! Intermediate Representation (IR) functions for client-side parsing.
//!
//! This module provides the interface for the client-side parsing architecture where:
//! 1. The CLI parses code locally and builds the graph (`build_ir`)
//! 2. The serialized IR is sent to the API
//! 3. The API runs rules on the IR (`analyze_ir`)
//!
//! ## Data Flow
//!
//! ```text
//! CLI: files -> build_ir() -> (semantics, graph) -> serialize -> network
//! API: deserialize -> analyze_ir(semantics, graph) -> findings
//! ```
//!
//! ## Benefits
//!
//! - No source code sent over the wire (only IR)
//! - Parsing work offloaded to the client
//! - Faster API responses
//! - Cross-file analysis via the graph

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::EngineError;
use crate::graph::{CodeGraph, build_code_graph};
use crate::parse::{self, ast::FileId};
use crate::profiles::ProfileRegistry;
use crate::rules::finding::RuleFinding;
use crate::rules::registry::RuleRegistry;
use crate::semantics::{SourceSemantics, build_source_semantics};
use crate::types::context::SourceFile;

/// The intermediate representation containing semantics and code graph.
///
/// This struct is serializable and can be sent over the wire to the API
/// for rule evaluation without sending source code.
///
/// Note: This struct mirrors `unfault_core::IntermediateRepresentation`.
/// The CLI uses the core crate version, and the engine deserializes it here.
/// SourceSemantics already contains file_id internally, so no wrapper is needed.
#[derive(Debug, Serialize, Deserialize)]
pub struct IntermediateRepresentation {
    /// Per-file semantics containing parsed information about each source file.
    pub semantics: Vec<SourceSemantics>,
    /// The code graph built from semantics
    pub graph: CodeGraph,
}

impl IntermediateRepresentation {
    /// Rebuild internal indexes after deserialization.
    ///
    /// This must be called after deserializing an IR to restore
    /// the quick-lookup HashMaps in the CodeGraph.
    pub fn rebuild_indexes(&mut self) {
        self.graph.rebuild_indexes();
    }
}

/// Build the intermediate representation from source files.
///
/// This function:
/// 1. Parses all source files
/// 2. Builds language-agnostic semantics
/// 3. Constructs the code graph
///
/// The resulting IR can be serialized and sent to the API for rule evaluation.
///
/// # Arguments
///
/// * `files` - Source files to process
///
/// # Returns
///
/// * `Ok(IntermediateRepresentation)` - The IR ready for serialization
/// * `Err(EngineError)` - If parsing or semantics building fails
///
/// # Example
///
/// ```ignore
/// use unfault_engine::ir::build_ir;
/// use unfault_engine::types::context::{Language, SourceFile};
///
/// let files = vec![
///     SourceFile {
///         path: "main.py".to_string(),
///         language: Language::Python,
///         content: "import requests".to_string(),
///     }
/// ];
///
/// let ir = build_ir(files)?;
/// let serialized = serde_json::to_vec(&ir)?;
/// // Send serialized to API...
/// ```
pub fn build_ir(files: Vec<SourceFile>) -> Result<IntermediateRepresentation, EngineError> {
    let mut next_id: u64 = 1;
    let mut semantics_list = Vec::new();
    let mut sem_entries = Vec::new();

    // Parse all files and build semantics
    for file in files {
        let file_id = FileId(next_id);
        next_id += 1;

        // Parse the file
        let parsed = parse::parse_source_file(file_id, &file).map_err(|e| {
            EngineError::Internal(anyhow::anyhow!("Failed to parse file {}: {}", file.path, e))
        })?;

        // Build semantics
        if let Some(sem) = build_source_semantics(&parsed).map_err(|e| {
            EngineError::Internal(anyhow::anyhow!(
                "Failed to build semantics for {}: {}",
                file.path,
                e
            ))
        })? {
            let sem_arc = Arc::new(sem.clone());
            sem_entries.push((file_id, sem_arc));
            // Store SourceSemantics directly - it already contains file_id internally
            semantics_list.push(sem);
        }
    }

    // Build the code graph
    let graph = build_code_graph(&sem_entries);

    Ok(IntermediateRepresentation {
        semantics: semantics_list,
        graph,
    })
}

/// Analyze the intermediate representation and return findings.
///
/// This function runs all applicable rules against the pre-computed
/// semantics and graph. It's called by the API after receiving
/// the serialized IR from the client.
///
/// # Arguments
///
/// * `ir` - The intermediate representation (must call `rebuild_indexes()` after deserialization)
/// * `rules` - The rule registry to use
///
/// # Returns
///
/// * A vector of rule findings
///
/// # Example
///
/// ```ignore
/// use unfault_engine::ir::{analyze_ir, IntermediateRepresentation};
/// use unfault_engine::rules::registry::RuleRegistry;
///
/// // Deserialize IR from client
/// let mut ir: IntermediateRepresentation = serde_json::from_slice(&data)?;
/// ir.rebuild_indexes();
///
/// let rules = RuleRegistry::with_builtin_rules();
/// let findings = analyze_ir(&ir, &rules).await;
/// ```
pub async fn analyze_ir(ir: &IntermediateRepresentation, rules: &RuleRegistry) -> Vec<RuleFinding> {
    // Build sem_entries for rule evaluation
    // SourceSemantics has file_id() method to get the FileId
    let sem_entries: Vec<(FileId, Arc<SourceSemantics>)> = ir
        .semantics
        .iter()
        .map(|sem| (sem.file_id(), Arc::new(sem.clone())))
        .collect();

    // Run all rules
    let mut all_findings = Vec::new();
    for rule in rules.all() {
        let mut findings = rule.evaluate(&sem_entries, Some(&ir.graph)).await;
        all_findings.append(&mut findings);
    }

    all_findings
}

/// Analyze IR with a specific set of rules (by rule ID).
///
/// This is the preferred method for profile-based analysis:
/// 1. Client creates a session with advertised profiles
/// 2. Server resolves profiles and returns rule IDs
/// 3. Client builds IR and sends to server
/// 4. Server calls this method with the resolved rule IDs
///
/// # Arguments
///
/// * `ir` - The intermediate representation
/// * `rules` - The full rule registry
/// * `rule_ids` - The rule IDs to run (from resolved profiles)
///
/// # Returns
///
/// * A vector of rule findings
pub async fn analyze_ir_with_rules(
    ir: &IntermediateRepresentation,
    rules: &RuleRegistry,
    rule_ids: &[String],
) -> Vec<RuleFinding> {
    let filtered = rules.filter_by_ids(rule_ids);
    analyze_ir(ir, &filtered).await
}

/// Get the rule IDs for a set of profiles.
///
/// This helper resolves profile names to their constituent rule IDs,
/// enabling the client to know which rules will be run.
///
/// # Arguments
///
/// * `profiles` - The profile registry
/// * `profile_names` - Names of profiles to resolve
///
/// # Returns
///
/// * A vector of rule IDs from all matched profiles
pub fn resolve_profile_rules(profiles: &ProfileRegistry, profile_names: &[String]) -> Vec<String> {
    let mut rule_ids = Vec::new();

    for name in profile_names {
        if let Some(profile) = profiles.get(name) {
            rule_ids.extend(profile.rule_ids.clone());
        }
    }

    // Deduplicate while preserving order
    let mut seen = std::collections::HashSet::new();
    rule_ids.retain(|id| seen.insert(id.clone()));

    rule_ids
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::context::Language;

    #[test]
    fn test_build_ir_empty_files() {
        let result = build_ir(vec![]);
        assert!(result.is_ok());
        let ir = result.unwrap();
        assert!(ir.semantics.is_empty());
        assert_eq!(ir.graph.stats().total_nodes, 0);
    }

    #[test]
    fn test_build_ir_single_python_file() {
        let files = vec![SourceFile {
            path: "main.py".to_string(),
            language: Language::Python,
            content: "import requests\nx = 1".to_string(),
        }];

        let result = build_ir(files);
        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.semantics.len(), 1);
        assert!(ir.graph.stats().file_count >= 1);
    }

    #[test]
    fn test_build_ir_multiple_files() {
        let files = vec![
            SourceFile {
                path: "main.py".to_string(),
                language: Language::Python,
                content: "from lib import helper".to_string(),
            },
            SourceFile {
                path: "lib.py".to_string(),
                language: Language::Python,
                content: "def helper(): pass".to_string(),
            },
        ];

        let result = build_ir(files);
        assert!(result.is_ok());
        let ir = result.unwrap();
        assert_eq!(ir.semantics.len(), 2);
        assert_eq!(ir.graph.stats().file_count, 2);
    }

    #[test]
    fn test_ir_serialization_roundtrip() {
        let files = vec![SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: "import os\ndef hello(): pass".to_string(),
        }];

        let ir = build_ir(files).unwrap();

        // Serialize
        let serialized = serde_json::to_string(&ir).expect("serialization should succeed");

        // Deserialize
        let mut deserialized: IntermediateRepresentation =
            serde_json::from_str(&serialized).expect("deserialization should succeed");

        // Rebuild indexes
        deserialized.rebuild_indexes();

        // Verify structure is preserved
        assert_eq!(ir.semantics.len(), deserialized.semantics.len());
        assert_eq!(
            ir.graph.stats().total_nodes,
            deserialized.graph.stats().total_nodes
        );
    }

    #[tokio::test]
    async fn test_analyze_ir_empty() {
        let ir = IntermediateRepresentation {
            semantics: vec![],
            graph: CodeGraph::new(),
        };
        let rules = RuleRegistry::new();

        let findings = analyze_ir(&ir, &rules).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn test_analyze_ir_with_rules() {
        let files = vec![SourceFile {
            path: "main.py".to_string(),
            language: Language::Python,
            content: "import requests\nrequests.get('http://example.com')".to_string(),
        }];

        let ir = build_ir(files).unwrap();
        let rules = RuleRegistry::with_builtin_rules();

        // Run with all rules
        let findings = analyze_ir(&ir, &rules).await;
        // May or may not have findings depending on rule implementations
        let _ = findings;
    }

    #[test]
    fn test_resolve_profile_rules() {
        let profiles = ProfileRegistry::with_builtin_profiles();

        let rule_ids = resolve_profile_rules(&profiles, &["stability".to_string()]);
        // Should have some rules from the stability profile
        // The actual rules depend on the profile configuration
        let _ = rule_ids;
    }

    #[test]
    fn test_resolve_profile_rules_deduplicates() {
        let profiles = ProfileRegistry::with_builtin_profiles();

        // Request overlapping profiles
        let rule_ids = resolve_profile_rules(
            &profiles,
            &["stability".to_string(), "correctness".to_string()],
        );

        // Check for uniqueness
        let unique: std::collections::HashSet<_> = rule_ids.iter().collect();
        assert_eq!(unique.len(), rule_ids.len());
    }
}
