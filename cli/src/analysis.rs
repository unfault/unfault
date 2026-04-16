//! Local analysis bridge.
//!
//! Bridges the CLI's IR (built by unfault-core) with the analysis engine
//! (unfault-analysis). Replaces the old API call to `/api/v1/graph/analyze`.

use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};

use unfault_analysis::suppression::{filter_suppressed_findings, parse_suppressions};
use unfault_analysis::types::finding::Finding;

use crate::output::{IrAnalyzeResponse, IrFinding, IrGraphStats, IrSystemHazard};

/// Run analysis locally on a serialized IR.
///
/// This replaces the old `api_client.analyze_ir()` call. The flow is:
/// 1. Deserialize the IR JSON (from unfault-core format)
/// 2. Rebuild graph indexes
/// 3. Resolve profiles to rule IDs
/// 4. Run matching rules against the IR
/// 5. Convert findings to the CLI's display format
pub async fn analyze_ir_locally(
    ir_json: String,
    profiles: &[String],
    workspace_path: Option<&Path>,
) -> Result<IrAnalyzeResponse> {
    let start = Instant::now();

    // Step 1: Deserialize IR (analysis crate's format is compatible via JSON)
    let mut ir: unfault_analysis::ir::IntermediateRepresentation =
        serde_json::from_str(&ir_json).context("Failed to deserialize IR for analysis")?;

    // Step 2: Rebuild indexes (needed after deserialization)
    ir.rebuild_indexes();

    let file_count = ir.semantics.len() as i32;

    // Step 3: Resolve profiles to rule IDs and run rules
    let profile_registry = unfault_analysis::profiles::ProfileRegistry::with_builtin_profiles();
    let rule_registry = unfault_analysis::rules::registry::RuleRegistry::with_builtin_rules();

    let rule_ids: Vec<String> = if profiles.is_empty() {
        // No profiles specified: run all rules
        rule_registry
            .all()
            .iter()
            .map(|r| r.id().to_string())
            .collect()
    } else {
        // Resolve profile IDs to rule IDs
        let resolved = unfault_analysis::ir::resolve_profile_rules(&profile_registry, profiles);
        if resolved.is_empty() {
            // Fallback: if no profiles matched, run all rules
            rule_registry
                .all()
                .iter()
                .map(|r| r.id().to_string())
                .collect()
        } else {
            resolved
        }
    };

    // Step 4: Run rules
    let rule_findings =
        unfault_analysis::ir::analyze_ir_with_rules(&ir, &rule_registry, &rule_ids).await;

    let elapsed_ms = start.elapsed().as_millis() as i64;

    // Step 5a: Apply suppression comments from source files.
    // The IR path bypasses InternalSessionState's filter_suppressions(), so we
    // re-apply it here using the workspace path to read source files.
    let rule_findings = if let Some(ws) = workspace_path {
        apply_suppressions_from_disk(rule_findings, ws)
    } else {
        rule_findings
    };

    // Step 5b: Convert RuleFindings → Findings (needed for SRE synthesis).
    let findings: Vec<Finding> = rule_findings.into_iter().map(Finding::from).collect();

    // Step 5b: SRE synthesis (Pass 3) — enrich findings with blast radius.
    let sem_entries: Vec<(
        unfault_analysis::FileId,
        std::sync::Arc<unfault_analysis::SourceSemantics>,
    )> = ir
        .semantics
        .iter()
        .map(|s| (s.file_id(), std::sync::Arc::new(s.clone())))
        .collect();
    let system_hazards_raw = unfault_analysis::sre::synthesize(&findings, &sem_entries, &ir.graph);

    // Step 5c: Convert Findings → IrFindings.
    let ir_findings: Vec<IrFinding> = findings
        .iter()
        .map(|f| {
            let patch_json = None::<String>; // patches handled by PatchApplier, not here
            IrFinding {
                rule_id: f.rule_id.clone(),
                title: f.title.clone(),
                description: f.description.clone(),
                severity: format!("{:?}", f.severity),
                dimension: format!("{:?}", f.dimension),
                file_path: f.file_path.clone(),
                line: f.line.unwrap_or(0),
                column: f.column.unwrap_or(0),
                end_line: f.end_line,
                end_column: f.end_column,
                message: String::new(),
                patch_json,
                fix_preview: f.fix_preview.clone(),
                patch: None,
                byte_start: f.byte_range.map(|(s, _)| s),
                byte_end: f.byte_range.map(|(_, e)| e),
            }
        })
        .collect();

    // Build a lookup from finding_id → finding title for the system view.
    let finding_titles: std::collections::HashMap<String, String> = findings
        .iter()
        .map(|f| {
            let key = format!("{}:{}:{}", f.rule_id, f.file_path, f.line.unwrap_or(0));
            (key, f.title.clone())
        })
        .collect();

    // Step 5d: Convert SystemHazards → IrSystemHazards.
    let ir_hazards: Vec<IrSystemHazard> = system_hazards_raw
        .into_iter()
        .map(|h| {
            let finding_title = finding_titles
                .get(&h.finding_id)
                .cloned()
                .unwrap_or_default();
            IrSystemHazard {
                glossary_id: h.glossary_id,
                aka: h.aka,
                file_path: h.file_path,
                line: h.line.unwrap_or(0),
                effective_severity: format!("{:?}", h.effective_severity),
                one_line_impact: h.one_line_impact,
                destruction_path: h.destruction_path,
                finding_id: h.finding_id,
                // World Model fields
                aggregate_risk: h.propagation.aggregate_risk,
                macro_goal: h.propagation.macro_goal,
                anchored_to_slo: h.propagation.anchored_to_slo,
                // Tradeoff fields
                tradeoff_gain: h.tradeoff.gain,
                tradeoff_risk: h.tradeoff.risk,
                finding_title,
            }
        })
        .collect();

    // Build graph stats from the IR
    let total_nodes = ir.graph.graph.node_count() as i32;
    let total_edges = ir.graph.graph.edge_count() as i32;
    let graph_stats = Some(IrGraphStats {
        file_count: ir.graph.file_nodes.len() as i32,
        function_count: ir.graph.function_nodes.len() as i32,
        class_count: ir.graph.class_nodes.len() as i32,
        external_module_count: ir.graph.external_modules.len() as i32,
        import_edge_count: 0,
        contains_edge_count: 0,
        uses_library_edge_count: 0,
        total_nodes,
        total_edges,
    });

    Ok(IrAnalyzeResponse {
        findings: ir_findings,
        system_hazards: ir_hazards,
        file_count,
        elapsed_ms,
        graph_stats,
    })
}

/// Apply suppression comments by reading source files from disk.
///
/// Groups findings by file path, reads each file once, parses its suppression
/// comments, and filters out suppressed findings. Files that cannot be read
/// are silently skipped (findings kept).
fn apply_suppressions_from_disk(
    findings: Vec<unfault_analysis::rules::finding::RuleFinding>,
    workspace_path: &Path,
) -> Vec<unfault_analysis::rules::finding::RuleFinding> {
    if findings.is_empty() {
        return findings;
    }

    use unfault_analysis::types::context::Language;

    // Read each unique file once.
    let mut source_cache: HashMap<String, (String, Language)> = HashMap::new();

    // Collect unique file paths and detect language.
    for finding in &findings {
        if source_cache.contains_key(&finding.file_path) {
            continue;
        }
        let full_path = workspace_path.join(&finding.file_path);
        // unfault-ignore: rust.io_in_hot_path — deduplicated by source_cache above
        if let Ok(src) = std::fs::read_to_string(&full_path) {
            // Infer language from extension.
            let lang = match full_path.extension().and_then(|e| e.to_str()).unwrap_or("") {
                "py" => Language::Python,
                "rs" => Language::Rust,
                "go" => Language::Go,
                "ts" | "tsx" => Language::Typescript,
                "js" | "jsx" => Language::Javascript,
                _ => Language::Rust, // fallback
            };
            source_cache.insert(finding.file_path.clone(), (src, lang));
        }
    }

    // Group findings by file.
    let mut by_file: HashMap<String, Vec<unfault_analysis::rules::finding::RuleFinding>> =
        HashMap::new();
    for finding in findings {
        by_file
            .entry(finding.file_path.clone())
            .or_default()
            .push(finding);
    }

    // Filter each group.
    let mut result = Vec::new();
    for (file_path, file_findings) in by_file {
        if let Some((source, language)) = source_cache.get(&file_path) {
            let suppressions = parse_suppressions(source, *language);
            let kept = filter_suppressed_findings(file_findings, &suppressions);
            result.extend(kept);
        } else {
            result.extend(file_findings);
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_analyze_empty_ir() {
        // Build a minimal valid IR JSON
        let ir_json = serde_json::json!({
            "semantics": [],
            "graph": {
                "graph": {
                    "nodes": [],
                    "node_holes": [],
                    "edge_property": "directed",
                    "edges": []
                }
            }
        });

        let result = analyze_ir_locally(ir_json.to_string(), &[], None).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.file_count, 0);
        assert!(response.findings.is_empty());
    }
}
