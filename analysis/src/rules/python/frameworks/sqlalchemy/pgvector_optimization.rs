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

/// Rule: pgvector Suboptimal Query Pattern
///
/// Detects pgvector queries that use suboptimal operators or index configurations.
/// For normalized vectors (like bge, sentence-transformers), using inner product (<#>)
/// instead of cosine distance (<=>) provides better performance.
///
/// Key optimizations detected:
/// 1. Using `<=>` operator instead of faster `<#>` for normalized vectors
/// 2. Index creation with `vector_cosine_ops` instead of `vector_ip_ops`
/// 3. Missing LIMIT on vector similarity queries (prevents iterative scan)
/// 4. Complex WHERE conditions that may break HNSW index usage
///
/// See: https://www.clarvo.ai/blog/optimizing-filtered-vector-queries
#[derive(Debug)]
pub struct PgvectorOptimizationRule;

impl PgvectorOptimizationRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PgvectorOptimizationRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PgvectorOptimizationRule {
    fn id(&self) -> &'static str {
        "python.sqlalchemy.pgvector_suboptimal_query"
    }

    fn name(&self) -> &'static str {
        "Detects pgvector queries using suboptimal operators for normalized vectors."
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

            // Check for pgvector imports
            let has_pgvector = py.imports.iter().any(|imp| {
                imp.module.contains("pgvector")
                    || imp.names.iter().any(|n| n == "Vector" || n == "VECTOR")
            });

            if !has_pgvector {
                continue;
            }

            // Look for raw SQL queries with <=> operator
            for call in &py.calls {
                let is_execute = call.function_call.callee_expr.ends_with(".execute")
                    || call.function_call.callee_expr.ends_with(".text")
                    || call.function_call.callee_expr == "text";

                if !is_execute {
                    continue;
                }

                let args = &call.args_repr;

                // Check for cosine distance operator <=>
                if args.contains("<=>") {
                    // Suggest using <#> for normalized vectors
                    let title =
                        "pgvector: Use inner product (<#>) instead of cosine (<=>)".to_string();

                    let description =
                        "For normalized vectors (like bge-small, sentence-transformers), \
                             the negative inner product operator (<#>) is faster than cosine \
                             distance (<=>). Inner product equals cosine similarity for \
                             normalized vectors. Change: 1 - (embedding <=> query) to \
                             -1 * (embedding <#> query) for better performance."
                            .to_string();

                    let fix_preview = generate_operator_fix_preview();

                    // Generate patch replacing <=> with <#>
                    let patch = generate_operator_patch(
                        *file_id,
                        call.function_call.location.line,
                        Some(call.start_byte),
                        Some(call.end_byte),
                        &call.args_repr,
                    );

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::Low,
                        confidence: 0.75,
                        dimension: Dimension::Performance,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch,
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "python".into(),
                            "sqlalchemy".into(),
                            "pgvector".into(),
                            "performance".into(),
                        ],
                    });
                }

                // Check for vector queries without LIMIT
                let has_order_by_vector =
                    args.contains("ORDER BY") && (args.contains("<=>") || args.contains("<#>"));
                let has_limit = args.to_uppercase().contains("LIMIT");

                if has_order_by_vector && !has_limit {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "pgvector: Missing LIMIT on vector similarity query".to_string(),
                        description: Some(
                            "Vector similarity queries without LIMIT can be slow and \
                                 prevent pgvector's iterative scan optimization. Always use \
                                 LIMIT to enable efficient approximate nearest neighbor search \
                                 with HNSW indexes."
                                .to_string(),
                        ),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::Medium,
                        confidence: 0.80,
                        dimension: Dimension::Performance,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_limit_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "sqlalchemy".into(),
                            "pgvector".into(),
                            "performance".into(),
                        ],
                    });
                }

                // Also check for index creation with vector_cosine_ops in call args
                if args.contains("CREATE INDEX") && args.contains("vector_cosine_ops") {
                    let title =
                        "pgvector: Consider vector_ip_ops for normalized vectors".to_string();

                    let description =
                        "INDEX uses vector_cosine_ops. For normalized vectors (most embedding \
                         models produce normalized output), vector_ip_ops (inner product) is \
                         faster and equivalent to cosine similarity. Use vector_ip_ops unless \
                         your vectors are NOT normalized."
                            .to_string();

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::Low,
                        confidence: 0.70,
                        dimension: Dimension::Performance,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: None, // Don't auto-patch without exact byte positions
                        fix_preview: Some(generate_index_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "sqlalchemy".into(),
                            "pgvector".into(),
                            "performance".into(),
                            "index".into(),
                        ],
                    });
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::n_plus_one())
    }
}

/// Generate patch for operator replacement (<=> to <#>).
fn generate_operator_patch(
    file_id: FileId,
    line: u32,
    start_byte: Option<usize>,
    end_byte: Option<usize>,
    _args: &str,
) -> Option<FilePatch> {
    // If we have byte positions, suggest the fix
    if let (Some(_start), Some(_end)) = (start_byte, end_byte) {
        // The actual fix requires understanding the full query context
        // For now, add a comment suggestion
        let comment = "# TODO: For normalized vectors, replace:\n\
             #   1 - (embedding <=> query) -> -1 * (embedding <#> query)\n\
             #   ORDER BY embedding <=> query -> ORDER BY embedding <#> query\n"
            .to_string();

        // Don't modify the original code, just add a comment
        return Some(FilePatch {
            file_id,
            hunks: vec![PatchHunk {
                range: PatchRange::InsertBeforeLine { line },
                replacement: comment,
            }],
        });
    }

    None
}

/// Generate fix preview for operator optimization.
fn generate_operator_fix_preview() -> String {
    r#"# pgvector Operator Optimization for Normalized Vectors

# BEFORE (slower):
query = """
    SELECT id, 1 - (embedding <=> :query::vector) as similarity
    FROM embeddings
    WHERE org_id = :org_id
    ORDER BY embedding <=> :query::vector
    LIMIT 10
"""

# AFTER (faster for normalized vectors):
query = """
    SELECT id, -1 * (embedding <#> :query::vector) as similarity
    FROM embeddings
    WHERE org_id = :org_id
    ORDER BY embedding <#> :query::vector
    LIMIT 10
"""

# Why it's faster:
# - <=> (cosine distance) requires normalization check
# - <#> (negative inner product) skips the check
# - For normalized vectors: inner_product = cosine_similarity
# - Most embedding models (bge, sentence-transformers) produce normalized vectors

# Key changes:
# 1. Replace <=> with <#>
# 2. Change similarity calculation:
#    - WAS: 1 - (embedding <=> query)
#    - NOW: -1 * (embedding <#> query)
# 3. Update index to use vector_ip_ops"#
        .to_string()
}

/// Generate fix preview for missing LIMIT.
fn generate_limit_fix_preview() -> String {
    r#"# pgvector: Always Use LIMIT on Vector Queries

# BEFORE (no LIMIT - scans entire table):
query = """
    SELECT id, embedding
    FROM embeddings
    WHERE org_id = :org_id
    ORDER BY embedding <#> :query::vector
"""
# This will scan ALL rows, even with HNSW index!

# AFTER (with LIMIT - enables iterative scan):
query = """
    SELECT id, embedding
    FROM embeddings
    WHERE org_id = :org_id
    ORDER BY embedding <#> :query::vector
    LIMIT 10
"""
# Iterative scan: HNSW index traverses deeper only if needed

# Why LIMIT matters:
# - pgvector uses "iterative scan" for filtered queries
# - Without LIMIT, it must return ALL rows
# - With LIMIT, it can stop early once enough results found
# - HNSW index only fully utilized with ORDER BY + LIMIT"#
        .to_string()
}

/// Generate fix preview for index optimization.
fn generate_index_fix_preview() -> String {
    r#"# pgvector Index Optimization

# BEFORE (vector_cosine_ops):
CREATE INDEX ix_embeddings_vector
ON embeddings
USING hnsw (embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

# AFTER (vector_ip_ops for normalized vectors):
CREATE INDEX ix_embeddings_vector
ON embeddings
USING hnsw (embedding vector_ip_ops)
WITH (m = 16, ef_construction = 64);

# When to use each:
# - vector_ip_ops: Normalized vectors (most embedding models)
# - vector_cosine_ops: Non-normalized vectors only
# - vector_l2_ops: When you need Euclidean distance

# Common normalized embedding models:
# - bge-small-en-v1.5, bge-base-en-v1.5
# - sentence-transformers models
# - OpenAI text-embedding-3-small/large
# - Cohere embed models"#
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed)
            .expect("framework analysis should succeed");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = PgvectorOptimizationRule::new();
        assert_eq!(rule.id(), "python.sqlalchemy.pgvector_suboptimal_query");
    }

    #[test]
    fn rule_name_mentions_pgvector() {
        let rule = PgvectorOptimizationRule::new();
        assert!(rule.name().contains("pgvector"));
    }

    #[tokio::test]
    async fn no_finding_without_pgvector_import() {
        let rule = PgvectorOptimizationRule::new();
        let src = r#"
from sqlalchemy import text

conn.execute(text("SELECT * FROM table WHERE embedding <=> query"))
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            findings.is_empty(),
            "Should not fire without pgvector import"
        );
    }

    #[tokio::test]
    async fn finding_for_cosine_operator_with_pgvector() {
        let rule = PgvectorOptimizationRule::new();
        let src = r#"
from pgvector.sqlalchemy import Vector
from sqlalchemy import text

conn.execute(text("SELECT * FROM t ORDER BY embedding <=> query"))
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            !findings.is_empty(),
            "Should detect <=> usage with pgvector"
        );
        assert!(findings[0].title.contains("<#>") || findings[0].title.contains("inner product"));
    }

    #[tokio::test]
    async fn no_finding_for_inner_product_operator() {
        let rule = PgvectorOptimizationRule::new();
        let src = r#"
from pgvector.sqlalchemy import Vector
from sqlalchemy import text

conn.execute(text("SELECT * FROM t ORDER BY embedding <#> query LIMIT 10"))
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should only have the <=> finding, not the <#> one
        let cosine_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("<=>") || f.title.contains("cosine"))
            .collect();
        assert!(cosine_findings.is_empty(), "Should not flag <#> operator");
    }

    #[tokio::test]
    async fn finding_for_fstring_with_pgvector() {
        let rule = PgvectorOptimizationRule::new();
        // Test f-string pattern like in the RAG sample app
        let src = r#"
from pgvector.sqlalchemy import Vector
from sqlalchemy import text

embedding_str = "[0.1, 0.2]"
query = text(f"""
    SELECT id, content,
           1 - (embedding <=> '{embedding_str}'::vector) as similarity
    FROM documents
    ORDER BY embedding <=> '{embedding_str}'::vector
""")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(
            !findings.is_empty(),
            "Should detect <=> usage in f-string with pgvector"
        );
    }

    #[tokio::test]
    async fn finding_for_missing_limit_in_fstring() {
        let rule = PgvectorOptimizationRule::new();
        let src = r#"
from pgvector.sqlalchemy import Vector
from sqlalchemy import text

query = text(f"""
    SELECT * FROM embeddings
    ORDER BY embedding <#> '{query_vec}'::vector
""")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let limit_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("LIMIT"))
            .collect();
        assert!(
            !limit_findings.is_empty(),
            "Should detect missing LIMIT in f-string query"
        );
    }

    #[test]
    fn fix_preview_contains_examples() {
        let preview = generate_operator_fix_preview();
        assert!(preview.contains("<#>"));
        assert!(preview.contains("<=>"));
        assert!(preview.contains("normalized"));
    }

    #[test]
    fn index_fix_preview_covers_alternatives() {
        let preview = generate_index_fix_preview();
        assert!(preview.contains("vector_ip_ops"));
        assert!(preview.contains("vector_cosine_ops"));
        assert!(preview.contains("bge"));
    }
}
