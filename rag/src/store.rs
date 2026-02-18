//! LanceDB vector store for finding embeddings.
//!
//! Stores and searches embeddings locally using LanceDB.
//! Data is stored at `.unfault/vectors.lance` in the project root.

use std::sync::Arc;

use arrow_array::{
    Array, FixedSizeListArray, Float32Array, RecordBatch, RecordBatchIterator, StringArray,
    UInt32Array, types::Float32Type,
};
use arrow_schema::{DataType, Field, Schema};
use futures::TryStreamExt;
use lancedb::query::{ExecutableQuery, QueryBase};

use crate::error::RagError;
use crate::types::{FindingRecord, ScoredFinding};

const TABLE_NAME: &str = "findings";

/// LanceDB-backed vector store for finding embeddings.
pub struct VectorStore {
    db: lancedb::Connection,
    dims: usize,
}

impl VectorStore {
    /// Open or create a vector store at the given path.
    pub async fn open(path: &str, dims: usize) -> Result<Self, RagError> {
        let db = lancedb::connect(path).execute().await?;
        let store = Self { db, dims };
        store.ensure_table().await?;
        Ok(store)
    }

    /// Build the Arrow schema for the findings table.
    fn schema(&self) -> Arc<Schema> {
        Arc::new(Schema::new(vec![
            Field::new("id", DataType::Utf8, false),
            Field::new("workspace_id", DataType::Utf8, false),
            Field::new("file_path", DataType::Utf8, false),
            Field::new("rule_id", DataType::Utf8, false),
            Field::new("title", DataType::Utf8, false),
            Field::new("description", DataType::Utf8, false),
            Field::new("dimension", DataType::Utf8, false),
            Field::new("severity", DataType::Utf8, false),
            Field::new("line", DataType::UInt32, true),
            Field::new("content_hash", DataType::Utf8, false),
            Field::new(
                "vector",
                DataType::FixedSizeList(
                    Arc::new(Field::new("item", DataType::Float32, true)),
                    self.dims as i32,
                ),
                false,
            ),
        ]))
    }

    /// Ensure the findings table exists.
    async fn ensure_table(&self) -> Result<(), RagError> {
        let tables = self.db.table_names().execute().await?;
        if !tables.contains(&TABLE_NAME.to_string()) {
            let schema = self.schema();
            let empty_batch = RecordBatch::new_empty(schema.clone());
            let batches = RecordBatchIterator::new(vec![Ok(empty_batch)], schema);
            self.db
                .create_table(TABLE_NAME, batches)
                .execute()
                .await?;
        }
        Ok(())
    }

    /// Index findings with pre-computed embeddings.
    pub async fn index_findings(
        &self,
        findings: &[FindingRecord],
        embeddings: Vec<Vec<f32>>,
    ) -> Result<usize, RagError> {
        if findings.is_empty() || embeddings.is_empty() {
            return Ok(0);
        }

        if findings.len() != embeddings.len() {
            return Err(RagError::Embedding(format!(
                "Mismatch: {} findings but {} embeddings",
                findings.len(),
                embeddings.len()
            )));
        }

        let schema = self.schema();
        let n = findings.len();

        // Build Arrow arrays from findings
        let ids = StringArray::from_iter_values(findings.iter().map(|f| f.id.as_str()));
        let workspace_ids =
            StringArray::from_iter_values(findings.iter().map(|f| f.workspace_id.as_str()));
        let file_paths =
            StringArray::from_iter_values(findings.iter().map(|f| f.file_path.as_str()));
        let rule_ids =
            StringArray::from_iter_values(findings.iter().map(|f| f.rule_id.as_str()));
        let titles = StringArray::from_iter_values(findings.iter().map(|f| f.title.as_str()));
        let descriptions =
            StringArray::from_iter_values(findings.iter().map(|f| f.description.as_str()));
        let dimensions =
            StringArray::from_iter_values(findings.iter().map(|f| f.dimension.as_str()));
        let severities =
            StringArray::from_iter_values(findings.iter().map(|f| f.severity.as_str()));
        let lines = UInt32Array::from(findings.iter().map(|f| f.line).collect::<Vec<_>>());
        let content_hashes =
            StringArray::from_iter_values(findings.iter().map(|f| f.content_hash.as_str()));

        // Build the vector column
        let vector_array = FixedSizeListArray::from_iter_primitive::<Float32Type, _, _>(
            embeddings
                .into_iter()
                .map(|v| Some(v.into_iter().map(Some).collect::<Vec<_>>())),
            self.dims as i32,
        );

        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(ids),
                Arc::new(workspace_ids),
                Arc::new(file_paths),
                Arc::new(rule_ids),
                Arc::new(titles),
                Arc::new(descriptions),
                Arc::new(dimensions),
                Arc::new(severities),
                Arc::new(lines),
                Arc::new(content_hashes),
                Arc::new(vector_array) as Arc<dyn Array>,
            ],
        )
        .map_err(|e| RagError::Store(format!("Failed to create record batch: {e}")))?;

        let table = self.db.open_table(TABLE_NAME).execute().await?;
        let batches = RecordBatchIterator::new(vec![Ok(batch)], schema);
        table.add(batches).execute().await?;

        Ok(n)
    }

    /// Search for findings similar to a query embedding.
    pub async fn search(
        &self,
        query_embedding: &[f32],
        limit: usize,
        workspace_id: Option<&str>,
    ) -> Result<Vec<ScoredFinding>, RagError> {
        let table = self.db.open_table(TABLE_NAME).execute().await?;

        let mut query = table
            .vector_search(query_embedding)
            .map_err(|e| RagError::Store(format!("Failed to build search query: {e}")))?;

        query = query.limit(limit);

        if let Some(ws_id) = workspace_id {
            query = query.only_if(format!("workspace_id = '{ws_id}'"));
        }

        let results: Vec<RecordBatch> =
            query.execute().await?.try_collect().await.map_err(|e| {
                RagError::Store(format!("Failed to execute search: {e}"))
            })?;

        let mut scored_findings = Vec::new();
        for batch in &results {
            let n = batch.num_rows();
            let ids = batch
                .column_by_name("id")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let workspace_ids = batch
                .column_by_name("workspace_id")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let file_paths = batch
                .column_by_name("file_path")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let rule_ids = batch
                .column_by_name("rule_id")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let titles = batch
                .column_by_name("title")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let descriptions = batch
                .column_by_name("description")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let dimensions = batch
                .column_by_name("dimension")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let severities = batch
                .column_by_name("severity")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let lines = batch
                .column_by_name("line")
                .and_then(|c| c.as_any().downcast_ref::<UInt32Array>());
            let content_hashes = batch
                .column_by_name("content_hash")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let distances = batch
                .column_by_name("_distance")
                .and_then(|c| c.as_any().downcast_ref::<Float32Array>());

            // All required columns must be present
            let (
                Some(ids),
                Some(workspace_ids),
                Some(file_paths),
                Some(rule_ids),
                Some(titles),
                Some(descriptions),
                Some(dims),
                Some(sevs),
                Some(hashes),
            ) = (
                ids,
                workspace_ids,
                file_paths,
                rule_ids,
                titles,
                descriptions,
                dimensions,
                severities,
                content_hashes,
            )
            else {
                continue;
            };

            for i in 0..n {
                let distance = distances.map(|d| d.value(i)).unwrap_or(0.0);
                let similarity = 1.0 / (1.0 + distance);

                scored_findings.push(ScoredFinding {
                    finding: FindingRecord {
                        id: ids.value(i).to_string(),
                        workspace_id: workspace_ids.value(i).to_string(),
                        file_path: file_paths.value(i).to_string(),
                        rule_id: rule_ids.value(i).to_string(),
                        title: titles.value(i).to_string(),
                        description: descriptions.value(i).to_string(),
                        dimension: dims.value(i).to_string(),
                        severity: sevs.value(i).to_string(),
                        line: lines.and_then(|l| {
                            if l.is_null(i) {
                                None
                            } else {
                                Some(l.value(i))
                            }
                        }),
                        content_hash: hashes.value(i).to_string(),
                    },
                    similarity,
                });
            }
        }

        Ok(scored_findings)
    }

    /// Delete all findings for a workspace.
    pub async fn clear_workspace(&self, workspace_id: &str) -> Result<(), RagError> {
        let table = self.db.open_table(TABLE_NAME).execute().await?;
        table
            .delete(&format!("workspace_id = '{workspace_id}'"))
            .await?;
        Ok(())
    }

    /// Get the number of indexed findings.
    pub async fn count(&self) -> Result<usize, RagError> {
        let table = self.db.open_table(TABLE_NAME).execute().await?;
        let count = table.count_rows(None).await?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_open_creates_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lance");
        let store = VectorStore::open(path.to_str().unwrap(), 4).await.unwrap();
        let count = store.count().await.unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn test_index_and_search() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lance");
        let store = VectorStore::open(path.to_str().unwrap(), 4).await.unwrap();

        let findings = vec![
            FindingRecord {
                id: "f1".to_string(),
                workspace_id: "ws1".to_string(),
                file_path: "app.py".to_string(),
                rule_id: "python.http.timeout".to_string(),
                title: "Missing timeout".to_string(),
                description: "HTTP call without timeout".to_string(),
                dimension: "Stability".to_string(),
                severity: "High".to_string(),
                line: Some(42),
                content_hash: "abc123".to_string(),
            },
            FindingRecord {
                id: "f2".to_string(),
                workspace_id: "ws1".to_string(),
                file_path: "db.py".to_string(),
                rule_id: "python.sql.injection".to_string(),
                title: "SQL injection".to_string(),
                description: "Unsanitized input in query".to_string(),
                dimension: "Security".to_string(),
                severity: "Critical".to_string(),
                line: Some(10),
                content_hash: "def456".to_string(),
            },
        ];

        let embeddings = vec![vec![1.0, 0.0, 0.0, 0.0], vec![0.0, 1.0, 0.0, 0.0]];

        let indexed = store.index_findings(&findings, embeddings).await.unwrap();
        assert_eq!(indexed, 2);
        assert_eq!(store.count().await.unwrap(), 2);

        // Search for something similar to the first finding
        let results = store
            .search(&[0.9, 0.1, 0.0, 0.0], 5, None)
            .await
            .unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].finding.id, "f1");
    }

    #[tokio::test]
    async fn test_workspace_filtering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lance");
        let store = VectorStore::open(path.to_str().unwrap(), 4).await.unwrap();

        let findings = vec![
            FindingRecord {
                id: "f1".to_string(),
                workspace_id: "ws1".to_string(),
                file_path: "a.py".to_string(),
                rule_id: "rule1".to_string(),
                title: "T1".to_string(),
                description: "D1".to_string(),
                dimension: "Stability".to_string(),
                severity: "High".to_string(),
                line: None,
                content_hash: "h1".to_string(),
            },
            FindingRecord {
                id: "f2".to_string(),
                workspace_id: "ws2".to_string(),
                file_path: "b.py".to_string(),
                rule_id: "rule2".to_string(),
                title: "T2".to_string(),
                description: "D2".to_string(),
                dimension: "Security".to_string(),
                severity: "Low".to_string(),
                line: None,
                content_hash: "h2".to_string(),
            },
        ];

        let embeddings = vec![vec![1.0, 0.0, 0.0, 0.0], vec![0.0, 1.0, 0.0, 0.0]];

        store.index_findings(&findings, embeddings).await.unwrap();

        let results = store
            .search(&[1.0, 0.0, 0.0, 0.0], 5, Some("ws1"))
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].finding.workspace_id, "ws1");
    }

    #[tokio::test]
    async fn test_clear_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.lance");
        let store = VectorStore::open(path.to_str().unwrap(), 4).await.unwrap();

        let findings = vec![FindingRecord {
            id: "f1".to_string(),
            workspace_id: "ws1".to_string(),
            file_path: "a.py".to_string(),
            rule_id: "r".to_string(),
            title: "T".to_string(),
            description: "D".to_string(),
            dimension: "S".to_string(),
            severity: "H".to_string(),
            line: None,
            content_hash: "h".to_string(),
        }];
        let embeddings = vec![vec![1.0, 0.0, 0.0, 0.0]];

        store.index_findings(&findings, embeddings).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 1);

        store.clear_workspace("ws1").await.unwrap();
        assert_eq!(store.count().await.unwrap(), 0);
    }
}
