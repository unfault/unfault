//! Content builders for generating text representations of findings.
//!
//! These text representations are what gets embedded for vector search.
//! The format is designed to capture the most relevant information for
//! semantic similarity matching.

use sha2::{Digest, Sha256};

use crate::types::FindingRecord;

/// Build embeddable text content from a finding.
///
/// The format includes rule metadata, title, description, and location
/// to enable semantic search across findings.
pub fn build_finding_content(
    rule_id: &str,
    dimension: &str,
    severity: &str,
    title: &str,
    description: &str,
    file_path: &str,
    diff: Option<&str>,
) -> String {
    let mut content = format!(
        "Rule: {rule_id}\nDimension: {dimension}\nSeverity: {severity}\n\
         Title: {title}\nDescription: {description}\nFile: {file_path}"
    );

    // Include a snippet of the diff if available (added lines only)
    if let Some(diff_text) = diff {
        let added_lines: Vec<&str> = diff_text
            .lines()
            .filter(|line| line.starts_with('+') && !line.starts_with("+++"))
            .take(5)
            .collect();

        if !added_lines.is_empty() {
            content.push_str("\nFix:\n");
            for line in added_lines {
                // Trim the '+' prefix and limit line length
                let line = &line[1..];
                if line.len() > 200 {
                    content.push_str(&line[..200]);
                } else {
                    content.push_str(line);
                }
                content.push('\n');
            }
        }
    }

    content
}

/// Compute a SHA-256 content hash for deduplication.
#[allow(dead_code)]
pub fn compute_content_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Build a FindingRecord from analysis findings.
#[allow(dead_code)]
pub fn finding_to_record(
    workspace_id: &str,
    finding: &unfault_analysis::types::finding::Finding,
) -> FindingRecord {
    let content = build_finding_content(
        &finding.rule_id,
        &format!("{:?}", finding.dimension),
        &format!("{:?}", finding.severity),
        &finding.title,
        &finding.description,
        &finding.file_path,
        finding.diff.as_deref(),
    );

    FindingRecord {
        id: finding.id.clone(),
        workspace_id: workspace_id.to_string(),
        file_path: finding.file_path.clone(),
        rule_id: finding.rule_id.clone(),
        title: finding.title.clone(),
        description: finding.description.clone(),
        dimension: format!("{:?}", finding.dimension),
        severity: format!("{:?}", finding.severity),
        line: finding.line,
        content_hash: compute_content_hash(&content),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_finding_content() {
        let content = build_finding_content(
            "python.http.missing_timeout",
            "stability",
            "high",
            "HTTP call without timeout",
            "requests.get() called without a timeout parameter",
            "app/services/api.py",
            None,
        );

        assert!(content.contains("python.http.missing_timeout"));
        assert!(content.contains("stability"));
        assert!(content.contains("HTTP call without timeout"));
        assert!(content.contains("app/services/api.py"));
    }

    #[test]
    fn test_build_finding_content_with_diff() {
        let diff = "+    timeout=30,\n+    retry=3,\n";
        let content = build_finding_content(
            "rule.id",
            "stability",
            "medium",
            "Title",
            "Description",
            "file.py",
            Some(diff),
        );

        assert!(content.contains("Fix:"));
        assert!(content.contains("timeout=30"));
    }

    #[test]
    fn test_content_hash_deterministic() {
        let hash1 = compute_content_hash("test content");
        let hash2 = compute_content_hash("test content");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_content_hash_different() {
        let hash1 = compute_content_hash("content a");
        let hash2 = compute_content_hash("content b");
        assert_ne!(hash1, hash2);
    }
}
