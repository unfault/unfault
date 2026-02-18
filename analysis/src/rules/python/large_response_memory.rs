//! Rule: Large Response Bodies Loaded Into Memory
//!
//! Detects patterns where large HTTP responses or file contents are loaded
//! entirely into memory, which can cause memory spikes and OOM errors.

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

/// Rule that detects large response bodies being loaded into memory.
#[derive(Debug, Default)]
pub struct PythonLargeResponseMemoryRule;

impl PythonLargeResponseMemoryRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for PythonLargeResponseMemoryRule {
    fn id(&self) -> &'static str {
        "python.large_response_memory"
    }

    fn name(&self) -> &'static str {
        "Large Response Body Loaded Into Memory"
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
            let py = match sem.as_ref() {
                SourceSemantics::Python(py) => py,
                _ => continue,
            };

            // Check for patterns that load large data into memory
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;
                let args = &call.args_repr;
                let call_text = format!("{}({})", callee, args);
                let call_lower = call_text.to_lowercase();

                // Check for HTTP response content loading
                // Pattern: response.content, response.text
                if callee.ends_with(".content") || callee.ends_with(".text") {
                    // Check if it's likely an HTTP response
                    if call_lower.contains("response") || call_lower.contains("resp") {
                        // Check if it's not using streaming
                        if !call_text.contains("stream=True") && !call_text.contains("iter_") {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "HTTP response loaded entirely into memory".to_string(),
                                description: Some(
                                    "Accessing .content or .text on an HTTP response loads the entire response body into memory. \
                                     For large responses, this can cause memory spikes or OOM errors. Consider using streaming."
                                        .to_string(),
                                ),
                                kind: FindingKind::PerformanceSmell,
                                severity: Severity::Medium,
                                confidence: 0.70,
                                dimension: Dimension::Performance,
                                file_id: *file_id,
                                file_path: py.path.clone(),
                                line: Some(call.function_call.location.line),
                                column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                                patch: None,
                                fix_preview: Some(HTTP_STREAMING_FIX.to_string()),
                                tags: vec!["memory".to_string(), "performance".to_string(), "streaming".to_string()],
                            });
                        }
                    }
                }

                // Check for response.json() on potentially large responses
                if callee.ends_with(".json") {
                    if call_lower.contains("response") || call_lower.contains("resp") {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Large JSON response loaded into memory".to_string(),
                            description: Some(
                                "Calling .json() on an HTTP response loads and parses the entire JSON body into memory. \
                                 For large JSON responses, consider streaming JSON parsing."
                                    .to_string(),
                            ),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::Medium,
                            confidence: 0.65,
                            dimension: Dimension::Performance,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: None,
                            fix_preview: Some(JSON_STREAMING_FIX.to_string()),
                            tags: vec!["memory".to_string(), "json".to_string(), "streaming".to_string()],
                        });
                    }
                }

                // Check for file.read() without size limit
                if callee.ends_with(".read") && args.trim() == "()" {
                    // .read() without arguments reads entire file
                    if !callee.contains("readline") && !callee.contains("readlines") {
                        // Generate actual fix: .read() → .read(8192)
                        let patch = generate_read_chunked_patch(
                            *file_id,
                            call.start_byte,
                            call.end_byte,
                        );
                        
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "File read entirely into memory".to_string(),
                            description: Some(
                                "Calling .read() without a size argument reads the entire file into memory. \
                                 For large files, this can cause memory exhaustion."
                                    .to_string(),
                            ),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::Medium,
                            confidence: 0.75,
                            dimension: Dimension::Performance,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(FILE_READ_FIX.to_string()),
                            tags: vec!["memory".to_string(), "file".to_string(), "streaming".to_string()],
                        });
                    }
                }

                // Check for json.load() on files
                if callee == "json.load" {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "JSON file loaded entirely into memory".to_string(),
                        description: Some(
                            "json.load() reads and parses the entire JSON file into memory. \
                             For large JSON files, consider streaming JSON parsing."
                                .to_string(),
                        ),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::Medium,
                        confidence: 0.70,
                        dimension: Dimension::Performance,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(JSON_FILE_FIX.to_string()),
                        tags: vec!["memory".to_string(), "json".to_string(), "streaming".to_string()],
                    });
                }

                // Check for pickle.load()
                if callee == "pickle.load" || callee == "pickle.loads" || callee == "cPickle.load" {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Pickle file loaded entirely into memory".to_string(),
                        description: Some(
                            "pickle.load() deserializes the entire pickle file into memory. \
                             For large serialized objects, consider chunked serialization or alternative formats."
                                .to_string(),
                        ),
                        kind: FindingKind::PerformanceSmell,
                        severity: Severity::Medium,
                        confidence: 0.70,
                        dimension: Dimension::Performance,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(PICKLE_FIX.to_string()),
                        tags: vec!["memory".to_string(), "pickle".to_string(), "serialization".to_string()],
                    });
                }

                // Check for pandas read without chunking
                if callee == "pd.read_csv" || callee == "pandas.read_csv" {
                    if !args.contains("chunksize=") && !args.contains("iterator=True") {
                        // Generate actual fix: add chunksize parameter
                        let patch = generate_pandas_chunksize_patch(
                            *file_id,
                            call.start_byte,
                            call.end_byte,
                            callee,
                            args,
                        );
                        
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Large CSV file read entirely into memory".to_string(),
                            description: Some(
                                "Reading a CSV file without chunking loads the entire dataset into memory. \
                                 For large files, use chunked reading or dask for out-of-core processing."
                                    .to_string(),
                            ),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::Medium,
                            confidence: 0.65,
                            dimension: Dimension::Performance,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(PANDAS_FIX.to_string()),
                            tags: vec!["memory".to_string(), "pandas".to_string(), "csv".to_string()],
                        });
                    }
                }

                if callee == "pd.read_json" || callee == "pandas.read_json" {
                    if !args.contains("chunksize=") && !args.contains("lines=True") {
                        // Generate actual fix: add chunksize parameter
                        let patch = generate_pandas_chunksize_patch(
                            *file_id,
                            call.start_byte,
                            call.end_byte,
                            callee,
                            args,
                        );
                        
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Large JSON file read entirely into memory".to_string(),
                            description: Some(
                                "Reading a JSON file without chunking loads the entire dataset into memory. \
                                 For large files, use chunked reading or dask for out-of-core processing."
                                    .to_string(),
                            ),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::Medium,
                            confidence: 0.65,
                            dimension: Dimension::Performance,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(PANDAS_FIX.to_string()),
                            tags: vec!["memory".to_string(), "pandas".to_string(), "json".to_string()],
                        });
                    }
                }
            }
        }

        findings
    }
}

const HTTP_STREAMING_FIX: &str = r#"Use streaming for large responses:

# With requests:
response = requests.get(url, stream=True)
for chunk in response.iter_content(chunk_size=8192):
    process(chunk)

# With httpx:
async with httpx.AsyncClient() as client:
    async with client.stream('GET', url) as response:
        async for chunk in response.aiter_bytes():
            process(chunk)"#;

const JSON_STREAMING_FIX: &str = r#"For large JSON responses, use streaming:

# With ijson for streaming JSON parsing:
import ijson

response = requests.get(url, stream=True)
for item in ijson.items(response.raw, 'items.item'):
    process(item)

# Or process in chunks if the API supports pagination:
page = 1
while True:
    response = requests.get(f"{url}?page={page}")
    data = response.json()
    if not data['items']:
        break
    for item in data['items']:
        process(item)
    page += 1"#;

const FILE_READ_FIX: &str = r#"Read files in chunks:

# Read in chunks:
with open(filename, 'rb') as f:
    while chunk := f.read(8192):
        process(chunk)

# Or iterate over lines:
with open(filename, 'r') as f:
    for line in f:
        process(line)"#;

const JSON_FILE_FIX: &str = r#"Use streaming JSON parsing for large files:

# With ijson:
import ijson

with open(filename, 'rb') as f:
    for item in ijson.items(f, 'items.item'):
        process(item)

# Or for JSON Lines format:
with open(filename, 'r') as f:
    for line in f:
        item = json.loads(line)
        process(item)"#;

const PICKLE_FIX: &str = r#"Consider alternatives for large data:

# Use chunked processing with joblib:
from joblib import dump, load
# dump(large_data, filename, compress=3)
# data = load(filename, mmap_mode='r')  # Memory-mapped

# Or use HDF5 for large arrays:
import h5py
with h5py.File(filename, 'r') as f:
    # Access data lazily
    chunk = f['dataset'][0:1000]"#;

const PANDAS_FIX: &str = r#"Use chunked reading for large files:

# Read in chunks:
for chunk in pd.read_csv(filename, chunksize=10000):
    process(chunk)

# Or use dask for out-of-core processing:
import dask.dataframe as dd
df = dd.read_csv(filename)
result = df.groupby('column').sum().compute()

# For very large files, consider:
# - Filtering columns: usecols=['col1', 'col2']
# - Specifying dtypes: dtype={'col1': 'int32'}
# - Using pyarrow: engine='pyarrow'"#;

/// Generate patch to add chunk size to .read() call
fn generate_read_chunked_patch(
    file_id: FileId,
    _start_byte: usize,
    _end_byte: usize,
) -> FilePatch {
    // The call pattern `.read()` is typically part of a method chain (e.g., `f.read()`)
    // We can't easily replace just the `.read()` part without more context
    // So we provide a helpful comment with the recommended fix pattern
    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine {
                line: 1,
            },
            replacement: "# TODO: Replace .read() with chunked reading:\n# while chunk := f.read(8192):\n#     process(chunk)\n".to_string(),
        }],
    }
}

/// Generate patch to add chunksize parameter to pandas read functions
fn generate_pandas_chunksize_patch(
    file_id: FileId,
    start_byte: usize,
    end_byte: usize,
    callee: &str,
    args: &str,
) -> FilePatch {
    // Parse args to insert chunksize parameter
    let args_inner = args.trim().trim_start_matches('(').trim_end_matches(')');
    
    let new_call = if args_inner.is_empty() {
        format!("{}(chunksize=10000)", callee)
    } else {
        format!("{}({}, chunksize=10000)", callee, args_inner)
    };
    
    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: start_byte,
                end: end_byte,
            },
            replacement: new_call,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_id() {
        let rule = PythonLargeResponseMemoryRule::new();
        assert_eq!(rule.id(), "python.large_response_memory");
    }

    #[test]
    fn test_rule_name() {
        let rule = PythonLargeResponseMemoryRule::new();
        assert_eq!(rule.name(), "Large Response Body Loaded Into Memory");
    }
}