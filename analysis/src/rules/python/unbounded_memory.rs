use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule: Unbounded Memory Operation
///
/// Detects operations that load unlimited data into memory without pagination or streaming.
/// This can cause OOM kills when production data is larger than test data.
#[derive(Debug)]
pub struct PythonUnboundedMemoryOperationRule;

impl PythonUnboundedMemoryOperationRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonUnboundedMemoryOperationRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonUnboundedMemoryOperationRule {
    fn id(&self) -> &'static str {
        "python.performance.unbounded_memory_operation"
    }

    fn name(&self) -> &'static str {
        "Unbounded memory operation"
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

            let import_line = py.import_insertion_line();
            
            // Check all calls in the file for unbounded memory patterns
            for call in &py.calls {
                if let Some(finding) = check_unbounded_pattern(
                    &call.function_call.callee_expr,
                    &call.args_repr,
                    *file_id,
                    &py.path,
                    &call.function_call.location,
                    call.start_byte,
                    call.end_byte,
                    import_line,
                ) {
                    findings.push(finding);
                }
            }
        }

        findings
    }
}

/// Check if a call represents an unbounded memory pattern.
fn check_unbounded_pattern(
    callee: &str,
    args_repr: &str,
    file_id: FileId,
    file_path: &str,
    location: &crate::semantics::common::CommonLocation,
    start_byte: usize,
    end_byte: usize,
    import_insertion_line: u32,
) -> Option<RuleFinding> {
    // Patterns that load all data into memory
    let unbounded_patterns = [
        (".all()", "Query.all() loads entire result set into memory"),
        (".fetchall()", "fetchall() loads all rows into memory"),
        ("list(", "list() materializes entire iterator into memory"),
        (".read()", "read() without size limit loads entire file"),
        ("json.load(", "json.load() loads entire JSON into memory"),
        (".readlines()", "readlines() loads all lines into memory"),
        ("pd.read_csv(", "read_csv() loads entire CSV into memory"),
        ("pd.read_json(", "read_json() loads entire JSON into memory"),
        ("pd.read_excel(", "read_excel() loads entire Excel file into memory"),
    ];

    let full_call = format!("{}{}", callee, args_repr);

    for (pattern, description) in unbounded_patterns {
        if full_call.contains(pattern) || callee.contains(pattern.trim_end_matches("(")) {
            // Skip if already using pagination/streaming
            if full_call.contains("limit")
                || full_call.contains("chunk")
                || full_call.contains("batch")
                || full_call.contains("yield_per")
                || full_call.contains("iter")
                || full_call.contains("stream")
            {
                continue;
            }

            let title = format!("Unbounded memory operation: {}", description);

            let description_text = format!(
                "The call `{}` loads data without bounds. \
                 In production with large datasets, this can exhaust memory and cause \
                 OOM kills. Consider using pagination, streaming, or chunked processing.",
                callee,
            );

            let fix_preview = generate_fix_preview(pattern);

            // Generate actual fix using ReplaceBytes where possible
            let patch = generate_unbounded_memory_patch(
                pattern,
                callee,
                args_repr,
                file_id,
                start_byte,
                end_byte,
                import_insertion_line,
            );

            return Some(RuleFinding {
                rule_id: "python.performance.unbounded_memory_operation".to_string(),
                title,
                description: Some(description_text),
                kind: FindingKind::PerformanceSmell,
                severity: Severity::High,
                confidence: 0.85,
                dimension: Dimension::Performance,
                file_id,
                file_path: file_path.to_string(),
                line: Some(location.line),
                column: Some(location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                patch: Some(patch),
                fix_preview: Some(fix_preview),
                tags: vec![
                    "python".into(),
                    "memory".into(),
                    "oom".into(),
                    "performance".into(),
                    "pagination".into(),
                ],
            });
        }
    }

    None
}

/// Generate actual fix patch for unbounded memory patterns.
fn generate_unbounded_memory_patch(
    pattern: &str,
    callee: &str,
    args_repr: &str,
    file_id: FileId,
    start_byte: usize,
    end_byte: usize,
    import_insertion_line: u32,
) -> FilePatch {
    // Generate actual code fix for certain patterns
    let replacement = match pattern {
        ".fetchall()" => {
            // cursor.fetchall() -> cursor.fetchmany(1000)
            let base = callee.trim_end_matches(".fetchall");
            Some(format!("{}.fetchmany(1000)", base))
        }
        "pd.read_csv(" => {
            // pd.read_csv(file) -> pd.read_csv(file, chunksize=10000)
            // Extract args and add chunksize
            let args = args_repr.trim_start_matches('(').trim_end_matches(')');
            if args.is_empty() {
                None
            } else {
                Some(format!("pd.read_csv({}, chunksize=10000)", args))
            }
        }
        "pd.read_json(" => {
            // pd.read_json(file) -> pd.read_json(file, chunksize=10000)
            let args = args_repr.trim_start_matches('(').trim_end_matches(')');
            if args.is_empty() {
                None
            } else {
                Some(format!("pd.read_json({}, chunksize=10000)", args))
            }
        }
        ".all()" => {
            // Model.query.all() -> Model.query.limit(1000).all()
            // SQLAlchemy/ORM pattern
            let base = callee.trim_end_matches(".all");
            Some(format!("{}.limit(1000).all()", base))
        }
        _ => None,
    };

    if let Some(fixed_call) = replacement {
        FilePatch {
            file_id,
            hunks: vec![PatchHunk {
                range: PatchRange::ReplaceBytes {
                    start: start_byte,
                    end: end_byte,
                },
                replacement: fixed_call,
            }],
        }
    } else {
        // Fallback to comment-based guidance
        FilePatch {
            file_id,
            hunks: vec![PatchHunk {
                range: PatchRange::InsertBeforeLine { line: import_insertion_line },
                replacement: "# TODO: Add pagination or streaming to prevent OOM\n".to_string(),
            }],
        }
    }
}

/// Generate a fix preview for unbounded memory patterns.
fn generate_fix_preview(pattern: &str) -> String {
    match pattern {
        ".all()" => r#"# Bad: Loads everything into memory
users = User.query.all()  # 5M records = 20GB RAM

# Good: Process in chunks with yield_per
for batch in User.query.yield_per(100):
    process_batch(batch)  # Only 100 records in memory

# Good: Use pagination
page = 1
page_size = 100
while True:
    users = User.query.limit(page_size).offset((page - 1) * page_size).all()
    if not users:
        break
    process_users(users)
    page += 1

# Good: Use server-side cursor (SQLAlchemy)
from sqlalchemy.orm import Session

with Session(engine) as session:
    for user in session.execute(select(User)).scalars().yield_per(100):
        process_user(user)"#.to_string(),

        ".fetchall()" => r#"# Bad: Loads all rows into memory
cursor.execute("SELECT * FROM large_table")
rows = cursor.fetchall()  # OOM risk!

# Good: Fetch in batches
cursor.execute("SELECT * FROM large_table")
while True:
    rows = cursor.fetchmany(1000)
    if not rows:
        break
    process_rows(rows)

# Good: Use server-side cursor
cursor = connection.cursor(name='server_cursor')
cursor.execute("SELECT * FROM large_table")
for row in cursor:
    process_row(row)"#.to_string(),

        "list(" => r#"# Bad: Materializes entire iterator
all_items = list(generate_items())  # Could be millions!

# Good: Process items one at a time
for item in generate_items():
    process_item(item)

# Good: Use itertools for chunked processing
from itertools import islice

def chunked(iterable, size):
    it = iter(iterable)
    while chunk := list(islice(it, size)):
        yield chunk

for chunk in chunked(generate_items(), 1000):
    process_chunk(chunk)"#.to_string(),

        ".read()" => r#"# Bad: Reads entire file into memory
with open('large_file.txt') as f:
    content = f.read()  # OOM for large files!

# Good: Read in chunks
with open('large_file.txt') as f:
    while chunk := f.read(8192):  # 8KB chunks
        process_chunk(chunk)

# Good: Read line by line
with open('large_file.txt') as f:
    for line in f:
        process_line(line)"#.to_string(),

        "json.load(" => r#"# Bad: Loads entire JSON into memory
with open('large.json') as f:
    data = json.load(f)  # OOM for large files!

# Good: Use ijson for streaming JSON parsing
import ijson

with open('large.json', 'rb') as f:
    for item in ijson.items(f, 'items.item'):
        process_item(item)

# Good: Use JSON Lines format for large datasets
with open('data.jsonl') as f:
    for line in f:
        item = json.loads(line)
        process_item(item)"#.to_string(),

        _ => r#"# General pattern: Avoid loading unbounded data into memory

# Bad: Load everything at once
all_data = load_all_data()

# Good: Stream or paginate
for chunk in load_data_in_chunks(chunk_size=1000):
    process_chunk(chunk)

# Good: Use generators
def process_data():
    for item in data_source:
        yield transform(item)

# Good: Use memory-efficient libraries
# - Use pandas with chunksize parameter
# - Use Dask for out-of-core computation
# - Use Apache Arrow for memory-mapped files"#.to_string(),
    }
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
        let rule = PythonUnboundedMemoryOperationRule::new();
        assert_eq!(rule.id(), "python.performance.unbounded_memory_operation");
    }

    #[test]
    fn rule_name_mentions_memory() {
        let rule = PythonUnboundedMemoryOperationRule::new();
        assert!(rule.name().contains("memory"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_safe_code() {
        let rule = PythonUnboundedMemoryOperationRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn fix_preview_for_all_contains_yield_per() {
        let preview = generate_fix_preview(".all()");
        assert!(preview.contains("yield_per"));
    }

    #[test]
    fn fix_preview_for_fetchall_contains_fetchmany() {
        let preview = generate_fix_preview(".fetchall()");
        assert!(preview.contains("fetchmany"));
    }

    #[test]
    fn fix_preview_for_json_load_contains_ijson() {
        let preview = generate_fix_preview("json.load(");
        assert!(preview.contains("ijson"));
    }
}