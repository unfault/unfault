//! Rule B15: Ephemeral filesystem writes detection
//!
//! Detects writes to local filesystem paths that may be ephemeral in
//! containerized or serverless environments (Docker, Kubernetes, Lambda, etc.).

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::error_handling_in_handler;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::ImportInsertionType;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects writes to ephemeral filesystem locations.
///
/// In containerized and serverless environments, the local filesystem is
/// typically ephemeral and data written to it will be lost when the
/// container/function instance is terminated. This rule flags writes to
/// paths that are likely ephemeral and suggests using persistent storage.
#[derive(Debug)]
pub struct PythonEphemeralFilesystemWriteRule;

impl PythonEphemeralFilesystemWriteRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonEphemeralFilesystemWriteRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about an ephemeral filesystem write
#[derive(Debug, Clone)]
struct EphemeralWrite {
    /// The operation being performed
    callee: String,
    /// The type of write operation
    write_type: WriteOperationType,
    /// The path being written to (if detectable)
    path_hint: Option<String>,
    /// Line number (1-based)
    line: u32,
    /// Column number (1-based)
    column: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum WriteOperationType {
    /// File open with write mode
    FileOpen,
    /// Direct file write
    FileWrite,
    /// Path-based write (pathlib)
    PathWrite,
    /// Temporary file creation
    TempFile,
    /// Directory creation
    DirectoryCreate,
    /// File copy/move
    FileCopyMove,
    /// Pickle/serialization to file
    Serialization,
}

impl WriteOperationType {
    fn description(&self) -> &'static str {
        match self {
            WriteOperationType::FileOpen => "file open for writing",
            WriteOperationType::FileWrite => "file write",
            WriteOperationType::PathWrite => "path write",
            WriteOperationType::TempFile => "temporary file creation",
            WriteOperationType::DirectoryCreate => "directory creation",
            WriteOperationType::FileCopyMove => "file copy/move",
            WriteOperationType::Serialization => "serialization to file",
        }
    }
}

#[async_trait]
impl Rule for PythonEphemeralFilesystemWriteRule {
    fn id(&self) -> &'static str {
        "python.ephemeral_filesystem_write"
    }

    fn name(&self) -> &'static str {
        "Filesystem write may be lost in ephemeral environment"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(error_handling_in_handler())
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
                #[allow(unreachable_patterns)]
                _ => continue,
            };

            // Check all calls for filesystem write operations
            for call in &py.calls {
                if let Some((write_type, path_hint)) =
                    detect_filesystem_write(&call.function_call.callee_expr, &call.args_repr)
                {
                    // Skip writes to known persistent paths
                    if let Some(ref path) = path_hint {
                        if is_persistent_path(path) {
                            continue;
                        }
                    }

                    // Use third_party_import since we're adding "import boto3"
                    findings.push(create_finding(
                        self.id(),
                        &EphemeralWrite {
                            callee: call.function_call.callee_expr.clone(),
                            write_type,
                            path_hint,
                            line: call.function_call.location.line,
                            column: call.function_call.location.column,
                        },
                        *file_id,
                        &py.path,
                        py.import_insertion_line_for(ImportInsertionType::third_party_import()),
                    ));
                }
            }
        }

        findings
    }
}

fn detect_filesystem_write(
    callee: &str,
    args: &str,
) -> Option<(WriteOperationType, Option<String>)> {
    // File open with write mode
    if callee == "open" || callee.ends_with(".open") {
        // Check for write modes: 'w', 'a', 'x', 'wb', 'ab', 'xb', etc.
        if args.contains("'w")
            || args.contains("\"w")
            || args.contains("'a")
            || args.contains("\"a")
            || args.contains("'x")
            || args.contains("\"x")
            || args.contains("mode='w")
            || args.contains("mode=\"w")
            || args.contains("mode='a")
            || args.contains("mode=\"a")
        {
            let path = extract_path_from_args(args);
            return Some((WriteOperationType::FileOpen, path));
        }
    }

    // Direct file write methods
    if callee.contains(".write(") || callee.contains(".writelines(") {
        return Some((WriteOperationType::FileWrite, None));
    }

    // Pathlib write operations
    if callee.contains("Path(")
        && (callee.contains(".write_text(") || callee.contains(".write_bytes("))
    {
        let path = extract_path_from_args(args);
        return Some((WriteOperationType::PathWrite, path));
    }
    if callee.contains(".write_text(") || callee.contains(".write_bytes(") {
        return Some((WriteOperationType::PathWrite, None));
    }

    // Temporary file creation
    if callee.contains("tempfile.")
        || callee.contains("NamedTemporaryFile")
        || callee.contains("TemporaryFile")
        || callee.contains("mkstemp")
        || callee.contains("mkdtemp")
    {
        return Some((WriteOperationType::TempFile, None));
    }

    // Directory creation
    if callee.contains("os.mkdir")
        || callee.contains("os.makedirs")
        || callee.contains("Path.mkdir")
        || callee.contains(".mkdir(")
    {
        let path = extract_path_from_args(args);
        return Some((WriteOperationType::DirectoryCreate, path));
    }

    // File copy/move operations
    if callee.contains("shutil.copy")
        || callee.contains("shutil.move")
        || callee.contains("shutil.copytree")
        || callee.contains("os.rename")
    {
        return Some((WriteOperationType::FileCopyMove, None));
    }

    // Serialization to file
    if callee.contains("pickle.dump")
        || callee.contains("json.dump")
        || callee.contains("yaml.dump")
        || callee.contains("toml.dump")
        || callee.contains("torch.save")
        || callee.contains("joblib.dump")
        || callee.contains("np.save")
        || callee.contains("numpy.save")
    {
        return Some((WriteOperationType::Serialization, None));
    }

    None
}

fn extract_path_from_args(args: &str) -> Option<String> {
    // Try to extract a string literal path from arguments
    // This is a simple heuristic - look for quoted strings
    let args_trimmed = args.trim_start_matches('(').trim_end_matches(')');

    // Look for single or double quoted strings
    for quote in &['\'', '"'] {
        if let Some(start) = args_trimmed.find(*quote) {
            if let Some(end) = args_trimmed[start + 1..].find(*quote) {
                let path = &args_trimmed[start + 1..start + 1 + end];
                if !path.is_empty() {
                    return Some(path.to_string());
                }
            }
        }
    }

    None
}

fn is_persistent_path(path: &str) -> bool {
    // Paths that are typically persistent even in containers
    let persistent_prefixes = [
        "/mnt/",        // Mounted volumes
        "/data/",       // Common data mount point
        "/var/data/",   // Data directory
        "/persistent/", // Explicit persistent storage
        "/efs/",        // AWS EFS
        "/nfs/",        // NFS mounts
        "/shared/",     // Shared storage
        "s3://",        // S3 (not local filesystem)
        "gs://",        // Google Cloud Storage
        "az://",        // Azure Blob Storage
        "hdfs://",      // HDFS
    ];

    for prefix in &persistent_prefixes {
        if path.starts_with(prefix) {
            return true;
        }
    }

    // Environment variable paths are often configured for persistence
    if path.starts_with("$") || path.contains("${") || path.contains("os.environ") {
        return true;
    }

    false
}

fn create_finding(
    rule_id: &str,
    write: &EphemeralWrite,
    file_id: FileId,
    file_path: &str,
    import_line: u32,
) -> RuleFinding {
    let path_info = write
        .path_hint
        .as_ref()
        .map(|p| format!(" to '{}'", p))
        .unwrap_or_default();

    let title = format!(
        "{}{} may be lost in ephemeral environment",
        write.write_type.description(),
        path_info
    );

    let description = format!(
        "The {} operation '{}'{} writes to the local filesystem, which is \
         ephemeral in containerized (Docker, Kubernetes) and serverless \
         (Lambda, Cloud Functions) environments. Data written here will be \
         lost when the container/instance terminates.\n\n\
         Consider using:\n\
         - Object storage (S3, GCS, Azure Blob)\n\
         - Mounted persistent volumes\n\
         - Database storage\n\
         - Redis/Memcached for caching",
        write.write_type.description(),
        write.callee,
        path_info
    );

    let patch = generate_storage_suggestion_patch(write, file_id, import_line);

    let fix_preview = format!(
        r#"# Before (ephemeral write):
with open("{path}", "w") as f:
    f.write(data)

# After (persistent storage):
# Option 1: Use object storage
import boto3
s3 = boto3.client('s3')
s3.put_object(Bucket='my-bucket', Key='{path}', Body=data)

# Option 2: Use mounted volume
with open("/mnt/persistent/{path}", "w") as f:
    f.write(data)

# Option 3: Use database
db.execute("INSERT INTO files (name, content) VALUES (?, ?)", ['{path}', data])"#,
        path = write.path_hint.as_deref().unwrap_or("output.txt")
    );

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::StabilityRisk,
        severity: Severity::Medium,
        confidence: 0.70,
        dimension: Dimension::Stability,
        file_id,
        file_path: file_path.to_string(),
        line: Some(write.line),
        column: Some(write.column),
        end_line: None,
        end_column: None,
        byte_range: None,
        patch: Some(patch),
        fix_preview: Some(fix_preview),
        tags: vec![
            "python".into(),
            "filesystem".into(),
            "ephemeral".into(),
            "container".into(),
            "serverless".into(),
        ],
    }
}

fn generate_storage_suggestion_patch(
    write: &EphemeralWrite,
    file_id: FileId,
    import_line: u32,
) -> FilePatch {
    let mut hunks = Vec::new();

    // Generate specific fix based on write type
    let (import_str, replacement) = match write.write_type {
        WriteOperationType::FileOpen
        | WriteOperationType::FileWrite
        | WriteOperationType::PathWrite => {
            let path = write.path_hint.as_deref().unwrap_or("output.txt");
            let import = "import boto3  # or: from google.cloud import storage\n";
            let fix = format!(
                "# Fix: Use object storage instead of local filesystem:\n\
                 # s3 = boto3.client('s3')\n\
                 # s3.put_object(Bucket='my-bucket', Key='{}', Body=data)\n\
                 # Or use mounted persistent volume: /mnt/persistent/{}\n",
                path, path
            );
            (import, fix)
        }
        WriteOperationType::TempFile => {
            let import = "";
            let fix = "# Fix: For temporary files in containers, use:\n\
                 # - /tmp with awareness it's ephemeral\n\
                 # - Redis/Memcached for temporary data\n\
                 # - Object storage with TTL for larger temp files\n"
                .to_string();
            (import, fix)
        }
        WriteOperationType::DirectoryCreate => {
            let import = "";
            let fix = "# Fix: Create directories on persistent volumes:\n\
                 # os.makedirs('/mnt/persistent/my_dir', exist_ok=True)\n"
                .to_string();
            (import, fix)
        }
        WriteOperationType::FileCopyMove => {
            let import = "";
            let fix = "# Fix: Copy/move to persistent storage:\n\
                 # shutil.copy(src, '/mnt/persistent/dest')\n\
                 # Or upload to object storage after copy\n"
                .to_string();
            (import, fix)
        }
        WriteOperationType::Serialization => {
            let import = "import boto3\n";
            let fix = "# Fix: Serialize to object storage or database:\n\
                 # # Option 1: S3\n\
                 # import io\n\
                 # buffer = io.BytesIO()\n\
                 # pickle.dump(obj, buffer)\n\
                 # s3.put_object(Bucket='bucket', Key='model.pkl', Body=buffer.getvalue())\n\
                 # # Option 2: Database BLOB\n\
                 # db.execute('INSERT INTO models (data) VALUES (?)', [pickle.dumps(obj)])\n"
                .to_string();
            (import, fix)
        }
    };

    // Add import if needed
    if !import_str.is_empty() {
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: import_line },
            replacement: import_str.to_string(),
        });
    }

    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: write.line },
        replacement,
    });

    FilePatch { file_id, hunks }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::SourceSemantics;
    use crate::semantics::python::build_python_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_python_semantics(&parsed).expect("semantics should build");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    #[test]
    fn rule_id_is_correct() {
        let rule = PythonEphemeralFilesystemWriteRule::new();
        assert_eq!(rule.id(), "python.ephemeral_filesystem_write");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonEphemeralFilesystemWriteRule::new();
        assert!(rule.name().contains("ephemeral"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonEphemeralFilesystemWriteRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonEphemeralFilesystemWriteRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonEphemeralFilesystemWriteRule::default();
        assert_eq!(rule.id(), "python.ephemeral_filesystem_write");
    }

    #[tokio::test]
    async fn detects_file_open_write_mode() {
        let rule = PythonEphemeralFilesystemWriteRule::new();
        let src = r#"
with open("output.txt", "w") as f:
    f.write("data")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(!findings.is_empty(), "Should detect open() with write mode");
        assert_eq!(findings[0].rule_id, "python.ephemeral_filesystem_write");
    }

    #[tokio::test]
    async fn detects_tempfile_creation() {
        let rule = PythonEphemeralFilesystemWriteRule::new();
        let src = r#"
import tempfile

with tempfile.NamedTemporaryFile() as f:
    f.write(b"data")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(!findings.is_empty(), "Should detect tempfile creation");
    }

    #[tokio::test]
    async fn detects_pickle_dump() {
        let rule = PythonEphemeralFilesystemWriteRule::new();
        let src = r#"
import pickle

with open("model.pkl", "wb") as f:
    pickle.dump(model, f)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should detect both open() and pickle.dump()
        assert!(!findings.is_empty(), "Should detect pickle.dump");
    }

    #[tokio::test]
    async fn no_finding_for_read_mode() {
        let rule = PythonEphemeralFilesystemWriteRule::new();
        let src = r#"
with open("input.txt", "r") as f:
    data = f.read()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(findings.is_empty(), "Should not flag read-only operations");
    }

    #[tokio::test]
    async fn no_finding_for_persistent_path() {
        let rule = PythonEphemeralFilesystemWriteRule::new();
        let src = r#"
with open("/mnt/data/output.txt", "w") as f:
    f.write("data")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            findings.is_empty(),
            "Should not flag writes to persistent paths"
        );
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = PythonEphemeralFilesystemWriteRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = PythonEphemeralFilesystemWriteRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = PythonEphemeralFilesystemWriteRule::new();
        let src = r#"
with open("/tmp/output.txt", "w") as f:
    f.write("data")
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        if !findings.is_empty() {
            let finding = &findings[0];
            assert_eq!(finding.rule_id, "python.ephemeral_filesystem_write");
            assert!(matches!(finding.kind, FindingKind::StabilityRisk));
            assert_eq!(finding.dimension, Dimension::Stability);
            assert!(finding.patch.is_some());
            assert!(finding.fix_preview.is_some());
            assert!(finding.tags.contains(&"ephemeral".to_string()));
        }
    }

    #[test]
    fn detect_filesystem_write_identifies_open_write() {
        let result = detect_filesystem_write("open", "('file.txt', 'w')");
        assert!(result.is_some());
        let (write_type, _) = result.unwrap();
        assert!(matches!(write_type, WriteOperationType::FileOpen));
    }

    #[test]
    fn detect_filesystem_write_identifies_tempfile() {
        let result = detect_filesystem_write("tempfile.NamedTemporaryFile", "()");
        assert!(result.is_some());
        let (write_type, _) = result.unwrap();
        assert!(matches!(write_type, WriteOperationType::TempFile));
    }

    #[test]
    fn detect_filesystem_write_ignores_read_mode() {
        let result = detect_filesystem_write("open", "('file.txt', 'r')");
        assert!(result.is_none());
    }

    #[test]
    fn is_persistent_path_identifies_mounted_volumes() {
        assert!(is_persistent_path("/mnt/data/file.txt"));
        assert!(is_persistent_path("/efs/shared/file.txt"));
        assert!(is_persistent_path("s3://bucket/key"));
    }

    #[test]
    fn is_persistent_path_rejects_local_paths() {
        assert!(!is_persistent_path("/tmp/file.txt"));
        assert!(!is_persistent_path("./output.txt"));
        assert!(!is_persistent_path("/home/user/file.txt"));
    }

    #[test]
    fn write_operation_type_descriptions_are_meaningful() {
        assert!(WriteOperationType::FileOpen.description().contains("file"));
        assert!(
            WriteOperationType::TempFile
                .description()
                .contains("temporary")
        );
        assert!(
            WriteOperationType::Serialization
                .description()
                .contains("serialization")
        );
    }
}
