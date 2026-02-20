//! Rule B12: I/O in hot paths detection
//!
//! Detects I/O operations (file reads, network calls, database queries)
//! inside loops or comprehensions that can cause performance issues.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects I/O operations in hot paths (loops, comprehensions).
///
/// I/O operations inside loops can cause severe performance degradation
/// due to repeated latency and resource consumption. These should be
/// batched, cached, or moved outside the loop.
#[derive(Debug)]
pub struct PythonIoInHotPathRule;

impl PythonIoInHotPathRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonIoInHotPathRule {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about an I/O operation in a hot path
#[derive(Debug, Clone)]
struct IoInHotPath {
    /// The I/O operation being called
    callee: String,
    /// The type of I/O operation
    io_type: IoOperationType,
    /// Line number (1-based)
    line: u32,
    /// Column number (1-based)
    column: u32,
    /// Whether it's in a loop
    in_loop: bool,
    /// Whether it's in a comprehension
    in_comprehension: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum IoOperationType {
    /// File system operations
    FileSystem,
    /// Network/HTTP operations
    Network,
    /// Database operations
    Database,
    /// External process execution
    ProcessExecution,
    /// Socket operations
    Socket,
    /// Generic I/O
    #[allow(dead_code)]
    Generic,
}

impl IoOperationType {
    fn description(&self) -> &'static str {
        match self {
            IoOperationType::FileSystem => "file system operation",
            IoOperationType::Network => "network operation",
            IoOperationType::Database => "database operation",
            IoOperationType::ProcessExecution => "process execution",
            IoOperationType::Socket => "socket operation",
            IoOperationType::Generic => "I/O operation",
        }
    }
}

#[async_trait]
impl Rule for PythonIoInHotPathRule {
    fn id(&self) -> &'static str {
        "python.io_in_hot_path"
    }

    fn name(&self) -> &'static str {
        "I/O operation in loop or comprehension causes performance issues"
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
                #[allow(unreachable_patterns)]
                _ => continue,
            };

            // Check all calls for I/O operations in loops/comprehensions
            for call in &py.calls {
                // Only check calls that are in loops or comprehensions
                if !call.in_loop && !call.in_comprehension {
                    continue;
                }

                if let Some(io_type) = detect_io_operation(&call.function_call.callee_expr) {
                    findings.push(create_finding(
                        self.id(),
                        &IoInHotPath {
                            callee: call.function_call.callee_expr.clone(),
                            io_type,
                            line: call.function_call.location.line,
                            column: call.function_call.location.column,
                            in_loop: call.in_loop,
                            in_comprehension: call.in_comprehension,
                        },
                        *file_id,
                        &py.path,
                    ));
                }
            }
        }

        findings
    }
}

fn detect_io_operation(callee: &str) -> Option<IoOperationType> {
    // File system operations
    if callee.starts_with("open(")
        || callee == "open"
        || callee.contains("pathlib")
        || callee.contains(".read(")
        || callee.contains(".write(")
        || callee.contains(".readlines(")
        || callee.contains(".writelines(")
        || callee.contains("os.path")
        || callee.contains("os.listdir")
        || callee.contains("os.walk")
        || callee.contains("os.stat")
        || callee.contains("os.remove")
        || callee.contains("os.rename")
        || callee.contains("os.mkdir")
        || callee.contains("os.makedirs")
        || callee.contains("shutil.")
        || callee.contains("glob.glob")
        || callee.contains("glob.iglob")
    {
        return Some(IoOperationType::FileSystem);
    }

    // Network operations
    if callee.contains("requests.")
        || callee.contains("httpx.")
        || callee.contains("aiohttp.")
        || callee.contains("urllib.")
        || callee.contains("http.client")
        || callee.contains(".get(")
        || callee.contains(".post(")
        || callee.contains(".put(")
        || callee.contains(".delete(")
        || callee.contains(".patch(")
        || callee.contains(".fetch(")
    {
        // Avoid false positives for dict.get()
        if callee.contains("requests.")
            || callee.contains("httpx.")
            || callee.contains("aiohttp.")
            || callee.contains("urllib.")
            || callee.contains("http.client")
        {
            return Some(IoOperationType::Network);
        }
    }

    // Database operations
    if callee.contains(".execute(")
        || callee.contains(".executemany(")
        || callee.contains(".fetchone(")
        || callee.contains(".fetchall(")
        || callee.contains(".fetchmany(")
        || callee.contains(".query(")
        || callee.contains(".filter(")
        || callee.contains(".all(")
        || callee.contains(".first(")
        || callee.contains(".get(")
        || callee.contains("cursor.")
        || callee.contains("session.query")
        || callee.contains("Session.query")
    {
        // Check for ORM/DB patterns
        if callee.contains("execute")
            || callee.contains("fetch")
            || callee.contains("cursor")
            || callee.contains("session.query")
            || callee.contains("Session.query")
        {
            return Some(IoOperationType::Database);
        }
    }

    // Process execution
    if callee.contains("subprocess.")
        || callee.contains("os.system")
        || callee.contains("os.popen")
        || callee.contains("os.spawn")
        || callee.contains("Popen")
        || callee.contains(".run(")
        || callee.contains(".call(")
        || callee.contains(".check_output(")
        || callee.contains(".check_call(")
    {
        if callee.contains("subprocess")
            || callee.contains("os.system")
            || callee.contains("os.popen")
            || callee.contains("os.spawn")
            || callee.contains("Popen")
        {
            return Some(IoOperationType::ProcessExecution);
        }
    }

    // Socket operations
    if callee.contains("socket.")
        || callee.contains(".connect(")
        || callee.contains(".send(")
        || callee.contains(".recv(")
        || callee.contains(".sendall(")
        || callee.contains(".accept(")
        || callee.contains(".listen(")
    {
        if callee.contains("socket") {
            return Some(IoOperationType::Socket);
        }
    }

    None
}

fn create_finding(
    rule_id: &str,
    io_call: &IoInHotPath,
    file_id: FileId,
    file_path: &str,
) -> RuleFinding {
    let context = if io_call.in_loop && io_call.in_comprehension {
        "loop and comprehension"
    } else if io_call.in_loop {
        "loop"
    } else {
        "comprehension"
    };

    let title = format!(
        "{} '{}' inside {} causes performance issues",
        io_call.io_type.description(),
        io_call.callee,
        context
    );

    let description = format!(
        "The {} '{}' is called inside a {}, which can cause severe performance \
         degradation due to repeated I/O latency. Consider:\n\
         - Batching operations (e.g., bulk database queries)\n\
         - Caching results before the loop\n\
         - Moving the I/O operation outside the loop\n\
         - Using async/concurrent execution for independent operations",
        io_call.io_type.description(),
        io_call.callee,
        context
    );

    let patch = generate_batch_suggestion_patch(io_call, file_id);

    let fix_preview = format!(
        r#"# Before (I/O in loop):
for item in items:
    result = {callee}(item)  # I/O on each iteration

# After (batched):
# Option 1: Batch the operation
results = batch_{callee}(items)

# Option 2: Cache before loop
cache = {{}}
for item in items:
    if item not in cache:
        cache[item] = {callee}(item)
    result = cache[item]

# Option 3: Concurrent execution
import asyncio
results = await asyncio.gather(*[async_{callee}(item) for item in items])"#,
        callee = io_call.callee.split('.').last().unwrap_or(&io_call.callee)
    );

    RuleFinding {
        rule_id: rule_id.to_string(),
        title,
        description: Some(description),
        kind: FindingKind::PerformanceSmell,
        severity: Severity::High,
        confidence: 0.85,
        dimension: Dimension::Performance,
        file_id,
        file_path: file_path.to_string(),
        line: Some(io_call.line),
        column: Some(io_call.column),
        end_line: None,
        end_column: None,
        byte_range: None,
        patch: Some(patch),
        fix_preview: Some(fix_preview),
        tags: vec![
            "python".into(),
            "performance".into(),
            "io".into(),
            "hot-path".into(),
            "loop".into(),
        ],
    }
}

fn generate_batch_suggestion_patch(io_call: &IoInHotPath, file_id: FileId) -> FilePatch {
    let func_name = io_call.callee.split('.').last().unwrap_or(&io_call.callee);

    // Generate specific fix based on I/O type
    let replacement = match io_call.io_type {
        IoOperationType::FileSystem => {
            format!(
                "# Fix: Move file I/O outside the loop or batch operations:\n\
                 # # Option 1: Read all files before loop\n\
                 # all_data = {{f: open(f).read() for f in files}}\n\
                 # for item in items:\n\
                 #     data = all_data[item]\n"
            )
        }
        IoOperationType::Network => {
            format!(
                "# Fix: Use async/concurrent requests instead of sequential:\n\
                 # import asyncio\n\
                 # async def fetch_all(urls):\n\
                 #     return await asyncio.gather(*[{}(url) for url in urls])\n",
                func_name
            )
        }
        IoOperationType::Database => {
            format!(
                "# Fix: Use batch query instead of N individual queries:\n\
                 # # Instead of: for id in ids: db.query(id)\n\
                 # # Use: results = db.query_batch(ids)  # Single query\n\
                 # # Or: results = Model.objects.filter(id__in=ids)\n"
            )
        }
        IoOperationType::ProcessExecution => {
            format!(
                "# Fix: Batch subprocess calls or use parallel execution:\n\
                 # import concurrent.futures\n\
                 # with concurrent.futures.ThreadPoolExecutor() as executor:\n\
                 #     results = list(executor.map({}, items))\n",
                func_name
            )
        }
        IoOperationType::Socket => {
            format!(
                "# Fix: Use connection pooling or async sockets:\n\
                 # # Reuse connections instead of creating new ones in loop\n\
                 # # Or use asyncio for concurrent socket operations\n"
            )
        }
        IoOperationType::Generic => {
            format!(
                "# Fix: Move '{}' outside the loop or batch the operations\n",
                io_call.callee
            )
        }
    };

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::InsertBeforeLine { line: io_call.line },
            replacement,
        }],
    }
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
        let rule = PythonIoInHotPathRule::new();
        assert_eq!(rule.id(), "python.io_in_hot_path");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonIoInHotPathRule::new();
        assert!(rule.name().contains("I/O"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonIoInHotPathRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonIoInHotPathRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonIoInHotPathRule::default();
        assert_eq!(rule.id(), "python.io_in_hot_path");
    }

    #[tokio::test]
    async fn detects_file_open_in_loop() {
        let rule = PythonIoInHotPathRule::new();
        let src = r#"
for filename in filenames:
    with open(filename) as f:
        data = f.read()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(!findings.is_empty(), "Should detect open() in loop");
        assert_eq!(findings[0].rule_id, "python.io_in_hot_path");
    }

    #[tokio::test]
    async fn detects_http_request_in_loop() {
        let rule = PythonIoInHotPathRule::new();
        let src = r#"
import requests

for url in urls:
    response = requests.get(url)
    data = response.json()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(!findings.is_empty(), "Should detect requests.get in loop");
    }

    #[tokio::test]
    async fn detects_db_query_in_comprehension() {
        let rule = PythonIoInHotPathRule::new();
        let src = r#"
results = [cursor.execute(f"SELECT * FROM users WHERE id = {id}") for id in user_ids]
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        assert!(
            !findings.is_empty(),
            "Should detect cursor.execute in comprehension"
        );
    }

    #[tokio::test]
    async fn no_finding_for_io_outside_loop() {
        let rule = PythonIoInHotPathRule::new();
        let src = r#"
import requests

response = requests.get("https://api.example.com/data")
data = response.json()

for item in data:
    process(item)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        // Should not flag I/O outside loops
        let io_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "python.io_in_hot_path")
            .collect();
        assert!(io_findings.is_empty(), "Should not flag I/O outside loops");
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = PythonIoInHotPathRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = PythonIoInHotPathRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = PythonIoInHotPathRule::new();
        let src = r#"
for f in files:
    data = open(f).read()
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;

        if !findings.is_empty() {
            let finding = &findings[0];
            assert_eq!(finding.rule_id, "python.io_in_hot_path");
            assert!(matches!(finding.kind, FindingKind::PerformanceSmell));
            assert_eq!(finding.dimension, Dimension::Performance);
            assert!(finding.patch.is_some());
            assert!(finding.fix_preview.is_some());
            assert!(finding.tags.contains(&"hot-path".to_string()));
        }
    }

    #[test]
    fn detect_io_operation_identifies_file_operations() {
        assert!(matches!(
            detect_io_operation("open"),
            Some(IoOperationType::FileSystem)
        ));
        assert!(matches!(
            detect_io_operation("os.listdir"),
            Some(IoOperationType::FileSystem)
        ));
    }

    #[test]
    fn detect_io_operation_identifies_network_operations() {
        assert!(matches!(
            detect_io_operation("requests.get"),
            Some(IoOperationType::Network)
        ));
        assert!(matches!(
            detect_io_operation("httpx.post"),
            Some(IoOperationType::Network)
        ));
    }

    #[test]
    fn detect_io_operation_identifies_database_operations() {
        assert!(matches!(
            detect_io_operation("cursor.execute"),
            Some(IoOperationType::Database)
        ));
        assert!(matches!(
            detect_io_operation("cursor.fetchall"),
            Some(IoOperationType::Database)
        ));
    }

    #[test]
    fn detect_io_operation_identifies_subprocess() {
        assert!(matches!(
            detect_io_operation("subprocess.run"),
            Some(IoOperationType::ProcessExecution)
        ));
        assert!(matches!(
            detect_io_operation("os.system"),
            Some(IoOperationType::ProcessExecution)
        ));
    }

    #[test]
    fn io_operation_type_descriptions_are_meaningful() {
        assert!(IoOperationType::FileSystem.description().contains("file"));
        assert!(IoOperationType::Network.description().contains("network"));
        assert!(IoOperationType::Database.description().contains("database"));
    }
}
