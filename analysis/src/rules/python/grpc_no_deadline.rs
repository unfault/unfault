//! Rule: gRPC Client Without Deadline
//!
//! Detects gRPC client calls that don't specify a deadline/timeout,
//! which can cause stuck channels and resource exhaustion.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::python::model::PyCallSite;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects gRPC client calls without deadlines.
#[derive(Debug, Default)]
pub struct PythonGrpcNoDeadlineRule;

impl PythonGrpcNoDeadlineRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for PythonGrpcNoDeadlineRule {
    fn id(&self) -> &'static str {
        "python.grpc.missing_deadline"
    }

    fn name(&self) -> &'static str {
        "gRPC Client Without Deadline"
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

            // Check if this file uses gRPC
            let has_grpc = py.imports.iter().any(|imp| {
                imp.module == "grpc"
                    || imp.module.starts_with("grpc.")
                    || imp.module.contains("_pb2_grpc")
            });

            if !has_grpc {
                continue;
            }

            // Check for gRPC calls without timeout/deadline
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;
                let args = &call.args_repr;
                let call_text = format!("{}({})", callee, args);
                let call_lower = call_text.to_lowercase();

                // Check for gRPC channel creation without options
                if callee.contains("grpc.insecure_channel") || callee.contains("grpc.secure_channel") {
                    // Check if options are specified
                    if !args.contains("options=") && !args.contains("options =") {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "gRPC channel without default timeout options".to_string(),
                            description: Some(
                                "This gRPC channel is created without specifying default timeout options. \
                                 Without timeouts, calls can hang indefinitely if the server is unresponsive."
                                    .to_string(),
                            ),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.85,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(generate_channel_patch(call, *file_id)),
                            fix_preview: Some(generate_channel_fix(callee)),
                            tags: vec!["grpc".to_string(), "timeout".to_string(), "deadline".to_string()],
                        });
                    }
                }

                // Check for stub method calls (these are the actual RPC calls)
                // Pattern: stub.MethodName(request) or stub.MethodName(request, timeout=...)
                if call_lower.contains("stub.") && !callee.contains("Stub(") {
                    // Check if timeout is specified
                    let has_timeout = args.contains("timeout=")
                        || args.contains("timeout =")
                        || args.contains("deadline=")
                        || args.contains("deadline =")
                        || (args.contains("metadata=") && args.contains("grpc-timeout"));

                    if !has_timeout {
                        // Extract method name
                        let method_name = extract_grpc_method_name(callee);
                        let is_streaming = call_lower.contains("stream");

                        let (title, description) = if is_streaming {
                            (
                                format!("gRPC streaming call '{}' without timeout", method_name),
                                format!(
                                    "This gRPC streaming call to '{}' doesn't specify a timeout. \
                                     Streaming calls without timeouts are especially dangerous as they can \
                                     hold connections open indefinitely.",
                                    method_name
                                ),
                            )
                        } else {
                            (
                                format!("gRPC unary call '{}' without timeout", method_name),
                                format!(
                                    "This gRPC unary call to '{}' doesn't specify a timeout. \
                                     Without a timeout, the call can hang indefinitely, blocking the thread \
                                     and potentially causing resource exhaustion.",
                                    method_name
                                ),
                            )
                        };

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::High,
                            confidence: 0.80,
                            dimension: Dimension::Stability,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(generate_stub_call_patch(call, *file_id)),
                            fix_preview: Some(generate_call_fix(&method_name, is_streaming)),
                            tags: vec!["grpc".to_string(), "timeout".to_string(), "deadline".to_string()],
                        });
                    }
                }

                // Check for aio (async) gRPC calls
                if callee.contains("grpc.aio.") {
                    if callee.contains("insecure_channel") || callee.contains("secure_channel") {
                        if !args.contains("options=") {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "Async gRPC channel without default timeout options".to_string(),
                                description: Some(
                                    "This async gRPC channel is created without specifying default timeout options. \
                                     Without timeouts, calls can hang indefinitely."
                                        .to_string(),
                                ),
                                kind: FindingKind::StabilityRisk,
                                severity: Severity::High,
                                confidence: 0.85,
                                dimension: Dimension::Stability,
                                file_id: *file_id,
                                file_path: py.path.clone(),
                                line: Some(call.function_call.location.line),
                                column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                                patch: Some(generate_channel_patch(call, *file_id)),
                                fix_preview: Some(generate_channel_fix(callee)),
                                tags: vec!["grpc".to_string(), "timeout".to_string(), "async".to_string()],
                            });
                        }
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::timeout())
    }
}

fn extract_grpc_method_name(callee: &str) -> String {
    // Try to extract method name from patterns like "stub.GetUser" or "self.stub.ListItems"
    if let Some(dot_pos) = callee.rfind('.') {
        return callee[dot_pos + 1..].to_string();
    }
    "unknown".to_string()
}

fn generate_channel_fix(callee: &str) -> String {
    let is_secure = callee.contains("secure_channel");
    let channel_type = if is_secure { "secure_channel" } else { "insecure_channel" };
    
    format!(
        r#"Add timeout options to the channel:

channel = grpc.{}(
    target,
    options=[
        ('grpc.keepalive_time_ms', 10000),
        ('grpc.keepalive_timeout_ms', 5000),
        ('grpc.keepalive_permit_without_calls', True),
        ('grpc.http2.max_pings_without_data', 0),
    ]
)"#,
        channel_type
    )
}

fn generate_call_fix(method: &str, is_streaming: bool) -> String {
    if is_streaming {
        format!(
            r#"Add a timeout to the streaming gRPC call:

# For server streaming:
responses = stub.{}(request, timeout=60.0)
for response in responses:
    process(response)

# For long-running streams, handle deadline exceeded:
import grpc

try:
    responses = stub.{}(request, timeout=30.0)
    for response in responses:
        yield response
except grpc.RpcError as e:
    if e.code() == grpc.StatusCode.DEADLINE_EXCEEDED:
        # Handle timeout - maybe reconnect
        pass
    raise"#,
            method, method
        )
    } else {
        format!(
            r#"Add a timeout to the gRPC call:

# Option 1: Add timeout parameter (in seconds)
response = stub.{}(request, timeout=30.0)

# Option 2: For more control, use wait_for_ready
response = stub.{}(
    request,
    timeout=30.0,
    wait_for_ready=True  # Wait for channel to be ready
)"#,
            method, method
        )
    }
}

/// Generate a patch to add timeout parameter to a gRPC stub method call.
///
/// Transforms: `stub.Method(request)` → `stub.Method(request, timeout=30.0)`
fn generate_stub_call_patch(call: &PyCallSite, file_id: FileId) -> FilePatch {
    let args_trimmed = call.args_repr.trim_matches(|c| c == '(' || c == ')');
    
    let replacement = if args_trimmed.is_empty() || args_trimmed.trim().is_empty() {
        // No existing arguments: stub.Method() → stub.Method(timeout=30.0)
        format!("{}(timeout=30.0)", call.function_call.callee_expr)
    } else {
        // Has arguments: stub.Method(request) → stub.Method(request, timeout=30.0)
        format!("{}({}, timeout=30.0)", call.function_call.callee_expr, args_trimmed)
    };

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: call.start_byte,
                end: call.end_byte,
            },
            replacement,
        }],
    }
}

/// Generate a patch to add options to a gRPC channel creation call.
///
/// This is more complex as we need to add the options= parameter.
fn generate_channel_patch(call: &PyCallSite, file_id: FileId) -> FilePatch {
    let args_trimmed = call.args_repr.trim_matches(|c| c == '(' || c == ')');
    
    // Add options parameter after the target
    let replacement = if args_trimmed.is_empty() {
        format!(
            "{}(options=[\
            ('grpc.keepalive_time_ms', 10000), \
            ('grpc.keepalive_timeout_ms', 5000)\
            ])",
            call.function_call.callee_expr
        )
    } else {
        format!(
            "{}({}, options=[\
            ('grpc.keepalive_time_ms', 10000), \
            ('grpc.keepalive_timeout_ms', 5000)\
            ])",
            call.function_call.callee_expr, args_trimmed
        )
    };

    FilePatch {
        file_id,
        hunks: vec![PatchHunk {
            range: PatchRange::ReplaceBytes {
                start: call.start_byte,
                end: call.end_byte,
            },
            replacement,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::parse::ast::FileId;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::semantics::SourceSemantics;
    use crate::types::context::{Language, SourceFile};
    use crate::types::patch::apply_file_patch;

    /// Helper to parse Python source and build semantics tuple
    fn parse_and_build_semantics(source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: "test.py".to_string(),
            language: Language::Python,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_python_file(file_id, &sf).expect("parsing should succeed");
        let mut sem = PyFileSemantics::from_parsed(&parsed);
        sem.analyze_frameworks(&parsed).expect("framework analysis should succeed");
        (file_id, Arc::new(SourceSemantics::Python(sem)))
    }

    #[test]
    fn test_rule_id() {
        let rule = PythonGrpcNoDeadlineRule::new();
        assert_eq!(rule.id(), "python.grpc.missing_deadline");
    }

    #[test]
    fn test_rule_name() {
        let rule = PythonGrpcNoDeadlineRule::new();
        assert_eq!(rule.name(), "gRPC Client Without Deadline");
    }

    #[test]
    fn test_extract_method_name() {
        assert_eq!(extract_grpc_method_name("stub.GetUser"), "GetUser");
        assert_eq!(extract_grpc_method_name("self.stub.ListItems"), "ListItems");
        // When there's no dot, return "unknown" since we can't extract the method name
        assert_eq!(extract_grpc_method_name("CreateOrder"), "unknown");
    }

    // ==================== Detection Tests ====================

    #[tokio::test]
    async fn detects_grpc_stub_call_without_timeout() {
        let rule = PythonGrpcNoDeadlineRule::new();
        let src = r#"
import grpc

stub = service_pb2_grpc.MyServiceStub(channel)
response = stub.GetUser(request)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty(), "Should detect stub call without timeout");
    }

    #[tokio::test]
    async fn no_finding_when_timeout_present() {
        let rule = PythonGrpcNoDeadlineRule::new();
        let src = r#"
import grpc

stub = service_pb2_grpc.MyServiceStub(channel)
response = stub.GetUser(request, timeout=30.0)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should not flag stub calls that already have timeout
        let stub_findings: Vec<_> = findings.iter()
            .filter(|f| f.title.contains("GetUser"))
            .collect();
        assert!(stub_findings.is_empty(), "Should not flag stub call with timeout");
    }

    #[tokio::test]
    async fn detects_grpc_channel_without_options() {
        let rule = PythonGrpcNoDeadlineRule::new();
        let src = r#"
import grpc

channel = grpc.insecure_channel('localhost:50051')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(!findings.is_empty(), "Should detect channel without options");
    }

    // ==================== Patch Application Tests ====================

    #[tokio::test]
    async fn patch_adds_timeout_to_stub_call() {
        let rule = PythonGrpcNoDeadlineRule::new();
        let src = "import grpc\nstub = service_pb2_grpc.MyServiceStub(channel)\nresponse = stub.GetUser(request)\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Find the stub call finding (title contains "GetUser" or "unary call")
        let stub_finding = findings.iter()
            .find(|f| f.title.contains("GetUser") || f.title.contains("unary call"))
            .expect("Should have a stub call finding");
        
        let patch = stub_finding.patch.as_ref().expect("Finding should have a patch");
        let patched = apply_file_patch(src, patch);
        
        // Verify the patch adds timeout
        assert!(patched.contains("timeout=30.0"), "Patched code should contain timeout");
        assert!(!patched.contains("stub.GetUser(request)") || patched.contains("stub.GetUser(request, timeout=30.0)"),
            "Stub call should have timeout added");
    }

    #[tokio::test]
    async fn patch_adds_options_to_channel() {
        let rule = PythonGrpcNoDeadlineRule::new();
        let src = "import grpc\nchannel = grpc.insecure_channel('localhost:50051')\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Find the channel finding
        let channel_finding = findings.iter()
            .find(|f| f.title.contains("channel"))
            .expect("Should have a channel finding");
        
        let patch = channel_finding.patch.as_ref().expect("Finding should have a patch");
        let patched = apply_file_patch(src, patch);
        
        // Verify the patch adds options
        assert!(patched.contains("options="), "Patched code should contain options");
        assert!(patched.contains("keepalive_time_ms"), "Options should include keepalive settings");
    }

    #[tokio::test]
    async fn patch_uses_replace_bytes() {
        let rule = PythonGrpcNoDeadlineRule::new();
        let src = "import grpc\nresponse = stub.GetUser(request)\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Any finding with a patch should use ReplaceBytes
        for finding in &findings {
            if let Some(patch) = &finding.patch {
                let has_replace_bytes = patch.hunks.iter().any(|h| {
                    matches!(h.range, PatchRange::ReplaceBytes { .. })
                });
                assert!(has_replace_bytes, "Patch should use ReplaceBytes for actual code replacement");
            }
        }
    }
}