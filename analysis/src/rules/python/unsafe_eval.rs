//! Rule: eval/exec and Dynamic Code Execution
//!
//! Detects usage of eval(), exec(), and other dynamic code execution patterns.
//! Using explicit code paths rather than dynamic execution makes code behavior
//! predictable and easier to review.

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::hardcoded_secrets;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::{PyCallSite, PyFileSemantics};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects unsafe dynamic code execution.
#[derive(Debug, Default)]
pub struct PythonUnsafeEvalRule;

impl PythonUnsafeEvalRule {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Rule for PythonUnsafeEvalRule {
    fn id(&self) -> &'static str {
        "python.unsafe_eval"
    }

    fn name(&self) -> &'static str {
        "Unsafe Dynamic Code Execution"
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(hardcoded_secrets())
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

            // Check for unsafe dynamic code execution patterns
            for call in &py.calls {
                let callee = &call.function_call.callee_expr;
                let args = &call.args_repr;

                // Get the enclosing function's parameter names for taint analysis
                let enclosing_params = get_enclosing_function_params(py, call);

                // Check for eval()
                if callee == "eval" {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Dynamic code execution via eval()".to_string(),
                        description: Some(
                            "eval() executes Python code dynamically. Using explicit code paths \
                             makes behavior predictable and easier to review. Consider using \
                             ast.literal_eval() for safe literal evaluation or restructuring \
                             the code to avoid dynamic execution."
                                .to_string(),
                        ),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::Critical,
                        confidence: 0.95,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column as u32),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: None,
                        fix_preview: Some(EVAL_FIX.to_string()),
                        tags: vec![
                            "security".to_string(),
                            "code-injection".to_string(),
                            "rce".to_string(),
                        ],
                    });
                }

                // Check for exec()
                if callee == "exec" {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Dynamic code execution via exec()".to_string(),
                        description: Some(
                            "exec() executes Python code dynamically. Using explicit code paths \
                             makes behavior predictable and easier to review. Consider using \
                             configuration files or plugin patterns for dynamic behavior."
                                .to_string(),
                        ),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::Critical,
                        confidence: 0.95,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column as u32),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: None,
                        fix_preview: Some(EXEC_FIX.to_string()),
                        tags: vec![
                            "security".to_string(),
                            "code-injection".to_string(),
                            "rce".to_string(),
                        ],
                    });
                }

                // Check for compile() with exec mode
                if callee == "compile" && args.contains("exec") {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Dynamic code compilation via compile()".to_string(),
                        description: Some(
                            "compile() with exec mode enables dynamic code execution. \
                             Using explicit code paths makes behavior predictable and easier to review. \
                             Consider AST parsing for analysis without execution."
                                .to_string(),
                        ),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::Critical,
                        confidence: 0.90,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some("Avoid compile() with 'exec' mode. Use safer alternatives like AST parsing for analysis.".to_string()),
                        tags: vec!["security".to_string(), "code-injection".to_string()],
                    });
                }

                // Check for __import__() with variables
                if callee == "__import__" {
                    // Check if it's using a variable (not a string literal)
                    if !args.starts_with('"') && !args.starts_with('\'') {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Dynamic import with variable module name".to_string(),
                            description: Some(
                                "__import__() with a variable module name enables dynamic module loading. \
                                 Using an explicit allowlist of modules makes the import behavior predictable \
                                 and the codebase easier to review."
                                    .to_string(),
                            ),
                            kind: FindingKind::BehaviorThreat,
                            severity: Severity::High,
                            confidence: 0.80,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: None,
                            fix_preview: Some(DYNAMIC_IMPORT_FIX.to_string()),
                            tags: vec!["security".to_string(), "import".to_string()],
                        });
                    }
                }

                // Check for getattr() with non-literal attribute names that come from user input
                if callee == "getattr" {
                    // Check if the second argument is a variable (potential user input)
                    let parts: Vec<&str> = args.split(',').collect();
                    if parts.len() >= 2 {
                        let attr_arg = parts[1].trim();
                        // Strip parentheses that might wrap the argument
                        let attr_arg = attr_arg.trim_end_matches(')');

                        // If it's a string literal, it's safe
                        if attr_arg.starts_with('"') || attr_arg.starts_with('\'') {
                            continue;
                        }

                        // Only flag if the variable is directly a function parameter (user input)
                        // Variables that come from intermediate sources like dict.get() are not flagged
                        // as they are typically constrained by the dictionary keys
                        if is_user_input(&enclosing_params, attr_arg) {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "getattr() with user-controlled attribute name".to_string(),
                                description: Some(
                                    "Using getattr() with a dynamic attribute name from a function parameter. \
                                     Constraining attribute access to an explicit allowlist makes the \
                                     accessible attributes clear and the code easier to review."
                                        .to_string(),
                                ),
                                kind: FindingKind::BehaviorThreat,
                                severity: Severity::Medium,
                                confidence: 0.85,
                                dimension: Dimension::Correctness,
                                file_id: *file_id,
                                file_path: py.path.clone(),
                                line: Some(call.function_call.location.line),
                                column: Some(call.function_call.location.column as u32),
                                end_line: None,
                                end_column: None,
            byte_range: None,
                                patch: None,
                                fix_preview: Some(GETATTR_FIX.to_string()),
                                tags: vec!["security".to_string(), "attribute-access".to_string()],
                            });
                        }
                    }
                }

                // Check for setattr() with non-literal attribute names that come from user input
                if callee == "setattr" {
                    let parts: Vec<&str> = args.split(',').collect();
                    if parts.len() >= 2 {
                        let attr_arg = parts[1].trim();
                        // Strip parentheses that might wrap the argument
                        let attr_arg = attr_arg.trim_end_matches(')');

                        // If it's a string literal, it's safe
                        if attr_arg.starts_with('"') || attr_arg.starts_with('\'') {
                            continue;
                        }

                        // Only flag if the variable is directly a function parameter (user input)
                        if is_user_input(&enclosing_params, attr_arg) {
                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title: "setattr() with user-controlled attribute name".to_string(),
                                description: Some(
                                    "Using setattr() with a dynamic attribute name from a function parameter. \
                                     Constraining attribute modification to an explicit allowlist makes the \
                                     modifiable attributes clear and the code easier to review."
                                        .to_string(),
                                ),
                                kind: FindingKind::BehaviorThreat,
                                severity: Severity::High,
                                confidence: 0.85,
                                dimension: Dimension::Correctness,
                                file_id: *file_id,
                                file_path: py.path.clone(),
                                line: Some(call.function_call.location.line),
                                column: Some(call.function_call.location.column as u32),
                                end_line: None,
                                end_column: None,
            byte_range: None,
                                patch: None,
                                fix_preview: Some(SETATTR_FIX.to_string()),
                                tags: vec!["security".to_string(), "attribute-access".to_string()],
                            });
                        }
                    }
                }

                // Check for pickle.loads() - always potentially unsafe
                if callee == "pickle.loads"
                    || callee == "pickle.load"
                    || callee == "cPickle.loads"
                    || callee == "cPickle.load"
                {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Unsafe pickle deserialization".to_string(),
                        description: Some(
                            "pickle.load()/loads() can execute arbitrary code during deserialization. \
                             Never unpickle data from untrusted sources."
                                .to_string(),
                        ),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::Critical,
                        confidence: 0.90,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(PICKLE_FIX.to_string()),
                        tags: vec!["security".to_string(), "deserialization".to_string(), "rce".to_string()],
                    });
                }

                // Check for yaml.load() without SafeLoader
                if callee == "yaml.load" {
                    if !args.contains("Loader=") && !args.contains("SafeLoader") {
                        let patch = generate_yaml_safe_load_patch(call, *file_id);
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Unsafe YAML loading".to_string(),
                            description: Some(
                                "yaml.load() without SafeLoader allows YAML tags that execute Python code. \
                                 Using yaml.safe_load() restricts parsing to standard YAML types, making \
                                 the parsing behavior predictable."
                                    .to_string(),
                            ),
                            kind: FindingKind::BehaviorThreat,
                            severity: Severity::Critical,
                            confidence: 0.95,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(YAML_FIX.to_string()),
                            tags: vec!["security".to_string(), "yaml".to_string(), "rce".to_string()],
                        });
                    }
                }

                // Check for subprocess with shell=True
                if callee.starts_with("subprocess.") {
                    if args.contains("shell=True") || args.contains("shell = True") {
                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title: "Subprocess with shell=True".to_string(),
                            description: Some(
                                "Using subprocess with shell=True passes commands through the shell. \
                                 Using shell=False with an argument list makes command execution explicit \
                                 and avoids shell parsing."
                                    .to_string(),
                            ),
                            kind: FindingKind::BehaviorThreat,
                            severity: Severity::High,
                            confidence: 0.85,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: None,
                            fix_preview: Some(SHELL_FIX.to_string()),
                            tags: vec!["security".to_string(), "shell-injection".to_string()],
                        });
                    }
                }

                // Check for os.system()
                if callee == "os.system" || callee == "os.popen" {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Use of os.system()".to_string(),
                        description: Some(
                            "os.system() passes commands through the shell. Using subprocess with \
                             shell=False makes command execution explicit and provides better control \
                             over arguments and output."
                                .to_string(),
                        ),
                        kind: FindingKind::BehaviorThreat,
                        severity: Severity::High,
                        confidence: 0.90,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column as u32),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(OS_SYSTEM_FIX.to_string()),
                        tags: vec!["security".to_string(), "shell-injection".to_string()],
                    });
                }
            }
        }

        findings
    }
}

/// Get the parameter names of the function that encloses the given call site.
///
/// Returns a set of parameter names if the call is inside a function, empty set otherwise.
fn get_enclosing_function_params(py: &PyFileSemantics, call: &PyCallSite) -> HashSet<String> {
    // Prefer the semantic caller_function, which avoids relying on line ranges.
    let caller = call.function_call.caller_function.as_str();
    if caller.is_empty() {
        return HashSet::new();
    }

    for func in &py.functions {
        if func.name == caller {
            return func.params.iter().map(|p| p.name.clone()).collect();
        }
    }

    HashSet::new()
}

/// Check if a variable name represents user input.
///
/// A variable is considered user input if:
/// 1. It directly matches a function parameter name, OR
/// 2. It's an attribute access on a function parameter (e.g., `request.attr_name`)
///
/// Variables that are intermediate values (like results of dict.get()) are NOT
/// considered direct user input, as they are typically constrained by the
/// dictionary's keys.
fn is_user_input(params: &HashSet<String>, var_name: &str) -> bool {
    // Direct parameter match
    if params.contains(var_name) {
        return true;
    }

    // Attribute access on a parameter (e.g., request.body, user.name)
    // This catches patterns like `getattr(obj, request.attr_name)`
    if let Some(dot_pos) = var_name.find('.') {
        let base = &var_name[..dot_pos];
        if params.contains(base) {
            return true;
        }
    }

    false
}

/// Generate a patch to replace yaml.load() with yaml.safe_load().
///
/// Transforms: `yaml.load(data)` → `yaml.safe_load(data)`
fn generate_yaml_safe_load_patch(call: &PyCallSite, file_id: FileId) -> FilePatch {
    // args_repr includes parentheses like "(data)", so we strip only the outermost ones
    // Using trim_matches would be too aggressive as it removes ALL matching chars
    let args_trimmed = if call.args_repr.starts_with('(') && call.args_repr.ends_with(')') {
        &call.args_repr[1..call.args_repr.len() - 1]
    } else {
        &call.args_repr
    };

    // Replace yaml.load with yaml.safe_load, keeping the same arguments
    let replacement = format!("yaml.safe_load({})", args_trimmed);

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

const EVAL_FIX: &str = r#"Replace eval() with safer alternatives:

# Instead of eval() for math expressions:
import ast
result = ast.literal_eval(expression)  # Only evaluates literals

# For simple math:
import operator
ops = {'+': operator.add, '-': operator.sub, '*': operator.mul, '/': operator.truediv}
# Parse and evaluate safely

# For JSON-like data:
import json
data = json.loads(json_string)

# For configuration:
# Use a proper config parser or schema validation"#;

const EXEC_FIX: &str = r#"Avoid exec() entirely if possible:

# Instead of dynamic code execution, use:
# 1. Configuration files (YAML, JSON, TOML)
# 2. Plugin systems with defined interfaces
# 3. Strategy pattern for dynamic behavior

# If you must have dynamic behavior:
class PluginBase:
    def execute(self, context):
        raise NotImplementedError

# Register plugins by name, not by code
plugins = {'plugin_a': PluginA(), 'plugin_b': PluginB()}
plugins[name].execute(context)"#;

const DYNAMIC_IMPORT_FIX: &str = r#"Use importlib with a whitelist:

import importlib

ALLOWED_MODULES = {'module_a', 'module_b', 'module_c'}

def safe_import(module_name):
    if module_name not in ALLOWED_MODULES:
        raise ValueError(f"Module {module_name} not allowed")
    return importlib.import_module(module_name)"#;

const GETATTR_FIX: &str = r#"Use a whitelist for allowed attributes:

ALLOWED_ATTRS = {'name', 'value', 'status'}

def safe_getattr(obj, attr_name):
    if attr_name not in ALLOWED_ATTRS:
        raise ValueError(f"Attribute {attr_name} not allowed")
    return getattr(obj, attr_name)"#;

const SETATTR_FIX: &str = r#"Use a whitelist for allowed attributes:

ALLOWED_ATTRS = {'name', 'value', 'status'}

def safe_setattr(obj, attr_name, value):
    if attr_name not in ALLOWED_ATTRS:
        raise ValueError(f"Attribute {attr_name} not allowed")
    setattr(obj, attr_name, value)"#;

const PICKLE_FIX: &str = r#"Use safer serialization formats:

# For data interchange, use JSON:
import json
data = json.loads(json_string)

# For complex Python objects from trusted sources only:
# Add signature verification
import hmac
import hashlib

def safe_unpickle(data, signature, secret_key):
    expected_sig = hmac.new(secret_key, data, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError("Invalid signature")
    return pickle.loads(data)

# Or use safer alternatives like:
# - msgpack for binary serialization
# - protobuf for structured data
# - jsonpickle with safe mode"#;

const YAML_FIX: &str = r#"Use safe YAML loading:

import yaml

# Option 1: Use safe_load
data = yaml.safe_load(yaml_string)

# Option 2: Specify SafeLoader explicitly
data = yaml.load(yaml_string, Loader=yaml.SafeLoader)

# For files:
with open('config.yaml') as f:
    data = yaml.safe_load(f)"#;

const SHELL_FIX: &str = r#"Avoid shell=True:

import subprocess

# Instead of:
# subprocess.run(f"ls {user_input}", shell=True)

# Use a list of arguments:
subprocess.run(["ls", user_input], shell=False)

# For complex commands, use shlex:
import shlex
args = shlex.split(command)
subprocess.run(args, shell=False)

# If you need shell features, validate input strictly:
import re
if not re.match(r'^[a-zA-Z0-9_-]+$', user_input):
    raise ValueError("Invalid input")"#;

const OS_SYSTEM_FIX: &str = r#"Replace os.system() with subprocess:

import subprocess

# Instead of:
# os.system(f"ls {directory}")

# Use subprocess:
result = subprocess.run(["ls", directory], capture_output=True, text=True)
print(result.stdout)

# For checking return codes:
result = subprocess.run(["command", "arg"], check=True)"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};
    use crate::types::patch::apply_file_patch;

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
    fn test_rule_id() {
        let rule = PythonUnsafeEvalRule::new();
        assert_eq!(rule.id(), "python.unsafe_eval");
    }

    #[test]
    fn test_rule_name() {
        let rule = PythonUnsafeEvalRule::new();
        assert_eq!(rule.name(), "Unsafe Dynamic Code Execution");
    }

    // ==================== YAML Detection Tests ====================

    #[tokio::test]
    async fn detects_unsafe_yaml_load() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"
import yaml

data = yaml.load(yaml_string)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let yaml_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("YAML"))
            .collect();

        assert!(
            !yaml_findings.is_empty(),
            "Should detect unsafe yaml.load()"
        );
        assert!(yaml_findings[0].patch.is_some(), "Should have a patch");
    }

    #[tokio::test]
    async fn no_finding_for_yaml_safe_load() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"
import yaml

data = yaml.safe_load(yaml_string)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let yaml_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("YAML"))
            .collect();

        assert!(yaml_findings.is_empty(), "Should not flag yaml.safe_load()");
    }

    #[tokio::test]
    async fn no_finding_for_yaml_load_with_safeloader() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"
import yaml

data = yaml.load(yaml_string, Loader=yaml.SafeLoader)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let yaml_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("YAML"))
            .collect();

        assert!(
            yaml_findings.is_empty(),
            "Should not flag yaml.load() with SafeLoader"
        );
    }

    // ==================== YAML Patch Tests ====================

    #[tokio::test]
    async fn patch_replaces_yaml_load_with_safe_load() {
        let rule = PythonUnsafeEvalRule::new();
        let src = "import yaml\n\ndata = yaml.load(yaml_string)\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let yaml_finding = findings
            .iter()
            .find(|f| f.title.contains("YAML"))
            .expect("Should detect unsafe yaml.load()");

        let patch = yaml_finding.patch.as_ref().expect("Should have a patch");
        let patched = apply_file_patch(src, patch);

        assert!(
            patched.contains("yaml.safe_load(yaml_string)"),
            "Patched code should use yaml.safe_load()"
        );
        assert!(
            !patched.contains("yaml.load(yaml_string)"),
            "Patched code should not contain yaml.load()"
        );
    }

    #[tokio::test]
    async fn patch_uses_replace_bytes_for_yaml() {
        let rule = PythonUnsafeEvalRule::new();
        let src = "import yaml\n\ndata = yaml.load(yaml_string)\n";
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let yaml_finding = findings
            .iter()
            .find(|f| f.title.contains("YAML"))
            .expect("Should detect unsafe yaml.load()");

        let patch = yaml_finding.patch.as_ref().expect("Should have a patch");

        // Verify that one hunk is ReplaceBytes (the actual fix)
        let has_replace_bytes = patch
            .hunks
            .iter()
            .any(|h| matches!(h.range, PatchRange::ReplaceBytes { .. }));
        assert!(
            has_replace_bytes,
            "Patch should use ReplaceBytes for actual code replacement"
        );
    }

    // ==================== Other Detection Tests ====================

    #[tokio::test]
    async fn detects_eval() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"result = eval(user_input)"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let eval_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("eval"))
            .collect();

        assert!(!eval_findings.is_empty(), "Should detect eval()");
    }

    #[tokio::test]
    async fn detects_exec() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"exec(code)"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let exec_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("exec"))
            .collect();

        assert!(!exec_findings.is_empty(), "Should detect exec()");
    }

    #[tokio::test]
    async fn detects_pickle_loads() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"
import pickle

data = pickle.loads(user_data)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let pickle_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("pickle"))
            .collect();

        assert!(!pickle_findings.is_empty(), "Should detect pickle.loads()");
    }

    #[tokio::test]
    async fn detects_subprocess_shell_true() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"
import subprocess

subprocess.run(cmd, shell=True)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let shell_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("shell"))
            .collect();

        assert!(
            !shell_findings.is_empty(),
            "Should detect subprocess with shell=True"
        );
    }

    // ==================== getattr/setattr Taint Analysis Tests ====================

    #[tokio::test]
    async fn getattr_flags_direct_parameter_usage() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"
def get_attribute(obj, attr_name):
    return getattr(obj, attr_name)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let getattr_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("getattr"))
            .collect();

        assert!(
            !getattr_findings.is_empty(),
            "Should flag getattr() when attribute name is directly from function parameter"
        );
    }

    #[tokio::test]
    async fn getattr_does_not_flag_intermediate_variable() {
        let rule = PythonUnsafeEvalRule::new();
        // This simulates the lsp.py case: lang_name comes from a dict lookup, not directly from user input
        let src = r#"
LANGUAGE_MAP = {"python": "Python", "go": "Go"}

def get_language(language_id):
    lang_name = LANGUAGE_MAP.get(language_id, "Python")
    return getattr(Language, lang_name)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let getattr_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("getattr"))
            .collect();

        assert!(
            getattr_findings.is_empty(),
            "Should NOT flag getattr() when attribute name comes from intermediate variable (dict lookup)"
        );
    }

    #[tokio::test]
    async fn getattr_does_not_flag_literal_string() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"
def get_name(obj):
    return getattr(obj, 'name')
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let getattr_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("getattr"))
            .collect();

        assert!(
            getattr_findings.is_empty(),
            "Should NOT flag getattr() with literal string attribute name"
        );
    }

    #[tokio::test]
    async fn getattr_flags_parameter_attribute_access() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"
def get_dynamic_attr(obj, request):
    return getattr(obj, request.attr_name)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let getattr_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("getattr"))
            .collect();

        assert!(
            !getattr_findings.is_empty(),
            "Should flag getattr() when attribute name is accessed from a parameter (request.attr_name)"
        );
    }

    #[tokio::test]
    async fn setattr_flags_direct_parameter_usage() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"
def set_attribute(obj, attr_name, value):
    setattr(obj, attr_name, value)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let setattr_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("setattr"))
            .collect();

        assert!(
            !setattr_findings.is_empty(),
            "Should flag setattr() when attribute name is directly from function parameter"
        );
    }

    #[tokio::test]
    async fn setattr_does_not_flag_intermediate_variable() {
        let rule = PythonUnsafeEvalRule::new();
        let src = r#"
ALLOWED_ATTRS = {"name", "value"}

def safe_set(obj, attr_name, value):
    safe_name = attr_name if attr_name in ALLOWED_ATTRS else "default"
    setattr(obj, safe_name, value)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let setattr_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("setattr"))
            .collect();

        assert!(
            setattr_findings.is_empty(),
            "Should NOT flag setattr() when attribute name comes from intermediate variable"
        );
    }

    #[tokio::test]
    async fn getattr_at_module_level_not_flagged() {
        let rule = PythonUnsafeEvalRule::new();
        // Module-level getattr without enclosing function - no parameters to check
        let src = r#"
import os
some_var = "path"
result = getattr(os, some_var)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        let getattr_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.title.contains("getattr"))
            .collect();

        assert!(
            getattr_findings.is_empty(),
            "Should NOT flag getattr() at module level (no function parameters to taint-track)"
        );
    }
}
