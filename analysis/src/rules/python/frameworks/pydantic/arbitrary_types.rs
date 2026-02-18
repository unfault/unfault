use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};

/// Rule: Pydantic Arbitrary Types Allowed
///
/// Detects Pydantic models with arbitrary_types_allowed=True without proper
/// validation, which can lead to runtime errors and security issues.
#[derive(Debug)]
pub struct PydanticArbitraryTypesRule;

impl PydanticArbitraryTypesRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PydanticArbitraryTypesRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PydanticArbitraryTypesRule {
    fn id(&self) -> &'static str {
        "python.pydantic.arbitrary_types_allowed"
    }

    fn name(&self) -> &'static str {
        "Detects Pydantic models with arbitrary_types_allowed without proper validation."
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

            // Check for Pydantic imports
            let has_pydantic = py.imports.iter().any(|imp| {
                imp.module.contains("pydantic")
                    || imp.names.iter().any(|n| n == "BaseModel" || n == "BaseSettings")
            });

            if !has_pydantic {
                continue;
            }

            // Look for arbitrary_types_allowed in class Config or model_config
            for assign in &py.assignments {
                if assign.target == "arbitrary_types_allowed" 
                    && assign.value_repr.trim() == "True" 
                {
                    let title = "Pydantic model allows arbitrary types".to_string();

                    let description = 
                        "arbitrary_types_allowed=True allows any Python object as a field type \
                         without validation. This bypasses Pydantic's type checking and can lead \
                         to runtime errors, serialization issues, and potential security \
                         vulnerabilities. Use custom validators or proper type annotations instead.".to_string();

                    let fix_preview = generate_arbitrary_types_fix_preview();

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(assign.location.range.start_line + 1),
                        column: Some(assign.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "python".into(),
                            "pydantic".into(),
                            "validation".into(),
                            "type-safety".into(),
                        ],
                    });
                }
            }

            // Also check for model_config dict pattern (Pydantic v2)
            for call in &py.calls {
                if call.function_call.callee_expr.contains("ConfigDict") {
                    let args = &call.args_repr;
                    if args.contains("arbitrary_types_allowed") && args.contains("True") {
                        let title = "Pydantic model allows arbitrary types (v2 config)".to_string();

                        let description = 
                            "ConfigDict with arbitrary_types_allowed=True allows any Python \
                             object as a field type without validation. Consider using proper \
                             type annotations with custom validators instead.".to_string();

                        let fix_preview = generate_arbitrary_types_fix_preview();

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::StabilityRisk,
                            severity: Severity::Medium,
                            confidence: 0.85,
                            dimension: Dimension::Correctness,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: None,
                            fix_preview: Some(fix_preview),
                            tags: vec![
                                "python".into(),
                                "pydantic".into(),
                                "validation".into(),
                                "type-safety".into(),
                            ],
                        });
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
    }
}

/// Generate fix preview for arbitrary types.
fn generate_arbitrary_types_fix_preview() -> String {
    r#"# Avoid arbitrary_types_allowed when possible

from pydantic import BaseModel, field_validator, ConfigDict
from typing import Any
import numpy as np

# Bad: Using arbitrary_types_allowed
class BadModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    data: np.ndarray  # No validation!

# Good: Use custom validators for complex types
class GoodModel(BaseModel):
    data: list[float]  # Use standard types
    
    @field_validator('data', mode='before')
    @classmethod
    def convert_array(cls, v):
        if isinstance(v, np.ndarray):
            return v.tolist()
        return v

# Good: Use Annotated with custom types
from typing import Annotated
from pydantic import BeforeValidator

def validate_array(v: Any) -> list[float]:
    if isinstance(v, np.ndarray):
        return v.tolist()
    if isinstance(v, list):
        return [float(x) for x in v]
    raise ValueError("Expected array or list")

ArrayField = Annotated[list[float], BeforeValidator(validate_array)]

class BetterModel(BaseModel):
    data: ArrayField

# Good: Create a wrapper class
class NumpyArray:
    def __init__(self, data: list[float]):
        self._data = np.array(data)
    
    @classmethod
    def __get_pydantic_core_schema__(cls, source_type, handler):
        from pydantic_core import core_schema
        return core_schema.no_info_after_validator_function(
            cls._validate,
            core_schema.list_schema(core_schema.float_schema())
        )
    
    @classmethod
    def _validate(cls, v):
        return cls(v)

# If you must use arbitrary_types_allowed, add explicit validation:
class SaferModel(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    data: np.ndarray
    
    @field_validator('data', mode='before')
    @classmethod
    def validate_array(cls, v):
        if not isinstance(v, np.ndarray):
            raise ValueError("Expected numpy array")
        if v.dtype not in [np.float32, np.float64]:
            raise ValueError("Expected float array")
        return v"#.to_string()
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
        let rule = PydanticArbitraryTypesRule::new();
        assert_eq!(rule.id(), "python.pydantic.arbitrary_types_allowed");
    }

    #[test]
    fn rule_name_mentions_arbitrary_types() {
        let rule = PydanticArbitraryTypesRule::new();
        assert!(rule.name().contains("arbitrary_types"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_pydantic_code() {
        let rule = PydanticArbitraryTypesRule::new();
        let src = r#"
arbitrary_types_allowed = True
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_arbitrary_types_allowed() {
        let rule = PydanticArbitraryTypesRule::new();
        let src = r#"
from pydantic import BaseModel

class MyModel(BaseModel):
    class Config:
        arbitrary_types_allowed = True
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("arbitrary types"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_safe_model() {
        let rule = PydanticArbitraryTypesRule::new();
        let src = r#"
from pydantic import BaseModel

class MyModel(BaseModel):
    name: str
    value: int
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn fix_preview_contains_alternatives() {
        let preview = generate_arbitrary_types_fix_preview();
        assert!(preview.contains("field_validator"));
        assert!(preview.contains("Annotated"));
    }
}