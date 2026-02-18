use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};

/// Rule: Pydantic Missing Validators
///
/// Detects Pydantic models with fields that should have validators but don't,
/// such as email fields, URLs, passwords, or other sensitive data.
#[derive(Debug)]
pub struct PydanticMissingValidatorsRule;

impl PydanticMissingValidatorsRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PydanticMissingValidatorsRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PydanticMissingValidatorsRule {
    fn id(&self) -> &'static str {
        "python.pydantic.missing_validators"
    }

    fn name(&self) -> &'static str {
        "Detects Pydantic models with fields that should have validators."
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

            // Check for Pydantic built-in types that provide validation
            let has_email_str = py.imports.iter().any(|imp| {
                imp.names.iter().any(|n| n == "EmailStr")
            });
            let has_http_url = py.imports.iter().any(|imp| {
                imp.names.iter().any(|n| n == "HttpUrl" || n == "AnyUrl")
            });
            let has_secret_str = py.imports.iter().any(|imp| {
                imp.names.iter().any(|n| n == "SecretStr" || n == "SecretBytes")
            });

            // Look for field assignments that might need validators
            for assign in &py.assignments {
                let target_lower = assign.target.to_lowercase();
                let type_hint = assign.value_repr.to_lowercase();

                // Check for email fields without EmailStr
                if (target_lower.contains("email") || target_lower.ends_with("_email"))
                    && type_hint.contains("str")
                    && !type_hint.contains("emailstr")
                    && !has_email_str
                {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Email field should use EmailStr type".to_string(),
                        description: Some(
                            "Field appears to store an email address but uses plain str type. \
                             Use pydantic.EmailStr for automatic email validation, or add a \
                             custom validator.".to_string()
                        ),
                        kind: FindingKind::AntiPattern,
                        severity: Severity::Low,
                        confidence: 0.70,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(assign.location.range.start_line + 1),
                        column: Some(assign.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_email_validator_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "pydantic".into(),
                            "validation".into(),
                            "email".into(),
                        ],
                    });
                }

                // Check for URL fields without HttpUrl
                if (target_lower.contains("url") || target_lower.contains("link") || target_lower.contains("href"))
                    && type_hint.contains("str")
                    && !type_hint.contains("httpurl")
                    && !type_hint.contains("anyurl")
                    && !has_http_url
                {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "URL field should use HttpUrl type".to_string(),
                        description: Some(
                            "Field appears to store a URL but uses plain str type. \
                             Use pydantic.HttpUrl for automatic URL validation, or add a \
                             custom validator.".to_string()
                        ),
                        kind: FindingKind::AntiPattern,
                        severity: Severity::Low,
                        confidence: 0.65,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(assign.location.range.start_line + 1),
                        column: Some(assign.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_url_validator_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "pydantic".into(),
                            "validation".into(),
                            "url".into(),
                        ],
                    });
                }

                // Check for password/secret fields without SecretStr
                if (target_lower.contains("password") 
                    || target_lower.contains("secret") 
                    || target_lower.contains("token")
                    || target_lower.contains("api_key")
                    || target_lower.contains("apikey"))
                    && type_hint.contains("str")
                    && !type_hint.contains("secretstr")
                    && !has_secret_str
                {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Sensitive field should use SecretStr type".to_string(),
                        description: Some(
                            "Field appears to store sensitive data but uses plain str type. \
                             Use pydantic.SecretStr to prevent accidental logging or exposure \
                             of sensitive values.".to_string()
                        ),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::Medium,
                        confidence: 0.75,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(assign.location.range.start_line + 1),
                        column: Some(assign.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_secret_validator_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "pydantic".into(),
                            "validation".into(),
                            "security".into(),
                            "secrets".into(),
                        ],
                    });
                }

                // Check for phone number fields
                if (target_lower.contains("phone") || target_lower.contains("mobile") || target_lower.contains("tel"))
                    && type_hint.contains("str")
                {
                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title: "Phone number field should have validation".to_string(),
                        description: Some(
                            "Field appears to store a phone number but has no validation. \
                             Add a custom validator or use a library like phonenumbers for \
                             proper phone number validation.".to_string()
                        ),
                        kind: FindingKind::AntiPattern,
                        severity: Severity::Low,
                        confidence: 0.60,
                        dimension: Dimension::Correctness,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(assign.location.range.start_line + 1),
                        column: Some(assign.location.range.start_col + 1),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                        patch: None,
                        fix_preview: Some(generate_phone_validator_fix_preview()),
                        tags: vec![
                            "python".into(),
                            "pydantic".into(),
                            "validation".into(),
                            "phone".into(),
                        ],
                    });
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
    }
}

/// Generate fix preview for email validation.
fn generate_email_validator_fix_preview() -> String {
    r#"# Use Pydantic's EmailStr for email validation

from pydantic import BaseModel, EmailStr, field_validator

# Option 1: Use EmailStr (recommended)
class User(BaseModel):
    email: EmailStr  # Automatic email validation

# Option 2: Custom validator
class UserWithCustomValidator(BaseModel):
    email: str
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        import re
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(pattern, v):
            raise ValueError('Invalid email address')
        return v.lower()

# Option 3: Use email-validator library
from email_validator import validate_email, EmailNotValidError

class UserWithLibrary(BaseModel):
    email: str
    
    @field_validator('email')
    @classmethod
    def validate_email(cls, v: str) -> str:
        try:
            email_info = validate_email(v, check_deliverability=False)
            return email_info.normalized
        except EmailNotValidError as e:
            raise ValueError(str(e))"#.to_string()
}

/// Generate fix preview for URL validation.
fn generate_url_validator_fix_preview() -> String {
    r#"# Use Pydantic's URL types for URL validation

from pydantic import BaseModel, HttpUrl, AnyUrl, field_validator

# Option 1: Use HttpUrl (recommended for web URLs)
class Website(BaseModel):
    url: HttpUrl  # Validates http:// and https:// URLs

# Option 2: Use AnyUrl for any URL scheme
class Resource(BaseModel):
    url: AnyUrl  # Validates any URL scheme

# Option 3: Custom validator for specific requirements
class CustomUrl(BaseModel):
    url: str
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        from urllib.parse import urlparse
        result = urlparse(v)
        if not all([result.scheme, result.netloc]):
            raise ValueError('Invalid URL')
        if result.scheme not in ['http', 'https']:
            raise ValueError('URL must use http or https')
        return v

# Option 4: Constrained URL with pattern
from pydantic import field_validator
import re

class StrictUrl(BaseModel):
    url: str
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        if not re.match(pattern, v):
            raise ValueError('Invalid URL format')
        return v"#.to_string()
}

/// Generate fix preview for secret/password validation.
fn generate_secret_validator_fix_preview() -> String {
    r#"# Use Pydantic's SecretStr for sensitive data

from pydantic import BaseModel, SecretStr, field_validator

# Option 1: Use SecretStr (recommended)
class Credentials(BaseModel):
    password: SecretStr  # Value hidden in logs and repr
    api_key: SecretStr

# Accessing the secret value:
creds = Credentials(password="secret123", api_key="key123")
print(creds.password)  # Prints: SecretStr('**********')
print(creds.password.get_secret_value())  # Prints: secret123

# Option 2: SecretStr with validation
class SecureCredentials(BaseModel):
    password: SecretStr
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v: SecretStr) -> SecretStr:
        password = v.get_secret_value()
        if len(password) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in password):
            raise ValueError('Password must contain uppercase letter')
        if not any(c.isdigit() for c in password):
            raise ValueError('Password must contain a digit')
        return v

# Option 3: For settings/config, use SecretStr in BaseSettings
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_password: SecretStr
    api_secret: SecretStr
    
    class Config:
        env_file = '.env'

# The secret values won't be exposed in logs or error messages"#.to_string()
}

/// Generate fix preview for phone number validation.
fn generate_phone_validator_fix_preview() -> String {
    r#"# Add validation for phone number fields

from pydantic import BaseModel, field_validator
import re

# Option 1: Simple regex validation
class Contact(BaseModel):
    phone: str
    
    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v: str) -> str:
        # Remove common formatting characters
        cleaned = re.sub(r'[\s\-\(\)\.]', '', v)
        # Check if it's a valid phone number format
        if not re.match(r'^\+?[1-9]\d{6,14}$', cleaned):
            raise ValueError('Invalid phone number format')
        return cleaned

# Option 2: Use phonenumbers library (recommended)
# pip install phonenumbers
import phonenumbers

class ContactWithLibrary(BaseModel):
    phone: str
    country_code: str = 'US'
    
    @field_validator('phone')
    @classmethod
    def validate_phone(cls, v: str, info) -> str:
        try:
            country = info.data.get('country_code', 'US')
            parsed = phonenumbers.parse(v, country)
            if not phonenumbers.is_valid_number(parsed):
                raise ValueError('Invalid phone number')
            return phonenumbers.format_number(
                parsed, 
                phonenumbers.PhoneNumberFormat.E164
            )
        except phonenumbers.NumberParseException:
            raise ValueError('Could not parse phone number')

# Option 3: Create a custom type
from typing import Annotated
from pydantic import BeforeValidator

def validate_phone(v: str) -> str:
    cleaned = re.sub(r'[\s\-\(\)\.]', '', v)
    if not re.match(r'^\+?[1-9]\d{6,14}$', cleaned):
        raise ValueError('Invalid phone number')
    return cleaned

PhoneNumber = Annotated[str, BeforeValidator(validate_phone)]

class ContactWithType(BaseModel):
    phone: PhoneNumber"#.to_string()
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
        let rule = PydanticMissingValidatorsRule::new();
        assert_eq!(rule.id(), "python.pydantic.missing_validators");
    }

    #[test]
    fn rule_name_mentions_validators() {
        let rule = PydanticMissingValidatorsRule::new();
        assert!(rule.name().contains("validators"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_pydantic_code() {
        let rule = PydanticMissingValidatorsRule::new();
        let src = r#"
email = "test@example.com"
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn fix_preview_contains_emailstr() {
        let preview = generate_email_validator_fix_preview();
        assert!(preview.contains("EmailStr"));
        assert!(preview.contains("field_validator"));
    }

    #[tokio::test]
    async fn fix_preview_contains_secretstr() {
        let preview = generate_secret_validator_fix_preview();
        assert!(preview.contains("SecretStr"));
        assert!(preview.contains("get_secret_value"));
    }
}