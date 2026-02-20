use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule: Django Missing CSRF Protection
///
/// Detects Django views that handle POST/PUT/DELETE requests without
/// proper CSRF protection, or settings that disable CSRF middleware.
#[derive(Debug)]
pub struct DjangoMissingCsrfRule;

impl DjangoMissingCsrfRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DjangoMissingCsrfRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for DjangoMissingCsrfRule {
    fn id(&self) -> &'static str {
        "python.django.missing_csrf_protection"
    }

    fn name(&self) -> &'static str {
        "Detects Django views or settings that disable or bypass CSRF protection."
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

            // Check for @csrf_exempt decorator usage
            for call in &py.calls {
                if call.function_call.callee_expr == "csrf_exempt"
                    || call.function_call.callee_expr.ends_with(".csrf_exempt")
                {
                    let title = "CSRF protection disabled with @csrf_exempt".to_string();

                    let description =
                        "The @csrf_exempt decorator disables CSRF protection for this view. \
                         This makes the view vulnerable to cross-site request forgery attacks. \
                         Only use this for views that genuinely need to accept requests from \
                         external sources (e.g., webhooks) and implement alternative security \
                         measures."
                            .to_string();

                    let fix_preview = generate_csrf_exempt_fix_preview();

                    findings.push(RuleFinding {
                        rule_id: self.id().to_string(),
                        title,
                        description: Some(description),
                        kind: FindingKind::StabilityRisk,
                        severity: Severity::High,
                        confidence: 0.90,
                        dimension: Dimension::Stability,
                        file_id: *file_id,
                        file_path: py.path.clone(),
                        line: Some(call.function_call.location.line),
                        column: Some(call.function_call.location.column),
                        end_line: None,
                        end_column: None,
                        byte_range: None,
                        patch: None, // Can't auto-fix without understanding the use case
                        fix_preview: Some(fix_preview),
                        tags: vec![
                            "python".into(),
                            "django".into(),
                            "csrf".into(),
                            "security".into(),
                        ],
                    });
                }
            }

            // Check settings files for missing CSRF middleware
            let is_settings_file = py.path.contains("settings")
                || py.path.ends_with("settings.py")
                || py.path.contains("settings/");

            if is_settings_file {
                // Check if MIDDLEWARE is defined
                for assign in &py.assignments {
                    if assign.target == "MIDDLEWARE" || assign.target == "MIDDLEWARE_CLASSES" {
                        // Check if CsrfViewMiddleware is present
                        let has_csrf_middleware = assign.value_repr.contains("CsrfViewMiddleware")
                            || assign.value_repr.contains("csrf");

                        if !has_csrf_middleware {
                            let title = "Django CSRF middleware is missing".to_string();

                            let description =
                                "The MIDDLEWARE setting does not include CsrfViewMiddleware. \
                                 This leaves all views vulnerable to CSRF attacks. Add \
                                 'django.middleware.csrf.CsrfViewMiddleware' to MIDDLEWARE."
                                    .to_string();

                            let fix_preview = generate_middleware_fix_preview();

                            let patch = generate_middleware_patch(
                                *file_id,
                                assign.location.range.start_line + 1,
                            );

                            findings.push(RuleFinding {
                                rule_id: self.id().to_string(),
                                title,
                                description: Some(description),
                                kind: FindingKind::StabilityRisk,
                                severity: Severity::Critical,
                                confidence: 0.85,
                                dimension: Dimension::Stability,
                                file_id: *file_id,
                                file_path: py.path.clone(),
                                line: Some(assign.location.range.start_line + 1),
                                column: Some(assign.location.range.start_col + 1),
                                end_line: None,
                                end_column: None,
                                byte_range: None,
                                patch: Some(patch),
                                fix_preview: Some(fix_preview),
                                tags: vec![
                                    "python".into(),
                                    "django".into(),
                                    "csrf".into(),
                                    "middleware".into(),
                                    "security".into(),
                                ],
                            });
                        }
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::cors_policy())
    }
}

/// Generate patch to add CSRF middleware.
fn generate_middleware_patch(file_id: FileId, line: u32) -> FilePatch {
    let hunks = vec![PatchHunk {
        range: PatchRange::InsertBeforeLine { line },
        replacement:
            "# Note: Ensure 'django.middleware.csrf.CsrfViewMiddleware' is in MIDDLEWARE\n"
                .to_string(),
    }];

    FilePatch { file_id, hunks }
}

/// Generate a fix preview for csrf_exempt usage.
fn generate_csrf_exempt_fix_preview() -> String {
    r#"# If you must use @csrf_exempt, implement alternative security:

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import hmac
import hashlib

# Option 1: Use API key authentication
@csrf_exempt
def webhook_view(request):
    # Verify webhook signature
    signature = request.headers.get('X-Webhook-Signature')
    expected = hmac.new(
        settings.WEBHOOK_SECRET.encode(),
        request.body,
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected):
        return JsonResponse({'error': 'Invalid signature'}, status=403)
    
    # Process webhook...

# Option 2: Use Django REST Framework with token auth
from rest_framework.decorators import api_view, authentication_classes
from rest_framework.authentication import TokenAuthentication

@api_view(['POST'])
@authentication_classes([TokenAuthentication])
def api_view(request):
    # Token auth provides CSRF-like protection
    pass

# Option 3: For internal APIs, use session auth with CSRF
# Don't use @csrf_exempt - let Django handle CSRF normally"#
        .to_string()
}

/// Generate a fix preview for missing middleware.
fn generate_middleware_fix_preview() -> String {
    r#"# Add CsrfViewMiddleware to your MIDDLEWARE setting:

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',  # Add this line
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# In templates, use {% csrf_token %} in forms:
# <form method="post">
#     {% csrf_token %}
#     ...
# </form>

# For AJAX requests, include the CSRF token in headers:
# const csrftoken = document.querySelector('[name=csrfmiddlewaretoken]').value;
# fetch('/api/endpoint/', {
#     method: 'POST',
#     headers: {'X-CSRFToken': csrftoken},
#     body: JSON.stringify(data)
# });"#
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::python::parse_python_file;
    use crate::semantics::python::model::PyFileSemantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(source: &str, path: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: path.to_string(),
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
        let rule = DjangoMissingCsrfRule::new();
        assert_eq!(rule.id(), "python.django.missing_csrf_protection");
    }

    #[test]
    fn rule_name_mentions_csrf() {
        let rule = DjangoMissingCsrfRule::new();
        assert!(rule.name().contains("CSRF"));
    }

    #[tokio::test]
    async fn evaluate_detects_csrf_exempt_call() {
        let rule = DjangoMissingCsrfRule::new();
        // Note: The rule detects csrf_exempt as a function call, not as a decorator.
        // Decorator detection would require additional semantics support.
        let src = r#"
from django.views.decorators.csrf import csrf_exempt

# Using csrf_exempt as a function call (wrapping pattern)
my_view = csrf_exempt(my_view)
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "views.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("csrf_exempt"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_normal_view() {
        let rule = DjangoMissingCsrfRule::new();
        let src = r#"
def my_view(request):
    return HttpResponse("Hello")
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "views.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_has_high_severity() {
        let rule = DjangoMissingCsrfRule::new();
        let src = r#"
from django.views.decorators.csrf import csrf_exempt
csrf_exempt(my_view)
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "views.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(matches!(findings[0].severity, Severity::High));
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = DjangoMissingCsrfRule::new();
        let src = r#"
from django.views.decorators.csrf import csrf_exempt
csrf_exempt(my_view)
"#;
        let (file_id, sem) = parse_and_build_semantics(src, "views.py");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings[0].fix_preview.is_some());
    }
}
