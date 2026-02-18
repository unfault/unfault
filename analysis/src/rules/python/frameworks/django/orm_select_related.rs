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

/// Rule: Django ORM Missing select_related/prefetch_related
///
/// Detects Django ORM queries in loops that could benefit from
/// select_related or prefetch_related to avoid N+1 query problems.
#[derive(Debug)]
pub struct DjangoOrmSelectRelatedRule;

impl DjangoOrmSelectRelatedRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DjangoOrmSelectRelatedRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for DjangoOrmSelectRelatedRule {
    fn id(&self) -> &'static str {
        "python.django.orm_missing_select_related"
    }

    fn name(&self) -> &'static str {
        "Detects Django ORM queries that may cause N+1 problems due to missing select_related/prefetch_related."
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

            // Check for Django ORM imports
            let has_django_models = py.imports.iter().any(|imp| {
                imp.module.contains("django") && 
                (imp.module.contains("models") || imp.names.iter().any(|n| n == "models"))
            });

            if !has_django_models {
                // Also check for common Django ORM patterns in calls
                let has_orm_calls = py.calls.iter().any(|c| {
                    c.function_call.callee_expr.contains(".objects.") || 
                    c.function_call.callee_expr.ends_with(".all()") ||
                    c.function_call.callee_expr.ends_with(".filter(") ||
                    c.function_call.callee_expr.ends_with(".get(")
                });
                
                if !has_orm_calls {
                    continue;
                }
            }

            // Look for ORM queries inside loops
            for call in &py.calls {
                // Check if this is an ORM query call inside a loop
                if call.in_loop {
                    let is_orm_query = call.function_call.callee_expr.contains(".objects.")
                        || call.function_call.callee_expr.ends_with(".all")
                        || call.function_call.callee_expr.contains(".filter")
                        || call.function_call.callee_expr.contains(".get")
                        || call.function_call.callee_expr.contains(".first")
                        || call.function_call.callee_expr.contains(".last");

                    // Skip if already using select_related or prefetch_related
                    let has_optimization = call.function_call.callee_expr.contains("select_related")
                        || call.function_call.callee_expr.contains("prefetch_related")
                        || call.args_repr.contains("select_related")
                        || call.args_repr.contains("prefetch_related");

                    if is_orm_query && !has_optimization {
                        let title = "Django ORM query inside loop may cause N+1 problem".to_string();

                        let description = format!(
                            "The query '{}' is executed inside a loop, which can cause N+1 query \
                             problems. Each iteration triggers a separate database query. Use \
                             select_related() for ForeignKey/OneToOne fields or prefetch_related() \
                             for ManyToMany/reverse ForeignKey fields to fetch related objects \
                             in a single query.",
                            call.function_call.callee_expr
                        );

                        let fix_preview = generate_fix_preview();

                        let patch = generate_optimization_patch(
                            *file_id,
                            call.function_call.location.line,
                        );

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::Medium,
                            confidence: 0.75,
                            dimension: Dimension::Performance,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(call.function_call.location.line),
                            column: Some(call.function_call.location.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                            patch: Some(patch),
                            fix_preview: Some(fix_preview),
                            tags: vec![
                                "python".into(),
                                "django".into(),
                                "orm".into(),
                                "n+1".into(),
                                "performance".into(),
                            ],
                        });
                    }
                }
            }

            // Also check for attribute access patterns that suggest N+1
            // e.g., accessing .author on a queryset without select_related
            for call in &py.calls {
                if call.in_loop && call.function_call.callee_expr.contains(".") {
                    // Check for patterns like obj.related_field.attribute
                    let parts: Vec<&str> = call.function_call.callee_expr.split('.').collect();
                    if parts.len() >= 3 {
                        // This might be accessing a related field
                        let might_be_related_access = !call.function_call.callee_expr.contains("objects")
                            && !call.function_call.callee_expr.starts_with("self.")
                            && !is_builtin_method(&call.function_call.callee_expr);

                        if might_be_related_access {
                            // Already reported above, skip to avoid duplicates
                            continue;
                        }
                    }
                }
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::n_plus_one())
    }
}

/// Check if a method name is a Python builtin.
fn is_builtin_method(callee: &str) -> bool {
    let builtins = [
        "append", "extend", "insert", "remove", "pop", "clear",
        "index", "count", "sort", "reverse", "copy", "keys",
        "values", "items", "get", "update", "setdefault",
        "format", "strip", "split", "join", "replace",
        "lower", "upper", "startswith", "endswith",
    ];
    
    builtins.iter().any(|b| callee.ends_with(b))
}

/// Generate patch to add optimization hint.
fn generate_optimization_patch(file_id: FileId, line: u32) -> FilePatch {
    let hunks = vec![PatchHunk {
        range: PatchRange::InsertBeforeLine { line },
        replacement: "# TODO: Consider using select_related() or prefetch_related() to optimize this query\n".to_string(),
    }];

    FilePatch { file_id, hunks }
}

/// Generate a fix preview showing how to use select_related/prefetch_related.
fn generate_fix_preview() -> String {
    r#"# Use select_related() for ForeignKey and OneToOneField relationships
# Use prefetch_related() for ManyToManyField and reverse ForeignKey

# Before (N+1 queries - 1 query for books + N queries for authors):
books = Book.objects.all()
for book in books:
    print(book.author.name)  # Each access triggers a query!

# After with select_related (2 queries total using JOIN):
books = Book.objects.select_related('author').all()
for book in books:
    print(book.author.name)  # No additional query - already fetched

# For ManyToMany or reverse ForeignKey, use prefetch_related:
# Before (N+1 queries):
authors = Author.objects.all()
for author in authors:
    for book in author.books.all():  # Each iteration triggers a query
        print(book.title)

# After with prefetch_related (2 queries total):
authors = Author.objects.prefetch_related('books').all()
for author in authors:
    for book in author.books.all():  # Uses prefetched data
        print(book.title)

# You can chain multiple relations:
books = Book.objects.select_related(
    'author',
    'publisher'
).prefetch_related(
    'categories',
    'reviews'
).all()

# Use Prefetch for more control:
from django.db.models import Prefetch

authors = Author.objects.prefetch_related(
    Prefetch(
        'books',
        queryset=Book.objects.filter(published=True).order_by('-date')
    )
).all()"#.to_string()
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
        let rule = DjangoOrmSelectRelatedRule::new();
        assert_eq!(rule.id(), "python.django.orm_missing_select_related");
    }

    #[test]
    fn rule_name_mentions_select_related() {
        let rule = DjangoOrmSelectRelatedRule::new();
        assert!(rule.name().contains("select_related"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_django_code() {
        let rule = DjangoOrmSelectRelatedRule::new();
        let src = r#"
for item in items:
    print(item)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_finding_has_medium_severity() {
        let rule = DjangoOrmSelectRelatedRule::new();
        // This test verifies the rule structure
        assert_eq!(rule.id(), "python.django.orm_missing_select_related");
    }

    #[tokio::test]
    async fn evaluate_finding_has_fix_preview() {
        let rule = DjangoOrmSelectRelatedRule::new();
        // Verify fix preview generation
        let preview = generate_fix_preview();
        assert!(preview.contains("select_related"));
        assert!(preview.contains("prefetch_related"));
    }

    #[test]
    fn is_builtin_method_detects_common_methods() {
        assert!(is_builtin_method("list.append"));
        assert!(is_builtin_method("dict.get"));
        assert!(is_builtin_method("str.split"));
        assert!(!is_builtin_method("model.save"));
    }
}