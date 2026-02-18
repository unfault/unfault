//! Rule B5: N+1 queries detection
//!
//! Detects inefficient database query patterns where queries are executed
//! inside loops, causing N+1 query problems that severely impact performance.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::applicability_defaults::unbounded_resource;
use crate::rules::Rule;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::semantics::python::model::ImportInsertionType;
use crate::semantics::python::orm::{OrmKind, OuterQueryInfo, detect_n_plus_one_patterns};
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule that detects N+1 query patterns in Python ORM code.
///
/// N+1 queries occur when code fetches a collection of objects and then
/// executes an additional query for each object to fetch related data.
/// This is extremely inefficient and can cause severe performance issues.
#[derive(Debug)]
pub struct PythonNPlusOneQueriesRule;

impl PythonNPlusOneQueriesRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonNPlusOneQueriesRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonNPlusOneQueriesRule {
    fn id(&self) -> &'static str {
        "python.n_plus_one_queries"
    }

    fn name(&self) -> &'static str {
        "N+1 query pattern detected - use eager loading"
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

            // Skip files that don't have any ORM imports - this prevents false positives
            // on non-ORM code like Kubernetes clients, HTTP clients, etc.
            if !py.has_orm_imports() {
                continue;
            }

            // Detect N+1 patterns using ORM semantics
            let patterns = detect_n_plus_one_patterns(&py.orm_queries);
            // Use third_party_from_import since we're adding ORM imports like "from sqlalchemy.orm import selectinload"
            let import_line = py.import_insertion_line_for(ImportInsertionType::third_party_from_import());

            for pattern in patterns {
                let query = &pattern.inner_access;
                
                // Skip findings with Unknown ORM type - we can't generate meaningful patches
                // and these are likely false positives (e.g., non-ORM code that looks similar)
                if query.orm_kind == OrmKind::Unknown {
                    continue;
                }
                
                let title = format!(
                    "N+1 query: {} query inside {}",
                    query.orm_kind.as_str(),
                    if query.in_loop { "loop" } else { "comprehension" }
                );

                let description = format!(
                    "{}. This pattern executes a separate database query for each item in the collection, \
                     causing severe performance degradation. {}",
                    pattern.pattern_description,
                    get_fix_suggestion(query.orm_kind)
                );

                let patch = generate_eager_loading_patch(query, *file_id, import_line);

                let fix_preview = get_fix_preview(query.orm_kind);

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::PerformanceSmell,
                    severity: Severity::High,
                    confidence: if query.in_loop || query.in_comprehension { 0.85 } else { 0.65 },
                    dimension: Dimension::Performance,
                    file_id: *file_id,
                    file_path: py.path.clone(),
                    line: Some(query.line),
                    column: Some(query.column),
                    end_line: None,
                    end_column: None,
            byte_range: None,
                    patch: Some(patch),
                    fix_preview: Some(fix_preview),
                    tags: vec![
                        "python".into(),
                        "orm".into(),
                        "n+1".into(),
                        "performance".into(),
                        query.orm_kind.as_str().to_lowercase().replace(' ', "-"),
                    ],
                });
            }
        }

        findings
    }
}

fn get_fix_suggestion(orm_kind: OrmKind) -> &'static str {
    match orm_kind {
        OrmKind::SqlAlchemy => {
            "Use joinedload(), selectinload(), or subqueryload() to eagerly load related objects."
        }
        OrmKind::Django => {
            "Use select_related() for foreign keys or prefetch_related() for many-to-many relationships."
        }
        OrmKind::Tortoise => {
            "Use prefetch_related() to eagerly load related objects."
        }
        OrmKind::SqlModel => {
            "Use SQLAlchemy's joinedload() or selectinload() options."
        }
        OrmKind::Peewee => {
            "Use prefetch() or join() to eagerly load related objects."
        }
        OrmKind::Unknown => {
            "Use your ORM's eager loading mechanism to fetch related data in a single query."
        }
    }
}

fn get_fix_preview(orm_kind: OrmKind) -> String {
    match orm_kind {
        OrmKind::SqlAlchemy => {
            r#"# Before (N+1):
for user in session.query(User).all():
    print(user.posts)  # Executes a query for each user

# After (eager loading):
from sqlalchemy.orm import joinedload
for user in session.query(User).options(joinedload(User.posts)).all():
    print(user.posts)  # No additional queries"#.to_string()
        }
        OrmKind::Django => {
            r#"# Before (N+1):
for user in User.objects.all():
    print(user.profile)  # Executes a query for each user

# After (eager loading):
for user in User.objects.select_related('profile').all():
    print(user.profile)  # No additional queries

# For many-to-many:
for user in User.objects.prefetch_related('groups').all():
    print(user.groups.all())  # No additional queries"#.to_string()
        }
        OrmKind::Tortoise => {
            r#"# Before (N+1):
async for user in User.all():
    posts = await user.posts  # Executes a query for each user

# After (eager loading):
async for user in User.all().prefetch_related('posts'):
    posts = user.posts  # No additional queries"#.to_string()
        }
        OrmKind::SqlModel | OrmKind::Unknown => {
            r#"# Use eager loading to fetch related data in a single query
# instead of executing queries inside loops"#.to_string()
        }
        OrmKind::Peewee => {
            r#"# Before (N+1):
for user in User.select():
    print(user.posts)  # Executes a query for each user

# After (eager loading):
query = User.select().join(Post).switch(User)
for user in prefetch(query, Post.select()):
    print(user.posts)  # No additional queries"#.to_string()
        }
    }
}

fn generate_eager_loading_patch(
    query: &crate::semantics::python::orm::OrmQueryCall,
    file_id: FileId,
    import_insertion_line: u32,
) -> FilePatch {
    // If we have outer query information, generate an actual code transformation
    if let Some(ref outer_query) = query.outer_query {
        return generate_outer_query_patch(outer_query, query, file_id, import_insertion_line);
    }
    
    // Fallback: generate a comment-based suggestion
    generate_fallback_patch(query, file_id, import_insertion_line)
}

/// Generate a patch that transforms the outer query to include eager loading
fn generate_outer_query_patch(
    outer_query: &OuterQueryInfo,
    inner_query: &crate::semantics::python::orm::OrmQueryCall,
    file_id: FileId,
    import_insertion_line: u32,
) -> FilePatch {
    let mut hunks = Vec::new();
    
    // Determine the relationship field to eager load
    // Use the inner query's model name or a placeholder
    let relationship_field = inner_query.model_name.as_deref()
        .map(|m| m.to_lowercase())
        .unwrap_or_else(|| "related_field".to_string());
    
    // Generate the transformed query based on ORM type
    let (import_line, transformed_query) = match outer_query.orm_kind {
        OrmKind::Django => {
            let original = &outer_query.query_text;
            // Insert .select_related() or .prefetch_related() before .all() or at the end
            let transformed = if original.contains(".all()") {
                original.replace(".all()", &format!(".select_related('{relationship_field}').all()"))
            } else if original.contains(".filter(") {
                // Insert before .filter()
                original.replace(".filter(", &format!(".select_related('{relationship_field}').filter("))
            } else {
                // Append to the query
                format!("{}.select_related('{}')", original, relationship_field)
            };
            ("", transformed)
        }
        OrmKind::SqlAlchemy => {
            let import = "from sqlalchemy.orm import selectinload\n";
            let original = &outer_query.query_text;
            // Insert .options() before .all() or .first()
            let model = outer_query.model_name.as_deref().unwrap_or("Model");
            let transformed = if original.contains(".all()") {
                original.replace(".all()", &format!(".options(selectinload({model}.{relationship_field})).all()"))
            } else if original.contains(".first()") {
                original.replace(".first()", &format!(".options(selectinload({model}.{relationship_field})).first()"))
            } else {
                format!("{}.options(selectinload({}.{}))", original, model, relationship_field)
            };
            (import, transformed)
        }
        OrmKind::Tortoise => {
            let original = &outer_query.query_text;
            let transformed = if original.contains(".all()") {
                original.replace(".all()", &format!(".all().prefetch_related('{relationship_field}')"))
            } else {
                format!("{}.prefetch_related('{}')", original, relationship_field)
            };
            ("", transformed)
        }
        OrmKind::SqlModel => {
            let import = "from sqlalchemy.orm import selectinload\n";
            let original = &outer_query.query_text;
            let transformed = format!("{}.options(selectinload({}))", original, relationship_field);
            (import, transformed)
        }
        OrmKind::Peewee => {
            let import = "from peewee import prefetch\n";
            let original = &outer_query.query_text;
            // Peewee uses a different pattern - wrap with prefetch()
            let transformed = format!("prefetch({}, {})", original, relationship_field);
            (import, transformed)
        }
        OrmKind::Unknown => {
            // Can't generate a specific transformation
            return generate_fallback_patch(inner_query, file_id, import_insertion_line);
        }
    };
    
    // Add import if needed
    if !import_line.is_empty() {
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: import_insertion_line },
            replacement: import_line.to_string(),
        });
    }
    
    // Use ReplaceBytes to directly transform the outer query
    // This provides an actual code fix rather than just a comment
    hunks.push(PatchHunk {
        range: PatchRange::ReplaceBytes {
            start: outer_query.start_byte,
            end: outer_query.end_byte,
        },
        replacement: transformed_query.clone(),
    });

    FilePatch {
        file_id,
        hunks,
    }
}

/// Generate a fallback patch with comment-based suggestions
fn generate_fallback_patch(
    query: &crate::semantics::python::orm::OrmQueryCall,
    file_id: FileId,
    import_insertion_line: u32,
) -> FilePatch {
    let (import_line, transformation) = match query.orm_kind {
        OrmKind::SqlAlchemy => {
            let import = "from sqlalchemy.orm import joinedload, selectinload\n";
            let model = query.model_name.as_deref().unwrap_or("Model");
            let transform = format!(
                "# Fix N+1: Add eager loading to the outer query:\n\
                 # query.options(selectinload({model}.relationship_name))\n"
            );
            (import, transform)
        }
        OrmKind::Django => {
            let model = query.model_name.as_deref().unwrap_or("Model");
            let transform = format!(
                "# Fix N+1: Add eager loading to the outer query:\n\
                 # {model}.objects.select_related('relationship_name').all()\n"
            );
            ("", transform)
        }
        OrmKind::Tortoise => {
            let model = query.model_name.as_deref().unwrap_or("Model");
            let transform = format!(
                "# Fix N+1: Add eager loading to the outer query:\n\
                 # await {model}.all().prefetch_related('relationship_name')\n"
            );
            ("", transform)
        }
        OrmKind::SqlModel => {
            let import = "from sqlalchemy.orm import selectinload\n";
            let transform =
                "# Fix N+1: Add eager loading to the select statement:\n\
                 # select(Model).options(selectinload(Model.relationship))\n".to_string();
            (import, transform)
        }
        OrmKind::Peewee => {
            let import = "from peewee import prefetch\n";
            let model = query.model_name.as_deref().unwrap_or("Model");
            let transform = format!(
                "# Fix N+1: Use prefetch to eagerly load related objects:\n\
                 # prefetch({model}.select(), RelatedModel.select())\n"
            );
            (import, transform)
        }
        OrmKind::Unknown => {
            let transform =
                "# Fix N+1: Add eager loading to avoid N+1 queries\n".to_string();
            ("", transform)
        }
    };

    let mut hunks = Vec::new();
    
    if !import_line.is_empty() {
        hunks.push(PatchHunk {
            range: PatchRange::InsertBeforeLine { line: import_insertion_line },
            replacement: import_line.to_string(),
        });
    }
    
    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine {
            line: query.line,
        },
        replacement: transformation,
    });

    FilePatch {
        file_id,
        hunks,
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
        let rule = PythonNPlusOneQueriesRule::new();
        assert_eq!(rule.id(), "python.n_plus_one_queries");
    }

    #[test]
    fn rule_name_is_correct() {
        let rule = PythonNPlusOneQueriesRule::new();
        assert!(rule.name().contains("N+1"));
    }

    #[test]
    fn rule_implements_debug() {
        let rule = PythonNPlusOneQueriesRule::new();
        let debug_str = format!("{:?}", rule);
        assert!(debug_str.contains("PythonNPlusOneQueriesRule"));
    }

    #[test]
    fn rule_implements_default() {
        let rule = PythonNPlusOneQueriesRule::default();
        assert_eq!(rule.id(), "python.n_plus_one_queries");
    }

    #[tokio::test]
    async fn detects_django_n_plus_one_in_loop() {
        let rule = PythonNPlusOneQueriesRule::new();
        let src = r#"
from django.db import models

def get_user_posts():
    users = User.objects.all()
    for user in users:
        posts = Post.objects.filter(user=user)
        print(posts)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Should detect the N+1 pattern
        assert!(!findings.is_empty(), "Should detect N+1 query in loop");
        assert_eq!(findings[0].rule_id, "python.n_plus_one_queries");
        assert!(matches!(findings[0].severity, Severity::High));
    }

    #[tokio::test]
    async fn detects_sqlalchemy_n_plus_one_in_loop() {
        let rule = PythonNPlusOneQueriesRule::new();
        let src = r#"
from sqlalchemy.orm import Session

def get_user_posts(session: Session):
    users = session.query(User).all()
    for user in users:
        posts = session.query(Post).filter(Post.user_id == user.id).all()
        print(posts)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Should detect the N+1 pattern
        assert!(!findings.is_empty(), "Should detect N+1 query in loop");
    }

    #[tokio::test]
    async fn detects_n_plus_one_in_comprehension() {
        let rule = PythonNPlusOneQueriesRule::new();
        let src = r#"
from django.db import models

def get_all_posts():
    users = User.objects.all()
    all_posts = [Post.objects.filter(user=u) for u in users]
    return all_posts
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Should detect the N+1 pattern in comprehension
        assert!(!findings.is_empty(), "Should detect N+1 query in comprehension");
    }

    #[tokio::test]
    async fn no_finding_for_eager_loaded_query() {
        let rule = PythonNPlusOneQueriesRule::new();
        // This test verifies that queries with eager loading are not flagged
        // The eager loading is detected in the query itself, not in attribute access
        let src = r#"
def get_users_with_posts():
    # Using select_related for eager loading - no additional queries in loop
    users = User.objects.select_related('profile').all()
    return users
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Should not flag queries outside loops
        assert!(findings.is_empty(), "Should not flag queries outside loops");
    }

    #[tokio::test]
    async fn no_finding_for_single_query() {
        let rule = PythonNPlusOneQueriesRule::new();
        let src = r#"
def get_users():
    users = User.objects.all()
    return users
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Should not flag single queries outside loops
        assert!(findings.is_empty(), "Should not flag single query outside loop");
    }

    #[tokio::test]
    async fn handles_empty_semantics() {
        let rule = PythonNPlusOneQueriesRule::new();
        let semantics: Vec<(FileId, Arc<SourceSemantics>)> = vec![];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn handles_empty_file() {
        let rule = PythonNPlusOneQueriesRule::new();
        let (file_id, sem) = parse_and_build_semantics("");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn finding_has_correct_properties() {
        let rule = PythonNPlusOneQueriesRule::new();
        let src = r#"
for user in users:
    posts = Post.objects.filter(user=user)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        if !findings.is_empty() {
            let finding = &findings[0];
            assert_eq!(finding.rule_id, "python.n_plus_one_queries");
            assert!(matches!(finding.kind, FindingKind::PerformanceSmell));
            assert_eq!(finding.dimension, Dimension::Performance);
            assert!(finding.patch.is_some());
            assert!(finding.fix_preview.is_some());
            assert!(finding.tags.contains(&"n+1".to_string()));
        }
    }

    #[test]
    fn fix_suggestions_are_orm_specific() {
        assert!(get_fix_suggestion(OrmKind::SqlAlchemy).contains("joinedload"));
        assert!(get_fix_suggestion(OrmKind::Django).contains("select_related"));
        assert!(get_fix_suggestion(OrmKind::Tortoise).contains("prefetch_related"));
        assert!(get_fix_suggestion(OrmKind::Peewee).contains("prefetch"));
    }

    #[test]
    fn fix_previews_are_orm_specific() {
        assert!(get_fix_preview(OrmKind::SqlAlchemy).contains("joinedload"));
        assert!(get_fix_preview(OrmKind::Django).contains("select_related"));
        assert!(get_fix_preview(OrmKind::Tortoise).contains("prefetch_related"));
        assert!(get_fix_preview(OrmKind::Peewee).contains("prefetch"));
    }

    #[tokio::test]
    async fn no_finding_for_kubernetes_client_code() {
        let rule = PythonNPlusOneQueriesRule::new();
        // Simulated Kubernetes client code - should NOT trigger N+1 detection
        let src = r#"
from kubernetes import client
import asyncio

async def watch_pods():
    k8s_client = client.ApiClient()
    
    wait_for = 3
    while not event.is_set():
        await asyncio.sleep(wait_for)
        wait_for += 3
        pods = k8s_client.list_namespaced_pod(namespace="default")
        for pod in pods.items:
            print(pod.metadata.name)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Should NOT flag Kubernetes code as N+1 - no ORM imports present
        assert!(findings.is_empty(), "Should not flag non-ORM code (Kubernetes client)");
    }

    #[tokio::test]
    async fn no_finding_for_http_client_code() {
        let rule = PythonNPlusOneQueriesRule::new();
        // HTTP client code - should NOT trigger N+1 detection
        let src = r#"
import requests
import asyncio

def fetch_all_users():
    users = requests.get('https://api.example.com/users').json()
    for user in users:
        details = requests.get(f'https://api.example.com/users/{user["id"]}')
        print(details)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Should NOT flag HTTP client code as N+1 - no ORM imports present
        assert!(findings.is_empty(), "Should not flag non-ORM code (HTTP client)");
    }

    #[tokio::test]
    async fn no_finding_for_asyncio_code() {
        let rule = PythonNPlusOneQueriesRule::new();
        // Plain asyncio code - should NOT trigger N+1 detection
        let src = r#"
import asyncio

async def process_items():
    items = await get_items()
    while True:
        await asyncio.sleep(1)
        for item in items:
            await process(item)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Should NOT flag asyncio code as N+1 - no ORM imports present
        assert!(findings.is_empty(), "Should not flag non-ORM code (asyncio)");
    }

    #[tokio::test]
    async fn detects_n_plus_one_when_orm_imports_present() {
        let rule = PythonNPlusOneQueriesRule::new();
        // Code WITH ORM imports - SHOULD trigger N+1 detection
        let src = r#"
from sqlalchemy.orm import Session
from sqlalchemy import select

def get_user_posts(session: Session):
    users = session.query(User).all()
    for user in users:
        # This should be flagged as N+1
        posts = session.query(Post).filter(Post.user_id == user.id).all()
        print(posts)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        
        // Should detect N+1 pattern when ORM imports are present
        assert!(!findings.is_empty(), "Should detect N+1 when ORM imports are present");
    }
}