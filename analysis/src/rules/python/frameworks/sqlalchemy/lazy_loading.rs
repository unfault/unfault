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

/// Rule: SQLAlchemy Lazy Loading in Loop
///
/// Detects SQLAlchemy relationship access patterns that trigger lazy loading
/// inside loops, causing N+1 query problems.
#[derive(Debug)]
pub struct SqlAlchemyLazyLoadingRule;

impl SqlAlchemyLazyLoadingRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SqlAlchemyLazyLoadingRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for SqlAlchemyLazyLoadingRule {
    fn id(&self) -> &'static str {
        "python.sqlalchemy.lazy_loading_in_loop"
    }

    fn name(&self) -> &'static str {
        "Detects SQLAlchemy lazy loading patterns in loops that cause N+1 query problems."
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

            // Check for SQLAlchemy imports
            let has_sqlalchemy = py.imports.iter().any(|imp| {
                imp.module.contains("sqlalchemy")
                    || imp
                        .names
                        .iter()
                        .any(|n| n == "relationship" || n == "Session" || n == "Query")
            });

            if !has_sqlalchemy {
                continue;
            }

            // Look for attribute access patterns in loops that might trigger lazy loading
            for call in &py.calls {
                if !call.in_loop {
                    continue;
                }

                // Check for patterns like: item.related_items, user.posts, order.items
                // These are typically relationship accesses that trigger lazy loading
                let callee_parts: Vec<&str> = call.function_call.callee_expr.split('.').collect();

                if callee_parts.len() >= 2 {
                    // Check if this looks like a relationship access
                    // Common patterns: obj.relationship, obj.relationship.all(), obj.relationship.filter()
                    let might_be_relationship =
                        !call.function_call.callee_expr.starts_with("self.")
                            && !is_builtin_or_common_method(&call.function_call.callee_expr)
                            && !call.function_call.callee_expr.contains("session")
                            && !call.function_call.callee_expr.contains("query");

                    // Check if it's a query method that would trigger lazy load
                    let is_query_method = call.function_call.callee_expr.ends_with(".all")
                        || call.function_call.callee_expr.ends_with(".first")
                        || call.function_call.callee_expr.ends_with(".one")
                        || call.function_call.callee_expr.ends_with(".filter")
                        || call.function_call.callee_expr.ends_with(".count");

                    if might_be_relationship && is_query_method {
                        let title = "Potential N+1 query from lazy loading in loop".to_string();

                        let description = format!(
                            "The call '{}' inside a loop may trigger lazy loading, causing \
                             N+1 queries. Each iteration executes a separate database query. \
                             Use joinedload(), selectinload(), or subqueryload() to eagerly \
                             load relationships in the initial query.",
                            call.function_call.callee_expr
                        );

                        let fix_preview = generate_fix_preview();

                        let patch =
                            generate_lazy_loading_patch(*file_id, call.function_call.location.line);

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::Medium,
                            confidence: 0.65,
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
                                "sqlalchemy".into(),
                                "n+1".into(),
                                "lazy-loading".into(),
                                "performance".into(),
                            ],
                        });
                    }
                }
            }

            // Also check ORM queries for missing eager loading options
            for query in &py.orm_queries {
                if query.in_loop {
                    // Check if the query has eager loading
                    let has_eager_loading = query.query_text.as_ref().map_or(false, |text| {
                        text.contains("joinedload")
                            || text.contains("selectinload")
                            || text.contains("subqueryload")
                            || text.contains("contains_eager")
                            || text.contains("lazyload")
                    });

                    if !has_eager_loading {
                        let title = "ORM query in loop without eager loading".to_string();

                        let description =
                            "An ORM query is executed inside a loop without eager loading \
                             options. This can cause N+1 query problems. Consider using \
                             joinedload() or selectinload() to fetch related data efficiently."
                                .to_string();

                        let fix_preview = generate_fix_preview();

                        findings.push(RuleFinding {
                            rule_id: self.id().to_string(),
                            title,
                            description: Some(description),
                            kind: FindingKind::PerformanceSmell,
                            severity: Severity::Medium,
                            confidence: 0.70,
                            dimension: Dimension::Performance,
                            file_id: *file_id,
                            file_path: py.path.clone(),
                            line: Some(query.location.range.start_line + 1),
                            column: Some(query.location.range.start_col + 1),
                            end_line: None,
                            end_column: None,
                            byte_range: None,
                            patch: None,
                            fix_preview: Some(fix_preview),
                            tags: vec![
                                "python".into(),
                                "sqlalchemy".into(),
                                "n+1".into(),
                                "performance".into(),
                            ],
                        });
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

/// Check if a method name is a builtin or common non-relationship method.
fn is_builtin_or_common_method(callee: &str) -> bool {
    let common_methods = [
        "append",
        "extend",
        "insert",
        "remove",
        "pop",
        "clear",
        "index",
        "count",
        "sort",
        "reverse",
        "copy",
        "keys",
        "values",
        "items",
        "get",
        "update",
        "setdefault",
        "format",
        "strip",
        "split",
        "join",
        "replace",
        "lower",
        "upper",
        "startswith",
        "endswith",
        "print",
        "len",
        "str",
        "int",
        "float",
        "list",
        "dict",
        "isinstance",
        "hasattr",
        "getattr",
        "setattr",
    ];

    common_methods.iter().any(|m| callee.ends_with(m))
}

/// Generate patch for lazy loading issue.
fn generate_lazy_loading_patch(file_id: FileId, line: u32) -> FilePatch {
    let hunks = vec![PatchHunk {
        range: PatchRange::InsertBeforeLine { line },
        replacement: "# TODO: Use eager loading to avoid N+1 queries:\n# .options(joinedload(Model.relationship)) or .options(selectinload(Model.relationship))\n".to_string(),
    }];

    FilePatch { file_id, hunks }
}

/// Generate a fix preview for lazy loading issues.
fn generate_fix_preview() -> String {
    r#"# Use eager loading to avoid N+1 queries in SQLAlchemy

from sqlalchemy.orm import joinedload, selectinload, subqueryload

# Before (N+1 queries - 1 for users + N for posts):
users = session.query(User).all()
for user in users:
    print(user.posts)  # Each access triggers a query!

# After with joinedload (uses JOIN - good for one-to-one/many-to-one):
users = session.query(User).options(joinedload(User.posts)).all()
for user in users:
    print(user.posts)  # Already loaded, no additional query

# After with selectinload (uses IN clause - good for one-to-many):
users = session.query(User).options(selectinload(User.posts)).all()
for user in users:
    print(user.posts)  # Loaded with a single IN query

# After with subqueryload (uses subquery - good for large collections):
users = session.query(User).options(subqueryload(User.posts)).all()

# Chain multiple eager loads:
orders = session.query(Order).options(
    joinedload(Order.customer),
    selectinload(Order.items).joinedload(OrderItem.product)
).all()

# SQLAlchemy 2.0 style:
from sqlalchemy import select
from sqlalchemy.orm import selectinload

stmt = select(User).options(selectinload(User.posts))
users = session.scalars(stmt).all()

# Configure default loading strategy in model:
class User(Base):
    __tablename__ = 'users'
    
    # Default to lazy loading but can be overridden
    posts = relationship("Post", lazy="select")  # default
    
    # Or set eager loading as default
    profile = relationship("Profile", lazy="joined")
    
    # For large collections, use selectin
    orders = relationship("Order", lazy="selectin")"#
        .to_string()
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
        let rule = SqlAlchemyLazyLoadingRule::new();
        assert_eq!(rule.id(), "python.sqlalchemy.lazy_loading_in_loop");
    }

    #[test]
    fn rule_name_mentions_lazy_loading() {
        let rule = SqlAlchemyLazyLoadingRule::new();
        assert!(rule.name().contains("lazy loading"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_sqlalchemy_code() {
        let rule = SqlAlchemyLazyLoadingRule::new();
        let src = r#"
for item in items:
    print(item.name)
"#;
        let (file_id, sem) = parse_and_build_semantics(src);
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn is_builtin_detects_common_methods() {
        assert!(is_builtin_or_common_method("list.append"));
        assert!(is_builtin_or_common_method("dict.get"));
        assert!(is_builtin_or_common_method("str.split"));
        assert!(!is_builtin_or_common_method("user.posts"));
    }

    #[tokio::test]
    async fn fix_preview_contains_eager_loading() {
        let preview = generate_fix_preview();
        assert!(preview.contains("joinedload"));
        assert!(preview.contains("selectinload"));
    }
}
