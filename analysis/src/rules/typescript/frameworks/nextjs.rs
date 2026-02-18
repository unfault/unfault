//! Next.js API Route Missing Error Logging Rule
//!
//! Detects Next.js API routes that catch errors but fail to log them
//! before returning an error response.

use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::finding::RuleFinding;
use crate::rules::Rule;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};


/// Rule that detects missing error logging in Next.js API routes.
///
/// When an API route catches an error and returns a 500 response,
/// it should log the error so it can be debugged.
#[derive(Debug)]
pub struct NextJsApiMissingErrorLoggingRule;

impl NextJsApiMissingErrorLoggingRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NextJsApiMissingErrorLoggingRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for NextJsApiMissingErrorLoggingRule {
    fn id(&self) -> &'static str {
        "typescript.nextjs.api_missing_error_logging"
    }

    fn name(&self) -> &'static str {
        "Next.js API route catches error without logging"
    }

    async fn evaluate(
        &self,
        semantics: &[(FileId, Arc<SourceSemantics>)],
        _graph: Option<&CodeGraph>,
    ) -> Vec<RuleFinding> {
        let mut findings = Vec::new();

        for (file_id, sem) in semantics {
            let ts = match sem.as_ref() {
                SourceSemantics::Typescript(ts) => ts,
                _ => continue,
            };

            // Only check Next.js API routes (usually in app/api/ or pages/api/)
            if !ts.path.contains("/api/") {
                continue;
            }

            // Look for exported functions (GET, POST, PUT, DELETE, etc.)
            for func in &ts.functions {
                if !func.is_exported {
                    continue;
                }

                let name = func.name.to_uppercase();
                if !matches!(name.as_str(), "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS") {
                    continue;
                }

                // Check if function has try-catch
                if !func.has_try_catch {
                    continue;
                }

                // We need to check if the catch block logs the error.
                // Since we don't have full control flow graph or detailed catch block analysis in the current model,
                // we'll use a heuristic: check if there are any console.error or logger calls inside the function.
                // This is a simplification but works for the common case where the catch block is the only place handling errors.
                
                // A better approach would be to have the catch block content in the semantic model,
                // but for now we can check if "console.error" or similar is called within the function's range.
                // However, the current model stores calls as a flat list for the file, not nested in functions.
                // But we do have `inner_calls` in `TsFunction`!
                
                // Also check if there are any calls in the file that look like logging,
                // because the current semantic model might not perfectly attribute calls to functions
                // if they are nested deeply or in certain constructs.
                // For safety, if we see ANY error logging in the file, we might want to be lenient,
                // but let's stick to function scope first.
                
                // Debug: print inner calls to see what we're getting
                // println!("Function {} inner calls: {:?}", func.name, func.inner_calls);

                let has_error_logging = func.inner_calls.iter().any(|call| {
                    let call_lower = call.to_lowercase();
                    call_lower.contains("console.error") ||
                    call_lower.contains("logger.error") ||
                    call_lower.contains("log.error")
                });

                // Also check global calls if function calls are empty (fallback)
                // This is a heuristic: if we see ANY error logging in the file, we assume it might be used here.
                // This reduces false positives where the semantic model fails to attribute the call to the function.
                let has_global_logging = if !has_error_logging {
                    ts.calls.iter().any(|call| {
                        let call_lower = call.callee.to_lowercase();
                        call_lower.contains("console.error") ||
                        call_lower.contains("logger.error") ||
                        call_lower.contains("log.error")
                    })
                } else {
                    false
                };

                if has_error_logging || has_global_logging {
                    continue;
                }

                // If we're here, we have an API route with try-catch but no error logging detected.
                // We'll flag this.
                
                // For the patch, we'll try to insert logging at the start of the catch block.
                // Since we don't have the exact location of the catch block in `TsFunction`,
                // we might need to rely on `bare_catches` or `empty_catches` if it matches,
                // or just flag the function start.
                
                // Actually, let's look at `bare_catches` and `empty_catches` to see if any are inside this function.
                // But a catch block might not be empty or bare, just missing logging (e.g. it returns a response).
                
                // Since we can't easily generate a precise patch inside the catch block without more semantic info,
                // we'll attach the finding to the function definition and suggest adding logging.
                
                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title: "API route catches error without logging".to_string(),
                    description: Some(format!(
                        "The API route handler `{}` catches errors but doesn't appear to log them. \
                         When returning a generic error response to the client, the actual error should be logged \
                         on the server for debugging purposes.",
                        func.name
                    )),
                    kind: FindingKind::AntiPattern,
                    severity: Severity::Medium,
                    confidence: 0.7, // Heuristic based
                    dimension: Dimension::Observability,
                    file_id: *file_id,
                    file_path: ts.path.clone(),
                    line: Some(func.location.range.start_line + 1),
                    column: Some(func.location.range.start_col + 1),
                    end_line: Some(func.location.range.end_line + 1),
                    end_column: Some(func.location.range.end_col + 1),
                    byte_range: None,
                    patch: None, // Hard to patch without precise catch block location
                    fix_preview: Some("Add console.error(error) or logger.error(error) in the catch block".to_string()),
                    tags: vec!["nextjs".into(), "observability".into(), "logging".into()],
                });
            }
        }

        findings
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(crate::rules::applicability_defaults::error_handling_in_handler())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ast::FileId;
    use crate::parse::typescript::parse_typescript_file;
    use crate::semantics::typescript::build_typescript_semantics;
    use crate::types::context::{Language, SourceFile};

    fn parse_and_build_semantics(path: &str, source: &str) -> (FileId, Arc<SourceSemantics>) {
        let sf = SourceFile {
            path: path.to_string(),
            language: Language::Typescript,
            content: source.to_string(),
        };
        let file_id = FileId(1);
        let parsed = parse_typescript_file(file_id, &sf).expect("parsing should succeed");
        let sem = build_typescript_semantics(&parsed).unwrap();
        (file_id, Arc::new(SourceSemantics::Typescript(sem)))
    }

    #[tokio::test]
    async fn evaluate_detects_missing_logging_in_api_route() {
        let rule = NextJsApiMissingErrorLoggingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "app/api/users/route.ts",
            r#"
import { NextResponse } from 'next/server';

export async function GET() {
    try {
        const users = await fetchUsers();
        return NextResponse.json(users);
    } catch (error) {
        return NextResponse.json({ error: 'Failed' }, { status: 500 });
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert_eq!(findings.len(), 1);
    }

    #[tokio::test]
    async fn evaluate_ignores_when_logging_present() {
        let rule = NextJsApiMissingErrorLoggingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "app/api/users/route.ts",
            r#"
import { NextResponse } from 'next/server';

export async function GET() {
    try {
        const users = await fetchUsers();
        return NextResponse.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        return NextResponse.json({ error: 'Failed' }, { status: 500 });
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_ignores_non_api_routes() {
        let rule = NextJsApiMissingErrorLoggingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "lib/utils.ts",
            r#"
export async function GET() {
    try {
        // ...
    } catch (error) {
        // No logging
    }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[tokio::test]
    async fn evaluate_detects_real_nextjs_api_route_pattern() {
        // This test matches the exact pattern from leaderboard/book-app-nextjs-gemini3-pro/app/api/tasks/[id]/route.ts
        let rule = NextJsApiMissingErrorLoggingRule::new();
        let (file_id, sem) = parse_and_build_semantics(
            "app/api/tasks/[id]/route.ts",
            r#"
import { NextResponse } from 'next/server';
import prisma from '@/lib/prisma';

export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const id = parseInt(params.id);
    const task = await prisma.task.findUnique({
      where: { id },
    });

    if (!task) {
      return NextResponse.json({ error: 'Task not found' }, { status: 404 });
    }

    return NextResponse.json(task);
  } catch (error) {
    return NextResponse.json({ error: 'Failed to fetch task' }, { status: 500 });
  }
}

export async function PUT(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const id = parseInt(params.id);
    const body = await request.json();
    const { title, completed } = body;

    const task = await prisma.task.update({
      where: { id },
      data: {
        title,
        completed,
      },
    });

    return NextResponse.json(task);
  } catch (error) {
    return NextResponse.json({ error: 'Failed to update task' }, { status: 500 });
  }
}

export async function DELETE(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const id = parseInt(params.id);
    await prisma.task.delete({
      where: { id },
    });

    return new NextResponse(null, { status: 204 });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to delete task' }, { status: 500 });
  }
}
"#,
        );
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        // Should detect all 3 functions (GET, PUT, DELETE) missing error logging
        assert_eq!(findings.len(), 3, "Expected 3 findings for GET, PUT, DELETE without logging");
        
        // Verify all three methods are detected
        let detected_methods: Vec<&str> = findings.iter()
            .filter_map(|f| f.description.as_ref())
            .filter_map(|d| {
                if d.contains("`GET`") { Some("GET") }
                else if d.contains("`PUT`") { Some("PUT") }
                else if d.contains("`DELETE`") { Some("DELETE") }
                else { None }
            })
            .collect();
        assert!(detected_methods.contains(&"GET"), "Should detect GET");
        assert!(detected_methods.contains(&"PUT"), "Should detect PUT");
        assert!(detected_methods.contains(&"DELETE"), "Should detect DELETE");
    }

    #[tokio::test]
    async fn debug_semantic_model_for_nextjs_route() {
        // Debug test to inspect what the semantic model produces
        let (file_id, sem) = parse_and_build_semantics(
            "app/api/tasks/[id]/route.ts",
            r#"
export async function GET(
  request: Request,
  { params }: { params: { id: string } }
) {
  try {
    const x = 1;
  } catch (error) {
    return { error: 'Failed' };
  }
}
"#,
        );
        
        if let SourceSemantics::Typescript(ts) = sem.as_ref() {
            println!("Path: {}", ts.path);
            println!("Functions count: {}", ts.functions.len());
            for func in &ts.functions {
                println!("  Function: {}", func.name);
                println!("    is_exported: {}", func.is_exported);
                println!("    is_async: {}", func.is_async);
                println!("    has_try_catch: {}", func.has_try_catch);
                println!("    inner_calls: {:?}", func.inner_calls);
            }
            println!("Calls count: {}", ts.calls.len());
            for call in &ts.calls {
                println!("  Call: {}", call.callee);
            }
        }
        
        // This test always passes, it's just for debugging output
        assert!(true);
    }
}