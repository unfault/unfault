//! Path pattern matching for SLOs to HTTP routes.
//!
//! This module provides utilities to match SLO path patterns against
//! HTTP route paths discovered in the code graph.

use unfault_core::graph::CodeGraph;
use unfault_core::graph::GraphNodeIndex as NodeIndex;

use super::types::SloDefinition;

/// Match an SLO path pattern to route handler nodes in the graph.
///
/// Returns NodeIndexes of Function nodes where `is_handler=true` and
/// the `http_path` matches the SLO's `path_pattern`.
///
/// # Pattern Matching Rules
///
/// | SLO Pattern | Matches Route |
/// |-------------|---------------|
/// | `/api/users` | `/api/users` (exact) |
/// | `/api/users/*` | `/api/users/:id`, `/api/users/{id}` |
/// | `/api/**` | Any route starting with `/api/` |
/// | `*` | All routes |
pub fn find_matching_routes(slo: &SloDefinition, graph: &CodeGraph) -> Vec<NodeIndex> {
    let Some(ref pattern) = slo.path_pattern else {
        return vec![];
    };

    let routes = graph.get_http_route_handlers();

    routes
        .into_iter()
        .filter(|(_, route_path, route_method)| {
            // Check HTTP method match if SLO specifies one
            if let Some(ref slo_method) = slo.http_method
                && let Some(rm) = route_method
                && !slo_method.eq_ignore_ascii_case(rm)
            {
                return false;
            }
            path_matches(pattern, route_path)
        })
        .map(|(idx, _, _)| idx)
        .collect()
}

/// Normalise a raw route path for comparison.
///
/// Collapses framework-specific dynamic segment syntax into `*`:
/// - Express `:param` → `*`
/// - FastAPI / Flask `{param}` → `*`
/// - Werkzeug / Falcon `<param>` → `*`
///
/// Also lowercases and strips a trailing `/`.
///
/// Returns `"/"` for an empty path so callers always get a non-empty string.
pub fn normalize_route_path(path: &str) -> String {
    let mut result = String::with_capacity(path.len());
    let mut chars = path.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            ':' => {
                result.push('*');
                while chars.peek().is_some_and(|&c| c != '/') {
                    chars.next();
                }
            }
            '{' => {
                result.push('*');
                while chars.peek().is_some_and(|&c| c != '}') {
                    chars.next();
                }
                chars.next();
            }
            '<' => {
                result.push('*');
                while chars.peek().is_some_and(|&c| c != '>') {
                    chars.next();
                }
                chars.next();
            }
            _ => result.push(c.to_ascii_lowercase()),
        }
    }

    if result.len() > 1 && result.ends_with('/') {
        result.pop();
    }

    if result.is_empty() {
        "/".to_string()
    } else {
        result
    }
}

/// Check if a route path matches an SLO path pattern.
fn path_matches(pattern: &str, route_path: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    let pattern = normalize_pattern(pattern);
    let route = normalize_route_path(route_path);

    if pattern.ends_with("/**") {
        let prefix = &pattern[..pattern.len() - 3];
        return route.starts_with(prefix) || route == prefix.trim_end_matches('/');
    }

    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        if !route.starts_with(prefix) {
            return false;
        }
        let remainder = &route[prefix.len()..];
        if remainder.is_empty() {
            return true;
        }
        if let Some(after_slash) = remainder.strip_prefix('/') {
            return !after_slash.contains('/');
        }
        return false;
    }

    pattern == route
}

fn normalize_pattern(path: &str) -> String {
    // Patterns use simple lowercase + trailing-slash stripping; dynamic
    // segments in patterns are already written as `*` or `**` by the user.
    let mut p = path.to_lowercase();
    if p.len() > 1 && p.ends_with('/') {
        p.pop();
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_route_path_express() {
        assert_eq!(super::normalize_route_path("/users/:id"), "/users/*");
    }

    #[test]
    fn test_normalize_route_path_fastapi() {
        assert_eq!(super::normalize_route_path("/users/{user_id}"), "/users/*");
    }

    #[test]
    fn test_path_matches_exact() {
        assert!(path_matches("/api/users", "/api/users"));
        assert!(path_matches("/api/users/", "/api/users"));
        assert!(!path_matches("/api/users", "/api/posts"));
    }

    #[test]
    fn test_path_matches_wildcard() {
        assert!(path_matches("/api/users/*", "/api/users/:id"));
        assert!(!path_matches("/api/users/*", "/api/users/123/posts"));
        assert!(path_matches("/api/**", "/api/users/123/posts"));
        assert!(path_matches("*", "/any/path"));
    }
}
