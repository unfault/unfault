//! Query intent classification and routing.
//!
//! Determines the intent of a user query (flow, impact, usage, semantic, etc.)
//! using regex-based signal detection. The routing is deterministic and does not
//! require ML models.

mod signals;

pub use signals::classify_intent;

use crate::types::{RagQuery, RouteIntent};

/// Parse a raw query string into a structured RagQuery.
///
/// Detects intent, extracts targets, and identifies programming languages
/// and frameworks mentioned in the query.
pub fn parse_query(text: &str) -> RagQuery {
    let intent = classify_intent(text);
    let target = extract_target(text);
    let languages = detect_languages(text);
    let frameworks = detect_frameworks(text);

    RagQuery {
        text: text.to_string(),
        intent,
        target,
        languages,
        frameworks,
    }
}

/// Extract a target file/function/symbol from the query.
///
/// Looks for quoted strings, file paths, or identifier-like tokens.
fn extract_target(text: &str) -> Option<String> {
    // Check for quoted targets first: "foo/bar.py" or 'auth_handler'
    if let Some(start) = text.find('"') {
        if let Some(end) = text[start + 1..].find('"') {
            let target = &text[start + 1..start + 1 + end];
            if !target.is_empty() {
                return Some(target.to_string());
            }
        }
    }
    if let Some(start) = text.find('\'') {
        if let Some(end) = text[start + 1..].find('\'') {
            let target = &text[start + 1..start + 1 + end];
            if !target.is_empty() {
                return Some(target.to_string());
            }
        }
    }

    // Look for file paths (contains / or . with extension)
    for word in text.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '.' && c != '_' && c != '-');
        if clean.contains('/') && clean.len() > 2 {
            return Some(clean.to_string());
        }
        if clean.contains('.') && !clean.starts_with('.') {
            let parts: Vec<&str> = clean.rsplitn(2, '.').collect();
            if parts.len() == 2 {
                let ext = parts[0];
                if matches!(ext, "py" | "rs" | "go" | "ts" | "js" | "tsx" | "jsx") {
                    return Some(clean.to_string());
                }
            }
        }
    }

    // Look for identifier-like tokens (snake_case or CamelCase with 4+ chars)
    for word in text.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
        if clean.len() >= 4
            && (clean.contains('_')
                || (clean.chars().any(|c| c.is_uppercase())
                    && clean.chars().any(|c| c.is_lowercase())))
        {
            // Skip common words that look like identifiers
            let lower = clean.to_lowercase();
            if !matches!(
                lower.as_str(),
                "what" | "where" | "which" | "does" | "this"
                    | "that" | "these" | "those" | "from" | "have"
                    | "with" | "about" | "many" | "most" | "some"
            ) {
                return Some(clean.to_string());
            }
        }
    }

    None
}

/// Detect programming languages mentioned in the query.
fn detect_languages(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut langs = Vec::new();

    let checks = [
        ("python", "python"),
        ("rust", "rust"),
        ("go", "go"),
        ("golang", "go"),
        ("typescript", "typescript"),
        ("javascript", "javascript"),
    ];

    for (pattern, lang) in &checks {
        if lower.contains(pattern) && !langs.contains(&lang.to_string()) {
            langs.push(lang.to_string());
        }
    }

    langs
}

/// Detect frameworks mentioned in the query.
fn detect_frameworks(text: &str) -> Vec<String> {
    let lower = text.to_lowercase();
    let mut frameworks = Vec::new();

    let checks = [
        ("fastapi", "fastapi"),
        ("flask", "flask"),
        ("django", "django"),
        ("express", "express"),
        ("axum", "axum"),
        ("actix", "actix"),
        ("gin", "gin"),
        ("echo", "echo"),
        ("nextjs", "nextjs"),
        ("next.js", "nextjs"),
    ];

    for (pattern, fw) in &checks {
        if lower.contains(pattern) && !frameworks.contains(&fw.to_string()) {
            frameworks.push(fw.to_string());
        }
    }

    frameworks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query_flow() {
        let q = parse_query("how does authentication work?");
        assert_eq!(q.intent, RouteIntent::Flow);
    }

    #[test]
    fn test_parse_query_impact() {
        let q = parse_query("what breaks if I change auth.py?");
        assert_eq!(q.intent, RouteIntent::Impact);
        assert!(q.target.is_some());
    }

    #[test]
    fn test_parse_query_enumerate() {
        let q = parse_query("how many routes do we have?");
        assert_eq!(q.intent, RouteIntent::Enumerate);
    }

    #[test]
    fn test_parse_query_semantic() {
        let q = parse_query("are there any security issues?");
        assert_eq!(q.intent, RouteIntent::Semantic);
    }

    #[test]
    fn test_extract_target_quoted() {
        assert_eq!(
            extract_target(r#"what calls "auth_handler"?"#),
            Some("auth_handler".to_string())
        );
    }

    #[test]
    fn test_extract_target_file_path() {
        assert_eq!(
            extract_target("what breaks if I change src/auth.py?"),
            Some("src/auth.py".to_string())
        );
    }

    #[test]
    fn test_extract_target_identifier() {
        assert_eq!(
            extract_target("where is process_payment used?"),
            Some("process_payment".to_string())
        );
    }

    #[test]
    fn test_detect_languages() {
        let langs = detect_languages("show me python security issues");
        assert_eq!(langs, vec!["python"]);
    }

    #[test]
    fn test_detect_frameworks() {
        let fws = detect_frameworks("are there FastAPI cors issues?");
        assert_eq!(fws, vec!["fastapi"]);
    }
}
