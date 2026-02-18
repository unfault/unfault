//! Regex-based intent classification.
//!
//! Ported from the Python API's `rag_routing/routing_signals.py`.
//! Uses two-tier scoring: regex hits and phrase matches for each intent.

use regex::Regex;
use std::sync::LazyLock;

use crate::types::RouteIntent;

/// Classify a query string into a RouteIntent.
///
/// Uses deterministic regex-based scoring. No ML model needed.
pub fn classify_intent(query: &str) -> RouteIntent {
    let lower = query.to_lowercase();
    let scores = compute_scores(&lower);

    // Return the highest scoring intent (with deterministic tie-breaking)
    scores
        .into_iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(intent, _)| intent)
        .unwrap_or(RouteIntent::Semantic)
}

/// Compute scores for all intents.
fn compute_scores(query: &str) -> Vec<(RouteIntent, f32)> {
    let base_semantic = 4.0;

    vec![
        (RouteIntent::Flow, score_flow(query)),
        (RouteIntent::Overview, score_overview(query)),
        (RouteIntent::Usage, score_usage(query)),
        (RouteIntent::Impact, score_impact(query)),
        (RouteIntent::Dependencies, score_dependencies(query)),
        (RouteIntent::Centrality, score_centrality(query)),
        (RouteIntent::Enumerate, score_enumerate(query)),
        (RouteIntent::Semantic, base_semantic),
    ]
}

// --- Regex patterns (compiled once) ---

static FLOW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(flow|trace|path|chain|call.*(graph|tree|chain)|how\s+does|walk\s+through|step\s+by\s+step|sequence)\b").unwrap()
});

static FLOW_PHRASE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(how\s+does\s+\w+\s+work|trace\s+the\s+(flow|path|call)|what\s+happens\s+when|walk\s+me\s+through|step\s+by\s+step)").unwrap()
});

static OVERVIEW_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(overview|describe|summary|what\s+is\s+this|structure|architecture|explain\s+this\s+(project|repo|codebase))\b").unwrap()
});

static OVERVIEW_PHRASE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(what\s+(is|does)\s+this\s+(project|repo|workspace|codebase)|give\s+me\s+(an?\s+)?overview|describe\s+the\s+(project|workspace|codebase))").unwrap()
});

static USAGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(who\s+(uses?|calls?|imports?)|where\s+is\s+\w+\s+(used|called|imported)|callers?\s+of|references?\s+to)\b").unwrap()
});

static IMPACT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(impact|break|affect|downstream|what\s+(breaks?|changes?)|ripple|blast\s+radius)\b",
    )
    .unwrap()
});

static IMPACT_PHRASE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(what\s+(breaks|is\s+affected|changes)\s+if|impact\s+of\s+(changing|modifying|removing))").unwrap()
});

static DEPENDENCIES_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(depends?\s+on|dependencies|imports?|requires?|what\s+does\s+\w+\s+(import|depend|use|require))\b").unwrap()
});

static CENTRALITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(central|critical|important|hotspots?|hub|most\s+(used|called|imported)|pagerank|coupling)\b").unwrap()
});

static ENUMERATE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(how\s+many|count|list\s+(all|the|every)|enumerate|show\s+(all|me\s+all)|total\s+number)\b").unwrap()
});

static ENUMERATE_PHRASE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(how\s+many\s+(routes?|endpoints?|functions?|files?|classes?|modules?)|list\s+(all|every)\s+(routes?|endpoints?|functions?|files?))").unwrap()
});

// --- Scoring functions ---

fn score_flow(query: &str) -> f32 {
    let mut score = 0.0;
    if FLOW_RE.is_match(query) {
        score += 10.0;
    }
    if FLOW_PHRASE_RE.is_match(query) {
        score += 15.0;
    }
    score
}

fn score_overview(query: &str) -> f32 {
    let mut score = 0.0;
    if OVERVIEW_RE.is_match(query) {
        score += 10.0;
    }
    if OVERVIEW_PHRASE_RE.is_match(query) {
        score += 15.0;
    }
    score
}

fn score_usage(query: &str) -> f32 {
    let mut score = 0.0;
    if USAGE_RE.is_match(query) {
        score += 12.0;
    }
    score
}

fn score_impact(query: &str) -> f32 {
    let mut score = 0.0;
    if IMPACT_RE.is_match(query) {
        score += 10.0;
    }
    if IMPACT_PHRASE_RE.is_match(query) {
        score += 15.0;
    }
    score
}

fn score_dependencies(query: &str) -> f32 {
    let mut score = 0.0;
    if DEPENDENCIES_RE.is_match(query) {
        score += 10.0;
    }
    score
}

fn score_centrality(query: &str) -> f32 {
    let mut score = 0.0;
    if CENTRALITY_RE.is_match(query) {
        score += 10.0;
    }
    score
}

fn score_enumerate(query: &str) -> f32 {
    let mut score = 0.0;
    if ENUMERATE_RE.is_match(query) {
        score += 10.0;
    }
    if ENUMERATE_PHRASE_RE.is_match(query) {
        score += 15.0;
    }
    score
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Flow intent tests ---

    #[test]
    fn test_flow_how_does_work() {
        assert_eq!(
            classify_intent("how does authentication work?"),
            RouteIntent::Flow
        );
    }

    #[test]
    fn test_flow_trace() {
        assert_eq!(classify_intent("trace the login flow"), RouteIntent::Flow);
    }

    #[test]
    fn test_flow_what_happens_when() {
        assert_eq!(
            classify_intent("what happens when a user signs up?"),
            RouteIntent::Flow
        );
    }

    #[test]
    fn test_flow_walk_through() {
        assert_eq!(
            classify_intent("walk me through the payment process"),
            RouteIntent::Flow
        );
    }

    // --- Overview intent tests ---

    #[test]
    fn test_overview_describe() {
        assert_eq!(
            classify_intent("describe this project"),
            RouteIntent::Overview
        );
    }

    #[test]
    fn test_overview_what_is_this() {
        assert_eq!(
            classify_intent("what is this codebase about?"),
            RouteIntent::Overview
        );
    }

    #[test]
    fn test_overview_give_overview() {
        assert_eq!(
            classify_intent("give me an overview"),
            RouteIntent::Overview
        );
    }

    // --- Usage intent tests ---

    #[test]
    fn test_usage_who_calls() {
        assert_eq!(
            classify_intent("who calls process_payment?"),
            RouteIntent::Usage
        );
    }

    #[test]
    fn test_usage_where_is_used() {
        assert_eq!(
            classify_intent("where is auth_handler used?"),
            RouteIntent::Usage
        );
    }

    // --- Impact intent tests ---

    #[test]
    fn test_impact_what_breaks() {
        assert_eq!(
            classify_intent("what breaks if I change auth.py?"),
            RouteIntent::Impact
        );
    }

    #[test]
    fn test_impact_blast_radius() {
        assert_eq!(
            classify_intent("blast radius of modifying the database module"),
            RouteIntent::Impact
        );
    }

    // --- Dependencies intent tests ---

    #[test]
    fn test_dependencies_depends_on() {
        assert_eq!(
            classify_intent("what does auth.py depend on?"),
            RouteIntent::Dependencies
        );
    }

    #[test]
    fn test_dependencies_imports() {
        assert_eq!(
            classify_intent("what does the payment module import?"),
            RouteIntent::Dependencies
        );
    }

    // --- Centrality intent tests ---

    #[test]
    fn test_centrality_most_important() {
        assert_eq!(
            classify_intent("most important files"),
            RouteIntent::Centrality
        );
    }

    #[test]
    fn test_centrality_hotspots() {
        assert_eq!(
            classify_intent("show me the hotspots"),
            RouteIntent::Centrality
        );
    }

    // --- Enumerate intent tests ---

    #[test]
    fn test_enumerate_how_many() {
        assert_eq!(
            classify_intent("how many routes do we have?"),
            RouteIntent::Enumerate
        );
    }

    #[test]
    fn test_enumerate_list_all() {
        assert_eq!(
            classify_intent("list all endpoints"),
            RouteIntent::Enumerate
        );
    }

    // --- Semantic fallback tests ---

    #[test]
    fn test_semantic_general() {
        assert_eq!(
            classify_intent("are there any security issues?"),
            RouteIntent::Semantic
        );
    }

    #[test]
    fn test_semantic_vague() {
        assert_eq!(
            classify_intent("tell me about the code"),
            RouteIntent::Semantic
        );
    }
}
