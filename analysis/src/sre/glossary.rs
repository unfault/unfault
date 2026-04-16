use std::collections::HashMap;
use std::sync::OnceLock;

/// The gain/risk tradeoff profile for a failure mode.
///
/// In the System Design Interview framing: every engineering decision has a
/// positive side effect (the gain) and a negative side effect (the risk).
/// A mature engineer names both before recommending a fix.
#[derive(Debug, Clone)]
pub struct TradeoffProfile {
    /// What the pattern provides when it works correctly.
    /// e.g. "Local availability: retries mask transient failures from the caller"
    pub gain: &'static str,
    /// What the pattern risks at the system level.
    /// e.g. "Systemic metastability: synchronized retries prevent downstream recovery"
    pub risk: &'static str,
}

/// A full SRE glossary entry, displayed by `unfault info <id>`.
#[derive(Debug)]
pub struct GlossaryEntry {
    pub id: &'static str,
    pub aka: &'static str,
    /// One-sentence description of the hazard.
    pub hazard: &'static str,
    /// Two-sentence explanation of how it plays out in production.
    pub mechanics: &'static str,
    /// One-sentence fix recommendation.
    pub fix: &'static str,
    /// Gain/risk tradeoff profile for System Design Interview framing.
    pub tradeoff: TradeoffProfile,
}

static GLOSSARY: OnceLock<HashMap<&'static str, GlossaryEntry>> = OnceLock::new();

fn init_glossary() -> HashMap<&'static str, GlossaryEntry> {
    let mut m = HashMap::new();

    m.insert(
        "SLO-001",
        GlossaryEntry {
            id: "SLO-001",
            aka: "The Slow Death",
            hazard: "A downstream dependency slows down and your service holds threads/connections \
                     until it saturates and dies.",
            mechanics: "Without a timeout, every in-flight request waits forever for the slow \
                        dependency. Worker threads pile up, the connection pool exhausts, and the \
                        service stops accepting new requests — a cascading failure.",
            fix: "Add an explicit timeout (e.g. timeout=2.5) to every outbound remote call.",
            tradeoff: TradeoffProfile {
                gain: "Simplicity: no timeout means less code and fewer configuration decisions \
                       at call time.",
                risk: "Systemic availability: a single slow dependency can exhaust the thread \
                       pool and take down the entire service.",
            },
        },
    );

    m.insert(
        "SLO-002",
        GlossaryEntry {
            id: "SLO-002",
            aka: "The Retry Storm",
            hazard: "During an outage your service retries failures instantly, preventing the \
                     downstream service from ever recovering.",
            mechanics: "Synchronized retries with no backoff or jitter create a thunderstorm of \
                        requests the moment the downstream service tries to come back up. Each \
                        retry wave re-triggers the outage — a metastability loop.",
            fix: "Use exponential backoff with jitter (e.g. backoff.expo with jitter=True).",
            tradeoff: TradeoffProfile {
                gain: "Local availability: retries transparently mask transient failures from \
                       the caller, improving perceived reliability.",
                risk: "Systemic metastability: synchronized retries with no backoff create \
                       thunderstorms that prevent downstream services from ever recovering.",
            },
        },
    );

    m.insert(
        "SLO-003",
        GlossaryEntry {
            id: "SLO-003",
            aka: "The Zombie Process",
            hazard: "Your process is running but stuck in a deadlock or infinite loop, so health \
                     checks pass while users see 100% timeouts.",
            mechanics: "A blocking call in an async context, or a mutex acquired but never \
                        released, freezes the event loop. The process is alive but unable to \
                        process any requests — a gray failure invisible to basic monitoring.",
            fix: "Replace blocking calls with async equivalents and ensure all locks are \
                  released via RAII or try-finally.",
            tradeoff: TradeoffProfile {
                gain: "Simplicity: blocking I/O is easier to reason about than async code and \
                       avoids callback complexity.",
                risk: "Gray failure: a blocked event loop looks healthy to monitors while \
                       silently refusing all user requests.",
            },
        },
    );

    m.insert(
        "SLO-004",
        GlossaryEntry {
            id: "SLO-004",
            aka: "The Thundering Herd",
            hazard: "A hot cache key expires and all workers simultaneously slam the database to \
                     re-generate it, causing a DB outage.",
            mechanics: "With no singleflight or lock-on-miss pattern, N concurrent cache misses \
                        produce N identical database queries at exactly the same moment. The DB \
                        is overwhelmed, the cache remains empty, and the storm repeats.",
            fix: "Implement a singleflight pattern or use a distributed lock (e.g. Redis SETNX) \
                  to ensure only one worker rebuilds a hot cache key.",
            tradeoff: TradeoffProfile {
                gain: "Read throughput: caching avoids repeated expensive queries and improves \
                       P50 latency significantly.",
                risk: "Stampede on expiry: cache TTLs create synchronized miss windows that \
                       produce N×load spikes directly on the database.",
            },
        },
    );

    m.insert(
        "SLO-005",
        GlossaryEntry {
            id: "SLO-005",
            aka: "The Blackhole",
            hazard: "A hardcoded IP or an expired token means traffic is sent to a destination \
                     that no longer exists or won't accept it.",
            mechanics: "Hardcoded IPs bypass service discovery and break silently during AZ \
                        failovers or IP rotation. Expired credentials cause silent 401s that \
                        look like application errors, not auth failures.",
            fix: "Replace hardcoded IPs with DNS names backed by service discovery, and rotate \
                  credentials via a secrets manager.",
            tradeoff: TradeoffProfile {
                gain: "Startup simplicity: hardcoded endpoints remove the need for service \
                       discovery infrastructure at the cost of operational rigidity.",
                risk: "Silent breakage: hardcoded IPs or expired credentials fail silently \
                       during failovers or rotation, with no indication at the call site.",
            },
        },
    );

    m.insert(
        "SLO-006",
        GlossaryEntry {
            id: "SLO-006",
            aka: "The Cascade",
            hazard: "A dependency failure propagates unchecked through the call chain because \
                     no circuit breaker stops the flood of failing requests.",
            mechanics: "Without a circuit breaker or bulkhead, every caller of a failing \
                        service blocks until timeout, consuming threads, connections, and \
                        memory. The failure fans out upstream — a previously isolated outage \
                        takes down the entire request path in seconds.",
            fix: "Wrap outbound calls in a circuit breaker (e.g. py-breaker, resilience4j, \
                  or a custom half-open state machine) so that open circuits fast-fail \
                  immediately and give downstream services time to recover.",
            tradeoff: TradeoffProfile {
                gain: "Simplicity: calling a dependency directly without extra machinery is \
                       the fastest path to a working feature.",
                risk: "Cascading failure: a single dependency outage propagates unchecked \
                       upstream, consuming all available resources and taking down healthy \
                       services.",
            },
        },
    );

    m
}

/// Look up a glossary entry by its ID (e.g. "SLO-001"). O(1).
pub fn lookup(id: &str) -> Option<&'static GlossaryEntry> {
    GLOSSARY.get_or_init(init_glossary).get(id)
}

/// All known glossary IDs, for help text.
pub fn all_ids() -> Vec<&'static str> {
    GLOSSARY
        .get_or_init(init_glossary)
        .keys()
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_slo_001() {
        let e = lookup("SLO-001").expect("SLO-001 must exist");
        assert_eq!(e.aka, "The Slow Death");
        assert!(!e.hazard.is_empty());
        assert!(!e.mechanics.is_empty());
        assert!(!e.fix.is_empty());
    }

    #[test]
    fn lookup_all_six_entries() {
        for id in [
            "SLO-001", "SLO-002", "SLO-003", "SLO-004", "SLO-005", "SLO-006",
        ] {
            assert!(lookup(id).is_some(), "{id} missing from glossary");
        }
    }

    #[test]
    fn lookup_slo_006_cascade() {
        let e = lookup("SLO-006").expect("SLO-006 must exist");
        assert_eq!(e.aka, "The Cascade");
        assert!(!e.tradeoff.gain.is_empty());
        assert!(!e.tradeoff.risk.is_empty());
    }

    #[test]
    fn lookup_unknown_returns_none() {
        assert!(lookup("SLO-999").is_none());
    }

    #[test]
    fn all_ids_returns_six() {
        assert_eq!(all_ids().len(), 6);
    }
}
