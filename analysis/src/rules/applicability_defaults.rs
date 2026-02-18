use crate::types::finding::{
    Benefit, DecisionLevel, FindingApplicability, InvestmentLevel, LifecycleStage,
};

pub fn timeout() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Low,
        min_stage: LifecycleStage::Prototype,
        decision_level: DecisionLevel::Code,
        benefits: vec![Benefit::Reliability, Benefit::Latency],
        prerequisites: vec![],
        notes: Some("Time bounds are helpful even in demos; pick a sensible default.".to_string()),
    }
}

pub fn retry() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Medium,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::Code,
        benefits: vec![Benefit::Reliability],
        prerequisites: vec![
            "Only retry idempotent operations (or add idempotency keys)".to_string(),
            "Define which failures are retryable and apply backoff + max attempts".to_string(),
        ],
        notes: Some(
            "Retries can increase load during outages; tune carefully and measure.".to_string(),
        ),
    }
}

pub fn circuit_breaker() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::High,
        min_stage: LifecycleStage::Production,
        decision_level: DecisionLevel::Architecture,
        benefits: vec![Benefit::Reliability, Benefit::Operability],
        prerequisites: vec![
            "Choose a circuit breaker library/pattern".to_string(),
            "Define fallback behavior and error semantics".to_string(),
            "Tune thresholds based on real traffic".to_string(),
        ],
        notes: Some(
            "Typically unnecessary for small demos; most useful with real traffic and external dependencies."
                .to_string(),
        ),
    }
}

pub fn idempotency_key() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::High,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::ApiContract,
        benefits: vec![Benefit::Reliability, Benefit::Correctness],
        prerequisites: vec![
            "Define idempotency key contract (scope, TTL, conflict behavior)".to_string(),
            "Persist request outcomes keyed by idempotency key".to_string(),
        ],
        notes: Some(
            "Often overkill for demos; valuable when clients may retry or payments/side-effects exist."
                .to_string(),
        ),
    }
}

pub fn correlation_id() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Medium,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::ApiContract,
        benefits: vec![Benefit::Operability],
        prerequisites: vec![
            "Decide on header names and propagation rules across services".to_string(),
            "Ensure logs include the chosen correlation identifiers".to_string(),
        ],
        notes: Some(
            "Optional for demos; becomes valuable once multiple services or async workflows exist."
                .to_string(),
        ),
    }
}

pub fn tracing() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Medium,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::Config,
        benefits: vec![Benefit::Operability],
        prerequisites: vec![
            "Choose a tracing stack (OpenTelemetry / vendor SDK)".to_string(),
            "Propagate trace context across service boundaries".to_string(),
        ],
        notes: Some(
            "Usually unnecessary for small demos; useful once you debug production behavior."
                .to_string(),
        ),
    }
}

pub fn structured_logging() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Medium,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::Config,
        benefits: vec![Benefit::Operability],
        prerequisites: vec!["Pick a structured logger and log schema".to_string()],
        notes: Some(
            "For demos, printf-style logs can be fine; structured logs shine when you aggregate."
                .to_string(),
        ),
    }
}

pub fn graceful_shutdown() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Low,
        min_stage: LifecycleStage::Prototype,
        decision_level: DecisionLevel::Config,
        benefits: vec![Benefit::Reliability, Benefit::Operability],
        prerequisites: vec!["Handle SIGTERM and stop accepting new requests".to_string()],
        notes: Some(
            "Helpful even for demos when you run under a supervisor (docker/k8s).".to_string(),
        ),
    }
}

pub fn error_handling_in_handler() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Low,
        min_stage: LifecycleStage::Prototype,
        decision_level: DecisionLevel::Code,
        benefits: vec![Benefit::Reliability, Benefit::Correctness],
        prerequisites: vec![],
        notes: Some(
            "Worth fixing even in demos: panics/unwraps in request paths crash or 500.".to_string(),
        ),
    }
}

pub fn ignored_result() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Low,
        min_stage: LifecycleStage::Prototype,
        decision_level: DecisionLevel::Code,
        benefits: vec![Benefit::Correctness, Benefit::Reliability],
        prerequisites: vec![],
        notes: Some(
            "Ignoring errors hides failures; handle or explicitly document why it is safe."
                .to_string(),
        ),
    }
}

pub fn cors_policy() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Medium,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::ApiContract,
        benefits: vec![Benefit::Operability, Benefit::Security],
        prerequisites: vec![
            "Decide allowed origins/methods/headers (avoid allow-any in production)".to_string(),
        ],
        notes: Some(
            "For demos, permissive CORS may be acceptable; for production, be explicit."
                .to_string(),
        ),
    }
}

pub fn unbounded_resource() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Medium,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::Code,
        benefits: vec![Benefit::Reliability, Benefit::Performance],
        prerequisites: vec!["Define explicit limits / backpressure".to_string()],
        notes: Some(
            "For demos it may be fine; for production it often becomes a stability incident."
                .to_string(),
        ),
    }
}

pub fn runtime_config() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Medium,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::Config,
        benefits: vec![Benefit::Reliability, Benefit::Operability],
        prerequisites: vec![
            "Define runtime/threading settings appropriate for the workload".to_string(),
            "Add panic hooks / diagnostics as needed".to_string(),
        ],
        notes: Some(
            "Often unnecessary for demos; revisit once performance and reliability goals exist."
                .to_string(),
        ),
    }
}

pub fn sql_injection() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Low,
        min_stage: LifecycleStage::Prototype,
        decision_level: DecisionLevel::Code,
        benefits: vec![Benefit::Security],
        prerequisites: vec![],
        notes: Some("Security issues are worth fixing even in demos.".to_string()),
    }
}

pub fn hardcoded_secrets() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Low,
        min_stage: LifecycleStage::Prototype,
        decision_level: DecisionLevel::Config,
        benefits: vec![Benefit::Security],
        prerequisites: vec!["Move secrets to env vars / secret manager".to_string()],
        notes: Some("Hardcoded secrets leak via git history and logs.".to_string()),
    }
}

pub fn n_plus_one() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Medium,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::Code,
        benefits: vec![Benefit::Performance, Benefit::Reliability],
        prerequisites: vec!["Batch queries using JOINs or IN clauses".to_string()],
        notes: Some(
            "N+1 queries are common in demos; production requires query optimization.".to_string(),
        ),
    }
}

pub fn missing_rate_limiting() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Medium,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::Config,
        benefits: vec![Benefit::Security, Benefit::Reliability],
        prerequisites: vec![
            "Choose rate limiting strategy (token bucket, sliding window)".to_string(),
        ],
        notes: Some("Rate limiting becomes essential once APIs are exposed to users.".to_string()),
    }
}

pub fn regex_compile() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Low,
        min_stage: LifecycleStage::Prototype,
        decision_level: DecisionLevel::Code,
        benefits: vec![Benefit::Performance],
        prerequisites: vec![],
        notes: Some("Regex compilation is cheap but repeated compilation adds up.".to_string()),
    }
}

pub fn transaction_boundary() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Medium,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::Code,
        benefits: vec![Benefit::Reliability, Benefit::Correctness],
        prerequisites: vec!["Wrap related DB operations in a transaction".to_string()],
        notes: Some("Transactions ensure atomicity of related operations.".to_string()),
    }
}

pub fn unbounded_concurrency() -> FindingApplicability {
    FindingApplicability {
        investment_level: InvestmentLevel::Medium,
        min_stage: LifecycleStage::Product,
        decision_level: DecisionLevel::Code,
        benefits: vec![Benefit::Reliability, Benefit::Latency],
        prerequisites: vec!["Define concurrency limits/backpressure".to_string()],
        notes: Some(
            "For demos it may be fine; for production it often becomes a stability incident."
                .to_string(),
        ),
    }
}
