use std::sync::Arc;

use async_trait::async_trait;

use crate::graph::CodeGraph;
use crate::parse::ast::FileId;
use crate::rules::Rule;
use crate::rules::applicability_defaults::idempotency_key;
use crate::rules::finding::RuleFinding;
use crate::semantics::SourceSemantics;
use crate::types::context::Dimension;
use crate::types::finding::{FindingApplicability, FindingKind, Severity};
use crate::types::patch::{FilePatch, PatchHunk, PatchRange};

/// Rule: Missing Idempotency Key
///
/// Detects payment/financial operations without idempotency protection.
/// Without idempotency keys, retries can cause duplicate charges.
#[derive(Debug)]
pub struct PythonMissingIdempotencyKeyRule;

impl PythonMissingIdempotencyKeyRule {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PythonMissingIdempotencyKeyRule {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Rule for PythonMissingIdempotencyKeyRule {
    fn id(&self) -> &'static str {
        "python.resilience.missing_idempotency_key"
    }

    fn name(&self) -> &'static str {
        "Detects payment/financial operations without idempotency keys to prevent duplicate charges."
    }

    fn applicability(&self) -> Option<FindingApplicability> {
        Some(idempotency_key())
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

            // Check for payment-related imports
            let has_stripe = py.imports.iter().any(|imp| imp.module.contains("stripe"));
            let has_payment_imports = py.imports.iter().any(|imp| {
                imp.module.contains("stripe")
                    || imp.module.contains("paypal")
                    || imp.module.contains("braintree")
                    || imp.module.contains("square")
                    || imp.module.contains("adyen")
            });

            if !has_payment_imports {
                continue;
            }

            // Look for payment operations in file-level calls
            for call in &py.calls {
                if !is_payment_operation(&call.function_call.callee_expr) {
                    continue;
                }

                // Check if idempotency key is present in args
                if call.args_repr.contains("idempotency_key")
                    || call.args_repr.contains("idempotency-key")
                {
                    continue;
                }

                let title = format!(
                    "Payment operation `{}` lacks idempotency key",
                    call.function_call.callee_expr
                );

                let description = format!(
                    "The payment operation `{callee}` does not use \
                     an idempotency key. Without idempotency protection, network retries \
                     or duplicate requests can result in duplicate charges. Always use \
                     idempotency keys for payment operations.",
                    callee = call.function_call.callee_expr,
                );

                let fix_preview = generate_fix_preview(has_stripe);

                // Generate actual fix using ReplaceBytes to add idempotency_key to the call
                let patch = generate_idempotency_call_patch(
                    *file_id,
                    &call.function_call.callee_expr,
                    &call.args_repr,
                    call.start_byte,
                    call.end_byte,
                    py.module_docstring_end_line.map(|l| l + 1).unwrap_or(1),
                );

                findings.push(RuleFinding {
                    rule_id: self.id().to_string(),
                    title,
                    description: Some(description),
                    kind: FindingKind::BehaviorThreat,
                    severity: Severity::Critical,
                    confidence: 0.90,
                    dimension: Dimension::Correctness,
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
                        "payment".into(),
                        "idempotency".into(),
                        "financial".into(),
                        "duplicate-prevention".into(),
                    ],
                });
            }
        }

        findings
    }
}

/// Check if a call is a payment operation.
fn is_payment_operation(callee: &str) -> bool {
    let payment_patterns = [
        // Stripe
        "PaymentIntent.create",
        "Charge.create",
        "stripe.PaymentIntent",
        "stripe.Charge",
        "stripe.Refund",
        "stripe.Transfer",
        // PayPal
        "paypal.Payment",
        "paypal.Order",
        "paypal.Capture",
        // Generic patterns
        "create_payment",
        "process_payment",
        "charge",
        "refund",
        "transfer",
        "payout",
        "create_charge",
        "process_charge",
        "create_transfer",
    ];

    payment_patterns
        .iter()
        .any(|pattern| callee.contains(pattern))
}

/// Generate idempotency patch that modifies the payment call to add idempotency_key parameter.
fn generate_idempotency_call_patch(
    file_id: FileId,
    callee: &str,
    args_repr: &str,
    start_byte: usize,
    end_byte: usize,
    import_line: u32,
) -> FilePatch {
    let mut hunks = Vec::new();

    // First, add the helper function as an import
    let import_str = "import hashlib\n\ndef generate_idempotency_key(prefix: str, *args) -> str:\n    \"\"\"Generate a deterministic idempotency key from inputs.\"\"\"\n    data = f\"{prefix}:\" + \":\".join(str(a) for a in args)\n    return hashlib.sha256(data.encode()).hexdigest()[:32]\n\n";

    hunks.push(PatchHunk {
        range: PatchRange::InsertBeforeLine { line: import_line },
        replacement: import_str.to_string(),
    });

    // Then, modify the call to add idempotency_key parameter
    // Parse the existing args and add idempotency_key
    let args_inner = args_repr.trim_start_matches('(').trim_end_matches(')');

    // Build the new call with idempotency_key added
    let new_call = if args_inner.is_empty() {
        format!(
            "{}(idempotency_key=generate_idempotency_key(\"payment\"))",
            callee
        )
    } else {
        format!(
            "{}({}, idempotency_key=generate_idempotency_key(\"payment\"))",
            callee, args_inner
        )
    };

    hunks.push(PatchHunk {
        range: PatchRange::ReplaceBytes {
            start: start_byte,
            end: end_byte,
        },
        replacement: new_call,
    });

    FilePatch { file_id, hunks }
}

/// Generate a fix preview for idempotency key usage.
fn generate_fix_preview(has_stripe: bool) -> String {
    if has_stripe {
        r#"# Stripe: Always use idempotency_key for payment operations
import stripe
import hashlib

def generate_idempotency_key(order_id: str, action: str) -> str:
    """Generate deterministic idempotency key from order context."""
    data = f"{order_id}:{action}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]

def process_payment(order_id: str, amount: int, currency: str):
    # Generate idempotency key from order context
    # Same order_id always produces same key = safe to retry
    idempotency_key = generate_idempotency_key(order_id, "payment")
    
    payment_intent = stripe.PaymentIntent.create(
        amount=amount,
        currency=currency,
        idempotency_key=idempotency_key,  # Prevents duplicate charges!
        metadata={"order_id": order_id}
    )
    return payment_intent

# For refunds
def refund_payment(payment_id: str, amount: int):
    idempotency_key = generate_idempotency_key(payment_id, f"refund:{amount}")
    
    refund = stripe.Refund.create(
        payment_intent=payment_id,
        amount=amount,
        idempotency_key=idempotency_key,
    )
    return refund

# For transfers
def create_transfer(destination: str, amount: int, transfer_group: str):
    idempotency_key = generate_idempotency_key(transfer_group, f"{destination}:{amount}")
    
    transfer = stripe.Transfer.create(
        amount=amount,
        currency="usd",
        destination=destination,
        transfer_group=transfer_group,
        idempotency_key=idempotency_key,
    )
    return transfer"#
            .to_string()
    } else {
        r#"# Generic idempotency pattern for payment operations
import hashlib
import uuid
from functools import wraps

def generate_idempotency_key(*args) -> str:
    """Generate deterministic idempotency key from inputs."""
    data = ":".join(str(a) for a in args)
    return hashlib.sha256(data.encode()).hexdigest()[:32]

def process_payment(order_id: str, amount: float):
    # Generate idempotency key from business context
    idempotency_key = generate_idempotency_key(order_id, "payment")
    
    # Check if this operation was already processed
    existing = db.query(PaymentRecord).filter_by(
        idempotency_key=idempotency_key
    ).first()
    
    if existing:
        return existing  # Return cached result, don't process again
    
    # Process payment
    result = payment_gateway.charge(
        amount=amount,
        idempotency_key=idempotency_key,
    )
    
    # Store result with idempotency key
    record = PaymentRecord(
        idempotency_key=idempotency_key,
        order_id=order_id,
        result=result,
    )
    db.add(record)
    db.commit()
    
    return result

# Decorator pattern for idempotent operations
def idempotent(key_func):
    """Decorator to make a function idempotent."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = key_func(*args, **kwargs)
            
            # Check cache/database for existing result
            cached = get_cached_result(key)
            if cached:
                return cached
            
            # Execute and cache
            result = func(*args, **kwargs)
            cache_result(key, result)
            return result
        return wrapper
    return decorator

@idempotent(key_func=lambda order_id, amount: f"payment:{order_id}")
def process_payment(order_id: str, amount: float):
    # This function is now idempotent
    return payment_gateway.charge(amount)"#
            .to_string()
    }
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
        let rule = PythonMissingIdempotencyKeyRule::new();
        assert_eq!(rule.id(), "python.resilience.missing_idempotency_key");
    }

    #[test]
    fn rule_name_mentions_idempotency() {
        let rule = PythonMissingIdempotencyKeyRule::new();
        assert!(rule.name().contains("idempotency"));
    }

    #[tokio::test]
    async fn evaluate_returns_empty_for_non_payment_code() {
        let rule = PythonMissingIdempotencyKeyRule::new();
        let (file_id, sem) = parse_and_build_semantics("x = 1\ny = 2");
        let semantics = vec![(file_id, sem)];

        let findings = rule.evaluate(&semantics, None).await;
        assert!(findings.is_empty());
    }

    #[test]
    fn is_payment_operation_detects_stripe_payment_intent() {
        assert!(is_payment_operation("stripe.PaymentIntent.create"));
    }

    #[test]
    fn is_payment_operation_detects_charge() {
        assert!(is_payment_operation("Charge.create"));
    }

    #[test]
    fn is_payment_operation_detects_generic_payment() {
        assert!(is_payment_operation("gateway.create_payment"));
    }

    #[test]
    fn is_payment_operation_ignores_non_payment() {
        assert!(!is_payment_operation("User.create"));
    }

    #[test]
    fn fix_preview_for_stripe_contains_idempotency_key() {
        let preview = generate_fix_preview(true);
        assert!(preview.contains("idempotency_key"));
        assert!(preview.contains("stripe"));
    }

    #[test]
    fn fix_preview_for_generic_contains_idempotency_pattern() {
        let preview = generate_fix_preview(false);
        assert!(preview.contains("idempotency_key"));
        assert!(preview.contains("generate_idempotency_key"));
    }
}
