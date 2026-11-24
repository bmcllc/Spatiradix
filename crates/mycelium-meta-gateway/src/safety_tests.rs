use super::*;
use ed25519_dalek::SigningKey;
use mycelium_core::NodeId;
use serde_json::json;

fn intent(metadata: serde_json::Value) -> PaymentIntent {
    PaymentIntent::auto_route(
        MICRO_UNIT,
        "MYC",
        "did:mycelium:sender",
        "myc:receiver",
        metadata,
    )
    .unwrap()
}

#[test]
fn unkeyed_payment_intents_have_distinct_ids() {
    let first = intent(json!({}));
    let second = intent(json!({}));
    assert_ne!(first.id, second.id);
}

#[test]
fn explicit_idempotency_key_stabilizes_payment_identity() {
    let first = intent(json!({"idempotency_key": "checkout-1"}));
    let second = intent(json!({"idempotency_key": "checkout-1"}));
    let other = intent(json!({"idempotency_key": "checkout-2"}));
    assert_eq!(first.id, second.id);
    assert_ne!(first.id, other.id);
}

#[test]
fn metadata_changes_invalidate_signed_canonical_payload() {
    let first = intent(json!({"idempotency_key": "checkout-1", "local_hour": 14}));
    let mut changed = first.clone();
    changed.compliance_metadata = json!({"idempotency_key": "checkout-1", "local_hour": 23});
    assert_ne!(first.canonical_bytes(), changed.canonical_bytes());
}

#[test]
fn no_implicit_brl_usd_udc_conversion_to_usdc() {
    let policy = mycelium_mint::MonetaryPolicy::mainnet();
    for currency in ["BRL", "USD", "UDC"] {
        let candidate = PaymentIntent::auto_route(
            MICRO_UNIT,
            currency,
            "did:mycelium:sender",
            "myc:receiver",
            json!({}),
        )
        .unwrap();
        assert_eq!(candidate.myc_usdc_parity(&policy), (0, 0));
    }
}

#[test]
fn myc_rail_is_fail_closed_without_real_ledger() {
    let home = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[0x52; 32]);
    let author = NodeId::derive(key.verifying_key().as_bytes());
    let store = SporebankIntentStore::open_encrypted(home.path(), author, [0x64; 32]).unwrap();
    let mut engine = MetaGatewayEngine::new(key, b"safety-genesis").with_sporebank(store);
    let payment = intent(json!({"idempotency_key": "offline-only"}));
    let id = payment.id.clone();
    assert!(matches!(
        engine.execute(payment),
        Err(GatewayError::AdapterUnavailable("myc-ledger-settlement"))
    ));
    assert!(engine.recall_by_id(&id).unwrap().is_none());
}

#[test]
fn gateway_will_not_dispatch_with_plaintext_legacy_store() {
    let home = tempfile::tempdir().unwrap();
    let signer = SigningKey::from_bytes(&[0x42; 32]);
    let author = NodeId::derive(signer.verifying_key().as_bytes());
    let legacy = SporebankIntentStore::open(home.path(), author).unwrap();
    let mut gateway = MetaGatewayEngine::new(signer, b"privacy-test").with_sporebank(legacy);
    let mut payment = PaymentIntent::auto_route(
        MICRO_UNIT,
        "MYC",
        "did:mycelium:sender",
        "myc:receiver",
        json!({}),
    )
    .unwrap();
    assert!(matches!(
        gateway.execute(payment.clone()),
        Err(GatewayError::AdapterUnavailable(
            "sovereign-encrypted-store"
        ))
    ));
    assert!(matches!(
        gateway.confirm_settlement(&mut payment, "fake-tx"),
        Err(GatewayError::AdapterUnavailable(
            "sovereign-encrypted-store"
        ))
    ));
    assert!(matches!(payment.state, TransactionState::Initiated));
    assert!(gateway
        .fail_intent(&mut payment, 500, "network error")
        .is_err());
    assert!(matches!(payment.state, TransactionState::Initiated));
}

#[test]
fn explicit_external_disclosure_is_required_before_preparing_payload() {
    let home = tempfile::tempdir().unwrap();
    let signer = SigningKey::from_bytes(&[0x45; 32]);
    let author = NodeId::derive(signer.verifying_key().as_bytes());
    let store = SporebankIntentStore::open_encrypted(home.path(), author, [0x88; 32]).unwrap();
    let mut gateway = MetaGatewayEngine::new(signer, b"privacy-test").with_sporebank(store);
    let denied = PaymentIntent::auto_route(
        MICRO_UNIT,
        "BRL",
        "did:mycelium:sender",
        "pix:key@example.com",
        json!({"local_hour": 14}),
    )
    .unwrap();
    let id = denied.id.clone();
    assert!(matches!(
        gateway.execute(denied),
        Err(GatewayError::ComplianceViolation {
            rule: "external_disclosure_consent",
            ..
        })
    ));
    assert!(gateway.recall_by_id(&id).unwrap().is_none());
    let accepted = PaymentIntent::auto_route(
        MICRO_UNIT,
        "BRL",
        "did:mycelium:sender",
        "pix:key@example.com",
        json!({"local_hour": 14, "external_disclosure_consent": true}),
    )
    .unwrap();
    // Consent alone must NOT instantiate a fake PSP or constitute settlement.
    assert!(matches!(
        gateway.execute(accepted),
        Err(GatewayError::AdapterUnavailable("pix"))
    ));
}

#[test]
fn myc_usdc_reference_is_explicitly_not_a_redemption_guarantee() {
    let policy = mycelium_mint::MonetaryPolicy::mainnet();
    assert_eq!(policy.usdc_per_myc, 8);
    let candidate = intent(json!({}));
    let quote = candidate.reference_quote(&policy).unwrap();
    assert_eq!(quote.rate_usdc_per_myc, 8);
    assert_eq!(quote.myc_micros, MICRO_UNIT);
    assert_eq!(quote.usdc_reference_micros, 8 * MICRO_UNIT);
    assert!(!quote.redemption_guaranteed);
    assert!(PaymentIntent::auto_route(
        u64::MAX,
        "MYC",
        "did:mycelium:sender",
        "myc:receiver",
        json!({})
    )
    .unwrap()
    .reference_quote(&policy)
    .is_none());
}
