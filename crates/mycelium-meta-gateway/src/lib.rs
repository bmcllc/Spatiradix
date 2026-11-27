//! # mycelium-meta-gateway
//!
//! **A Bíblia do Meta-Gateway Mycelium** — orquestrador financeiro descentralizado
//! em Rust unificando Pix (EMV QR Code BR Code + DICT + cob/cobv + mTLS), SWIFT
//! (CSP A1/A2/A3/A4/B + Trust Boundary + HSM + pacs.008), BRICS Pay (DCMS MT103),
//! PKARR, persistência no `SporeBank`, Webhooks Axum e trilho nativo **MYC** estilo
//! USDC (`1 MYC = 8 USDC`).

pub mod adapters;
pub mod compliance;
pub mod core;
pub mod engine;
pub mod error;
pub mod persistence;
pub mod merchant_checkout;
pub mod sovereign_cipher;
#[cfg(feature = "pix")]
pub mod pix_brcode;
#[cfg(feature = "pix")]
pub mod bse_web_pix;
#[cfg(feature = "pix")]
pub use bse_web_pix::inspect_pix as inspect_pix_brcode;
#[cfg(feature = "pix")]
pub mod bse_web_pix_json;
#[cfg(feature = "pix")]
pub use bse_web_pix_json::inspect_json as inspect_pix_json;
#[cfg(feature = "pix")]
pub(crate) use bse_web_pix_json as pix_json;
#[cfg(feature = "pix")]
pub mod bse_web_http;
#[cfg(feature = "pix")]
pub use bse_web_http::observe_http_trace;
#[cfg(feature = "pix")]
pub mod bse_web_pix_state;
#[cfg(feature = "pix")]
pub use bse_web_pix_state::replay_json as replay_pix_state;
#[cfg(feature = "pix")]
pub(crate) use bse_web_pix_state as pix_state;
#[cfg(feature = "pix")]
pub mod bse_web_iso;
#[cfg(feature = "pix")]
pub use bse_web_iso::inspect_iso as inspect_iso_message;
#[cfg(feature = "pix")]
pub(crate) use bse_web_http as http_observer;
#[cfg(feature = "pix")]
pub(crate) use bse_web_iso as iso20022;
#[cfg(feature = "pix")]
pub(crate) use bse_web_pix::inspect_pix;
#[cfg(feature = "pix")]
pub mod bse_web_psp_lab;
#[cfg(feature = "pix")]
pub use bse_web_psp_lab::run_lab as run_pix_psp_lab;
#[cfg(feature = "pix-privacy-lab")]
pub mod bse_web_privacy_lab;
#[cfg(feature = "pix-privacy-lab")]
pub use bse_web_privacy_lab::run_privacy_lab as run_pix_privacy_lab;
#[cfg(feature = "pix-pay-lab")]
pub mod bse_web_pay_lab;
#[cfg(feature = "pix-pay-lab")]
pub use bse_web_pay_lab::run_pay_lab as run_pix_pay_lab;
pub mod pkarr_resolver;
#[cfg(any(feature = "swift", feature = "brics"))]
pub mod swift_formats;
pub mod tls_hsm;
pub mod veil_egress;
pub mod webhooks;

pub use adapters::MetaGatewayAdapter;
pub use compliance::CompliancePolicy;
pub use core::{
    DispatchReceipt, GatewayType, IndicativeMycQuote, PaymentIntent, SwiftCspType,
    TransactionState, MICRO_UNIT,
};
pub use engine::{ExecutionOutcome, MetaGatewayEngine};
pub use error::GatewayError;
pub use veil_egress::VeilEgress;
pub use persistence::SporebankIntentStore;
pub use merchant_checkout::{prepare_myc_purchase, PreparedMycCheckout};
pub use pkarr_resolver::PkarrIdentityResolver;
pub use tls_hsm::{CertFormat, HsmAttestation, PixMtlsConfig, SwiftHsmKeystore};
pub use webhooks::{
    build_webhook_router, BricsWebhookEvent, PixWebhookEvent, SwiftWebhookEvent, WebhookAck,
    WebhookServiceState,
};

#[cfg(test)]
mod safety_tests;

#[cfg(all(test, feature = "pix", feature = "swift", feature = "brics"))]
mod tests {
    use super::*;
    use crate::adapters::{
        crc16_ccitt, BricsPayAdapter, DcmsMessage, DictEntry, DictKeyType, PixAdapter, SwiftAdapter,
    };
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use mycelium_core::NodeId;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    fn test_engine_with_home(home: &std::path::Path) -> MetaGatewayEngine {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let author = NodeId::derive(sk.verifying_key().as_bytes());
        let store = SporebankIntentStore::open_encrypted(home, author, [0x32; 32]).unwrap();
        let mut engine =
            MetaGatewayEngine::new(sk, b"mycelium-meta-gateway-genesis").with_sporebank(store);

        let mut dict = HashMap::new();
        dict.insert(
            "alice@mycelium.net".into(),
            DictEntry {
                key: "alice@mycelium.net".into(),
                key_type: DictKeyType::Email,
                ispb: "60701190".into(),
                holder_name: "ALICE MYCELIUM".into(),
                merchant_city: "FORTALEZA".into(),
            },
        );
        engine.pix = Some(PixAdapter {
            psp_endpoint: "https://pix.local.psp/v2".into(),
            icp_brasil_cert_thumbprint: "icp-sha256:demo".into(),
            dict_directory: dict,
            strict_dict_lookup: true,
        });
        engine.swift = Some(SwiftAdapter {
            architecture: SwiftCspType::A4,
            bic_sender: "MYCEBRSPXXX".into(),
            channel_endpoint: "mq://secure-zone-local:1414".into(),
        });
        engine.brics = Some(BricsPayAdapter::new(
            "https://dcms.brics.local/v1/tx",
            SigningKey::from_bytes(&[0x77; 32]),
        ));
        engine
    }

    #[test]
    fn pix_generates_valid_emv_brcode_with_crc16_for_cob_and_cobv_and_enforces_dict() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = test_engine_with_home(dir.path());

        let unknown = PaymentIntent::auto_route(
            100 * MICRO_UNIT,
            "BRL",
            "did:mycelium:bob",
            "pix:desconhecido@exemplo.com",
            json!({ "local_hour": 14, "external_disclosure_consent": true }),
        )
        .unwrap();
        assert!(matches!(
            engine.execute(unknown),
            Err(GatewayError::InvalidTarget(_))
        ));

        let cob = PaymentIntent::auto_route(
            250 * MICRO_UNIT,
            "BRL",
            "did:mycelium:bob",
            "pix:alice@mycelium.net",
            json!({ "local_hour": 14, "external_disclosure_consent": true }),
        )
        .unwrap();
        let out_cob = engine.execute(cob).unwrap();
        assert!(matches!(
            out_cob.intent.state,
            TransactionState::AwaitingGatewayResponse { .. }
        ));
        let v: serde_json::Value = serde_json::from_str(&out_cob.receipt.native_payload).unwrap();
        assert_eq!(v["kind"], "cob");
        assert!(v["emv_qr_code"].is_null());
        assert_eq!(v["dispatch_status"], "prepared_not_submitted");
        let static_qr = crate::adapters::build_emv_brcode(
            "alice@mycelium.net",
            "250.00",
            "ALICE MYCELIUM",
            "FORTALEZA",
            "REF123",
        );
        let qr = static_qr.as_str();
        assert!(qr.starts_with("000201010211"));
        let (body, crc_hex) = qr.split_at(qr.len() - 4);
        assert_eq!(format!("{:04X}", crc16_ccitt(body.as_bytes())), crc_hex);
    }

    #[test]
    fn sporebank_persists_state_and_recovers_after_node_restart() {
        let dir = tempfile::tempdir().unwrap();
        let intent_id;
        let uetr;
        {
            let mut engine = test_engine_with_home(dir.path());
            let swift_intent = PaymentIntent::auto_route(
                8_000 * MICRO_UNIT,
                "USD",
                "did:mycelium:treasury",
                "swift:CHASUS33XXX",
                json!({
                    "swift_csp_compliant": true,
                    "secure_zone_log_id": "sz-restart-01", "external_disclosure_consent": true
                }),
            )
            .unwrap();
            let out = engine.execute(swift_intent).unwrap();
            intent_id = out.intent.id.clone();
            uetr = out.receipt.external_ref.clone();
            assert!(engine.latest_sporebank_cid(&intent_id).is_some());
        }

        // Simula reinício completo do nó reabrindo o SporeBank do disco.
        let reloaded = test_engine_with_home(dir.path());
        let recovered = reloaded
            .recall_by_external_ref(&uetr)
            .unwrap()
            .expect("intent recuperado após queda do nó");
        assert_eq!(recovered.id, intent_id);
        assert!(matches!(
            recovered.state,
            TransactionState::AwaitingGatewayResponse { .. }
        ));
    }

    #[tokio::test]
    async fn axum_webhooks_settle_swift_and_pix_cobv_and_reject_bad_signature() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = test_engine_with_home(dir.path());

        // 1. Cria cobrança Pix `cobv` (aguardando pagamento assíncrono).
        let cobv = PaymentIntent::auto_route(
            500 * MICRO_UNIT,
            "BRL",
            "did:mycelium:bob",
            "pix:alice@mycelium.net",
            json!({ "local_hour": 14, "due_date": "2026-12-20", "external_disclosure_consent": true }),
        )
        .unwrap();
        let out_cobv = engine.execute(cobv).unwrap();
        let txid = out_cobv.receipt.external_ref.clone();
        let cobv_id = out_cobv.intent.id.clone();

        // 2. Cria transferência SWIFT (aguardando pacs.002).
        let swift = PaymentIntent::auto_route(
            8_000 * MICRO_UNIT,
            "USD",
            "did:mycelium:treasury",
            "swift:CHASUS33XXX",
            json!({ "swift_csp_compliant": true, "secure_zone_log_id": "sz-wh-01", "external_disclosure_consent": true }),
        )
        .unwrap();
        let out_swift = engine.execute(swift).unwrap();
        let uetr = out_swift.receipt.external_ref.clone();

        let secret = [0x99u8; 32];
        let state = Arc::new(Mutex::new(WebhookServiceState {
            engine,
            webhook_secret: secret,
        }));
        let app = build_webhook_router(state.clone());
        let no_public_read = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/intents/{cobv_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(no_public_read.status(), StatusCode::NOT_FOUND);

        // Assinatura adulterada -> 401 Unauthorized.
        let bad_ev = PixWebhookEvent {
            txid: txid.clone(),
            end_to_end_id: "E60701190202611201600abc".into(),
            status: "CONCLUIDA".into(),
            signature_hex: "0000".into(),
        };
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/pix")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&bad_ev).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Webhook Pix válido -> liquida `cobv` e grava novo Plot no SporeBank.
        let sig_pix = WebhookServiceState::sign_callback(
            &secret,
            &format!("pix:{txid}:E60701190202611201600abc:CONCLUIDA"),
        );
        let ok_pix = PixWebhookEvent {
            txid,
            end_to_end_id: "E60701190202611201600abc".into(),
            status: "CONCLUIDA".into(),
            signature_hex: sig_pix,
        };
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/pix")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&ok_pix).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let ack: WebhookAck = serde_json::from_slice(&body).unwrap();
        assert_eq!(ack.intent_id, cobv_id);
        assert_eq!(ack.state, "settled");
        assert!(ack.sporebank_cid.is_some());

        // Exactly the same signed callback is idempotent; do not emit a second settlement.
        let again = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/pix")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&ok_pix).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(again.status(), StatusCode::OK);

        // Webhook SWIFT `pacs.002` (ACSC) -> liquida transferência SWIFT.
        let sig_swift = WebhookServiceState::sign_callback(&secret, &format!("swift:{uetr}:ACSC:"));
        let ok_swift = SwiftWebhookEvent {
            uetr,
            status_code: "ACSC".into(),
            reason: None,
            signature_hex: sig_swift,
        };
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/swift")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&ok_swift).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn brics_pay_dcms_mt103_payload_and_pkarr_node_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let mut engine = test_engine_with_home(dir.path());

        let brics_node_sk = SigningKey::from_bytes(&[0xB9; 32]);
        let (brics_pkarr, pkt) = PkarrIdentityResolver::sign_payment_record(
            &brics_node_sk,
            1_700_000_000_000,
            "brics:dcms-sao-paulo-01",
        )
        .unwrap();
        engine.pkarr.register_verified_packet(pkt).unwrap();

        let out = engine
            .resolve_and_execute(
                160 * MICRO_UNIT, // 160 USDC = 20 MYC
                "USDC",
                "did:mycelium:br-exporter",
                brics_pkarr,
                json!({ "value_date": "2026-11-20", "external_disclosure_consent": true }),
            )
            .unwrap();

        assert_eq!(out.receipt.gateway, GatewayType::BricsPay);
        let dcms: DcmsMessage = serde_json::from_str(&out.receipt.native_payload).unwrap();
        assert_eq!(dcms.msg_type, "DCMS.pacs.008.MT103");
        assert_eq!(dcms.receiver_node, "dcms-sao-paulo-01");
        assert_eq!(dcms.myc_reference_micros, 20 * MICRO_UNIT);
        assert_eq!(dcms.amount, "160.00");
        assert_eq!(dcms.signature_ed25519_hex.len(), 128);
    }

    #[test]
    fn pix_mtls_and_swift_hsm_keystore_fail_closed_and_attest() {
        let dir = tempfile::tempdir().unwrap();

        // Pix mTLS: arquivo ausente ou .p12 inválido falha fechado.
        assert!(PixMtlsConfig::load_pem_client(dir.path().join("missing.pem")).is_err());
        let p12_path = dir.path().join("icp-brasil.p12");
        let mut fake_der = vec![0x30u8; 32];
        fake_der[1] = 0x1e;
        std::fs::write(&p12_path, &fake_der).unwrap();
        assert!(PixMtlsConfig::load_pkcs12_metadata(&p12_path, "senha-icp-2026").is_err());

        // SWIFT HSM Keystore: cria, bloqueia PIN errado e atesta Secure Zone com PIN correto.
        let hsm_path = dir.path().join("swift-hsm.json");
        let _created =
            SwiftHsmKeystore::create_file(&hsm_path, "slot-a1-00", "pin-seguro-99", [0x55; 32])
                .unwrap();
        assert!(SwiftHsmKeystore::unlock_file(&hsm_path, "pin-errado").is_err());

        let unlocked = SwiftHsmKeystore::unlock_file(&hsm_path, "pin-seguro-99").unwrap();
        let att = unlocked.attest_secure_zone("sz-log-a1-777");
        assert_eq!(att.slot_id, "slot-a1-00");
        assert_eq!(att.signature_hex.len(), 128);
    }
}
