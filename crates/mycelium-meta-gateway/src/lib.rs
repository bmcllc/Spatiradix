//! # mycelium-meta-gateway
//!
//! **A Bíblia do Meta-Gateway Mycelium** — orquestrador financeiro descentralizado
//! em Rust unificando Pix (EMV QR Code BR Code + DICT + cob/cobv), SWIFT (CSP
//! A1/A2/A3/A4/B + Trust Boundary + pacs.008), BRICS Pay (DCMS P2P), resolução
//! descentralizada PKARR e o trilho nativo **MYC** estilo USDC (`1 MYC = 8 USDC`).

pub mod adapters;
pub mod compliance;
pub mod core;
pub mod engine;
pub mod error;
pub mod pkarr_resolver;

pub use adapters::MetaGatewayAdapter;
pub use compliance::CompliancePolicy;
pub use core::{
    DispatchReceipt, GatewayType, PaymentIntent, SwiftCspType, TransactionState, MICRO_UNIT,
};
pub use engine::{ExecutionOutcome, MetaGatewayEngine};
pub use error::GatewayError;
pub use pkarr_resolver::PkarrIdentityResolver;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{
        crc16_ccitt, BricsPayAdapter, DictEntry, DictKeyType, PixAdapter, SwiftAdapter,
    };
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use std::collections::HashMap;

    fn test_engine() -> MetaGatewayEngine {
        let mut engine = MetaGatewayEngine::new(
            SigningKey::from_bytes(&[0x42; 32]),
            b"mycelium-meta-gateway-genesis",
        );
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
        let mut engine = test_engine();

        // Chave ausente na DICT estrita deve falhar.
        let unknown = PaymentIntent::auto_route(
            100 * MICRO_UNIT,
            "BRL",
            "did:mycelium:bob",
            "pix:desconhecido@exemplo.com",
            json!({ "local_hour": 14 }),
        )
        .unwrap();
        assert!(matches!(
            engine.execute(unknown),
            Err(GatewayError::InvalidTarget(_))
        ));

        // Cobrança imediata (`cob`) com QR Code EMV `000201...` e CRC16 válido.
        let cob = PaymentIntent::auto_route(
            250 * MICRO_UNIT,
            "BRL",
            "did:mycelium:bob",
            "pix:alice@mycelium.net",
            json!({ "local_hour": 14 }),
        )
        .unwrap();
        let out_cob = engine.execute(cob).unwrap();
        assert!(matches!(out_cob.intent.state, TransactionState::Settled { .. }));
        let v: serde_json::Value = serde_json::from_str(&out_cob.receipt.native_payload).unwrap();
        assert_eq!(v["kind"], "cob");
        let qr = v["emv_qr_code"].as_str().unwrap();
        assert!(qr.starts_with("000201"));
        assert!(qr.contains("br.gov.bcb.pix"));
        let (body, crc_hex) = qr.split_at(qr.len() - 4);
        assert_eq!(format!("{:04X}", crc16_ccitt(body.as_bytes())), crc_hex);

        // Cobrança com vencimento (`cobv`) aguarda liquidação assíncrona.
        let cobv = PaymentIntent::auto_route(
            500 * MICRO_UNIT,
            "BRL",
            "did:mycelium:bob",
            "pix:alice@mycelium.net",
            json!({
                "local_hour": 14,
                "due_date": "2026-12-15",
                "days_after_due": 15
            }),
        )
        .unwrap();
        let out_cobv = engine.execute(cobv).unwrap();
        assert!(matches!(
            out_cobv.intent.state,
            TransactionState::AwaitingGatewayResponse { .. }
        ));
        let v2: serde_json::Value = serde_json::from_str(&out_cobv.receipt.native_payload).unwrap();
        assert_eq!(v2["kind"], "cobv");
        assert_eq!(v2["calendario"]["dataDeVencimento"], "2026-12-15");
    }

    #[test]
    fn swift_csp_decision_tree_enforces_trust_boundary_for_a1_a2_a3_a4_and_b() {
        let mut engine = test_engine();

        // A4 rejeita middleware_zone fora da Trust Boundary.
        let bad_a4 = PaymentIntent::auto_route(
            8_000 * MICRO_UNIT,
            "USDC",
            "did:mycelium:treasury",
            "swift:CHASUS33XXX",
            json!({
                "swift_csp_compliant": true,
                "secure_zone_log_id": "sz-001",
                "middleware_zone": "public_internet"
            }),
        )
        .unwrap();
        assert!(matches!(
            engine.execute(bad_a4),
            Err(GatewayError::ComplianceViolation {
                rule: "swift_trust_boundary_a4",
                ..
            })
        ));

        // Arquitetura A1 exige HSM/PKI verificado.
        engine.swift.as_mut().unwrap().architecture = SwiftCspType::A1;
        let bad_a1 = PaymentIntent::auto_route(
            8_000 * MICRO_UNIT,
            "USDC",
            "did:mycelium:treasury",
            "swift:CHASUS33XXX",
            json!({
                "swift_csp_compliant": true,
                "secure_zone_log_id": "sz-002"
            }),
        )
        .unwrap();
        assert!(matches!(
            engine.execute(bad_a1),
            Err(GatewayError::ComplianceViolation {
                rule: "swift_trust_boundary_a1",
                ..
            })
        ));

        // Arquitetura B (zero footprint) aceita Service Bureau + MFA do operador.
        engine.swift.as_mut().unwrap().architecture = SwiftCspType::B;
        let ok_b = PaymentIntent::auto_route(
            8_000 * MICRO_UNIT,
            "USDC",
            "did:mycelium:treasury",
            "swift:CHASUS33XXX",
            json!({
                "swift_csp_compliant": true,
                "secure_zone_log_id": "sz-b-003",
                "service_bureau_id": "sb-latam-01",
                "operator_mfa_verified": true
            }),
        )
        .unwrap();
        let out_b = engine.execute(ok_b).unwrap();
        assert!(out_b
            .receipt
            .native_payload
            .contains("ServiceBureau-ZeroFootprint-Portal"));
    }

    #[test]
    fn pkarr_resolves_decentralized_sender_and_receiver_before_routing() {
        let mut engine = test_engine();
        let alice_sk = SigningKey::from_bytes(&[0xA1; 32]);
        let bob_sk = SigningKey::from_bytes(&[0xB2; 32]);

        let (alice_pkarr, alice_pkt) =
            PkarrIdentityResolver::sign_payment_record(&alice_sk, 1_700_000_000_000, "pix:alice@mycelium.net")
                .unwrap();
        let (bob_pkarr, bob_pkt) =
            PkarrIdentityResolver::sign_payment_record(&bob_sk, 1_700_000_000_000, "myc:bob-node")
                .unwrap();

        engine.pkarr.register_verified_packet(alice_pkt).unwrap();
        engine.pkarr.register_verified_packet(bob_pkt).unwrap();

        // Bob (identificado por pkarr:) paga Alice (identificada por pkarr:) -> resolve para pix:alice@mycelium.net!
        let out = engine
            .resolve_and_execute(
                120 * MICRO_UNIT,
                "BRL",
                bob_pkarr,
                alice_pkarr,
                json!({ "local_hour": 15 }),
            )
            .unwrap();
        assert_eq!(out.receipt.gateway, GatewayType::Pix);
        assert_eq!(out.intent.receiver_id, "pix:alice@mycelium.net");
        assert!(matches!(out.intent.state, TransactionState::Settled { .. }));
    }

    #[test]
    fn myc_rail_settles_like_usdc_with_1_myc_equals_8_usdc_parity() {
        let mut engine = test_engine();
        let intent = PaymentIntent::auto_route(
            10 * MICRO_UNIT,
            "MYC",
            "did:mycelium:alice",
            "myc:73b07611ba1c6cbefb6f1c0be1efe46d766906b06b2e9930270a6d1e66f965de",
            json!({}),
        )
        .unwrap();

        let out = engine.execute(intent).unwrap();
        assert_eq!(out.receipt.gateway, GatewayType::MycRail);
        match out.intent.state {
            TransactionState::Settled {
                myc_micros,
                usdc_equivalent_micros,
                ..
            } => {
                assert_eq!(myc_micros, 10 * MICRO_UNIT);
                assert_eq!(usdc_equivalent_micros, 80 * MICRO_UNIT);
            }
            other => panic!("estado inesperado: {other:?}"),
        }
    }

    #[test]
    fn fsm_blocks_illegal_skip_from_initiated_to_settled() {
        let mut intent = PaymentIntent::auto_route(
            10 * MICRO_UNIT,
            "MYC",
            "did:mycelium:alice",
            "myc:bob",
            json!({}),
        )
        .unwrap();

        let err = intent
            .transition_to(TransactionState::Settled {
                external_tx_id: "bypass".into(),
                myc_micros: 10 * MICRO_UNIT,
                usdc_equivalent_micros: 80 * MICRO_UNIT,
            })
            .unwrap_err();
        assert!(matches!(err, GatewayError::InvalidTransition { .. }));
    }
}
