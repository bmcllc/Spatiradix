//! # mycelium-meta-gateway
//!
//! **A Bíblia do Meta-Gateway Mycelium** — orquestrador financeiro descentralizado
//! em Rust unificando Pix (O Sangue), SWIFT (O Esqueleto), BRICS Pay (O Espírito)
//! e o trilho nativo **MYC** comportando-se como ativo de liquidação estilo USDC
//! (`1 MYC = 8 USDC` via `mycelium-mint`) com selo pós-quântico ML-KEM-1024.

pub mod adapters;
pub mod compliance;
pub mod core;
pub mod engine;
pub mod error;

pub use adapters::MetaGatewayAdapter;
pub use compliance::CompliancePolicy;
pub use core::{
    DispatchReceipt, GatewayType, PaymentIntent, SwiftCspType, TransactionState,
};
pub use engine::{ExecutionOutcome, MetaGatewayEngine};
pub use error::GatewayError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{BricsPayAdapter, PixAdapter, SwiftAdapter};
    use crate::core::types::MICRO_UNIT;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    fn test_engine() -> MetaGatewayEngine {
        let mut engine = MetaGatewayEngine::new(
            SigningKey::from_bytes(&[0x42; 32]),
            b"mycelium-meta-gateway-genesis",
        );
        engine.pix = Some(PixAdapter {
            psp_endpoint: "https://pix.local.psp/v2/cob".into(),
            icp_brasil_cert_thumbprint: "icp-sha256:demo".into(),
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
    fn myc_rail_settles_like_usdc_with_1_myc_equals_8_usdc_parity() {
        let mut engine = test_engine();
        let intent = PaymentIntent::auto_route(
            10 * MICRO_UNIT, // 10 MYC = 80 USDC
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
    fn pix_enforces_night_limit_and_settles_daytime_payment() {
        let mut engine = test_engine();

        // Bloqueado: R$ 2.500 às 22h excede o teto noturno de R$ 1.000.
        let blocked = PaymentIntent::auto_route(
            2_500 * MICRO_UNIT,
            "BRL",
            "did:mycelium:alice",
            "pix:alice@mycelium.net",
            json!({ "local_hour": 22 }),
        )
        .unwrap();
        assert!(matches!(
            engine.execute(blocked),
            Err(GatewayError::ComplianceViolation {
                rule: "pix_night_limit",
                ..
            })
        ));

        // Permitido: R$ 500 às 14h liquida imediatamente.
        let ok_intent = PaymentIntent::auto_route(
            500 * MICRO_UNIT,
            "BRL",
            "did:mycelium:alice",
            "pix:alice@mycelium.net",
            json!({ "local_hour": 14 }),
        )
        .unwrap();
        let out = engine.execute(ok_intent).unwrap();
        assert!(matches!(out.intent.state, TransactionState::Settled { .. }));
        assert!(out.receipt.native_payload.contains("alice@mycelium.net"));
    }

    #[test]
    fn swift_requires_csp_compliance_and_generates_pacs008_a4() {
        let mut engine = test_engine();

        // Sem swift_csp_compliant=true -> bloqueado pelo Compliance-as-Code.
        let non_compliant = PaymentIntent::auto_route(
            8_000 * MICRO_UNIT,
            "USDC",
            "did:mycelium:treasury",
            "swift:CHASUS33XXX",
            json!({ "swift_csp_compliant": false }),
        )
        .unwrap();
        assert!(matches!(
            engine.execute(non_compliant),
            Err(GatewayError::ComplianceViolation {
                rule: "swift_csp_cscf",
                ..
            })
        ));

        // Com CSP ativo + secure_zone_log_id -> despacha pacs.008 via A4 e confirma via callback.
        let compliant = PaymentIntent::auto_route(
            8_000 * MICRO_UNIT, // 8.000 USDC = 1.000 MYC
            "USDC",
            "did:mycelium:treasury",
            "swift:CHASUS33XXX",
            json!({
                "swift_csp_compliant": true,
                "secure_zone_log_id": "sz-log-2026-001"
            }),
        )
        .unwrap();
        let mut out = engine.execute(compliant).unwrap();
        assert!(matches!(
            out.intent.state,
            TransactionState::AwaitingGatewayResponse { .. }
        ));
        assert!(out.receipt.native_payload.contains("Local-Middleware-MQ-FileAct"));
        assert!(out.receipt.native_payload.contains("<UETR>"));

        engine
            .confirm_settlement(&mut out.intent, out.receipt.external_ref.clone())
            .unwrap();
        match out.intent.state {
            TransactionState::Settled {
                myc_micros,
                usdc_equivalent_micros,
                ..
            } => {
                assert_eq!(usdc_equivalent_micros, 8_000 * MICRO_UNIT);
                assert_eq!(myc_micros, 1_000 * MICRO_UNIT);
            }
            other => panic!("estado inesperado: {other:?}"),
        }
    }

    #[test]
    fn brics_pay_dispatches_signed_dcms_packet() {
        let mut engine = test_engine();
        let intent = PaymentIntent::auto_route(
            160 * MICRO_UNIT, // 160 USDC = 20 MYC
            "USDC",
            "did:mycelium:br-node",
            "brics:dcms-node-09",
            json!({}),
        )
        .unwrap();

        let out = engine.execute(intent).unwrap();
        assert_eq!(out.receipt.gateway, GatewayType::BricsPay);
        assert!(out.receipt.native_payload.contains("DCMS-P2P-v1"));
        assert!(matches!(out.intent.state, TransactionState::Settled { .. }));
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
