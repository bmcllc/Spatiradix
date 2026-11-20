//! Livro IV (Números): adaptadores isolados para Pix (O Sangue), SWIFT (O Esqueleto),
//! BRICS Pay (O Espírito) e MYC Settlement Rail (comportamento estilo USDC, 1 MYC = 8 USDC).

use crate::core::{DispatchReceipt, GatewayType, PaymentIntent, SwiftCspType, MICRO_UNIT};
use crate::error::GatewayError;
use ed25519_dalek::{Signer, SigningKey};
use mycelium_mint::MonetaryPolicy;

/// Contrato comum de tradução de um `PaymentIntent` para o protocolo nativo do gateway.
pub trait MetaGatewayAdapter: Send + Sync {
    fn gateway_type(&self) -> GatewayType;
    fn dispatch(&self, intent: &PaymentIntent) -> Result<DispatchReceipt, GatewayError>;
}

/// 4.1 O Adapter PIX (O Sangue): traduz para payload `cob` padrão BACEN/ISO 20022.
#[cfg(feature = "pix")]
#[derive(Debug, Clone)]
pub struct PixAdapter {
    pub psp_endpoint: String,
    pub icp_brasil_cert_thumbprint: String,
}

#[cfg(feature = "pix")]
impl MetaGatewayAdapter for PixAdapter {
    fn gateway_type(&self) -> GatewayType {
        GatewayType::Pix
    }

    fn dispatch(&self, intent: &PaymentIntent) -> Result<DispatchReceipt, GatewayError> {
        let dict_key = intent
            .receiver_id
            .strip_prefix("pix:")
            .unwrap_or(&intent.receiver_id)
            .trim();
        if dict_key.is_empty() {
            return Err(GatewayError::InvalidTarget(intent.receiver_id.clone()));
        }

        // txid determinístico (32 chars hex alfanuméricos, compatível com especificação BACEN 26..35).
        let txid = hex::encode(&blake3::hash(intent.canonical_bytes().as_slice()).as_bytes()[..16]);
        let valor = format!(
            "{}.{:02}",
            intent.amount_micros / MICRO_UNIT,
            (intent.amount_micros % MICRO_UNIT) / 10_000
        );
        let payload = serde_json::json!({
            "txid": txid,
            "chave": dict_key,
            "valor": { "original": valor },
            "solicitacaoPagador": format!("mycelium:{}", &intent.id[..12]),
            "mtls_thumbprint": self.icp_brasil_cert_thumbprint,
            "endpoint": self.psp_endpoint,
        });

        Ok(DispatchReceipt {
            gateway: GatewayType::Pix,
            external_ref: txid,
            native_payload: payload.to_string(),
            settled_immediately: true,
        })
    }
}

/// 4.2 O Adapter SWIFT (O Esqueleto): gera UETR + envelope `pacs.008` respeitando pegada CSP (A1/A3/A4).
#[cfg(feature = "swift")]
#[derive(Debug, Clone)]
pub struct SwiftAdapter {
    pub architecture: SwiftCspType,
    pub bic_sender: String,
    pub channel_endpoint: String,
}

#[cfg(feature = "swift")]
impl MetaGatewayAdapter for SwiftAdapter {
    fn gateway_type(&self) -> GatewayType {
        GatewayType::Swift
    }

    fn dispatch(&self, intent: &PaymentIntent) -> Result<DispatchReceipt, GatewayError> {
        let bic_receiver = intent
            .receiver_id
            .strip_prefix("swift:")
            .unwrap_or(&intent.receiver_id)
            .trim();
        if bic_receiver.len() < 8 {
            return Err(GatewayError::InvalidTarget(intent.receiver_id.clone()));
        }

        // Gera UETR em formato UUIDv4 canônico (8-4-4-4-12) derivado do intent.
        let h = blake3::hash(&intent.canonical_bytes());
        let b = h.as_bytes();
        let uetr = format!(
            "{}-{}-{}-{}-{}",
            hex::encode(&b[0..4]),
            hex::encode(&b[4..6]),
            hex::encode(&b[6..8]),
            hex::encode(&b[8..10]),
            hex::encode(&b[10..16]),
        );

        let route_mode = match self.architecture {
            SwiftCspType::A1 => "MI/CI-Direct",
            SwiftCspType::A3 => "SWIFT-API-Gateway",
            SwiftCspType::A4 => "Local-Middleware-MQ-FileAct",
        };
        let amount_fmt = format!(
            "{}.{:02}",
            intent.amount_micros / MICRO_UNIT,
            (intent.amount_micros % MICRO_UNIT) / 10_000
        );
        let pacs008 = format!(
            "<Document><FIToFICstmrCdtTrf><GrpHdr><MsgId>{}</MsgId></GrpHdr><CdtTrfTxInf><PmtId><UETR>{}</UETR></PmtId><IntrBkSttlmAmt Ccy=\"{}\">{}</IntrBkSttlmAmt><DbtrAgt><FinInstnId><BICFI>{}</BICFI></FinInstnId></DbtrAgt><CdtrAgt><FinInstnId><BICFI>{}</BICFI></FinInstnId></CdtrAgt><Route>{}:{}</Route></CdtTrfTxInf></FIToFICstmrCdtTrf></Document>",
            &intent.id[..16],
            uetr,
            intent.currency,
            amount_fmt,
            self.bic_sender,
            bic_receiver,
            route_mode,
            self.channel_endpoint
        );

        Ok(DispatchReceipt {
            gateway: GatewayType::Swift,
            external_ref: uetr,
            native_payload: pacs008,
            settled_immediately: false,
        })
    }
}

/// 4.3 O Adapter BRICS Pay (O Espírito): mensageria descentralizada DCMS com assinatura do próprio nó.
#[cfg(feature = "brics")]
#[derive(Clone)]
pub struct BricsPayAdapter {
    pub dcms_node_url: String,
    node_signing_key: SigningKey,
}

#[cfg(feature = "brics")]
impl BricsPayAdapter {
    pub fn new(dcms_node_url: impl Into<String>, node_signing_key: SigningKey) -> Self {
        Self {
            dcms_node_url: dcms_node_url.into(),
            node_signing_key,
        }
    }
}

#[cfg(feature = "brics")]
impl MetaGatewayAdapter for BricsPayAdapter {
    fn gateway_type(&self) -> GatewayType {
        GatewayType::BricsPay
    }

    fn dispatch(&self, intent: &PaymentIntent) -> Result<DispatchReceipt, GatewayError> {
        let target_node = intent
            .receiver_id
            .strip_prefix("brics:")
            .or_else(|| intent.receiver_id.strip_prefix("dcms:"))
            .unwrap_or(&intent.receiver_id)
            .trim();
        if target_node.is_empty() {
            return Err(GatewayError::InvalidTarget(intent.receiver_id.clone()));
        }

        let sig = self.node_signing_key.sign(&intent.canonical_bytes());
        let dcms_tx_id = format!(
            "dcms:{}",
            hex::encode(&blake3::hash(&sig.to_bytes()).as_bytes()[..16])
        );
        let payload = serde_json::json!({
            "protocol": "DCMS-P2P-v1",
            "node_url": self.dcms_node_url,
            "target_node": target_node,
            "intent_id": intent.id,
            "amount_micros": intent.amount_micros,
            "currency": intent.currency,
            "signature_hex": hex::encode(sig.to_bytes()),
        });

        Ok(DispatchReceipt {
            gateway: GatewayType::BricsPay,
            external_ref: dcms_tx_id,
            native_payload: payload.to_string(),
            settled_immediately: true,
        })
    }
}

/// Trilho nativo MYC comportando-se como ativo de liquidação estilo USDC (`1 MYC = 8 USDC`).
#[derive(Debug, Clone)]
pub struct MycSettlementAdapter {
    pub policy: MonetaryPolicy,
}

impl Default for MycSettlementAdapter {
    fn default() -> Self {
        Self {
            policy: MonetaryPolicy::mainnet(),
        }
    }
}

impl MetaGatewayAdapter for MycSettlementAdapter {
    fn gateway_type(&self) -> GatewayType {
        GatewayType::MycRail
    }

    fn dispatch(&self, intent: &PaymentIntent) -> Result<DispatchReceipt, GatewayError> {
        let (myc_micros, usdc_micros) = intent.myc_usdc_parity(&self.policy);
        let ref_id = format!("myc-tx:{}", &intent.id[..24]);
        let payload = serde_json::json!({
            "rail": "mycelium-myc-usdc-settlement",
            "usdc_per_myc": self.policy.usdc_per_myc,
            "myc_micros": myc_micros,
            "usdc_equivalent_micros": usdc_micros,
            "receiver": intent.receiver_id,
        });

        Ok(DispatchReceipt {
            gateway: GatewayType::MycRail,
            external_ref: ref_id,
            native_payload: payload.to_string(),
            settled_immediately: true,
        })
    }
}
