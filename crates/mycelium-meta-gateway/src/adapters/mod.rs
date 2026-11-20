//! Livro IV (Números): adaptadores isolados para Pix (EMV QR Code BR Code + DICT + cob/cobv),
//! SWIFT (CSP Decision Tree A1/A2/A3/A4/B + Trust Boundary + pacs.008 / MQ-FileAct),
//! BRICS Pay (DCMS P2P) e MYC Settlement Rail (comportamento estilo USDC, 1 MYC = 8 USDC).

use crate::core::{DispatchReceipt, GatewayType, PaymentIntent, SwiftCspType, MICRO_UNIT};
use crate::error::GatewayError;
use ed25519_dalek::{Signer, SigningKey};
use mycelium_mint::MonetaryPolicy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Contrato comum de tradução de um `PaymentIntent` para o protocolo nativo do gateway.
pub trait MetaGatewayAdapter: Send + Sync {
    fn gateway_type(&self) -> GatewayType;
    fn dispatch(&self, intent: &PaymentIntent) -> Result<DispatchReceipt, GatewayError>;
}

// ─── 4.1 O Adapter PIX (O Sangue): DICT + EMV QR Code (000201...) + cob/cobv ──

#[cfg(feature = "pix")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DictKeyType {
    Cpf,
    Cnpj,
    Email,
    Phone,
    Evp,
}

#[cfg(feature = "pix")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DictEntry {
    pub key: String,
    pub key_type: DictKeyType,
    pub ispb: String,
    pub holder_name: String,
    pub merchant_city: String,
}

#[cfg(feature = "pix")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PixChargeKind {
    /// Cobrança imediata (PUT /cob/{txid}).
    Cob,
    /// Cobrança com vencimento (PUT /cobv/{txid}).
    Cobv,
}

/// Classifica uma chave Pix segundo o Manual de Padrões DICT do BACEN.
#[cfg(feature = "pix")]
pub fn classify_dict_key(key: &str) -> Option<DictKeyType> {
    let k = key.trim();
    if k.is_empty() {
        return None;
    }
    if k.contains('@') && k.contains('.') {
        return Some(DictKeyType::Email);
    }
    if k.starts_with("+55") && k.len() >= 13 && k[1..].chars().all(|c| c.is_ascii_digit()) {
        return Some(DictKeyType::Phone);
    }
    if k.len() == 11 && k.chars().all(|c| c.is_ascii_digit()) {
        return Some(DictKeyType::Cpf);
    }
    if k.len() == 14 && k.chars().all(|c| c.is_ascii_digit()) {
        return Some(DictKeyType::Cnpj);
    }
    // Chave aleatória EVP (UUID 36 chars com hífens).
    if k.len() == 36 && k.chars().filter(|&c| c == '-').count() == 4 {
        return Some(DictKeyType::Evp);
    }
    None
}

/// Calcula CRC16-CCITT (polinômio 0x1021, inicial 0xFFFF) exigido pelo padrão EMVCo / BR Code.
#[cfg(feature = "pix")]
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

#[cfg(feature = "pix")]
fn emv_tlv(id: &str, value: &str) -> String {
    format!("{id}{:02}{value}", value.len())
}

/// Gera um payload EMV QR Code BR Code (`000201...6304XXXX`) conforme Manual de Padrões do Pix.
#[cfg(feature = "pix")]
pub fn build_emv_brcode(
    dict_key: &str,
    amount_brl: &str,
    merchant_name: &str,
    merchant_city: &str,
    txid: &str,
) -> String {
    let gui = emv_tlv("00", "br.gov.bcb.pix");
    let key_field = emv_tlv("01", dict_key);
    let mai = emv_tlv("26", &format!("{gui}{key_field}"));
    let name: String = merchant_name.chars().take(25).collect();
    let city: String = merchant_city.chars().take(15).collect();
    let add_data = emv_tlv("62", &emv_tlv("05", txid));

    let body = format!(
        "{}{}{}{}{}{}{}{}{}{}6304",
        emv_tlv("00", "01"),
        emv_tlv("01", "12"),
        mai,
        emv_tlv("52", "0000"),
        emv_tlv("53", "986"),
        emv_tlv("54", amount_brl),
        emv_tlv("58", "BR"),
        emv_tlv("59", &name),
        emv_tlv("60", &city),
        add_data,
    );
    let crc = crc16_ccitt(body.as_bytes());
    format!("{body}{crc:04X}")
}

/// 4.1 O Adapter PIX (O Sangue): consulta DICT, gera EMV QR Code (`000201...`) e monta `cob` ou `cobv`.
#[cfg(feature = "pix")]
#[derive(Debug, Clone)]
pub struct PixAdapter {
    pub psp_endpoint: String,
    pub icp_brasil_cert_thumbprint: String,
    /// Diretório DICT local/cacheado (`chave -> DictEntry`). Se vazio, resolve pela classificação sintática.
    pub dict_directory: HashMap<String, DictEntry>,
    /// Quando `true`, exige que a chave exista explicitamente no `dict_directory`.
    pub strict_dict_lookup: bool,
}

#[cfg(feature = "pix")]
impl PixAdapter {
    pub fn resolve_dict(&self, key: &str) -> Result<DictEntry, GatewayError> {
        let k = key.trim();
        if let Some(entry) = self.dict_directory.get(k) {
            return Ok(entry.clone());
        }
        if self.strict_dict_lookup {
            return Err(GatewayError::InvalidTarget(format!(
                "chave Pix `{k}` não encontrada na DICT"
            )));
        }
        let key_type = classify_dict_key(k).ok_or_else(|| {
            GatewayError::InvalidTarget(format!("chave Pix `{k}` fora do padrão DICT"))
        })?;
        Ok(DictEntry {
            key: k.to_string(),
            key_type,
            ispb: "00000000".into(),
            holder_name: "MYCELIUM NODE".into(),
            merchant_city: "FORTALEZA".into(),
        })
    }
}

#[cfg(feature = "pix")]
impl MetaGatewayAdapter for PixAdapter {
    fn gateway_type(&self) -> GatewayType {
        GatewayType::Pix
    }

    fn dispatch(&self, intent: &PaymentIntent) -> Result<DispatchReceipt, GatewayError> {
        let raw_key = intent
            .receiver_id
            .strip_prefix("pix:")
            .unwrap_or(&intent.receiver_id)
            .trim();
        let dict = self.resolve_dict(raw_key)?;

        // txid determinístico (32 chars hex alfanuméricos, padrão BACEN 26..35).
        let txid = hex::encode(&blake3::hash(intent.canonical_bytes().as_slice()).as_bytes()[..16]);
        let valor = format!(
            "{}.{:02}",
            intent.amount_micros / MICRO_UNIT,
            (intent.amount_micros % MICRO_UNIT) / 10_000
        );

        let due_date = intent
            .compliance_metadata
            .get("due_date")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty());

        let (charge_kind, endpoint, calendario) = if let Some(venc) = due_date {
            let validade_apos = intent
                .compliance_metadata
                .get("days_after_due")
                .and_then(|v| v.as_u64())
                .unwrap_or(30);
            (
                PixChargeKind::Cobv,
                format!("{}/cobv/{txid}", self.psp_endpoint.trim_end_matches('/')),
                serde_json::json!({
                    "dataDeVencimento": venc,
                    "validadeAposVencimento": validade_apos,
                }),
            )
        } else {
            let expiracao = intent
                .compliance_metadata
                .get("expiration_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(3600);
            (
                PixChargeKind::Cob,
                format!("{}/cob/{txid}", self.psp_endpoint.trim_end_matches('/')),
                serde_json::json!({ "expiracao": expiracao }),
            )
        };

        let emv_qr = build_emv_brcode(
            &dict.key,
            &valor,
            &dict.holder_name,
            &dict.merchant_city,
            &txid,
        );

        let payload = serde_json::json!({
            "kind": charge_kind,
            "txid": txid,
            "endpoint": endpoint,
            "dict": dict,
            "calendario": calendario,
            "valor": { "original": valor },
            "emv_qr_code": emv_qr,
            "mtls_thumbprint": self.icp_brasil_cert_thumbprint,
        });

        Ok(DispatchReceipt {
            gateway: GatewayType::Pix,
            external_ref: txid,
            native_payload: payload.to_string(),
            settled_immediately: charge_kind == PixChargeKind::Cob,
        })
    }
}

// ─── 4.2 O Adapter SWIFT (O Esqueleto): CSP A1/A2/A3/A4/B + Trust Boundary ────

#[cfg(feature = "swift")]
#[derive(Debug, Clone)]
pub struct SwiftAdapter {
    pub architecture: SwiftCspType,
    pub bic_sender: String,
    pub channel_endpoint: String,
}

#[cfg(feature = "swift")]
impl SwiftAdapter {
    /// Verifica a fronteira de confiança (Trust Boundary) exigida pela árvore de decisão SWIFT CSP.
    pub fn verify_trust_boundary(&self, intent: &PaymentIntent) -> Result<&'static str, GatewayError> {
        let meta = &intent.compliance_metadata;
        match self.architecture {
            SwiftCspType::A1 => {
                if !meta
                    .get("hsm_pki_verified")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
                {
                    return Err(GatewayError::ComplianceViolation {
                        rule: "swift_trust_boundary_a1",
                        detail: "arquitetura A1 exige hsm_pki_verified=true (MI/CI próprios)".into(),
                    });
                }
                Ok("MI/CI-Direct-ISO20022")
            }
            SwiftCspType::A2 => {
                let hsm = meta
                    .get("hsm_pki_verified")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let sb = meta
                    .get("service_bureau_id")
                    .and_then(|v| v.as_str())
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                if !hsm || !sb {
                    return Err(GatewayError::ComplianceViolation {
                        rule: "swift_trust_boundary_a2",
                        detail: "arquitetura A2 exige hsm_pki_verified=true e service_bureau_id"
                            .into(),
                    });
                }
                Ok("MI-Local-to-ServiceBureau-CI")
            }
            SwiftCspType::A3 => {
                let mtls = meta
                    .get("api_mtls_thumbprint")
                    .and_then(|v| v.as_str())
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                if !mtls {
                    return Err(GatewayError::ComplianceViolation {
                        rule: "swift_trust_boundary_a3",
                        detail: "arquitetura A3 exige api_mtls_thumbprint para SWIFT API Gateway"
                            .into(),
                    });
                }
                Ok("SWIFT-API-Gateway-pacs008")
            }
            SwiftCspType::A4 => {
                let zone = meta
                    .get("middleware_zone")
                    .and_then(|v| v.as_str())
                    .unwrap_or("customer_connector");
                if zone != "customer_connector" && zone != "secure_zone" {
                    return Err(GatewayError::ComplianceViolation {
                        rule: "swift_trust_boundary_a4",
                        detail: format!(
                            "middleware_zone `{zone}` fora da Trust Boundary A4 (customer_connector/secure_zone)"
                        ),
                    });
                }
                Ok("Local-Middleware-MQ-FileAct")
            }
            SwiftCspType::B => {
                let sb = meta
                    .get("service_bureau_id")
                    .and_then(|v| v.as_str())
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                let mfa = meta
                    .get("operator_mfa_verified")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !sb || !mfa {
                    return Err(GatewayError::ComplianceViolation {
                        rule: "swift_trust_boundary_b",
                        detail: "arquitetura B exige service_bureau_id e operator_mfa_verified=true"
                            .into(),
                    });
                }
                Ok("ServiceBureau-ZeroFootprint-Portal")
            }
        }
    }
}

#[cfg(feature = "swift")]
impl MetaGatewayAdapter for SwiftAdapter {
    fn gateway_type(&self) -> GatewayType {
        GatewayType::Swift
    }

    fn dispatch(&self, intent: &PaymentIntent) -> Result<DispatchReceipt, GatewayError> {
        let route_mode = self.verify_trust_boundary(intent)?;

        let bic_receiver = intent
            .receiver_id
            .strip_prefix("swift:")
            .unwrap_or(&intent.receiver_id)
            .trim();
        if bic_receiver.len() < 8 {
            return Err(GatewayError::InvalidTarget(intent.receiver_id.clone()));
        }

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

        let amount_fmt = format!(
            "{}.{:02}",
            intent.amount_micros / MICRO_UNIT,
            (intent.amount_micros % MICRO_UNIT) / 10_000
        );
        let transport_frame = match self.architecture {
            SwiftCspType::A4 => format!(
                "<Transport protocol=\"MQ/FileAct\" csp=\"A4\" endpoint=\"{}\"/>",
                self.channel_endpoint
            ),
            arch => format!(
                "<Transport protocol=\"{route_mode}\" csp=\"{arch:?}\" endpoint=\"{}\"/>",
                self.channel_endpoint
            ),
        };
        let pacs008 = format!(
            "<Document><FIToFICstmrCdtTrf><GrpHdr><MsgId>{}</MsgId></GrpHdr><CdtTrfTxInf><PmtId><UETR>{}</UETR></PmtId><IntrBkSttlmAmt Ccy=\"{}\">{}</IntrBkSttlmAmt><DbtrAgt><FinInstnId><BICFI>{}</BICFI></FinInstnId></DbtrAgt><CdtrAgt><FinInstnId><BICFI>{}</BICFI></FinInstnId></CdtrAgt>{}</CdtTrfTxInf></FIToFICstmrCdtTrf></Document>",
            &intent.id[..16],
            uetr,
            intent.currency,
            amount_fmt,
            self.bic_sender,
            bic_receiver,
            transport_frame
        );

        Ok(DispatchReceipt {
            gateway: GatewayType::Swift,
            external_ref: uetr,
            native_payload: pacs008,
            settled_immediately: false,
        })
    }
}

// ─── 4.3 O Adapter BRICS Pay (O Espírito): DCMS P2P (MT103 / ISO 20022) ─────

/// Mensagem estruturada DCMS (Decentralized Cross-Border Messaging System)
/// mapeando `PaymentIntent` para o padrão MT103 / `pacs.008` do BRICS Pay.
#[cfg(feature = "brics")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DcmsMessage {
    pub protocol: String,
    pub msg_type: String,
    pub uetr: String,
    pub sender_did: String,
    pub receiver_node: String,
    pub node_url: String,
    pub value_date: String,
    pub currency: String,
    pub amount: String,
    pub myc_reference_micros: u64,
    pub remittance_info: String,
    pub signer_pubkey_hex: String,
    pub signature_ed25519_hex: String,
}

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
        let dcms_tx_id = format!(
            "dcms:{}",
            hex::encode(&blake3::hash(&sig.to_bytes()).as_bytes()[..16])
        );
        let amount_fmt = format!(
            "{}.{:02}",
            intent.amount_micros / MICRO_UNIT,
            (intent.amount_micros % MICRO_UNIT) / 10_000
        );
        let value_date = intent
            .compliance_metadata
            .get("value_date")
            .and_then(|v| v.as_str())
            .unwrap_or("2026-11-20")
            .to_string();
        let (myc_reference_micros, _) = intent.myc_usdc_parity(&MonetaryPolicy::mainnet());

        let msg = DcmsMessage {
            protocol: "DCMS-P2P-v1".into(),
            msg_type: "DCMS.pacs.008.MT103".into(),
            uetr,
            sender_did: intent.sender_did.clone(),
            receiver_node: target_node.to_string(),
            node_url: self.dcms_node_url.clone(),
            value_date,
            currency: intent.currency.clone(),
            amount: amount_fmt,
            myc_reference_micros,
            remittance_info: format!("MYCELIUM:{}", &intent.id[..16]),
            signer_pubkey_hex: hex::encode(self.node_signing_key.verifying_key().as_bytes()),
            signature_ed25519_hex: hex::encode(sig.to_bytes()),
        };
        let payload = serde_json::to_string(&msg)
            .map_err(|e| GatewayError::Crypto(format!("serialize DCMS message: {e}")))?;

        Ok(DispatchReceipt {
            gateway: GatewayType::BricsPay,
            external_ref: dcms_tx_id,
            native_payload: payload,
            settled_immediately: true,
        })
    }
}

// ─── 4.4 Trilho Nativo MYC (comportamento estilo USDC, 1 MYC = 8 USDC) ───────

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
