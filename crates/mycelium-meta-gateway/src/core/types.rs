//! Livro III (Levítico): tipos de domínio e Máquina de Estados Finitos (FSM)
//! imutável do Supreme Meta-Gateway Mycelium.
//!
//! O MYC atua como ativo de liquidação estilo USDC (`1 MYC = 8 USDC` via
//! `mycelium_mint::MonetaryPolicy`), com precisão inteira em micro-unidades
//! (`1e-6`, compatível com `mycelium_bank::Asset::Myc` e `Asset::Usdc`).

use crate::error::GatewayError;
use mycelium_mint::{MonetaryPolicy, DEFAULT_USDC_PER_MYC};
use serde::{Deserialize, Serialize};

/// 1 unidade inteira em micro-unidades (6 casas decimais, padrão USDC / mycelium-bank).
pub const MICRO_UNIT: u64 = 1_000_000;

/// Pilares suportados pelo Meta-Gateway + trilho nativo MYC (comportamento estilo USDC).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum GatewayType {
    /// O Sangue: liquidação doméstica instantânea (DICT / EMV QR / mTLS ICP-Brasil).
    Pix,
    /// O Esqueleto: espinha dorsal global ISO 20022 (pacs.008 / CSP A1, A3, A4).
    Swift,
    /// O Espírito: mensageria cross-border descentralizada (DCMS P2P).
    BricsPay,
    /// Trilho nativo soberano onde o MYC se comporta como stable-settlement estilo USDC (1 MYC = 8 USDC).
    MycRail,
}

impl GatewayType {
    /// Infere o gateway pelo prefixo do destinatário (`pix:`, `swift:`, `brics:`, `myc:`).
    pub fn infer_from_receiver(receiver_id: &str) -> Option<Self> {
        let lower = receiver_id.trim().to_ascii_lowercase();
        if lower.starts_with("pix:") {
            Some(Self::Pix)
        } else if lower.starts_with("swift:") {
            Some(Self::Swift)
        } else if lower.starts_with("brics:") || lower.starts_with("dcms:") {
            Some(Self::BricsPay)
        } else if lower.starts_with("myc:") || lower.starts_with("usdc:") {
            Some(Self::MycRail)
        } else {
            None
        }
    }
}

/// Pegada arquitetural completa da árvore de decisão SWIFT CSP (A1, A2, A3, A4, B).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SwiftCspType {
    /// A1: Dono da infraestrutura de mensageria (MI) e comunicação (CI).
    A1,
    /// A2: Dono da Messaging Interface (MI), com Communication Interface (CI) via Service Bureau.
    A2,
    /// A3: SWIFT Connector / API Gateway direto.
    A3,
    /// A4: Customer Connector falando via Middleware Server local (MQ / FileAct).
    A4,
    /// B: Zero footprint local (acesso apenas via Service Bureau / portal com MFA).
    B,
}

/// Máquina de Estados Finitos (FSM) auditável de uma intenção de pagamento.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TransactionState {
    /// Criado localmente no nó Mycelium.
    Initiated,
    /// Assinado com Ed25519 + encapsulamento PQC (ML-KEM-1024) + âncora causal `hash_chronicle`.
    CryptographicSeal {
        chronicle_hash: String,
        pqc_ciphertext_len: usize,
        signature_hex: String,
        pedersen_commit_hex: String,
    },
    /// Despachado para o gateway externo ou trilho nativo aguardando confirmação.
    AwaitingGatewayResponse {
        external_ref: String,
    },
    /// Liquidado e contabilizado na paridade de referência MYC ↔ USDC (1 MYC = 8 USDC).
    Settled {
        external_tx_id: String,
        myc_micros: u64,
        usdc_equivalent_micros: u64,
    },
    /// Falha explícita com código e motivo.
    Failed {
        code: u32,
        reason: String,
    },
    /// Estornado após liquidação ou falha parcial.
    Refunded {
        reason: String,
    },
}

impl TransactionState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Initiated => "initiated",
            Self::CryptographicSeal { .. } => "cryptographic_seal",
            Self::AwaitingGatewayResponse { .. } => "awaiting_gateway_response",
            Self::Settled { .. } => "settled",
            Self::Failed { .. } => "failed",
            Self::Refunded { .. } => "refunded",
        }
    }

    /// Garante que a FSM nunca pule etapas obrigatórias (ex.: selo criptográfico antes do despacho).
    pub fn can_transition_to(&self, next: &Self) -> bool {
        matches!(
            (self, next),
            (Self::Initiated, Self::CryptographicSeal { .. })
                | (Self::Initiated, Self::Failed { .. })
                | (
                    Self::CryptographicSeal { .. },
                    Self::AwaitingGatewayResponse { .. }
                )
                | (Self::CryptographicSeal { .. }, Self::Failed { .. })
                | (Self::AwaitingGatewayResponse { .. }, Self::Settled { .. })
                | (Self::AwaitingGatewayResponse { .. }, Self::Failed { .. })
                | (Self::Settled { .. }, Self::Refunded { .. })
        )
    }
}

/// Recibo padronizado retornado por qualquer adaptador (Pix, SWIFT, BRICS Pay ou MYC Rail).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DispatchReceipt {
    pub gateway: GatewayType,
    pub external_ref: String,
    pub native_payload: String,
    pub settled_immediately: bool,
}

/// Intenção soberana de pagamento unificada no Mycelium Meta-Gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentIntent {
    /// Identificador determinístico hex (32 bytes BLAKE3).
    pub id: String,
    pub gateway: GatewayType,
    /// Valor em micro-unidades (6 casas decimais, ex.: 10_000_000 = 10.000000).
    pub amount_micros: u64,
    /// Moeda de origem/liquidação (`MYC`, `USDC`, `BRL`, `USD`, etc.).
    pub currency: String,
    /// Identidade descentralizada no Mycelium (`did:mycelium:...` ou GhostID).
    pub sender_did: String,
    /// Destinatário qualificado (`pix:chave`, `swift:BIC`, `brics:node`, `myc:node_id`).
    pub receiver_id: String,
    /// Estado atual na FSM.
    pub state: TransactionState,
    /// Metadados de Compliance-as-Code (`swift_csp_compliant`, `hour_utc`, `secure_zone_log_id`, etc.).
    pub compliance_metadata: serde_json::Value,
}

impl PaymentIntent {
    /// Cria uma nova intenção em estado `Initiated` com ID determinístico BLAKE3.
    pub fn new(
        gateway: GatewayType,
        amount_micros: u64,
        currency: impl Into<String>,
        sender_did: impl Into<String>,
        receiver_id: impl Into<String>,
        compliance_metadata: serde_json::Value,
    ) -> Result<Self, GatewayError> {
        if amount_micros == 0 {
            return Err(GatewayError::InvalidAmount);
        }
        let currency = currency.into().to_ascii_uppercase();
        let sender_did = sender_did.into();
        let receiver_id = receiver_id.into();

        let mut h = blake3::Hasher::new();
        h.update(b"mycelium-meta-gateway-intent-v1:");
        h.update(format!("{gateway:?}").as_bytes());
        h.update(&amount_micros.to_be_bytes());
        h.update(currency.as_bytes());
        h.update(sender_did.as_bytes());
        h.update(receiver_id.as_bytes());
        let id = hex::encode(h.finalize().as_bytes());

        Ok(Self {
            id,
            gateway,
            amount_micros,
            currency,
            sender_did,
            receiver_id,
            state: TransactionState::Initiated,
            compliance_metadata,
        })
    }

    /// Auto-roteia criando a intenção a partir do prefixo do `receiver_id`.
    pub fn auto_route(
        amount_micros: u64,
        currency: impl Into<String>,
        sender_did: impl Into<String>,
        receiver_id: impl Into<String>,
        compliance_metadata: serde_json::Value,
    ) -> Result<Self, GatewayError> {
        let receiver = receiver_id.into();
        let gateway = GatewayType::infer_from_receiver(&receiver)
            .ok_or_else(|| GatewayError::InvalidTarget(receiver.clone()))?;
        Self::new(
            gateway,
            amount_micros,
            currency,
            sender_did,
            receiver,
            compliance_metadata,
        )
    }

    /// Aplica uma transição verificada na FSM.
    pub fn transition_to(&mut self, next: TransactionState) -> Result<(), GatewayError> {
        if !self.state.can_transition_to(&next) {
            return Err(GatewayError::InvalidTransition {
                from: self.state.label(),
                to: next.label(),
            });
        }
        self.state = next;
        Ok(())
    }

    /// Calcula `(myc_micros, usdc_equivalent_micros)` sob a paridade de referência (`1 MYC = 8 USDC`).
    pub fn myc_usdc_parity(&self, policy: &MonetaryPolicy) -> (u64, u64) {
        let rate = policy.usdc_per_myc.max(DEFAULT_USDC_PER_MYC);
        match self.currency.as_str() {
            "MYC" => (
                self.amount_micros,
                self.amount_micros.saturating_mul(rate),
            ),
            "USDC" | "USD" => (self.amount_micros / rate, self.amount_micros),
            _ => (self.amount_micros / rate, self.amount_micros),
        }
    }

    /// Bytes canônicos usados para assinatura Ed25519 e âncora causal `hash_chronicle`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(self.id.as_bytes());
        out.extend_from_slice(&self.amount_micros.to_be_bytes());
        out.extend_from_slice(self.currency.as_bytes());
        out.extend_from_slice(self.sender_did.as_bytes());
        out.extend_from_slice(self.receiver_id.as_bytes());
        out
    }
}
