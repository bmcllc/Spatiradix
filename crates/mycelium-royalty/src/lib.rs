//! # mycelium-royalty
//!
//! Motor de royalties em **CPX** (moeda unificada da plataforma Mycelium) para criadores
//! de conteúdo, com splits determinísticos em basis points (`10_000 bps = 100%`),
//! alocação de taxa de reserva (`reserve_fee_bps`, padrão 5% = `500 bps`) para o
//! fundo de reserva `mycelium-mint` / `Enzymes`, assinatura estrita Ed25519 e
//! projeção verificável em átomos `Isotope`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use isotope::Atom;
use mycelium_core::{ContentId, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// 100% em basis points.
pub const BPS_DENOMINATOR: u64 = 10_000;
/// Taxa padrão de reserva / manutenção da malha (5% = 500 bps).
pub const DEFAULT_RESERVE_FEE_BPS: u64 = 500;
/// Limite superior de segurança para a taxa de reserva (25% = 2500 bps).
pub const MAX_RESERVE_FEE_BPS: u64 = 2_500;

const ROYALTY_CONTRACT_DOMAIN: &[u8] = b"mycelium/royalty/contract/v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoyaltyError {
    #[error("contrato de royalty exige ao menos um beneficiário")]
    EmptySplits,
    #[error("soma dos splits ({got} bps) deve ser exatamente 10000 bps (100%)")]
    InvalidSplitSum { got: u64 },
    #[error("beneficiário com share_bps zero não é permitido: {0}")]
    ZeroShare(String),
    #[error("taxa de reserva ({0} bps) excede o máximo permitido ({MAX_RESERVE_FEE_BPS} bps)")]
    ReserveFeeTooHigh(u64),
    #[error("chave pública Ed25519 inválida ou incompatível com creator_node_id")]
    KeyMismatch,
    #[error("assinatura Ed25519 do contrato de royalty inválida")]
    BadSignature,
    #[error("valor bruto de pagamento CPX deve ser maior que zero")]
    ZeroAmount,
    #[error("contrato de royalty não encontrado para o conteúdo {0}")]
    ContractNotFound(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoyaltySplit {
    pub beneficiary_id: String,
    #[serde(default)]
    pub ghost_pubkey_hex: Option<String>,
    pub role: String,
    pub share_bps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoyaltyContract {
    pub contract_id: String,
    pub content_id: String,
    pub creator_node_id: NodeId,
    pub creator_pubkey_hex: String,
    #[serde(default)]
    pub creator_ghost_pubkey_hex: Option<String>,
    pub license: String,
    /// Moeda canônica de liquidação (padrão `"CPX"`).
    pub currency: String,
    /// Taxa encaminhada à reserva `mycelium-mint` / `Enzymes` antes do split dos criadores.
    pub reserve_fee_bps: u64,
    pub splits: Vec<RoyaltySplit>,
    pub created_at: u64,
    pub signature_hex: String,
}

impl RoyaltyContract {
    #[allow(clippy::too_many_arguments)]
    pub fn sign_new(
        content_id: impl Into<String>,
        creator_key: &SigningKey,
        creator_ghost_pubkey_hex: Option<String>,
        license: impl Into<String>,
        reserve_fee_bps: u64,
        splits: Vec<RoyaltySplit>,
        created_at: u64,
    ) -> Result<Self, RoyaltyError> {
        let content_id = content_id.into();
        let license = license.into();
        let pub_bytes = creator_key.verifying_key().to_bytes();
        let creator_node_id = NodeId::derive(&pub_bytes);
        let creator_pubkey_hex = hex::encode(pub_bytes);

        let mut contract = Self {
            contract_id: String::new(),
            content_id,
            creator_node_id,
            creator_pubkey_hex,
            creator_ghost_pubkey_hex,
            license,
            currency: "CPX".to_string(),
            reserve_fee_bps,
            splits,
            created_at,
            signature_hex: String::new(),
        };
        contract.validate_rules()?;
        let canonical = contract.canonical_bytes();
        contract.contract_id = format!(
            "roy-{}",
            &blake3::hash(&canonical).to_hex()[..24]
        );
        let sig = creator_key.sign(&canonical);
        contract.signature_hex = hex::encode(sig.to_bytes());
        Ok(contract)
    }

    pub fn validate_rules(&self) -> Result<(), RoyaltyError> {
        if self.splits.is_empty() {
            return Err(RoyaltyError::EmptySplits);
        }
        if self.reserve_fee_bps > MAX_RESERVE_FEE_BPS {
            return Err(RoyaltyError::ReserveFeeTooHigh(self.reserve_fee_bps));
        }
        let mut total = 0u64;
        for s in &self.splits {
            if s.share_bps == 0 {
                return Err(RoyaltyError::ZeroShare(s.beneficiary_id.clone()));
            }
            total = total.saturating_add(s.share_bps);
        }
        if total != BPS_DENOMINATOR {
            return Err(RoyaltyError::InvalidSplitSum { got: total });
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let payload = serde_json::json!({
            "content_id": self.content_id,
            "creator_node_id": self.creator_node_id.to_string(),
            "creator_pubkey_hex": self.creator_pubkey_hex,
            "creator_ghost_pubkey_hex": self.creator_ghost_pubkey_hex,
            "license": self.license,
            "currency": self.currency,
            "reserve_fee_bps": self.reserve_fee_bps,
            "splits": self.splits,
            "created_at": self.created_at,
        });
        let raw = serde_json::to_vec(&payload).unwrap_or_default();
        let mut out = Vec::with_capacity(ROYALTY_CONTRACT_DOMAIN.len() + 1 + raw.len());
        out.extend_from_slice(ROYALTY_CONTRACT_DOMAIN);
        out.push(0);
        out.extend_from_slice(&raw);
        out
    }

    /// Valida regras econômicas, derivação do `creator_node_id` e assinatura Ed25519.
    pub fn verify_strict(&self) -> Result<(), RoyaltyError> {
        self.validate_rules()?;
        let pub_bytes: [u8; 32] = hex::decode(&self.creator_pubkey_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(RoyaltyError::KeyMismatch)?;
        if NodeId::derive(&pub_bytes) != self.creator_node_id {
            return Err(RoyaltyError::KeyMismatch);
        }
        let vk = VerifyingKey::from_bytes(&pub_bytes).map_err(|_| RoyaltyError::KeyMismatch)?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(RoyaltyError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        let canonical = self.canonical_bytes();
        vk.verify(&canonical, &sig)
            .map_err(|_| RoyaltyError::BadSignature)?;
        Ok(())
    }

    /// Chave canônica no anel `Isotope`.
    pub fn isotope_key(&self) -> String {
        format!("royalty/license/{}", self.content_id)
    }

    /// Projeta a licença de royalty como `isotope::Atom` para replicação CRDT na malha.
    pub fn to_isotope_atom(&self) -> Atom {
        let value = serde_json::to_vec(self).unwrap_or_default();
        Atom {
            value,
            clock: self.created_at,
        }
    }

    pub fn from_isotope_atom(atom: &Atom) -> Result<Self, RoyaltyError> {
        let contract: Self =
            serde_json::from_slice(&atom.value).map_err(|_| RoyaltyError::BadSignature)?;
        contract.verify_strict()?;
        Ok(contract)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoyaltyAllocation {
    pub beneficiary_id: String,
    #[serde(default)]
    pub ghost_pubkey_hex: Option<String>,
    pub role: String,
    pub share_bps: u64,
    pub cpx_micros: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoyaltyDistribution {
    pub payout_id: String,
    pub contract_id: String,
    pub content_id: String,
    pub currency: String,
    pub payer_id: String,
    #[serde(default)]
    pub payer_ghost_pubkey_hex: Option<String>,
    pub gross_cpx_micros: i64,
    pub reserve_fee_cpx_micros: i64,
    pub net_creators_cpx_micros: i64,
    pub allocations: Vec<RoyaltyAllocation>,
    pub memo: String,
    pub created_at: u64,
    pub receipt_hash: String,
}

/// Motor determinístico de contratos e liquidações de royalty em CPX.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RoyaltyEngine {
    pub contracts: BTreeMap<String, RoyaltyContract>,
    pub distributions: Vec<RoyaltyDistribution>,
    pub total_gross_cpx_micros: i64,
    pub total_reserve_fee_cpx_micros: i64,
}

impl RoyaltyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_contract(&mut self, contract: RoyaltyContract) -> Result<(), RoyaltyError> {
        contract.verify_strict()?;
        self.contracts
            .insert(contract.content_id.clone(), contract);
        Ok(())
    }

    pub fn get_contract(&self, content_id: &str) -> Option<&RoyaltyContract> {
        self.contracts.get(content_id)
    }

    /// Calcula e registra a distribuição exata de `gross_cpx_micros` em CPX
    /// preservando conservação inteira: `sum(allocations) + reserve_fee == gross_cpx_micros`.
    pub fn distribute_cpx(
        &mut self,
        content_id: &str,
        gross_cpx_micros: i64,
        payer_id: impl Into<String>,
        payer_ghost_pubkey_hex: Option<String>,
        memo: impl Into<String>,
        now_unix: u64,
    ) -> Result<RoyaltyDistribution, RoyaltyError> {
        if gross_cpx_micros <= 0 {
            return Err(RoyaltyError::ZeroAmount);
        }
        let contract = self
            .contracts
            .get(content_id)
            .ok_or_else(|| RoyaltyError::ContractNotFound(content_id.to_string()))?
            .clone();
        contract.verify_strict()?;

        let gross = gross_cpx_micros as u128;
        let reserve_fee = (gross * contract.reserve_fee_bps as u128 / BPS_DENOMINATOR as u128) as i64;
        let net_creators = gross_cpx_micros - reserve_fee;

        let mut allocations = Vec::with_capacity(contract.splits.len());
        let mut allocated_sum = 0i64;
        for split in &contract.splits {
            let share = (net_creators as u128 * split.share_bps as u128 / BPS_DENOMINATOR as u128) as i64;
            allocated_sum += share;
            allocations.push(RoyaltyAllocation {
                beneficiary_id: split.beneficiary_id.clone(),
                ghost_pubkey_hex: split.ghost_pubkey_hex.clone(),
                role: split.role.clone(),
                share_bps: split.share_bps,
                cpx_micros: share,
            });
        }
        // Resto de divisão inteira vai integralmente ao criador principal (índice 0)
        // garantindo conservação estrita sem perda de 1 micro-CPX.
        let remainder = net_creators - allocated_sum;
        if remainder != 0 {
            if let Some(primary) = allocations.first_mut() {
                primary.cpx_micros += remainder;
            }
        }

        let payer_id = payer_id.into();
        let memo = memo.into();
        let mut h = blake3::Hasher::new();
        h.update(b"mycelium/royalty/payout/v1");
        h.update(contract.contract_id.as_bytes());
        h.update(content_id.as_bytes());
        h.update(payer_id.as_bytes());
        h.update(&gross_cpx_micros.to_le_bytes());
        h.update(&now_unix.to_le_bytes());
        h.update(&(self.distributions.len() as u64).to_le_bytes());
        let receipt_hash = h.finalize().to_hex().to_string();
        let payout_id = format!("roypay-{}", &receipt_hash[..20]);

        let dist = RoyaltyDistribution {
            payout_id,
            contract_id: contract.contract_id,
            content_id: content_id.to_string(),
            currency: "CPX".to_string(),
            payer_id,
            payer_ghost_pubkey_hex,
            gross_cpx_micros,
            reserve_fee_cpx_micros: reserve_fee,
            net_creators_cpx_micros: net_creators,
            allocations,
            memo,
            created_at: now_unix,
            receipt_hash,
        };

        self.total_gross_cpx_micros += gross_cpx_micros;
        self.total_reserve_fee_cpx_micros += reserve_fee;
        self.distributions.push(dist.clone());
        Ok(dist)
    }
}

/// Deriva um `ContentId` canônico para contratos externos sem CID prévio.
pub fn royalty_content_id(label: &str) -> ContentId {
    ContentId::of(label.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    #[test]
    fn signs_verifies_distributes_cpx_with_exact_conservation_and_isotope_atom() {
        let creator_sk = key(11);
        let cid = royalty_content_id("video-demo-cpx").to_string();
        let contract = RoyaltyContract::sign_new(
            cid.clone(),
            &creator_sk,
            Some("aa".repeat(32)),
            "CC-BY-4.0",
            DEFAULT_RESERVE_FEE_BPS,
            vec![
                RoyaltySplit {
                    beneficiary_id: "creator-main".into(),
                    ghost_pubkey_hex: Some("aa".repeat(32)),
                    role: "Direção & Roteiro".into(),
                    share_bps: 7_000,
                },
                RoyaltySplit {
                    beneficiary_id: "editor-1".into(),
                    ghost_pubkey_hex: Some("bb".repeat(32)),
                    role: "Edição".into(),
                    share_bps: 2_000,
                },
                RoyaltySplit {
                    beneficiary_id: "seeder-pool".into(),
                    ghost_pubkey_hex: None,
                    role: "Seeders P2P".into(),
                    share_bps: 1_000,
                },
            ],
            1_700_000_000,
        )
        .expect("contrato válido");

        contract.verify_strict().expect("assinatura válida");

        // Roundtrip em Isotope Atom
        let atom = contract.to_isotope_atom();
        let restored = RoyaltyContract::from_isotope_atom(&atom).expect("atom válido");
        assert_eq!(restored, contract);

        // Distribuição com valor ímpar (1_000_003 micro-CPX) valida conservação inteira
        let mut engine = RoyaltyEngine::new();
        engine.register_contract(contract).unwrap();
        let dist = engine
            .distribute_cpx(
                &cid,
                1_000_003,
                "fan-1",
                Some("cc".repeat(32)),
                "Gorjeta CPX",
                1_700_000_010,
            )
            .expect("distribuição OK");

        assert_eq!(dist.currency, "CPX");
        assert_eq!(dist.reserve_fee_cpx_micros, 50_000); // 5% de 1_000_003 = 50_000
        let alloc_total: i64 = dist.allocations.iter().map(|a| a.cpx_micros).sum();
        assert_eq!(alloc_total + dist.reserve_fee_cpx_micros, 1_000_003);
        assert_eq!(engine.total_gross_cpx_micros, 1_000_003);
        assert_eq!(engine.total_reserve_fee_cpx_micros, 50_000);
    }

    #[test]
    fn rejects_invalid_split_sum_and_tampered_contract() {
        let creator_sk = key(22);
        let bad = RoyaltyContract::sign_new(
            "cid-bad",
            &creator_sk,
            None,
            "CC-BY-4.0",
            500,
            vec![RoyaltySplit {
                beneficiary_id: "a".into(),
                ghost_pubkey_hex: None,
                role: "Autor".into(),
                share_bps: 9_999,
            }],
            1_700_000_000,
        );
        assert_eq!(bad.unwrap_err(), RoyaltyError::InvalidSplitSum { got: 9_999 });

        let mut good = RoyaltyContract::sign_new(
            "cid-ok",
            &creator_sk,
            None,
            "CC-BY-4.0",
            500,
            vec![RoyaltySplit {
                beneficiary_id: "a".into(),
                ghost_pubkey_hex: None,
                role: "Autor".into(),
                share_bps: 10_000,
            }],
            1_700_000_000,
        )
        .unwrap();
        good.license = "ALL-RIGHTS-TAMPERED".into();
        assert_eq!(good.verify_strict().unwrap_err(), RoyaltyError::BadSignature);
    }
}
