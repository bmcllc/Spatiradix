//! Primitivos do **Mycelium Commons Protocol (MCP)**, **Mycelium Media Protocol (MMP)**
//! e **Mycelium Economic Protocol (MEP)** integrados ao Rhizome com assinatura Ed25519 estrita.
//!
//! Inclui:
//! - `CommonsProject` e `CommonsContribution` (financiamento coletivo, orçamento transparente e split contratual 100%)
//! - `ShardReplicaReceipt` (provas assinadas de retenção e integridade de chunks BLAKE3 entre nós distintos)
//! - `TipRecord` (gorjetas P2P assinadas em `SPORES` ou `P2P_COIN`)
//! - `CustomDiscoveryLens` (algoritmos de descoberta intercambiáveis assinados e propagáveis pela rede)

use crate::identity::{verify_domain_signature, SovereignKeys};
use crate::model::validate_handle;
use crate::{unix_now, RhizomeError};
use mycelium_core::{ContentId, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const DOMAIN_COMMONS_PROJECT: &str = "mycelium-rhizome/commons-project/v1";
const DOMAIN_COMMONS_CONTRIBUTION: &str = "mycelium-rhizome/commons-contribution/v1";
const DOMAIN_SHARD_RECEIPT: &str = "mycelium-rhizome/shard-receipt/v1";
const DOMAIN_TIP_RECORD: &str = "mycelium-rhizome/tip/v1";
const DOMAIN_DISCOVERY_LENS: &str = "mycelium-rhizome/lens/v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BudgetItem {
    pub item: String,
    pub cost_p2p: f64,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitContractParty {
    pub role: String,
    pub pubkey: String,
    pub name: String,
    pub split_percentage: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MilestoneItem {
    pub title: String,
    pub status: String,
    pub date: String,
}

pub fn validate_split_agreement(parties: &[SplitContractParty]) -> Result<(), RhizomeError> {
    if parties.is_empty() {
        return Err(RhizomeError::InvalidInput(
            "split_agreement deve ter ao menos um participante".into(),
        ));
    }
    let total: u32 = parties.iter().map(|p| p.split_percentage as u32).sum();
    if total != 100 {
        return Err(RhizomeError::InvalidInput(format!(
            "split_agreement deve somar exatamente 100% (atual: {total}%)"
        )));
    }
    for p in parties {
        if p.role.trim().is_empty() || p.name.trim().is_empty() {
            return Err(RhizomeError::InvalidInput(
                "participante do split_agreement precisa de papel e nome".into(),
            ));
        }
    }
    Ok(())
}

/// Projeto colaborativo do Mycelium Commons Protocol (MCP).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommonsProject {
    pub project_id: String,
    pub slug: String,
    pub title: String,
    pub summary: String,
    pub full_proposal: String,
    pub funding_goal: f64,
    pub spores_pool_allocated: u64,
    pub lead_node_id: String,
    pub lead_pubkey_hex: String,
    pub lead_handle: String,
    pub status: String,
    pub target_release_date: String,
    #[serde(default)]
    pub budget_ledger: Vec<BudgetItem>,
    #[serde(default)]
    pub split_agreement: Vec<SplitContractParty>,
    #[serde(default)]
    pub milestones: Vec<MilestoneItem>,
    pub revision: u64,
    pub updated_at: u64,
    pub signature: String,
}

impl CommonsProject {
    pub fn derive_id(lead_node_id: &str, slug: &str) -> String {
        let h = blake3::hash(
            format!("mycelium-rhizome/commons/{lead_node_id}/{slug}").as_bytes(),
        );
        format!("proj_{}", hex::encode(&h.as_bytes()[..12]))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    fn validate_fields(&self) -> Result<(), RhizomeError> {
        validate_handle(&self.slug)?;
        if self.title.trim().is_empty() || self.summary.trim().is_empty() {
            return Err(RhizomeError::InvalidInput(
                "título e resumo do projeto MCP são obrigatórios".into(),
            ));
        }
        if !self.funding_goal.is_finite() || self.funding_goal <= 0.0 {
            return Err(RhizomeError::InvalidInput(
                "meta orçamentária do projeto MCP deve ser positiva".into(),
            ));
        }
        for b in &self.budget_ledger {
            if !b.cost_p2p.is_finite() || b.cost_p2p < 0.0 {
                return Err(RhizomeError::InvalidInput(
                    "item de orçamento MCP inválido".into(),
                ));
            }
        }
        validate_split_agreement(&self.split_agreement)?;
        Ok(())
    }

    pub fn finalize_and_sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        self.slug = self.slug.trim().trim_start_matches('@').to_ascii_lowercase();
        self.validate_fields()?;
        self.lead_node_id = keys.node_id_hex();
        self.lead_pubkey_hex = keys.ed25519_pubkey_hex();
        self.project_id = Self::derive_id(&self.lead_node_id, &self.slug);
        if self.status.trim().is_empty() {
            self.status = "funding".into();
        }
        if self.target_release_date.trim().is_empty() {
            self.target_release_date = "2026-Q4".into();
        }
        if self.revision == 0 {
            self.revision = 1;
        }
        if self.updated_at == 0 {
            self.updated_at = unix_now();
        }
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_COMMONS_PROJECT, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        self.validate_fields()?;
        let expected_id = Self::derive_id(&self.lead_node_id, &self.slug);
        if self.project_id != expected_id {
            return Err(RhizomeError::Corrupted("project_id MCP divergente".into()));
        }
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.lead_node_id,
            &self.lead_pubkey_hex,
            DOMAIN_COMMONS_PROJECT,
            &bytes,
            &self.signature,
        )
    }
}

/// Contribuição comunitária assinada para um projeto MCP.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommonsContribution {
    pub contribution_id: String,
    pub project_id: String,
    pub contributor_node_id: String,
    pub contributor_pubkey_hex: String,
    pub contributor_name: String,
    pub amount_p2p: f64,
    pub spores_contributed: u64,
    pub message: String,
    pub created_at: u64,
    pub signature: String,
}

impl CommonsContribution {
    fn id_material(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.contribution_id.clear();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    fn validate_fields(&self) -> Result<(), RhizomeError> {
        if self.project_id.trim().is_empty() {
            return Err(RhizomeError::InvalidInput("project_id obrigatório".into()));
        }
        if !self.amount_p2p.is_finite() || self.amount_p2p < 0.0 {
            return Err(RhizomeError::InvalidInput(
                "amount_p2p inválido na contribuição".into(),
            ));
        }
        if self.amount_p2p == 0.0 && self.spores_contributed == 0 {
            return Err(RhizomeError::InvalidInput(
                "contribuição precisa de valor P2P ou Spores".into(),
            ));
        }
        Ok(())
    }

    pub fn finalize_and_sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        self.validate_fields()?;
        self.contributor_node_id = keys.node_id_hex();
        self.contributor_pubkey_hex = keys.ed25519_pubkey_hex();
        if self.created_at == 0 {
            self.created_at = unix_now();
        }
        let id_bytes = self.id_material()?;
        let cid_hex = hex::encode(&blake3::hash(&id_bytes).as_bytes()[..12]);
        self.contribution_id = format!("cb_{cid_hex}");
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_COMMONS_CONTRIBUTION, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        self.validate_fields()?;
        let id_bytes = self.id_material()?;
        let expected = format!(
            "cb_{}",
            hex::encode(&blake3::hash(&id_bytes).as_bytes()[..12])
        );
        if self.contribution_id != expected {
            return Err(RhizomeError::Corrupted(
                "contribution_id MCP divergente".into(),
            ));
        }
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.contributor_node_id,
            &self.contributor_pubkey_hex,
            DOMAIN_COMMONS_CONTRIBUTION,
            &bytes,
            &self.signature,
        )
    }
}

/// Recibo criptográfico assinado por um nó comprovando retenção/integridade de um shard BLAKE3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardReplicaReceipt {
    pub receipt_id: String,
    pub video_manifest_cid: String,
    pub chunk_index: u32,
    pub chunk_cid: String,
    pub node_id: String,
    pub node_pubkey_hex: String,
    pub node_handle: String,
    pub device_type: String,
    pub latency_ms: u32,
    pub sampled_hash: String,
    pub verified_at: u64,
    pub signature: String,
}

impl ShardReplicaReceipt {
    pub fn derive_id(video_manifest_cid: &str, chunk_index: u32, node_id: &str) -> String {
        let h = blake3::hash(
            format!("mycelium-rhizome/shard-rcpt/{video_manifest_cid}/{chunk_index}/{node_id}")
                .as_bytes(),
        );
        format!("rcpt_{}", hex::encode(&h.as_bytes()[..12]))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn finalize_and_sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        if self.video_manifest_cid.trim().is_empty()
            || self.chunk_cid.trim().is_empty()
            || self.sampled_hash.trim().is_empty()
        {
            return Err(RhizomeError::InvalidInput(
                "recibo de shard incompleto".into(),
            ));
        }
        self.node_id = keys.node_id_hex();
        self.node_pubkey_hex = keys.ed25519_pubkey_hex();
        self.receipt_id =
            Self::derive_id(&self.video_manifest_cid, self.chunk_index, &self.node_id);
        if self.verified_at == 0 {
            self.verified_at = unix_now();
        }
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_SHARD_RECEIPT, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        let expected_id =
            Self::derive_id(&self.video_manifest_cid, self.chunk_index, &self.node_id);
        if self.receipt_id != expected_id {
            return Err(RhizomeError::Corrupted(
                "receipt_id de shard divergente".into(),
            ));
        }
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.node_id,
            &self.node_pubkey_hex,
            DOMAIN_SHARD_RECEIPT,
            &bytes,
            &self.signature,
        )
    }
}

/// Registro assinado de gorjeta P2P direta (SPORES ou P2P_COIN).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TipRecord {
    pub tip_id: String,
    pub target_post_id: String,
    #[serde(default)]
    pub video_manifest_cid: Option<String>,
    pub recipient_node_id: String,
    pub sender_node_id: String,
    pub sender_pubkey_hex: String,
    pub sender_handle: String,
    /// `"SPORES"` | `"P2P_COIN"`
    pub asset_type: String,
    pub amount: u64,
    pub memo: String,
    #[serde(default)]
    pub ledger_tx_id: Option<String>,
    pub created_at: u64,
    pub signature: String,
}

impl TipRecord {
    fn id_material(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.tip_id.clear();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    fn validate_fields(&self) -> Result<(), RhizomeError> {
        if self.amount == 0 {
            return Err(RhizomeError::InvalidInput(
                "valor da gorjeta deve ser positivo".into(),
            ));
        }
        if !matches!(
            self.asset_type.as_str(),
            "CPX" | "SPORES" | "P2P_COIN" | "ATP" | "MYCELIA" | "ENZYMES" | "RESILIENCE" | "PLEDGE"
        ) {
            return Err(RhizomeError::InvalidInput(
                "asset_type deve ser SPORES, ATP, MYCELIA, ENZYMES, RESILIENCE, P2P_COIN ou PLEDGE".into(),
            ));
        }
        if self.recipient_node_id.trim().is_empty() {
            return Err(RhizomeError::InvalidInput(
                "recipient_node_id obrigatório".into(),
            ));
        }
        Ok(())
    }

    pub fn finalize_and_sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        self.validate_fields()?;
        self.sender_node_id = keys.node_id_hex();
        self.sender_pubkey_hex = keys.ed25519_pubkey_hex();
        if self.created_at == 0 {
            self.created_at = unix_now();
        }
        let id_bytes = self.id_material()?;
        self.tip_id = format!(
            "tip_{}",
            hex::encode(&ContentId::of(&id_bytes).0[..12])
        );
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_TIP_RECORD, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        self.validate_fields()?;
        let id_bytes = self.id_material()?;
        let expected = format!(
            "tip_{}",
            hex::encode(&ContentId::of(&id_bytes).0[..12])
        );
        if self.tip_id != expected {
            return Err(RhizomeError::Corrupted("tip_id divergente".into()));
        }
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.sender_node_id,
            &self.sender_pubkey_hex,
            DOMAIN_TIP_RECORD,
            &bytes,
            &self.signature,
        )
    }
}

/// Lente / Algoritmo de Descoberta Intercambiável criado pela comunidade e assinado por Ed25519.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomDiscoveryLens {
    pub lens_id: String,
    pub name: String,
    pub author_node_id: String,
    pub author_pubkey_hex: String,
    pub author_handle: String,
    pub description: String,
    pub weights: BTreeMap<String, f64>,
    pub created_at: u64,
    pub signature: String,
}

impl CustomDiscoveryLens {
    fn id_material(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.lens_id.clear();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    fn validate_fields(&self) -> Result<(), RhizomeError> {
        if self.name.trim().is_empty() {
            return Err(RhizomeError::InvalidInput(
                "nome da lente de descoberta é obrigatório".into(),
            ));
        }
        for (k, v) in &self.weights {
            if k.trim().is_empty() || !v.is_finite() || *v < 0.0 || *v > 10.0 {
                return Err(RhizomeError::InvalidInput(format!(
                    "peso inválido na lente para '{k}'"
                )));
            }
        }
        Ok(())
    }

    pub fn finalize_and_sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        self.validate_fields()?;
        self.author_node_id = keys.node_id_hex();
        self.author_pubkey_hex = keys.ed25519_pubkey_hex();
        if self.created_at == 0 {
            self.created_at = unix_now();
        }
        let id_bytes = self.id_material()?;
        self.lens_id = format!(
            "lens_{}",
            hex::encode(&blake3::hash(&id_bytes).as_bytes()[..10])
        );
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_DISCOVERY_LENS, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        self.validate_fields()?;
        let id_bytes = self.id_material()?;
        let expected = format!(
            "lens_{}",
            hex::encode(&blake3::hash(&id_bytes).as_bytes()[..10])
        );
        if self.lens_id != expected {
            return Err(RhizomeError::Corrupted("lens_id divergente".into()));
        }
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.author_node_id,
            &self.author_pubkey_hex,
            DOMAIN_DISCOVERY_LENS,
            &bytes,
            &self.signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commons_project_split_validation_and_signing() {
        let keys = SovereignKeys::from_seed([0x41; 32]).unwrap();
        let mut bad = CommonsProject {
            project_id: String::new(),
            slug: "doc-floresta".into(),
            title: "Doc Floresta".into(),
            summary: "Resumo".into(),
            full_proposal: "Proposta completa".into(),
            funding_goal: 2000.0,
            spores_pool_allocated: 1000,
            lead_node_id: String::new(),
            lead_pubkey_hex: String::new(),
            lead_handle: "bruno".into(),
            status: "funding".into(),
            target_release_date: "2026-Q4".into(),
            budget_ledger: vec![BudgetItem {
                item: "Captação".into(),
                cost_p2p: 2000.0,
                status: "Alocado".into(),
            }],
            split_agreement: vec![SplitContractParty {
                role: "Direção".into(),
                pubkey: keys.ed25519_pubkey_hex(),
                name: "Bruno".into(),
                split_percentage: 80,
            }],
            milestones: vec![MilestoneItem {
                title: "Corte".into(),
                status: "pending".into(),
                date: "2026-12".into(),
            }],
            revision: 1,
            updated_at: 1_760_000_000,
            signature: String::new(),
        };
        assert!(bad.finalize_and_sign(&keys).is_err());

        bad.split_agreement.push(SplitContractParty {
            role: "Seeders".into(),
            pubkey: "mycelium:pool".into(),
            name: "Nós P2P".into(),
            split_percentage: 20,
        });
        bad.finalize_and_sign(&keys).unwrap();
        bad.verify().unwrap();

        let mut tampered = bad.clone();
        tampered.funding_goal = 99999.0;
        assert!(tampered.verify().is_err());

        let mut contrib = CommonsContribution {
            contribution_id: String::new(),
            project_id: bad.project_id.clone(),
            contributor_node_id: String::new(),
            contributor_pubkey_hex: String::new(),
            contributor_name: "Alice".into(),
            amount_p2p: 150.0,
            spores_contributed: 50,
            message: "Força!".into(),
            created_at: 1_760_000_100,
            signature: String::new(),
        };
        contrib.finalize_and_sign(&keys).unwrap();
        contrib.verify().unwrap();
    }

    #[test]
    fn shard_receipt_tip_and_custom_lens_signing_and_tamper_rejection() {
        let keys = SovereignKeys::from_seed([0x55; 32]).unwrap();
        let mut rcpt = ShardReplicaReceipt {
            receipt_id: String::new(),
            video_manifest_cid: "Qm01".repeat(16) + "ab",
            chunk_index: 0,
            chunk_cid: "Qm02".repeat(16) + "cd",
            node_id: String::new(),
            node_pubkey_hex: String::new(),
            node_handle: "bruno".into(),
            device_type: "mobile".into(),
            latency_ms: 14,
            sampled_hash: "abcd".into(),
            verified_at: 1_760_000_200,
            signature: String::new(),
        };
        rcpt.finalize_and_sign(&keys).unwrap();
        rcpt.verify().unwrap();

        let mut rcpt_bad = rcpt.clone();
        rcpt_bad.sampled_hash = "dead".into();
        assert!(rcpt_bad.verify().is_err());

        let mut tip = TipRecord {
            tip_id: String::new(),
            target_post_id: "post_1".into(),
            video_manifest_cid: Some("Qm".into()),
            recipient_node_id: "node_b".into(),
            sender_node_id: String::new(),
            sender_pubkey_hex: String::new(),
            sender_handle: "bruno".into(),
            asset_type: "SPORES".into(),
            amount: 25,
            memo: "Excelente vídeo".into(),
            ledger_tx_id: None,
            created_at: 1_760_000_300,
            signature: String::new(),
        };
        tip.finalize_and_sign(&keys).unwrap();
        tip.verify().unwrap();

        let mut weights = BTreeMap::new();
        weights.insert("replication_health".into(), 0.5);
        weights.insert("commons_weight".into(), 0.5);
        let mut lens = CustomDiscoveryLens {
            lens_id: String::new(),
            name: "Cinema Livre".into(),
            author_node_id: String::new(),
            author_pubkey_hex: String::new(),
            author_handle: "bruno".into(),
            description: "Prioriza MCP e saúde".into(),
            weights,
            created_at: 1_760_000_400,
            signature: String::new(),
        };
        lens.finalize_and_sign(&keys).unwrap();
        lens.verify().unwrap();
    }
}
