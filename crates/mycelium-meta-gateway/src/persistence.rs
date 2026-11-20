//! Persistência imutável de `PaymentIntent` no `SporeBank` (`giggs::Plot`).
//!
//! Cada transição relevante da FSM (`CryptographicSeal`, `AwaitingGatewayResponse`,
//! `Settled`, `Failed`, `Refunded`) é gravada como um `Plot` marcado `[private]`
//! (impedindo vazamento em claro para a DHT pública) e encadeado ao `ContentId`
//! anterior do mesmo pagamento, garantindo recuperação completa após queda do nó.

use crate::core::PaymentIntent;
use crate::error::GatewayError;
use giggs::{Leaf, Plot};
use mycelium_core::{ContentId, NodeId};
use mycelium_sporebank::SporeBank;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Default, Serialize, Deserialize)]
struct GatewayIntentIndex {
    /// `intent_id -> último ContentId no SporeBank`
    by_intent: HashMap<String, ContentId>,
    /// `external_ref (txid / UETR / dcms_tx_id) -> intent_id`
    by_external_ref: HashMap<String, String>,
}

/// Camada de persistência de transações do Meta-Gateway sobre `SporeBank`.
pub struct SporebankIntentStore {
    author: NodeId,
    index_path: PathBuf,
    bank: SporeBank,
    index: GatewayIntentIndex,
}

impl SporebankIntentStore {
    /// Abre (ou cria) o `SporeBank` e o índice de intenções em `home`.
    pub fn open(home: impl AsRef<Path>, author: NodeId) -> Result<Self, GatewayError> {
        let bank = SporeBank::open(&home)
            .map_err(|e| GatewayError::Crypto(format!("sporebank open: {e}")))?;
        let index_path = home.as_ref().join("meta_gateway_index.json");
        let index: GatewayIntentIndex = if index_path.exists() {
            let bytes = std::fs::read(&index_path)
                .map_err(|e| GatewayError::Crypto(format!("read gateway index: {e}")))?;
            serde_json::from_slice(&bytes)
                .map_err(|e| GatewayError::Crypto(format!("parse gateway index: {e}")))?
        } else {
            GatewayIntentIndex::default()
        };
        Ok(Self {
            author,
            index_path,
            bank,
            index,
        })
    }

    /// Grava o estado atual da intenção como um `Plot` privado no `SporeBank`,
    /// encadeando ao `ContentId` anterior dessa mesma intenção.
    pub fn persist_intent(
        &mut self,
        intent: &PaymentIntent,
        external_ref: Option<&str>,
    ) -> Result<ContentId, GatewayError> {
        let parents = self
            .index
            .by_intent
            .get(&intent.id)
            .copied()
            .into_iter()
            .collect();
        let content = serde_json::to_vec_pretty(intent)
            .map_err(|e| GatewayError::Crypto(format!("serialize intent: {e}")))?;
        let plot = Plot {
            author: self.author,
            message: format!(
                "[private] meta-gateway:{}:{}",
                intent.id,
                intent.state.label()
            ),
            parents,
            leaves: vec![Leaf {
                path: format!("intent/{}.json", intent.id),
                content,
            }],
        };
        let cid = self
            .bank
            .deposit(plot)
            .map_err(|e| GatewayError::Crypto(format!("sporebank deposit: {e}")))?;

        self.index.by_intent.insert(intent.id.clone(), cid);
        if let Some(ext) = external_ref {
            self.index
                .by_external_ref
                .insert(ext.to_string(), intent.id.clone());
        }
        self.save_index()?;
        Ok(cid)
    }

    /// Recupera a versão mais recente de um `PaymentIntent` pelo seu `intent_id`.
    pub fn load_by_id(&self, intent_id: &str) -> Result<Option<PaymentIntent>, GatewayError> {
        let Some(cid) = self.index.by_intent.get(intent_id) else {
            return Ok(None);
        };
        let Some(plot) = self.bank.recall(cid) else {
            return Ok(None);
        };
        let Some(leaf) = plot.leaves.first() else {
            return Ok(None);
        };
        let intent: PaymentIntent = serde_json::from_slice(&leaf.content)
            .map_err(|e| GatewayError::Crypto(format!("decode intent from sporebank: {e}")))?;
        Ok(Some(intent))
    }

    /// Recupera um `PaymentIntent` a partir da referência externa (`txid`, `UETR` ou `dcms_tx_id`).
    pub fn load_by_external_ref(
        &self,
        external_ref: &str,
    ) -> Result<Option<PaymentIntent>, GatewayError> {
        let Some(intent_id) = self.index.by_external_ref.get(external_ref) else {
            return Ok(None);
        };
        self.load_by_id(intent_id)
    }

    /// Retorna o último `ContentId` gravado no `SporeBank` para um `intent_id`.
    pub fn latest_cid(&self, intent_id: &str) -> Option<ContentId> {
        self.index.by_intent.get(intent_id).copied()
    }

    fn save_index(&self) -> Result<(), GatewayError> {
        let bytes = serde_json::to_vec_pretty(&self.index)
            .map_err(|e| GatewayError::Crypto(format!("serialize gateway index: {e}")))?;
        std::fs::write(&self.index_path, bytes)
            .map_err(|e| GatewayError::Crypto(format!("write gateway index: {e}")))?;
        Ok(())
    }
}
