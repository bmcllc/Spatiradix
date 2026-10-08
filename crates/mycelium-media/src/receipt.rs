//! # mycelium-media: recibos e provas criptográficas de contribuição
//!
//! Implementa Proof of Delivery, Proof of Storage e Proof of Relay para evitar farming
//! e permitir que a atribuição de Spores corresponda a bytes efetivamente entregues e retidos.

use mycelium_core::ContentId;
use serde::{Deserialize, Serialize};

/// Recibo assinado de entrega de fragmento (Proof of Delivery).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfDelivery {
    pub content_id: ContentId,
    pub chunk_index: u32,
    pub byte_size: usize,
    pub host_node: String,
    pub viewer_node: String,
    pub timestamp_unix: u64,
    pub nonce: u64,
    pub viewer_signature: String,
    pub host_signature: String,
}

impl ProofOfDelivery {
    pub fn payload_to_sign(&self) -> String {
        format!(
            "deliver:{}:{}:{}:{}:{}:{}",
            self.content_id, self.chunk_index, self.byte_size, self.host_node, self.viewer_node, self.nonce
        )
    }

    pub fn compute_receipt_id(&self) -> String {
        let hash = blake3::hash(self.payload_to_sign().as_bytes());
        format!("pod_{}", hex::encode(&hash.as_bytes()[..12]))
    }
}

/// Prova periódica de posse/retenção de dados (Proof of Storage).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfStorage {
    pub content_id: ContentId,
    pub host_node: String,
    pub challenge_nonce: u64,
    pub challenge_offset: u64,
    pub sampled_hash: String,
    pub timestamp_unix: u64,
    pub signature: String,
}

impl ProofOfStorage {
    pub fn create_challenge_response(
        content_id: ContentId,
        host_node: &str,
        chunk_data: &[u8],
        challenge_nonce: u64,
    ) -> Self {
        let offset = if chunk_data.is_empty() {
            0
        } else {
            (challenge_nonce as usize % chunk_data.len()) as u64
        };

        let sample_len = std::cmp::min(64, chunk_data.len().saturating_sub(offset as usize));
        let slice = &chunk_data[offset as usize..offset as usize + sample_len];
        let sampled_hash = hex::encode(blake3::hash(slice).as_bytes());

        ProofOfStorage {
            content_id,
            host_node: host_node.to_string(),
            challenge_nonce,
            challenge_offset: offset,
            sampled_hash,
            timestamp_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            signature: String::new(),
        }
    }
}

/// Prova de retransmissão de tráfego entre pares (Proof of Relay).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofOfRelay {
    pub session_id: String,
    pub source_node: String,
    pub relay_node: String,
    pub destination_node: String,
    pub bytes_relayed: u64,
    pub timestamp_unix: u64,
    pub relay_signature: String,
}
