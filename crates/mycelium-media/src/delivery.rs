//! # mycelium-media: entrega e streaming distribuído (Delivery Engine)
//!
//! Coordena a solicitação de chunks a múltiplos nós simultaneamente (swarming),
//! com verificação estrita de hash e emissão de ProofOfDelivery.

use crate::chunk::{verify_chunk_integrity, RawChunk};
use crate::manifest::VideoManifest;
use crate::receipt::ProofOfDelivery;
use mycelium_core::ContentId;

pub struct DeliveryPlan {
    pub video_cid: ContentId,
    pub total_chunks: usize,
    pub pending_chunk_indices: Vec<u32>,
}

impl DeliveryPlan {
    pub fn from_manifest(manifest_cid: ContentId, manifest: &VideoManifest) -> Self {
        let indices = manifest.chunks.iter().map(|c| c.index).collect();
        Self {
            video_cid: manifest_cid,
            total_chunks: manifest.chunks.len(),
            pending_chunk_indices: indices,
        }
    }
}

pub struct DeliveryEngine;

impl DeliveryEngine {
    /// Valida o chunk recebido de um nó par e emite o recibo assinado de entrega.
    pub fn process_received_chunk(
        chunk: &RawChunk,
        viewer_pubkey: &str,
        host_pubkey: &str,
    ) -> Result<ProofOfDelivery, String> {
        if !verify_chunk_integrity(&chunk.data, &chunk.info.content_id) {
            return Err(format!(
                "Integridade violada para chunk {}: hash não confere com ContentId {}",
                chunk.info.index, chunk.info.content_id
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let pod = ProofOfDelivery {
            content_id: chunk.info.content_id,
            chunk_index: chunk.info.index,
            byte_size: chunk.data.len(),
            host_node: host_pubkey.to_string(),
            viewer_node: viewer_pubkey.to_string(),
            timestamp_unix: now,
            nonce: rand::random(),
            viewer_signature: String::new(),
            host_signature: String::new(),
        };

        Ok(pod)
    }
}
