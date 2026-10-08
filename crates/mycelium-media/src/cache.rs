//! # mycelium-media: cache orgânico do espectador (Physarum Cache)
//!
//! Organiza a retenção de chunks de mídia em três estados adaptativos:
//! - HOT: Vídeos populares com alta demanda, mantidos na memória/SSD e servidos à malha.
//! - WARM: Chunks assistidos recentemente pelo usuário, compartilhados voluntariamente.
//! - COLD: Conteúdo arquivado ou raro com baixa taxa de acesso.

use mycelium_core::ContentId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageTier {
    Hot,
    Warm,
    Cold,
}

#[derive(Clone, Debug)]
pub struct CachedItem {
    pub content_id: ContentId,
    pub tier: StorageTier,
    pub access_count: u64,
    pub last_accessed_unix: u64,
    pub size_bytes: usize,
}

#[derive(Clone, Debug, Default)]
pub struct PhysarumCache {
    items: Arc<RwLock<HashMap<ContentId, CachedItem>>>,
    max_hot_bytes: usize,
    max_warm_bytes: usize,
}

impl PhysarumCache {
    pub fn new(max_hot_mb: usize, max_warm_mb: usize) -> Self {
        Self {
            items: Arc::new(RwLock::new(HashMap::new())),
            max_hot_bytes: max_hot_mb * 1024 * 1024,
            max_warm_bytes: max_warm_mb * 1024 * 1024,
        }
    }

    pub fn max_hot_bytes(&self) -> usize {
        self.max_hot_bytes
    }

    pub fn max_warm_bytes(&self) -> usize {
        self.max_warm_bytes
    }

    /// Registra o acesso a um chunk, promovendo-o dinamicamente de nível conforme a demanda.
    pub fn record_access(&self, cid: ContentId, size_bytes: usize) {
        let mut lock = self.items.write().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let entry = lock.entry(cid).or_insert_with(|| CachedItem {
            content_id: cid,
            tier: StorageTier::Warm,
            access_count: 0,
            last_accessed_unix: now,
            size_bytes,
        });

        entry.access_count += 1;
        entry.last_accessed_unix = now;

        // Se muito acessado (> 5 vezes na janela), promove para HOT
        if entry.access_count >= 5 {
            entry.tier = StorageTier::Hot;
        }
    }

    pub fn get_tier(&self, cid: &ContentId) -> Option<StorageTier> {
        let lock = self.items.read().unwrap();
        lock.get(cid).map(|i| i.tier)
    }

    pub fn list_tier(&self, tier: StorageTier) -> Vec<ContentId> {
        let lock = self.items.read().unwrap();
        lock.values().filter(|i| i.tier == tier).map(|i| i.content_id).collect()
    }
}
