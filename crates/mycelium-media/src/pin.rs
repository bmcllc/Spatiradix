//! # mycelium-media: pinning local de mídia
//!
//! Garante a retenção de conteúdo no SporeBank local para nós voluntários e criadores.

use mycelium_core::ContentId;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, Default)]
pub struct PinManager {
    pinned_cids: Arc<RwLock<HashSet<ContentId>>>,
    storage_path: Option<PathBuf>,
}

impl PinManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let path_buf = path.as_ref().to_path_buf();
        let set: HashSet<ContentId> = if path_buf.exists() {
            let data = std::fs::read(&path_buf)?;
            serde_json::from_slice(&data).unwrap_or_default()
        } else {
            HashSet::new()
        };
        Ok(Self {
            pinned_cids: Arc::new(RwLock::new(set)),
            storage_path: Some(path_buf),
        })
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        if let Some(ref p) = self.storage_path {
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let lock = self.pinned_cids.read().unwrap();
            let data = serde_json::to_vec_pretty(&*lock).unwrap_or_default();
            std::fs::write(p, data)?;
        }
        Ok(())
    }

    pub fn pin(&self, cid: ContentId) -> bool {
        let mut lock = self.pinned_cids.write().unwrap();
        let inserted = lock.insert(cid);
        drop(lock);
        let _ = self.save();
        inserted
    }

    pub fn unpin(&self, cid: &ContentId) -> bool {
        let mut lock = self.pinned_cids.write().unwrap();
        let removed = lock.remove(cid);
        drop(lock);
        let _ = self.save();
        removed
    }

    pub fn is_pinned(&self, cid: &ContentId) -> bool {
        let lock = self.pinned_cids.read().unwrap();
        lock.contains(cid)
    }

    pub fn list_pins(&self) -> Vec<ContentId> {
        let lock = self.pinned_cids.read().unwrap();
        lock.iter().cloned().collect()
    }
}

