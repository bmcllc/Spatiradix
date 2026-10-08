//! # mycelium-media: canais descentralizados
//!
//! Gerencia entidades de criadores como objetos criptográficos assinados por GhostID / Ed25519.
//! Canais não dependem de tabelas SQL centralizadas: a última revisão assinada na rede é a canônica.

use crate::manifest::ChannelManifest;
use mycelium_core::ContentId;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

pub struct ChannelStore {
    channels: Arc<RwLock<HashMap<String, ChannelManifest>>>,
    dir: Option<PathBuf>,
}

impl ChannelStore {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            dir: None,
        }
    }

    pub fn open(dir: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let dir_buf = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir_buf)?;
        let mut map = HashMap::new();

        if let Ok(entries) = std::fs::read_dir(&dir_buf) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().map(|e| e == "json").unwrap_or(false) {
                    if let Ok(bytes) = std::fs::read(&p) {
                        if let Ok(manifest) = serde_json::from_slice::<ChannelManifest>(&bytes) {
                            map.insert(manifest.channel_id.clone(), manifest);
                        }
                    }
                }
            }
        }

        Ok(Self {
            channels: Arc::new(RwLock::new(map)),
            dir: Some(dir_buf),
        })
    }

    fn persist_channel(&self, manifest: &ChannelManifest) {
        if let Some(ref d) = self.dir {
            let path = d.join(format!("{}.json", manifest.channel_id));
            if let Ok(bytes) = serde_json::to_vec_pretty(manifest) {
                let _ = std::fs::write(path, bytes);
            }
        }
    }

    /// Cria um novo manifesto inicial de canal (revisão 1).
    pub fn create_channel(
        &self,
        handle: &str,
        display_name: &str,
        owner_pubkey: &str,
        bio: &str,
        license: &str,
    ) -> ChannelManifest {
        let channel_id = format!("ch_{}", hex::encode(&blake3::hash(format!("{handle}:{owner_pubkey}").as_bytes()).as_bytes()[..10]));

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let manifest = ChannelManifest {
            channel_id: channel_id.clone(),
            owner_pubkey: owner_pubkey.to_string(),
            handle: handle.to_string(),
            display_name: display_name.to_string(),
            bio: bio.to_string(),
            avatar_cid: None,
            banner_cid: None,
            default_license: license.to_string(),
            videos: Vec::new(),
            playlists: Vec::new(),
            moderators: Vec::new(),
            revision: 1,
            updated_at_unix: now,
            signature: String::new(),
        };

        let mut lock = self.channels.write().unwrap();
        lock.insert(channel_id, manifest.clone());
        drop(lock);
        self.persist_channel(&manifest);
        manifest
    }

    /// Publica um vídeo no canal, avançando a revisão criptográfica.
    pub fn add_video_to_channel(&self, channel_id: &str, video_cid: ContentId) -> Result<ChannelManifest, String> {
        let mut lock = self.channels.write().unwrap();
        let channel = lock
            .get_mut(channel_id)
            .ok_or_else(|| format!("Canal {channel_id} não encontrado"))?;

        if !channel.videos.contains(&video_cid) {
            channel.videos.push(video_cid);
        }
        channel.revision += 1;
        channel.updated_at_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let cloned = channel.clone();
        drop(lock);
        self.persist_channel(&cloned);
        Ok(cloned)
    }

    /// Recupera o manifesto do canal pelo identificador.
    pub fn get_channel(&self, channel_id: &str) -> Option<ChannelManifest> {
        let lock = self.channels.read().unwrap();
        lock.get(channel_id).cloned()
    }
}
