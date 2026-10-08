//! # mycelium-media: manifestos criptográficos
//!
//! Manifestos de Canais, Vídeos e Playlists como objetos soberanos
//! com endereçamento por conteúdo (BLAKE3 / ContentId) e assinaturas criptográficas.

use mycelium_core::ContentId;
use serde::{Deserialize, Serialize};

/// Informações sobre um fragmento individual de mídia.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaChunkInfo {
    pub index: u32,
    pub content_id: ContentId,
    pub byte_size: usize,
    pub chunk_hash: String,
    pub offset_bytes: u64,
}

/// Manifesto canônico de um Vídeo publicado na rede Mycelium.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VideoManifest {
    pub video_id: String,
    pub author_pubkey: String,
    pub channel_id: String,
    pub title: String,
    pub description: String,
    pub content_type: String, // "longform" | "short" | "doc"
    pub duration_seconds: u32,
    pub license: String,
    pub tags: Vec<String>,
    #[serde(default)]
    pub thumbnail_cid: Option<ContentId>,
    pub chunks: Vec<MediaChunkInfo>,
    pub total_byte_size: u64,
    pub resolution: String,
    pub mime_type: String,
    pub target_replicas: u32,
    pub published_at_unix: u64,
    pub signature: String,
}

impl VideoManifest {
    pub fn content_id(&self) -> Result<ContentId, String> {
        let serialized = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(ContentId::of(&serialized))
    }

    pub fn canonical_payload(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}:{}",
            self.video_id, self.channel_id, self.title, self.total_byte_size, self.chunks.len(), self.published_at_unix
        )
    }
}

/// Manifesto canônico de um Canal/Criador soberano.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelManifest {
    pub channel_id: String,
    pub owner_pubkey: String,
    pub handle: String,
    pub display_name: String,
    pub bio: String,
    #[serde(default)]
    pub avatar_cid: Option<ContentId>,
    #[serde(default)]
    pub banner_cid: Option<ContentId>,
    pub default_license: String,
    pub videos: Vec<ContentId>,
    pub playlists: Vec<ContentId>,
    pub moderators: Vec<String>,
    pub revision: u64,
    pub updated_at_unix: u64,
    pub signature: String,
}

impl ChannelManifest {
    pub fn content_id(&self) -> Result<ContentId, String> {
        let serialized = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(ContentId::of(&serialized))
    }

    pub fn canonical_payload(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.channel_id, self.owner_pubkey, self.handle, self.revision, self.videos.len()
        )
    }
}

/// Manifesto canônico de uma Playlist independente.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlaylistManifest {
    pub playlist_id: String,
    pub owner_pubkey: String,
    pub title: String,
    pub description: String,
    pub videos: Vec<ContentId>,
    pub is_collaborative: bool,
    pub revision: u64,
    pub signature: String,
}

impl PlaylistManifest {
    pub fn content_id(&self) -> Result<ContentId, String> {
        let serialized = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        Ok(ContentId::of(&serialized))
    }
}
