//! Modelo de dados criptográfico unificado do Mycelium Rhizome.
//!
//! Cobre todos os primitivos sociais com assinatura Ed25519 estrita e separação de domínio:
//! - Perfis & Canais (YouTube + Instagram + Facebook + X + Cartão de Contato PQC/WhatsApp)
//! - Posts Unificados (Vídeo longo, Short/Reel, Galeria de Fotos, Artigo/Mural, Microblog/Thread/Repost/Quote)
//! - Stories efêmeros (24h TTL em Isotope)
//! - Comunidades / Grupos (Facebook Groups / YouTube Community)
//! - Comentários encadeados, Reações ricas e Grafo de Seguidores/Inscrições

use crate::commons::{
    CommonsContribution, CommonsProject, CustomDiscoveryLens, ShardReplicaReceipt, TipRecord,
};
use crate::identity::{verify_domain_signature, SovereignKeys};
use crate::{unix_now, RhizomeError};
use mycelium_core::{ContentId, NodeId};
use mycelium_media::{ChannelManifest, PlaylistManifest, VideoManifest};
use serde::{Deserialize, Serialize};

pub const DEFAULT_STORY_TTL_SECS: u64 = 86_400; // 24 horas

const DOMAIN_PROFILE: &str = "mycelium-rhizome/profile/v1";
const DOMAIN_POST: &str = "mycelium-rhizome/post/v1";
const DOMAIN_STORY: &str = "mycelium-rhizome/story/v1";
const DOMAIN_COMMENT: &str = "mycelium-rhizome/comment/v1";
const DOMAIN_REACTION: &str = "mycelium-rhizome/reaction/v1";
const DOMAIN_FOLLOW: &str = "mycelium-rhizome/follow/v1";
const DOMAIN_COMMUNITY: &str = "mycelium-rhizome/community/v1";

/// Origem de um objeto (nativo ou retrocompatível importado/bridged).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ExternalOrigin {
    #[default]
    Native,
    XArchive {
        original_id: String,
        #[serde(default)]
        original_handle: Option<String>,
        imported_at: u64,
    },
    WhatsAppExport {
        chat_title: String,
        original_sender: String,
        imported_at: u64,
    },
    NostrEvent {
        event_id: String,
        pubkey_hex: String,
        kind: u16,
    },
    XApiV2 {
        tweet_id: String,
        #[serde(default)]
        author_id: Option<String>,
    },
    WhatsAppCloud {
        wamid: String,
        from_wa_id: String,
    },
}

/// Tipo de publicação no feed unificado.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostKind {
    /// Vídeo estilo YouTube (long-form, chunks BLAKE3 via `mycelium-media`).
    Video,
    /// Vídeo vertical curto estilo Shorts / Reels.
    Short,
    /// Galeria / Carrossel de fotos estilo Instagram.
    PhotoGallery,
    /// Post longo / mural / discussão de comunidade estilo Facebook.
    Article,
    /// Microblog / thread / repost / quote estilo X (Twitter).
    Microblog,
}

/// Anexo de mídia endereçado por conteúdo (BLAKE3 ContentId).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaAttachment {
    pub cid: String,
    pub mime_type: String,
    pub byte_size: u64,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub duration_secs: Option<u32>,
    #[serde(default)]
    pub alt_text: String,
    /// Se `true`, `cid` aponta para um `VideoManifest` chunked do `mycelium-media`.
    #[serde(default)]
    pub is_chunked_video: bool,
}

/// Fatia binária content-addressed (≤ 32 KiB brutos → ~44 KiB Base64 < 64 KiB gossipsub)
/// para replicar fotos, áudios, documentos e chunks BLAKE3 de vídeo pela malha P2P.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaChunkPacket {
    /// Para vídeo: `VideoManifest` CID; para blob (foto/áudio/doc): ContentId BLAKE3 do blob completo.
    pub asset_cid: String,
    /// Para vídeo: `ContentId` BLAKE3 deste chunk individual; para blob: igual a `asset_cid`.
    pub chunk_cid: String,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub is_video_chunk: bool,
    #[serde(default)]
    pub mime_type: String,
    pub data_b64: String,
}

/// Perfil / Canal soberano unificado.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileManifest {
    pub node_id: String,
    pub ed25519_pubkey_hex: String,
    pub ghost_pubkey_hex: String,
    pub pkarr_addr: String,
    /// Chave pública ML-KEM-1024 (hex) para receber mensagens E2EE pós-quânticas.
    pub mlkem1024_pubkey_hex: String,
    pub handle: String,
    pub display_name: String,
    pub bio: String,
    #[serde(default)]
    pub avatar_cid: Option<String>,
    #[serde(default)]
    pub banner_cid: Option<String>,
    #[serde(default)]
    pub channel_id: Option<String>,
    #[serde(default)]
    pub links: Vec<String>,
    #[serde(default)]
    pub wallet_pubkey_hex: Option<String>,
    pub revision: u64,
    pub updated_at: u64,
    pub signature: String,
}

impl ProfileManifest {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        Ok(serde_json::to_vec(&unsigned)?)
    }

    pub fn sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        self.node_id = keys.node_id_hex();
        self.ed25519_pubkey_hex = keys.ed25519_pubkey_hex();
        self.ghost_pubkey_hex = keys.ghost_pubkey_hex();
        self.pkarr_addr = keys.pkarr_address();
        self.mlkem1024_pubkey_hex = keys.mlkem_pubkey_hex();
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_PROFILE, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        validate_handle(&self.handle)?;
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.node_id,
            &self.ed25519_pubkey_hex,
            DOMAIN_PROFILE,
            &bytes,
            &self.signature,
        )
    }
}

/// Publicação unificada (Vídeo YouTube, Reel/Short, Foto Instagram, Post Facebook, Microblog X).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SocialPost {
    /// ContentId canônico (`Qm...`) calculado sobre o corpo sem assinatura.
    pub post_id: String,
    pub author_node_id: String,
    pub author_pubkey_hex: String,
    pub author_handle: String,
    pub kind: PostKind,
    #[serde(default)]
    pub title: Option<String>,
    pub body: String,
    #[serde(default)]
    pub media: Vec<MediaAttachment>,
    #[serde(default)]
    pub video_manifest_cid: Option<String>,
    #[serde(default)]
    pub thumbnail_cid: Option<String>,
    #[serde(default)]
    pub channel_id: Option<String>,
    #[serde(default)]
    pub community_id: Option<String>,
    /// Tipo editorial para vídeo (`"longform"` | `"short"` | `"doc"`).
    #[serde(default)]
    pub content_type: Option<String>,
    /// Projeto colaborativo MCP associado (Mycelium Commons Protocol).
    #[serde(default)]
    pub commons_project_id: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub mentions: Vec<String>,
    /// Thread estilo X: responde a outro `post_id`.
    #[serde(default)]
    pub reply_to: Option<String>,
    /// Repost / Retweet estilo X.
    #[serde(default)]
    pub repost_of: Option<String>,
    /// Quote Post estilo X.
    #[serde(default)]
    pub quote_of: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub external_origin: ExternalOrigin,
    pub created_at: u64,
    pub signature: String,
}

impl SocialPost {
    /// Calcula bytes canônicos sem `post_id` nem `signature` para derivar o `ContentId`.
    fn id_material(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.post_id.clear();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn finalize_and_sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        self.author_node_id = keys.node_id_hex();
        self.author_pubkey_hex = keys.ed25519_pubkey_hex();
        normalize_tags(&mut self.tags, &self.body);
        extract_mentions(&mut self.mentions, &self.body);
        let id_bytes = self.id_material()?;
        self.post_id = ContentId::of(&id_bytes).to_string();
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_POST, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        let id_bytes = self.id_material()?;
        let expected_id = ContentId::of(&id_bytes).to_string();
        if self.post_id != expected_id {
            return Err(RhizomeError::Corrupted(format!(
                "post_id divergente: declarado {}, calculado {}",
                self.post_id, expected_id
            )));
        }
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.author_node_id,
            &self.author_pubkey_hex,
            DOMAIN_POST,
            &bytes,
            &self.signature,
        )
    }
}

/// Story efêmero (Instagram Stories / WhatsApp Status) com TTL em Isotope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoryItem {
    pub story_id: String,
    pub author_node_id: String,
    pub author_pubkey_hex: String,
    pub author_handle: String,
    pub caption: String,
    #[serde(default)]
    pub background: String,
    #[serde(default)]
    pub media: Option<MediaAttachment>,
    pub created_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

impl StoryItem {
    pub fn isotope_key(&self) -> String {
        format!("rhizome/story/{}/{}", self.author_node_id, self.story_id)
    }

    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    fn id_material(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.story_id.clear();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn finalize_and_sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        self.author_node_id = keys.node_id_hex();
        self.author_pubkey_hex = keys.ed25519_pubkey_hex();
        if self.created_at == 0 {
            self.created_at = unix_now();
        }
        if self.expires_at <= self.created_at {
            self.expires_at = self.created_at + DEFAULT_STORY_TTL_SECS;
        }
        let id_bytes = self.id_material()?;
        self.story_id = ContentId::of(&id_bytes).to_string();
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_STORY, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        let id_bytes = self.id_material()?;
        let expected_id = ContentId::of(&id_bytes).to_string();
        if self.story_id != expected_id {
            return Err(RhizomeError::Corrupted("story_id divergente".into()));
        }
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.author_node_id,
            &self.author_pubkey_hex,
            DOMAIN_STORY,
            &bytes,
            &self.signature,
        )
    }
}

/// Comentário assinado em vídeo ou post (com suporte a threads aninhadas).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Comment {
    pub comment_id: String,
    pub target_post_id: String,
    #[serde(default)]
    pub parent_comment_id: Option<String>,
    pub author_node_id: String,
    pub author_pubkey_hex: String,
    pub author_handle: String,
    pub body: String,
    pub created_at: u64,
    pub signature: String,
}

impl Comment {
    fn id_material(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.comment_id.clear();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn finalize_and_sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        self.author_node_id = keys.node_id_hex();
        self.author_pubkey_hex = keys.ed25519_pubkey_hex();
        if self.created_at == 0 {
            self.created_at = unix_now();
        }
        let id_bytes = self.id_material()?;
        self.comment_id = ContentId::of(&id_bytes).to_string();
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_COMMENT, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        let id_bytes = self.id_material()?;
        let expected_id = ContentId::of(&id_bytes).to_string();
        if self.comment_id != expected_id {
            return Err(RhizomeError::Corrupted("comment_id divergente".into()));
        }
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.author_node_id,
            &self.author_pubkey_hex,
            DOMAIN_COMMENT,
            &bytes,
            &self.signature,
        )
    }
}

/// Reação estilo Facebook / YouTube / Instagram / X.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactionKind {
    Like,
    Love,
    Mushroom,
    Fire,
    Haha,
    Insightful,
    Bookmark,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reaction {
    pub target_post_id: String,
    pub author_node_id: String,
    pub author_pubkey_hex: String,
    pub kind: ReactionKind,
    pub active: bool,
    pub updated_at: u64,
    pub signature: String,
}

impl Reaction {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        self.author_node_id = keys.node_id_hex();
        self.author_pubkey_hex = keys.ed25519_pubkey_hex();
        if self.updated_at == 0 {
            self.updated_at = unix_now();
        }
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_REACTION, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.author_node_id,
            &self.author_pubkey_hex,
            DOMAIN_REACTION,
            &bytes,
            &self.signature,
        )
    }
}

/// Aresta assinada do grafo social (Seguir perfil, Inscrever-se em canal, Entrar em comunidade).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FollowEdge {
    pub follower_node_id: String,
    pub follower_pubkey_hex: String,
    /// `NodeId` de um usuário/canal ou `community_id`.
    pub target_id: String,
    /// `"user"` | `"channel"` | `"community"`
    pub target_kind: String,
    pub active: bool,
    pub updated_at: u64,
    pub signature: String,
}

impl FollowEdge {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        self.follower_node_id = keys.node_id_hex();
        self.follower_pubkey_hex = keys.ed25519_pubkey_hex();
        if self.updated_at == 0 {
            self.updated_at = unix_now();
        }
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_FOLLOW, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.follower_node_id,
            &self.follower_pubkey_hex,
            DOMAIN_FOLLOW,
            &bytes,
            &self.signature,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommunityVisibility {
    Public,
    InviteOnly,
}

/// Comunidade / Grupo soberano (Facebook Groups + YouTube Community).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Community {
    pub community_id: String,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub creator_node_id: String,
    pub creator_pubkey_hex: String,
    #[serde(default)]
    pub moderators: Vec<String>,
    #[serde(default)]
    pub rules: Vec<String>,
    pub visibility: CommunityVisibility,
    pub revision: u64,
    pub updated_at: u64,
    pub signature: String,
}

impl Community {
    pub fn derive_id(creator_node_id: &str, slug: &str) -> String {
        let h = blake3::hash(format!("mycelium-rhizome/community/{creator_node_id}/{slug}").as_bytes());
        format!("com_{}", hex::encode(&h.as_bytes()[..12]))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RhizomeError> {
        let mut clone = self.clone();
        clone.signature.clear();
        Ok(serde_json::to_vec(&clone)?)
    }

    pub fn finalize_and_sign(&mut self, keys: &SovereignKeys) -> Result<(), RhizomeError> {
        validate_handle(&self.slug)?;
        self.creator_node_id = keys.node_id_hex();
        self.creator_pubkey_hex = keys.ed25519_pubkey_hex();
        self.community_id = Self::derive_id(&self.creator_node_id, &self.slug);
        if self.updated_at == 0 {
            self.updated_at = unix_now();
        }
        let bytes = self.canonical_bytes()?;
        self.signature = keys.sign_domain(DOMAIN_COMMUNITY, &bytes);
        Ok(())
    }

    pub fn verify(&self) -> Result<NodeId, RhizomeError> {
        validate_handle(&self.slug)?;
        let expected_id = Self::derive_id(&self.creator_node_id, &self.slug);
        if self.community_id != expected_id {
            return Err(RhizomeError::Corrupted("community_id divergente".into()));
        }
        let bytes = self.canonical_bytes()?;
        verify_domain_signature(
            &self.creator_node_id,
            &self.creator_pubkey_hex,
            DOMAIN_COMMUNITY,
            &bytes,
            &self.signature,
        )
    }
}

/// Envelope unificado de replicação P2P pública (gossipsub `mycelium/lattice/v1` + SporeBank).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SyncEnvelope {
    Profile(ProfileManifest),
    Post(SocialPost),
    Story(StoryItem),
    Comment(Comment),
    Reaction(Reaction),
    Follow(FollowEdge),
    Community(Community),
    VideoManifest {
        manifest_cid: String,
        manifest: VideoManifest,
        author_node_id: String,
        author_pubkey_hex: String,
        signature: String,
    },
    Channel(ChannelManifest),
    Playlist(PlaylistManifest),
    CommonsProject(CommonsProject),
    CommonsContribution(CommonsContribution),
    ShardReceipt(ShardReplicaReceipt),
    Tip(TipRecord),
    DiscoveryLens(CustomDiscoveryLens),
}

impl SyncEnvelope {
    pub fn sign_video_manifest(
        manifest_cid: String,
        manifest: VideoManifest,
        keys: &SovereignKeys,
    ) -> Result<Self, RhizomeError> {
        let payload = serde_json::to_vec(&(&manifest_cid, &manifest))?;
        let signature = keys.sign_domain("mycelium-rhizome/video-manifest/v1", &payload);
        Ok(Self::VideoManifest {
            manifest_cid,
            manifest,
            author_node_id: keys.node_id_hex(),
            author_pubkey_hex: keys.ed25519_pubkey_hex(),
            signature,
        })
    }

    /// Verifica a integridade criptográfica do objeto contido no envelope antes de absorver.
    pub fn verify(&self) -> Result<(), RhizomeError> {
        match self {
            SyncEnvelope::Profile(p) => p.verify().map(|_| ()),
            SyncEnvelope::Post(p) => p.verify().map(|_| ()),
            SyncEnvelope::Story(s) => s.verify().map(|_| ()),
            SyncEnvelope::Comment(c) => c.verify().map(|_| ()),
            SyncEnvelope::Reaction(r) => r.verify().map(|_| ()),
            SyncEnvelope::Follow(f) => f.verify().map(|_| ()),
            SyncEnvelope::Community(c) => c.verify().map(|_| ()),
            SyncEnvelope::VideoManifest {
                manifest_cid,
                manifest,
                author_node_id,
                author_pubkey_hex,
                signature,
            } => {
                let computed = manifest
                    .content_id()
                    .map_err(RhizomeError::Corrupted)?
                    .to_string();
                if &computed != manifest_cid {
                    return Err(RhizomeError::Corrupted(format!(
                        "VideoManifest CID divergente: {manifest_cid} != {computed}"
                    )));
                }
                let payload = serde_json::to_vec(&(manifest_cid, manifest))?;
                verify_domain_signature(
                    author_node_id,
                    author_pubkey_hex,
                    "mycelium-rhizome/video-manifest/v1",
                    &payload,
                    signature,
                )?;
                Ok(())
            }
            SyncEnvelope::Channel(ch) => {
                if ch.channel_id.is_empty() || ch.handle.is_empty() {
                    return Err(RhizomeError::InvalidInput("canal sem id/handle".into()));
                }
                Ok(())
            }
            SyncEnvelope::Playlist(pl) => {
                if pl.playlist_id.is_empty() || pl.title.is_empty() {
                    return Err(RhizomeError::InvalidInput("playlist sem id/título".into()));
                }
                Ok(())
            }
            SyncEnvelope::CommonsProject(p) => p.verify().map(|_| ()),
            SyncEnvelope::CommonsContribution(c) => c.verify().map(|_| ()),
            SyncEnvelope::ShardReceipt(r) => r.verify().map(|_| ()),
            SyncEnvelope::Tip(t) => t.verify().map(|_| ()),
            SyncEnvelope::DiscoveryLens(l) => l.verify().map(|_| ()),
        }
    }
}

pub fn validate_handle(handle: &str) -> Result<(), RhizomeError> {
    let trimmed = handle.trim_start_matches('@');
    if trimmed.is_empty() || trimmed.len() > 48 {
        return Err(RhizomeError::InvalidInput(
            "handle/slug deve ter entre 1 e 48 caracteres".into(),
        ));
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
    {
        return Err(RhizomeError::InvalidInput(format!(
            "handle/slug inválido '{handle}': use apenas [a-zA-Z0-9_.-]"
        )));
    }
    Ok(())
}

/// Normaliza tags e extrai `#hashtags` presentes no texto do post.
pub fn normalize_tags(tags: &mut Vec<String>, body: &str) {
    let mut set = std::collections::BTreeSet::new();
    for t in tags.iter() {
        let clean = t.trim().trim_start_matches('#').to_ascii_lowercase();
        if !clean.is_empty() && clean.len() <= 48 {
            set.insert(clean);
        }
    }
    for word in body.split_whitespace() {
        if let Some(rest) = word.strip_prefix('#') {
            let clean: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect::<String>()
                .to_ascii_lowercase();
            if !clean.is_empty() && clean.len() <= 48 {
                set.insert(clean);
            }
        }
    }
    *tags = set.into_iter().collect();
}

/// Extrai `@menções` presentes no texto do post.
pub fn extract_mentions(mentions: &mut Vec<String>, body: &str) {
    let mut set = std::collections::BTreeSet::new();
    for m in mentions.iter() {
        let clean = m.trim().trim_start_matches('@').to_ascii_lowercase();
        if !clean.is_empty() && clean.len() <= 48 {
            set.insert(clean);
        }
    }
    for word in body.split_whitespace() {
        if let Some(rest) = word.strip_prefix('@') {
            let clean: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
                .collect::<String>()
                .to_ascii_lowercase();
            if !clean.is_empty() && clean.len() <= 48 {
                set.insert(clean);
            }
        }
    }
    *mentions = set.into_iter().collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_post_profile_story_and_tamper_detection() {
        let keys = SovereignKeys::from_seed([0x33; 32]).unwrap();

        let mut profile = ProfileManifest {
            node_id: String::new(),
            ed25519_pubkey_hex: String::new(),
            ghost_pubkey_hex: String::new(),
            pkarr_addr: String::new(),
            mlkem1024_pubkey_hex: String::new(),
            handle: "floresta".into(),
            display_name: "Floresta Viva".into(),
            bio: "Rede soberana".into(),
            avatar_cid: None,
            banner_cid: None,
            channel_id: None,
            links: vec![],
            wallet_pubkey_hex: None,
            revision: 1,
            updated_at: 1_760_000_000,
            signature: String::new(),
        };
        profile.sign(&keys).unwrap();
        profile.verify().unwrap();

        let mut bad_profile = profile.clone();
        bad_profile.bio = "alterado".into();
        assert!(bad_profile.verify().is_err());

        let mut post = SocialPost {
            post_id: String::new(),
            author_node_id: String::new(),
            author_pubkey_hex: String::new(),
            author_handle: "floresta".into(),
            kind: PostKind::Microblog,
            title: None,
            body: "Olá #Mycelium e @alice! Sem servidor central.".into(),
            media: vec![],
            video_manifest_cid: None,
            thumbnail_cid: None,
            channel_id: None,
            community_id: None,
            content_type: None,
            commons_project_id: None,
            tags: vec![],
            mentions: vec![],
            reply_to: None,
            repost_of: None,
            quote_of: None,
            location: None,
            license: "CC-BY-4.0".into(),
            external_origin: ExternalOrigin::Native,
            created_at: 1_760_000_010,
            signature: String::new(),
        };
        post.finalize_and_sign(&keys).unwrap();
        assert_eq!(post.tags, vec!["mycelium"]);
        assert_eq!(post.mentions, vec!["alice"]);
        post.verify().unwrap();

        let mut tampered_post = post.clone();
        tampered_post.body.push('!');
        assert!(tampered_post.verify().is_err());

        let mut story = StoryItem {
            story_id: String::new(),
            author_node_id: String::new(),
            author_pubkey_hex: String::new(),
            author_handle: "floresta".into(),
            caption: "Story 24h via Isotope".into(),
            background: "linear-gradient(135deg,#10b981,#06b6d4)".into(),
            media: None,
            created_at: 1_000,
            expires_at: 1_000 + 3600,
            signature: String::new(),
        };
        story.finalize_and_sign(&keys).unwrap();
        story.verify().unwrap();
        assert!(!story.is_expired(2_000));
        assert!(story.is_expired(4_600));
        assert!(story.isotope_key().starts_with("rhizome/story/"));
    }
}
