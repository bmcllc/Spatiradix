//! Armazenamento soberano do Mycelium Rhizome integrado a:
//! - `SporeBank` (Plots públicos BLAKE3 para replicação via DHT/gossipsub/anti-entropy)
//! - `mycelium-media` (chunks BLAKE3 de vídeo, canais, playlists, pins e lentes de descoberta)
//! - `Isotope` (Stories efêmeros com decaimento por TTL)
//! - Histórico local de chat E2EE Pós-Quântico (ML-KEM-1024 + XChaCha20-Poly1305)

use crate::chat::{
    new_message_id, seal_for_nostr_nip44, unseal_from_nostr_nip44, ChatMessageKind, ChatPlaintext,
    ChatReceipt, ConversationSummary, DecryptedChatMessage, GroupManifest, ReceiptStatus,
    SealedChatEnvelope,
};
use crate::commons::{
    BudgetItem, CommonsContribution, CommonsProject, CustomDiscoveryLens, MilestoneItem,
    ShardReplicaReceipt, SplitContractParty, TipRecord,
};
use crate::compat::{
    import_x_archive_into_posts, nostr_event_to_post, parse_whatsapp_txt, post_to_nostr_event,
    render_activitypub_actor, render_activitypub_outbox, render_rss_feed, BridgeCapabilities,
    ExternalBridgeAdapter, WhatsAppCloudAdapter, XApiV2Adapter,
};
use crate::identity::{PublicIdentityCard, SovereignKeys};
use crate::model::{
    validate_handle, Comment, Community, CommunityVisibility, ExternalOrigin, FollowEdge,
    MediaAttachment, MediaChunkPacket, PostKind, ProfileManifest, Reaction, ReactionKind,
    SocialPost, StoryItem, SyncEnvelope, DEFAULT_STORY_TTL_SECS,
};
use crate::{unix_now, RhizomeError};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use giggs::{Leaf, Plot};
use isotope::Atom;
use mycelium_core::ContentId;
use mycelium_media::{
    ingest_video, verify_chunk_integrity, ChannelStore, DiscoveryLens, MediaChunkInfo, PinManager,
    PlaylistManifest, ProofOfStorage, VideoManifest,
};
use mycelium_nostr::NostrEvent;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Tamanho padrão de chunk de mídia/vídeo (32 KiB brutos → ~44 KiB Base64 < 64 KiB gossipsub).
pub const RHIZOME_VIDEO_CHUNK_BYTES: usize = 32 * 1024; // 32 KiB

/// Máximo de bytes por upload de mídia simples (imagem/áudio/documento).
pub const MAX_SINGLE_BLOB_BYTES: usize = 5 * 1024 * 1024; // 5 MiB

/// Máximo de bytes por upload de vídeo em fatias (512 MiB em disco, streaming sem estourar RAM).
pub const MAX_VIDEO_UPLOAD_BYTES: u64 = 512 * 1024 * 1024;

/// Resultado da preparação de vídeo executada FORA do Mutex (leitura + fatiamento BLAKE3 em disco).
pub struct PreparedVideoIngest {
    pub manifest: VideoManifest,
    pub video_id: String,
    pub channel_id: String,
    pub meta: VideoUploadMeta,
}

/// Fatiamento BLAKE3 de vídeo por streaming direto de arquivo em disco (O(32 KiB) de RAM — ideal para Android/mobile!).
pub fn prepare_video_ingest_from_file(
    source_path: &Path,
    chunks_dir: &Path,
    author_pubkey_hex: &str,
    channel_id: &str,
    mut meta: VideoUploadMeta,
) -> Result<PreparedVideoIngest, RhizomeError> {
    if meta.title.trim().is_empty() {
        return Err(RhizomeError::InvalidInput("título do vídeo é obrigatório".into()));
    }
    std::fs::create_dir_all(chunks_dir)?;

    let mut file = std::fs::File::open(source_path)?;
    let mut buf = vec![0u8; RHIZOME_VIDEO_CHUNK_BYTES];
    let mut full_hasher = blake3::Hasher::new();
    let mut chunks = Vec::new();
    let mut offset: u64 = 0;
    let mut index: u32 = 0;
    let mut detected_mime: Option<&'static str> = None;

    loop {
        let mut filled = 0usize;
        while filled < buf.len() {
            let n = file.read(&mut buf[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        let slice = &buf[..filled];
        if detected_mime.is_none() {
            detected_mime = Some(detect_mime_from_bytes(slice));
        }
        full_hasher.update(slice);

        let content_id = ContentId::of(slice);
        let chunk_hash = hex::encode(blake3::hash(slice).as_bytes());
        let chunk_cid_str = content_id.to_string();
        let chunk_path = chunks_dir.join(&chunk_cid_str);
        if !chunk_path.exists() {
            std::fs::write(&chunk_path, slice)?;
        }

        chunks.push(MediaChunkInfo {
            index,
            content_id,
            byte_size: filled,
            chunk_hash,
            offset_bytes: offset,
        });
        offset += filled as u64;
        index += 1;
    }

    if offset == 0 {
        return Err(RhizomeError::InvalidInput("arquivo de vídeo vazio".into()));
    }

    let content_type = resolve_video_content_type(&meta);
    meta.content_type = content_type.clone();
    if content_type == "short" {
        meta.is_short = true;
    }

    let license = if meta.license.trim().is_empty() {
        "CC-BY-4.0".to_string()
    } else {
        meta.license.trim().to_string()
    };
    let full_hash = full_hasher.finalize();
    let video_id = format!("vid_{}", hex::encode(&full_hash.as_bytes()[..10]));
    let mime_type = if !meta.mime_type.trim().is_empty() {
        meta.mime_type.trim().to_string()
    } else {
        detected_mime.unwrap_or("video/mp4").to_string()
    };
    let resolution = if meta.resolution.trim().is_empty() {
        "1080p".to_string()
    } else {
        meta.resolution.trim().to_string()
    };
    let thumbnail_cid = meta
        .thumbnail_cid
        .as_deref()
        .and_then(|s| s.parse::<ContentId>().ok());

    let manifest = VideoManifest {
        video_id: video_id.clone(),
        author_pubkey: author_pubkey_hex.to_string(),
        channel_id: channel_id.to_string(),
        title: meta.title.trim().to_string(),
        description: meta.description.trim().to_string(),
        content_type,
        duration_seconds: meta.duration_secs,
        license,
        tags: meta.tags.clone(),
        thumbnail_cid,
        chunks,
        total_byte_size: offset,
        resolution,
        mime_type,
        target_replicas: meta.target_replicas.max(1),
        published_at_unix: unix_now(),
        signature: String::new(),
    };

    Ok(PreparedVideoIngest {
        manifest,
        video_id,
        channel_id: channel_id.to_string(),
        meta,
    })
}

fn resolve_video_content_type(meta: &VideoUploadMeta) -> String {
    let ct = meta.content_type.trim().to_ascii_lowercase();
    match ct.as_str() {
        "short" | "doc" | "longform" => ct,
        _ => {
            if meta.is_short {
                "short".into()
            } else {
                "longform".into()
            }
        }
    }
}

/// Fatiamento BLAKE3 de vídeo + escrita direta dos chunks brutos em disco — executa fora do lock!
pub fn prepare_video_ingest(
    media_data: &[u8],
    chunks_dir: &Path,
    author_pubkey_hex: &str,
    channel_id: &str,
    mut meta: VideoUploadMeta,
) -> Result<PreparedVideoIngest, RhizomeError> {
    if media_data.is_empty() {
        return Err(RhizomeError::InvalidInput("arquivo de vídeo vazio".into()));
    }
    if meta.title.trim().is_empty() {
        return Err(RhizomeError::InvalidInput("título do vídeo é obrigatório".into()));
    }
    std::fs::create_dir_all(chunks_dir)?;

    let content_type = resolve_video_content_type(&meta);
    meta.content_type = content_type.clone();
    if content_type == "short" {
        meta.is_short = true;
    }
    let license = if meta.license.trim().is_empty() {
        "CC-BY-4.0"
    } else {
        meta.license.trim()
    };
    let video_id = format!(
        "vid_{}",
        hex::encode(&blake3::hash(media_data).as_bytes()[..10])
    );

    let mut ingest = ingest_video(
        &video_id,
        author_pubkey_hex,
        channel_id,
        meta.title.trim(),
        meta.description.trim(),
        &content_type,
        meta.duration_secs,
        license,
        meta.tags.clone(),
        media_data,
        Some(RHIZOME_VIDEO_CHUNK_BYTES),
    );
    ingest.manifest.target_replicas = meta.target_replicas.max(1);
    if !meta.mime_type.trim().is_empty() {
        ingest.manifest.mime_type = meta.mime_type.trim().to_string();
    } else {
        ingest.manifest.mime_type = detect_mime_from_bytes(media_data).to_string();
    }
    if !meta.resolution.trim().is_empty() {
        ingest.manifest.resolution = meta.resolution.trim().to_string();
    }
    if let Some(ref thumb) = meta.thumbnail_cid {
        if let Ok(cid) = thumb.parse::<ContentId>() {
            ingest.manifest.thumbnail_cid = Some(cid);
        }
    }

    for chunk in &ingest.raw_chunks {
        let chunk_cid_str = chunk.info.content_id.to_string();
        let chunk_path = chunks_dir.join(&chunk_cid_str);
        if !chunk_path.exists() {
            std::fs::write(&chunk_path, &chunk.data)?;
        }
    }

    Ok(PreparedVideoIngest {
        manifest: ingest.manifest,
        video_id,
        channel_id: channel_id.to_string(),
        meta,
    })
}

/// Detecta o MIME real pelos magic bytes (essencial sob `X-Content-Type-Options: nosniff`).
pub fn detect_mime_from_bytes(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
        return "image/png";
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return "image/jpeg";
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return "image/gif";
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return "image/webp";
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WAVE" {
        return "audio/wav";
    }
    if bytes.starts_with(b"OggS") {
        return "audio/ogg";
    }
    if bytes.starts_with(b"ID3") || (bytes.len() >= 2 && bytes[0] == 0xFF && (bytes[1] & 0xE0) == 0xE0) {
        return "audio/mpeg";
    }
    if bytes.starts_with(&[0x1A, 0x45, 0xDF, 0xA3]) {
        return "video/webm";
    }
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        if &bytes[8..12] == b"avif" || &bytes[8..12] == b"avis" {
            return "image/avif";
        }
        return "video/mp4";
    }
    if bytes.starts_with(b"%PDF-") {
        return "application/pdf";
    }
    if let Ok(head) = std::str::from_utf8(&bytes[..bytes.len().min(64)]) {
        let t = head.trim_start();
        if t.starts_with("<svg") || (t.starts_with("<?xml") && t.contains("<svg")) {
            return "image/svg+xml";
        }
    }
    "application/octet-stream"
}

fn default_target_replicas() -> u32 {
    3
}

/// Metadados de publicação de vídeo.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VideoUploadMeta {
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub is_short: bool,
    /// `"longform"` | `"short"` | `"doc"`
    #[serde(default)]
    pub content_type: String,
    #[serde(default)]
    pub duration_secs: u32,
    #[serde(default)]
    pub resolution: String,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub community_id: Option<String>,
    #[serde(default)]
    pub commons_project_id: Option<String>,
    #[serde(default)]
    pub thumbnail_cid: Option<String>,
    #[serde(default = "default_target_replicas")]
    pub target_replicas: u32,
}

impl Default for VideoUploadMeta {
    fn default() -> Self {
        Self {
            title: String::new(),
            description: String::new(),
            is_short: false,
            content_type: String::new(),
            duration_secs: 0,
            resolution: String::new(),
            mime_type: String::new(),
            license: String::new(),
            tags: Vec::new(),
            community_id: None,
            commons_project_id: None,
            thumbnail_cid: None,
            target_replicas: default_target_replicas(),
        }
    }
}

/// Sessão de upload em fatias (para vídeos maiores que o limite por requisição do proxy).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UploadSessionInfo {
    pub upload_id: String,
    pub filename: String,
    pub mime_type: String,
    pub received_bytes: u64,
    pub chunks_received: u32,
}

/// Filtro de leitura do feed unificado.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FeedFilter {
    pub kind: Option<String>,
    pub lens: Option<String>,
    pub tag: Option<String>,
    pub author: Option<String>,
    pub community_id: Option<String>,
    pub query: Option<String>,
    pub limit: Option<usize>,
    #[serde(default)]
    pub commons_only: Option<bool>,
}

/// Visão enriquecida de um projeto MCP (Mycelium Commons Protocol).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommonsProjectView {
    pub project: CommonsProject,
    pub current_raised: f64,
    pub spores_contributed: u64,
    pub contributions_count: usize,
    pub contributions: Vec<CommonsContribution>,
    pub linked_video_cids: Vec<String>,
}

/// Visão detalhada de um shard de vídeo com recibos criptográficos verificados.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VideoShardView {
    pub index: u32,
    pub chunk_cid: String,
    pub byte_size: usize,
    pub chunk_hash: String,
    pub offset_bytes: u64,
    pub local_available: bool,
    pub target_replicas: u32,
    pub receipts: Vec<ShardReplicaReceipt>,
}

/// Visão completa de vídeo MMP (Player HUD + Shards + Split MCP + Views + Gorjetas).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VideoDetailsView {
    pub manifest: VideoManifest,
    pub manifest_cid: String,
    pub post: Option<SocialPost>,
    pub author_profile: Option<ProfileManifest>,
    pub shards: Vec<VideoShardView>,
    pub replication_score: u8,
    pub distinct_replica_nodes: usize,
    pub is_pinned: bool,
    pub views_count: u64,
    pub tips_total_spores: u64,
    pub tips_total_p2p: f64,
    pub commons_project: Option<CommonsProjectView>,
}

/// Filtros locais de moderação federada (soberania do usuário).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModerationFilters {
    pub anti_spam: bool,
    pub safe_community: bool,
    pub followed_only: bool,
    #[serde(default)]
    pub muted_tags: Vec<String>,
}

impl Default for ModerationFilters {
    fn default() -> Self {
        Self {
            anti_spam: true,
            safe_community: true,
            followed_only: false,
            muted_tags: Vec::new(),
        }
    }
}

/// Visão enriquecida de um post no feed (com perfil do autor, contagem de reações, comentários e score da lente).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeedItemView {
    pub post: SocialPost,
    pub author_profile: Option<ProfileManifest>,
    pub video_manifest: Option<VideoManifest>,
    pub is_pinned: bool,
    pub reactions_summary: BTreeMap<String, usize>,
    pub my_reactions: Vec<ReactionKind>,
    pub comments_count: usize,
    pub comments: Vec<Comment>,
    pub repost_count: usize,
    pub lens_score: f64,
    pub views_count: u64,
    pub tips_total_spores: u64,
    pub tips_total_p2p: f64,
    pub replication_score: u8,
    pub distinct_replica_nodes: usize,
    pub commons_project: Option<CommonsProjectView>,
}

/// Resumo operacional do nó Rhizome para o painel de identidade & telemetria.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeOverview {
    pub identity: PublicIdentityCard,
    pub profile: ProfileManifest,
    pub stats: RhizomeStats,
    pub lenses: Vec<DiscoveryLens>,
    pub bridges: Vec<BridgeCapabilities>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RhizomeStats {
    pub profiles_count: usize,
    pub posts_count: usize,
    pub videos_count: usize,
    pub stories_active_count: usize,
    pub communities_count: usize,
    pub playlists_count: usize,
    pub conversations_count: usize,
    pub messages_count: usize,
    pub pinned_videos_count: usize,
    pub media_blobs_count: usize,
    pub commons_projects_count: usize,
    pub shard_receipts_count: usize,
    pub tips_count: usize,
    pub custom_lenses_count: usize,
}

/// Estado persistido atomicamente em `{home}/rhizome/state.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PersistedState {
    profiles: BTreeMap<String, ProfileManifest>,
    posts: BTreeMap<String, SocialPost>,
    stories: BTreeMap<String, StoryItem>,
    comments: BTreeMap<String, Comment>,
    /// chave: `"{target_post_id}|{author_node_id}|{kind}"`
    reactions: BTreeMap<String, Reaction>,
    /// chave: `"{follower_node_id}|{target_kind}|{target_id}"`
    follows: BTreeMap<String, FollowEdge>,
    communities: BTreeMap<String, Community>,
    video_manifests: BTreeMap<String, VideoManifest>,
    playlists: BTreeMap<String, PlaylistManifest>,
    groups: BTreeMap<String, GroupManifest>,
    /// Chaves simétricas de grupo decifradas localmente (hex 64 chars) — NUNCA replicadas!
    group_keys_hex: BTreeMap<String, String>,
    /// Histórico de chat por `conversation_id`.
    conversations: BTreeMap<String, Vec<DecryptedChatMessage>>,
    /// Nomes amigáveis de conversas (ex.: importações do WhatsApp ou grupos).
    conversation_titles: BTreeMap<String, String>,
    /// Mapeamento `msg_id -> conversation_id` para atualizar recibos rapidamente.
    msg_index: BTreeMap<String, String>,
    /// Mapa de `cid -> mime_type` para mídia armazenada localmente.
    blob_mimes: BTreeMap<String, String>,
    #[serde(default)]
    commons_projects: BTreeMap<String, CommonsProject>,
    #[serde(default)]
    commons_contributions: BTreeMap<String, CommonsContribution>,
    #[serde(default)]
    shard_receipts: BTreeMap<String, ShardReplicaReceipt>,
    #[serde(default)]
    tips: BTreeMap<String, TipRecord>,
    #[serde(default)]
    custom_lenses: BTreeMap<String, CustomDiscoveryLens>,
    #[serde(default)]
    video_views: BTreeMap<String, u64>,
    #[serde(default)]
    moderation_filters: ModerationFilters,
}

/// Motor central local-first + P2P do Mycelium Rhizome.
pub struct RhizomeStore {
    home: PathBuf,
    rhizome_dir: PathBuf,
    blobs_dir: PathBuf,
    blob_parts_dir: PathBuf,
    uploads_dir: PathBuf,
    media_dir: PathBuf,
    chunks_dir: PathBuf,
    legacy_chunks_dir: PathBuf,
    keys: SovereignKeys,
    state: PersistedState,
    uploads: HashMap<String, UploadSessionInfo>,
    pinned_cache: HashSet<String>,
    wallet_pubkey_hex: Option<String>,
}

impl RhizomeStore {
    /// Abre (ou inicializa) o armazenamento Rhizome dentro de `home`.
    pub fn open(home: impl AsRef<Path>) -> Result<Self, RhizomeError> {
        let home = home.as_ref().to_path_buf();
        let rhizome_dir = home.join("rhizome");
        let blobs_dir = home.join("sporebank").join("media_blobs");
        let blob_parts_dir = blobs_dir.join(".parts");
        let uploads_dir = rhizome_dir.join("uploads");
        let media_dir = home.join("sporebank").join("media");
        let chunks_dir = media_dir.join("chunks");
        let legacy_chunks_dir = home.join("sporebank").join("chunks");

        std::fs::create_dir_all(&rhizome_dir)?;
        std::fs::create_dir_all(&blob_parts_dir)?;
        std::fs::create_dir_all(&uploads_dir)?;
        std::fs::create_dir_all(&chunks_dir)?;

        let keys = SovereignKeys::load_or_create(&home)?;
        let state_path = rhizome_dir.join("state.json");
        let state: PersistedState = if state_path.exists() {
            let raw = std::fs::read(&state_path)?;
            serde_json::from_slice(&raw).unwrap_or_default()
        } else {
            PersistedState::default()
        };

        let pins_path = home.join("sporebank").join("pinned_media.json");
        let pinned_cache: HashSet<String> = PinManager::open(&pins_path)
            .map(|pm| pm.list_pins().into_iter().map(|c| c.to_string()).collect())
            .unwrap_or_default();

        let mut store = Self {
            home,
            rhizome_dir,
            blobs_dir,
            blob_parts_dir,
            uploads_dir,
            media_dir,
            chunks_dir,
            legacy_chunks_dir,
            keys,
            state,
            uploads: HashMap::new(),
            pinned_cache,
            wallet_pubkey_hex: None,
        };

        store.ensure_local_profile()?;
        store.hydrate_existing_media_manifests();
        store.prune_expired_stories();
        store.save()?;
        Ok(store)
    }

    pub fn chunks_dir(&self) -> PathBuf {
        self.chunks_dir.clone()
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn keys(&self) -> &SovereignKeys {
        &self.keys
    }

    /// Recarrega o estado do disco (útil para processos CLI que compartilham o mesmo `home`).
    pub fn reload(&mut self) -> Result<(), RhizomeError> {
        let state_path = self.rhizome_dir.join("state.json");
        if state_path.exists() {
            let raw = std::fs::read(&state_path)?;
            if let Ok(disk_state) = serde_json::from_slice::<PersistedState>(&raw) {
                self.state = disk_state;
            }
        }
        self.prune_expired_stories();
        Ok(())
    }

    fn save(&self) -> Result<(), RhizomeError> {
        let path = self.rhizome_dir.join("state.json");
        let tmp = self.rhizome_dir.join("state.json.tmp");
        let bytes = serde_json::to_vec_pretty(&self.state)?;
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Garante que o nó local tenha um `ProfileManifest` assinado e um `ChannelManifest` em `mycelium-media`.
    fn ensure_local_profile(&mut self) -> Result<(), RhizomeError> {
        let my_nid = self.keys.node_id_hex();
        if !self.state.profiles.contains_key(&my_nid) {
            let short = &my_nid[..8.min(my_nid.len())];
            let handle = format!("node_{short}");
            let channels_dir = self.home.join("sporebank").join("channels");
            let channel_id = ChannelStore::open(&channels_dir)
                .ok()
                .map(|cs| {
                    cs.create_channel(
                        &handle,
                        &format!("Nó {short}"),
                        &self.keys.ed25519_pubkey_hex(),
                        "Nó soberano na malha Mycelium Rhizome.",
                        "CC-BY-4.0",
                    )
                    .channel_id
                });

            let mut profile = ProfileManifest {
                node_id: String::new(),
                ed25519_pubkey_hex: String::new(),
                ghost_pubkey_hex: String::new(),
                pkarr_addr: String::new(),
                mlkem1024_pubkey_hex: String::new(),
                handle,
                display_name: format!("Criador {short}"),
                bio: "Soberano na rede Spatiradix — Vídeo, Feed, Comunidades e Chat Pós-Quântico.".into(),
                avatar_cid: None,
                banner_cid: None,
                channel_id,
                links: vec![],
                wallet_pubkey_hex: self.wallet_pubkey_hex.clone(),
                revision: 1,
                updated_at: unix_now(),
                signature: String::new(),
            };
            profile.sign(&self.keys)?;
            self.state.profiles.insert(my_nid, profile);
        }
        Ok(())
    }

    /// Carrega manifestos de vídeo previamente publicados via `mycelium media publish` no mesmo nó
    /// (incluindo playlists legadas e chunks `.bin` em `sporebank/chunks/`) e garante que tenham
    /// um `SocialPost` visível no Feed e no Tube.
    fn hydrate_existing_media_manifests(&mut self) {
        if let Ok(entries) = std::fs::read_dir(&self.media_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(bytes) = std::fs::read(&p) {
                        if let Ok(vm) = serde_json::from_slice::<VideoManifest>(&bytes) {
                            if let Ok(cid) = vm.content_id() {
                                self.state
                                    .video_manifests
                                    .entry(cid.to_string())
                                    .or_insert(vm);
                            }
                        }
                    }
                }
            }
        }

        // Hidrata playlists salvas em `sporebank/playlists/*.json`
        let playlists_dir = self.home.join("sporebank").join("playlists");
        if let Ok(entries) = std::fs::read_dir(&playlists_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("json") {
                    if let Ok(bytes) = std::fs::read(&p) {
                        if let Ok(pl) = serde_json::from_slice::<PlaylistManifest>(&bytes) {
                            self.state
                                .playlists
                                .entry(pl.playlist_id.clone())
                                .or_insert(pl);
                        }
                    }
                }
            }
        }

        // Para cada VideoManifest ainda sem SocialPost correspondente, cria post local assinado
        let linked_cids: HashSet<String> = self
            .state
            .posts
            .values()
            .filter_map(|p| p.video_manifest_cid.clone())
            .collect();
        let unlinked: Vec<(String, VideoManifest)> = self
            .state
            .video_manifests
            .iter()
            .filter(|(cid, _)| !linked_cids.contains(*cid))
            .map(|(cid, vm)| (cid.clone(), vm.clone()))
            .collect();

        if !unlinked.is_empty() {
            let prof = self.local_profile();
            for (cid_str, vm) in unlinked {
                let is_short = vm.content_type.eq_ignore_ascii_case("short");
                let attachment = MediaAttachment {
                    cid: cid_str.clone(),
                    mime_type: if vm.mime_type.is_empty() {
                        "video/mp4".into()
                    } else {
                        vm.mime_type.clone()
                    },
                    byte_size: vm.total_byte_size,
                    filename: format!("{}.mp4", vm.video_id),
                    width: None,
                    height: None,
                    duration_secs: Some(vm.duration_seconds),
                    alt_text: vm.title.clone(),
                    is_chunked_video: true,
                };
                let mut post = SocialPost {
                    post_id: String::new(),
                    author_node_id: String::new(),
                    author_pubkey_hex: String::new(),
                    author_handle: prof.handle.clone(),
                    kind: if is_short {
                        PostKind::Short
                    } else {
                        PostKind::Video
                    },
                    title: Some(vm.title.clone()),
                    body: vm.description.clone(),
                    media: vec![attachment],
                    video_manifest_cid: Some(cid_str.clone()),
                    thumbnail_cid: vm.thumbnail_cid.map(|c| c.to_string()),
                    channel_id: Some(vm.channel_id.clone()),
                    community_id: None,
                    content_type: Some(if vm.content_type.is_empty() {
                        "longform".into()
                    } else {
                        vm.content_type.clone()
                    }),
                    commons_project_id: None,
                    tags: vm.tags.clone(),
                    mentions: vec![],
                    reply_to: None,
                    repost_of: None,
                    quote_of: None,
                    location: None,
                    license: vm.license.clone(),
                    external_origin: ExternalOrigin::Native,
                    created_at: vm.published_at_unix,
                    signature: String::new(),
                };
                if post.finalize_and_sign(&self.keys).is_ok() {
                    self.state.posts.insert(post.post_id.clone(), post);
                }
            }
        }

        // Emite recibos locais para vídeos que já tenham chunks presentes em disco
        let cids: Vec<String> = self.state.video_manifests.keys().cloned().collect();
        for cid in cids {
            let _ = self.issue_local_shard_receipts(&cid, "local_node");
        }
    }

    /// Resolve o caminho físico de um chunk de vídeo em `rhizome/media/chunks/<cid>` ou no layout
    /// legado do `mycelium media publish` (`sporebank/chunks/<cid>.bin` / `sporebank/chunks/<cid>`).
    pub fn resolve_chunk_path(&self, chunk_cid: &str) -> Option<PathBuf> {
        if !is_safe_cid(chunk_cid) {
            return None;
        }
        let primary = self.chunks_dir.join(chunk_cid);
        if primary.exists() {
            return Some(primary);
        }
        let legacy_bin = self.legacy_chunks_dir.join(format!("{chunk_cid}.bin"));
        if legacy_bin.exists() {
            return Some(legacy_bin);
        }
        let legacy_plain = self.legacy_chunks_dir.join(chunk_cid);
        if legacy_plain.exists() {
            return Some(legacy_plain);
        }
        None
    }

    pub fn set_wallet_pubkey_hex(&mut self, wallet_hex: String) -> Result<(), RhizomeError> {
        self.wallet_pubkey_hex = Some(wallet_hex.clone());
        let mut prof = self.local_profile();
        if prof.wallet_pubkey_hex.as_deref() != Some(&wallet_hex) {
            prof.wallet_pubkey_hex = Some(wallet_hex);
            prof.revision += 1;
            prof.updated_at = unix_now();
            prof.sign(&self.keys)?;
            self.state.profiles.insert(prof.node_id.clone(), prof);
            self.save()?;
        }
        Ok(())
    }

    pub fn local_profile(&self) -> ProfileManifest {
        self.state
            .profiles
            .get(&self.keys.node_id_hex())
            .cloned()
            .expect("perfil local sempre inicializado")
    }

    /// Atualiza e assina o perfil soberano local, retornando o `SyncEnvelope` para propagação P2P.
    pub fn update_profile(
        &mut self,
        handle: Option<String>,
        display_name: Option<String>,
        bio: Option<String>,
        avatar_cid: Option<String>,
        banner_cid: Option<String>,
        links: Option<Vec<String>>,
    ) -> Result<(ProfileManifest, SyncEnvelope, Option<Plot>), RhizomeError> {
        let mut prof = self.local_profile();
        if let Some(h) = handle {
            let clean = h.trim().trim_start_matches('@').to_string();
            validate_handle(&clean)?;
            prof.handle = clean;
        }
        if let Some(name) = display_name {
            let trimmed = name.trim().to_string();
            if !trimmed.is_empty() {
                prof.display_name = trimmed;
            }
        }
        if let Some(b) = bio {
            prof.bio = b.trim().to_string();
        }
        if let Some(av) = avatar_cid {
            prof.avatar_cid = if av.trim().is_empty() { None } else { Some(av) };
        }
        if let Some(bn) = banner_cid {
            prof.banner_cid = if bn.trim().is_empty() { None } else { Some(bn) };
        }
        if let Some(l) = links {
            prof.links = l;
        }
        if let Some(ref w) = self.wallet_pubkey_hex {
            prof.wallet_pubkey_hex = Some(w.clone());
        }
        prof.revision += 1;
        prof.updated_at = unix_now();
        prof.sign(&self.keys)?;

        self.state
            .profiles
            .insert(self.keys.node_id_hex(), prof.clone());

        let env = SyncEnvelope::Profile(prof.clone());
        let plot = self.deposit_sync_envelope_plot(&env).ok();
        self.save()?;
        Ok((prof, env, plot))
    }

    pub fn list_profiles(&self) -> Vec<ProfileManifest> {
        self.state.profiles.values().cloned().collect()
    }

    pub fn get_profile(&self, node_id_or_handle: &str) -> Option<ProfileManifest> {
        if let Some(p) = self.state.profiles.get(node_id_or_handle) {
            return Some(p.clone());
        }
        let target = node_id_or_handle.trim_start_matches('@').to_ascii_lowercase();
        self.state
            .profiles
            .values()
            .find(|p| {
                p.handle.to_ascii_lowercase() == target
                    || p.pkarr_addr == node_id_or_handle
                    || p.ghost_pubkey_hex == node_id_or_handle
            })
            .cloned()
    }

    // ========================================================================
    // MÍDIA (BLOBS + VÍDEO CHUNKED BLAKE3 VIA MYCELIUM-MEDIA)
    // ========================================================================

    /// Armazena um anexo de imagem/áudio/documento em disco (O(1)) e retorna seu `MediaAttachment`
    /// + pacotes `MediaChunkPacket` de 32 KiB prontos para replicação P2P para todos os peers!
    pub fn store_media_blob(
        &mut self,
        filename: &str,
        mime_type: &str,
        bytes: &[u8],
        alt_text: &str,
        duration_secs: Option<u32>,
    ) -> Result<(MediaAttachment, Vec<MediaChunkPacket>), RhizomeError> {
        if bytes.is_empty() {
            return Err(RhizomeError::InvalidInput("mídia vazia".into()));
        }
        if bytes.len() > MAX_SINGLE_BLOB_BYTES {
            return Err(RhizomeError::InvalidInput(format!(
                "blob excede limite de {} bytes",
                MAX_SINGLE_BLOB_BYTES
            )));
        }

        let effective_mime = if mime_type.trim().is_empty() || mime_type == "application/octet-stream" {
            detect_mime_from_bytes(bytes).to_string()
        } else {
            mime_type.trim().to_string()
        };

        let cid = ContentId::of(bytes).to_string();
        let blob_path = self.blobs_dir.join(&cid);
        if !blob_path.exists() {
            std::fs::write(&blob_path, bytes)?;
        }
        self.state
            .blob_mimes
            .insert(cid.clone(), effective_mime.clone());

        let packets = slice_blob_to_packets(&cid, &effective_mime, bytes);

        let att = MediaAttachment {
            cid,
            mime_type: effective_mime,
            byte_size: bytes.len() as u64,
            filename: sanitize_filename(filename),
            width: None,
            height: None,
            duration_secs,
            alt_text: alt_text.to_string(),
            is_chunked_video: false,
        };
        self.save()?;
        Ok((att, packets))
    }

    /// Lê bytes + mime_type real de um blob de mídia (detecta magic bytes se necessário para `nosniff`).
    pub fn load_media_blob(&self, cid: &str) -> Option<(Vec<u8>, String)> {
        if !is_safe_cid(cid) {
            return None;
        }
        let path = self.blobs_dir.join(cid);
        if let Ok(bytes) = std::fs::read(&path) {
            if ContentId::of(&bytes).to_string() == cid {
                let stored = self.state.blob_mimes.get(cid).map(|s| s.as_str()).unwrap_or("");
                let mime = if stored.is_empty() || stored == "application/octet-stream" {
                    detect_mime_from_bytes(&bytes).to_string()
                } else {
                    stored.to_string()
                };
                return Some((bytes, mime));
            }
        }
        None
    }

    /// Verifica rapidamente se um blob existe localmente em disco.
    pub fn has_media_blob(&self, cid: &str) -> bool {
        is_safe_cid(cid) && self.blobs_dir.join(cid).exists()
    }

    /// Gera pacotes `MediaChunkPacket` de 32 KiB a partir de um blob armazenado localmente.
    pub fn blob_to_packets(&self, cid: &str) -> Vec<MediaChunkPacket> {
        let Some((bytes, mime)) = self.load_media_blob(cid) else {
            return Vec::new();
        };
        slice_blob_to_packets(cid, &mime, &bytes)
    }

    /// Gera pacotes `MediaChunkPacket` de 32 KiB para os chunks de um vídeo (`missing_indices` vazio = todos).
    pub fn video_to_packets(&self, manifest_cid: &str, missing_indices: &[u32]) -> Vec<MediaChunkPacket> {
        let Some(manifest) = self.state.video_manifests.get(manifest_cid) else {
            return Vec::new();
        };
        let total = manifest.chunks.len() as u32;
        let filter: HashSet<u32> = missing_indices.iter().copied().collect();
        let mut out = Vec::new();
        for ch in &manifest.chunks {
            if !filter.is_empty() && !filter.contains(&ch.index) {
                continue;
            }
            let chunk_cid_str = ch.content_id.to_string();
            if let Some(chunk_path) = self.resolve_chunk_path(&chunk_cid_str) {
                if let Ok(bytes) = std::fs::read(&chunk_path) {
                    out.push(MediaChunkPacket {
                        asset_cid: manifest_cid.to_string(),
                        chunk_cid: chunk_cid_str,
                        chunk_index: ch.index,
                        total_chunks: total,
                        is_video_chunk: true,
                        mime_type: manifest.mime_type.clone(),
                        data_b64: BASE64.encode(&bytes),
                    });
                }
            }
        }
        out
    }

    /// Retorna os índices de chunks faltantes de um `VideoManifest` localmente.
    pub fn missing_video_chunk_indices(&self, manifest_cid: &str) -> Vec<u32> {
        let Some(manifest) = self.state.video_manifests.get(manifest_cid) else {
            return Vec::new();
        };
        manifest
            .chunks
            .iter()
            .filter(|ch| self.resolve_chunk_path(&ch.content_id.to_string()).is_none())
            .map(|ch| ch.index)
            .collect()
    }

    /// Absorve um `MediaChunkPacket` recebido da malha P2P com verificação BLAKE3 (zero `save()` por fatia).
    pub fn absorb_media_chunk(&mut self, packet: MediaChunkPacket) -> Result<bool, RhizomeError> {
        if !is_safe_cid(&packet.asset_cid) || !is_safe_cid(&packet.chunk_cid) {
            return Err(RhizomeError::InvalidInput("CID de chunk de mídia inválido".into()));
        }
        let raw = BASE64
            .decode(&packet.data_b64)
            .map_err(|e| RhizomeError::Corrupted(format!("base64 chunk inválido: {e}")))?;

        if packet.is_video_chunk {
            let expected: ContentId = packet
                .chunk_cid
                .parse()
                .map_err(|_| RhizomeError::Corrupted("chunk_cid inválido".into()))?;
            if !verify_chunk_integrity(&raw, &expected) {
                return Err(RhizomeError::Corrupted(format!(
                    "chunk de vídeo {} adulterado (BLAKE3 divergente)",
                    packet.chunk_index
                )));
            }
            let path = self.chunks_dir.join(&packet.chunk_cid);
            if !path.exists() {
                std::fs::write(&path, &raw)?;
                return Ok(true);
            }
            return Ok(false);
        }

        // Blob (imagem / áudio / documento)
        let blob_path = self.blobs_dir.join(&packet.asset_cid);
        if blob_path.exists() {
            return Ok(false);
        }

        let total = packet.total_chunks.max(1);
        if total == 1 {
            if ContentId::of(&raw).to_string() != packet.asset_cid {
                return Err(RhizomeError::Corrupted("blob adulterado (BLAKE3 divergente)".into()));
            }
            let mime = if packet.mime_type.is_empty() || packet.mime_type == "application/octet-stream" {
                detect_mime_from_bytes(&raw).to_string()
            } else {
                packet.mime_type
            };
            std::fs::write(&blob_path, &raw)?;
            self.state.blob_mimes.insert(packet.asset_cid, mime);
            return Ok(true);
        }

        if total > 512 || packet.chunk_index >= total {
            return Err(RhizomeError::InvalidInput("índice de fatia de blob fora do limite".into()));
        }
        let part_dir = self.blob_parts_dir.join(&packet.asset_cid);
        std::fs::create_dir_all(&part_dir)?;
        let part_file = part_dir.join(format!("{:06}.part", packet.chunk_index));
        if !part_file.exists() {
            std::fs::write(&part_file, &raw)?;
        }

        // Verifica se todas as `total` fatias chegaram
        for idx in 0..total {
            if !part_dir.join(format!("{idx:06}.part")).exists() {
                return Ok(false);
            }
        }

        // Monta e verifica integridade BLAKE3 do blob completo!
        let mut assembled = Vec::new();
        for idx in 0..total {
            let p = part_dir.join(format!("{idx:06}.part"));
            assembled.extend_from_slice(&std::fs::read(&p)?);
        }
        if ContentId::of(&assembled).to_string() != packet.asset_cid {
            let _ = std::fs::remove_dir_all(&part_dir);
            return Err(RhizomeError::Corrupted(
                "blob remontado falhou verificação BLAKE3 — descartado".into(),
            ));
        }

        let mime = if packet.mime_type.is_empty() || packet.mime_type == "application/octet-stream" {
            detect_mime_from_bytes(&assembled).to_string()
        } else {
            packet.mime_type
        };
        std::fs::write(&blob_path, &assembled)?;
        let _ = std::fs::remove_dir_all(&part_dir);
        self.state.blob_mimes.insert(packet.asset_cid, mime);
        Ok(true)
    }

    /// Identifica mídias (fotos/áudios ou chunks de vídeo) referenciadas por um `SyncEnvelope`
    /// que ainda não existem localmente, para disparar pull automático (`RhizomeMediaWant`).
    pub fn missing_media_for_envelope(&self, env: &SyncEnvelope) -> Vec<(String, bool, Vec<u32>)> {
        let mut wanted = Vec::new();
        match env {
            SyncEnvelope::Post(p) => {
                for m in &p.media {
                    if m.is_chunked_video {
                        let miss = self.missing_video_chunk_indices(&m.cid);
                        if !miss.is_empty() {
                            wanted.push((m.cid.clone(), true, miss));
                        }
                    } else if !self.has_media_blob(&m.cid) {
                        wanted.push((m.cid.clone(), false, vec![]));
                    }
                }
                if let Some(ref thumb) = p.thumbnail_cid {
                    if !self.has_media_blob(thumb) {
                        wanted.push((thumb.clone(), false, vec![]));
                    }
                }
            }
            SyncEnvelope::Story(s) => {
                if let Some(ref m) = s.media {
                    if !m.is_chunked_video && !self.has_media_blob(&m.cid) {
                        wanted.push((m.cid.clone(), false, vec![]));
                    }
                }
            }
            SyncEnvelope::VideoManifest { manifest_cid, .. } => {
                let miss = self.missing_video_chunk_indices(manifest_cid);
                if !miss.is_empty() {
                    wanted.push((manifest_cid.clone(), true, miss));
                }
            }
            SyncEnvelope::Profile(p) => {
                if let Some(ref av) = p.avatar_cid {
                    if !self.has_media_blob(av) {
                        wanted.push((av.clone(), false, vec![]));
                    }
                }
            }
            _ => {}
        }
        wanted
    }

    /// Retira o caminho do arquivo temporário de upload para processamento fora do Mutex.
    pub fn take_upload_session(
        &mut self,
        upload_id: &str,
    ) -> Result<(PathBuf, UploadSessionInfo, String, String), RhizomeError> {
        let info = self
            .uploads
            .remove(upload_id)
            .ok_or_else(|| RhizomeError::NotFound(format!("upload '{upload_id}' não encontrado")))?;
        let path = self.uploads_dir.join(format!("{upload_id}.part"));
        let profile = self.local_profile();
        let channel_id = profile
            .channel_id
            .clone()
            .unwrap_or_else(|| format!("ch_{}", &profile.node_id[..12]));
        Ok((path, info, self.keys.ed25519_pubkey_hex(), channel_id))
    }

    /// Consolida um vídeo já fatiado em disco (`PreparedVideoIngest`) em O(1) (< 5ms sob lock!).
    pub fn commit_prepared_video(
        &mut self,
        mut prepared: PreparedVideoIngest,
    ) -> Result<(SocialPost, VideoManifest, Vec<SyncEnvelope>, Vec<Plot>, Vec<MediaChunkPacket>), RhizomeError> {
        let profile = self.local_profile();
        let manifest_sig = self.keys.sign_domain(
            "mycelium-media/video-manifest/v1",
            prepared.manifest.canonical_payload().as_bytes(),
        );
        prepared.manifest.signature = manifest_sig;
        let manifest_cid = prepared
            .manifest
            .content_id()
            .map_err(RhizomeError::Corrupted)?;
        let manifest_cid_str = manifest_cid.to_string();

        // Persiste o VideoManifest no diretório compatível com `mycelium media watch`.
        let manifest_path = self.media_dir.join(format!("{manifest_cid_str}.json"));
        std::fs::write(&manifest_path, serde_json::to_vec_pretty(&prepared.manifest)?)?;
        self.state
            .video_manifests
            .insert(manifest_cid_str.clone(), prepared.manifest.clone());

        // Vincula o vídeo ao canal do criador no `mycelium-media::ChannelStore`.
        let channels_dir = self.home.join("sporebank").join("channels");
        if let Ok(cstore) = ChannelStore::open(&channels_dir) {
            let _ = cstore.add_video_to_channel(&prepared.channel_id, manifest_cid);
        }

        // Fixa automaticamente o próprio vídeo publicado no PinManager + cache RAM.
        let pins_path = self.home.join("sporebank").join("pinned_media.json");
        if let Ok(pm) = PinManager::open(&pins_path) {
            pm.pin(manifest_cid);
        }
        self.pinned_cache.insert(manifest_cid_str.clone());

        let attachment = MediaAttachment {
            cid: manifest_cid_str.clone(),
            mime_type: prepared.manifest.mime_type.clone(),
            byte_size: prepared.manifest.total_byte_size,
            filename: format!("{}.mp4", prepared.video_id),
            width: None,
            height: None,
            duration_secs: Some(prepared.manifest.duration_seconds),
            alt_text: prepared.manifest.title.clone(),
            is_chunked_video: true,
        };

        let is_short_post = prepared.meta.is_short
            || prepared.manifest.content_type.eq_ignore_ascii_case("short");
        let resolved_ct = if prepared.manifest.content_type.is_empty() {
            if is_short_post {
                "short".to_string()
            } else {
                "longform".to_string()
            }
        } else {
            prepared.manifest.content_type.clone()
        };

        let mut post = SocialPost {
            post_id: String::new(),
            author_node_id: String::new(),
            author_pubkey_hex: String::new(),
            author_handle: profile.handle,
            kind: if is_short_post {
                PostKind::Short
            } else {
                PostKind::Video
            },
            title: Some(prepared.manifest.title.clone()),
            body: prepared.manifest.description.clone(),
            media: vec![attachment],
            video_manifest_cid: Some(manifest_cid_str.clone()),
            thumbnail_cid: prepared.meta.thumbnail_cid,
            channel_id: Some(prepared.channel_id),
            community_id: prepared.meta.community_id,
            content_type: Some(resolved_ct),
            commons_project_id: prepared
                .meta
                .commons_project_id
                .filter(|s| !s.trim().is_empty()),
            tags: prepared.meta.tags,
            mentions: vec![],
            reply_to: None,
            repost_of: None,
            quote_of: None,
            location: None,
            license: prepared.manifest.license.clone(),
            external_origin: ExternalOrigin::Native,
            created_at: prepared.manifest.published_at_unix,
            signature: String::new(),
        };
        post.finalize_and_sign(&self.keys)?;
        self.state.posts.insert(post.post_id.clone(), post.clone());

        let vm_env = SyncEnvelope::sign_video_manifest(
            manifest_cid_str.clone(),
            prepared.manifest.clone(),
            &self.keys,
        )?;
        let post_env = SyncEnvelope::Post(post.clone());

        let (_, rcpt_envs) = self
            .issue_local_shard_receipts(&manifest_cid_str, "publisher")
            .unwrap_or_default();

        let mut plots = Vec::new();
        if let Ok(p) = self.deposit_sync_envelope_plot(&vm_env) {
            plots.push(p);
        }
        if let Ok(p) = self.deposit_sync_envelope_plot(&post_env) {
            plots.push(p);
        }

        // Prepara pacotes de replicação para vídeos moderados (vídeos enormes replicam sob demanda via Want)
        let packets = if prepared.manifest.chunks.len() <= 320 {
            self.video_to_packets(&manifest_cid_str, &[])
        } else {
            // Envia os primeiros 32 chunks (~1 MiB) imediatamente para instant-play; restante sob demanda!
            let head: Vec<u32> = (0..32).collect();
            self.video_to_packets(&manifest_cid_str, &head)
        };

        let mut envs = vec![vm_env, post_env];
        envs.extend(rcpt_envs.into_iter().take(32));

        self.save()?;
        Ok((post, prepared.manifest, envs, plots, packets))
    }

    /// Inicia uma sessão de upload em fatias (streaming de vídeo para o nó).
    pub fn start_upload_session(
        &mut self,
        filename: &str,
        mime_type: &str,
    ) -> Result<UploadSessionInfo, RhizomeError> {
        let mut salt = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);
        let upload_id = format!("up_{}", hex::encode(salt));
        let path = self.uploads_dir.join(format!("{upload_id}.part"));
        std::fs::write(&path, &[])?;

        let info = UploadSessionInfo {
            upload_id: upload_id.clone(),
            filename: sanitize_filename(filename),
            mime_type: if mime_type.is_empty() {
                "video/mp4".into()
            } else {
                mime_type.to_string()
            },
            received_bytes: 0,
            chunks_received: 0,
        };
        self.uploads.insert(upload_id, info.clone());
        Ok(info)
    }

    /// Acrescenta uma fatia de bytes a uma sessão de upload em andamento.
    pub fn append_upload_chunk(
        &mut self,
        upload_id: &str,
        bytes: &[u8],
    ) -> Result<UploadSessionInfo, RhizomeError> {
        use std::io::Write;
        let info = self
            .uploads
            .get_mut(upload_id)
            .ok_or_else(|| RhizomeError::NotFound(format!("upload '{upload_id}' não encontrado")))?;
        if info.received_bytes + bytes.len() as u64 > MAX_VIDEO_UPLOAD_BYTES {
            return Err(RhizomeError::InvalidInput(format!(
                "limite de {} MiB por vídeo excedido",
                MAX_VIDEO_UPLOAD_BYTES / (1024 * 1024)
            )));
        }
        let path = self.uploads_dir.join(format!("{upload_id}.part"));
        let mut file = std::fs::OpenOptions::new().append(true).open(&path)?;
        file.write_all(bytes)?;
        info.received_bytes += bytes.len() as u64;
        info.chunks_received += 1;
        Ok(info.clone())
    }

    /// Finaliza uma sessão de upload chunked via streaming em disco (versão síncrona usada em testes/CLI).
    pub fn finish_video_upload(
        &mut self,
        upload_id: &str,
        mut meta: VideoUploadMeta,
    ) -> Result<(SocialPost, VideoManifest, Vec<SyncEnvelope>, Vec<Plot>, Vec<MediaChunkPacket>), RhizomeError> {
        let (path, info, author_pk, channel_id) = self.take_upload_session(upload_id)?;
        if meta.mime_type.is_empty() {
            meta.mime_type = info.mime_type;
        }
        let prepared =
            prepare_video_ingest_from_file(&path, &self.chunks_dir, &author_pk, &channel_id, meta);
        let _ = std::fs::remove_file(&path);
        self.commit_prepared_video(prepared?)
    }

    /// Publica um vídeo completo (CLI / testes).
    pub fn publish_video_bytes(
        &mut self,
        media_data: &[u8],
        meta: VideoUploadMeta,
    ) -> Result<(SocialPost, VideoManifest, Vec<SyncEnvelope>, Vec<Plot>, Vec<MediaChunkPacket>), RhizomeError> {
        let profile = self.local_profile();
        let channel_id = profile
            .channel_id
            .clone()
            .unwrap_or_else(|| format!("ch_{}", &profile.node_id[..12]));
        let prepared = prepare_video_ingest(
            media_data,
            &self.chunks_dir,
            &self.keys.ed25519_pubkey_hex(),
            &channel_id,
            meta,
        )?;
        self.commit_prepared_video(prepared)
    }

    /// Lê um intervalo de bytes `[start..=end]` de um vídeo chunked, verificando integridade BLAKE3
    /// de cada chunk (`mycelium_media::verify_chunk_integrity`)! Suporta HTTP 206 Partial Content.
    pub fn read_video_range(
        &self,
        manifest_cid: &str,
        start: u64,
        end_inclusive: Option<u64>,
    ) -> Result<(Vec<u8>, u64, u64, u64, String), RhizomeError> {
        let manifest = self
            .state
            .video_manifests
            .get(manifest_cid)
            .ok_or_else(|| RhizomeError::NotFound(format!("vídeo {manifest_cid} não encontrado")))?;

        let total = manifest.total_byte_size;
        if total == 0 {
            return Err(RhizomeError::Corrupted("vídeo com 0 bytes".into()));
        }
        if start >= total {
            return Err(RhizomeError::InvalidInput("range fora do tamanho do vídeo".into()));
        }
        let end = end_inclusive
            .unwrap_or(total - 1)
            .min(total - 1);
        if end < start {
            return Err(RhizomeError::InvalidInput("range invertido".into()));
        }

        let mut out = Vec::with_capacity((end - start + 1) as usize);
        for chunk_info in &manifest.chunks {
            let chunk_start = chunk_info.offset_bytes;
            let chunk_end = chunk_start + chunk_info.byte_size as u64 - 1;
            if chunk_end < start || chunk_start > end {
                continue;
            }
            let chunk_cid_str = chunk_info.content_id.to_string();
            let chunk_path = self.resolve_chunk_path(&chunk_cid_str).ok_or_else(|| {
                RhizomeError::NotFound(format!(
                    "chunk {} ({}) ainda não replicado localmente",
                    chunk_info.index, chunk_cid_str
                ))
            })?;
            let chunk_bytes = std::fs::read(&chunk_path).map_err(|_| {
                RhizomeError::NotFound(format!(
                    "chunk {} ({}) ainda não replicado localmente",
                    chunk_info.index, chunk_cid_str
                ))
            })?;
            if !verify_chunk_integrity(&chunk_bytes, &chunk_info.content_id) {
                return Err(RhizomeError::Corrupted(format!(
                    "chunk {} corrompido: hash BLAKE3 divergente",
                    chunk_info.index
                )));
            }

            let slice_from = start.saturating_sub(chunk_start) as usize;
            let slice_to = (end.min(chunk_end) - chunk_start) as usize;
            out.extend_from_slice(&chunk_bytes[slice_from..=slice_to]);
        }

        Ok((out, start, end, total, manifest.mime_type.clone()))
    }

    pub fn get_video_manifest(&self, manifest_cid: &str) -> Option<VideoManifest> {
        self.state.video_manifests.get(manifest_cid).cloned()
    }

    pub fn pin_video(&mut self, manifest_cid: &str) -> Result<bool, RhizomeError> {
        let _manifest = self
            .state
            .video_manifests
            .get(manifest_cid)
            .ok_or_else(|| RhizomeError::NotFound(format!("vídeo {manifest_cid} não encontrado")))?;
        let cid: ContentId = manifest_cid
            .parse()
            .map_err(|_| RhizomeError::InvalidInput("CID de vídeo inválido".into()))?;
        let pins_path = self.home.join("sporebank").join("pinned_media.json");
        let pm = PinManager::open(&pins_path)?;
        self.pinned_cache.insert(manifest_cid.to_string());
        let newly_pinned = pm.pin(cid);
        let _ = self.issue_local_shard_receipts(manifest_cid, "pinned_seeder");
        self.save()?;
        Ok(newly_pinned)
    }

    pub fn is_video_pinned(&self, manifest_cid: &str) -> bool {
        self.pinned_cache.contains(manifest_cid)
    }

    // ========================================================================
    // POSTS, STORIES (ISOTOPE), COMENTÁRIOS, REAÇÕES, COMUNIDADES, PLAYLISTS
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    pub fn create_post(
        &mut self,
        kind: PostKind,
        title: Option<String>,
        body: String,
        media: Vec<MediaAttachment>,
        community_id: Option<String>,
        tags: Vec<String>,
        reply_to: Option<String>,
        repost_of: Option<String>,
        quote_of: Option<String>,
        location: Option<String>,
    ) -> Result<(SocialPost, SyncEnvelope, Option<Plot>), RhizomeError> {
        if body.trim().is_empty() && media.is_empty() && repost_of.is_none() {
            return Err(RhizomeError::InvalidInput(
                "publicação precisa de texto, mídia ou referência de repost".into(),
            ));
        }
        let prof = self.local_profile();
        let mut post = SocialPost {
            post_id: String::new(),
            author_node_id: String::new(),
            author_pubkey_hex: String::new(),
            author_handle: prof.handle,
            kind,
            title: title.filter(|t| !t.trim().is_empty()),
            body: body.trim().to_string(),
            media,
            video_manifest_cid: None,
            thumbnail_cid: None,
            channel_id: prof.channel_id,
            community_id: community_id.filter(|c| !c.trim().is_empty()),
            content_type: None,
            commons_project_id: None,
            tags,
            mentions: vec![],
            reply_to: reply_to.filter(|s| !s.trim().is_empty()),
            repost_of: repost_of.filter(|s| !s.trim().is_empty()),
            quote_of: quote_of.filter(|s| !s.trim().is_empty()),
            location: location.filter(|s| !s.trim().is_empty()),
            license: "CC-BY-4.0".into(),
            external_origin: ExternalOrigin::Native,
            created_at: unix_now(),
            signature: String::new(),
        };
        post.finalize_and_sign(&self.keys)?;
        self.state.posts.insert(post.post_id.clone(), post.clone());
        let env = SyncEnvelope::Post(post.clone());
        let plot = self.deposit_sync_envelope_plot(&env).ok();
        self.save()?;
        Ok((post, env, plot))
    }

    /// Cria um Story efêmero (Instagram/WhatsApp Status) pronto para propagar via Isotope (`Atom`).
    pub fn create_story(
        &mut self,
        caption: String,
        background: Option<String>,
        media: Option<MediaAttachment>,
        ttl_secs: Option<u64>,
    ) -> Result<(StoryItem, String, Atom, SyncEnvelope), RhizomeError> {
        if caption.trim().is_empty() && media.is_none() {
            return Err(RhizomeError::InvalidInput(
                "story precisa de legenda ou mídia".into(),
            ));
        }
        let now = unix_now();
        let ttl = ttl_secs.unwrap_or(DEFAULT_STORY_TTL_SECS).clamp(60, 7 * 86_400);
        let prof = self.local_profile();
        let mut story = StoryItem {
            story_id: String::new(),
            author_node_id: String::new(),
            author_pubkey_hex: String::new(),
            author_handle: prof.handle,
            caption: caption.trim().to_string(),
            background: background.unwrap_or_else(|| {
                "linear-gradient(135deg, #065f46 0%, #0e7490 50%, #581c87 100%)".into()
            }),
            media,
            created_at: now,
            expires_at: now + ttl,
            signature: String::new(),
        };
        story.finalize_and_sign(&self.keys)?;
        let isotope_key = story.isotope_key();
        let atom = Atom {
            value: serde_json::to_vec(&story)?,
            clock: now,
        };

        self.state
            .stories
            .insert(story.story_id.clone(), story.clone());
        let env = SyncEnvelope::Story(story.clone());
        self.save()?;
        Ok((story, isotope_key, atom, env))
    }

    pub fn prune_expired_stories(&mut self) -> usize {
        let now = unix_now();
        let before = self.state.stories.len();
        self.state.stories.retain(|_, s| !s.is_expired(now));
        before.saturating_sub(self.state.stories.len())
    }

    pub fn list_active_stories(&mut self) -> Vec<StoryItem> {
        self.prune_expired_stories();
        let mut list: Vec<StoryItem> = self.state.stories.values().cloned().collect();
        list.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        list
    }

    /// Absorve um Story recebido via `Isotope` (`Envelope::AtomSync` em chave `rhizome/story/...`).
    pub fn absorb_isotope_story(&mut self, atom: &Atom) -> Result<bool, RhizomeError> {
        let story: StoryItem = serde_json::from_slice(&atom.value)?;
        story.verify()?;
        if story.is_expired(unix_now()) {
            return Ok(false);
        }
        let inserted = !self.state.stories.contains_key(&story.story_id);
        self.state
            .stories
            .insert(story.story_id.clone(), story);
        if inserted {
            self.save()?;
        }
        Ok(inserted)
    }

    pub fn add_comment(
        &mut self,
        target_post_id: String,
        parent_comment_id: Option<String>,
        body: String,
    ) -> Result<(Comment, SyncEnvelope, Option<Plot>), RhizomeError> {
        if body.trim().is_empty() {
            return Err(RhizomeError::InvalidInput("comentário vazio".into()));
        }
        let prof = self.local_profile();
        let mut comment = Comment {
            comment_id: String::new(),
            target_post_id,
            parent_comment_id: parent_comment_id.filter(|s| !s.trim().is_empty()),
            author_node_id: String::new(),
            author_pubkey_hex: String::new(),
            author_handle: prof.handle,
            body: body.trim().to_string(),
            created_at: unix_now(),
            signature: String::new(),
        };
        comment.finalize_and_sign(&self.keys)?;
        self.state
            .comments
            .insert(comment.comment_id.clone(), comment.clone());
        let env = SyncEnvelope::Comment(comment.clone());
        let plot = self.deposit_sync_envelope_plot(&env).ok();
        self.save()?;
        Ok((comment, env, plot))
    }

    pub fn toggle_reaction(
        &mut self,
        target_post_id: String,
        kind: ReactionKind,
    ) -> Result<(Reaction, SyncEnvelope, Option<Plot>), RhizomeError> {
        let key = reaction_key(&target_post_id, &self.keys.node_id_hex(), &kind);
        let currently_active = self
            .state
            .reactions
            .get(&key)
            .map(|r| r.active)
            .unwrap_or(false);
        let mut reaction = Reaction {
            target_post_id,
            author_node_id: String::new(),
            author_pubkey_hex: String::new(),
            kind,
            active: !currently_active,
            updated_at: unix_now(),
            signature: String::new(),
        };
        reaction.sign(&self.keys)?;
        self.state.reactions.insert(key, reaction.clone());
        let env = SyncEnvelope::Reaction(reaction.clone());
        let plot = self.deposit_sync_envelope_plot(&env).ok();
        self.save()?;
        Ok((reaction, env, plot))
    }

    pub fn toggle_follow(
        &mut self,
        target_id: String,
        target_kind: String,
    ) -> Result<(FollowEdge, SyncEnvelope, Option<Plot>), RhizomeError> {
        let key = follow_key(&self.keys.node_id_hex(), &target_kind, &target_id);
        let currently_active = self
            .state
            .follows
            .get(&key)
            .map(|f| f.active)
            .unwrap_or(false);
        let mut edge = FollowEdge {
            follower_node_id: String::new(),
            follower_pubkey_hex: String::new(),
            target_id,
            target_kind,
            active: !currently_active,
            updated_at: unix_now(),
            signature: String::new(),
        };
        edge.sign(&self.keys)?;
        self.state.follows.insert(key, edge.clone());
        let env = SyncEnvelope::Follow(edge.clone());
        let plot = self.deposit_sync_envelope_plot(&env).ok();
        self.save()?;
        Ok((edge, env, plot))
    }

    pub fn create_community(
        &mut self,
        slug: String,
        name: String,
        description: String,
        rules: Vec<String>,
        visibility: CommunityVisibility,
    ) -> Result<(Community, SyncEnvelope, Option<Plot>), RhizomeError> {
        if name.trim().is_empty() {
            return Err(RhizomeError::InvalidInput("nome da comunidade obrigatório".into()));
        }
        let mut com = Community {
            community_id: String::new(),
            slug: slug.trim().to_ascii_lowercase(),
            name: name.trim().to_string(),
            description: description.trim().to_string(),
            creator_node_id: String::new(),
            creator_pubkey_hex: String::new(),
            moderators: vec![self.keys.node_id_hex()],
            rules,
            visibility,
            revision: 1,
            updated_at: unix_now(),
            signature: String::new(),
        };
        com.finalize_and_sign(&self.keys)?;
        self.state
            .communities
            .insert(com.community_id.clone(), com.clone());

        // Criador entra automaticamente na comunidade
        let mut join_edge = FollowEdge {
            follower_node_id: String::new(),
            follower_pubkey_hex: String::new(),
            target_id: com.community_id.clone(),
            target_kind: "community".into(),
            active: true,
            updated_at: unix_now(),
            signature: String::new(),
        };
        join_edge.sign(&self.keys)?;
        self.state.follows.insert(
            follow_key(&self.keys.node_id_hex(), "community", &com.community_id),
            join_edge,
        );

        let env = SyncEnvelope::Community(com.clone());
        let plot = self.deposit_sync_envelope_plot(&env).ok();
        self.save()?;
        Ok((com, env, plot))
    }

    pub fn list_communities(&self) -> Vec<(Community, usize, bool)> {
        let my_nid = self.keys.node_id_hex();
        self.state
            .communities
            .values()
            .map(|c| {
                let members = self
                    .state
                    .follows
                    .values()
                    .filter(|f| f.active && f.target_kind == "community" && f.target_id == c.community_id)
                    .count();
                let joined = self
                    .state
                    .follows
                    .get(&follow_key(&my_nid, "community", &c.community_id))
                    .map(|f| f.active)
                    .unwrap_or(false);
                (c.clone(), members, joined)
            })
            .collect()
    }

    pub fn create_playlist(
        &mut self,
        title: String,
        description: String,
        video_cids: Vec<String>,
    ) -> Result<(PlaylistManifest, SyncEnvelope), RhizomeError> {
        if title.trim().is_empty() {
            return Err(RhizomeError::InvalidInput("título da playlist obrigatório".into()));
        }
        let playlist_id = format!(
            "pl_{}",
            hex::encode(
                &blake3::hash(
                    format!("{}:{}:{}", self.keys.node_id_hex(), title, unix_now()).as_bytes()
                )
                .as_bytes()[..10]
            )
        );
        let videos: Vec<ContentId> = video_cids
            .iter()
            .filter_map(|c| c.parse::<ContentId>().ok())
            .collect();
        let mut pl = PlaylistManifest {
            playlist_id: playlist_id.clone(),
            owner_pubkey: self.keys.ed25519_pubkey_hex(),
            title: title.trim().to_string(),
            description: description.trim().to_string(),
            videos,
            is_collaborative: false,
            revision: 1,
            signature: String::new(),
        };
        pl.signature = self
            .keys
            .sign_domain("mycelium-media/playlist/v1", pl.playlist_id.as_bytes());
        self.state.playlists.insert(playlist_id, pl.clone());
        let env = SyncEnvelope::Playlist(pl.clone());
        let _ = self.deposit_sync_envelope_plot(&env);
        self.save()?;
        Ok((pl, env))
    }

    pub fn list_playlists(&self) -> Vec<PlaylistManifest> {
        self.state.playlists.values().cloned().collect()
    }

    // ========================================================================
    // MYCELIUM COMMONS PROTOCOL (MCP), SHARD RECEIPTS, GORJETAS & LENTES (MMP/MEP)
    // ========================================================================

    #[allow(clippy::too_many_arguments)]
    pub fn create_commons_project(
        &mut self,
        slug: String,
        title: String,
        summary: String,
        full_proposal: String,
        funding_goal: f64,
        spores_pool_allocated: u64,
        target_release_date: String,
        budget_ledger: Vec<BudgetItem>,
        split_agreement: Vec<SplitContractParty>,
        milestones: Vec<MilestoneItem>,
    ) -> Result<(CommonsProject, SyncEnvelope, Option<Plot>), RhizomeError> {
        let prof = self.local_profile();
        let mut proj = CommonsProject {
            project_id: String::new(),
            slug,
            title: title.trim().to_string(),
            summary: summary.trim().to_string(),
            full_proposal: if full_proposal.trim().is_empty() {
                summary.trim().to_string()
            } else {
                full_proposal.trim().to_string()
            },
            funding_goal,
            spores_pool_allocated,
            lead_node_id: String::new(),
            lead_pubkey_hex: String::new(),
            lead_handle: prof.handle,
            status: "funding".into(),
            target_release_date: if target_release_date.trim().is_empty() {
                "2026-Q4".into()
            } else {
                target_release_date.trim().to_string()
            },
            budget_ledger,
            split_agreement,
            milestones,
            revision: 1,
            updated_at: unix_now(),
            signature: String::new(),
        };
        proj.finalize_and_sign(&self.keys)?;
        self.state
            .commons_projects
            .insert(proj.project_id.clone(), proj.clone());
        let env = SyncEnvelope::CommonsProject(proj.clone());
        let plot = self.deposit_sync_envelope_plot(&env).ok();
        self.save()?;
        Ok((proj, env, plot))
    }

    pub fn contribute_to_commons(
        &mut self,
        project_id_or_slug: &str,
        contributor_name: String,
        amount_p2p: f64,
        spores_contributed: u64,
        message: String,
    ) -> Result<(CommonsContribution, CommonsProjectView, SyncEnvelope, Option<Plot>), RhizomeError> {
        let proj = self
            .find_commons_project(project_id_or_slug)
            .ok_or_else(|| {
                RhizomeError::NotFound(format!("projeto MCP '{project_id_or_slug}' não encontrado"))
            })?;
        let prof = self.local_profile();
        let mut contrib = CommonsContribution {
            contribution_id: String::new(),
            project_id: proj.project_id.clone(),
            contributor_node_id: String::new(),
            contributor_pubkey_hex: String::new(),
            contributor_name: if contributor_name.trim().is_empty() {
                prof.display_name
            } else {
                contributor_name.trim().to_string()
            },
            amount_p2p,
            spores_contributed,
            message: message.trim().to_string(),
            created_at: unix_now(),
            signature: String::new(),
        };
        contrib.finalize_and_sign(&self.keys)?;
        self.state
            .commons_contributions
            .insert(contrib.contribution_id.clone(), contrib.clone());
        let view = self.build_commons_view(&proj);
        let env = SyncEnvelope::CommonsContribution(contrib.clone());
        let plot = self.deposit_sync_envelope_plot(&env).ok();
        self.save()?;
        Ok((contrib, view, env, plot))
    }

    fn find_commons_project(&self, id_or_slug: &str) -> Option<CommonsProject> {
        if let Some(p) = self.state.commons_projects.get(id_or_slug) {
            return Some(p.clone());
        }
        let target = id_or_slug.trim().to_ascii_lowercase();
        self.state
            .commons_projects
            .values()
            .find(|p| p.slug.to_ascii_lowercase() == target)
            .cloned()
    }

    fn build_commons_view(&self, proj: &CommonsProject) -> CommonsProjectView {
        let mut contributions: Vec<CommonsContribution> = self
            .state
            .commons_contributions
            .values()
            .filter(|c| c.project_id == proj.project_id)
            .cloned()
            .collect();
        contributions.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        let current_raised: f64 = contributions.iter().map(|c| c.amount_p2p).sum();
        let spores_contributed: u64 = contributions.iter().map(|c| c.spores_contributed).sum();
        let linked_video_cids: Vec<String> = self
            .state
            .posts
            .values()
            .filter(|p| p.commons_project_id.as_deref() == Some(proj.project_id.as_str()))
            .filter_map(|p| p.video_manifest_cid.clone())
            .collect();
        CommonsProjectView {
            project: proj.clone(),
            current_raised,
            spores_contributed,
            contributions_count: contributions.len(),
            contributions,
            linked_video_cids,
        }
    }

    pub fn list_commons_projects(&self) -> Vec<CommonsProjectView> {
        let mut list: Vec<CommonsProjectView> = self
            .state
            .commons_projects
            .values()
            .map(|p| self.build_commons_view(p))
            .collect();
        list.sort_by(|a, b| b.project.updated_at.cmp(&a.project.updated_at));
        list
    }

    pub fn get_commons_project(&self, id_or_slug: &str) -> Option<CommonsProjectView> {
        self.find_commons_project(id_or_slug)
            .map(|p| self.build_commons_view(&p))
    }

    /// Gera recibos criptográficos reais (`ShardReplicaReceipt` usando desafio `ProofOfStorage`)
    /// para todos os chunks de vídeo verificados em disco no nó local.
    pub fn issue_local_shard_receipts(
        &mut self,
        manifest_cid: &str,
        device_type: &str,
    ) -> Result<(Vec<ShardReplicaReceipt>, Vec<SyncEnvelope>), RhizomeError> {
        let manifest = self
            .state
            .video_manifests
            .get(manifest_cid)
            .cloned()
            .ok_or_else(|| RhizomeError::NotFound(format!("vídeo {manifest_cid} não encontrado")))?;

        let my_nid = self.keys.node_id_hex();
        let handle = self.local_profile().handle;
        let now = unix_now();
        let mut created = Vec::new();
        let mut envs = Vec::new();

        for ch in &manifest.chunks {
            let chunk_cid_str = ch.content_id.to_string();
            let receipt_id = ShardReplicaReceipt::derive_id(manifest_cid, ch.index, &my_nid);
            if self.state.shard_receipts.contains_key(&receipt_id) {
                continue;
            }
            let Some(path) = self.resolve_chunk_path(&chunk_cid_str) else {
                continue;
            };
            let Ok(bytes) = std::fs::read(&path) else {
                continue;
            };
            if !verify_chunk_integrity(&bytes, &ch.content_id) {
                continue;
            }
            let pos = ProofOfStorage::create_challenge_response(
                ch.content_id,
                &my_nid,
                &bytes,
                now ^ (ch.index as u64 + 1),
            );
            let mut rcpt = ShardReplicaReceipt {
                receipt_id: String::new(),
                video_manifest_cid: manifest_cid.to_string(),
                chunk_index: ch.index,
                chunk_cid: chunk_cid_str,
                node_id: String::new(),
                node_pubkey_hex: String::new(),
                node_handle: handle.clone(),
                device_type: device_type.to_string(),
                latency_ms: 8,
                sampled_hash: pos.sampled_hash,
                verified_at: now,
                signature: String::new(),
            };
            if rcpt.finalize_and_sign(&self.keys).is_ok() {
                self.state
                    .shard_receipts
                    .insert(rcpt.receipt_id.clone(), rcpt.clone());
                envs.push(SyncEnvelope::ShardReceipt(rcpt.clone()));
                created.push(rcpt);
            }
        }
        Ok((created, envs))
    }

    fn compute_video_metrics(
        &self,
        manifest_cid: Option<&str>,
        post_id: Option<&str>,
    ) -> (u64, u64, f64, u8, usize) {
        let views_count = manifest_cid
            .and_then(|c| self.state.video_views.get(c).copied())
            .unwrap_or(0);

        let mut tips_total_spores = 0u64;
        let mut tips_total_p2p = 0f64;
        for tip in self.state.tips.values() {
            let match_post = post_id.is_some_and(|pid| tip.target_post_id == pid);
            let match_vid = manifest_cid
                .is_some_and(|cid| tip.video_manifest_cid.as_deref() == Some(cid));
            if match_post || match_vid {
                if tip.asset_type == "SPORES" {
                    tips_total_spores = tips_total_spores.saturating_add(tip.amount);
                } else {
                    tips_total_p2p += tip.amount as f64;
                }
            }
        }

        let Some(mcid) = manifest_cid else {
            return (views_count, tips_total_spores, tips_total_p2p, 100, 1);
        };
        let Some(manifest) = self.state.video_manifests.get(mcid) else {
            return (views_count, tips_total_spores, tips_total_p2p, 0, 0);
        };

        let mut pairs: HashSet<(u32, String)> = HashSet::new();
        let mut distinct_nodes: HashSet<String> = HashSet::new();
        for r in self.state.shard_receipts.values() {
            if r.video_manifest_cid == mcid {
                pairs.insert((r.chunk_index, r.node_id.clone()));
                distinct_nodes.insert(r.node_id.clone());
            }
        }
        let my_nid = self.keys.node_id_hex();
        for ch in &manifest.chunks {
            if self.resolve_chunk_path(&ch.content_id.to_string()).is_some() {
                pairs.insert((ch.index, my_nid.clone()));
                distinct_nodes.insert(my_nid.clone());
            }
        }
        let total_shards = manifest.chunks.len().max(1);
        let target = manifest.target_replicas.max(1) as usize;
        let denom = total_shards * target;
        let score = ((pairs.len() * 100) / denom).min(100) as u8;
        (
            views_count,
            tips_total_spores,
            tips_total_p2p,
            score,
            distinct_nodes.len(),
        )
    }

    pub fn get_video_details(&self, cid_or_post_id: &str) -> Option<VideoDetailsView> {
        let (manifest_cid, manifest, post) =
            if let Some(m) = self.state.video_manifests.get(cid_or_post_id) {
                let post = self
                    .state
                    .posts
                    .values()
                    .find(|p| p.video_manifest_cid.as_deref() == Some(cid_or_post_id))
                    .cloned();
                (cid_or_post_id.to_string(), m.clone(), post)
            } else if let Some(p) = self.state.posts.get(cid_or_post_id) {
                let vcid = p.video_manifest_cid.as_ref()?.clone();
                let m = self.state.video_manifests.get(&vcid)?.clone();
                (vcid, m, Some(p.clone()))
            } else {
                return None;
            };

        let mut by_chunk: HashMap<u32, Vec<ShardReplicaReceipt>> = HashMap::new();
        for r in self.state.shard_receipts.values() {
            if r.video_manifest_cid == manifest_cid {
                by_chunk.entry(r.chunk_index).or_default().push(r.clone());
            }
        }
        let target = manifest.target_replicas.max(1);
        let shards: Vec<VideoShardView> = manifest
            .chunks
            .iter()
            .map(|ch| {
                let cid_str = ch.content_id.to_string();
                let local_available = self.resolve_chunk_path(&cid_str).is_some();
                let mut receipts = by_chunk.remove(&ch.index).unwrap_or_default();
                receipts.sort_by(|a, b| a.verified_at.cmp(&b.verified_at));
                VideoShardView {
                    index: ch.index,
                    chunk_cid: cid_str,
                    byte_size: ch.byte_size,
                    chunk_hash: ch.chunk_hash.clone(),
                    offset_bytes: ch.offset_bytes,
                    local_available,
                    target_replicas: target,
                    receipts,
                }
            })
            .collect();

        let (views_count, tips_total_spores, tips_total_p2p, replication_score, distinct_replica_nodes) =
            self.compute_video_metrics(
                Some(&manifest_cid),
                post.as_ref().map(|p| p.post_id.as_str()),
            );

        let author_profile = post
            .as_ref()
            .and_then(|p| self.state.profiles.get(&p.author_node_id).cloned())
            .or_else(|| {
                self.state
                    .profiles
                    .values()
                    .find(|pr| pr.ed25519_pubkey_hex == manifest.author_pubkey)
                    .cloned()
            });
        let commons_project = post
            .as_ref()
            .and_then(|p| p.commons_project_id.as_deref())
            .and_then(|pid| self.get_commons_project(pid));

        Some(VideoDetailsView {
            is_pinned: self.is_video_pinned(&manifest_cid),
            manifest,
            manifest_cid,
            post,
            author_profile,
            shards,
            replication_score,
            distinct_replica_nodes,
            views_count,
            tips_total_spores,
            tips_total_p2p,
            commons_project,
        })
    }

    pub fn record_video_view(&mut self, manifest_cid: &str) -> Result<u64, RhizomeError> {
        if !self.state.video_manifests.contains_key(manifest_cid) {
            return Err(RhizomeError::NotFound(format!(
                "vídeo {manifest_cid} não encontrado"
            )));
        }
        let entry = self
            .state
            .video_views
            .entry(manifest_cid.to_string())
            .or_insert(0);
        *entry += 1;
        let views = *entry;
        self.save()?;
        Ok(views)
    }

    pub fn record_tip(
        &mut self,
        target_post_id_or_cid: &str,
        asset_type: String,
        amount: u64,
        memo: String,
        ledger_tx_id: Option<String>,
    ) -> Result<(TipRecord, SyncEnvelope, Option<Plot>), RhizomeError> {
        let post = self
            .state
            .posts
            .get(target_post_id_or_cid)
            .cloned()
            .or_else(|| {
                self.state
                    .posts
                    .values()
                    .find(|p| p.video_manifest_cid.as_deref() == Some(target_post_id_or_cid))
                    .cloned()
            })
            .ok_or_else(|| {
                RhizomeError::NotFound(format!(
                    "publicação/vídeo '{target_post_id_or_cid}' não encontrado"
                ))
            })?;

        let normalized_asset = match asset_type.trim().to_ascii_uppercase().as_str() {
            "P2P" => "P2P_COIN".to_string(),
            other => other.to_string(),
        };
        let prof = self.local_profile();
        let mut tip = TipRecord {
            tip_id: String::new(),
            target_post_id: post.post_id.clone(),
            video_manifest_cid: post.video_manifest_cid.clone(),
            recipient_node_id: post.author_node_id.clone(),
            sender_node_id: String::new(),
            sender_pubkey_hex: String::new(),
            sender_handle: prof.handle,
            asset_type: normalized_asset,
            amount,
            memo: if memo.trim().is_empty() {
                "Apoio direto no Mycelium Rhizome".into()
            } else {
                memo.trim().to_string()
            },
            ledger_tx_id,
            created_at: unix_now(),
            signature: String::new(),
        };
        tip.finalize_and_sign(&self.keys)?;
        self.state.tips.insert(tip.tip_id.clone(), tip.clone());
        let env = SyncEnvelope::Tip(tip.clone());
        let plot = self.deposit_sync_envelope_plot(&env).ok();
        self.save()?;
        Ok((tip, env, plot))
    }

    pub fn create_custom_lens(
        &mut self,
        name: String,
        description: String,
        weights: BTreeMap<String, f64>,
    ) -> Result<(CustomDiscoveryLens, SyncEnvelope, Option<Plot>), RhizomeError> {
        let prof = self.local_profile();
        let mut lens = CustomDiscoveryLens {
            lens_id: String::new(),
            name: name.trim().to_string(),
            author_node_id: String::new(),
            author_pubkey_hex: String::new(),
            author_handle: prof.handle,
            description: if description.trim().is_empty() {
                "Lente de descoberta comunitária personalizada".into()
            } else {
                description.trim().to_string()
            },
            weights,
            created_at: unix_now(),
            signature: String::new(),
        };
        lens.finalize_and_sign(&self.keys)?;
        self.state
            .custom_lenses
            .insert(lens.lens_id.clone(), lens.clone());
        let env = SyncEnvelope::DiscoveryLens(lens.clone());
        let plot = self.deposit_sync_envelope_plot(&env).ok();
        self.save()?;
        Ok((lens, env, plot))
    }

    pub fn list_all_lenses(&self) -> Vec<DiscoveryLens> {
        let mut commons_w = HashMap::new();
        commons_w.insert("commons_weight".into(), 0.5);
        commons_w.insert("replication_health".into(), 0.3);
        commons_w.insert("reciprocity_score".into(), 0.2);
        let commons_lens = DiscoveryLens {
            id: "commons".into(),
            name: "Curadoria Commons & Coletivos (MCP)".into(),
            description: "Prioriza produções coletivas MCP, orçamentos abertos e contratos split 100%.".into(),
            weights: commons_w,
        };

        let mut list = vec![
            DiscoveryLens::default_symbiosis(),
            commons_lens,
            DiscoveryLens::chronological(),
            DiscoveryLens::trust_web(),
        ];
        for cl in self.state.custom_lenses.values() {
            list.push(DiscoveryLens {
                id: cl.lens_id.clone(),
                name: format!("{} (@{})", cl.name, cl.author_handle),
                description: cl.description.clone(),
                weights: cl.weights.iter().map(|(k, v)| (k.clone(), *v)).collect(),
            });
        }
        list
    }

    pub fn get_moderation_filters(&self) -> ModerationFilters {
        self.state.moderation_filters.clone()
    }

    pub fn set_moderation_filters(
        &mut self,
        filters: ModerationFilters,
    ) -> Result<ModerationFilters, RhizomeError> {
        self.state.moderation_filters = ModerationFilters {
            muted_tags: filters
                .muted_tags
                .into_iter()
                .map(|t| t.trim().trim_start_matches('#').to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect(),
            ..filters
        };
        self.save()?;
        Ok(self.state.moderation_filters.clone())
    }

    // ========================================================================
    // FEED UNIFICADO + LENTES DE DESCOBERTA SOBERANAS (MYCELIUM-MEDIA)
    // ========================================================================

    pub fn query_feed(&self, filter: &FeedFilter) -> Vec<FeedItemView> {
        let my_nid = self.keys.node_id_hex();
        let following: HashSet<String> = self
            .state
            .follows
            .values()
            .filter(|f| f.active && f.follower_node_id == my_nid)
            .map(|f| f.target_id.clone())
            .collect();

        let lens_id = filter.lens.as_deref().unwrap_or("symbiosis");
        let custom_lens = self.state.custom_lenses.get(lens_id);
        let builtin_lens = match lens_id {
            "chronological" => DiscoveryLens::chronological(),
            "trust_web" => DiscoveryLens::trust_web(),
            _ => DiscoveryLens::default_symbiosis(),
        };
        let now = unix_now().max(1);
        let mod_cfg = &self.state.moderation_filters;

        let mut items = Vec::new();
        for post in self.state.posts.values() {
            if mod_cfg.followed_only
                && post.author_node_id != my_nid
                && !following.contains(&post.author_node_id)
            {
                continue;
            }
            if mod_cfg.anti_spam
                && post.body.trim().is_empty()
                && post.media.is_empty()
                && post.repost_of.is_none()
            {
                continue;
            }
            if !mod_cfg.muted_tags.is_empty()
                && post.tags.iter().any(|t| mod_cfg.muted_tags.contains(t))
            {
                continue;
            }
            if filter.commons_only == Some(true) && post.commons_project_id.is_none() {
                continue;
            }
            if let Some(ref k) = filter.kind {
                let matches_kind = match k.as_str() {
                    "all" | "" => true,
                    "video" | "videos" => post.kind == PostKind::Video,
                    "short" | "shorts" | "reels" => post.kind == PostKind::Short,
                    "doc" | "docs" => post.content_type.as_deref() == Some("doc"),
                    "tube" => matches!(post.kind, PostKind::Video | PostKind::Short),
                    "photo" | "photos" | "photo_gallery" => post.kind == PostKind::PhotoGallery,
                    "article" | "articles" | "wall" => post.kind == PostKind::Article,
                    "microblog" | "x" => post.kind == PostKind::Microblog,
                    _ => true,
                };
                if !matches_kind {
                    continue;
                }
            }
            if let Some(ref tag) = filter.tag {
                let clean = tag.trim_start_matches('#').to_ascii_lowercase();
                if !clean.is_empty() && !post.tags.contains(&clean) {
                    continue;
                }
            }
            if let Some(ref author) = filter.author {
                let clean = author.trim_start_matches('@').to_ascii_lowercase();
                if !clean.is_empty()
                    && post.author_node_id != *author
                    && post.author_handle.to_ascii_lowercase() != clean
                {
                    continue;
                }
            }
            if let Some(ref cid) = filter.community_id {
                if !cid.is_empty() && post.community_id.as_deref() != Some(cid.as_str()) {
                    continue;
                }
            }
            if let Some(ref q) = filter.query {
                let ql = q.trim().to_ascii_lowercase();
                if !ql.is_empty() {
                    let in_body = post.body.to_ascii_lowercase().contains(&ql);
                    let in_title = post
                        .title
                        .as_deref()
                        .map(|t| t.to_ascii_lowercase().contains(&ql))
                        .unwrap_or(false);
                    let in_tags = post.tags.iter().any(|t| t.contains(&ql));
                    let in_author = post.author_handle.to_ascii_lowercase().contains(&ql);
                    let in_cid = post
                        .video_manifest_cid
                        .as_deref()
                        .map(|c| c.to_ascii_lowercase().contains(&ql))
                        .unwrap_or(false);
                    if !(in_body || in_title || in_tags || in_author || in_cid) {
                        continue;
                    }
                }
            }

            let mut reactions_summary: BTreeMap<String, usize> = BTreeMap::new();
            let mut my_reactions = Vec::new();
            let mut total_reactions = 0usize;
            for r in self.state.reactions.values() {
                if r.active && r.target_post_id == post.post_id {
                    let k = serde_json::to_value(&r.kind)
                        .ok()
                        .and_then(|v| v.as_str().map(String::from))
                        .unwrap_or_else(|| "like".into());
                    *reactions_summary.entry(k).or_insert(0) += 1;
                    total_reactions += 1;
                    if r.author_node_id == my_nid {
                        my_reactions.push(r.kind.clone());
                    }
                }
            }

            let mut comments: Vec<Comment> = self
                .state
                .comments
                .values()
                .filter(|c| c.target_post_id == post.post_id)
                .cloned()
                .collect();
            comments.sort_by_key(|c| c.created_at);
            let comments_count = comments.len();

            let repost_count = self
                .state
                .posts
                .values()
                .filter(|p| {
                    p.repost_of.as_deref() == Some(post.post_id.as_str())
                        || p.quote_of.as_deref() == Some(post.post_id.as_str())
                })
                .count();

            let video_manifest = post
                .video_manifest_cid
                .as_deref()
                .and_then(|cid| self.state.video_manifests.get(cid).cloned());
            let is_pinned = post
                .video_manifest_cid
                .as_deref()
                .map(|cid| self.is_video_pinned(cid))
                .unwrap_or(false);

            let (
                views_count,
                tips_total_spores,
                tips_total_p2p,
                replication_score,
                distinct_replica_nodes,
            ) = self.compute_video_metrics(
                post.video_manifest_cid.as_deref(),
                Some(&post.post_id),
            );
            let commons_project = post
                .commons_project_id
                .as_deref()
                .and_then(|pid| self.get_commons_project(pid));

            // Pontuação transparente pela Lente de Descoberta escolhida pelo usuário
            let age_hours = now.saturating_sub(post.created_at) as f64 / 3600.0;
            let freshness = 1.0 / (1.0 + age_hours / 24.0);
            let peer_trust = if post.author_node_id == my_nid || following.contains(&post.author_node_id) {
                1.0
            } else {
                0.2
            };
            let replication_health = if is_pinned {
                1.0
            } else {
                (replication_score as f64 / 100.0).max(0.4)
            };
            let commons_bonus = if commons_project.is_some() { 1.0 } else { 0.0 };
            let reciprocity = ((total_reactions + comments_count + repost_count) as f64
                + (tips_total_spores as f64 / 10.0)
                + 1.0)
                .ln_1p();

            let lens_score = if let Some(cl) = custom_lens {
                let w_rep = *cl.weights.get("replication_health").unwrap_or(&0.3);
                let w_rec = *cl.weights.get("reciprocity_score").unwrap_or(&0.3);
                let w_fresh = *cl.weights.get("freshness").unwrap_or(&0.2);
                let w_trust = *cl.weights.get("peer_trust").unwrap_or(&0.1);
                let w_com = *cl.weights.get("commons_weight").unwrap_or(&0.2);
                let w_chr = *cl.weights.get("chronological").unwrap_or(&0.0);
                replication_health * w_rep * 50.0
                    + reciprocity * w_rec * 20.0
                    + freshness * w_fresh * 100.0
                    + peer_trust * w_trust * 50.0
                    + commons_bonus * w_com * 80.0
                    + (post.created_at as f64 / 1e7) * w_chr
            } else {
                match lens_id {
                    "chronological" => post.created_at as f64,
                    "commons" => {
                        commons_bonus * 80.0
                            + replication_health * 30.0
                            + reciprocity * 15.0
                            + freshness * 25.0
                    }
                    "trust_web" => {
                        peer_trust * *builtin_lens.weights.get("peer_endorsements").unwrap_or(&0.7) * 100.0
                            + freshness * *builtin_lens.weights.get("local_affinity").unwrap_or(&0.3) * 50.0
                            + reciprocity * 5.0
                    }
                    _ => {
                        replication_health * *builtin_lens.weights.get("replication_health").unwrap_or(&0.4) * 50.0
                            + reciprocity * *builtin_lens.weights.get("reciprocity_score").unwrap_or(&0.3) * 20.0
                            + freshness * *builtin_lens.weights.get("freshness").unwrap_or(&0.2) * 100.0
                            + peer_trust * *builtin_lens.weights.get("peer_trust").unwrap_or(&0.1) * 50.0
                    }
                }
            };

            items.push(FeedItemView {
                author_profile: self.state.profiles.get(&post.author_node_id).cloned(),
                video_manifest,
                is_pinned,
                reactions_summary,
                my_reactions,
                comments_count,
                comments,
                repost_count,
                lens_score,
                views_count,
                tips_total_spores,
                tips_total_p2p,
                replication_score,
                distinct_replica_nodes,
                commons_project,
                post: post.clone(),
            });
        }

        items.sort_by(|a, b| {
            b.lens_score
                .partial_cmp(&a.lens_score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.post.created_at.cmp(&a.post.created_at))
        });

        let limit = filter.limit.unwrap_or(100).min(500);
        items.truncate(limit);
        items
    }

    // ========================================================================
    // MENSAGERIA PÓS-QUÂNTICA (WHATSAPP PARITY — 1:1, GRUPOS, DTN, NOSTR NIP-44)
    // ========================================================================

    /// Envia uma mensagem 1:1 cifrada com ML-KEM-1024 + XChaCha20-Poly1305.
    /// Retorna `(SealedChatEnvelope, DecryptedChatMessage, Option<NostrEvent>)`.
    #[allow(clippy::too_many_arguments)]
    pub fn send_direct_chat(
        &mut self,
        recipient_node_id: &str,
        recipient_mlkem_override: Option<&str>,
        kind: ChatMessageKind,
        body: String,
        media: Option<MediaAttachment>,
        reply_to: Option<String>,
        with_nostr_nip44: bool,
    ) -> Result<(SealedChatEnvelope, DecryptedChatMessage, Option<NostrEvent>), RhizomeError> {
        if body.trim().is_empty() && media.is_none() {
            return Err(RhizomeError::InvalidInput("mensagem vazia".into()));
        }

        let recip_profile = self.get_profile(recipient_node_id);
        let resolved_node_id = recip_profile
            .as_ref()
            .map(|p| p.node_id.clone())
            .unwrap_or_else(|| recipient_node_id.to_string());

        let mlkem_hex = recipient_mlkem_override
            .filter(|s| !s.trim().is_empty())
            .map(String::from)
            .or_else(|| recip_profile.as_ref().map(|p| p.mlkem1024_pubkey_hex.clone()))
            .ok_or_else(|| {
                RhizomeError::NotFound(format!(
                    "chave pública ML-KEM-1024 desconhecida para '{recipient_node_id}' — aguarde o anúncio de perfil na malha ou informe a chave"
                ))
            })?;

        let my_prof = self.local_profile();
        let conv_id = SealedChatEnvelope::dm_conversation_id(&my_prof.node_id, &resolved_node_id);
        let now = unix_now();
        let msg_id = new_message_id(&my_prof.node_id, &conv_id, &body, now);

        let plaintext = ChatPlaintext {
            msg_id: msg_id.clone(),
            conversation_id: conv_id.clone(),
            sender_node_id: my_prof.node_id.clone(),
            sender_handle: my_prof.handle,
            kind,
            body: body.trim().to_string(),
            media,
            reply_to,
            forwarded: false,
            created_at: now,
            external_origin: ExternalOrigin::Native,
        };

        let sealed = SealedChatEnvelope::seal_direct(
            &self.keys,
            &resolved_node_id,
            &mlkem_hex,
            &plaintext,
        )?;

        let nostr_fallback = if with_nostr_nip44 {
            recip_profile
                .as_ref()
                .map(|p| seal_for_nostr_nip44(&self.keys, &p.ghost_pubkey_hex, &plaintext))
                .transpose()?
        } else {
            None
        };

        let stored = DecryptedChatMessage {
            plaintext,
            recipient_node_id: resolved_node_id.clone(),
            is_group: false,
            direction: "outbound".into(),
            status: ReceiptStatus::Sent,
            transport: if nostr_fallback.is_some() {
                "pq_dtn_direct+nostr_nip44".into()
            } else {
                "pq_dtn_direct".into()
            },
            pq_verified: true,
        };

        if let Some(ref p) = recip_profile {
            self.state
                .conversation_titles
                .insert(conv_id.clone(), format!("{} (@{})", p.display_name, p.handle));
        } else {
            self.state.conversation_titles.entry(conv_id.clone()).or_insert_with(|| {
                format!("Nó {}", &resolved_node_id[..10.min(resolved_node_id.len())])
            });
        }
        self.state.msg_index.insert(msg_id, conv_id.clone());
        self.state
            .conversations
            .entry(conv_id)
            .or_default()
            .push(stored.clone());
        self.save()?;

        Ok((sealed, stored, nostr_fallback))
    }

    /// Cria um grupo criptografado estilo WhatsApp usando ML-KEM-1024 para embrulhar a chave por membro.
    pub fn create_chat_group(
        &mut self,
        name: String,
        description: String,
        member_node_ids: Vec<String>,
    ) -> Result<GroupManifest, RhizomeError> {
        if name.trim().is_empty() {
            return Err(RhizomeError::InvalidInput("nome do grupo obrigatório".into()));
        }
        let mut member_keys = Vec::new();
        for m in member_node_ids {
            if let Some(prof) = self.get_profile(&m) {
                member_keys.push((prof.node_id, prof.mlkem1024_pubkey_hex));
            }
        }
        let (manifest, group_key) =
            GroupManifest::create(&self.keys, name.trim(), description.trim(), &member_keys)?;
        self.state
            .group_keys_hex
            .insert(manifest.group_id.clone(), hex::encode(*group_key));
        self.state
            .conversation_titles
            .insert(manifest.group_id.clone(), format!("👥 {}", manifest.name));
        self.state
            .conversations
            .entry(manifest.group_id.clone())
            .or_default();
        self.state
            .groups
            .insert(manifest.group_id.clone(), manifest.clone());
        self.save()?;
        Ok(manifest)
    }

    /// Absorve um `GroupManifest` recebido de outro par e desembrulha a chave simétrica se formos membros.
    pub fn absorb_group_manifest(&mut self, manifest: GroupManifest) -> Result<bool, RhizomeError> {
        let gkey = manifest.unwrap_my_key(&self.keys)?;
        self.state
            .group_keys_hex
            .insert(manifest.group_id.clone(), hex::encode(*gkey));
        self.state
            .conversation_titles
            .insert(manifest.group_id.clone(), format!("👥 {}", manifest.name));
        self.state
            .conversations
            .entry(manifest.group_id.clone())
            .or_default();
        self.state
            .groups
            .insert(manifest.group_id.clone(), manifest);
        self.save()?;
        Ok(true)
    }

    /// Envia uma mensagem cifrada para um grupo (retorna o envelope + lista de NodeIds destinatários para fanout).
    pub fn send_group_chat(
        &mut self,
        group_id: &str,
        kind: ChatMessageKind,
        body: String,
        media: Option<MediaAttachment>,
        reply_to: Option<String>,
    ) -> Result<(SealedChatEnvelope, Vec<String>, DecryptedChatMessage), RhizomeError> {
        let manifest = self
            .state
            .groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| RhizomeError::NotFound(format!("grupo {group_id} não encontrado")))?;
        let key_hex = self
            .state
            .group_keys_hex
            .get(group_id)
            .ok_or_else(|| RhizomeError::Crypto("chave simétrica do grupo ausente".into()))?;
        let key_arr: [u8; 32] = hex::decode(key_hex)
            .map_err(|_| RhizomeError::Crypto("chave de grupo corrompida".into()))?
            .try_into()
            .map_err(|_| RhizomeError::Crypto("tamanho de chave de grupo inválido".into()))?;

        let my_prof = self.local_profile();
        let now = unix_now();
        let msg_id = new_message_id(&my_prof.node_id, group_id, &body, now);
        let plaintext = ChatPlaintext {
            msg_id: msg_id.clone(),
            conversation_id: group_id.to_string(),
            sender_node_id: my_prof.node_id.clone(),
            sender_handle: my_prof.handle,
            kind,
            body: body.trim().to_string(),
            media,
            reply_to,
            forwarded: false,
            created_at: now,
            external_origin: ExternalOrigin::Native,
        };

        let sealed = SealedChatEnvelope::seal_group(
            &self.keys,
            group_id,
            manifest.epoch,
            &key_arr,
            &plaintext,
        )?;

        let stored = DecryptedChatMessage {
            plaintext,
            recipient_node_id: group_id.to_string(),
            is_group: true,
            direction: "outbound".into(),
            status: ReceiptStatus::Sent,
            transport: "pq_group".into(),
            pq_verified: true,
        };

        let other_members: Vec<String> = manifest
            .members
            .into_iter()
            .filter(|m| m != &my_prof.node_id)
            .collect();

        self.state.msg_index.insert(msg_id, group_id.to_string());
        self.state
            .conversations
            .entry(group_id.to_string())
            .or_default()
            .push(stored.clone());
        self.save()?;

        Ok((sealed, other_members, stored))
    }

    /// Absorve um envelope de chat cifrado recebido pela malha (verifica Ed25519 + decapsula ML-KEM-1024 + decifra AEAD)
    /// e emite automaticamente um recibo assinado `Delivered` (`✓✓`)!
    pub fn absorb_sealed_chat(
        &mut self,
        envelope: SealedChatEnvelope,
    ) -> Result<(DecryptedChatMessage, Option<ChatReceipt>), RhizomeError> {
        if self.state.msg_index.contains_key(&envelope.msg_id) {
            let conv = self.state.msg_index[&envelope.msg_id].clone();
            if let Some(existing) = self
                .state
                .conversations
                .get(&conv)
                .and_then(|v| v.iter().find(|m| m.plaintext.msg_id == envelope.msg_id))
            {
                return Ok((existing.clone(), None));
            }
        }

        let plaintext = if envelope.is_group {
            let key_hex = self
                .state
                .group_keys_hex
                .get(&envelope.recipient_node_id)
                .ok_or_else(|| RhizomeError::Crypto("chave de grupo desconhecida".into()))?;
            let key_arr: [u8; 32] = hex::decode(key_hex)
                .map_err(|_| RhizomeError::Crypto("chave de grupo inválida".into()))?
                .try_into()
                .map_err(|_| RhizomeError::Crypto("chave de grupo inválida".into()))?;
            envelope.open_group(&key_arr)?
        } else {
            envelope.open_direct(&self.keys)?
        };

        let conv_id = plaintext.conversation_id.clone();
        let receipt = if !envelope.is_group && envelope.sender_node_id != self.keys.node_id_hex() {
            Some(ChatReceipt::create_and_sign(
                &self.keys,
                &plaintext.msg_id,
                &conv_id,
                &envelope.sender_node_id,
                ReceiptStatus::Delivered,
            )?)
        } else {
            None
        };

        let stored = DecryptedChatMessage {
            plaintext: plaintext.clone(),
            recipient_node_id: envelope.recipient_node_id.clone(),
            is_group: envelope.is_group,
            direction: "inbound".into(),
            status: ReceiptStatus::Delivered,
            transport: if envelope.is_group {
                "pq_group".into()
            } else {
                "pq_dtn_direct".into()
            },
            pq_verified: true,
        };

        if !envelope.is_group {
            let title = self
                .state
                .profiles
                .get(&plaintext.sender_node_id)
                .map(|p| format!("{} (@{})", p.display_name, p.handle))
                .unwrap_or_else(|| format!("@{}", plaintext.sender_handle));
            self.state.conversation_titles.insert(conv_id.clone(), title);
        }

        self.state
            .msg_index
            .insert(plaintext.msg_id.clone(), conv_id.clone());
        self.state
            .conversations
            .entry(conv_id)
            .or_default()
            .push(stored.clone());
        self.save()?;

        Ok((stored, receipt))
    }

    /// Absorve um evento Nostr NIP-44 de chat (fallback CGNAT).
    pub fn absorb_nostr_dm(&mut self, event: &NostrEvent) -> Result<DecryptedChatMessage, RhizomeError> {
        let pt = unseal_from_nostr_nip44(&self.keys, event)?;
        let conv_id = pt.conversation_id.clone();
        let stored = DecryptedChatMessage {
            plaintext: pt.clone(),
            recipient_node_id: self.keys.node_id_hex(),
            is_group: false,
            direction: "inbound".into(),
            status: ReceiptStatus::Delivered,
            transport: "nostr_nip44".into(),
            pq_verified: false,
        };
        self.state
            .conversation_titles
            .entry(conv_id.clone())
            .or_insert_with(|| format!("@{} (Nostr)", pt.sender_handle));
        self.state.msg_index.insert(pt.msg_id, conv_id.clone());
        self.state
            .conversations
            .entry(conv_id)
            .or_default()
            .push(stored.clone());
        self.save()?;
        Ok(stored)
    }

    /// Marca todas as mensagens recebidas de uma conversa como lidas e gera recibos assinados `Read` (`✓✓ azul`).
    pub fn mark_conversation_read(
        &mut self,
        conversation_id: &str,
    ) -> Result<Vec<ChatReceipt>, RhizomeError> {
        let mut receipts = Vec::new();
        let my_nid = self.keys.node_id_hex();
        if let Some(msgs) = self.state.conversations.get_mut(conversation_id) {
            for m in msgs.iter_mut() {
                if m.direction == "inbound"
                    && m.status < ReceiptStatus::Read
                    && m.plaintext.sender_node_id != my_nid
                {
                    m.status = ReceiptStatus::Read;
                    if !m.is_group && m.pq_verified {
                        if let Ok(r) = ChatReceipt::create_and_sign(
                            &self.keys,
                            &m.plaintext.msg_id,
                            conversation_id,
                            &m.plaintext.sender_node_id,
                            ReceiptStatus::Read,
                        ) {
                            receipts.push(r);
                        }
                    }
                }
            }
        }
        if !receipts.is_empty() {
            self.save()?;
        }
        Ok(receipts)
    }

    /// Absorve um recibo assinado (`Delivered` / `Read`) e avança o checkmark da mensagem original.
    pub fn absorb_receipt(&mut self, receipt: ChatReceipt) -> Result<bool, RhizomeError> {
        receipt.verify()?;
        let Some(conv_id) = self.state.msg_index.get(&receipt.msg_id).cloned() else {
            return Ok(false);
        };
        let mut changed = false;
        if let Some(msgs) = self.state.conversations.get_mut(&conv_id) {
            for m in msgs.iter_mut() {
                if m.plaintext.msg_id == receipt.msg_id && receipt.status > m.status {
                    m.status = receipt.status;
                    changed = true;
                }
            }
        }
        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    pub fn list_conversations(&self) -> Vec<ConversationSummary> {
        let my_nid = self.keys.node_id_hex();
        let mut list = Vec::new();
        for (conv_id, msgs) in &self.state.conversations {
            let last = msgs.last();
            let is_group = self.state.groups.contains_key(conv_id)
                || last.map(|m| m.is_group).unwrap_or(false);
            let peer_node_id = if is_group {
                None
            } else {
                last.map(|m| {
                    if m.plaintext.sender_node_id == my_nid {
                        m.recipient_node_id.clone()
                    } else {
                        m.plaintext.sender_node_id.clone()
                    }
                })
            };
            let title = self
                .state
                .conversation_titles
                .get(conv_id)
                .cloned()
                .unwrap_or_else(|| conv_id.clone());
            let unread_count = msgs
                .iter()
                .filter(|m| m.direction == "inbound" && m.status < ReceiptStatus::Read)
                .count();
            let pq_protected = msgs.iter().any(|m| m.pq_verified)
                || self.state.groups.contains_key(conv_id);
            list.push(ConversationSummary {
                conversation_id: conv_id.clone(),
                title,
                peer_node_id,
                is_group,
                last_message_preview: last
                    .map(|m| m.plaintext.body.clone())
                    .unwrap_or_else(|| "Conversa vazia".into()),
                last_timestamp: last.map(|m| m.plaintext.created_at).unwrap_or(0),
                message_count: msgs.len(),
                unread_count,
                pq_protected,
            });
        }
        list.sort_by(|a, b| b.last_timestamp.cmp(&a.last_timestamp));
        list
    }

    pub fn get_conversation_messages(&self, conversation_id: &str) -> Vec<DecryptedChatMessage> {
        self.state
            .conversations
            .get(conversation_id)
            .cloned()
            .unwrap_or_default()
    }

    pub fn list_groups(&self) -> Vec<GroupManifest> {
        self.state.groups.values().cloned().collect()
    }

    // ========================================================================
    // RETROCOMPATIBILIDADE (IMPORTADORES X / WHATSAPP + BRIDGES NOSTR/RSS/AP)
    // ========================================================================

    pub fn import_x_archive(
        &mut self,
        raw: &str,
    ) -> Result<(Vec<SocialPost>, Vec<SyncEnvelope>, Vec<Plot>), RhizomeError> {
        let prof = self.local_profile();
        let posts = import_x_archive_into_posts(raw, &self.keys, &prof.handle)?;
        let mut envs = Vec::with_capacity(posts.len());
        let mut plots = Vec::new();
        for p in &posts {
            self.state.posts.insert(p.post_id.clone(), p.clone());
            let env = SyncEnvelope::Post(p.clone());
            if let Ok(plot) = self.deposit_sync_envelope_plot(&env) {
                plots.push(plot);
            }
            envs.push(env);
        }
        self.save()?;
        Ok((posts, envs, plots))
    }

    pub fn import_whatsapp_chat(
        &mut self,
        chat_title: &str,
        raw_txt: &str,
    ) -> Result<(String, usize), RhizomeError> {
        let parsed = parse_whatsapp_txt(raw_txt)?;
        let now = unix_now();
        let title = if chat_title.trim().is_empty() {
            "WhatsApp Importado".to_string()
        } else {
            chat_title.trim().to_string()
        };
        let conv_hash = blake3::hash(format!("wa-import:{title}:{now}").as_bytes());
        let conv_id = format!("wa_{}", hex::encode(&conv_hash.as_bytes()[..10]));
        self.state
            .conversation_titles
            .insert(conv_id.clone(), format!("📱 {title} (WhatsApp)"));

        let count = parsed.len();
        let entry = self.state.conversations.entry(conv_id.clone()).or_default();
        for (idx, m) in parsed.into_iter().enumerate() {
            let msg_id = ContentId::of(
                format!("wa:{conv_id}:{idx}:{}:{}", m.timestamp, m.body).as_bytes(),
            )
            .to_string();
            let pt = ChatPlaintext {
                msg_id: msg_id.clone(),
                conversation_id: conv_id.clone(),
                sender_node_id: format!("wa_sender_{}", m.sender.to_ascii_lowercase().replace(' ', "_")),
                sender_handle: m.sender.clone(),
                kind: m.kind,
                body: m.body,
                media: None,
                reply_to: None,
                forwarded: false,
                created_at: m.timestamp,
                external_origin: ExternalOrigin::WhatsAppExport {
                    chat_title: title.clone(),
                    original_sender: m.sender,
                    imported_at: now,
                },
            };
            self.state.msg_index.insert(msg_id, conv_id.clone());
            entry.push(DecryptedChatMessage {
                plaintext: pt,
                recipient_node_id: self.keys.node_id_hex(),
                is_group: false,
                direction: "imported".into(),
                status: ReceiptStatus::Read,
                transport: "whatsapp_import".into(),
                pq_verified: false,
            });
        }
        self.save()?;
        Ok((conv_id, count))
    }

    /// Ingere um payload de webhook do WhatsApp Cloud API para o histórico local.
    pub fn ingest_whatsapp_cloud_webhook(&mut self, payload: &Value) -> Result<usize, RhizomeError> {
        let msgs = WhatsAppCloudAdapter::parse_webhook_payload(payload)?;
        let count = msgs.len();
        for m in msgs {
            let conv_id = format!("wacloud_{}", m.from_wa_id);
            self.state
                .conversation_titles
                .insert(conv_id.clone(), format!("📱 {} (+{})", m.sender_name, m.from_wa_id));
            let msg_id = ContentId::of(format!("wacloud:{}", m.wamid).as_bytes()).to_string();
            let pt = ChatPlaintext {
                msg_id: msg_id.clone(),
                conversation_id: conv_id.clone(),
                sender_node_id: format!("wa:{}", m.from_wa_id),
                sender_handle: m.sender_name,
                kind: m.kind,
                body: m.body,
                media: None,
                reply_to: None,
                forwarded: false,
                created_at: m.timestamp,
                external_origin: ExternalOrigin::WhatsAppCloud {
                    wamid: m.wamid,
                    from_wa_id: m.from_wa_id,
                },
            };
            self.state.msg_index.insert(msg_id, conv_id.clone());
            self.state
                .conversations
                .entry(conv_id)
                .or_default()
                .push(DecryptedChatMessage {
                    plaintext: pt,
                    recipient_node_id: self.keys.node_id_hex(),
                    is_group: false,
                    direction: "inbound".into(),
                    status: ReceiptStatus::Delivered,
                    transport: "whatsapp_cloud".into(),
                    pq_verified: false,
                });
        }
        if count > 0 {
            self.save()?;
        }
        Ok(count)
    }

    /// Exporta um post para evento Nostr NIP-01/NIP-71 assinado por Schnorr (`GhostId`).
    pub fn export_post_as_nostr(&self, post_id: &str) -> Result<NostrEvent, RhizomeError> {
        let post = self
            .state
            .posts
            .get(post_id)
            .ok_or_else(|| RhizomeError::NotFound(format!("post {post_id} não encontrado")))?;
        post_to_nostr_event(post, self.keys.ghost())
    }

    /// Importa um evento Nostr externo verificando assinatura Schnorr real.
    pub fn import_nostr_event(
        &mut self,
        event: &NostrEvent,
    ) -> Result<(SocialPost, SyncEnvelope, Option<Plot>), RhizomeError> {
        let prof = self.local_profile();
        let post = nostr_event_to_post(event, &self.keys, &prof.handle)?;
        self.state.posts.insert(post.post_id.clone(), post.clone());
        let env = SyncEnvelope::Post(post.clone());
        let plot = self.deposit_sync_envelope_plot(&env).ok();
        self.save()?;
        Ok((post, env, plot))
    }

    pub fn export_rss(&self, base_url: &str) -> String {
        let prof = self.local_profile();
        let mut posts: Vec<SocialPost> = self.state.posts.values().cloned().collect();
        posts.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        render_rss_feed(&prof, &posts, base_url)
    }

    pub fn export_activitypub_actor(&self, base_url: &str) -> Value {
        render_activitypub_actor(&self.local_profile(), base_url)
    }

    pub fn export_activitypub_outbox(&self, base_url: &str) -> Value {
        let mut posts: Vec<SocialPost> = self.state.posts.values().cloned().collect();
        posts.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        render_activitypub_outbox(&self.local_profile(), &posts, base_url)
    }

    // ========================================================================
    // REPLICAÇÃO P2P (ABSORÇÃO DE SYNC ENVELOPES + SPOREBANK PLOTS)
    // ========================================================================

    /// Verifica assinatura estrita e absorve um `SyncEnvelope` vindo da malha libp2p/gossipsub.
    pub fn absorb_sync_envelope(&mut self, env: SyncEnvelope) -> Result<bool, RhizomeError> {
        env.verify()?;
        let changed = match env {
            SyncEnvelope::Profile(p) => {
                let replace = self
                    .state
                    .profiles
                    .get(&p.node_id)
                    .map(|cur| p.revision > cur.revision || p.updated_at > cur.updated_at)
                    .unwrap_or(true);
                if replace {
                    self.state.profiles.insert(p.node_id.clone(), p);
                }
                replace
            }
            SyncEnvelope::Post(p) => {
                if self.state.posts.contains_key(&p.post_id) {
                    false
                } else {
                    self.state.posts.insert(p.post_id.clone(), p);
                    true
                }
            }
            SyncEnvelope::Story(s) => {
                if s.is_expired(unix_now()) || self.state.stories.contains_key(&s.story_id) {
                    false
                } else {
                    self.state.stories.insert(s.story_id.clone(), s);
                    true
                }
            }
            SyncEnvelope::Comment(c) => {
                if self.state.comments.contains_key(&c.comment_id) {
                    false
                } else {
                    self.state.comments.insert(c.comment_id.clone(), c);
                    true
                }
            }
            SyncEnvelope::Reaction(r) => {
                let key = reaction_key(&r.target_post_id, &r.author_node_id, &r.kind);
                let replace = self
                    .state
                    .reactions
                    .get(&key)
                    .map(|cur| r.updated_at >= cur.updated_at)
                    .unwrap_or(true);
                if replace {
                    self.state.reactions.insert(key, r);
                }
                replace
            }
            SyncEnvelope::Follow(f) => {
                let key = follow_key(&f.follower_node_id, &f.target_kind, &f.target_id);
                let replace = self
                    .state
                    .follows
                    .get(&key)
                    .map(|cur| f.updated_at >= cur.updated_at)
                    .unwrap_or(true);
                if replace {
                    self.state.follows.insert(key, f);
                }
                replace
            }
            SyncEnvelope::Community(c) => {
                let replace = self
                    .state
                    .communities
                    .get(&c.community_id)
                    .map(|cur| c.revision > cur.revision || c.updated_at > cur.updated_at)
                    .unwrap_or(true);
                if replace {
                    self.state.communities.insert(c.community_id.clone(), c);
                }
                replace
            }
            SyncEnvelope::VideoManifest {
                manifest_cid,
                manifest,
                ..
            } => {
                let is_new = !self.state.video_manifests.contains_key(&manifest_cid);
                if is_new {
                    let manifest_path = self.media_dir.join(format!("{manifest_cid}.json"));
                    let _ = std::fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?);
                    self.state.video_manifests.insert(manifest_cid, manifest);
                }
                is_new
            }
            SyncEnvelope::Channel(ch) => {
                let channels_dir = self.home.join("sporebank").join("channels");
                let _ = std::fs::create_dir_all(&channels_dir);
                let path = channels_dir.join(format!("{}.json", ch.channel_id));
                let _ = std::fs::write(path, serde_json::to_vec_pretty(&ch)?);
                true
            }
            SyncEnvelope::Playlist(pl) => {
                let replace = self
                    .state
                    .playlists
                    .get(&pl.playlist_id)
                    .map(|cur| pl.revision > cur.revision)
                    .unwrap_or(true);
                if replace {
                    self.state.playlists.insert(pl.playlist_id.clone(), pl);
                }
                replace
            }
            SyncEnvelope::CommonsProject(p) => {
                let replace = self
                    .state
                    .commons_projects
                    .get(&p.project_id)
                    .map(|cur| p.revision > cur.revision || p.updated_at > cur.updated_at)
                    .unwrap_or(true);
                if replace {
                    self.state.commons_projects.insert(p.project_id.clone(), p);
                }
                replace
            }
            SyncEnvelope::CommonsContribution(c) => {
                if self
                    .state
                    .commons_contributions
                    .contains_key(&c.contribution_id)
                {
                    false
                } else {
                    self.state
                        .commons_contributions
                        .insert(c.contribution_id.clone(), c);
                    true
                }
            }
            SyncEnvelope::ShardReceipt(r) => {
                let replace = self
                    .state
                    .shard_receipts
                    .get(&r.receipt_id)
                    .map(|cur| r.verified_at > cur.verified_at)
                    .unwrap_or(true);
                if replace {
                    self.state.shard_receipts.insert(r.receipt_id.clone(), r);
                }
                replace
            }
            SyncEnvelope::Tip(t) => {
                if self.state.tips.contains_key(&t.tip_id) {
                    false
                } else {
                    self.state.tips.insert(t.tip_id.clone(), t);
                    true
                }
            }
            SyncEnvelope::DiscoveryLens(l) => {
                if self.state.custom_lenses.contains_key(&l.lens_id) {
                    false
                } else {
                    self.state.custom_lenses.insert(l.lens_id.clone(), l);
                    true
                }
            }
        };

        if changed {
            self.save()?;
        }
        Ok(changed)
    }

    /// Absorve um `giggs::Plot` público do SporeBank caso ele pertença ao namespace `rhizome:`.
    /// Isso garante que replicação via DHT/anti-entropy também hidrate eventos, blobs e chunks de vídeo!
    pub fn absorb_plot(&mut self, plot: &Plot) -> Result<bool, RhizomeError> {
        if !plot.is_public() || !plot.message.starts_with("rhizome:") {
            return Ok(false);
        }
        if plot.message.starts_with("rhizome:event:") {
            if let Some(leaf) = plot.leaves.iter().find(|l| l.path == "rhizome/event.json") {
                let env: SyncEnvelope = serde_json::from_slice(&leaf.content)?;
                return self.absorb_sync_envelope(env);
            }
        } else if let Some(chunk_cid) = plot.message.strip_prefix("rhizome:video-chunk:") {
            let raw_opt = if let Some(leaf) = plot.leaves.iter().find(|l| l.path == "chunk.b64") {
                BASE64.decode(&leaf.content).ok()
            } else {
                plot.leaves
                    .iter()
                    .find(|l| l.path == "chunk.bin")
                    .map(|l| l.content.clone())
            };
            if let Some(raw_bytes) = raw_opt {
                let expected: ContentId = chunk_cid
                    .parse()
                    .map_err(|_| RhizomeError::Corrupted("chunk cid inválido".into()))?;
                if !verify_chunk_integrity(&raw_bytes, &expected) {
                    return Err(RhizomeError::Corrupted("chunk de vídeo adulterado no Plot".into()));
                }
                let path = self.chunks_dir.join(chunk_cid);
                if !path.exists() {
                    std::fs::write(&path, &raw_bytes)?;
                    return Ok(true);
                }
            }
        } else if let Some(blob_cid) = plot.message.strip_prefix("rhizome:blob:") {
            let raw_opt = if let Some(leaf) = plot.leaves.iter().find(|l| l.path == "blob.b64") {
                BASE64.decode(&leaf.content).ok()
            } else {
                plot.leaves
                    .iter()
                    .find(|l| l.path == "blob.bin")
                    .map(|l| l.content.clone())
            };
            if let Some(raw_bytes) = raw_opt {
                if ContentId::of(&raw_bytes).to_string() != blob_cid {
                    return Err(RhizomeError::Corrupted("blob adulterado no Plot".into()));
                }
                let path = self.blobs_dir.join(blob_cid);
                if !path.exists() {
                    std::fs::write(&path, &raw_bytes)?;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Retorna envelopes recentes do nó local para anunciar na anastomose (conexão de novos peers).
    pub fn local_snapshot_envelopes(&mut self, max_items: usize) -> Vec<SyncEnvelope> {
        self.prune_expired_stories();
        let mut out = Vec::new();
        out.push(SyncEnvelope::Profile(self.local_profile()));
        for com in self.state.communities.values().take(16) {
            out.push(SyncEnvelope::Community(com.clone()));
        }
        for proj in self.state.commons_projects.values().take(16) {
            out.push(SyncEnvelope::CommonsProject(proj.clone()));
        }
        for c in self.state.commons_contributions.values().take(32) {
            out.push(SyncEnvelope::CommonsContribution(c.clone()));
        }
        for lens in self.state.custom_lenses.values().take(16) {
            out.push(SyncEnvelope::DiscoveryLens(lens.clone()));
        }
        for (cid, vm) in self.state.video_manifests.iter().take(16) {
            if let Ok(env) = SyncEnvelope::sign_video_manifest(cid.clone(), vm.clone(), &self.keys) {
                out.push(env);
            }
        }
        let mut posts: Vec<SocialPost> = self.state.posts.values().cloned().collect();
        posts.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        for p in posts.into_iter().take(max_items) {
            out.push(SyncEnvelope::Post(p));
        }
        for s in self.state.stories.values().take(16) {
            out.push(SyncEnvelope::Story(s.clone()));
        }
        for r in self.state.shard_receipts.values().take(64) {
            out.push(SyncEnvelope::ShardReceipt(r.clone()));
        }
        for t in self.state.tips.values().take(32) {
            out.push(SyncEnvelope::Tip(t.clone()));
        }
        out
    }

    /// Retorna visão geral do nó, estatísticas, lentes e capacidades das bridges.
    pub fn overview(&mut self) -> NodeOverview {
        self.prune_expired_stories();
        let pinned_videos_count = self.pinned_cache.len();
        let messages_count = self.state.conversations.values().map(|v| v.len()).sum();

        let x_adapter = XApiV2Adapter::from_env();
        let wa_adapter = WhatsAppCloudAdapter::from_env();

        NodeOverview {
            identity: self.keys.public_card(),
            profile: self.local_profile(),
            stats: RhizomeStats {
                profiles_count: self.state.profiles.len(),
                posts_count: self.state.posts.len(),
                videos_count: self.state.video_manifests.len(),
                stories_active_count: self.state.stories.len(),
                communities_count: self.state.communities.len(),
                playlists_count: self.state.playlists.len(),
                conversations_count: self.state.conversations.len(),
                messages_count,
                pinned_videos_count,
                media_blobs_count: self.state.blob_mimes.len(),
                commons_projects_count: self.state.commons_projects.len(),
                shard_receipts_count: self.state.shard_receipts.len(),
                tips_count: self.state.tips.len(),
                custom_lenses_count: self.state.custom_lenses.len(),
            },
            lenses: self.list_all_lenses(),
            bridges: vec![
                BridgeCapabilities {
                    adapter_id: "nostr_open".into(),
                    platform: "Nostr (NIP-01 / NIP-44 / NIP-71 / NIP-94)".into(),
                    direction: crate::compat::BridgeDirection::Bidirectional,
                    requires_external_credentials: false,
                    live_dispatch_configured: true,
                    honest_notice: "Assinatura Schnorr real (GhostID) + NIP-44 local ativos sem conta central.".into(),
                },
                BridgeCapabilities {
                    adapter_id: "rss_activitypub".into(),
                    platform: "RSS 2.0 & ActivityPub (Fediverse JSON-LD)".into(),
                    direction: crate::compat::BridgeDirection::Outbound,
                    requires_external_credentials: false,
                    live_dispatch_configured: true,
                    honest_notice: "Endpoints /rhizome/feed.xml, /rhizome/ap/actor e /rhizome/ap/outbox ativos.".into(),
                },
                x_adapter.capabilities(),
                wa_adapter.capabilities(),
            ],
        }
    }

    fn deposit_sync_envelope_plot(&self, env: &SyncEnvelope) -> Result<Plot, RhizomeError> {
        let bytes = serde_json::to_vec(env)?;
        let tag = match env {
            SyncEnvelope::Profile(_) => "profile",
            SyncEnvelope::Post(_) => "post",
            SyncEnvelope::Story(_) => "story",
            SyncEnvelope::Comment(_) => "comment",
            SyncEnvelope::Reaction(_) => "reaction",
            SyncEnvelope::Follow(_) => "follow",
            SyncEnvelope::Community(_) => "community",
            SyncEnvelope::VideoManifest { .. } => "video-manifest",
            SyncEnvelope::Channel(_) => "channel",
            SyncEnvelope::Playlist(_) => "playlist",
            SyncEnvelope::CommonsProject(_) => "commons-project",
            SyncEnvelope::CommonsContribution(_) => "commons-contribution",
            SyncEnvelope::ShardReceipt(_) => "shard-receipt",
            SyncEnvelope::Tip(_) => "tip",
            SyncEnvelope::DiscoveryLens(_) => "discovery-lens",
        };
        self.deposit_binary_plot(&format!("rhizome:event:{tag}"), "rhizome/event.json", &bytes)
    }

    /// Constrói um `Plot` público em memória (O(1), sem reabrir o SporeBank em disco).
    /// O `Organism` deposita diretamente no `self.bank` já aberto em RAM!
    fn deposit_binary_plot(
        &self,
        message: &str,
        leaf_path: &str,
        bytes: &[u8],
    ) -> Result<Plot, RhizomeError> {
        Ok(Plot {
            author: self.keys.node_id(),
            message: message.to_string(),
            parents: vec![],
            leaves: vec![Leaf {
                path: leaf_path.to_string(),
                content: bytes.to_vec(),
            }],
        })
    }
}

fn slice_blob_to_packets(cid: &str, mime_type: &str, bytes: &[u8]) -> Vec<MediaChunkPacket> {
    let chunks: Vec<&[u8]> = bytes.chunks(RHIZOME_VIDEO_CHUNK_BYTES).collect();
    let total = chunks.len().max(1) as u32;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, slice)| MediaChunkPacket {
            asset_cid: cid.to_string(),
            chunk_cid: cid.to_string(),
            chunk_index: i as u32,
            total_chunks: total,
            is_video_chunk: false,
            mime_type: mime_type.to_string(),
            data_b64: BASE64.encode(slice),
        })
        .collect()
}

fn reaction_key(post_id: &str, node_id: &str, kind: &ReactionKind) -> String {
    format!("{post_id}|{node_id}|{kind:?}")
}

fn follow_key(follower: &str, target_kind: &str, target_id: &str) -> String {
    format!("{follower}|{target_kind}|{target_id}")
}

fn sanitize_filename(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("file.bin");
    let clean: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .take(96)
        .collect();
    if clean.is_empty() {
        "file.bin".into()
    } else {
        clean
    }
}

fn is_safe_cid(cid: &str) -> bool {
    cid.starts_with("Qm")
        && cid.len() == 66
        && cid[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn end_to_end_store_video_streaming_stories_and_pq_chat_between_two_stores() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();

        let mut store_a = RhizomeStore::open(dir_a.path()).unwrap();
        let mut store_b = RhizomeStore::open(dir_b.path()).unwrap();

        // 1. Perfis sincronizados
        let (_, prof_a_env, _) = store_a
            .update_profile(
                Some("bruno".into()),
                Some("Bruno Mycelium".into()),
                Some("Criador soberano".into()),
                None,
                None,
                None,
            )
            .unwrap();
        let (_, prof_b_env, _) = store_b
            .update_profile(
                Some("alice".into()),
                Some("Alice Mesh".into()),
                Some("Nó réplica".into()),
                None,
                None,
                None,
            )
            .unwrap();
        assert!(store_b.absorb_sync_envelope(prof_a_env).unwrap());
        assert!(store_a.absorb_sync_envelope(prof_b_env).unwrap());

        // 2. Publicação de vídeo multi-chunk BLAKE3 + replicação por MediaChunkPacket
        let fake_mp4 = vec![0x42u8; RHIZOME_VIDEO_CHUNK_BYTES + 12345];
        let (vpost, vman, envs, plots, video_packets) = store_a
            .publish_video_bytes(
                &fake_mp4,
                VideoUploadMeta {
                    title: "Demo Rhizome Tube".into(),
                    description: "Streaming P2P sem servidor #video".into(),
                    duration_secs: 42,
                    resolution: "1080p".into(),
                    mime_type: "video/mp4".into(),
                    license: "CC-BY-4.0".into(),
                    tags: vec!["mycelium".into()],
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(vman.chunks.len(), 2);
        assert_eq!(video_packets.len(), 2);

        for env in envs {
            store_b.absorb_sync_envelope(env).unwrap();
        }
        for plot in plots {
            store_b.absorb_plot(&plot).unwrap();
        }
        for pkt in video_packets {
            assert!(store_b.absorb_media_chunk(pkt).unwrap());
        }

        // 2b. Replicação de imagem PNG grande (> 150 KiB = 5 pacotes de 32 KiB) + MIME real
        let mut fake_png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        fake_png.resize(150 * 1024, 0xAB);
        let (img_att, img_packets) = store_a
            .store_media_blob("foto.png", "application/octet-stream", &fake_png, "foto teste", None)
            .unwrap();
        assert_eq!(img_att.mime_type, "image/png");
        assert_eq!(img_packets.len(), 5);
        for (idx, pkt) in img_packets.into_iter().enumerate() {
            let done = store_b.absorb_media_chunk(pkt).unwrap();
            assert_eq!(done, idx == 4);
        }
        let (got_bytes, got_mime) = store_b.load_media_blob(&img_att.cid).unwrap();
        assert_eq!(got_bytes, fake_png);
        assert_eq!(got_mime, "image/png");

        // Nó B faz streaming de range parcial verificando BLAKE3 dos chunks
        let vcid = vpost.video_manifest_cid.as_deref().unwrap();
        let (slice, start, end, total, mime) = store_b
            .read_video_range(vcid, RHIZOME_VIDEO_CHUNK_BYTES as u64 - 10, Some(RHIZOME_VIDEO_CHUNK_BYTES as u64 + 19))
            .unwrap();
        assert_eq!(start, RHIZOME_VIDEO_CHUNK_BYTES as u64 - 10);
        assert_eq!(end, RHIZOME_VIDEO_CHUNK_BYTES as u64 + 19);
        assert_eq!(total, fake_mp4.len() as u64);
        assert_eq!(mime, "video/mp4");
        assert_eq!(slice.len(), 30);
        assert!(slice.iter().all(|&b| b == 0x42));

        // 3. Story efêmero via Isotope Atom
        let (story, key, atom, _) = store_a
            .create_story("Bom dia floresta!".into(), None, None, Some(3600))
            .unwrap();
        assert!(key.starts_with("rhizome/story/"));
        assert!(store_b.absorb_isotope_story(&atom).unwrap());
        assert_eq!(store_b.list_active_stories()[0].story_id, story.story_id);

        // 4. Chat Pós-Quântico E2EE (ML-KEM-1024 + XChaCha20) + Recibo Read
        let (sealed, _, nostr_ev) = store_a
            .send_direct_chat(
                &store_b.keys().node_id_hex(),
                None,
                ChatMessageKind::Text,
                "Fala Alice! Pós-quântico ativo.".into(),
                None,
                None,
                true,
            )
            .unwrap();
        assert!(nostr_ev.is_some());

        let (received, delivered_receipt) = store_b.absorb_sealed_chat(sealed).unwrap();
        assert_eq!(received.plaintext.body, "Fala Alice! Pós-quântico ativo.");
        assert!(store_a.absorb_receipt(delivered_receipt.unwrap()).unwrap());

        let read_receipts = store_b
            .mark_conversation_read(&received.plaintext.conversation_id)
            .unwrap();
        assert_eq!(read_receipts.len(), 1);
        assert!(store_a.absorb_receipt(read_receipts[0].clone()).unwrap());

        let conv_msgs = store_a.get_conversation_messages(&received.plaintext.conversation_id);
        assert_eq!(conv_msgs[0].status, ReceiptStatus::Read);
    }

    #[test]
    fn commons_mcp_legacy_bin_hydration_shard_receipts_tips_and_custom_lenses() {
        let dir_a = tempdir().unwrap();
        let dir_b = tempdir().unwrap();

        // 1. Prepara chunks legados (.bin) e VideoManifest antigo no dir_a ANTES de abrir RhizomeStore
        let raw_legacy = vec![0x7Au8; RHIZOME_VIDEO_CHUNK_BYTES + 2048];
        let legacy_ingest = ingest_video(
            "vid_legacy_01",
            "pubkey_legacy",
            "ch_legacy",
            "Documentário Legado Mycelium Video",
            "Gravado com chunks .bin",
            "doc",
            90,
            "CC-BY-SA-4.0",
            vec!["doc".into(), "legacy".into()],
            &raw_legacy,
            Some(RHIZOME_VIDEO_CHUNK_BYTES),
        );
        let legacy_media_dir = dir_a.path().join("sporebank").join("media");
        let legacy_chunks_dir = dir_a.path().join("sporebank").join("chunks");
        std::fs::create_dir_all(&legacy_media_dir).unwrap();
        std::fs::create_dir_all(&legacy_chunks_dir).unwrap();
        let legacy_cid = legacy_ingest.manifest.content_id().unwrap().to_string();
        std::fs::write(
            legacy_media_dir.join(format!("{legacy_cid}.json")),
            serde_json::to_vec_pretty(&legacy_ingest.manifest).unwrap(),
        )
        .unwrap();
        for ch in &legacy_ingest.raw_chunks {
            std::fs::write(
                legacy_chunks_dir.join(format!("{}.bin", ch.info.content_id)),
                &ch.data,
            )
            .unwrap();
        }

        let mut store_a = RhizomeStore::open(dir_a.path()).unwrap();
        let mut store_b = RhizomeStore::open(dir_b.path()).unwrap();

        // Verifica hidratação automática + streaming via .bin legado
        let doc_feed = store_a.query_feed(&FeedFilter {
            kind: Some("doc".into()),
            ..Default::default()
        });
        assert_eq!(doc_feed.len(), 1);
        assert_eq!(
            doc_feed[0].post.video_manifest_cid.as_deref(),
            Some(legacy_cid.as_str())
        );
        let (slice, _, _, total, _) = store_a
            .read_video_range(&legacy_cid, RHIZOME_VIDEO_CHUNK_BYTES as u64 - 4, Some(RHIZOME_VIDEO_CHUNK_BYTES as u64 + 3))
            .unwrap();
        assert_eq!(total, raw_legacy.len() as u64);
        assert_eq!(slice, vec![0x7Au8; 8]);

        // 2. Cria projeto MCP Commons no Store A + replica no Store B + contribuição no Store B
        let (proj, proj_env, _) = store_a
            .create_commons_project(
                "terra-viva".into(),
                "Doc Terra Viva".into(),
                "Produção colaborativa MCP".into(),
                "Proposta completa".into(),
                3000.0,
                1000,
                "2026-Q4".into(),
                vec![BudgetItem {
                    item: "Edição".into(),
                    cost_p2p: 3000.0,
                    status: "Aberto".into(),
                }],
                vec![
                    SplitContractParty {
                        role: "Direção".into(),
                        pubkey: store_a.keys().ed25519_pubkey_hex(),
                        name: "Bruno".into(),
                        split_percentage: 80,
                    },
                    SplitContractParty {
                        role: "Pool Seeders".into(),
                        pubkey: "mycelium:pool".into(),
                        name: "Nós".into(),
                        split_percentage: 20,
                    },
                ],
                vec![MilestoneItem {
                    title: "Captação".into(),
                    status: "in_progress".into(),
                    date: "2026-11".into(),
                }],
            )
            .unwrap();
        assert!(store_b.absorb_sync_envelope(proj_env).unwrap());

        let (_, _, contrib_env, _) = store_b
            .contribute_to_commons(
                &proj.project_id,
                "Alice".into(),
                250.0,
                100,
                "Apoiando!".into(),
            )
            .unwrap();
        assert!(store_a.absorb_sync_envelope(contrib_env).unwrap());
        let proj_view_a = store_a.get_commons_project("terra-viva").unwrap();
        assert_eq!(proj_view_a.current_raised, 250.0);
        assert_eq!(proj_view_a.spores_contributed, 100);

        // 3. Streaming ingest from file + vínculo MCP + recibos de shard entre 2 nós + gorjeta + lente customizada
        let tmp_vid = dir_a.path().join("upload_stream.bin");
        let vid_bytes = vec![0x33u8; RHIZOME_VIDEO_CHUNK_BYTES + 512];
        std::fs::write(&tmp_vid, &vid_bytes).unwrap();
        let prep = prepare_video_ingest_from_file(
            &tmp_vid,
            &store_a.chunks_dir(),
            &store_a.keys().ed25519_pubkey_hex(),
            "ch_a",
            VideoUploadMeta {
                title: "Filme Streaming MCP".into(),
                content_type: "doc".into(),
                commons_project_id: Some(proj.project_id.clone()),
                target_replicas: 2,
                ..Default::default()
            },
        )
        .unwrap();
        let (vpost, _, envs, _, pkts) = store_a.commit_prepared_video(prep).unwrap();
        for e in envs {
            store_b.absorb_sync_envelope(e).unwrap();
        }
        for p in pkts {
            store_b.absorb_media_chunk(p).unwrap();
        }
        let vcid = vpost.video_manifest_cid.as_deref().unwrap();
        let (_, b_rcpt_envs) = store_b.issue_local_shard_receipts(vcid, "mobile").unwrap();
        assert_eq!(b_rcpt_envs.len(), 2);
        for e in b_rcpt_envs {
            store_a.absorb_sync_envelope(e).unwrap();
        }
        let details = store_a.get_video_details(vcid).unwrap();
        assert_eq!(details.distinct_replica_nodes, 2);
        assert_eq!(details.replication_score, 100);
        assert!(details.commons_project.is_some());

        let (_, tip_env, _) = store_b
            .record_tip(&vpost.post_id, "SPORES".into(), 40, "Excelente!".into(), None)
            .unwrap();
        assert!(store_a.absorb_sync_envelope(tip_env).unwrap());
        let details_after_tip = store_a.get_video_details(vcid).unwrap();
        assert_eq!(details_after_tip.tips_total_spores, 40);

        let mut weights = BTreeMap::new();
        weights.insert("commons_weight".into(), 1.0);
        let (lens, lens_env, _) = store_a
            .create_custom_lens("Cinema MCP".into(), "Foco MCP".into(), weights)
            .unwrap();
        assert!(store_b.absorb_sync_envelope(lens_env).unwrap());
        let fed_custom = store_b.query_feed(&FeedFilter {
            lens: Some(lens.lens_id),
            commons_only: Some(true),
            ..Default::default()
        });
        assert_eq!(fed_custom.len(), 1);
        assert_eq!(fed_custom[0].post.post_id, vpost.post_id);
    }
}
