//! # mycelium-rhizome
//!
//! **Mycelium Rhizome** — Super-app social soberano sobre a infraestrutura completa
//! do Mycelium Network:
//!
//! - **Vídeo & Canais (YouTube + Reels/Shorts)**: chunks BLAKE3 via `mycelium-media` +
//!   `SporeBank` + streaming byte-range + playlists + lentes de descoberta intercambiáveis.
//! - **Feed Visual, Stories & Comunidades (Instagram + Facebook)**: posts ricos, carrosséis,
//!   reações, threads de comentários, comunidades assinadas e Stories efêmeros com TTL
//!   propagados via `Isotope`.
//! - **Microblog & Threads (X / Twitter)**: posts curtos, reposts, quotes, threads, `#hashtags`,
//!   importador de archive do X (`tweets.js` / JSON), bridge Nostr NIP-01, RSS 2.0, ActivityPub
//!   e adaptador plugável X API v2.
//! - **Mensageria Pós-Quântica E2EE & Offline (WhatsApp)**: envelopes 1:1 e em grupo cifrados
//!   com `ML-KEM-1024` (`mycelium-pqc`) + `XChaCha20-Poly1305` + assinatura Ed25519, entrega
//!   offline via DTN Store-and-Forward (`mycelium-hyphae`), recibos assinados (`✓` / `✓✓`),
//!   fallback CGNAT via Nostr NIP-44 (`mycelium-nostr`), importador de histórico `.txt` do
//!   WhatsApp e adaptador plugável WhatsApp Cloud API.
//! - **Identidade Soberana**: `Gland` Ed25519 + `GhostID` Nostr + `PKARR` (`myc1...`) +
//!   chave pública `ML-KEM-1024`, sem login central e sem DNS.

pub mod chat;
pub mod commons;
pub mod compat;
pub mod identity;
pub mod model;
pub mod omnibridge;
pub mod store;

pub use chat::{
    seal_for_nostr_nip44, unseal_from_nostr_nip44, ChatMessageKind, ChatPlaintext, ChatReceipt,
    ConversationSummary, DecryptedChatMessage, GroupManifest, ReceiptStatus, SealedChatEnvelope,
    WrappedGroupKey,
};
pub use commons::{
    validate_split_agreement, BudgetItem, CommonsContribution, CommonsProject,
    CustomDiscoveryLens, MilestoneItem, ShardReplicaReceipt, SplitContractParty, TipRecord,
};
pub use compat::{
    import_x_archive_into_posts, nostr_event_to_post, parse_whatsapp_txt, parse_x_tweets_export,
    post_to_nostr_event, render_activitypub_actor, render_activitypub_outbox, render_rss_feed,
    BridgeCapabilities, BridgeDirection, ExternalBridgeAdapter, ExternalDispatchPreview,
    ImportedWhatsAppMessage, ImportedXTweet, WhatsAppCloudAdapter, WhatsAppCloudInbound,
    XApiV2Adapter,
};
pub use identity::{verify_domain_signature, PublicIdentityCard, SovereignKeys};
pub use model::{
    Comment, Community, CommunityVisibility, ExternalOrigin, FollowEdge, MediaAttachment,
    MediaChunkPacket, PostKind, ProfileManifest, Reaction, ReactionKind, SocialPost, StoryItem,
    SyncEnvelope, DEFAULT_STORY_TTL_SECS,
};
pub use omnibridge::{
    parse_meta_json, parse_reddit_listing_json, parse_telegram_json, parse_tiktok_json,
    parse_twitch_helix_json, parse_vcard_contacts, parse_x_json, parse_youtube_atom_feed,
    ExternalChannel, ExternalContact, ExternalFeedItem, OmnibridgeIndex, OmnibridgeSyncDelta,
    OmnibridgeVault, PlatformCredentialRecord, PlatformCredentialView, SocialPlatform,
};
pub use store::{
    detect_mime_from_bytes, prepare_video_ingest, prepare_video_ingest_from_file,
    CommonsProjectView, FeedFilter, FeedItemView, ModerationFilters, NodeOverview,
    PreparedVideoIngest, RhizomeStore, UploadSessionInfo, VideoDetailsView, VideoShardView,
    VideoUploadMeta, RHIZOME_VIDEO_CHUNK_BYTES,
};

#[derive(Debug, thiserror::Error)]
pub enum RhizomeError {
    #[error("assinatura criptográfica inválida: {0}")]
    InvalidSignature(String),
    #[error("chave ou identidade inválida: {0}")]
    InvalidKey(String),
    #[error("criptografia E2EE falhou: {0}")]
    Crypto(String),
    #[error("entrada inválida: {0}")]
    InvalidInput(String),
    #[error("recurso não encontrado: {0}")]
    NotFound(String),
    #[error("conteúdo expirado: {0}")]
    Expired(String),
    #[error("integridade corrompida: {0}")]
    Corrupted(String),
    #[error("bridge/compatibilidade: {0}")]
    Compat(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
