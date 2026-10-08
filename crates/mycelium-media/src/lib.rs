//! # mycelium-media
//!
//! Substrato soberano de áudio e vídeo descentralizado do ecossistema The Lattice.
//! Implementa o protocolo Mycelium Media Protocol (MMP) com arquitetura "zero VPS obrigatório":
//! - Computadores comuns (folhas, raízes e esporocarpos) constituem a infraestrutura comunitária.
//! - Vídeos são fatiados em chunks independentes endereçados por BLAKE3 (ContentId).
//! - Canais e Playlists são manifestos criptográficos com revisões assinadas por GhostID.
//! - Provas de Entrega (Proof of Delivery) e Provas de Posse (Proof of Storage) garantem nutrição justa via Spores.
//! - Espectadores atuam dinamicamente como CDN orgânica (quanto mais demanda, maior a capacidade).

pub mod cache;
pub mod channel;
pub mod chunk;
pub mod delivery;
pub mod discovery;
pub mod manifest;
pub mod pin;
pub mod playlist;
pub mod receipt;
pub mod video;

pub use cache::{PhysarumCache, StorageTier};
pub use channel::ChannelStore;
pub use chunk::{assemble_chunks, slice_media_into_chunks, verify_chunk_integrity, RawChunk};
pub use delivery::DeliveryEngine;
pub use discovery::DiscoveryLens;
pub use manifest::{ChannelManifest, MediaChunkInfo, PlaylistManifest, VideoManifest};
pub use pin::PinManager;
pub use playlist::PlaylistService;
pub use receipt::{ProofOfDelivery, ProofOfRelay, ProofOfStorage};
pub use video::ingest_video;

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("bloco corrompido ou hash divergente: {0}")]
    CorruptedChunk(String),
    #[error("manifesto inválido: {0}")]
    InvalidManifest(String),
    #[error("canal não encontrado: {0}")]
    ChannelNotFound(String),
    #[error("assinatura criptográfica inválida: {0}")]
    InvalidSignature(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
