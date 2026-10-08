//! # mycelium-media: publicação e gestão de vídeos
//!
//! Converte arquivos brutos ou segmentos em manifestos soberanos decompostos em chunks.

use crate::chunk::{slice_media_into_chunks, RawChunk, DEFAULT_CHUNK_SIZE};
use crate::manifest::VideoManifest;
use mycelium_core::ContentId;

pub struct VideoIngestResult {
    pub manifest: VideoManifest,
    pub manifest_cid: ContentId,
    pub raw_chunks: Vec<RawChunk>,
}

/// Ingesta um arquivo de mídia em memória ou streaming, fatiando-o e gerando o manifesto.
pub fn ingest_video(
    video_id: &str,
    author_pubkey: &str,
    channel_id: &str,
    title: &str,
    description: &str,
    content_type: &str,
    duration_seconds: u32,
    license: &str,
    tags: Vec<String>,
    media_data: &[u8],
    chunk_size: Option<usize>,
) -> VideoIngestResult {
    let raw_chunks = slice_media_into_chunks(media_data, chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE));
    let chunk_infos = raw_chunks.iter().map(|c| c.info.clone()).collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let manifest = VideoManifest {
        video_id: video_id.to_string(),
        author_pubkey: author_pubkey.to_string(),
        channel_id: channel_id.to_string(),
        title: title.to_string(),
        description: description.to_string(),
        content_type: content_type.to_string(),
        duration_seconds,
        license: license.to_string(),
        tags,
        thumbnail_cid: None,
        chunks: chunk_infos,
        total_byte_size: media_data.len() as u64,
        resolution: "1080p".to_string(),
        mime_type: "video/mp4".to_string(),
        target_replicas: 3,
        published_at_unix: now,
        signature: String::new(),
    };

    let manifest_cid = manifest.content_id().unwrap_or_else(|_| ContentId::of(video_id.as_bytes()));

    VideoIngestResult {
        manifest,
        manifest_cid,
        raw_chunks,
    }
}
