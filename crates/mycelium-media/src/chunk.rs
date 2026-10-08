//! # mycelium-media: fragmentação de mídia
//!
//! Decompõe fluxos e arquivos de mídia em pedaços (chunks) content-addressed por BLAKE3,
//! permitindo streaming distribuído, download paralelo e validação criptográfica ponta a ponta.

use crate::manifest::MediaChunkInfo;
use mycelium_core::ContentId;

pub const DEFAULT_CHUNK_SIZE: usize = 2 * 1024 * 1024; // 2 MB

/// Representa um bloco de dados em memória pronto para armazenamento ou transmissão.
#[derive(Clone, Debug)]
pub struct RawChunk {
    pub info: MediaChunkInfo,
    pub data: Vec<u8>,
}

/// Decompõe um payload de mídia em chunks independentes.
pub fn slice_media_into_chunks(media_bytes: &[u8], chunk_size: usize) -> Vec<RawChunk> {
    let size = if chunk_size == 0 { DEFAULT_CHUNK_SIZE } else { chunk_size };
    let mut chunks = Vec::new();
    let mut offset: u64 = 0;
    let mut index: u32 = 0;

    for slice in media_bytes.chunks(size) {
        let content_id = ContentId::of(slice);
        let chunk_hash = hex::encode(blake3::hash(slice).as_bytes());

        let info = MediaChunkInfo {
            index,
            content_id,
            byte_size: slice.len(),
            chunk_hash,
            offset_bytes: offset,
        };

        chunks.push(RawChunk {
            info,
            data: slice.to_vec(),
        });

        offset += slice.len() as u64;
        index += 1;
    }

    chunks
}

/// Valida se um bloco de dados corresponde exatamente ao ContentId e hash declarados.
pub fn verify_chunk_integrity(data: &[u8], expected_id: &ContentId) -> bool {
    let calculated_id = ContentId::of(data);
    calculated_id == *expected_id
}

/// Reconstitui os bytes originais a partir de uma coleção ordenada de chunks.
pub fn assemble_chunks(mut chunks: Vec<RawChunk>) -> Result<Vec<u8>, String> {
    chunks.sort_by_key(|c| c.info.index);

    let mut full = Vec::new();
    for (expected_idx, chunk) in chunks.into_iter().enumerate() {
        if chunk.info.index as usize != expected_idx {
            return Err(format!("Chunk faltante ou fora de ordem: esperado {expected_idx}, obtido {}", chunk.info.index));
        }
        if !verify_chunk_integrity(&chunk.data, &chunk.info.content_id) {
            return Err(format!("Hash inválido para o chunk índice {}", chunk.info.index));
        }
        full.extend_from_slice(&chunk.data);
    }

    Ok(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_slice_and_reassemble() {
        let sample = b"O micelio eh uma rede neural subterranea que sustenta a floresta inteira.";
        let chunks = slice_media_into_chunks(sample, 16);
        assert!(chunks.len() > 1);

        for c in &chunks {
            assert!(verify_chunk_integrity(&c.data, &c.info.content_id));
        }

        let assembled = assemble_chunks(chunks).unwrap();
        assert_eq!(assembled, sample);
    }
}
