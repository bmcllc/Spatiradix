//! `mycelium-pay`: envelope v1 e cifra híbrida (spec Sovereign Finance v0.2.1 §7).

pub mod bodies;
pub mod cbor;
pub mod envelope;
pub mod hybrid;
pub mod merchant;

#[derive(Debug, thiserror::Error)]
pub enum PayError {
    #[error("cbor: {0}")]
    Cbor(&'static str),
    #[error("envelope: {0}")]
    Envelope(&'static str),
    #[error("assinatura inválida")]
    BadSignature,
    #[error("híbrido: {0}")]
    Hybrid(&'static str),
    #[error("downgrade recusado: o destinatário anunciou ML-KEM")]
    Downgrade,
}
