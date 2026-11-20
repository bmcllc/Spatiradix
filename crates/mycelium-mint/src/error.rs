use mycelium_core::{ContentId, NodeId};
use thiserror::Error;

/// Erros do motor de emissão de mainnet (`mycelium-mint`).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MintError {
    #[error("política monetária inválida: {0}")]
    InvalidPolicy(&'static str),

    #[error("quórum de esporocarpos insuficiente: {got} assinaturas, mínimo {need}")]
    InsufficientQuorum { got: usize, need: usize },

    #[error("esporocarpo {0} não autorizado no conjunto de validadores")]
    UnauthorizedValidator(NodeId),

    #[error("voto duplicado do esporocarpo {0} na mesma época")]
    DuplicateValidator(NodeId),

    #[error("assinatura ed25519 inválida do esporocarpo {0}")]
    InvalidValidatorSignature(NodeId),

    #[error("chave pública não deriva o NodeId declarado ({0})")]
    KeyMismatch(NodeId),

    #[error("assinatura ed25519 inválida da contraparte no claim {0}")]
    InvalidWorkSignature(ContentId),

    #[error("auto-assinatura proibida: produtor e contraparte são o mesmo nó ({0})")]
    SelfWorkNotAllowed(NodeId),

    #[error("prova hashcash inválida ou abaixo da dificuldade mínima ({min_bits} bits)")]
    InvalidHashcash { min_bits: u8 },

    #[error("época do claim ({got}) difere da época ativa ({expected})")]
    EpochMismatch { expected: u64, got: u64 },

    #[error("peso efetivo de trabalho zerado para o claim {0}")]
    ZeroWeight(ContentId),

    #[error("claim já liquidado anteriormente (replay bloqueado pelo nullifier)")]
    ReplayedClaim,

    #[error("suprimento máximo da mainnet atingido")]
    SupplyExhausted,

    #[error("compromisso de Pedersen não abre para o valor e blinding informados")]
    CommitmentMismatch,
}
