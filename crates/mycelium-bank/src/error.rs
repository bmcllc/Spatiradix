use thiserror::Error;

#[derive(Debug, Error)]
pub enum BankError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("inválido: {0}")]
    Invalid(String),
    #[error("não encontrado: {0}")]
    NotFound(String),
    #[error("conflito de estado: {0}")]
    Conflict(String),
    #[error("saldo insuficiente")]
    InsufficientFunds,
    #[error("assinatura inválida")]
    BadSignature,
    #[error("PQC: {0}")]
    Pqc(String),
    #[error("transporte NFC indisponível")]
    NfcUnavailable,
    #[error("rede Mycelium indisponível: {0}")]
    Network(String),
}
