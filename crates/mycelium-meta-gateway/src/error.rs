use thiserror::Error;

/// Erros do Supreme Meta-Gateway Mycelium.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GatewayError {
    #[error("adaptador `{0}` não configurado ou feature desabilitada neste nó")]
    AdapterUnavailable(&'static str),

    #[error("valor de pagamento inválido: deve ser maior que zero")]
    InvalidAmount,

    #[error("destino `{0}` inválido para o gateway selecionado")]
    InvalidTarget(String),

    #[error("violação de compliance ({rule}): {detail}")]
    ComplianceViolation { rule: &'static str, detail: String },

    #[error("transição de estado inválida na FSM: {from} -> {to}")]
    InvalidTransition { from: &'static str, to: &'static str },

    #[error("falha criptográfica (PQC/Ed25519/ZKP): {0}")]
    Crypto(String),
}
