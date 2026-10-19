//! `mycelium-pkarr` — descoberta e nome sem seed, DNS ou VPS, para **um nó
//! anônimo**.
//!
//! Um registro Pkarr é um pacote DNS assinado por uma chave ed25519 e guardado
//! na Mainline DHT (via relays). Este crate o usa de forma anônima:
//!
//! | Ameaça | Defesa |
//! |---|---|
//! | DHT/relay liga registros à identidade | chave **cegada por época** (`blind`) |
//! | observador lê os endpoints | conteúdo **cifrado** (XChaCha20-Poly1305, chave do endereço) |
//! | tamanho denuncia o conteúdo | texto claro **acolchoado** a tamanho fixo |
//! | registro aponta para o IP do nó | só endpoints sem IP (Nostr wss, VEIL, onion, Plot), validados nos dois lados |
//! | relay vê o IP de quem publica | publicação **só via SOCKS5 local** (VEIL/Tor), `socks5h`, fail-closed |
//! | quem tem o endereço forja registro | assinar sob a chave cegada exige o escalar mestre |
//! | registro velho reaproveitado | AAD liga cifrado à chave+timestamp; validade ≤ época seguinte |
//!
//! O que **não** está coberto está em `docs/network/pkarr-anonimo.md`.

pub mod anon;
pub mod blind;
pub mod dns;
pub mod keystore;
pub mod packet;
pub mod relay;
pub mod zbase32;

pub use anon::{open, seal, AnonRecord, Capability, Endpoint};
pub use blind::{epoch_of, MasterIdentity, EPOCH_SECS};
pub use packet::SignedPacket;
pub use relay::{RelayClient, Transport, DEFAULT_RELAYS, VEIL_SOCKS5_DEFAULT};

#[derive(Debug, thiserror::Error)]
pub enum PkarrError {
    #[error("pacote DNS inválido: {0}")]
    Dns(&'static str),
    #[error("dado malformado: {0}")]
    Malformed(&'static str),
    #[error("chave pública inválida ou não corresponde à época")]
    BadKey,
    #[error("assinatura inválida")]
    BadSignature,
    #[error("falha de cifragem/autenticação do conteúdo")]
    Crypto,
    #[error("registro expirado")]
    Expired,
    #[error("recusado por anonimato: {0}")]
    Leak(String),
    #[error("política de transporte: {0}")]
    Policy(String),
    #[error("nenhum relay aceitou: {0}")]
    AllRelaysFailed(String),
    #[error("registro não encontrado: {0}")]
    NotFound(String),
    #[error("chaveiro: {0}")]
    Keystore(String),
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
