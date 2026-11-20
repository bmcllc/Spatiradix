//! # mycelium-bank
//!
//! Banco/corretora descentralizada e soberana construída sobre a infraestrutura
//! Mycelium Network. Opera em modo local-first: cada nó é dono dos seus dados;
//! a rede P2P (hifas libp2p, gossip, DHT, VEIL) transporta intenções,
//! recibos e liquidacões, nunca autoridade central. Chaves pós-quânticas
//! (ML-KEM-1024) garantem confidencialidade futura; Ed25519 garante
//! autoria hoje. Pagamentos P2P por NFC partem de um encontro físico
//! (tap-to-pay) e são selados por recibos hash-encadeados.
//!
//! Módulos:
//! - [`identity`] — carteira soberana (ed25519 + ML-KEM).
//! - [`assets`] — ativos e unidades.
//! - [`accounts`] — contas e saldos.
//! - [`ledger`] — razão hash-encadeada auditável.
//! - [`orders`] — livro de ordens e motor de matching (corretora).
//! - [`payments`] — intenções de pagamento e recibos NFC.
//! - [`nfc`] — abstração do transporte NFC.
//! - [`network`] — integração com a malha Mycelium.

pub mod accounts;
pub mod assets;
pub mod error;
pub mod identity;
pub mod ledger;
pub mod network;
#[cfg(feature = "pqc-ml-dsa")]
pub mod pqc;
pub mod nfc;
#[cfg(feature = "transport-mycelium")]
pub mod hyphae_transport;
pub mod orders;
pub mod store;
pub mod payments;
pub mod mint_bridge;

pub use crate::error::BankError;
pub use crate::identity::SovereignWallet;

/// Resultado padrão do crate.
pub type Result<T> = std::result::Result<T, BankError>;
