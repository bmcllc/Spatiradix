//! PQCripto: primitives for a future shielded, post-quantum Mycelium asset.
//!
//! **NOT A CURRENCY MAINNET.** This crate currently protects private wallet
//! memos with ML-KEM-1024 + XChaCha20-Poly1305, signs ephemeral sessions with
//! ML-DSA-87, and plans a fail-closed VEIL/MIX route. It does NOT provide a
//! post-quantum shielded spend proof, amount-conservation proof, global
//! double-spend consensus, supply accounting or guaranteed anonymity.
//!
//! Do not serialize decrypted notes in public Plots, index them by persistent
//! identities, or promote an encrypted memo to a spendable balance.

pub mod auth;
pub mod chameleon;
pub mod coverage;
pub mod note;
pub mod payer_checkout;
pub mod route;
pub mod valuation;

#[derive(Debug, thiserror::Error)]
pub enum PqCriptoError {
    #[error("privacy floor unavailable: {0}")]
    PrivacyFloor(&'static str),
    #[error("invalid encrypted note: {0}")]
    InvalidNote(&'static str),
    #[error("post-quantum encryption failure")]
    Cryptography,
    #[error("post-quantum peer authentication failed")]
    Authentication,
    #[error("Cameon fixed-price policy: {0}")]
    Price(&'static str),
    #[error("global shielded-spend proof / consensus not yet implemented")]
    ShieldedSpendUnavailable,
}

/// A real transaction is *deliberately blocked* until there is an independently
/// verified, post-quantum-safe proof of ownership, balance conservation and
/// nullifier uniqueness. An encrypted payload alone is not valid money.
pub fn require_verified_shielded_spend() -> Result<(), PqCriptoError> {
    Err(PqCriptoError::ShieldedSpendUnavailable)
}

#[cfg(test)]
mod tests {
    #[test]
    fn do_not_claim_spendable_coins_without_shielded_proof() {
        assert!(super::require_verified_shielded_spend().is_err());
    }
}
