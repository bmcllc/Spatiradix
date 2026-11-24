//! ML-DSA-87 ephemeral proof of control over a *message session*.
//!
//! This proves only that the holder of a newly generated ML-DSA secret signed
//! the encrypted memo ID. It is NOT a payer authorization, ownership proof,
//! double-spend defense, merchant identity, or post-quantum ZK proof.

use crate::PqCriptoError;
use mycelium_zkp::license::{mldsa_signing_key_from_seed, mldsa_verify, Keypair, Signer};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const AUTH_DOMAIN: &str = "pqcripto/v1/memo-session-proof";
pub const MAX_VALIDITY_SECS: u64 = 10 * 60;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EphemeralSessionProof {
    pub note_id: [u8; 32],
    pub session_nonce: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    /// Fresh per-message ML-DSA-87 verifying key. Must NOT be reused.
    pub ephemeral_mldsa_public: Vec<u8>,
    pub signature: Vec<u8>,
}

impl EphemeralSessionProof {
    fn payload(
        chain: &str,
        note_id: &[u8; 32],
        nonce: &[u8; 32],
        issued_at: u64,
        expires_at: u64,
    ) -> Result<[u8; 32], PqCriptoError> {
        if chain.is_empty()
            || chain.len() > 63
            || !chain
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(PqCriptoError::Authentication);
        }
        let mut h = blake3::Hasher::new_derive_key(AUTH_DOMAIN);
        h.update(&(chain.len() as u64).to_be_bytes());
        h.update(chain.as_bytes());
        h.update(note_id);
        h.update(nonce);
        h.update(&issued_at.to_be_bytes());
        h.update(&expires_at.to_be_bytes());
        Ok(*h.finalize().as_bytes())
    }

    /// Signing uses fresh randomness and a one-time ML-DSA identity.
    pub fn issue(
        chain: &str,
        note_id: [u8; 32],
        now: u64,
        validity_secs: u64,
    ) -> Result<Self, PqCriptoError> {
        if note_id == [0u8; 32] || validity_secs == 0 || validity_secs > MAX_VALIDITY_SECS {
            return Err(PqCriptoError::Authentication);
        }
        let expires_at = now
            .checked_add(validity_secs)
            .ok_or(PqCriptoError::Authentication)?;
        let mut seed = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut *seed);
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let payload = Self::payload(chain, &note_id, &nonce, now, expires_at)?;
        let signing_key = mldsa_signing_key_from_seed(&seed);
        let public = signing_key.verifying_key().encode().as_slice().to_vec();
        let signature = signing_key
            .try_sign(&payload)
            .map_err(|_| PqCriptoError::Cryptography)?
            .encode()
            .as_slice()
            .to_vec();
        Ok(Self {
            note_id,
            session_nonce: nonce,
            issued_at: now,
            expires_at,
            ephemeral_mldsa_public: public,
            signature,
        })
    }

    /// Do NOT interpret this as an assertion that a payer owns funds.
    pub fn verify(
        &self,
        chain: &str,
        expected_note_id: &[u8; 32],
        now: u64,
    ) -> Result<(), PqCriptoError> {
        if &self.note_id != expected_note_id
            || self.note_id == [0u8; 32]
            || self.session_nonce == [0u8; 32]
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > MAX_VALIDITY_SECS
            || now < self.issued_at
            || now >= self.expires_at
        {
            return Err(PqCriptoError::Authentication);
        }
        let payload = Self::payload(
            chain,
            &self.note_id,
            &self.session_nonce,
            self.issued_at,
            self.expires_at,
        )?;
        if mldsa_verify(&self.ephemeral_mldsa_public, &payload, &self.signature) {
            Ok(())
        } else {
            Err(PqCriptoError::Authentication)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_mldsa_session_authenticates_only_the_encrypted_message() {
        // ML-DSA-87 debug builds can require a larger stack.
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(|| {
                let id = [0x41u8; 32];
                let p = EphemeralSessionProof::issue("cameon-test", id, 100, 60).unwrap();
                p.verify("cameon-test", &id, 110).unwrap();
                assert!(p.verify("other-chain", &id, 110).is_err());
                assert!(p.verify("cameon-test", &[0x42u8; 32], 110).is_err());
                assert!(p.verify("cameon-test", &id, 160).is_err());
                let mut altered = p.clone();
                altered.signature[0] ^= 1;
                assert!(altered.verify("cameon-test", &id, 110).is_err());
                assert!(EphemeralSessionProof::issue("cameon-test", id, 100, 0).is_err());
                assert!(EphemeralSessionProof::issue("cameon-test", id, 100, 601).is_err());
            })
            .unwrap()
            .join()
            .unwrap();
    }
}
