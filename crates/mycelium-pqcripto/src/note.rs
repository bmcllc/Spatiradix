//! Fixed-size private PQ-encrypted *message*, not a spendable coin.
//!
//! Public fields contain neither sender, recipient nor clear amount. The
//! salted BLAKE3 digest is NOT a PQ zero-knowledge balance proof or an amount
//! conservation commitment. The recipient public key is obtained out-of-band.

use crate::PqCriptoError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use mycelium_pqc::{mlkem_decapsulate, mlkem_encapsulate, mlkem_keypair_from_private};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const DOMAIN_COMMITMENT: &str = "pqcripto/v1/private-memo-commitment";
const DOMAIN_KEY: &str = "pqcripto/v1/private-memo-aead-key";
const DOMAIN_ENVELOPE: &str = "pqcripto/v1/private-memo-envelope";
pub const FIXED_PLAINTEXT_BYTES: usize = 256;
pub const MAX_MEMO_BYTES: usize = 128;
const KEM_CIPHERTEXT_BYTES: usize = 1568; // ML-KEM-1024
const HEADER_BYTES: usize = 43; // version(1) + amount(8) + random salt(32) + length(2)
const VERSION: u8 = 1;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedMemo {
    pub version: u8,
    pub note_id: [u8; 32],
    pub private_commitment: [u8; 32],
    pub kem_ciphertext: Vec<u8>,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// This type cannot be directly serialized, logged or used for accounting.
pub struct OpenedMemo {
    pub amount_micros: u64,
    pub memo: Zeroizing<Vec<u8>>,
}

fn validate_chain(chain: &str) -> Result<(), PqCriptoError> {
    if chain.is_empty()
        || chain.len() > 63
        || !chain
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(PqCriptoError::InvalidNote("invalid chain identifier"));
    }
    Ok(())
}

fn session_key(ss: &[u8], recipient_pk: &[u8], kem_ct: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key(DOMAIN_KEY);
    h.update(ss);
    h.update(blake3::hash(recipient_pk).as_bytes());
    h.update(kem_ct);
    Zeroizing::new(*h.finalize().as_bytes())
}

fn associated_data(chain: &str, commitment: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(58 + chain.len());
    aad.extend_from_slice(b"pqcripto/v1/chain-memo/");
    aad.extend_from_slice(&(chain.len() as u64).to_be_bytes());
    aad.extend_from_slice(chain.as_bytes());
    aad.extend_from_slice(commitment);
    aad
}

impl EncryptedMemo {
    fn computed_id(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key(DOMAIN_ENVELOPE);
        h.update(&[self.version]);
        h.update(&self.private_commitment);
        h.update(&self.kem_ciphertext);
        h.update(&self.nonce);
        h.update(&self.ciphertext);
        *h.finalize().as_bytes()
    }

    /// Encrypt a private memo with a random per-message ML-KEM shared secret.
    /// All ciphertext messages have the same length for this protocol version.
    pub fn seal(
        chain: &str,
        recipient_mlkem_public: &[u8],
        amount_micros: u64,
        memo: &[u8],
    ) -> Result<Self, PqCriptoError> {
        validate_chain(chain)?;
        if amount_micros == 0 || memo.len() > MAX_MEMO_BYTES {
            return Err(PqCriptoError::InvalidNote("invalid amount or memo length"));
        }
        let mut plain = Zeroizing::new([0u8; FIXED_PLAINTEXT_BYTES]);
        plain[0] = VERSION;
        plain[1..9].copy_from_slice(&amount_micros.to_be_bytes());
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        plain[9..41].copy_from_slice(&salt);
        plain[41..43].copy_from_slice(&(memo.len() as u16).to_be_bytes());
        plain[HEADER_BYTES..HEADER_BYTES + memo.len()].copy_from_slice(memo);
        let private_commitment = blake3::derive_key(DOMAIN_COMMITMENT, plain.as_ref());

        let mut kem =
            mlkem_encapsulate(recipient_mlkem_public).map_err(|_| PqCriptoError::Cryptography)?;
        let key = session_key(&kem.shared_secret, recipient_mlkem_public, &kem.ciphertext);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| PqCriptoError::Cryptography)?;
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plain.as_ref(),
                    aad: &associated_data(chain, &private_commitment),
                },
            )
            .map_err(|_| PqCriptoError::Cryptography)?;
        let mut result = Self {
            version: VERSION,
            note_id: [0u8; 32],
            private_commitment,
            kem_ciphertext: std::mem::take(&mut kem.ciphertext),
            nonce,
            ciphertext,
        };
        result.note_id = result.computed_id();
        Ok(result)
    }

    pub fn open(
        &self,
        chain: &str,
        recipient_mlkem_secret: &[u8],
    ) -> Result<OpenedMemo, PqCriptoError> {
        validate_chain(chain)?;
        if self.version != VERSION
            || self.kem_ciphertext.len() != KEM_CIPHERTEXT_BYTES
            || self.ciphertext.len() != FIXED_PLAINTEXT_BYTES + 16
            || self.note_id != self.computed_id()
        {
            return Err(PqCriptoError::InvalidNote(
                "invalid envelope format or checksum",
            ));
        }
        let recipient = mlkem_keypair_from_private(recipient_mlkem_secret)
            .map_err(|_| PqCriptoError::Cryptography)?;
        let shared = Zeroizing::new(
            mlkem_decapsulate(recipient.private_bytes(), &self.kem_ciphertext)
                .map_err(|_| PqCriptoError::Cryptography)?,
        );
        let key = session_key(shared.as_ref(), &recipient.public_key, &self.kem_ciphertext);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| PqCriptoError::Cryptography)?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&self.nonce),
                    Payload {
                        msg: &self.ciphertext,
                        aad: &associated_data(chain, &self.private_commitment),
                    },
                )
                .map_err(|_| PqCriptoError::Cryptography)?,
        );
        if plain.len() != FIXED_PLAINTEXT_BYTES
            || plain[0] != VERSION
            || blake3::derive_key(DOMAIN_COMMITMENT, plain.as_ref()) != self.private_commitment
        {
            return Err(PqCriptoError::InvalidNote(
                "decrypted message integrity failure",
            ));
        }
        let length = u16::from_be_bytes([plain[41], plain[42]]) as usize;
        let amount_micros = u64::from_be_bytes(
            plain[1..9]
                .try_into()
                .map_err(|_| PqCriptoError::InvalidNote("bad amount"))?,
        );
        if length > MAX_MEMO_BYTES
            || amount_micros == 0
            || plain[HEADER_BYTES + length..].iter().any(|b| *b != 0)
        {
            return Err(PqCriptoError::InvalidNote("invalid decrypted fields"));
        }
        Ok(OpenedMemo {
            amount_micros,
            memo: Zeroizing::new(plain[HEADER_BYTES..HEADER_BYTES + length].to_vec()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mycelium_pqc::mlkem_keygen;

    #[test]
    fn pq_memo_roundtrip_without_public_amount_or_recipient_and_fixed_length() {
        let receiver = mlkem_keygen();
        let note = EncryptedMemo::seal(
            "cameon-test",
            &receiver.public_key,
            5_000_000,
            b"private order",
        )
        .unwrap();
        let opened = note.open("cameon-test", receiver.private_bytes()).unwrap();
        assert_eq!(opened.amount_micros, 5_000_000);
        assert_eq!(opened.memo.as_slice(), b"private order");
        assert_eq!(note.ciphertext.len(), FIXED_PLAINTEXT_BYTES + 16);
        assert_eq!(note.kem_ciphertext.len(), KEM_CIPHERTEXT_BYTES);
        assert_ne!(note.private_commitment, [0u8; 32]);
        let serialized = serde_json::to_string(&note).unwrap();
        assert!(!serialized.contains("private order"));
        assert!(!serialized.contains("5000000"));
        assert_eq!(
            EncryptedMemo::seal("cameon-test", &receiver.public_key, 1, b"")
                .unwrap()
                .ciphertext
                .len(),
            note.ciphertext.len()
        );
    }

    #[test]
    fn bad_key_wrong_chain_or_tampering_fail_closed() {
        let receiver = mlkem_keygen();
        let wrong = mlkem_keygen();
        let note = EncryptedMemo::seal("cameon-test", &receiver.public_key, 100, b"hello").unwrap();
        assert!(note.open("other-chain", receiver.private_bytes()).is_err());
        assert!(note.open("cameon-test", wrong.private_bytes()).is_err());
        let mut bad = note.clone();
        bad.ciphertext[0] ^= 1;
        assert!(bad.open("cameon-test", receiver.private_bytes()).is_err());
        let mut bad = note.clone();
        bad.note_id[0] ^= 1;
        assert!(bad.open("cameon-test", receiver.private_bytes()).is_err());
        let mut bad = note.clone();
        bad.private_commitment[0] ^= 1;
        assert!(bad.open("cameon-test", receiver.private_bytes()).is_err());
        assert!(EncryptedMemo::seal("cameon-test", &receiver.public_key, 0, b"").is_err());
        assert!(EncryptedMemo::seal("cameon-test", &receiver.public_key, 1, &[4u8; 129]).is_err());
    }
}
