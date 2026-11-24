//! Sovereign Gateway: authenticated encryption for payment state and lookup indexes.
//!
//! The encryption key is supplied by a Keyring or a separate secret provider.
//! No KEM self-encapsulation, node signature or "[private]" label is treated
//! as a substitute for an at-rest encryption key.

use crate::error::GatewayError;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"MYCGWAE1";
const NONCE_LEN: usize = 24;

pub struct SovereignCipher {
    key: Zeroizing<[u8; 32]>,
}

impl SovereignCipher {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key: Zeroizing::new(key),
        }
    }

    pub fn from_keyring(keys: &mycelium_keyring::Keyring) -> Self {
        Self::new(keys.derive32("mycelium/v1/meta-gateway/intent-aead"))
    }

    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, GatewayError> {
        let aead = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| GatewayError::Crypto("invalid vault key".into()))?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ciphertext = aead
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| GatewayError::Crypto("encrypted intent sealing failed".into()))?;
        let mut data = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
        data.extend_from_slice(MAGIC);
        data.extend_from_slice(&nonce);
        data.extend_from_slice(&ciphertext);
        Ok(data)
    }

    pub fn open(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, GatewayError> {
        if data.len() < MAGIC.len() + NONCE_LEN + 16 || !data.starts_with(MAGIC) {
            return Err(GatewayError::Crypto(
                "invalid gateway ciphertext header".into(),
            ));
        }
        let nonce = &data[MAGIC.len()..MAGIC.len() + NONCE_LEN];
        let ciphertext = &data[MAGIC.len() + NONCE_LEN..];
        let aead = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| GatewayError::Crypto("invalid vault key".into()))?;
        aead.decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| GatewayError::Crypto("gateway ciphertext authentication failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sovereign_cipher_random_nonces_and_associated_data() {
        let cipher = SovereignCipher::new([0x72; 32]);
        let plaintext = br#"{"receiver_id":"pix:sensitive"}"#;
        let first = cipher.seal(plaintext, b"account/a").unwrap();
        let second = cipher.seal(plaintext, b"account/a").unwrap();
        assert_ne!(first, second);
        assert!(!first.windows(plaintext.len()).any(|b| b == plaintext));
        assert_eq!(cipher.open(&first, b"account/a").unwrap(), plaintext);
        assert!(cipher.open(&first, b"account/b").is_err());
        assert!(SovereignCipher::new([0x71; 32])
            .open(&first, b"account/a")
            .is_err());
        let mut tampered = first;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(cipher.open(&tampered, b"account/a").is_err());
    }

    #[test]
    fn keyring_separates_backup_from_gateway_keys() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let keyring =
            mycelium_keyring::Keyring::from_mnemonic(mnemonic, "unit-test-passphrase").unwrap();
        assert_ne!(
            keyring.backup_aead_key(),
            keyring.derive32("mycelium/v1/meta-gateway/intent-aead")
        );
        let a = SovereignCipher::from_keyring(&keyring);
        let b = SovereignCipher::from_keyring(&keyring);
        assert_eq!(
            b.open(&a.seal(b"private", b"index").unwrap(), b"index")
                .unwrap(),
            b"private"
        );
    }
}
