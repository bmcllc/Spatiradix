//! Chave do cofre (32 B) → chaves derivadas por HKDF-SHA256.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keys {
    pub chunk: [u8; 32],
    pub mac: [u8; 32],
    pub log: [u8; 32],
}

impl Keys {
    pub fn derive(vault_key: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"mycelium-root/v1"), vault_key);
        let mut k = Keys {
            chunk: [0; 32],
            mac: [0; 32],
            log: [0; 32],
        };
        hk.expand(b"chunk", &mut k.chunk).expect("hkdf 32");
        hk.expand(b"mac", &mut k.mac).expect("hkdf 32");
        hk.expand(b"log", &mut k.log).expect("hkdf 32");
        k
    }
}

/// MAC público da chave, gravado em cada raiz para conferir a reconstrução.
pub fn key_check(vault_key: &[u8; 32]) -> String {
    hex::encode(&blake3::keyed_hash(vault_key, b"mycelium-root/check/v1").as_bytes()[..16])
}
