//! Uma semente, todas as chaves (spec Sovereign Finance v0.2.1 §4).
//! `root = BIP39_seed(mnemônico, passphrase)` (64 B); demais chaves via `BLAKE3::derive_key`.
//! Fora deste G0 inicial: BIP-32 (BTC/EVM), keygen determinístico ML-KEM/ML-DSA.

use secp256k1::SecretKey;
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error("mnemônico inválido: {0}")]
    Mnemonic(String),
}

/// Gap limit da varredura de `n` (§4.2), igual ao da restauração NUT-13.
pub const GAP_LIMIT: u32 = 20;

pub struct Keyring {
    root: Zeroizing<[u8; 64]>,
}

impl Keyring {
    /// Mnemônico BIP-39 (24 palavras, inglês) + passphrase opcional.
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, KeyringError> {
        let m = bip39::Mnemonic::parse_in_normalized(bip39::Language::English, mnemonic)
            .map_err(|e| KeyringError::Mnemonic(e.to_string()))?;
        if m.word_count() != 24 {
            return Err(KeyringError::Mnemonic("a spec exige 24 palavras".into()));
        }
        Ok(Self { root: Zeroizing::new(m.to_seed(passphrase)) })
    }

    pub fn derive32(&self, ctx: &str) -> [u8; 32] {
        blake3::derive_key(ctx, &*self.root)
    }

    pub fn derive64(&self, ctx: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        blake3::Hasher::new_derive_key(ctx)
            .update(&*self.root)
            .finalize_xof()
            .fill(&mut out);
        out
    }

    /// Escalar secp256k1; se `k == 0` ou `k ≥ n`, recalcula com `ctx ‖ "/retry/" ‖ i` (§4.3).
    pub fn scalar(&self, ctx: &str) -> SecretKey {
        pick_scalar(|i| match i {
            0 => self.derive32(ctx),
            i => self.derive32(&format!("{ctx}/retry/{i}")),
        })
    }

    pub fn node_ed25519_seed(&self) -> [u8; 32] {
        self.derive32("mycelium/v1/node/ed25519")
    }
    pub fn wallet_key(&self, conta: u32) -> SecretKey {
        self.scalar(&format!("mycelium/v1/wallet/secp256k1/{conta}"))
    }
    /// `payment_id` determinístico: prefixo de 16 B (§4.2).
    pub fn payment_id(&self, n: u32) -> [u8; 16] {
        self.derive32(&format!("mycelium/v1/payid/{n}"))[..16].try_into().unwrap()
    }
    pub fn session_pay_key(&self, n: u32) -> SecretKey {
        self.scalar(&format!("mycelium/v1/session/pay/{n}"))
    }
    pub fn p2pk_key(&self, n: u32) -> SecretKey {
        self.scalar(&format!("mycelium/v1/p2pk/{n}"))
    }
    pub fn session_contact_key(&self, contact_id: &str, epoca: u32) -> SecretKey {
        self.scalar(&format!("mycelium/v1/session/contact/{contact_id}/{epoca}"))
    }
    pub fn cashu_nut13(&self) -> [u8; 32] {
        self.derive32("mycelium/v1/cashu/nut13")
    }
    pub fn ldk_entropy(&self) -> [u8; 32] {
        self.derive32("mycelium/v1/ln/ldk")
    }
    pub fn backup_aead_key(&self) -> [u8; 32] {
        self.derive32("mycelium/v1/backup/aead")
    }
    /// `d ‖ z` para `ML-KEM.KeyGen_internal` (FIPS 203).
    pub fn mlkem_seed(&self) -> [u8; 64] {
        self.derive64("mycelium/v1/pq/mlkem1024")
    }
    pub fn mlkem_keypair(&self) -> mycelium_pqc::KemKeyPair {
        mycelium_pqc::mlkem_keygen_from_seed(&self.mlkem_seed())
    }
    #[cfg(feature = "mldsa")]
    pub fn mldsa_signing_key(&self) -> mycelium_zkp::license::MlDsaSigningKey {
        mycelium_zkp::license::mldsa_signing_key_from_seed(&self.mldsa_seed())
    }
    /// `ξ` para `ML-DSA.KeyGen_internal` (FIPS 204).
    pub fn mldsa_seed(&self) -> [u8; 32] {
        self.derive32("mycelium/v1/pq/mldsa87")
    }
}

/// `hex(BLAKE3::derive_key("mycelium/v1/contact-id", xonly))` da chave apresentada no 1º contato.
pub fn contact_id(xonly: &[u8; 32]) -> String {
    hex::encode(blake3::derive_key("mycelium/v1/contact-id", xonly))
}

/// Primeiro candidato válido; `candidate(i)` devolve a tentativa `i` (0 = original).
fn pick_scalar(candidate: impl Fn(u32) -> [u8; 32]) -> SecretKey {
    (0u32..)
        .find_map(|i| SecretKey::from_slice(&candidate(i)).ok())
        .expect("laço infinito sempre acha escalar válido")
}

/// Varre `n = 0…` até `GAP_LIMIT` índices seguidos sem atividade; devolve os `n` ativos (§4.2).
pub fn scan_payments(mut active: impl FnMut(u32) -> bool) -> Vec<u32> {
    let (mut found, mut gap, mut n) = (vec![], 0, 0u32);
    while gap < GAP_LIMIT {
        if active(n) {
            found.push(n);
            gap = 0;
        } else {
            gap += 1;
        }
        n += 1;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn kr(pass: &str) -> Keyring {
        Keyring::from_mnemonic(M, pass).unwrap()
    }

    /// Vetores canônicos (mnemônico "abandon…art", passphrase vazia): outra implementação deve reproduzi-los.
    #[test]
    fn vectors_pinned() {
        let k = kr("");
        let h = |b: &[u8]| hex::encode(b);
        assert_eq!(h(&k.node_ed25519_seed()), "691debe9d465b42d5687aa3ee5b93e6f722f0f3e596f6dd4d96b7969deed9522");
        assert_eq!(h(&k.wallet_key(0).secret_bytes()), "8c5b6a04f9c42740a9ad2401867c76747fc24a7289b97a60f5026557f1da5163");
        assert_eq!(h(&k.payment_id(0)), "46b667e21036dcd858fd8a036c15ea64");
        assert_eq!(h(&k.p2pk_key(0).secret_bytes()), "6c5b56d6986766a6fed9db68e4f4045303b052aa080048affdbf3a88418782cf");
        assert_eq!(h(&k.mlkem_seed()), "bf66f90db3ab4181e84a6de8faef38f7545dbb22a09738846389b78830e70e689d79aba37dcd211f7cb21122c539eb016e9c85999e9b9810c6a47de2e4bb2e00");
        assert_eq!(h(&k.mldsa_seed()), "68fa1a31f0a754a029df4fd0a1c2dd63beef47cfc3d0b46184dbce983b541e35");
    }

    #[test]
    fn rejects_non_24_words_and_bad_checksum() {
        assert!(Keyring::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "").is_err());
        assert!(Keyring::from_mnemonic(&M.replace("art", "abandon"), "").is_err());
    }

    #[test]
    fn passphrase_changes_everything() {
        assert_ne!(kr("").node_ed25519_seed(), kr("x").node_ed25519_seed());
    }

    #[test]
    fn contexts_are_domain_separated() {
        let k = kr("");
        assert_ne!(k.payment_id(0), k.payment_id(1));
        assert_ne!(k.session_pay_key(0).secret_bytes(), k.p2pk_key(0).secret_bytes());
    }

    #[test]
    fn forced_retry_skips_invalid_scalar() {
        let k = kr("");
        let good = k.derive32("ctx/retry/1");
        let sk = pick_scalar(|i| if i == 0 { [0u8; 32] } else { k.derive32(&format!("ctx/retry/{i}")) });
        assert_eq!(sk.secret_bytes(), good);
        let sk = pick_scalar(|i| if i == 0 { [0xff; 32] } else { k.derive32(&format!("ctx/retry/{i}")) });
        assert_eq!(sk.secret_bytes(), good);
    }

    #[test]
    fn gap_limit_scan() {
        let act = [0u32, 3, 22]; // 3→22: gap de 18 (<20) continua; depois de 22 acaba
        assert_eq!(scan_payments(|n| act.contains(&n)), vec![0, 3, 22]);
        let act = [0u32, 25]; // gap de 24 ≥ 20: 25 não é achado
        assert_eq!(scan_payments(|n| act.contains(&n)), vec![0]);
    }

    #[test]
    fn mlkem_keypair_is_stable_across_restore() {
        let (a, b) = (kr("").mlkem_keypair(), kr("").mlkem_keypair());
        assert_eq!(a.public_key, b.public_key);
        assert_ne!(a.public_key, kr("x").mlkem_keypair().public_key);
        let enc = mycelium_pqc::mlkem_encapsulate(&a.public_key).unwrap();
        let ss = mycelium_pqc::mlkem_decapsulate(b.private_bytes(), &enc.ciphertext).unwrap();
        assert_eq!(ss, enc.shared_secret);
    }

    #[cfg(feature = "mldsa")]
    #[test]
    fn mldsa_key_is_stable_across_restore() {
        use mycelium_zkp::license::mldsa_verify;
        std::thread::Builder::new().stack_size(32 << 20).spawn(|| {
            use mycelium_zkp::license::{Keypair, Signer};
            let (a, b) = (kr("").mldsa_signing_key(), kr("").mldsa_signing_key());
            let vk = a.verifying_key().encode().as_slice().to_vec();
            assert_eq!(vk, b.verifying_key().encode().as_slice().to_vec());
            let sig = b.sign(b"m");
            assert!(mldsa_verify(&vk, b"m", sig.encode().as_slice()));
        }).unwrap().join().unwrap();
    }
}
