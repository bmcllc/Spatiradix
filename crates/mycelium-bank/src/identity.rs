use crate::error::BankError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mycelium_pqc::{mlkem_keygen, KemKeyPair};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Carteira soberana: identidade ed25519 (autoria) + par ML-KEM (confidencialidade).
/// A chave privada é materializada localmente e nunca sai do nó.
#[derive(Serialize, Deserialize)]
pub struct SovereignWallet {
    /// Chave de assinatura ed25519 (32 bytes). Armazenada como hex.
    pub signing_seed: [u8; 32],
    /// Seed privada ML-KEM (tamanho da crate) — guardada para rederivação do par.
    pub kem_seed: Vec<u8>,
    pub public_kem: Vec<u8>,
    pub account_id: String,
}

impl SovereignWallet {
    /// Cria uma nova carteira a partir de entropia do SO.
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let mut signing_seed = [0u8; 32];
        rng.fill_bytes(&mut signing_seed);
        let kem = mlkem_keygen();
        let public_kem = kem.public_key.clone();
        let kem_seed = kem.private_bytes().to_vec();
        let account_id = blake3_account(&signing_seed, &public_kem);
        Self {
            signing_seed,
            kem_seed,
            public_kem,
            account_id,
        }
    }

    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.signing_seed)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key().verifying_key()
    }

    /// Assina uma mensagem (hash canônico) com a chave ed25519.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sk = self.signing_key();
        sk.sign(msg).to_bytes()
    }

    /// Encapsula segredo para o par KEM desta carteira (usado pelo contraparte).
    pub fn encapsulate_to(&self) -> Option<mycelium_pqc::KemEncap> {
        mycelium_pqc::mlkem_encapsulate(&self.public_kem).ok()
    }

    /// Decapsula um segredo recebido (lado do destinatário).
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, BankError> {
        let kp = mycelium_pqc::mlkem_keypair_from_private(&self.kem_seed)
            .map_err(|e| BankError::Pqc(e.to_string()))?;
        let _ = kp; // keypair reconstructed implicitly via private key
        mycelium_pqc::mlkem_decapsulate(&self.kem_seed, ciphertext)
            .map_err(|e| BankError::Pqc(e.to_string()))
    }

    /// Verifica assinatura ed25519 sobre bytes.
    pub fn verify(verifying: &VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != 64 {
            return false;
        }
        let arr: [u8; 64] = sig.try_into().unwrap();
        Verifier::verify(verifying, msg, &Signature::from_bytes(&arr)).is_ok()
    }
}

impl Drop for SovereignWallet {
    fn drop(&mut self) {
        self.signing_seed.zeroize();
        self.kem_seed.zeroize();
    }
}

/// Reconstrói um par KEM from private seed (helper).
pub fn kem_pair_from_seed(seed: &[u8]) -> Result<KemKeyPair, BankError> {
    mycelium_pqc::mlkem_keypair_from_private(seed).map_err(|e| BankError::Pqc(e.to_string()))
}

fn blake3_account(signing_seed: &[u8; 32], public_kem: &[u8]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"mycelium-bank-account");
    h.update(signing_seed);
    h.update(public_kem);
    format!("mbk-{}", &h.finalize().to_hex()[..24])
}
