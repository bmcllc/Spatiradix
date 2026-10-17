//! Assinaturas pós-quânticas opcionais (ML-DSA).
//!
//! Compilado apenas com a feature `pqc-ml-dsa`. Ed25519 continua sendo o
//! caminho de compatibilidade; a assinatura composta (ed25519 || ML-DSA)
//! permite transição suave entre nós.

#[cfg(feature = "pqc-ml-dsa")]
pub mod ml_dsa {
    use ml_dsa::{
        Keypair, MlDsa65, Signature, SigningKey, Verifier, VerifyingKey,
    };
    use ml_dsa::Signer;
    use rand::rngs::OsRng;
    use rand::RngCore;

    /// Uma chave ML-DSA-65 derivada de uma seed de 32 bytes.
    #[derive(Clone)]
    pub struct MlDsaKey {
        seed: [u8; 32],
        signing: SigningKey<MlDsa65>,
        verifying: VerifyingKey<MlDsa65>,
    }

    impl MlDsaKey {
        pub fn generate() -> Self {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            Self::from_seed(seed)
        }

        pub fn from_seed(seed: [u8; 32]) -> Self {
            let signing = SigningKey::<MlDsa65>::from_seed(&seed.into());
            let verifying = signing.verifying_key();
            Self {
                seed,
                signing,
                verifying,
            }
        }

        pub fn seed(&self) -> [u8; 32] {
            self.seed
        }

        pub fn public_key_bytes(&self) -> Vec<u8> {
            self.verifying.encode().iter().copied().collect()
        }

        pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
            self.signing.sign(msg).encode().iter().copied().collect()
        }

        pub fn verify(public_key: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            let pk_arr: &[u8; 1952] = match public_key.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let vk = VerifyingKey::<MlDsa65>::decode(pk_arr.into());
            let sig_arr: &[u8; 3309] = match sig.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let signature = match Signature::<MlDsa65>::decode(sig_arr.into()) {
                Some(s) => s,
                None => return false,
            };
            vk.verify(msg, &signature).is_ok()
        }
    }

    /// Assinatura composta Ed25519 + ML-DSA. Serializada como
    /// `[ed25519(64) || ml_dsa(sig)]`.
    pub struct CompositeSignature {
        pub ed25519: [u8; 64],
        pub ml_dsa: Vec<u8>,
    }
}
