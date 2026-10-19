//! Cegamento de chave por época (mesma ideia do serviço onion v3 do Tor).
//!
//! A identidade mestra `(a, A = a·B)` **nunca** aparece na DHT. Em cada época
//! publica-se sob `A_e = h_e·A`, com `h_e = H("blind" ‖ A ‖ e)`:
//!
//! - quem conhece `A` (o endereço) calcula `A_e` e sabe onde procurar;
//! - quem só observa a DHT/relays vê chaves que mudam a cada época e não
//!   consegue ligá-las entre si nem à identidade mestra;
//! - só quem tem `a` consegue assinar sob `A_e` (escalar `h_e·a`), então
//!   conhecer o endereço não permite forjar registros.

use crate::PkarrError;
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// Duração da época de cegamento (24 h).
pub const EPOCH_SECS: u64 = 86_400;

const BLIND_DOMAIN: &[u8] = b"mycelium-pkarr/blind/v1";
const PREFIX_DOMAIN: &[u8] = b"mycelium-pkarr/blind-prefix/v1";

pub fn epoch_of(unix_secs: u64) -> u64 {
    unix_secs / EPOCH_SECS
}

/// Identidade mestra do serviço anônimo. Deliberadamente **separada** da
/// `Gland`/NodeId do nó: reutilizar a chave do nó ligaria o serviço anônimo
/// à identidade de rede do operador.
pub struct MasterIdentity {
    seed: Zeroizing<[u8; 32]>,
}

impl MasterIdentity {
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(seed.as_mut());
        Self { seed }
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed: Zeroizing::new(seed),
        }
    }

    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    pub fn public(&self) -> [u8; 32] {
        SigningKey::from_bytes(&self.seed)
            .verifying_key()
            .to_bytes()
    }

    /// Chave de assinatura cegada para a época `epoch`.
    pub fn blinded_signer(&self, epoch: u64) -> Result<BlindedSigner, PkarrError> {
        let master_pub = self.public();
        let h = blinding_factor(&master_pub, epoch);

        let mut digest: [u8; 64] = Sha512::digest(self.seed.as_ref()).into();
        let base = ExpandedSecretKey::from_bytes(&digest);
        digest.zeroize();

        let mut prefix_hash = Sha512::new();
        prefix_hash.update(PREFIX_DOMAIN);
        prefix_hash.update(base.hash_prefix);
        prefix_hash.update(epoch.to_be_bytes());
        let mut prefix_full: [u8; 64] = prefix_hash.finalize().into();
        let mut hash_prefix = [0u8; 32];
        hash_prefix.copy_from_slice(&prefix_full[..32]);
        prefix_full.zeroize();

        let esk = ExpandedSecretKey {
            scalar: h * base.scalar,
            hash_prefix,
        };
        hash_prefix.zeroize();

        let vk = VerifyingKey::from(&esk);
        if vk.to_bytes() != blinded_public(&master_pub, epoch)? {
            // Invariante algébrica; se falhar, recusar em vez de publicar.
            return Err(PkarrError::BadKey);
        }
        Ok(BlindedSigner { esk, vk, epoch })
    }
}

pub struct BlindedSigner {
    pub(crate) esk: ExpandedSecretKey,
    pub(crate) vk: VerifyingKey,
    pub epoch: u64,
}

impl BlindedSigner {
    pub fn public(&self) -> [u8; 32] {
        self.vk.to_bytes()
    }
}

fn blinding_factor(master_pub: &[u8; 32], epoch: u64) -> Scalar {
    let mut h = Sha512::new();
    h.update(BLIND_DOMAIN);
    h.update(master_pub);
    h.update(epoch.to_be_bytes());
    Scalar::from_hash(h)
}

/// `A_e = h_e·A`, calculável por qualquer um que conheça `A`.
pub fn blinded_public(master_pub: &[u8; 32], epoch: u64) -> Result<[u8; 32], PkarrError> {
    let point = CompressedEdwardsY(*master_pub)
        .decompress()
        .ok_or(PkarrError::BadKey)?;
    if point.is_small_order() || !point.is_torsion_free() {
        return Err(PkarrError::BadKey);
    }
    let h = blinding_factor(master_pub, epoch);
    Ok((h * point).compress().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::SignedPacket;

    #[test]
    fn blinded_key_signs_verifiably_and_is_unlinkable() {
        let id = MasterIdentity::from_seed([42u8; 32]);
        let s1 = id.blinded_signer(100).unwrap();
        let s2 = id.blinded_signer(101).unwrap();
        assert_ne!(s1.public(), s2.public());
        assert_ne!(s1.public(), id.public());
        assert_eq!(s1.public(), blinded_public(&id.public(), 100).unwrap());

        let p = SignedPacket::sign_expanded(&s1.esk, &s1.vk, 5, vec![1, 2, 3]).unwrap();
        p.verify().unwrap();
        assert_eq!(p.public_key(), &s1.public());
    }

    #[test]
    fn different_identities_differ() {
        let a = MasterIdentity::from_seed([1u8; 32]);
        let b = MasterIdentity::from_seed([2u8; 32]);
        assert_ne!(
            blinded_public(&a.public(), 7).unwrap(),
            blinded_public(&b.public(), 7).unwrap()
        );
    }

    #[test]
    fn small_order_master_rejected() {
        // identidade do grupo (ponto neutro) é de ordem pequena
        let mut neutral = [0u8; 32];
        neutral[0] = 1;
        assert!(blinded_public(&neutral, 1).is_err());
    }
}
