//! Identidade Soberana unificada do Mycelium Rhizome.
//!
//! A partir da semente `gland.seed` do nó Mycelium (32 bytes), deriva deterministicamente:
//! - `Gland` (Ed25519): assinatura canônica de todos os objetos sociais + `NodeId`
//! - `GhostId` (secp256k1 / Schnorr): compatibilidade nativa com Nostr (NIP-01 / NIP-44)
//! - `KemKeyPair` (ML-KEM-1024 FIPS 203): encapsulamento pós-quântico para chat E2EE
//! - `MasterIdentity` (PKARR): endereço soberano `myc1...` sem DNS

use crate::RhizomeError;
use ed25519_dalek::{Signature, VerifyingKey};
use mycelium_core::NodeId;
use mycelium_ghostid::GhostId;
use mycelium_pheromones::Gland;
use mycelium_pkarr::{Capability, MasterIdentity};
use mycelium_pqc::{mlkem_keygen_from_seed, KemKeyPair};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

const GHOST_CTX: &str = "mycelium/rhizome/v1/ghostid/secp256k1";
const MLKEM_CTX: &str = "mycelium/rhizome/v1/pq/mlkem1024";
const PKARR_CTX: &str = "mycelium/rhizome/v1/pkarr/master";

/// Cartão público exportável da identidade soberana.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentityCard {
    pub node_id: String,
    pub ed25519_pubkey_hex: String,
    pub ghost_pubkey_hex: String,
    pub pkarr_addr: String,
    pub mlkem1024_pubkey_hex: String,
}

/// Conjunto completo de chaves soberanas de um nó Rhizome.
pub struct SovereignKeys {
    seed: Zeroizing<[u8; 32]>,
    gland: Gland,
    ghost_seed: Zeroizing<[u8; 32]>,
    ghost: GhostId,
    kem: KemKeyPair,
    pkarr: MasterIdentity,
}

impl SovereignKeys {
    /// Carrega `{home}/gland.seed` ou germina uma nova identidade persistida com permissão 0600.
    pub fn load_or_create(home: &Path) -> Result<Self, RhizomeError> {
        std::fs::create_dir_all(home)?;
        let seed_path = home.join("gland.seed");
        let seed = if seed_path.exists() {
            let raw = std::fs::read(&seed_path)?;
            if raw.len() != 32 {
                return Err(RhizomeError::InvalidKey(format!(
                    "gland.seed com tamanho inválido: {} bytes (esperado 32)",
                    raw.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&raw);
            arr
        } else {
            let gland = Gland::germinate();
            let arr = gland.seed();
            write_secret_file(&seed_path, &arr)?;
            arr
        };
        Self::from_seed(seed)
    }

    /// Constrói deterministicamente todo o feixe de chaves a partir da semente Ed25519 do nó.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, RhizomeError> {
        let gland = Gland::from_seed(seed);

        // Deriva GhostID secp256k1 determinístico com retry se o escalar cair fora da ordem da curva.
        let mut ghost_seed = [0u8; 32];
        let mut ghost_opt = None;
        for attempt in 0u32..16 {
            let ctx = if attempt == 0 {
                GHOST_CTX.to_string()
            } else {
                format!("{GHOST_CTX}/retry/{attempt}")
            };
            let candidate = blake3::derive_key(&ctx, &seed);
            if let Ok(g) = GhostId::from_secret_bytes(candidate, u64::MAX / 2) {
                ghost_seed = candidate;
                ghost_opt = Some(g);
                break;
            }
        }
        let ghost = ghost_opt
            .ok_or_else(|| RhizomeError::InvalidKey("falha ao derivar GhostID".into()))?;

        // Deriva par ML-KEM-1024 (64 bytes d || z) deterministicamente.
        let mut pq_seed = [0u8; 64];
        blake3::Hasher::new_derive_key(MLKEM_CTX)
            .update(&seed)
            .finalize_xof()
            .fill(&mut pq_seed);
        let kem = mlkem_keygen_from_seed(&pq_seed);
        zeroize::Zeroize::zeroize(&mut pq_seed);

        // Deriva identidade Pkarr isolada (não reutiliza a chave do nó na DHT Pkarr).
        let pkarr_seed = blake3::derive_key(PKARR_CTX, &seed);
        let pkarr = MasterIdentity::from_seed(pkarr_seed);

        Ok(Self {
            seed: Zeroizing::new(seed),
            gland,
            ghost_seed: Zeroizing::new(ghost_seed),
            ghost,
            kem,
            pkarr,
        })
    }

    pub fn gland(&self) -> &Gland {
        &self.gland
    }

    pub fn node_id(&self) -> NodeId {
        self.gland.node_id()
    }

    pub fn node_id_hex(&self) -> String {
        self.gland.node_id().to_string()
    }

    pub fn ed25519_pubkey_hex(&self) -> String {
        hex::encode(self.gland.verifying_key().as_bytes())
    }

    pub fn ghost(&self) -> &GhostId {
        &self.ghost
    }

    pub fn ghost_secret_bytes(&self) -> &[u8; 32] {
        &self.ghost_seed
    }

    pub fn ghost_pubkey_hex(&self) -> String {
        self.ghost.nostr_pubkey_hex()
    }

    pub fn mlkem(&self) -> &KemKeyPair {
        &self.kem
    }

    pub fn mlkem_pubkey_hex(&self) -> String {
        hex::encode(&self.kem.public_key)
    }

    pub fn pkarr_identity(&self) -> &MasterIdentity {
        &self.pkarr
    }

    pub fn pkarr_address(&self) -> String {
        Capability {
            master_public: self.pkarr.public(),
            access_secret: None,
        }
        .to_address()
    }

    pub fn public_card(&self) -> PublicIdentityCard {
        PublicIdentityCard {
            node_id: self.node_id_hex(),
            ed25519_pubkey_hex: self.ed25519_pubkey_hex(),
            ghost_pubkey_hex: self.ghost_pubkey_hex(),
            pkarr_addr: self.pkarr_address(),
            mlkem1024_pubkey_hex: self.mlkem_pubkey_hex(),
        }
    }

    /// Assina um payload com separação de domínio explícita (`domain || 0x00 || payload`).
    pub fn sign_domain(&self, domain: &str, payload: &[u8]) -> String {
        let mut framed = Vec::with_capacity(domain.len() + 1 + payload.len());
        framed.extend_from_slice(domain.as_bytes());
        framed.push(0x00);
        framed.extend_from_slice(payload);
        hex::encode(self.gland.sign_bytes(&framed))
    }

    /// Semente interna (usada apenas quando precisa recriar a instância em memória).
    pub fn seed_bytes(&self) -> [u8; 32] {
        *self.seed
    }
}

/// Verifica assinatura Ed25519 estrita (`verify_strict`) com separação de domínio e
/// confere que o `NodeId` declarado corresponde exatamente ao BLAKE3 da chave pública.
pub fn verify_domain_signature(
    expected_node_id: &str,
    ed25519_pubkey_hex: &str,
    domain: &str,
    payload: &[u8],
    signature_hex: &str,
) -> Result<NodeId, RhizomeError> {
    let pk_bytes: [u8; 32] = hex::decode(ed25519_pubkey_hex)
        .map_err(|e| RhizomeError::InvalidKey(format!("pubkey hex inválido: {e}")))?
        .try_into()
        .map_err(|_| RhizomeError::InvalidKey("pubkey Ed25519 deve ter 32 bytes".into()))?;

    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| RhizomeError::InvalidKey(format!("pubkey Ed25519 malformada: {e}")))?;

    let derived = NodeId::derive(&pk_bytes);
    if derived.to_string() != expected_node_id {
        return Err(RhizomeError::InvalidSignature(format!(
            "NodeId {} não corresponde à chave pública Ed25519 (derivado {})",
            expected_node_id, derived
        )));
    }

    let sig_bytes: [u8; 64] = hex::decode(signature_hex)
        .map_err(|e| RhizomeError::InvalidSignature(format!("assinatura hex inválida: {e}")))?
        .try_into()
        .map_err(|_| RhizomeError::InvalidSignature("assinatura Ed25519 deve ter 64 bytes".into()))?;
    let sig = Signature::from_bytes(&sig_bytes);

    let mut framed = Vec::with_capacity(domain.len() + 1 + payload.len());
    framed.extend_from_slice(domain.as_bytes());
    framed.push(0x00);
    framed.extend_from_slice(payload);

    vk.verify_strict(&framed, &sig)
        .map_err(|_| RhizomeError::InvalidSignature("verificação Ed25519 estrita falhou".into()))?;

    Ok(derived)
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<(), RhizomeError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_identity_derivation_and_strict_signing() {
        let k1 = SovereignKeys::from_seed([0x21; 32]).unwrap();
        let k2 = SovereignKeys::from_seed([0x21; 32]).unwrap();

        assert_eq!(k1.public_card(), k2.public_card());
        assert!(k1.pkarr_address().starts_with("myc1"));
        assert_eq!(k1.ghost_pubkey_hex().len(), 64);
        assert!(k1.mlkem().public_key.len() > 1000);

        let sig = k1.sign_domain("mycelium-rhizome/test/v1", b"payload-ok");
        verify_domain_signature(
            &k1.node_id_hex(),
            &k1.ed25519_pubkey_hex(),
            "mycelium-rhizome/test/v1",
            b"payload-ok",
            &sig,
        )
        .expect("assinatura válida deve passar");

        // Adulteração de payload deve ser rejeitada
        assert!(verify_domain_signature(
            &k1.node_id_hex(),
            &k1.ed25519_pubkey_hex(),
            "mycelium-rhizome/test/v1",
            b"payload-tampered",
            &sig,
        )
        .is_err());

        // Domínio trocado deve ser rejeitado
        assert!(verify_domain_signature(
            &k1.node_id_hex(),
            &k1.ed25519_pubkey_hex(),
            "mycelium-rhizome/other/v1",
            b"payload-ok",
            &sig,
        )
        .is_err());

        // Troca de NodeId deve ser rejeitada
        let other = SovereignKeys::from_seed([0x99; 32]).unwrap();
        assert!(verify_domain_signature(
            &other.node_id_hex(),
            &k1.ed25519_pubkey_hex(),
            "mycelium-rhizome/test/v1",
            b"payload-ok",
            &sig,
        )
        .is_err());
    }
}
