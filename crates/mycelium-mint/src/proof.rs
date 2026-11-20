use crate::error::MintError;
use blake3::Hasher as Blake3;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use mycelium_core::{ContentId, NodeId, Nutrient};
use mycelium_nutrients::TxKind;
use mycelium_zkp::{hashcash_mint_proof, hashcash_verify_proof, pedersen_open, HashcashProof};
use serde::{Deserialize, Serialize};

const NULLIFIER_DOMAIN: &[u8] = b"mycelium-mainnet-mint-nullifier-v1";
const HASHCASH_DOMAIN: &[u8] = b"mycelium-mainnet-hashcash-v1";

#[derive(Serialize)]
struct WorkSignPayload<'a> {
    chain_id: &'a str,
    epoch: u64,
    producer: &'a NodeId,
    counterparty: &'a NodeId,
    work_id: &'a ContentId,
    kind: TxKind,
    units: u64,
}

/// Reivindicação de trabalho útil submetida por um nó para cunhagem na época.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkClaim {
    pub epoch: u64,
    pub producer: NodeId,
    pub counterparty: NodeId,
    pub counterparty_key: [u8; 32],
    pub counterparty_sig: Vec<u8>,
    pub work_id: ContentId,
    pub kind: TxKind,
    pub units: u64,
    pub producer_spores: u64,
    pub producer_resilience: u64,
    pub hashcash: HashcashProof,
}

impl WorkClaim {
    pub fn hashcash_resource(
        chain_id: &str,
        epoch: u64,
        producer: &NodeId,
        work_id: &ContentId,
    ) -> Vec<u8> {
        let mut h = Blake3::new();
        h.update(HASHCASH_DOMAIN);
        h.update(chain_id.as_bytes());
        h.update(&epoch.to_be_bytes());
        h.update(&producer.0);
        h.update(&work_id.0);
        h.finalize().as_bytes().to_vec()
    }

    pub fn sign_payload(&self, chain_id: &str) -> Vec<u8> {
        serde_json::to_vec(&WorkSignPayload {
            chain_id,
            epoch: self.epoch,
            producer: &self.producer,
            counterparty: &self.counterparty,
            work_id: &self.work_id,
            kind: self.kind,
            units: self.units,
        })
        .unwrap_or_default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_signed(
        chain_id: &str,
        epoch: u64,
        producer: NodeId,
        counterparty_signing: &SigningKey,
        work_id: ContentId,
        kind: TxKind,
        units: u64,
        producer_spores: u64,
        producer_resilience: u64,
        hashcash_bits: u8,
    ) -> Self {
        let vk = counterparty_signing.verifying_key();
        let counterparty_key = vk.to_bytes();
        let counterparty = NodeId::derive(&counterparty_key);

        let resource = Self::hashcash_resource(chain_id, epoch, &producer, &work_id);
        let hashcash = hashcash_mint_proof(&resource, hashcash_bits);

        let mut claim = Self {
            epoch,
            producer,
            counterparty,
            counterparty_key,
            counterparty_sig: Vec::new(),
            work_id,
            kind,
            units,
            producer_spores,
            producer_resilience,
            hashcash,
        };
        let payload = claim.sign_payload(chain_id);
        claim.counterparty_sig = counterparty_signing.sign(&payload).to_bytes().to_vec();
        claim
    }

    /// Nullifier permanente para bloquear replay da mesma entrega em qualquer época.
    pub fn nullifier(&self, chain_id: &str) -> [u8; 32] {
        let mut h = Blake3::new();
        h.update(NULLIFIER_DOMAIN);
        h.update(chain_id.as_bytes());
        h.update(&self.work_id.0);
        h.update(&self.producer.0);
        h.update(&self.counterparty.0);
        *h.finalize().as_bytes()
    }

    pub fn verify(
        &self,
        chain_id: &str,
        expected_epoch: u64,
        min_hashcash_bits: u8,
    ) -> Result<(), MintError> {
        if self.epoch != expected_epoch {
            return Err(MintError::EpochMismatch {
                expected: expected_epoch,
                got: self.epoch,
            });
        }
        if self.producer == self.counterparty {
            return Err(MintError::SelfWorkNotAllowed(self.producer));
        }
        if NodeId::derive(&self.counterparty_key) != self.counterparty {
            return Err(MintError::KeyMismatch(self.counterparty));
        }

        let vk = VerifyingKey::from_bytes(&self.counterparty_key)
            .map_err(|_| MintError::InvalidWorkSignature(self.work_id))?;
        let sig = Signature::from_slice(&self.counterparty_sig)
            .map_err(|_| MintError::InvalidWorkSignature(self.work_id))?;
        vk.verify(&self.sign_payload(chain_id), &sig)
            .map_err(|_| MintError::InvalidWorkSignature(self.work_id))?;

        let expected_resource =
            Self::hashcash_resource(chain_id, self.epoch, &self.producer, &self.work_id);
        if !hashcash_verify_proof(&self.hashcash, &expected_resource, min_hashcash_bits) {
            return Err(MintError::InvalidHashcash {
                min_bits: min_hashcash_bits,
            });
        }

        Ok(())
    }
}

/// Atestado de quórum emitido por um esporocarpo verificado (`seeds/mainnet.txt`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SporocarpAttestation {
    pub validator: NodeId,
    pub epoch: u64,
    pub batch_root: [u8; 32],
    pub signature: Vec<u8>,
}

impl SporocarpAttestation {
    pub fn payload_bytes(chain_id: &str, epoch: u64, batch_root: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(chain_id.len() + 48);
        out.extend_from_slice(b"mycelium-sporocarp-quorum-v1:");
        out.extend_from_slice(chain_id.as_bytes());
        out.extend_from_slice(&epoch.to_be_bytes());
        out.extend_from_slice(batch_root);
        out
    }

    pub fn sign(chain_id: &str, epoch: u64, batch_root: [u8; 32], signing: &SigningKey) -> Self {
        let vk = signing.verifying_key();
        let validator = NodeId::derive(vk.as_bytes());
        let payload = Self::payload_bytes(chain_id, epoch, &batch_root);
        let signature = signing.sign(&payload).to_bytes().to_vec();
        Self {
            validator,
            epoch,
            batch_root,
            signature,
        }
    }
}

/// Recibo final de emissão selado na crônica causal (`hash_chronicle`) e comprometido via Pedersen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintReceipt {
    pub epoch: u64,
    pub chronicle_hash: [u8; 32],
    pub nullifier: [u8; 32],
    pub beneficiary: NodeId,
    pub nutrient: Nutrient,
    pub kind: TxKind,
    pub amount: u64,
    pub pedersen_commit: [u8; 32],
    pub blinding: [u8; 32],
}

impl MintReceipt {
    pub fn verify_commitment(&self) -> Result<(), MintError> {
        if pedersen_open(&self.pedersen_commit, self.amount, self.blinding) {
            Ok(())
        } else {
            Err(MintError::CommitmentMismatch)
        }
    }
}
