use crate::error::MintError;
use crate::policy::MonetaryPolicy;
use crate::proof::{MintReceipt, SporocarpAttestation, WorkClaim};
use blake3::Hasher as Blake3;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use mycelium_core::{NodeId, Nutrient};
use mycelium_nutrients::{Ledger, TxKind};
use mycelium_zkp::{hash_chronicle, pedersen_commit};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Motor de estado determinístico para emissão de criptoativo na mainnet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MainnetMintEngine {
    pub chain_id: String,
    pub policy: MonetaryPolicy,
    pub current_epoch: u64,
    pub total_supply: u64,
    pub epoch_parents: Vec<[u8; 32]>,
    pub used_nullifiers: HashSet<[u8; 32]>,
    pub sporocarps: HashMap<NodeId, [u8; 32]>,
    pub min_quorum: usize,
}

impl MainnetMintEngine {
    pub fn genesis(
        chain_id: impl Into<String>,
        genesis_seed: &[u8],
        policy: MonetaryPolicy,
        sporocarps: HashMap<NodeId, [u8; 32]>,
        min_quorum: usize,
    ) -> Result<Self, MintError> {
        policy.validate()?;
        if min_quorum == 0 || min_quorum > sporocarps.len() {
            return Err(MintError::InvalidPolicy(
                "min_quorum deve estar entre 1 e o total de esporocarpos cadastrados",
            ));
        }
        for (node_id, pubkey) in &sporocarps {
            if NodeId::derive(pubkey) != *node_id {
                return Err(MintError::KeyMismatch(*node_id));
            }
        }

        let chain_id = chain_id.into();
        let mut g = Blake3::new();
        g.update(b"mycelium-mainnet-genesis-v1:");
        g.update(chain_id.as_bytes());
        g.update(genesis_seed);
        let genesis_hash = *g.finalize().as_bytes();

        Ok(Self {
            chain_id,
            policy,
            current_epoch: 0,
            total_supply: 0,
            epoch_parents: vec![genesis_hash],
            used_nullifiers: HashSet::new(),
            sporocarps,
            min_quorum,
        })
    }

    pub fn current_epoch_budget(&self) -> u64 {
        self.policy
            .epoch_budget(self.current_epoch, self.total_supply)
    }

    pub fn compute_batch_root(&self, epoch: u64, claims: &[WorkClaim]) -> [u8; 32] {
        let mut h = Blake3::new();
        h.update(b"mycelium-mint-batch-v1:");
        h.update(self.chain_id.as_bytes());
        h.update(&epoch.to_be_bytes());
        for parent in &self.epoch_parents {
            h.update(parent);
        }
        for claim in claims {
            h.update(&claim.nullifier(&self.chain_id));
            h.update(&claim.units.to_be_bytes());
        }
        *h.finalize().as_bytes()
    }

    pub fn verify_quorum(
        &self,
        epoch: u64,
        batch_root: &[u8; 32],
        attestations: &[SporocarpAttestation],
    ) -> Result<(), MintError> {
        let mut seen = HashSet::with_capacity(attestations.len());
        let expected_payload =
            SporocarpAttestation::payload_bytes(&self.chain_id, epoch, batch_root);

        for att in attestations {
            if att.epoch != epoch || &att.batch_root != batch_root {
                return Err(MintError::InvalidValidatorSignature(att.validator));
            }
            if !seen.insert(att.validator) {
                return Err(MintError::DuplicateValidator(att.validator));
            }
            let pubkey = self
                .sporocarps
                .get(&att.validator)
                .ok_or(MintError::UnauthorizedValidator(att.validator))?;
            let vk = VerifyingKey::from_bytes(pubkey)
                .map_err(|_| MintError::InvalidValidatorSignature(att.validator))?;
            let sig = Signature::from_slice(&att.signature)
                .map_err(|_| MintError::InvalidValidatorSignature(att.validator))?;
            vk.verify(&expected_payload, &sig)
                .map_err(|_| MintError::InvalidValidatorSignature(att.validator))?;
        }

        if seen.len() < self.min_quorum {
            return Err(MintError::InsufficientQuorum {
                got: seen.len(),
                need: self.min_quorum,
            });
        }
        Ok(())
    }

    pub fn settle_epoch(
        &mut self,
        claims: &[WorkClaim],
        attestations: &[SporocarpAttestation],
    ) -> Result<Vec<MintReceipt>, MintError> {
        let budget = self.current_epoch_budget();
        if budget == 0 {
            return Err(MintError::SupplyExhausted);
        }

        let batch_root = self.compute_batch_root(self.current_epoch, claims);
        self.verify_quorum(self.current_epoch, &batch_root, attestations)?;

        let mut batch_nullifiers = HashSet::with_capacity(claims.len());
        let mut validated = Vec::with_capacity(claims.len());
        let mut total_weight: u128 = 0;

        for claim in claims {
            claim.verify(
                &self.chain_id,
                self.current_epoch,
                self.policy.min_hashcash_bits,
            )?;

            let nullifier = claim.nullifier(&self.chain_id);
            if self.used_nullifiers.contains(&nullifier) || !batch_nullifiers.insert(nullifier) {
                return Err(MintError::ReplayedClaim);
            }

            let weight = self.policy.effective_weight(
                claim.kind,
                claim.units,
                claim.producer_spores,
                claim.producer_resilience,
            );
            if weight == 0 {
                return Err(MintError::ZeroWeight(claim.work_id));
            }

            total_weight += weight as u128;
            validated.push((claim, nullifier, weight));
        }

        if validated.is_empty() || total_weight == 0 {
            return Ok(Vec::new());
        }

        let node_cap = self.policy.node_cap(budget);
        let mut minted_per_node: HashMap<NodeId, u64> = HashMap::new();
        let mut receipts = Vec::with_capacity(validated.len());
        let mut next_parents = Vec::with_capacity(validated.len());

        for (claim, nullifier, weight) in validated {
            let raw_share = ((budget as u128 * weight as u128) / total_weight) as u64;
            let already_node = minted_per_node.get(&claim.producer).copied().unwrap_or(0);
            let node_room = node_cap.saturating_sub(already_node);
            let supply_room = self.policy.max_supply.saturating_sub(self.total_supply);

            let amount = raw_share.min(node_room).min(supply_room);
            if amount == 0 {
                self.used_nullifiers.insert(nullifier);
                continue;
            }

            let blinding = Self::derive_blinding(&nullifier, self.current_epoch);
            let commit = pedersen_commit(amount, blinding);
            let nutrient = Self::nutrient_for_kind(claim.kind);

            let mut payload = Vec::with_capacity(112);
            payload.extend_from_slice(&nullifier);
            payload.extend_from_slice(&claim.producer.0);
            payload.extend_from_slice(&amount.to_be_bytes());
            payload.extend_from_slice(&commit);
            let chronicle_hash = hash_chronicle(&payload, &self.epoch_parents);

            self.used_nullifiers.insert(nullifier);
            self.total_supply += amount;
            *minted_per_node.entry(claim.producer).or_default() += amount;
            next_parents.push(chronicle_hash);

            receipts.push(MintReceipt {
                epoch: self.current_epoch,
                chronicle_hash,
                nullifier,
                beneficiary: claim.producer,
                nutrient,
                kind: claim.kind,
                amount,
                pedersen_commit: commit,
                blinding,
            });
        }

        if !next_parents.is_empty() {
            self.epoch_parents = next_parents;
            self.current_epoch += 1;
        }

        Ok(receipts)
    }

    pub fn apply_receipt_to_ledger(
        receipt: &MintReceipt,
        ledger: &mut Ledger,
    ) -> Result<(), MintError> {
        receipt.verify_commitment()?;
        let memo = format!(
            "mainnet-mint:epoch={}:chronicle={}",
            receipt.epoch,
            hex::encode(&receipt.chronicle_hash[..8])
        );
        ledger.feed_kind(receipt.nutrient, receipt.amount, memo, Some(receipt.kind));
        Ok(())
    }

    fn nutrient_for_kind(kind: TxKind) -> Nutrient {
        match kind {
            TxKind::Compute => Nutrient::Atp,
            TxKind::Seeding => Nutrient::Mycelia,
            TxKind::Relay => Nutrient::Spores,
            _ => Nutrient::Atp,
        }
    }

    fn derive_blinding(nullifier: &[u8; 32], epoch: u64) -> [u8; 32] {
        let mut h = Blake3::new();
        h.update(b"mycelium-mint-blinding-v1:");
        h.update(nullifier);
        h.update(&epoch.to_be_bytes());
        *h.finalize().as_bytes()
    }
}
