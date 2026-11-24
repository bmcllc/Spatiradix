use crate::arq::{arq_batch_root, monetary_policy_hash, ArqMintDecision, ArqMintPolicy};
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
    /// Committed in the genesis hash; legacy chains continue with None.
    #[serde(default)]
    arq_mint_policy: Option<ArqMintPolicy>,
}

/// Fotografia auditável do papel do `mycelium-mint` como reserva lastreadora de CPX.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpxReserveStatus {
    pub chain_id: String,
    pub current_epoch: u64,
    pub reserve_myc_base: u64,
    pub max_supply_myc_base: u64,
    pub usdc_per_myc: u64,
    pub cpx_per_myc: u64,
    pub cpx_backing_capacity_base: u128,
    pub cpx_circulating_base: u128,
    /// Cobertura da reserva em basis points (`10_000` = 100% lastreado).
    pub reserve_coverage_bps: u64,
    pub fully_backed: bool,
    pub head_chronicle_hex: String,
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
            arq_mint_policy: None,
        })
    }

    /// Separate, explicit consensus mode: ARQ is pinned at genesis.
    /// No identity documents, external prices or KYC inputs are needed.
    pub fn genesis_arq(
        chain_id: impl Into<String>,
        genesis_seed: &[u8],
        policy: MonetaryPolicy,
        sporocarps: HashMap<NodeId, [u8; 32]>,
        min_quorum: usize,
        arq_policy: ArqMintPolicy,
    ) -> Result<Self, MintError> {
        arq_policy.validate()?;
        let mut engine = Self::genesis(chain_id, genesis_seed, policy, sporocarps, min_quorum)?;
        let mut h = Blake3::new();
        h.update(b"mycelium/mint/arq/genesis/v1");
        h.update(&engine.epoch_parents[0]);
        h.update(&monetary_policy_hash(&engine.policy));
        h.update(&arq_policy.policy_hash());
        engine.epoch_parents[0] = *h.finalize().as_bytes();
        engine.arq_mint_policy = Some(arq_policy);
        Ok(engine)
    }

    pub fn arq_policy(&self) -> Option<&ArqMintPolicy> {
        self.arq_mint_policy.as_ref()
    }

    /// Intended for validators: verify all PoUW claims BEFORE signing the
    /// ARQ root. A preview call alone is not a settlement authorization.
    pub fn compute_arq_batch_root(
        &self,
        claims: &[WorkClaim],
    ) -> Result<([u8; 32], ArqMintDecision), MintError> {
        let policy = self
            .arq_mint_policy
            .as_ref()
            .ok_or(MintError::ArqModeMismatch)?;
        let mut batch_nullifiers = HashSet::new();
        for claim in claims {
            claim.verify(
                &self.chain_id,
                self.current_epoch,
                self.policy.min_hashcash_bits,
            )?;
            let id = claim.nullifier(&self.chain_id);
            if self.used_nullifiers.contains(&id) || !batch_nullifiers.insert(id) {
                return Err(MintError::ReplayedClaim);
            }
            if self.policy.effective_weight(
                claim.kind,
                claim.units,
                claim.producer_spores,
                claim.producer_resilience,
            ) == 0
            {
                return Err(MintError::ZeroWeight(claim.work_id));
            }
        }
        let decision = policy.evaluate(claims, self.current_epoch_budget())?;
        let base = self.compute_batch_root(self.current_epoch, claims);
        Ok((
            arq_batch_root(&base, &self.policy, policy, &decision),
            decision,
        ))
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

    /// Legacy chains cannot bypass an ARQ governance policy.
    pub fn settle_epoch(
        &mut self,
        claims: &[WorkClaim],
        attestations: &[SporocarpAttestation],
    ) -> Result<Vec<MintReceipt>, MintError> {
        if self.arq_mint_policy.is_some() {
            return Err(MintError::ArqModeMismatch);
        }
        let root = self.compute_batch_root(self.current_epoch, claims);
        self.settle_epoch_checked(claims, attestations, self.current_epoch_budget(), root)
    }

    /// Consensus-bound ARQ emission. The batch root commits the governance
    /// profile and data-derived budget, so nodes cannot silently reprice work.
    pub fn settle_epoch_arq(
        &mut self,
        claims: &[WorkClaim],
        attestations: &[SporocarpAttestation],
    ) -> Result<Vec<MintReceipt>, MintError> {
        let (root, decision) = self.compute_arq_batch_root(claims)?;
        if decision.allowed_epoch_budget == 0 {
            return Err(MintError::ArqEpochHalted);
        }
        self.settle_epoch_checked(claims, attestations, decision.allowed_epoch_budget, root)
    }

    fn settle_epoch_checked(
        &mut self,
        claims: &[WorkClaim],
        attestations: &[SporocarpAttestation],
        budget: u64,
        batch_root: [u8; 32],
    ) -> Result<Vec<MintReceipt>, MintError> {
        if budget == 0 {
            return Err(MintError::SupplyExhausted);
        }
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

    /// Retorna o estado verificável da reserva MYC do `mycelium-mint` lastreando a moeda CPX.
    pub fn cpx_reserve_status(&self, cpx_circulating_base: u128) -> CpxReserveStatus {
        let backing_capacity = self.policy.myc_reserve_to_cpx(self.total_supply);
        let coverage_bps = if cpx_circulating_base == 0 {
            if backing_capacity > 0 { 10_000 } else { 0 }
        } else {
            let ratio = backing_capacity
                .saturating_mul(10_000)
                / cpx_circulating_base;
            ratio.min(u64::MAX as u128) as u64
        };
        let head = self
            .epoch_parents
            .first()
            .map(hex::encode)
            .unwrap_or_default();
        CpxReserveStatus {
            chain_id: self.chain_id.clone(),
            current_epoch: self.current_epoch,
            reserve_myc_base: self.total_supply,
            max_supply_myc_base: self.policy.max_supply,
            usdc_per_myc: self.policy.usdc_per_myc,
            cpx_per_myc: self.policy.usdc_per_myc,
            cpx_backing_capacity_base: backing_capacity,
            cpx_circulating_base,
            reserve_coverage_bps: coverage_bps,
            fully_backed: backing_capacity >= cpx_circulating_base,
            head_chronicle_hex: head,
        }
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
