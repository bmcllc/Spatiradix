//! QVP-2/ARQ adapted for **decentralized PoUW emission**, not asset pricing.
//!
//! The user-supplied ARQ layers inspire work-data quality, concentration
//! controls, regime detection, adaptive budgets and a risk stop. This first
//! consensus profile deliberately uses ONLY in-batch work evidence: no KYC,
//! exchange accounts, identity profiles, USD quotes or off-chain price feeds.
//!
//! IMPORTANT: producers are pseudonymous NodeIds; distinct NodeIds are not
//! proof of distinct people. Claims still require independent validation by
//! the Mint engine, and ARQ cannot create fiat payment liquidity.
//!
//! Consensus uses integers, fixed domains and deterministic serialization.
//! The legacy mint mode remains intact for existing chains.

use crate::error::MintError;
use crate::policy::MonetaryPolicy;
use crate::proof::WorkClaim;
use blake3::Hasher;
use mycelium_core::NodeId;
use mycelium_nutrients::TxKind;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const POLICY_DOMAIN: &[u8] = b"mycelium/mint/arq/policy/v1";
const BATCH_DOMAIN: &[u8] = b"mycelium/mint/arq/batch/v1";

/// Genesis-committed governance. Choosing ARQ changes the chain rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArqMintPolicy {
    /// At least this many kinds of independently verified useful work.
    pub healthy_min_work_kinds: u8,
    /// The number of pseudonymous producers is an imperfect Sybil proxy.
    pub healthy_min_producers: u32,
    /// Concentration threshold of raw units attributed to one producer.
    pub healthy_max_concentration_bps: u16,
    /// Cap on normal PoUW issuance, never higher than monetary policy.
    pub healthy_budget_bps: u16,
    /// Conservative issuance cap on stress, never higher than healthy.
    pub stressed_budget_bps: u16,
}

impl Default for ArqMintPolicy {
    fn default() -> Self {
        Self {
            healthy_min_work_kinds: 2,
            healthy_min_producers: 2,
            healthy_max_concentration_bps: 8_000,
            healthy_budget_bps: 10_000,
            stressed_budget_bps: 2_500,
        }
    }
}

impl ArqMintPolicy {
    pub fn validate(&self) -> Result<(), MintError> {
        if !(1..=3).contains(&self.healthy_min_work_kinds)
            || self.healthy_min_producers == 0
            || !(1..=10_000).contains(&self.healthy_max_concentration_bps)
            || self.healthy_budget_bps > 10_000
            || self.stressed_budget_bps > self.healthy_budget_bps
        {
            return Err(MintError::InvalidPolicy(
                "ARQ consensus policy out of bounds",
            ));
        }
        Ok(())
    }

    /// Stable independent bytes; hashes do not depend on serde formats.
    pub fn policy_hash(&self) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(POLICY_DOMAIN);
        h.update(&[self.healthy_min_work_kinds]);
        h.update(&self.healthy_min_producers.to_be_bytes());
        h.update(&self.healthy_max_concentration_bps.to_be_bytes());
        h.update(&self.healthy_budget_bps.to_be_bytes());
        h.update(&self.stressed_budget_bps.to_be_bytes());
        *h.finalize().as_bytes()
    }

    /// Advisory before the claims are verified. The **engine** verifies every
    /// work proof and quorum before accepting any issuance.
    pub fn evaluate(
        &self,
        claims: &[WorkClaim],
        scheduled_epoch_budget: u64,
    ) -> Result<ArqMintDecision, MintError> {
        self.validate()?;
        let mut work_by_producer: HashMap<NodeId, u128> = HashMap::new();
        let mut seeding = 0u128;
        let mut compute = 0u128;
        let mut relay = 0u128;

        for c in claims {
            if c.units == 0 {
                return Err(MintError::InvalidPolicy(
                    "ARQ claim contains zero work units",
                ));
            }
            match c.kind {
                TxKind::Seeding => {
                    seeding = seeding
                        .checked_add(u128::from(c.units))
                        .ok_or(MintError::InvalidPolicy("ARQ seeding counters overflow"))?
                }
                TxKind::Compute => {
                    compute = compute
                        .checked_add(u128::from(c.units))
                        .ok_or(MintError::InvalidPolicy("ARQ compute counters overflow"))?
                }
                TxKind::Relay => {
                    relay = relay
                        .checked_add(u128::from(c.units))
                        .ok_or(MintError::InvalidPolicy("ARQ relay counters overflow"))?
                }
                _ => return Err(MintError::InvalidPolicy("ARQ rejects non-PoUW claim kind")),
            }
            let total = work_by_producer.entry(c.producer).or_default();
            *total = total
                .checked_add(u128::from(c.units))
                .ok_or(MintError::InvalidPolicy("ARQ producer counters overflow"))?;
        }
        let mut kind_count = 0u8;
        for v in [seeding, compute, relay] {
            if v > 0 {
                kind_count += 1;
            }
        }
        let total_work = seeding
            .checked_add(compute)
            .and_then(|n| n.checked_add(relay))
            .ok_or(MintError::InvalidPolicy("ARQ total counter overflow"))?;
        let max_by_node = work_by_producer.values().copied().max().unwrap_or(0);
        let concentration_bps = if total_work == 0 {
            0
        } else {
            u16::try_from(
                max_by_node
                    .checked_mul(10_000)
                    .ok_or(MintError::InvalidPolicy("ARQ concentration overflow"))?
                    / total_work,
            )
            .map_err(|_| MintError::InvalidPolicy("ARQ concentration invalid"))?
        };
        let producers = u32::try_from(work_by_producer.len())
            .map_err(|_| MintError::InvalidPolicy("ARQ producer count overflow"))?;
        let healthy = total_work != 0
            && kind_count >= self.healthy_min_work_kinds
            && producers >= self.healthy_min_producers
            && concentration_bps <= self.healthy_max_concentration_bps;
        let regime = if total_work == 0 {
            ArqRegime::Halted
        } else if healthy {
            ArqRegime::Healthy
        } else {
            ArqRegime::Stressed
        };
        let budget_bps = match regime {
            ArqRegime::Healthy => self.healthy_budget_bps,
            ArqRegime::Stressed => self.stressed_budget_bps,
            ArqRegime::Halted => 0,
        };
        let allowed = (u128::from(scheduled_epoch_budget) * u128::from(budget_bps)) / 10_000;
        let allowed_epoch_budget =
            u64::try_from(allowed).map_err(|_| MintError::InvalidPolicy("ARQ budget overflow"))?;
        Ok(ArqMintDecision {
            regime,
            work_kinds: kind_count,
            pseudonymous_producers: producers,
            concentration_bps,
            allowed_epoch_budget,
            scheduled_epoch_budget,
            total_work_units: total_work,
            // A risk dial on observable PoUW distribution, NOT a QVP market score.
            health_score_bps: if total_work == 0 {
                0
            } else if healthy {
                10_000
            } else {
                2_500
            },
        })
    }
}

/// Degradation states for an epoch, not investment macro regimes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArqRegime {
    Healthy,
    Stressed,
    Halted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArqMintDecision {
    pub regime: ArqRegime,
    pub work_kinds: u8,
    pub pseudonymous_producers: u32,
    pub concentration_bps: u16,
    pub health_score_bps: u16,
    pub total_work_units: u128,
    pub scheduled_epoch_budget: u64,
    pub allowed_epoch_budget: u64,
}

impl ArqMintDecision {
    fn canonical_digest(&self) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(b"mycelium/mint/arq/decision/v1");
        h.update(&[match self.regime {
            ArqRegime::Healthy => 1,
            ArqRegime::Stressed => 2,
            ArqRegime::Halted => 3,
        }]);
        h.update(&[self.work_kinds]);
        h.update(&self.pseudonymous_producers.to_be_bytes());
        h.update(&self.concentration_bps.to_be_bytes());
        h.update(&self.health_score_bps.to_be_bytes());
        h.update(&self.total_work_units.to_be_bytes());
        h.update(&self.scheduled_epoch_budget.to_be_bytes());
        h.update(&self.allowed_epoch_budget.to_be_bytes());
        *h.finalize().as_bytes()
    }
}

/// Bind ALL mint monetary parameters, not just the ARQ overlay, to the
/// deterministic genesis/epoch root. No serde or float encoding is used.
pub fn monetary_policy_hash(m: &MonetaryPolicy) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"mycelium/mint/arq/monetary-policy/v1");
    for n in [
        m.max_supply,
        m.usdc_per_myc,
        m.initial_epoch_budget,
        m.halving_epochs,
        m.max_node_share_bps,
        m.weight_seeding,
        m.weight_compute,
        m.weight_relay,
    ] {
        h.update(&n.to_be_bytes());
    }
    h.update(&[m.min_hashcash_bits]);
    *h.finalize().as_bytes()
}

/// The quorum attests the policy AND calculated epoch budget. A legacy
/// signature over the old batch root cannot authorize an ARQ epoch.
pub fn arq_batch_root(
    original_batch_root: &[u8; 32],
    monetary: &MonetaryPolicy,
    policy: &ArqMintPolicy,
    decision: &ArqMintDecision,
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(BATCH_DOMAIN);
    h.update(original_batch_root);
    h.update(&monetary_policy_hash(monetary));
    h.update(&policy.policy_hash());
    h.update(&decision.canonical_digest());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mycelium_core::{ContentId, NodeId};

    fn example(kind: TxKind, seed: u8, units: u64, marker: u8) -> WorkClaim {
        WorkClaim::build_signed(
            "mint-arq-test",
            0,
            NodeId::derive(&[seed]),
            &SigningKey::from_bytes(&[seed + 40; 32]),
            ContentId::of(&[marker]),
            kind,
            units,
            2_000,
            3_000,
            4,
        )
    }

    #[test]
    fn work_regimes_only_shrink_the_scheduled_supply() {
        let p = ArqMintPolicy::default();
        let healthy = p
            .evaluate(
                &[
                    example(TxKind::Seeding, 1, 100, 1),
                    example(TxKind::Compute, 2, 100, 2),
                ],
                50_000,
            )
            .unwrap();
        assert_eq!(healthy.regime, ArqRegime::Healthy);
        assert_eq!(healthy.allowed_epoch_budget, 50_000);
        let stressed = p
            .evaluate(&[example(TxKind::Compute, 1, 100, 3)], 50_000)
            .unwrap();
        assert_eq!(stressed.regime, ArqRegime::Stressed);
        assert_eq!(stressed.allowed_epoch_budget, 12_500);
        let halted = p.evaluate(&[], 50_000).unwrap();
        assert_eq!(halted.regime, ArqRegime::Halted);
        assert_eq!(halted.allowed_epoch_budget, 0);
        assert!(healthy.allowed_epoch_budget <= healthy.scheduled_epoch_budget);
    }

    #[test]
    fn policy_hash_and_batch_commitment_change_with_rules_or_signals() {
        let p = ArqMintPolicy::default();
        let work = vec![
            example(TxKind::Seeding, 1, 100, 1),
            example(TxKind::Compute, 2, 100, 2),
        ];
        let d = p.evaluate(&work, 10_000).unwrap();
        let root = [7; 32];
        let monetary = MonetaryPolicy::mainnet();
        assert_ne!(arq_batch_root(&root, &monetary, &p, &d), root);
        let mut alt = p.clone();
        alt.stressed_budget_bps = 1_000;
        assert_ne!(
            arq_batch_root(&root, &monetary, &p, &d),
            arq_batch_root(&root, &monetary, &alt, &d)
        );
        let mut altered_supply_policy = monetary.clone();
        altered_supply_policy.max_supply += 1;
        assert_ne!(
            arq_batch_root(&root, &monetary, &p, &d),
            arq_batch_root(&root, &altered_supply_policy, &p, &d)
        );
    }
}
