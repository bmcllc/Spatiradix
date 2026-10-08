//! ComputeRewardAdapter — P6 Opportunity Adapter for CQR-ME Verifiable Compute.
//!
//! # Structural Constraints
//!
//! 1. **No Private Key**: Neither the CQR worker nor this adapter holds or receives any signing key.
//! 2. **No Broadcast**: Cannot transmit or sign blockchain transactions. Only S1 Executor executes.
//! 3. **External Reward Requirement**: A CQR result produces 0 VerifiedNev unless an external party
//!    settles a real payment verified through authenticated chain evidence.

use super::job::{CqrComputeLevel, CqrJobSpec};
use super::kernel::PhaseSpacePoint;
use super::proof::CqrResultProof;
use super::result::CqrResult;
use crate::discovery::{
    BudgetSpend, EvidenceDefect, MeasuredEdge, ObservedThermal, OpportunityAdapter,
    OpportunityClass, SearchObservation, SearchPermit, SettlementReadiness,
    ValuationReadiness,
};
use crate::{EconomyError, Result};
use serde::{Deserialize, Serialize};

/// Domain separation for the digest a proof commits to its validation suite.
///
/// Its own domain, distinct from [`crate::cqr::proof::CQR_PROOF_DOMAIN`] (the
/// proof digest) and [`crate::cqr::job::CQR_JOB_DOMAIN`] (the job hash). The
/// suite list already appears inside the job hash; this digest exists so the
/// proof carries the suite *on its own*, and sharing a domain with either of the
/// other two would make that redundant rather than independent.
pub const CQR_VALIDATION_SUITE_DOMAIN: &[u8] = b"MYCELIUM-ECONOMY/CQR-VALIDATION-SUITE/V1";

/// The one refusal [`UnverifiedComputeEvidence::verify`] returns, as a fixed
/// string: the stable marker that callers and tests match on when they cannot
/// — or will not — match on the error type.
///
/// It is deliberately a fixed string rather than a value assembled from the
/// evidence at the call site: the refusal must be recognisable without trusting
/// the evidence that produced it. The typed form is
/// [`crate::EconomyError::RewardBindingIncomplete`], which carries the specific
/// missing binding in its payload; this constant is the same refusal in the
/// form a caller can match without depending on `EconomyError`'s shape, and its
/// text is the prefix every such message begins with. Prefer the variant, where
/// the caller is in this crate or can name the type — but this constant stays
/// exported and unchanged, so the path
/// `mycelium_economy::cqr::adapter::REWARD_BINDING_INCOMPLETE` and the substring
/// it carries both keep working.
pub const REWARD_BINDING_INCOMPLETE: &str =
    "RewardBindingIncomplete: delegated attestation does not sign the external payment identity";

/// Commits a job's declared validation suite to the digest its proof carries.
///
/// Built with [`crate::policy_auth::push_tagged`], the crate's canonical
/// encoder (`LEN:u32be || TAG || LEN:u32be || VALUE`), so the list cannot be
/// reshaped into a different suite without changing the preimage: entry count,
/// entry order and any shared prefix between two entries are all covered.
fn validation_suite_digest(suite: &[String]) -> String {
    let mut buf = Vec::new();
    crate::policy_auth::push_tagged(&mut buf, b"domain", CQR_VALIDATION_SUITE_DOMAIN);
    crate::policy_auth::push_tagged(&mut buf, b"count", &(suite.len() as u32).to_be_bytes());
    for (index, entry) in suite.iter().enumerate() {
        crate::policy_auth::push_tagged(&mut buf, b"index", &(index as u32).to_be_bytes());
        crate::policy_auth::push_tagged(&mut buf, b"entry", entry.as_bytes());
    }
    let mut hasher =
        blake3::Hasher::new_keyed(&super::state_bus::blake3_derive_key(CQR_VALIDATION_SUITE_DOMAIN));
    hasher.update(&buf);
    hasher.finalize().to_hex().to_string()
}

/// Lifecycle status of the ComputeReward opportunity class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputeRewardStatus {
    /// Class is defined but no adapter exists.
    Unsupported,
    /// Adapter runs and computes locally, but no real external market is attached.
    Experimental,
    /// Adapter produces cryptographic proofs verifiable by external protocols.
    Verifiable,
    /// Connected to a real external market with verified net settlement inflows.
    Real,
}

/// An observed compute opportunity from an external or internal source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeOpportunity {
    pub opportunity_id: String,
    pub source: String,
    pub compute_level: CqrComputeLevel,
    pub offered_reward_musd_micros: u64,
    pub estimated_cost_musd_micros: u64,
    pub job_spec: CqrJobSpec,
    pub initial_state: PhaseSpacePoint,
}

/// A validated compute opportunity satisfying economic and resource gates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedComputeOpportunity {
    pub opportunity_id: String,
    pub robust_net_musd_micros: u64,
    pub job_spec: CqrJobSpec,
    pub initial_state: PhaseSpacePoint,
}

/// An execution intent produced for S1 (read-only data structure, no transmission).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeExecutionIntent {
    pub intent_id: String,
    pub job_id: String,
    pub result_digest: String,
    pub proof_digest: String,
    pub target_contract_or_counterparty: String,
    pub expected_reward_musd_micros: u64,
}

/// External reward evidence received after delivery of verified compute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRewardEvidence {
    pub settlement_tx_hash: String,
    pub chain_id: u64,
    pub payer: String,
    pub recipient: String,
    pub gross_amount_musd_micros: u64,
    pub job_id: String,
    pub result_digest: String,
}

/// Unverified compute evidence received before cryptographic policy verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnverifiedComputeEvidence {
    pub proof: CqrResultProof,
    pub reward: ExternalRewardEvidence,
    pub attestation: super::proof::CqrResultAttestation,
}

impl UnverifiedComputeEvidence {
    pub fn new(
        proof: CqrResultProof,
        reward: ExternalRewardEvidence,
        attestation: super::proof::CqrResultAttestation,
    ) -> Self {
        Self {
            proof,
            reward,
            attestation,
        }
    }

    /// Cryptographically verifies that:
    /// 1. The compute proof integrity holds.
    /// 2. The reward evidence is strictly bound to this job_id and result_digest.
    /// 3. The attestation is signed by the delegated verifier authorized in the policy.
    ///
    /// It then refuses, always. That refusal is the answer, not a placeholder.
    ///
    /// # What is bound
    ///
    /// * `proof` — fully. [`CqrResultProof::verify_integrity`] re-derives
    ///   `proof_digest` over the job hash, the input and output state hashes, the
    ///   implementation identity and version, the validation-suite digest, the
    ///   result digest and the worker identity.
    /// * `attestation` — fully, but only *about the proof*.
    ///   [`crate::cqr::proof::CqrResultAttestation::verify`] re-derives
    ///   [`crate::cqr::proof::CqrResultProof::attestation_preimage`], which
    ///   is exactly `domain || policy_hash || proof_digest || result_digest ||
    ///   job_hash`, and checks it against the signature of the key the policy
    ///   delegates to.
    /// * `reward.job_id` — bound to `proof.job_id`, by string equality.
    /// * `reward.result_digest` — bound to `proof.result_digest`, by string
    ///   equality.
    ///
    /// # What is not bound
    ///
    /// Nothing else about the reward. `settlement_tx_hash`, `chain_id`, `payer`,
    /// `recipient` and `gross_amount_musd_micros` appear in **no** signed
    /// preimage — not in the attestation preimage above, and not in the proof
    /// digest. They are caller-supplied strings and integers, free to be set to
    /// anything by whoever assembled this evidence. The two fields that *are*
    /// checked are checked by equality against values the proof already fixes, so
    /// matching them proves only that the attacker read the proof, not that a
    /// payment purchased it.
    ///
    /// # Why it refuses anyway
    ///
    /// Because the remaining checks are real but not sufficient, and returning
    /// `Ok` here would mint an [`AuthenticatedComputeEvidence`] whose payment
    /// fields are entirely unauthenticated. The refusal is
    /// [`EconomyError::RewardBindingIncomplete`], whose message begins with
    /// [`REWARD_BINDING_INCOMPLETE`] so callers and tests can recognise it
    /// either way. Lifting it requires an external payment identity that is
    /// actually signed — a settlement receipt, or a delegated attestation whose
    /// preimage includes the transaction hash and amount.
    pub fn verify(
        self,
        policy: &crate::policy_auth::ValidatedOutcomePolicy,
    ) -> Result<AuthenticatedComputeEvidence> {
        if !self.proof.verify_integrity() {
            return Err(EconomyError::Invalid("CQR proof integrity check failed".into()));
        }
        if self.reward.job_id != self.proof.job_id {
            return Err(EconomyError::Invalid(format!(
                "reward evidence job_id '{}' does not match proof job_id '{}'",
                self.reward.job_id, self.proof.job_id
            )));
        }
        if self.reward.result_digest != self.proof.result_digest {
            return Err(EconomyError::Invalid(format!(
                "reward evidence result_digest '{}' does not match proof result_digest '{}'",
                self.reward.result_digest, self.proof.result_digest
            )));
        }
        self.attestation
            .verify(&self.proof, policy)
            .map_err(|e| EconomyError::Invalid(format!("CQR attestation cryptographic verification failed: {e}")))?;

        // The existing delegated signature authenticates the computation only.
        // Caller supplied payment labels cannot prove that a payment purchased it.
        // Typed refusal, not `Invalid`: the reason is the same one the const
        // records, and its `Display` starts with the const's exact text.
        Err(EconomyError::RewardBindingIncomplete(
            "attestation_preimage signs domain, policy_hash, proof_digest, result_digest and job_hash, and no field of the external payment identity",
        ))
    }
}

/// Authenticated compute evidence; settlement and trusted valuation remain separate gates.
///
/// Private fields with no `Deserialize`: cannot be constructed by arbitrary callers
/// or forged from JSON payloads. Can ONLY be created via `UnverifiedComputeEvidence::verify`.
///
/// **That constructor never succeeds today, so this type is currently
    /// unconstructible.** [`UnverifiedComputeEvidence::verify`] always returns
    /// [`EconomyError::RewardBindingIncomplete`] — whose message begins with
    /// [`REWARD_BINDING_INCOMPLETE`] — because
    /// [`crate::cqr::proof::CqrResultProof::attestation_preimage`] signs the
    /// domain, the policy hash, the proof digest, the result digest and the job hash
/// — and none of `settlement_tx_hash`, `chain_id`, `payer`, `recipient` or
/// `gross_amount_musd_micros`. There is therefore no
/// `AuthenticatedComputeEvidence` value in existence, by construction rather than
/// by omission.
///
/// That is the intended state, not a gap to be tidied away: there is no real
/// external compute market for this adapter to be paid by, so the honest reading
/// of a CQR result is that it produced 0 VerifiedNev. A caller that needs a value
/// of this type needs a signed payment identity first. Its accessors stay because
/// they are the contract a real settlement path will have to satisfy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthenticatedComputeEvidence {
    proof: CqrResultProof,
    reward: ExternalRewardEvidence,
    attestation: super::proof::CqrResultAttestation,
}

impl AuthenticatedComputeEvidence {
    pub fn proof(&self) -> &CqrResultProof {
        &self.proof
    }

    pub fn reward(&self) -> &ExternalRewardEvidence {
        &self.reward
    }

    pub fn attestation(&self) -> &super::proof::CqrResultAttestation {
        &self.attestation
    }
}

/// The P6 Compute Reward Adapter.
pub struct ComputeRewardAdapter {
    identity: String,
    status: ComputeRewardStatus,
    active_opportunity: Option<ComputeOpportunity>,
}

impl ComputeRewardAdapter {
    /// Creates an experimental adapter with no external payment channel attached.
    pub fn new_experimental(identity: impl Into<String>) -> Self {
        Self {
            identity: identity.into(),
            status: ComputeRewardStatus::Experimental,
            active_opportunity: None,
        }
    }

    /// Creates a verifiable adapter with an active opportunity.
    pub fn new_verifiable(
        identity: impl Into<String>,
        opportunity: ComputeOpportunity,
    ) -> Self {
        Self {
            identity: identity.into(),
            status: ComputeRewardStatus::Verifiable,
            active_opportunity: Some(opportunity),
        }
    }

    pub fn status(&self) -> ComputeRewardStatus {
        self.status
    }

    /// Stage 1: Discover compute opportunity.
    pub fn discover(&self) -> Option<&ComputeOpportunity> {
        self.active_opportunity.as_ref()
    }

    /// Stage 2: Validate opportunity against resource and economic thresholds.
    pub fn validate(&self, opp: &ComputeOpportunity) -> Result<ValidatedComputeOpportunity> {
        if !opp.compute_level.is_verifiable_compute_reward_ready() {
            return Err(EconomyError::Invalid(format!(
                "compute level {} is not verifiable for compute reward",
                opp.compute_level.as_str()
            )));
        }
        let net = opp.offered_reward_musd_micros.saturating_sub(opp.estimated_cost_musd_micros);
        Ok(ValidatedComputeOpportunity {
            opportunity_id: opp.opportunity_id.clone(),
            robust_net_musd_micros: net,
            job_spec: opp.job_spec.clone(),
            initial_state: opp.initial_state.clone(),
        })
    }

    /// Stage 3: Build CqrJobSpec.
    pub fn build_job(&self, validated: &ValidatedComputeOpportunity) -> CqrJobSpec {
        validated.job_spec.clone()
    }

    /// Stage 4: Execute computation locally.
    pub fn execute_local(
        &self,
        job_spec: &CqrJobSpec,
        initial_state: PhaseSpacePoint,
    ) -> Result<CqrResult> {
        self.execute_local_with_thermal(job_spec, initial_state, &super::oscillators::SystemThermalSource)
            .map(|(res, _)| res)
    }

    /// Execute computation locally with custom thermal source.
    pub fn execute_local_with_thermal(
        &self,
        job_spec: &CqrJobSpec,
        initial_state: PhaseSpacePoint,
        thermal_source: &dyn super::oscillators::ThermalSource,
    ) -> Result<(CqrResult, f64)> {
        super::oscillators::run_benchmark_with_thermal(job_spec, initial_state, thermal_source)
            .map_err(|e| EconomyError::Invalid(e.to_string()))
    }

    /// Stage 5: Verify result and generate cryptographic proof.
    ///
    /// The proof's own `validation_suite_digest` is computed from
    /// `job_spec.validation_suite`, so the suite the job *declared* reaches the
    /// artefact that claims to satisfy it. It used to be the constant
    /// `blake3::hash(b"validation_suite:v1")`, which meant every proof in the
    /// crate carried the same suite digest no matter what the job asked for: a
    /// proof asserting it satisfied an empty suite, and one asserting it
    /// satisfied a fifty-check suite, were cryptographically indistinguishable
    /// on that field.
    pub fn verify_result(
        &self,
        job_spec: &CqrJobSpec,
        result: &CqrResult,
        worker_id: &str,
    ) -> Result<CqrResultProof> {
        if !result.validation_passed {
            return Err(EconomyError::Invalid("CQR result did not pass validation".into()));
        }
        let suite_digest = validation_suite_digest(&job_spec.validation_suite);

        Ok(CqrResultProof::new(
            format!("proof-{}", result.job_id),
            &result.job_id,
            &result.job_hash,
            &result.input_state_hash,
            &result.output_state_hash,
            &result.implementation_id,
            &result.implementation_version,
            suite_digest,
            &result.result_digest,
            worker_id,
        ))
    }

    /// Stage 6: Build execution intent for S1 Executor (read-only).
    pub fn build_execution_intent(
        &self,
        proof: &CqrResultProof,
        counterparty: &str,
        reward_micros: u64,
    ) -> ComputeExecutionIntent {
        ComputeExecutionIntent {
            intent_id: format!("intent-{}", proof.job_id),
            job_id: proof.job_id.clone(),
            result_digest: proof.result_digest.clone(),
            proof_digest: proof.proof_digest.clone(),
            target_contract_or_counterparty: counterparty.to_string(),
            expected_reward_musd_micros: reward_micros,
        }
    }

    /// Stage 7: Reconcile external reward (if any).
    pub fn reconcile(
        &self,
        proof: &CqrResultProof,
        external_tx: Option<ExternalRewardEvidence>,
    ) -> Option<ExternalRewardEvidence> {
        if let Some(ref tx) = external_tx {
            if tx.job_id != proof.job_id || tx.result_digest != proof.result_digest {
                return None;
            }
        }
        external_tx
    }

    /// Stage 8: Package evidence into unverified compute evidence.
    pub fn package_evidence(
        &self,
        proof: CqrResultProof,
        reward: ExternalRewardEvidence,
        attestation: super::proof::CqrResultAttestation,
    ) -> UnverifiedComputeEvidence {
        UnverifiedComputeEvidence::new(proof, reward, attestation)
    }

    /// The observation body, with the thermal source as a parameter.
    ///
    /// Inherent rather than part of [`OpportunityAdapter`] on purpose: the trait
    /// must keep one `observe` for the machine, and hardwiring
    /// [`SystemThermalSource`](super::oscillators::SystemThermalSource) into that
    /// one method meant this adapter's thermal path could not be exercised by any
    /// test, and that `observe` failed outright on hardware exposing no sensors.
    /// The trait method below is now a one-line delegation to this one.
    pub fn observe_with_thermal(
        &self,
        permit: &SearchPermit,
        now_unix: u64,
        thermal_source: &dyn super::oscillators::ThermalSource,
    ) -> Result<SearchObservation> {
        // `now_unix` is part of the adapter contract and is forwarded verbatim by
        // the trait impl, but a CQR observation carries no timestamp of its own,
        // so nothing in this body reads it.
        let _ = now_unix;

        // Enforce permit class match
        if permit.class != OpportunityClass::ComputeReward {
            return Ok(SearchObservation::defective(
                OpportunityClass::ComputeReward,
                &self.identity,
                permit.cycle,
                EvidenceDefect::ClassMismatch {
                    why: format!(
                        "permit class {} does not match adapter class {}",
                        permit.class.state(),
                        OpportunityClass::ComputeReward.state()
                    ),
                },
            ));
        }

        // Under Experimental or Verifiable without external reward source:
        // robust net external edge is negative or 0 (measured negative edge).
        match &self.active_opportunity {
            Some(opp) => {
                let validated = self.validate(opp)?;
                let (result, thermal) = super::oscillators::run_benchmark_with_telemetry(
                    &validated.job_spec,
                    validated.initial_state.clone(),
                    thermal_source,
                ).map_err(|e| EconomyError::Invalid(e.to_string()))?;
                let _proof = self.verify_result(&validated.job_spec, &result, &self.identity)?;

                let observed_thermal = ObservedThermal {
                    start_max_c: Some(thermal.start_c),
                    end_c: Some(thermal.end_c),
                    // The mid-run peak, not just the two endpoints: a job that
                    // climbed to 80 °C and cooled back down before it finished
                    // reported only "40, 45" here and read as a cool search.
                    maximum_c: Some(thermal.maximum_c),
                };

                let (robust_net, token_edge) = if self.status == ComputeRewardStatus::Real {
                    let net = (opp.offered_reward_musd_micros as i64) - (opp.estimated_cost_musd_micros as i64);
                    (net, Some(opp.offered_reward_musd_micros as i64))
                } else {
                    (-(opp.estimated_cost_musd_micros as i64), Some(0))
                };

                let measured = MeasuredEdge {
                    token_edge_micros: token_edge,
                    robust_net_micros: robust_net,
                    source_field: "cqr_compute_reward".into(),
                };

                Ok(SearchObservation {
                    schema_version: crate::SCHEMA_VERSION,
                    class: OpportunityClass::ComputeReward,
                    adapter: self.identity.clone(),
                    cycle: permit.cycle,
                    cycles_budgeted: 1,
                    cycles_completed: 1,
                    cells_scanned: Some(1),
                    aborted: false,
                    candidates: Vec::new(),
                    best_observed_edge: Some(measured),
                    settlement: SettlementReadiness::NotApplicable,
                    valuation: ValuationReadiness::NotRequired,
                    thermal: observed_thermal,
                    spend: BudgetSpend::cycles(1),
                    resolution: None,
                    defect: None,
                })
            }
            None => {
                // Scanned with no active opportunity: measured negative edge
                let measured = MeasuredEdge {
                    token_edge_micros: Some(0),
                    robust_net_micros: -10_000,
                    source_field: "cqr_compute_reward_idle".into(),
                };
                Ok(SearchObservation {
                    schema_version: crate::SCHEMA_VERSION,
                    class: OpportunityClass::ComputeReward,
                    adapter: self.identity.clone(),
                    cycle: permit.cycle,
                    cycles_budgeted: 1,
                    cycles_completed: 1,
                    cells_scanned: Some(0),
                    aborted: false,
                    candidates: Vec::new(),
                    best_observed_edge: Some(measured),
                    settlement: SettlementReadiness::NotApplicable,
                    valuation: ValuationReadiness::NotRequired,
                    // No benchmark ran, so there is no temperature evidence at
                    // all. `default()` is the honest answer here — it is not a
                    // "cool" reading, it is the absence of one, and
                    // `measured()` says so.
                    thermal: ObservedThermal::default(),
                    spend: BudgetSpend::cycles(1),
                    resolution: None,
                    defect: None,
                })
            }
        }
    }

    /// Prove authenticated evidence by verifying against an authorized outcome policy.
    ///
    /// This can currently **never** succeed. It delegates to
    /// [`UnverifiedComputeEvidence::verify`], which refuses unconditionally with
    /// [`EconomyError::RewardBindingIncomplete`] — a message that begins with
    /// [`REWARD_BINDING_INCOMPLETE`] — because
    /// [`crate::cqr::proof::CqrResultProof::attestation_preimage`] signs
    /// only the domain, the policy hash, the proof digest, the result digest and
    /// the job hash — no transaction hash, no payer, no recipient, no amount. A
    /// valid signature over a valid proof therefore says nothing about a
    /// payment, and there is no external compute market whose payment this
    /// adapter could verify even if there were a signature covering it.
    ///
    /// Every caller today gets an error, and that is the correct result rather
    /// than a missing feature.
    pub fn prove(
        &self,
        evidence: UnverifiedComputeEvidence,
        policy: &crate::policy_auth::ValidatedOutcomePolicy,
    ) -> Result<AuthenticatedComputeEvidence> {
        evidence.verify(policy)
    }
}

impl OpportunityAdapter for ComputeRewardAdapter {
    fn class(&self) -> OpportunityClass {
        OpportunityClass::ComputeReward
    }

    fn identity(&self) -> &str {
        &self.identity
    }

    /// The one method the machine calls. Delegates to
    /// [`Self::observe_with_thermal`] with the real hardware sensors, so on a
    /// machine that exposes no sensor this is an error rather than a fabricated
    /// cool reading.
    fn observe(&self, permit: &SearchPermit, now_unix: u64) -> Result<SearchObservation> {
        self.observe_with_thermal(
            permit,
            now_unix,
            &super::oscillators::SystemThermalSource,
        )
    }
}

/// Telemetry metrics for CQR-ME compute search and execution.
/// Separated into distinct dimensions without collapsing into an arbitrary fused score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CqrSearchMetrics {
    /// Percentage of executed CQR jobs that cleared physical and numerical validation (bps).
    pub job_validation_rate_bps: u64,
    /// Percentage of identical jobs producing bitwise identical proofs (bps).
    pub job_reproducibility_rate_bps: u64,
    /// Measured micro-USD cost per validated compute result.
    pub compute_cost_per_valid_result_micros: u64,
    /// Rate of hardware or timeout worker failures (bps).
    pub worker_failure_rate_bps: u64,
    /// Rate of numerical instability or tolerance breaches (bps).
    pub numerical_failure_rate_bps: u64,
}

/// Creates a standard Mycelium WorkReceipt from a validated CQR compute execution.
#[allow(clippy::too_many_arguments)]
pub fn create_cqr_work_receipt(
    job_spec: &CqrJobSpec,
    result: &CqrResult,
    proof: &CqrResultProof,
    receipt_id: impl Into<String>,
    worker_id: impl Into<String>,
    verifier_id: impl Into<String>,
    started_at_unix: u64,
    completed_at_unix: u64,
) -> crate::WorkReceipt {
    let useful_work_units = (job_spec
        .step_count
        .saturating_mul(job_spec.classical_spec.oscillator_count as u64))
    .max(1);

    crate::WorkReceipt {
        schema_version: 1,
        receipt_id: receipt_id.into(),
        job_id: job_spec.job_id.clone(),
        worker_id: worker_id.into(),
        started_at_unix,
        completed_at_unix,
        result_hash: proof.proof_digest.clone(),
        useful_work_units,
        verifier_id: verifier_id.into(),
        verified_at_unix: completed_at_unix,
        verified: result.validation_passed && proof.verify_integrity(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::ControlledAddressRegistry;
    use crate::cqr::job::{ClassicalSpec, CqrResourceBudget, IntegratorSpec, PrecisionPolicy, TolerancePolicy};
    use crate::cqr::oscillators::{run_benchmark_with_telemetry, FakeThermalSource};
    use crate::cqr::proof::CqrResultAttestation;
    use crate::cqr::state_bus::hash_component;
    use crate::discovery::{SearchBudget, ThermalPermit, MIN_SEARCH_THERMAL_HEADROOM};
    use crate::mupp_adapter::MuppPhysicalGate;
    use crate::policy_auth::ValidatedOutcomePolicy;
    use crate::receipt_auth::testkit::AuthFixture;
    use crate::rpc_test_server::FakeRpcSocket;

    // ---------------------------------------------------------------------
    // Thermal reporting
    // ---------------------------------------------------------------------

    /// A MUPP gate that permits a search: fresh, sensors valid, not blocked, and
    /// comfortably above [`MIN_SEARCH_THERMAL_HEADROOM`].
    ///
    /// Built as a literal rather than through `read_mupp_gate` because the
    /// adapter tests need a permit and not a state file; the fields checked by
    /// [`ThermalPermit::check`] are the ones that matter and all of them are set
    /// to a passing value here.
    fn healthy_gate(now_unix: u64) -> MuppPhysicalGate {
        MuppPhysicalGate {
            schema_version: 1,
            source_mode: "MUPP_LOCAL_CONTROL".into(),
            timestamp_unix: now_unix as f64 - 1.0,
            age_seconds: 1.0,
            fresh: true,
            regime: "ECO".into(),
            phase: "IDLE".into(),
            temperature_c: Some(60.0),
            headroom_c: Some(12.0),
            recovery_debt: 0.0,
            sensor_valid: true,
            allow_execution: true,
            cpu_temp_c: Some(60.0),
            gpu_temp_c: Some(50.0),
            cpu_util_pct: Some(10.0),
            gpu_util_pct: Some(0.0),
            queue: 0,
            // `read_mupp_gate` maps H through `full_headroom_c: 20.0`, which is
            // where 12 °C of headroom becomes 0.6.
            thermal_headroom: 0.6,
            reason: "ok".into(),
        }
    }

    fn permit(now_unix: u64) -> SearchPermit {
        SearchPermit {
            class: OpportunityClass::ComputeReward,
            cycle: 7,
            budget: SearchBudget::default(),
            thermal: ThermalPermit::from_gate(
                &healthy_gate(now_unix),
                now_unix,
                MIN_SEARCH_THERMAL_HEADROOM,
            )
            .expect("a healthy gate issues a permit"),
        }
    }

    #[test]
    fn observed_thermal_peak_spans_start_end_and_maximum() {
        // Nothing measured: no evidence, which `measured()` reports as such.
        let nothing = ObservedThermal {
            start_max_c: None,
            end_c: None,
            maximum_c: None,
        };
        assert_eq!(nothing.peak(), None);
        assert!(!nothing.measured());

        // Each field alone is still a reading.
        let start_only = ObservedThermal {
            start_max_c: Some(61.0),
            end_c: None,
            maximum_c: None,
        };
        assert_eq!(start_only.peak(), Some(61.0));
        assert!(start_only.measured());

        let end_only = ObservedThermal {
            start_max_c: None,
            end_c: Some(62.0),
            maximum_c: None,
        };
        assert_eq!(end_only.peak(), Some(62.0));

        let mid_only = ObservedThermal {
            start_max_c: None,
            end_c: None,
            maximum_c: Some(63.0),
        };
        assert_eq!(mid_only.peak(), Some(63.0));
        assert!(mid_only.measured());

        // Endpoints only: the old behaviour, still correct on its own.
        let endpoints = ObservedThermal {
            start_max_c: Some(40.0),
            end_c: Some(60.0),
            maximum_c: None,
        };
        assert_eq!(endpoints.peak(), Some(60.0));

        // All three, and the mid-run maximum wins even though it is not an
        // endpoint. This is the case the old two-field `peak()` got wrong.
        let excursion = ObservedThermal {
            start_max_c: Some(40.0),
            end_c: Some(45.0),
            maximum_c: Some(93.0),
        };
        assert_eq!(excursion.peak(), Some(93.0));

        // Order does not matter.
        assert_eq!(
            ObservedThermal {
                start_max_c: Some(93.0),
                end_c: Some(45.0),
                maximum_c: Some(40.0),
            }
            .peak(),
            Some(93.0)
        );
    }

    #[test]
    fn idle_observation_reports_no_thermal_evidence() {
        let adapter = ComputeRewardAdapter::new_experimental("cqr-idle");
        let p = permit(1_000);

        let observation = adapter
            .observe_with_thermal(&p, 1_000, &FakeThermalSource::new(45.0))
            .expect("the idle branch runs nothing and cannot fail");

        assert_eq!(observation.thermal, ObservedThermal::default());
        assert!(!observation.thermal.measured());
        assert_eq!(observation.thermal.peak(), None);
        assert_eq!(observation.cells_scanned, Some(0));
        assert!(observation.defect.is_none());

        // The fake reports 45 °C and none of it reaches the observation: the
        // sensor was never read. A fabricated 45.0 here would be a measurement
        // of nothing.
        let via_trait = adapter
            .observe(&p, 1_000)
            .expect("the delegated trait method takes the same idle branch");
        assert_eq!(via_trait.thermal, ObservedThermal::default());
    }

    // ---------------------------------------------------------------------
    // Reward binding
    // ---------------------------------------------------------------------

    /// A real policy, validated from a real pinned anchor through the crate's
    /// own `testkit` fixture — the same one `proof.rs` uses, rather than a
    /// second copy of the fixture that would have to be kept in step with it.
    ///
    /// The socket and the temporary directory are returned so the caller keeps
    /// both alive: the pin lives in a directory that a dropped `TempDir` deletes.
    fn authority() -> (tempfile::TempDir, FakeRpcSocket, AuthFixture, ValidatedOutcomePolicy) {
        let dir = tempfile::tempdir().unwrap();
        let socket = FakeRpcSocket::bind(dir.path().join("rpc.sock"));
        let auth = AuthFixture::new(socket.path(), socket.uid(), ControlledAddressRegistry::new());
        let policy = auth.validated();
        (dir, socket, auth, policy)
    }

    fn sample_proof() -> CqrResultProof {
        let suite_digest = validation_suite_digest(&["symplectic_conservation".to_string()]);
        CqrResultProof::new(
            "proof-cqr-adapter-1",
            "job-cqr-adapter-1",
            "0xjobhash0000000000000000000000000000000000000000000000000000000001",
            "0xinputhash00000000000000000000000000000000000000000000000000000002",
            "0xoutputhash000000000000000000000000000000000000000000000000000003",
            "cqr-c0:coupled_oscillators:verlet",
            "1.0.0",
            suite_digest,
            "0xresultdigest0000000000000000000000000000000000000000000000000005",
            "worker-cqr-adapter-01",
        )
    }

    /// Reward evidence whose `job_id` and `result_digest` genuinely match the
    /// proof, and whose entire payment identity is invented.
    fn attacker_reward(proof: &CqrResultProof) -> ExternalRewardEvidence {
        ExternalRewardEvidence {
            settlement_tx_hash: "0xnot-a-real-transaction".into(),
            chain_id: 8453,
            payer: "0xattacker".into(),
            recipient: "0xattacker".into(),
            gross_amount_musd_micros: 900_000_000,
            job_id: proof.job_id.clone(),
            result_digest: proof.result_digest.clone(),
        }
    }

    /// The message `verify` refused with, so a test asserts on the refusal itself
    /// rather than on some string built here.
    ///
    /// Matched by variant, not by message: the refusal is typed, and its payload
    /// is the missing binding rather than anything read off the evidence.
    fn refusal(
        proof: &CqrResultProof,
        reward: ExternalRewardEvidence,
        attestation: &CqrResultAttestation,
        policy: &ValidatedOutcomePolicy,
    ) -> String {
        let error = match UnverifiedComputeEvidence::new(proof.clone(), reward, attestation.clone())
            .verify(policy)
        {
            Err(error) => error,
            Ok(_) => panic!("an unauthenticated payment identity must never authenticate"),
        };
        // Matched by variant, not by message: the typed refusal is the contract,
        // and it is asserted here before the text is looked at at all.
        assert!(
            matches!(&error, EconomyError::RewardBindingIncomplete(_)),
            "expected the typed binding refusal, got: {error}"
        );
        error.to_string()
    }

    #[test]
    fn delegated_attestation_alone_cannot_authenticate_a_payment() {
        let (_dir, _socket, auth, policy) = authority();
        let proof = sample_proof();
        assert!(proof.verify_integrity());

        // A genuine signature from the genuine delegated verifier over a genuine
        // proof. Nothing here is forged.
        let attestation = CqrResultAttestation::attest(&proof, &policy, &auth.verifier)
            .expect("the delegated verifier signs this proof");
        assert!(attestation.verify(&proof, &policy).is_ok());

        // The reward's job and result digest both match the proof, so the two
        // string checks pass and the attestation check passes. Only the payment
        // is the attacker's.
        let reward = attacker_reward(&proof);
        assert_eq!(reward.job_id, proof.job_id);
        assert_eq!(reward.result_digest, proof.result_digest);

        let adapter = ComputeRewardAdapter::new_experimental("cqr-reward-binding");
        let evidence = adapter.package_evidence(proof, reward, attestation);
        let error = match evidence.verify(&policy) {
            Err(error) => error,
            Ok(_) => panic!("verify must not accept an unsigned payment identity"),
        };
        assert!(
            matches!(&error, EconomyError::RewardBindingIncomplete(_)),
            "expected the typed binding refusal, got: {error}"
        );
        // The exported constant is the prefix of that refusal, so a caller
        // matching on either the type or the string recognises the same refusal.
        assert_eq!(
            error.to_string(),
            format!(
                "{REWARD_BINDING_INCOMPLETE}; no compute reward may be authenticated ({})",
                match &error {
                    EconomyError::RewardBindingIncomplete(reason) => *reason,
                    other => panic!("not a binding refusal: {other}"),
                }
            )
        );

        // And the adapter's own entry point, which is the only other way in,
        // refuses identically.
        let proof = sample_proof();
        let attestation = CqrResultAttestation::attest(&proof, &policy, &auth.verifier)
            .expect("the delegated verifier signs this proof too");
        let evidence = UnverifiedComputeEvidence::new(proof.clone(), attacker_reward(&proof), attestation);
        let adapter = ComputeRewardAdapter::new_experimental("cqr-reward-binding");
        match adapter.prove(evidence, &policy) {
            Err(error @ EconomyError::RewardBindingIncomplete(_)) => assert!(
                error.to_string().contains(REWARD_BINDING_INCOMPLETE),
                "the refusal must carry the stable marker: {error}"
            ),
            Err(other) => panic!("expected a binding refusal, got {other}"),
            Ok(_) => panic!("prove must not accept an unsigned payment identity"),
        }
    }

    #[test]
    fn attestation_does_not_sign_the_payment_identity() {
        let (_dir, _socket, auth, policy) = authority();
        let proof = sample_proof();
        let attestation = CqrResultAttestation::attest(&proof, &policy, &auth.verifier)
            .expect("the delegated verifier signs this proof");

        let baseline = attacker_reward(&proof);
        let baseline_message = refusal(&proof, baseline.clone(), &attestation, &policy);
        assert!(
            baseline_message.contains(REWARD_BINDING_INCOMPLETE),
            "the refusal must carry the stable marker: {baseline_message}"
        );

        // The same proof and the same signature, with the payment rewritten. If
        // any of these fields were covered by the attestation preimage, these
        // would fail differently from the baseline — a different error, a
        // signature rejection, or an `Ok`.
        let mut forged_tx = baseline.clone();
        forged_tx.settlement_tx_hash = "0xa-completely-different-transaction".into();
        assert_eq!(
            refusal(&proof, forged_tx, &attestation, &policy),
            baseline_message,
            "settlement_tx_hash is not signed, so rewriting it changes nothing"
        );

        let mut forged_payer = baseline.clone();
        forged_payer.payer = "0xsomeone-else-entirely".into();
        forged_payer.recipient = "0xsomeone-else-entirely".into();
        forged_payer.chain_id = 1;
        assert_eq!(
            refusal(&proof, forged_payer, &attestation, &policy),
            baseline_message,
            "payer, recipient and chain_id are not signed either"
        );

        let mut forged_amount = baseline;
        forged_amount.gross_amount_musd_micros = u64::MAX;
        assert_eq!(
            refusal(&proof, forged_amount, &attestation, &policy),
            baseline_message,
            "the amount is not signed: 0 and u64::MAX are equally acceptable"
        );

        // And the attestation is verified byte-for-byte identically in every one
        // of those cases, because it never saw the reward at all.
        assert!(attestation.verify(&proof, &policy).is_ok());
    }

    // ---------------------------------------------------------------------
    // The suite digest the proof carries
    // ---------------------------------------------------------------------

    #[test]
    fn the_proof_suite_digest_comes_from_the_job_spec() {
        let adapter = ComputeRewardAdapter::new_experimental("cqr-suite-digest");
        let state = PhaseSpacePoint::new(vec![0.1, -0.2], vec![0.3, 0.4]);
        let initial_hash =
            hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());

        let mut job_spec = CqrJobSpec {
            schema_version: 1,
            job_id: "job-suite-1".into(),
            model_id: "coupled_oscillators_2".into(),
            model_version: "1.0.0".into(),
            compute_level: CqrComputeLevel::C0ClassicalSymplectic,
            initial_state_hash: initial_hash,
            classical_spec: ClassicalSpec {
                oscillator_count: 2,
                mass: 1.0,
                spring_constant: 1.0,
                periodic_boundary: true,
            },
            integrator_spec: IntegratorSpec::VelocityVerlet,
            precision_policy: PrecisionPolicy::Float64Strict,
            tolerance_policy: TolerancePolicy::default(),
            step_count: 20,
            time_step: 0.001,
            seed: None,
            resource_budget: CqrResourceBudget::default(),
            expected_observables: vec!["energy".into()],
            validation_suite: vec!["symplectic_conservation".into()],
        };

        let (result, _) = run_benchmark_with_telemetry(
            &job_spec,
            state.clone(),
            &FakeThermalSource::new(41.0),
        )
        .expect("a cool machine runs the job");
        assert!(result.validation_passed);

        let one = adapter
            .verify_result(&job_spec, &result, "worker-suite-01")
            .expect("a validated result yields a proof");

        // The digest is a function of the suite, so any change to the suite
        // changes the proof. Before this, every proof carried the same constant.
        job_spec.validation_suite = vec![
            "symplectic_conservation".into(),
            "dispersion_check".into(),
        ];
        let two = adapter
            .verify_result(&job_spec, &result, "worker-suite-01")
            .expect("a validated result yields a proof");
        assert_ne!(one.validation_suite_digest, two.validation_suite_digest);
        assert_ne!(one.proof_digest, two.proof_digest);

        // Order is part of the suite, not a detail of serialisation.
        job_spec.validation_suite = vec![
            "dispersion_check".into(),
            "symplectic_conservation".into(),
        ];
        let three = adapter
            .verify_result(&job_spec, &result, "worker-suite-01")
            .expect("a validated result yields a proof");
        assert_ne!(two.validation_suite_digest, three.validation_suite_digest);

        // An empty suite is a different suite from a populated one, and it gets
        // its own digest rather than the old shared constant.
        job_spec.validation_suite = Vec::new();
        let empty = adapter
            .verify_result(&job_spec, &result, "worker-suite-01")
            .expect("a validated result yields a proof");
        assert_ne!(empty.validation_suite_digest, one.validation_suite_digest);
        assert!(empty.verify_integrity());

        // Deterministic: the same suite, the same digest, every time.
        assert_eq!(
            validation_suite_digest(&["a".into(), "b".into()]),
            validation_suite_digest(&["a".into(), "b".into()])
        );
        assert_ne!(
            validation_suite_digest(&["ab".into()]),
            validation_suite_digest(&["a".into(), "b".into()]),
            "the tagged encoding must keep entries from running together"
        );
    }
}

