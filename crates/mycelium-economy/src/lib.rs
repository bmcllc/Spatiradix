//! Mycelium Economy — local-first RV0 core.
//!
//! The fundamental accounting invariant is that internal work, simulated
//! settlements and MYC rewards never increase external PaidDemand.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

pub use boundary::SettlementAsset;

pub mod base_usdc;
pub mod autonomy;
pub mod boundary;
pub mod chain_provider;
/// P6 — the autonomous search state machine. Read-only/evidence: it classifies
/// what a measurement produced and never signs, orders or broadcasts.
pub mod discovery;
pub mod s1_adapter;
pub mod s1_perception_adapter;
pub mod s1_outcome;
/// P6.3 — read-only flash loan arbitrage scanner for Base L2.
pub mod flash_arb_adapter;
pub mod terr_research;
pub mod reinvestment;
pub mod scaling;
pub mod mupp_adapter;
pub mod verified_view;
pub mod durability;
pub mod policy_auth;
pub mod receipt_auth;
pub mod settlement_auth;
pub mod boundary_delta;
pub mod event_id;
pub mod settlement;
pub mod trusted_valuation;
pub mod verifier_key_store;
/// P6.6 — the economic result taxonomy. Nine arms, one of which can carry a
/// value. The other eight have no method that yields one, by type.
pub mod resolution;
/// P6.7 — the NEV-0 gate. Complete, authenticated, chain-confirmed,
/// boundary-derived, comparable, net of costs, verified sum > 0. No scale
/// requirement. Read-only/evidence: it mints no value and grants no budget.
pub mod nev0;
/// P6.10 — reorg revalidation and the `needs_revalidation` state that blocks
/// spend authority. Does not fake finality and has no production caller.
pub mod revalidation;
/// P6.9 — the policy high-water mark and rollback hardening. Not yet wired into
/// the CLI's policy load; see the module doc for why, and for what it does and
/// does not defeat.
pub mod policy_watermark;
/// CQR-ME — Computação Quântico-Relativística Mecânico-Estatística.
pub mod cqr;
/// NEV0–NEV4 tiered economic evaluator.
pub mod nev_tier;
/// Durable, hash-chained record of verified economic events — the source of
/// truth NEV replay protection is rebuilt from, so a restart cannot reopen it.
pub mod nev_durable;
/// Ponte contábil com `mycelium-mint` (1 MYC = 8 USDC), preservando estritamente
/// o invariante de que recompensas internas em MYC nunca aumentam `PaidDemand` externo.
pub mod mint_bridge;

pub use verified_view::TrustMode;

pub mod rpc_test_server;

pub mod testkit {
    pub use crate::rpc_test_server::FakeRpcSocket;
    pub use crate::receipt_auth::testkit::AuthFixture;
    pub use crate::nev0::testkit::*;
}

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum EconomyError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid record: {0}")]
    Invalid(String),
    #[error("record not found: {0}")]
    NotFound(String),
    #[error("state conflict: {0}")]
    Conflict(String),
    /// Fail-closed trust boundary: the chain data source is not pinned
    /// out-of-band. Same discipline as `vacuum`'s `IsolationUnavailable` — a
    /// missing source of truth is refused, never degraded into a default.
    #[error("chain provider not pinned: {0}")]
    ProviderUnpinned(String),
    /// Fail-closed compute-reward gate: a genuine delegated signature over a
    /// genuine CQR proof, and still no authenticated payment — because the
    /// signature covers none of the payment.
    ///
    /// # What is bound
    ///
    /// [`crate::cqr::proof::CqrResultProof::attestation_preimage`] signs
    /// `domain || policy_hash || proof_digest || result_digest || job_hash`,
    /// where `domain` is the constant that separates this attestation from
    /// every other signed structure in the crate. That is the entire preimage,
    /// and [`crate::cqr::proof::CqrResultAttestation::verify`] re-derives it and
    /// checks it against the key the policy delegates to. The proof itself is
    /// covered too, by
    /// [`crate::cqr::proof::CqrResultProof::verify_integrity`], and `reward`'s
    /// `job_id` and `result_digest` are checked by equality against values the
    /// proof already fixes.
    ///
    /// # What is not bound
    ///
    /// Every field of [`crate::cqr::adapter::ExternalRewardEvidence`] that
    /// identifies an external payment: `settlement_tx_hash`, `chain_id`,
    /// `payer`, `recipient` and `gross_amount_musd_micros`. None of them
    /// appears in any signed preimage — not the attestation preimage above, not
    /// the proof digest. They are caller-supplied labels, free to be set to
    /// anything by whoever assembled the evidence, and matching the two fields
    /// that *are* checked shows only that the assembler read the proof, never
    /// that a payment purchased it.
    ///
    /// # Why the gate exists
    ///
    /// Consequently [`crate::cqr::adapter::AuthenticatedComputeEvidence`] has
    /// no constructor: it is unconstructible, unforgeable and cannot be
    /// deserialized into existence. That is deliberate, not a gap to be tidied
    /// away. There is no real external compute market for
    /// [`crate::cqr::adapter::ComputeRewardAdapter`] to be paid by, so no
    /// on-chain artefact references a CQR result digest and there is nothing an
    /// external party could be attesting a payment *for*. Lifting this gate
    /// requires a signed payment identity first — a settlement receipt, or a
    /// delegated attestation whose preimage covers the transaction hash, the
    /// chain, both addresses and the amount.
    ///
    /// The payload names the specific missing binding, so a caller can report
    /// why without parsing prose. The same refusal is also available as a fixed
    /// string — [`crate::cqr::adapter::REWARD_BINDING_INCOMPLETE`] — which is
    /// what callers that cannot match on this enum match on instead.
    #[error("RewardBindingIncomplete: delegated attestation does not sign the external payment identity; no compute reward may be authenticated ({0})")]
    RewardBindingIncomplete(&'static str),
}

pub type Result<T> = std::result::Result<T, EconomyError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobType {
    Compute,
    Storage,
    Bandwidth,
    Build,
    Replication,
    Simulation,
    Quote,
    Backtest,
    Inference,
    DataTransform,
    Validation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Requested,
    Assigned,
    Completed,
    Verified,
    Settled,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRequest {
    pub schema_version: u32,
    pub job_id: String,
    pub created_at_unix: u64,
    pub requester_id: String,
    pub job_type: JobType,
    pub input_hash: String,
    pub max_price_musd_micros: u64,
    pub internal_work: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkReceipt {
    pub schema_version: u32,
    pub receipt_id: String,
    pub job_id: String,
    pub worker_id: String,
    pub started_at_unix: u64,
    pub completed_at_unix: u64,
    pub result_hash: String,
    pub useful_work_units: u64,
    pub verifier_id: String,
    pub verified_at_unix: u64,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentIntent {
    pub schema_version: u32,
    pub payment_intent_id: String,
    pub job_id: String,
    pub chain_id: u64,
    pub token: String,
    pub recipient: String,
    pub exact_amount_raw: u64,
    pub anchor_block: u64,
    pub anchor_block_hash: String,
    pub anchor_timestamp_unix: u64,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementMode {
    Simulated,
    External,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementReceipt {
    pub schema_version: u32,
    pub settlement_id: String,
    pub job_id: String,
    pub work_receipt_id: String,
    pub settled_at_unix: u64,
    pub mode: SettlementMode,
    /// Typed: a bare string used to accept "smUSD" in the same slot as a real
    /// on-chain token. The wire format is still a plain symbol string, so
    /// records already on disk keep the bytes their `record_hash` covers.
    pub settlement_asset: SettlementAsset,
    pub settled_amount_micros: u64,
    /// USD-equivalent value at settlement, in 1e-6 units.
    pub usd_equivalent_micros: u64,
    /// Hash/reference for an external payment candidate.
    pub payment_intent_id: Option<String>,
    pub payment_block_number: Option<u64>,
    pub payment_proof_hash: Option<String>,
    /// DIAGNOSTICS ONLY, same rule as
    /// [`autonomy::ExternalValueReceipt::proof_verified`]: no economic path
    /// reads it. The authoritative check is
    /// [`verified_view::VerifiedRevenueView`], which re-derives every other
    /// field from the ledger and re-reads the cited transaction from the pinned
    /// provider. Kept in the wire format so records on disk keep the exact bytes
    /// their `record_hash` was computed over, and so a settlement can still be
    /// compared against the adapter that wrote it.
    pub payment_proof_verified: bool,
    /// Claim that money left a payer for this job. Diagnostics only, for the
    /// same reason as `payment_proof_verified` above.
    pub external_paid: bool,
    pub internal_work: bool,
}

impl SettlementReceipt {
    pub fn counts_as_paid_demand(&self) -> bool {
        self.mode == SettlementMode::External
            && self.external_paid
            && !self.internal_work
            && self.payment_proof_verified
            && self.usd_equivalent_micros > 0
            // A synthetic ledger-internal unit cannot be external PaidDemand,
            // however well proven the payment behind it is.
            && self.settlement_asset.is_real()
            && self
                .payment_proof_hash
                .as_deref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LedgerRecord {
    Job {
        sequence: u64,
        recorded_at_unix: u64,
        prev_hash: String,
        record_hash: String,
        job: JobRequest,
    },
    Work {
        sequence: u64,
        recorded_at_unix: u64,
        prev_hash: String,
        record_hash: String,
        receipt: WorkReceipt,
    },
    PaymentIntent {
        sequence: u64,
        recorded_at_unix: u64,
        prev_hash: String,
        record_hash: String,
        intent: PaymentIntent,
    },
    Settlement {
        sequence: u64,
        recorded_at_unix: u64,
        prev_hash: String,
        record_hash: String,
        settlement: SettlementReceipt,
    },
}

impl LedgerRecord {
    pub fn sequence(&self) -> u64 {
        match self {
            Self::Job { sequence, .. }
            | Self::Work { sequence, .. }
            | Self::PaymentIntent { sequence, .. }
            | Self::Settlement { sequence, .. } => *sequence,
        }
    }

    pub fn prev_hash(&self) -> &str {
        match self {
            Self::Job { prev_hash, .. }
            | Self::Work { prev_hash, .. }
            | Self::PaymentIntent { prev_hash, .. }
            | Self::Settlement { prev_hash, .. } => prev_hash,
        }
    }

    pub fn record_hash(&self) -> &str {
        match self {
            Self::Job { record_hash, .. }
            | Self::Work { record_hash, .. }
            | Self::PaymentIntent { record_hash, .. }
            | Self::Settlement { record_hash, .. } => record_hash,
        }
    }

    fn set_prev_hash(&mut self, value: String) {
        match self {
            Self::Job { prev_hash, .. }
            | Self::Work { prev_hash, .. }
            | Self::PaymentIntent { prev_hash, .. }
            | Self::Settlement { prev_hash, .. } => *prev_hash = value,
        }
    }

    fn set_record_hash(&mut self, value: String) {
        match self {
            Self::Job { record_hash, .. }
            | Self::Work { record_hash, .. }
            | Self::PaymentIntent { record_hash, .. }
            | Self::Settlement { record_hash, .. } => *record_hash = value,
        }
    }

    /// The append path recomputes the sequence under the exclusive lock, so the
    /// value a caller passed in — read outside that lock — is never the one that
    /// reaches disk.
    fn set_sequence(&mut self, value: u64) {
        match self {
            Self::Job { sequence, .. }
            | Self::Work { sequence, .. }
            | Self::PaymentIntent { sequence, .. }
            | Self::Settlement { sequence, .. } => *sequence = value,
        }
    }

    /// Commits the canonical SEMANTIC record, not the exact persisted bytes:
    /// the value hashed here is this struct re-serialized with an empty
    /// `record_hash`, so key order, whitespace and any field serde drops on
    /// the way in are outside the hash. That is why the trusted envelopes
    /// above carry `deny_unknown_fields` -- otherwise a key added to a stored
    /// line would be dropped on read, invisible to the chain, and still
    /// parseable.
    fn computed_hash(&self) -> Result<String> {
        let mut canonical = self.clone();
        canonical.set_record_hash(String::new());
        let bytes = serde_json::to_vec(&canonical)?;
        Ok(blake3::hash(&bytes).to_hex().to_string())
    }
}

pub const LEDGER_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Revenue ledger file name; also the append lock name and the head anchor's
/// ledger identifier.
pub const REVENUE_LEDGER_FILE: &str = "revenue-ledger.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerAudit {
    pub valid: bool,
    pub records: u64,
    pub head_hash: String,
    pub ledger_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RevenueSummary {
    /// Settlements the [`verified_view::VerifiedRevenueView`] could attest.
    pub external_paid_jobs: u64,
    pub internal_or_simulated_jobs: u64,
    /// The attested paid demand. Zero in
    /// [`verified_view::TrustMode::Unverified`], which is the honest answer; the
    /// claimed total is reported under `unattested_*` below.
    pub paid_demand_musd_micros: u64,
    pub by_asset_micros: BTreeMap<String, u64>,
    #[serde(default)]
    pub trust_mode: TrustMode,
    #[serde(default)]
    pub unattested_external_paid_jobs: u64,
    #[serde(default)]
    pub unattested_paid_demand_musd_micros: u64,
    #[serde(default)]
    pub attestation_note: String,
}

impl RevenueSummary {
    pub fn paid_demand_musd(&self) -> f64 {
        self.paid_demand_musd_micros as f64 / 1_000_000.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RvStatus {
    pub level: String,
    pub external_paid_jobs: u64,
    pub paid_demand_musd_total: f64,
    pub paid_demand_musd_per_day_30d: f64,
    pub next_target_musd_per_day: Option<f64>,
    pub rv0_pass: bool,
    pub note: String,
    /// Which derivation produced the fields above. The four fields above are
    /// only ever non-zero for attested paid demand; what the ledger claims when
    /// nothing is attested is reported under `unattested_*` instead of being
    /// dropped to a silent zero.
    #[serde(default)]
    pub trust_mode: TrustMode,
    #[serde(default)]
    pub unattested_external_paid_jobs: u64,
    #[serde(default)]
    pub unattested_paid_demand_musd_total: f64,
    #[serde(default)]
    pub unattested_paid_demand_musd_per_day_30d: f64,
    #[serde(default)]
    pub attestation_note: String,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentPolicy {
    pub schema_version: u32,
    pub chain_id: u64,
    pub token: String,
    pub payout_address: String,
    pub min_confirmations: u64,
    pub created_at_unix: u64,
    /// Chain data source, pinned out-of-band at create_new time (or later via
    /// [`LocalEconomy::pin_chain_provider`]). `None` on a policy written before
    /// pinning existed: such a policy still loads, but the verifier refuses to
    /// run until a provider is pinned.
    #[serde(default)]
    pub chain_provider: Option<chain_provider::PinnedChainProvider>,
}

#[derive(Debug, Clone)]
pub struct LocalEconomy {
    root: PathBuf,
}

impl LocalEconomy {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        // The root holds every ledger and every policy. Forced to 0700 here so
        // a default `0022` umask cannot leave the whole economy readable by
        // other accounts; a pre-existing looser mode is corrected with a
        // warning rather than refused, so installations created before this
        // existed keep working.
        durability::ensure_private_dir(&root)?;
        Ok(Self { root })
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.root.join(REVENUE_LEDGER_FILE)
    }

    /// Head anchor for the revenue ledger, or `None` on a ledger written
    /// before anchoring existed.
    pub fn head_anchor(&self) -> Result<Option<durability::HeadAnchor>> {
        durability::read_head_anchor(&self.root, REVENUE_LEDGER_FILE)
    }

    pub fn payment_policy_path(&self) -> PathBuf {
        self.root.join("payment-policy.json")
    }

    pub fn init_payment_policy(
        &self,
        payout_address: &str,
        min_confirmations: u64,
    ) -> Result<PaymentPolicy> {
        self.init_payment_policy_with_provider(
            payout_address,
            min_confirmations,
            None,
        )
    }

    /// Create-once policy that also pins the chain provider. The pin is part
    /// of the policy from the first byte: whoever provisions the policy
    /// chooses the source of truth once, and no later argv argument can move
    /// it.
    pub fn init_payment_policy_with_provider(
        &self,
        payout_address: &str,
        min_confirmations: u64,
        chain_provider: Option<&chain_provider::PinnedChainProvider>,
    ) -> Result<PaymentPolicy> {
        let path = self.payment_policy_path();
        // Held across the existence check and the write: create-once is only
        // create-once if two processes cannot both see an absent file.
        let _lock =
            durability::LedgerLock::acquire_timeout(&self.root, REVENUE_LEDGER_FILE, durability::LEDGER_LOCK_WAIT)?;
        if path.exists() {
            return Err(EconomyError::Conflict(
                "payment policy already exists".into(),
            ));
        }
        let payout_address =
            crate::base_usdc::normalize_address(payout_address)?;
        if min_confirmations == 0 {
            return Err(EconomyError::Invalid(
                "min_confirmations must be >= 1".into(),
            ));
        }
        if let Some(provider) = chain_provider {
            provider.validate_policy_pin()?;
        }
        let policy = PaymentPolicy {
            schema_version: SCHEMA_VERSION,
            chain_id: crate::base_usdc::BASE_CHAIN_ID,
            token: crate::base_usdc::BASE_USDC.to_ascii_lowercase(),
            payout_address,
            min_confirmations,
            created_at_unix: now_unix(),
            chain_provider: chain_provider.cloned(),
        };
        let payload = serde_json::to_vec_pretty(&policy)?;
        let mut payload = payload;
        payload.push(b'\n');
        // 0600 from the first byte: the policy carries the payout address and
        // the pinned source of truth.
        durability::write_private_atomic(&path, &payload)?;
        Ok(policy)
    }

    /// Pin (or re-pin) the chain provider on an existing policy. Explicit
    /// operator action, separate from policy creation: an operator who created
    /// a policy before pinning existed can provision the source of truth
    /// without discarding the payout address, chain id or confirmations.
    pub fn pin_chain_provider(
        &self,
        provider: &chain_provider::PinnedChainProvider,
    ) -> Result<PaymentPolicy> {
        provider.validate_policy_pin()?;
        let mut policy = self.payment_policy()?;
        policy.chain_provider = Some(provider.clone());
        let payload = serde_json::to_vec_pretty(&policy)?;
        let path = self.payment_policy_path();
        // Write-then-rename: a torn rewrite would leave a policy whose pin no
        // longer matches the bytes it was verified against. `write_private_atomic`
        // also keeps the rewritten file at 0600.
        let mut payload = payload;
        payload.push(b'\n');
        durability::write_private_atomic(&path, &payload)?;
        Ok(policy)
    }

    /// Resolve the chain data source for this home. Fails closed: no pin and
    /// no dev override is an error, not a default endpoint.
    pub fn chain_provider(
        &self,
    ) -> Result<chain_provider::ResolvedChainProvider> {
        let dev = std::env::var(chain_provider::DEV_PROVIDER_ENV).ok();
        let pinned = match self.payment_policy() {
            Ok(policy) => policy.chain_provider.clone(),
            Err(EconomyError::NotFound(_)) => None,
            Err(e) => return Err(e),
        };
        chain_provider::resolve(dev.as_deref(), pinned.as_ref())
    }

    pub fn payment_policy(&self) -> Result<PaymentPolicy> {
        let path = self.payment_policy_path();
        if !path.exists() {
            return Err(EconomyError::NotFound(
                "payment policy; run payment-policy-init".into(),
            ));
        }
        let raw = fs::read(path)?;
        let policy: PaymentPolicy = serde_json::from_slice(&raw)?;
        if policy.schema_version != SCHEMA_VERSION {
            return Err(EconomyError::Invalid(
                "unsupported payment policy schema".into(),
            ));
        }
        validate_payment_policy(&policy)?;
        Ok(policy)
    }

    pub fn job(&self, job_id: &str) -> Result<Option<JobRequest>> {
        self.find_job(job_id)
    }

    pub fn payment_intent_for_job(
        &self,
        job_id: &str,
    ) -> Result<Option<PaymentIntent>> {
        Ok(self.records()?.into_iter().find_map(|r| match r {
            LedgerRecord::PaymentIntent { intent, .. }
                if intent.job_id == job_id => Some(intent),
            _ => None,
        }))
    }

    pub fn create_payment_intent(
        &self,
        job_id: &str,
        anchor_block: u64,
        anchor_block_hash: &str,
        anchor_timestamp_unix: u64,
    ) -> Result<PaymentIntent> {
        let job = self
            .find_job(job_id)?
            .ok_or_else(|| EconomyError::NotFound(format!("job {job_id}")))?;
        if job.internal_work {
            return Err(EconomyError::Invalid(
                "internal work cannot have an external payment intent".into(),
            ));
        }
        if let Some(existing) = self.payment_intent_for_job(job_id)? {
            return Ok(existing);
        }
        let policy = self.payment_policy()?;
        let intent_id = stable_id(
            "payintent",
            &[
                job_id,
                &anchor_block.to_string(),
                anchor_block_hash,
                &job.max_price_musd_micros.to_string(),
            ],
        );
        let intent = PaymentIntent {
            schema_version: SCHEMA_VERSION,
            payment_intent_id: intent_id,
            job_id: job_id.to_string(),
            chain_id: policy.chain_id,
            token: policy.token,
            recipient: policy.payout_address,
            exact_amount_raw: job.max_price_musd_micros,
            anchor_block,
            anchor_block_hash: anchor_block_hash.to_ascii_lowercase(),
            anchor_timestamp_unix,
            created_at_unix: now_unix(),
        };
        let seq = self.next_sequence()?;
        self.append(LedgerRecord::PaymentIntent {
            sequence: seq,
            recorded_at_unix: now_unix(),
            prev_hash: String::new(),
            record_hash: String::new(),
            intent: intent.clone(),
        })?;
        Ok(intent)
    }

    pub fn append_job(&self, mut job: JobRequest) -> Result<JobRequest> {
        validate_job(&job)?;
        job.schema_version = SCHEMA_VERSION;
        let seq = self.next_sequence()?;
        self.append(LedgerRecord::Job {
            sequence: seq,
            recorded_at_unix: now_unix(),
            prev_hash: String::new(),
            record_hash: String::new(),
            job: job.clone(),
        })?;
        Ok(job)
    }

    pub fn append_work(&self, mut receipt: WorkReceipt) -> Result<WorkReceipt> {
        validate_work(&receipt)?;
        if self.find_job(&receipt.job_id)?.is_none() {
            return Err(EconomyError::NotFound(format!(
                "job {}",
                receipt.job_id
            )));
        }
        if self.find_work_for_job(&receipt.job_id)?.is_some() {
            return Err(EconomyError::Conflict(format!(
                "job {} already has a work receipt",
                receipt.job_id
            )));
        }
        receipt.schema_version = SCHEMA_VERSION;
        let seq = self.next_sequence()?;
        self.append(LedgerRecord::Work {
            sequence: seq,
            recorded_at_unix: now_unix(),
            prev_hash: String::new(),
            record_hash: String::new(),
            receipt: receipt.clone(),
        })?;
        Ok(receipt)
    }

    pub fn append_settlement(
        &self,
        mut settlement: SettlementReceipt,
    ) -> Result<SettlementReceipt> {
        validate_settlement(&settlement)?;
        let job = self
            .find_job(&settlement.job_id)?
            .ok_or_else(|| EconomyError::NotFound(format!("job {}", settlement.job_id)))?;
        let work = self
            .find_work_for_job(&settlement.job_id)?
            .ok_or_else(|| EconomyError::NotFound(format!(
                "verified work for job {}",
                settlement.job_id
            )))?;

        if work.receipt_id != settlement.work_receipt_id {
            return Err(EconomyError::Conflict(
                "settlement references a different work receipt".into(),
            ));
        }
        if !work.verified {
            return Err(EconomyError::Invalid(
                "unverified work cannot be settled".into(),
            ));
        }
        if self.find_settlement_for_job(&settlement.job_id)?.is_some() {
            return Err(EconomyError::Conflict(format!(
                "job {} already settled",
                settlement.job_id
            )));
        }

        // Settlement inherits internal-work truth from the authoritative job.
        settlement.internal_work = job.internal_work;
        settlement.schema_version = SCHEMA_VERSION;

        if settlement.mode == SettlementMode::Simulated {
            settlement.external_paid = false;
            settlement.payment_proof_verified = false;
            settlement.payment_proof_hash = None;
        }
        if settlement.external_paid && settlement.mode != SettlementMode::External {
            return Err(EconomyError::Invalid(
                "external_paid requires external settlement mode".into(),
            ));
        }
        if settlement.mode == SettlementMode::External
            && !settlement.payment_proof_verified
        {
            return Err(EconomyError::Invalid(
                "external settlement requires a verified payment proof".into(),
            ));
        }
        if settlement.payment_proof_verified
            && settlement.mode != SettlementMode::External
        {
            return Err(EconomyError::Invalid(
                "verified payment proof requires external settlement mode".into(),
            ));
        }
        if settlement.payment_proof_verified && !settlement.external_paid {
            return Err(EconomyError::Invalid(
                "verified payment proof requires external_paid=true".into(),
            ));
        }
        if settlement.counts_as_paid_demand() {
            let intent = self
                .payment_intent_for_job(&settlement.job_id)?
                .ok_or_else(|| EconomyError::Invalid(
                    "external settlement requires a recorded payment intent".into(),
                ))?;
            if settlement.payment_intent_id.as_deref()
                != Some(intent.payment_intent_id.as_str())
            {
                return Err(EconomyError::Invalid(
                    "settlement payment_intent_id mismatch".into(),
                ));
            }
            let payment_block = settlement.payment_block_number.ok_or_else(|| {
                EconomyError::Invalid(
                    "external settlement requires payment block number".into(),
                )
            })?;
            if payment_block <= intent.anchor_block {
                return Err(EconomyError::Invalid(
                    "payment block is not after payment-intent anchor".into(),
                ));
            }
        }
        if settlement.counts_as_paid_demand()
            && settlement.usd_equivalent_micros != job.max_price_musd_micros
        {
            return Err(EconomyError::Invalid(
                "external settlement must exactly match job price".into(),
            ));
        }

        if settlement.payment_proof_verified {
            if let Some(proof) = settlement.payment_proof_hash.as_deref() {
                for record in self.records()? {
                    if let LedgerRecord::Settlement { settlement: prior, .. } = record {
                        if prior.payment_proof_verified
                            && prior
                                .payment_proof_hash
                                .as_deref()
                                .map(|p| p.eq_ignore_ascii_case(proof))
                                .unwrap_or(false)
                        {
                            return Err(EconomyError::Conflict(
                                "payment proof already used by another settlement".into(),
                            ));
                        }
                    }
                }
            }
        }

        let seq = self.next_sequence()?;
        self.append(LedgerRecord::Settlement {
            sequence: seq,
            recorded_at_unix: now_unix(),
            prev_hash: String::new(),
            record_hash: String::new(),
            settlement: settlement.clone(),
        })?;
        Ok(settlement)
    }

    pub fn records(&self) -> Result<Vec<LedgerRecord>> {
        // The lock covers the whole read, not just the repair. The head anchor
        // is a *second* file: reading the ledger and the anchor outside one
        // critical section can observe them at different instants, and the
        // result is a phantom "truncated" verdict on a perfectly healthy ledger.
        // The append path uses `read_records` for the same reason: it already
        // holds this lock, and this lock is not reentrant.
        //
        // A read therefore waits behind a writer rather than reading
        // unverified state, and fails closed with a named error if the wait
        // expires — the same discipline as the rest of this crate.
        let _lock = durability::LedgerLock::acquire_timeout(
            &self.root,
            REVENUE_LEDGER_FILE,
            durability::LEDGER_LOCK_WAIT,
        )?;
        // A crash mid-append leaves a partial final line. Failing closed on it
        // would strand the ledger forever, and those bytes were never a
        // completed record, so they are discarded — loudly.
        let recovery =
            durability::recover_torn_tail(&self.ledger_path(), "revenue ledger")?;
        let records = self.read_records()?;
        self.verify_head(&records)?;
        // Record what the repair discarded. Without this the tally would live
        // only in the log line, and the head anchor — the durable record of what
        // this ledger has been through — would claim a clean history.
        if let Some(torn) = recovery {
            let head = records
                .last()
                .map_or(LEDGER_GENESIS_HASH, |r| r.record_hash());
            durability::store_head_anchor(
                &self.root,
                REVENUE_LEDGER_FILE,
                records.last().map_or(0, |r| r.sequence()),
                head,
                Some(torn.report(now_unix())),
            )?;
        }
        Ok(records)
    }

    /// Chain-verified head against the out-of-band anchor. See
    /// [`durability::HeadAnchor`] for what this does and does not defend against.
    ///
    /// The lock spans the chain's own integrity. It does not span the callers'
    /// "does this already exist?" checks, which run before `append` is reached:
    /// two callers can both pass `append_settlement`'s duplicate check and both
    /// append. That is a pre-existing check-then-act race in the business rules,
    /// not in the ledger, and closing it would mean holding the lock across
    /// every public write path — including ones owned elsewhere in this crate.
    /// Each append is still individually well-formed and chained.
    fn verify_head(&self, records: &[LedgerRecord]) -> Result<()> {
        let anchor = durability::read_head_anchor(&self.root, REVENUE_LEDGER_FILE)?;
        let head = records
            .last()
            .map_or(LEDGER_GENESIS_HASH, |r| r.record_hash());
        let hash_at = |seq: u64| {
            records
                .iter()
                .find(|r| r.sequence() == seq)
                .map(|r| r.record_hash().to_string())
        };
        durability::verify_head_anchor(
            anchor.as_ref(),
            records.last().map_or(0, |r| r.sequence()),
            head,
            &hash_at,
            "revenue ledger",
        )
    }

    fn read_records(&self) -> Result<Vec<LedgerRecord>> {
        let path = self.ledger_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(path)?;
        let mut records = Vec::new();
        let mut expected = 1u64;
        let mut expected_prev = LEDGER_GENESIS_HASH.to_string();
        for (idx, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: LedgerRecord = serde_json::from_str(&line).map_err(|e| {
                EconomyError::Invalid(format!(
                    "ledger line {} cannot be parsed: {}",
                    idx + 1,
                    e
                ))
            })?;
            if record.sequence() != expected {
                return Err(EconomyError::Invalid(format!(
                    "non-contiguous ledger sequence: expected {}, got {}",
                    expected,
                    record.sequence()
                )));
            }
            if record.prev_hash() != expected_prev {
                return Err(EconomyError::Invalid(format!(
                    "ledger hash-chain break at sequence {}: prev_hash mismatch",
                    record.sequence()
                )));
            }
            let computed = record.computed_hash()?;
            if record.record_hash() != computed {
                return Err(EconomyError::Invalid(format!(
                    "ledger hash mismatch at sequence {}",
                    record.sequence()
                )));
            }
            expected_prev = record.record_hash().to_string();
            expected += 1;
            records.push(record);
        }
        Ok(records)
    }

    pub fn audit_ledger(&self) -> Result<LedgerAudit> {
        let records = self.records()?;
        let head_hash = records
            .last()
            .map(|r| r.record_hash().to_string())
            .unwrap_or_else(|| LEDGER_GENESIS_HASH.to_string());
        Ok(LedgerAudit {
            valid: true,
            records: records.len() as u64,
            head_hash,
            ledger_path: self.ledger_path().display().to_string(),
        })
    }

    /// Paid demand through the view. With no registry and no provider this is
    /// the offline view, and nothing on the ledger can be attested; see
    /// [`Self::revenue_view`].
    pub fn revenue_summary(&self) -> Result<RevenueSummary> {
        let registry = crate::boundary::ControlledAddressRegistry::new();
        self.revenue_view(&registry).revenue_summary()
    }

    /// The read-side authority over the revenue ledger. The registry is a
    /// parameter for the same reason as in
    /// [`autonomy::AutonomousEconomy::view`]: a registry-free derivation would
    /// be an assertion.
    pub fn revenue_view<'a>(
        &'a self,
        registry: &'a crate::boundary::ControlledAddressRegistry,
    ) -> crate::verified_view::VerifiedRevenueView<'a> {
        crate::verified_view::VerifiedRevenueView::unverified(self, registry)
    }

    /// Counter assembly, handed the evidence the view re-derived so the ledger
    /// is walked once.
    pub(crate) fn revenue_summary_with_evidence(
        &self,
        mode: TrustMode,
        settlements: &[crate::verified_view::SettlementEvidence],
        note: &str,
    ) -> Result<RevenueSummary> {
        let mut summary = RevenueSummary {
            trust_mode: mode,
            attestation_note: note.to_string(),
            ..RevenueSummary::default()
        };
        let mut unattested = 0u64;
        for settlement in settlements {
            if settlement.counted {
                summary.external_paid_jobs += 1;
                summary.paid_demand_musd_micros = summary
                    .paid_demand_musd_micros
                    .saturating_add(settlement.usd_equivalent_micros);
                *summary
                    .by_asset_micros
                    .entry(settlement.settlement_asset.clone())
                    .or_default() += settlement.settled_amount_micros;
            } else {
                summary.internal_or_simulated_jobs += 1;
                if settlement.rederived {
                    unattested += 1;
                    summary.unattested_paid_demand_musd_micros = summary
                        .unattested_paid_demand_musd_micros
                        .saturating_add(settlement.usd_equivalent_micros);
                }
            }
        }
        summary.unattested_external_paid_jobs = unattested;
        Ok(summary)
    }

    /// RV through the view. With no registry and no provider this is the
    /// offline view and cannot report a promoted level.
    pub fn rv_status(&self, now: u64) -> Result<RvStatus> {
        let registry = crate::boundary::ControlledAddressRegistry::new();
        self.revenue_view(&registry).rv_status(now)
    }

    fn append(&self, mut record: LedgerRecord) -> Result<()> {
        // The lock spans read-tail → derive → write, not just the write. Two
        // appends racing outside the lock both read the same tail and derive the
        // same `sequence`; the duplicate is detected on read but never
        // prevented. Holding it across the whole cycle is the only fix.
        let _lock = durability::LedgerLock::acquire_timeout(
            &self.root,
            REVENUE_LEDGER_FILE,
            durability::LEDGER_LOCK_WAIT,
        )?;
        // Torn-tail repair runs under the lock we just took, so a concurrent
        // writer cannot have bytes in flight that this would truncate away.
        let recovery =
            durability::recover_torn_tail(&self.ledger_path(), "revenue ledger")?;

        let existing = self.read_records()?;
        // Authoritative sequence and predecessor, derived under the lock. The
        // callers still call `next_sequence()` for their own record literal, but
        // that read happens outside the lock and cannot be trusted to be
        // distinct, so the value that reaches disk is recomputed here.
        let prev = existing
            .last()
            .map(|r| r.record_hash().to_string())
            .unwrap_or_else(|| LEDGER_GENESIS_HASH.to_string());
        record.set_sequence(existing.last().map_or(1, |r| r.sequence() + 1));
        record.set_prev_hash(prev);
        record.set_record_hash(String::new());
        let hash = record.computed_hash()?;
        record.set_record_hash(hash.clone());

        // One buffer, one `write_all`, one `sync_data`: no window in which a
        // partially serialized record interleaves with anything.
        let line = serde_json::to_vec(&record)?;
        durability::append_line(&self.ledger_path(), &line)?;
        durability::store_head_anchor(
            &self.root,
            REVENUE_LEDGER_FILE,
            record.sequence(),
            &hash,
            recovery.map(|t| t.report(now_unix())),
        )
    }

    fn next_sequence(&self) -> Result<u64> {
        Ok(self
            .records()?
            .last()
            .map(|r| r.sequence() + 1)
            .unwrap_or(1))
    }

    fn find_job(&self, job_id: &str) -> Result<Option<JobRequest>> {
        Ok(self.records()?.into_iter().find_map(|r| match r {
            LedgerRecord::Job { job, .. } if job.job_id == job_id => Some(job),
            _ => None,
        }))
    }

    fn find_work_for_job(&self, job_id: &str) -> Result<Option<WorkReceipt>> {
        Ok(self.records()?.into_iter().find_map(|r| match r {
            LedgerRecord::Work { receipt, .. } if receipt.job_id == job_id => {
                Some(receipt)
            }
            _ => None,
        }))
    }

    fn find_settlement_for_job(
        &self,
        job_id: &str,
    ) -> Result<Option<SettlementReceipt>> {
        Ok(self.records()?.into_iter().find_map(|r| match r {
            LedgerRecord::Settlement { settlement, .. }
                if settlement.job_id == job_id =>
            {
                Some(settlement)
            }
            _ => None,
        }))
    }

    // ---- P4c: the settlement attestation ledger ---------------------------
    //
    // Settlement attestations live beside the revenue ledger rather than inside
    // it, in their own hash-chained, head-anchored file, for the same two reasons
    // the receipt attestations do (`autonomy::AutonomousEconomy`):
    //
    //  * the revenue ledger's wire format is not changed, so a ledger written
    //    before this step keeps deserializing byte for byte and every existing
    //    `record_hash` still recomputes;
    //  * an attestation is not an economic event. It must never reach a count, a
    //    total or a summary, and a separate file makes it impossible for it to
    //    be mistaken for one by a `match` that only ever learned about
    //    settlements.
    //
    // It is still protected by the same durability machinery as the ledger it
    // gates, because an attestation that can be lost between the signature and
    // the read is a settlement that stops counting for no visible reason.

    /// Where the settlement attestation ledger lives.
    pub fn settlement_attestation_ledger_path(&self) -> PathBuf {
        self.root
            .join(settlement_auth::SETTLEMENT_ATTESTATION_LEDGER_FILE)
    }

    /// Records a verifier signature over a settlement.
    ///
    /// The attestation ledger is chain-verified before the append, so a
    /// corrupted or truncated file refuses the write instead of extending it.
    /// Nothing here decides whether the settlement is genuine: the signature is
    /// re-verified against the current validated policy on every read, against
    /// the ledger's own payment intent.
    pub fn record_settlement_attestation(
        &self,
        attestation: &settlement_auth::AuthenticatedSettlementReceipt,
    ) -> Result<()> {
        self.append_settlement_attestation(attestation.clone())
    }

    /// Every recorded settlement attestation, in ledger order.
    ///
    /// Chain-verified and head-anchored, like the revenue ledger. An empty vector
    /// for a file that does not exist is the legacy case, not an error: a
    /// directory written before this step has settlements and no attestations,
    /// and every settlement in it is reported as unattested with the reason.
    pub fn settlement_attestations(
        &self,
    ) -> Result<Vec<settlement_auth::AuthenticatedSettlementReceipt>> {
        Ok(self
            .read_settlement_attestation_records()?
            .into_iter()
            .map(|r| r.attestation)
            .collect())
    }

    fn append_settlement_attestation(
        &self,
        attestation: settlement_auth::AuthenticatedSettlementReceipt,
    ) -> Result<()> {
        use settlement_auth::SETTLEMENT_ATTESTATION_LEDGER_FILE as FILE;
        let _lock = durability::LedgerLock::acquire_timeout(
            &self.root,
            FILE,
            durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery = durability::recover_torn_tail(
            &self.settlement_attestation_ledger_path(),
            "settlement attestation ledger",
        )?;
        // `read_settlement_attestation_file`, not the locked read: the ledger
        // lock is not reentrant, and the append path holds it. The head anchor
        // is checked here explicitly for the same reason — refusing to extend a
        // rewritten ledger is part of the append, not an optional extra.
        let existing = settlement_auth::read_settlement_attestation_file(
            &self.settlement_attestation_ledger_path(),
        )?;
        self.verify_settlement_attestation_head(&existing)?;
        let sequence = existing.last().map(|r| r.sequence + 1).unwrap_or(1);
        let prev_hash = existing
            .last()
            .map(|r| r.record_hash.clone())
            .unwrap_or_else(|| {
                settlement_auth::SETTLEMENT_ATTESTATION_GENESIS_HASH.to_string()
            });
        let mut record = settlement_auth::SettlementAttestationRecord {
            sequence,
            recorded_at_unix: now_unix(),
            prev_hash,
            record_hash: String::new(),
            attestation,
        };
        record.record_hash = record.computed_hash()?;
        let line = serde_json::to_vec(&record)?;
        durability::append_line(&self.settlement_attestation_ledger_path(), &line)?;
        durability::store_head_anchor(
            &self.root,
            FILE,
            record.sequence,
            &record.record_hash,
            recovery.map(|t| t.report(now_unix())),
        )
    }

    fn verify_settlement_attestation_head(
        &self,
        records: &[settlement_auth::SettlementAttestationRecord],
    ) -> Result<()> {
        use settlement_auth::SETTLEMENT_ATTESTATION_LEDGER_FILE as FILE;
        let anchor =
            durability::read_head_anchor(&self.root, FILE)?;
        let head = records.last().map_or(
            settlement_auth::SETTLEMENT_ATTESTATION_GENESIS_HASH,
            |r| r.record_hash.as_str(),
        );
        let hash_at = |seq: u64| {
            records
                .iter()
                .find(|r| r.sequence == seq)
                .map(|r| r.record_hash.clone())
        };
        durability::verify_head_anchor(
            anchor.as_ref(),
            records.last().map_or(0, |r| r.sequence),
            head,
            &hash_at,
            "settlement attestation ledger",
        )
    }

    /// Chain-verifies the settlement attestation ledger under its own lock, then
    /// checks it against the head anchor. Mirrors [`Self::records`] exactly,
    /// including the separate lock name: the two ledgers are distinct files and
    /// must not share a lock, or an append to one would refuse while the other
    /// is held.
    fn read_settlement_attestation_records(
        &self,
    ) -> Result<Vec<settlement_auth::SettlementAttestationRecord>> {
        use settlement_auth::SETTLEMENT_ATTESTATION_LEDGER_FILE as FILE;
        let _lock = durability::LedgerLock::acquire_timeout(
            &self.root,
            FILE,
            durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery = durability::recover_torn_tail(
            &self.settlement_attestation_ledger_path(),
            "settlement attestation ledger",
        )?;
        let records = settlement_auth::read_settlement_attestation_file(
            &self.settlement_attestation_ledger_path(),
        )?;
        self.verify_settlement_attestation_head(&records)?;
        if let Some(torn) = recovery {
            let head = records.last().map_or(
                settlement_auth::SETTLEMENT_ATTESTATION_GENESIS_HASH,
                |r| r.record_hash.as_str(),
            );
            durability::store_head_anchor(
                &self.root,
                FILE,
                records.last().map_or(0, |r| r.sequence),
                head,
                Some(torn.report(now_unix())),
            )?;
        }
        Ok(records)
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(prefix.as_bytes());
    for part in parts {
        h.update(&[0]);
        h.update(part.as_bytes());
    }
    format!("{}-{}", prefix, &h.finalize().to_hex()[..24])
}

fn nonempty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(EconomyError::Invalid(format!("{} cannot be empty", name)))
    } else {
        Ok(())
    }
}

/// Applied on every policy load, not only at create time: the policy file is
/// the out-of-band trust configuration, so it gets the same treatment as a
/// hand-edited ledger record.
fn validate_payment_policy(policy: &PaymentPolicy) -> Result<()> {
    if policy.chain_id != crate::base_usdc::BASE_CHAIN_ID {
        return Err(EconomyError::Invalid(format!(
            "payment policy chain_id must be {}",
            crate::base_usdc::BASE_CHAIN_ID
        )));
    }
    if !policy
        .token
        .eq_ignore_ascii_case(crate::base_usdc::BASE_USDC)
    {
        return Err(EconomyError::Invalid(
            "payment policy token must be Base USDC".into(),
        ));
    }
    crate::base_usdc::normalize_address(&policy.payout_address)?;
    if policy.min_confirmations == 0 {
        return Err(EconomyError::Invalid(
            "payment policy min_confirmations must be >= 1".into(),
        ));
    }
    if let Some(provider) = &policy.chain_provider {
        provider.validate_policy_pin()?;
    }
    Ok(())
}

fn validate_job(job: &JobRequest) -> Result<()> {
    nonempty("job_id", &job.job_id)?;
    nonempty("requester_id", &job.requester_id)?;
    nonempty("input_hash", &job.input_hash)?;
    if job.max_price_musd_micros == 0 && !job.internal_work {
        return Err(EconomyError::Invalid(
            "external job max price must be > 0".into(),
        ));
    }
    Ok(())
}

fn validate_work(work: &WorkReceipt) -> Result<()> {
    nonempty("receipt_id", &work.receipt_id)?;
    nonempty("job_id", &work.job_id)?;
    nonempty("worker_id", &work.worker_id)?;
    nonempty("result_hash", &work.result_hash)?;
    nonempty("verifier_id", &work.verifier_id)?;
    if work.completed_at_unix < work.started_at_unix {
        return Err(EconomyError::Invalid(
            "completion precedes start".into(),
        ));
    }
    if work.useful_work_units == 0 {
        return Err(EconomyError::Invalid(
            "useful_work_units must be > 0".into(),
        ));
    }
    Ok(())
}

fn validate_settlement(s: &SettlementReceipt) -> Result<()> {
    nonempty("settlement_id", &s.settlement_id)?;
    nonempty("job_id", &s.job_id)?;
    nonempty("work_receipt_id", &s.work_receipt_id)?;
    nonempty("settlement_asset", s.settlement_asset.symbol())?;
    if s.settled_amount_micros == 0 {
        return Err(EconomyError::Invalid(
            "settled amount must be > 0".into(),
        ));
    }
    if s.external_paid
        && s.payment_proof_hash
            .as_deref()
            .map(|x| x.trim().is_empty())
            .unwrap_or(true)
    {
        return Err(EconomyError::Invalid(
            "external payment requires payment_proof_hash".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn job(internal: bool) -> JobRequest {
        JobRequest {
            schema_version: SCHEMA_VERSION,
            job_id: "job-1".into(),
            created_at_unix: 1_700_000_000,
            requester_id: "customer-A".into(),
            job_type: JobType::Build,
            input_hash: "sha256:input".into(),
            max_price_musd_micros: 5_000_000,
            internal_work: internal,
            description: "build test".into(),
        }
    }

    fn work() -> WorkReceipt {
        WorkReceipt {
            schema_version: SCHEMA_VERSION,
            receipt_id: "work-1".into(),
            job_id: "job-1".into(),
            worker_id: "worker-A".into(),
            started_at_unix: 1_700_000_001,
            completed_at_unix: 1_700_000_010,
            result_hash: "sha256:result".into(),
            useful_work_units: 10,
            verifier_id: "verifier-A".into(),
            verified_at_unix: 1_700_000_011,
            verified: true,
        }
    }

    fn prepare_external(econ: &LocalEconomy, job_id: &str) {
        if econ.payment_policy_path().exists() == false {
            econ.init_payment_policy(PAYOUT, 2)
            .unwrap();
        }
        econ.create_payment_intent(
            job_id,
            100,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1_700_000_005,
        )
        .unwrap();
    }

    fn external_settlement(
        econ: &LocalEconomy,
        job_id: &str,
        work_receipt_id: &str,
    ) -> SettlementReceipt {
        let intent = econ
            .payment_intent_for_job(job_id)
            .unwrap()
            .expect("payment intent");
        let mut s = settlement(SettlementMode::External, true);
        s.job_id = job_id.to_string();
        s.work_receipt_id = work_receipt_id.to_string();
        s.payment_intent_id = Some(intent.payment_intent_id);
        s.payment_block_number = Some(intent.anchor_block + 1);
        s
    }

    /// A pinned provider that actually serves the payment the settlement cites:
    /// an exact USDC transfer to the policy's payout address, in the block the
    /// settlement books, in the canonical block. `FakeRpcSocket` binds a real
    /// owner-only Unix socket, so the kernel identity check runs for real.
    fn serving_socket(
        dir: &std::path::Path,
        recipient: &str,
        amount_raw: u64,
    ) -> crate::rpc_test_server::FakeRpcSocket {
        let log = serde_json::json!({
            "address": crate::base_usdc::BASE_USDC,
            "topics": [
                crate::base_usdc::ERC20_TRANSFER_TOPIC,
                format!("0x{:0>64}", "1234567890abcdef1234567890abcdef12345678"),
                format!("0x{:0>64}", recipient.trim_start_matches("0x")),
            ],
            "data": format!("0x{amount:064x}", amount = amount_raw),
            "logIndex": "0x1",
        });
        crate::rpc_test_server::FakeRpcSocket::with_responses(
            dir.join("verifier.sock"),
            vec![
                ("eth_chainId", serde_json::json!("0x2105")),
                ("eth_blockNumber", serde_json::json!("0x6e")),
                ("eth_getTransactionReceipt", serde_json::json!({
                    "status": "0x1",
                    "blockNumber": "0x65",
                    "blockHash": format!("0x{}", "ab".repeat(32)),
                    "transactionHash": payment_tx_hash(),
                    "logs": [log],
                })),
                ("eth_getBlockByNumber", serde_json::json!({
                    "hash": format!("0x{}", "ab".repeat(32)),
                    "timestamp": "0x6553f0d0",
                })),
            ],
        )
    }

    fn payment_tx_hash() -> String {
        format!("0x{}", "cd".repeat(32))
    }

    const PAYOUT: &str = "0x1234567890abcdef1234567890abcdef12345678";

    /// An owned pinned revenue view. The socket has to outlive the verifier, and
    /// the registry, verifier and validated policy have to outlive the view, so
    /// they live here rather than in a function that hands a borrow back. The
    /// policy is P4b's requirement: a revenue view without one does not promote.
    struct PinnedRevenue<'a> {
        _socket: crate::rpc_test_server::FakeRpcSocket,
        registry: crate::boundary::ControlledAddressRegistry,
        verifier: crate::base_usdc::BaseUsdcVerifier,
        auth: crate::receipt_auth::testkit::AuthFixture,
        policy: crate::policy_auth::ValidatedOutcomePolicy,
        econ: &'a LocalEconomy,
    }

    impl<'a> PinnedRevenue<'a> {
        fn view(&'a self) -> crate::verified_view::VerifiedRevenueView<'a> {
            crate::verified_view::VerifiedRevenueView::provider_pinned(
                self.econ,
                &self.registry,
                &self.verifier,
                &self.policy,
            )
            .unwrap()
        }

        /// Signs the settlement for `job_id` with the policy's delegated
        /// verifier and records the attestation.
        ///
        /// P4c made this mandatory: from that step a settlement reaches paid
        /// demand only with a signature, so every positive control in this file
        /// signs here rather than each test re-deriving the two records.
        fn attest_settlement(&self, job_id: &str) {
            let settlement = self
                .econ
                .records()
                .unwrap()
                .into_iter()
                .find_map(|r| match r {
                    LedgerRecord::Settlement { settlement, .. }
                        if settlement.job_id == job_id =>
                    {
                        Some(settlement)
                    }
                    _ => None,
                })
                .unwrap_or_else(|| panic!("a settlement for job {job_id}"));
            let intent = self
                .econ
                .payment_intent_for_job(job_id)
                .unwrap()
                .expect("a payment intent");
            let attestation = self
                .auth
                .verifier
                .attest_settlement(&self.policy, &settlement, &intent)
                .unwrap();
            self.econ.record_settlement_attestation(&attestation).unwrap();
        }
    }

    /// A revenue view backed by a provider that serves this payment, plus the
    /// registry the payment recipient has to be in.
    fn pinned_revenue_view<'a>(
        dir: &std::path::Path,
        econ: &'a LocalEconomy,
        amount_raw: u64,
    ) -> PinnedRevenue<'a> {
        let registry = crate::boundary::ControlledAddressRegistry::new()
            .with_address(PAYOUT)
            .unwrap();
        let socket = serving_socket(dir, PAYOUT, amount_raw);
        let provider = crate::chain_provider::PinnedChainProvider::unix_socket(
            socket.path(),
            Some(socket.uid()),
        )
        .unwrap();
        let resolved =
            crate::chain_provider::resolve(None, Some(&provider)).unwrap();
        let verifier =
            crate::base_usdc::BaseUsdcVerifier::from_resolved(&resolved, 2)
                .unwrap();
        assert!(verifier.provider_identity_verified());
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        PinnedRevenue {
            _socket: socket,
            registry,
            verifier,
            auth,
            policy,
            econ,
        }
    }

    fn settlement(mode: SettlementMode, external: bool) -> SettlementReceipt {
        SettlementReceipt {
            schema_version: SCHEMA_VERSION,
            settlement_id: "settle-1".into(),
            job_id: "job-1".into(),
            work_receipt_id: "work-1".into(),
            settled_at_unix: 1_700_000_012,
            mode,
            settlement_asset: SettlementAsset::classify_symbol("USDC").unwrap(),
            settled_amount_micros: if external { 5_000_000 } else { 2_000_000 },
            usd_equivalent_micros: if external { 5_000_000 } else { 2_000_000 },
            payment_intent_id: external.then(|| "intent-1".into()),
            payment_block_number: external.then_some(101),
            payment_proof_hash: external.then(|| "proof:abc".into()),
            payment_proof_verified: external,
            external_paid: external,
            internal_work: false,
        }
    }

    #[test]
    fn payment_policy_pins_the_provider_at_create_time() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        let socket = dir.path().join("verifier.sock");
        let pin = crate::chain_provider::PinnedChainProvider::unix_socket(
            &socket,
            Some(4242),
        )
        .unwrap();
        let policy = econ
            .init_payment_policy_with_provider(
                "0x1234567890abcdef1234567890abcdef12345678",
                2,
                Some(&pin),
            )
            .unwrap();
        assert_eq!(
            policy.chain_provider.as_ref().unwrap().endpoint(),
            pin.endpoint()
        );
        // The pin survives a round trip through the file.
        let loaded = econ.payment_policy().unwrap();
        assert_eq!(loaded.chain_provider, Some(pin.clone()));
        assert!(loaded.chain_provider.unwrap().validate_policy_pin().is_ok());
    }

    #[test]
    fn policy_without_a_provider_loads_but_cannot_verify() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        // A policy written before provider pinning existed.
        fs::write(
            econ.payment_policy_path(),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "chain_id": 8453,
                "token": crate::base_usdc::BASE_USDC.to_ascii_lowercase(),
                "payout_address": "0x1234567890abcdef1234567890abcdef12345678",
                "min_confirmations": 2,
                "created_at_unix": 1_700_000_000
            }))
            .unwrap(),
        )
        .unwrap();
        let policy = econ.payment_policy().unwrap();
        assert!(policy.chain_provider.is_none());
        // Backwards compatible load, but the verifier still refuses.
        let err = crate::chain_provider::resolve(None, policy.chain_provider.as_ref())
            .unwrap_err();
        assert!(matches!(err, EconomyError::ProviderUnpinned(_)));
    }

    #[test]
    fn policy_load_rejects_a_forged_provider_pin() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        let write = |provider: serde_json::Value| {
            fs::write(
                econ.payment_policy_path(),
                serde_json::to_vec(&serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "chain_id": 8453,
                    "token": crate::base_usdc::BASE_USDC.to_ascii_lowercase(),
                    "payout_address": "0x1234567890abcdef1234567890abcdef12345678",
                    "min_confirmations": 2,
                    "created_at_unix": 1_700_000_000,
                    "chain_provider": provider
                }))
                .unwrap(),
            )
            .unwrap();
        };
        // A hand-edited policy cannot move the verifier to a loopback port.
        write(serde_json::json!({
            "transport": "loopback_http",
            "endpoint": "http://127.0.0.1:8546",
            "socket_owner_uid": null
        }));
        let err = econ.payment_policy().unwrap_err();
        assert!(err.to_string().contains("no verifiable identity"), "{err}");

        // Nor to a remote endpoint smuggled in as a "unix" transport.
        write(serde_json::json!({
            "transport": "unix_socket",
            "endpoint": "http://attacker.example:8546",
            "socket_owner_uid": 0
        }));
        assert!(econ.payment_policy().is_err());
    }

    #[test]
    fn policy_load_rejects_a_foreign_chain_or_token() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        let write = |chain_id: u64, token: &str| {
            fs::write(
                econ.payment_policy_path(),
                serde_json::to_vec(&serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "chain_id": chain_id,
                    "token": token,
                    "payout_address": "0x1234567890abcdef1234567890abcdef12345678",
                    "min_confirmations": 2,
                    "created_at_unix": 1_700_000_000
                }))
                .unwrap(),
            )
            .unwrap();
        };
        write(1, crate::base_usdc::BASE_USDC.to_ascii_lowercase().as_str());
        assert!(econ
            .payment_policy()
            .unwrap_err()
            .to_string()
            .contains("chain_id"));
        write(
            crate::base_usdc::BASE_CHAIN_ID,
            "0xdac17f958d2ee523a2206206994597c13d831ec7",
        );
        assert!(econ
            .payment_policy()
            .unwrap_err()
            .to_string()
            .contains("Base USDC"));
    }

    #[test]
    fn pinning_an_existing_policy_keeps_its_payout_address() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.init_payment_policy("0x1234567890abcdef1234567890abcdef12345678", 3)
            .unwrap();
        let pin = crate::chain_provider::PinnedChainProvider::unix_socket(
            "/run/mycelium-verifier.sock",
            Some(0),
        )
        .unwrap();
        let pinned = econ.pin_chain_provider(&pin).unwrap();
        assert_eq!(pinned.min_confirmations, 3);
        assert_eq!(
            pinned.payout_address,
            "0x1234567890abcdef1234567890abcdef12345678"
        );
        assert_eq!(econ.payment_policy().unwrap().chain_provider, Some(pin));
        // No temporary file left behind by the write-then-rename.
        assert!(!dir.path().join("payment-policy.json.tmp").exists());
    }

    #[test]
    fn payment_policy_is_create_once_and_local() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        let p = econ
            .init_payment_policy(
                "0x1234567890abcdef1234567890abcdef12345678",
                2,
            )
            .unwrap();
        assert_eq!(p.chain_id, 8453);
        assert_eq!(
            p.payout_address,
            "0x1234567890abcdef1234567890abcdef12345678"
        );
        assert!(econ.init_payment_policy(&p.payout_address, 2).is_err());
        assert_eq!(
            econ.payment_policy().unwrap().payout_address,
            p.payout_address
        );
    }

    #[test]
    fn simulated_settlement_never_counts_as_paid_demand() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        econ.append_settlement(settlement(SettlementMode::Simulated, false))
            .unwrap();

        let s = econ.revenue_summary().unwrap();
        assert_eq!(s.external_paid_jobs, 0);
        assert_eq!(s.paid_demand_musd_micros, 0);
        assert_eq!(s.internal_or_simulated_jobs, 1);
    }

    #[test]
    fn internal_work_never_counts_even_with_external_marker() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(true)).unwrap();
        econ.append_work(work()).unwrap();
        // Internal work cannot even create the external payment intent.
        econ.init_payment_policy(
            "0x1234567890abcdef1234567890abcdef12345678", 2
        ).unwrap();
        assert!(econ.create_payment_intent(
            "job-1", 100,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            1_700_000_005
        ).is_err());
        assert_eq!(econ.revenue_summary().unwrap().external_paid_jobs, 0);
    }

    #[test]
    fn verified_external_settlement_promotes_rv0() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        let mut s = external_settlement(&econ, "job-1", "work-1");
        // A settlement has to cite a real transaction for a reader to be able to
        // ask about one. Before P3 this field held "proof:abc" and the promotion
        // rested on `payment_proof_verified: true`.
        s.payment_proof_hash = Some(payment_tx_hash());
        econ.append_settlement(s).unwrap();

        // Offline: every structural fact re-derives, and the claim is reported.
        let offline_registry = crate::boundary::ControlledAddressRegistry::new();
        let offline =
            econ.revenue_view(&offline_registry).rv_status(1_700_000_100)
                .unwrap();
        assert_eq!(offline.level, "PRE-RV0");
        assert!(!offline.rv0_pass);
        assert_eq!(offline.external_paid_jobs, 0);
        assert_eq!(offline.unattested_external_paid_jobs, 0);
        assert!(offline.attestation_note.contains("TrustMode=unverified"), "{offline:?}");

        // Pinned and confirmed: RV0, and the same 5 mUSD the old code reported.
        // P4c: the settlement also has to be signed by the policy's delegated
        // verifier now, or it is an unsigned claim however real the payment.
        let pinned = pinned_revenue_view(dir.path(), &econ, 5_000_000);
        pinned.attest_settlement("job-1");
        let view = pinned.view();
        let s = view.revenue_summary().unwrap();
        assert_eq!(s.trust_mode, TrustMode::ProviderPinned);
        assert_eq!(s.external_paid_jobs, 1);
        assert_eq!(s.paid_demand_musd_micros, 5_000_000);

        let rv = view.rv_status(1_700_000_100).unwrap();
        assert_eq!(rv.level, "RV0");
        assert!(rv.rv0_pass);
        assert_eq!(rv.trust_mode, TrustMode::ProviderPinned);
        assert_eq!(rv.external_paid_jobs, 1);
        assert_eq!(rv.paid_demand_musd_total, 5.0);
    }

    #[test]
    fn a_settlement_whose_provider_disagrees_is_not_paid_demand() {
        // Same ledger, provider says the payment never happened. This is the
        // predicate a forged `payment_proof_verified: true` fails.
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        let mut s = external_settlement(&econ, "job-1", "work-1");
        s.payment_proof_hash = Some(payment_tx_hash());
        econ.append_settlement(s).unwrap();

        let registry =
            crate::boundary::ControlledAddressRegistry::new()
                .with_address("0x1234567890abcdef1234567890abcdef12345678")
                .unwrap();
        let socket = crate::rpc_test_server::FakeRpcSocket::with_responses(
            dir.path().join("unbacked.sock"),
            vec![
                ("eth_chainId", serde_json::json!("0x2105")),
                ("eth_blockNumber", serde_json::json!("0x6e")),
                ("eth_getTransactionReceipt", serde_json::Value::Null),
            ],
        );
        let provider = crate::chain_provider::PinnedChainProvider::unix_socket(
            socket.path(),
            Some(socket.uid()),
        )
        .unwrap();
        let resolved =
            crate::chain_provider::resolve(None, Some(&provider)).unwrap();
        let verifier =
            crate::base_usdc::BaseUsdcVerifier::from_resolved(&resolved, 2)
                .unwrap();
        // P4b: the revenue view needs a validated policy to promote at all.
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        let view = crate::verified_view::VerifiedRevenueView::provider_pinned(
            &econ, &registry, &verifier, &policy,
        )
        .unwrap();
        let evidence = view.settlement_evidence().unwrap();
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].stored_payment_proof_verified);
        assert!(evidence[0].rederived, "every structural fact re-derived");
        assert!(!evidence[0].counted);
        assert_eq!(view.rv_status(1_700_000_100).unwrap().level, "PRE-RV0");
    }

    /// Appends a settlement straight to the revenue ledger with a correctly
    /// chained hash, the way anything writing the file could. Used for records
    /// the typed write path refuses, which is exactly the set worth reading
    /// without consulting a stored boolean.
    fn append_settlement_by_hand(econ: &LocalEconomy, settlement: &SettlementReceipt) {
        let path = econ.ledger_path();
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = raw.lines().map(|l| l.to_string()).collect();
        let last: LedgerRecord =
            serde_json::from_str(lines.last().unwrap()).unwrap();
        let mut record = LedgerRecord::Settlement {
            sequence: last.sequence() + 1,
            recorded_at_unix: 1_700_000_013,
            prev_hash: last.record_hash().to_string(),
            record_hash: String::new(),
            settlement: settlement.clone(),
        };
        // Same rule as the append path: the hash is over the canonical record
        // with an empty `record_hash`, so this line chains exactly like one the
        // crate wrote itself.
        record.set_record_hash(record.computed_hash().unwrap());
        lines.push(serde_json::to_string(&record).unwrap());
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
    }

    #[test]
    fn the_settlement_flags_still_move_nothing() {
        // P4b verification of a P3 property, on the revenue side. The stored
        // `payment_proof_verified` and `external_paid` booleans grant nothing in
        // either direction: a settlement with both flags on and a payment that
        // does not exist does not promote, and one with both flags off but a
        // payment the provider confirms does.
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        let off = external_settlement(&econ, "job-1", "work-1");
        // The write path refuses an external settlement whose flags say "not
        // verified, not paid" — so the flags-off record has to be written the
        // way a forger would write it: by hand, into a correctly chained ledger.
        // That is the whole point of the test: the reader must not consult the
        // flags either way.
        let mut off = off;
        off.payment_proof_hash = Some(payment_tx_hash());
        off.payment_proof_verified = false;
        off.external_paid = false;
        append_settlement_by_hand(&econ, &off);

        // The flags are off. The payment is real and the provider confirms it,
        // so it still counts: the flags are not an input. P4c: the attestation
        // is signed over the flags-off record, so "the flags are not an input"
        // stays true of the signature too — signing does not read them either.
        let pinned = pinned_revenue_view(dir.path(), &econ, 5_000_000);
        pinned.attest_settlement("job-1");
        let view = pinned.view();
        let rows = view.settlement_evidence().unwrap();
        assert!(!rows[0].stored_payment_proof_verified);
        assert!(!rows[0].stored_external_paid);
        assert!(rows[0].counted, "the flags are not an input");
        assert_eq!(view.rv_status(1_700_000_100).unwrap().level, "RV0");

        // And the other direction, on a ledger the provider has never seen: the
        // flags are on and nothing counts.
        let forged_dir = tempdir().unwrap();
        let forged = LocalEconomy::open(forged_dir.path()).unwrap();
        forged.append_job(job(false)).unwrap();
        forged.append_work(work()).unwrap();
        prepare_external(&forged, "job-1");
        let mut on = external_settlement(&forged, "job-1", "work-1");
        on.payment_proof_hash = Some(payment_tx_hash());
        on.payment_proof_verified = true;
        on.external_paid = true;
        forged.append_settlement(on).unwrap();
        // A provider pinned to a socket that has never seen the transaction.
        let socket = crate::rpc_test_server::FakeRpcSocket::with_responses(
            forged_dir.path().join("unbacked.sock"),
            vec![
                ("eth_chainId", serde_json::json!("0x2105")),
                ("eth_blockNumber", serde_json::json!("0x6e")),
                ("eth_getTransactionReceipt", serde_json::Value::Null),
            ],
        );
        let provider = crate::chain_provider::PinnedChainProvider::unix_socket(
            socket.path(),
            Some(socket.uid()),
        )
        .unwrap();
        let resolved =
            crate::chain_provider::resolve(None, Some(&provider)).unwrap();
        let verifier =
            crate::base_usdc::BaseUsdcVerifier::from_resolved(&resolved, 2)
                .unwrap();
        let registry = crate::boundary::ControlledAddressRegistry::new()
            .with_address(PAYOUT)
            .unwrap();
        let auth_dir = tempdir().unwrap();
        let auth_socket = serving_socket(auth_dir.path(), PAYOUT, 5_000_000);
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            auth_socket.path(),
            auth_socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        let view =
            crate::verified_view::VerifiedRevenueView::provider_pinned(
                &forged,
                &registry,
                &verifier,
                &policy,
            )
            .unwrap();
        let rows = view.settlement_evidence().unwrap();
        assert!(rows[0].stored_payment_proof_verified);
        assert!(rows[0].stored_external_paid);
        assert!(!rows[0].counted, "a stored flag must not stand in for a payment");
        assert_eq!(view.rv_status(1_700_000_100).unwrap().level, "PRE-RV0");
        assert_eq!(view.rv_status(1_700_000_100).unwrap().external_paid_jobs, 0);
    }

    #[test]
    fn a_dev_provider_cannot_promote_paid_demand() {
        // The revenue half of `the_dev_provider_can_never_produce_a_verified_nev`
        // in `verified_view.rs`. It lives here because this module is where the
        // settlement fixtures are.
        //
        // A genuine paid settlement, re-derived from a real payment intent to a
        // controlled recipient, with a block after the intent's anchor and a
        // transaction hash in it. The only thing wrong is that the provider
        // asked to confirm it is an address rather than an identity.
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        let mut s = external_settlement(&econ, "job-1", "work-1");
        s.payment_proof_hash = Some(payment_tx_hash());
        econ.append_settlement(s).unwrap();

        // Positive control: the identical ledger, with a kernel-identified
        // provider and a validated policy, promotes. P4c: signed, so the
        // control is genuine in every respect and the only variable left for
        // the dev-provider half below is the provider's identity.
        let pinned = pinned_revenue_view(dir.path(), &econ, 5_000_000);
        pinned.attest_settlement("job-1");
        let rv = pinned.view().rv_status(1_700_000_100).unwrap();
        assert_eq!(rv.level, "RV0");
        assert_eq!(rv.external_paid_jobs, 1);

        // Now the same thing with the dev override, and an authority scoped to a
        // real socket so the policy is genuine.
        let auth_dir = tempdir().unwrap();
        let socket = serving_socket(auth_dir.path(), PAYOUT, 5_000_000);
        let registry = crate::boundary::ControlledAddressRegistry::new()
            .with_address(PAYOUT)
            .unwrap();
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        let dev = crate::base_usdc::BaseUsdcVerifier::new(
            "http://127.0.0.1:8546",
            2,
        )
        .unwrap();
        assert!(
            !dev.provider_identity_verified(),
            "a loopback address is not an identity"
        );

        // 1. No pinned view exists at all with this provider.
        let err = match crate::verified_view::VerifiedRevenueView::provider_pinned(
            &econ, &registry, &dev, &policy,
        ) {
            Ok(_) => panic!("a loopback endpoint must not attest paid demand"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("kernel-enforced identity"),
            "{err}"
        );

        // 2. And in the mode it is allowed, paid demand stays at zero.
        let offline =
            crate::verified_view::VerifiedRevenueView::unverified(
                &econ, &registry,
            );
        let rv = offline.rv_status(1_700_000_100).unwrap();
        assert_eq!(rv.level, "PRE-RV0");
        assert!(!rv.rv0_pass);
        assert_eq!(rv.trust_mode, TrustMode::Unverified);
        assert_eq!(rv.external_paid_jobs, 0);
        assert_eq!(rv.paid_demand_musd_total, 0.0);
        assert_eq!(rv.unattested_external_paid_jobs, 1);
        assert_eq!(rv.unattested_paid_demand_musd_total, 5.0);
        let summary = offline.revenue_summary().unwrap();
        assert_eq!(summary.external_paid_jobs, 0);
        assert_eq!(summary.paid_demand_musd_micros, 0);
        assert_eq!(summary.trust_mode, TrustMode::Unverified);
    }

    #[test]
    fn a_revenue_view_without_a_policy_does_not_promote() {
        // P4b. There is no `SettlementReceipt` wrapper, so the "authenticated"
        // half of RV is exactly one thing: the view holds a policy that
        // validated against the pinned anchor. This test says what that is worth
        // — without it, even a genuine settlement re-derived and confirmed by a
        // kernel-identified provider does not promote.
        //
        // P4c keeps that statement true and makes it smaller: the view holds a
        // policy *and* a signature from the key that policy delegated to. The
        // positive control below is signed, so what this test isolates is the
        // policy and not the signature.
        //
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        let mut s = external_settlement(&econ, "job-1", "work-1");
        s.payment_proof_hash = Some(payment_tx_hash());
        econ.append_settlement(s).unwrap();

        let registry =
            crate::boundary::ControlledAddressRegistry::new()
                .with_address(PAYOUT)
                .unwrap();
        let socket = serving_socket(dir.path(), PAYOUT, 5_000_000);
        let provider = crate::chain_provider::PinnedChainProvider::unix_socket(
            socket.path(),
            Some(socket.uid()),
        )
        .unwrap();
        let resolved =
            crate::chain_provider::resolve(None, Some(&provider)).unwrap();
        let verifier =
            crate::base_usdc::BaseUsdcVerifier::from_resolved(&resolved, 2)
                .unwrap();
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();

        // P4c: the positive control has to be signed, or it would be proving
        // "a policy is not enough" over a settlement that is also unsigned. The
        // sign is the whole point of the second half of this test.
        let intent = econ
            .payment_intent_for_job("job-1")
            .unwrap()
            .expect("payment intent");
        let signed = econ
            .records()
            .unwrap()
            .into_iter()
            .find_map(|r| match r {
                LedgerRecord::Settlement { settlement, .. } => Some(settlement),
                _ => None,
            })
            .expect("settlement");
        let attestation = auth
            .verifier
            .attest_settlement(&policy, &signed, &intent)
            .unwrap();
        econ.record_settlement_attestation(&attestation).unwrap();

        // Positive control first: with the policy, the same bytes promote.
        let promoted =
            crate::verified_view::VerifiedRevenueView::provider_pinned(
                &econ,
                &registry,
                &verifier,
                &policy,
            )
            .unwrap();
        let rows = promoted.settlement_evidence().unwrap();
        assert!(
            rows[0].counted,
            "with a validated policy the genuine payment is counted: {}",
            rows[0].gap.as_ref().map(|g| g.describe()).unwrap_or_default()
        );
        assert_eq!(promoted.rv_status(1_700_000_100).unwrap().level, "RV0");

        // And the same provider, the same chain read, no policy: unattested with
        // the reason. There is no constructor that skips this check.
        let offline =
            crate::verified_view::VerifiedRevenueView::unverified(
                &econ,
                &registry,
            );
        let rows = offline.settlement_evidence().unwrap();
        assert!(!rows[0].counted);
        assert_eq!(
            rows[0].gap,
            Some(crate::verified_view::SettlementGap::PolicyNotValidated)
        );
        let rv = offline.rv_status(1_700_000_100).unwrap();
        assert_eq!(rv.level, "PRE-RV0");
        assert_eq!(rv.external_paid_jobs, 0);
        assert_eq!(rv.paid_demand_musd_total, 0.0);
        assert!(rv
            .attestation_note
            .contains("no validated outcome policy"), "{rv:?}");
        assert_eq!(
            offline.revenue_summary().unwrap().external_paid_jobs,
            0,
            "the summary books nothing either"
        );
    }

    #[test]
    fn unverified_work_cannot_settle() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        let mut w = work();
        w.verified = false;
        econ.append_work(w).unwrap();
        prepare_external(&econ, "job-1");
        let err = econ
            .append_settlement(external_settlement(&econ, "job-1", "work-1"))
            .unwrap_err();
        assert!(err.to_string().contains("unverified"));
    }

    #[test]
    fn external_settlement_must_exactly_match_job_price() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        let mut s = external_settlement(&econ, "job-1", "work-1");
        s.usd_equivalent_micros = 6_000_000;
        let err = econ.append_settlement(s).unwrap_err();
        assert!(err.to_string().contains("exactly match job price"));
    }

    #[test]
    fn asserted_external_payment_without_verification_is_rejected() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        let mut s = external_settlement(&econ, "job-1", "work-1");
        s.payment_proof_verified = false;
        let err = econ.append_settlement(s).unwrap_err();
        assert!(err.to_string().contains("verified payment proof"));
        assert_eq!(econ.revenue_summary().unwrap().external_paid_jobs, 0);
    }

    #[test]
    fn verified_payment_proof_cannot_be_reused() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        econ.append_settlement(external_settlement(&econ, "job-1", "work-1"))
            .unwrap();

        let mut j2 = job(false);
        j2.job_id = "job-2".into();
        econ.append_job(j2).unwrap();
        let mut w2 = work();
        w2.job_id = "job-2".into();
        w2.receipt_id = "work-2".into();
        econ.append_work(w2).unwrap();
        econ.create_payment_intent(
            "job-2", 100,
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            1_700_000_005,
        ).unwrap();
        let mut s2 = external_settlement(&econ, "job-2", "work-2");
        s2.settlement_id = "settle-2".into();
        let err = econ.append_settlement(s2).unwrap_err();
        assert!(err.to_string().contains("already used"));
    }

    #[test]
    fn rv1_requires_complete_30_day_window() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        let mut s = external_settlement(&econ, "job-1", "work-1");
        s.usd_equivalent_micros = 5_000_000;
        s.settled_amount_micros = 5_000_000;
        s.payment_proof_hash = Some(payment_tx_hash());
        econ.append_settlement(s).unwrap();

        // 5 mUSD from a fresh settlement is RV0, never RV1 merely because
        // dividing a partial window happens to cross a daily threshold.
        // P4c: signed, or it is not counted and the level is PRE-RV0.
        let pinned = pinned_revenue_view(dir.path(), &econ, 5_000_000);
        pinned.attest_settlement("job-1");
        let rv = pinned.view().rv_status(1_700_000_100).unwrap();
        assert_eq!(rv.level, "RV0");
    }

    #[test]
    fn payment_at_or_before_anchor_is_rejected() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        let mut s = external_settlement(&econ, "job-1", "work-1");
        s.payment_block_number = Some(100);
        let err = econ.append_settlement(s).unwrap_err();
        assert!(err.to_string().contains("not after payment-intent anchor"));
    }

    #[test]
    fn ledger_hash_chain_detects_tampering() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        let audit = econ.audit_ledger().unwrap();
        assert!(audit.valid);
        assert_eq!(audit.records, 2);
        assert_ne!(audit.head_hash, LEDGER_GENESIS_HASH);

        let path = econ.ledger_path();
        let raw = fs::read_to_string(&path).unwrap();
        let tampered = raw.replace("sha256:input", "sha256:evil!");
        fs::write(&path, tampered).unwrap();
        let err = econ.audit_ledger().unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn ledger_sequence_is_contiguous() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        let records = econ.records().unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].sequence(), 1);
        assert_eq!(records[1].sequence(), 2);
    }

    #[test]
    fn legacy_ledger_line_with_a_real_asset_still_deserializes() {
        // The exact shape older versions wrote, including a bare string asset.
        let line = legacy_settlement_line("USDC");
        let record: LedgerRecord = serde_json::from_str(&line).unwrap();
        match record {
            LedgerRecord::Settlement { settlement, .. } => {
                assert!(settlement.settlement_asset.is_real());
                assert_eq!(settlement.settlement_asset.symbol(), "USDC");
            }
            _ => panic!("expected a settlement record"),
        }
    }

    #[test]
    fn legacy_ledger_line_with_an_ambiguous_asset_is_a_typed_error() {
        // No panic, and no silent upgrade to a real asset: the reader refuses
        // and the error names the symbol it could not classify.
        for ambiguous in ["USD", "USDC_BASE_XYZ"] {
            let line = legacy_settlement_line(ambiguous);
            let err = serde_json::from_str::<LedgerRecord>(&line).unwrap_err();
            let message = err.to_string();
            assert!(message.contains("refusing to guess"), "{message}");
            assert!(message.contains(ambiguous), "{message}");
        }
        // A ledger file carrying one is unreadable rather than miscounted.
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        fs::write(econ.ledger_path(), format!("{}\n", legacy_settlement_line("USD")))
            .unwrap();
        let err = econ.records().unwrap_err();
        assert!(err.to_string().contains("cannot be parsed"));
    }

    #[test]
    fn synthetic_settlement_asset_never_counts_as_paid_demand() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        let mut s = external_settlement(&econ, "job-1", "work-1");
        s.settlement_asset = SettlementAsset::classify_symbol("smUSD").unwrap();
        assert!(s.settlement_asset.is_synthetic());
        econ.append_settlement(s).unwrap();

        let summary = econ.revenue_summary().unwrap();
        assert_eq!(summary.external_paid_jobs, 0);
        assert_eq!(summary.paid_demand_musd_micros, 0);
        assert_eq!(summary.internal_or_simulated_jobs, 1);
        assert_eq!(econ.rv_status(1_700_000_100).unwrap().level, "PRE-RV0");
    }

    #[test]
    fn revenue_ledger_record_rejects_an_extra_unknown_key() {
        // Regression test for the audit finding that serde dropped unknown
        // keys, leaving them invisible to a hash that commits the
        // re-serialized record.
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        let path = econ.ledger_path();
        let raw = fs::read_to_string(&path).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(raw.lines().last().unwrap()).unwrap();
        value["free_payload"] = serde_json::json!({"anything": 1});
        fs::write(&path, format!("{}\n", value)).unwrap();
        let err = econ.records().unwrap_err();
        assert!(err.to_string().contains("cannot be parsed"));
    }

    #[test]
    fn a_closed_ledger_still_audits_clean() {
        let dir = tempdir().unwrap();
        let econ = LocalEconomy::open(dir.path()).unwrap();
        econ.append_job(job(false)).unwrap();
        econ.append_work(work()).unwrap();
        prepare_external(&econ, "job-1");
        econ.append_settlement(external_settlement(&econ, "job-1", "work-1"))
            .unwrap();
        let audit = econ.audit_ledger().unwrap();
        assert!(audit.valid);
        assert_eq!(audit.records, 4);
    }

    fn legacy_settlement_line(asset: &str) -> String {
        serde_json::json!({
            "kind": "settlement",
            "sequence": 1,
            "recorded_at_unix": 1_700_000_012,
            "prev_hash": LEDGER_GENESIS_HASH,
            "record_hash": "0xlegacy",
            "settlement": {
                "schema_version": 1,
                "settlement_id": "settle-legacy",
                "job_id": "job-1",
                "work_receipt_id": "work-1",
                "settled_at_unix": 1_700_000_012,
                "mode": "simulated",
                "settlement_asset": asset,
                "settled_amount_micros": 2_000_000,
                "usd_equivalent_micros": 2_000_000,
                "payment_intent_id": null,
                "payment_block_number": null,
                "payment_proof_hash": null,
                "payment_proof_verified": false,
                "external_paid": false,
                "internal_work": false,
            },
        })
        .to_string()
    }
}
