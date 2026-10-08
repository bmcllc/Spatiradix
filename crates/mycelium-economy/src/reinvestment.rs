//! Adaptive reinvestment controller.
//!
//! Only verified net external value can fund autonomous reinvestment. MYC
//! emission, internal transfers and bot service spend are excluded by
//! construction because the controller reads verified external-value receipts
//! through [`crate::verified_view::VerifiedEconomyView`] and never from a
//! ledger record's own `proof_verified` flag.
//!
//! The gate that matters is `commit_job`: it is the one that turns a number
//! into real spending authority, so it is driven by the view. With no pinned
//! provider the view is [`crate::verified_view::TrustMode::Unverified`], it hands
//! out no [`crate::verified_view::VerifiedNev`], and the budget is zero — a
//! ledger that claims a hundred mUSD of verified value buys nothing.

use crate::{
    autonomy::{AutonomousEconomy, EconomicAgentManifest, JobIntent},
    boundary::ControlledAddressRegistry,
    now_unix, stable_id,
    verified_view::{TrustMode, VerifiedEconomyView},
    EconomyError, Result, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

pub const REINVESTMENT_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Reinvestment ledger file name; also the append lock name and the head
/// anchor's ledger identifier.
pub const REINVESTMENT_LEDGER_FILE: &str = "reinvestment-ledger.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinvestmentSignals {
    /// 0 = healthy, 1 = severe worker-income/retention stress.
    pub worker_risk: f64,
    /// 0 = deep/healthy, 1 = severe liquidity stress.
    pub liquidity_risk: f64,
    /// 0 = clean, 1 = severe fraud/anomaly stress.
    pub fraud_risk: f64,
    /// 0 = healthy finality, 1 = severe partition/finality stress.
    pub partition_risk: f64,
    /// 0 = strong useful demand, 1 = no useful demand.
    pub demand_risk: f64,
    /// 0 = no thermal budget, 1 = full thermal headroom.
    pub thermal_headroom: f64,
}

impl Default for ReinvestmentSignals {
    fn default() -> Self {
        Self {
            worker_risk: 0.0,
            liquidity_risk: 0.0,
            fraud_risk: 0.0,
            partition_risk: 0.0,
            demand_risk: 0.0,
            thermal_headroom: 1.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinvestmentPolicy {
    /// Nominal fraction of investable verified NEV, in basis points.
    pub base_rate_bps: u64,
    /// Verified NEV that is never automatically committed.
    pub reserve_floor_musd_micros: u64,
    /// Maximum new commitments during one UTC day.
    pub max_daily_commitment_musd_micros: u64,
    /// No automatic jobs when thermal headroom is below this value.
    pub min_thermal_headroom: f64,
}

impl Default for ReinvestmentPolicy {
    fn default() -> Self {
        Self {
            base_rate_bps: 2_000, // 20%
            reserve_floor_musd_micros: 10_000_000, // 10 mUSD
            max_daily_commitment_musd_micros: 100_000_000, // 100 mUSD/day
            min_thermal_headroom: 0.20,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinvestmentDecision {
    pub schema_version: u32,
    pub decided_at_unix: u64,
    /// Chain-attested net external value. Zero unless the reporting view ran in
    /// [`TrustMode::ProviderPinned`]; what the ledger claims when nothing is
    /// attested is reported under `unattested_nev_musd_micros` instead of being
    /// folded into this field.
    pub verified_nev_musd_micros: i64,
    pub reserve_floor_musd_micros: u64,
    pub investable_nev_musd_micros: u64,
    pub prior_commitments_musd_micros: u64,
    pub today_commitments_musd_micros: u64,
    pub base_rate_bps: u64,
    pub effective_rate_bps: u64,
    pub risk_brake: f64,
    pub demand_brake: f64,
    pub worker_brake: f64,
    pub thermal_brake: f64,
    pub target_cumulative_reinvestment_musd_micros: u64,
    /// The budget `commit_job` enforces. Zero whenever the NEV behind it is not
    /// chain-attested.
    pub available_new_commitment_musd_micros: u64,
    pub autonomy_head_hash: String,
    pub reason: String,
    /// Which derivation produced `verified_nev_musd_micros`.
    #[serde(default)]
    pub trust_mode: TrustMode,
    /// What the ledger claims. NOT investable and NOT verified.
    #[serde(default)]
    pub unattested_nev_musd_micros: i64,
    /// Endpoint the chain facts came from, in pinned mode.
    #[serde(default)]
    pub nev_provider: String,
    #[serde(default)]
    pub attestation_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinvestmentCommitment {
    pub schema_version: u32,
    pub commitment_id: String,
    pub created_at_unix: u64,
    pub agent_id: String,
    pub opportunity_id: String,
    pub job_intent_id: String,
    pub amount_musd_micros: u64,
    pub autonomy_head_hash: String,
    pub effective_rate_bps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReinvestmentStatus {
    pub commitments: u64,
    pub committed_total_musd: f64,
    pub committed_today_musd: f64,
    pub ledger_valid: bool,
    pub head_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReinvestmentRecord {
    sequence: u64,
    recorded_at_unix: u64,
    prev_hash: String,
    record_hash: String,
    commitment: ReinvestmentCommitment,
}

impl ReinvestmentRecord {
    fn computed_hash(&self) -> Result<String> {
        let mut copy = self.clone();
        copy.record_hash.clear();
        Ok(blake3::hash(&serde_json::to_vec(&copy)?)
            .to_hex()
            .to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ReinvestmentController {
    root: PathBuf,
}

impl ReinvestmentController {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        crate::durability::ensure_private_dir(&root)?;
        Ok(Self { root })
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.root.join(REINVESTMENT_LEDGER_FILE)
    }

    /// Head anchor for the reinvestment ledger, or `None` on a ledger written
    /// before anchoring existed.
    pub fn head_anchor(&self) -> Result<Option<crate::durability::HeadAnchor>> {
        crate::durability::read_head_anchor(&self.root, REINVESTMENT_LEDGER_FILE)
    }

    /// Cross-bind this ledger's autonomy head references against the autonomy
    /// ledger they name.
    ///
    /// [`ReinvestmentCommitment::autonomy_head_hash`] already cross-binds the
    /// autonomy chain head into each commitment, which makes an autonomy tail
    /// that was rolled back after the fact observable: a commitment names a
    /// head that the autonomy ledger no longer reaches.
    ///
    /// This checks exactly that, against the autonomy ledger as it exists now,
    /// and it is deliberately read-only so it can run on any status path. It
    /// does not make the pair tamper-proof — both ledgers are writable by the
    /// same principal, so a same-principal attacker rewrites both anchors
    /// instead. It binds two ledgers that were previously free to drift.
    pub fn verify_autonomy_head_binding(
        &self,
        autonomy: &AutonomousEconomy,
    ) -> Result<()> {
        let commitments = self.read_records()?;
        // Read the autonomy ledger once: `records()` re-verifies the chain and
        // takes the autonomy lock, so calling it per commitment would make this
        // quadratic in a way that only shows up under load.
        let autonomy_records = autonomy.records()?;
        let autonomy_head = autonomy_records
            .last()
            .map(|r| r.record_hash.clone())
            .unwrap_or_else(|| crate::autonomy::AUTONOMY_GENESIS_HASH.to_string());
        let known: BTreeSet<&str> = autonomy_records
            .iter()
            .map(|r| r.record_hash.as_str())
            .collect();
        for record in &commitments {
            let observed = &record.commitment.autonomy_head_hash;
            // The autonomy head only ever moves forward, so an older commitment
            // may legitimately name an older head.
            if known.contains(observed.as_str()) {
                continue;
            }
            return Err(EconomyError::Invalid(format!(
                "reinvestment commitment {} references autonomy head {} which the autonomy \
                 ledger no longer contains (current head {}); the autonomy ledger was \
                 rewritten or truncated after this commitment was recorded",
                record.commitment.commitment_id, observed, autonomy_head
            )));
        }
        Ok(())
    }

    /// The decision, computed from the offline view.
    ///
    /// There is no registry and no provider here, so the view cannot attest
    /// anything: `verified_nev_musd_micros` and
    /// `available_new_commitment_musd_micros` are zero and the reason says so.
    /// This is the safe default, not a degraded mode — an operator who wants an
    /// actionable number calls [`Self::decide_from_view`].
    pub fn decide(
        &self,
        autonomy: &AutonomousEconomy,
        signals: &ReinvestmentSignals,
        policy: &ReinvestmentPolicy,
        now: u64,
    ) -> Result<ReinvestmentDecision> {
        let registry = ControlledAddressRegistry::new();
        let view = VerifiedEconomyView::unverified(autonomy, &registry);
        self.decide_from_view(&view, signals, policy, now)
    }

    /// The authoritative decision. The investment base is a
    /// [`crate::verified_view::VerifiedNev`], which only exists in
    /// [`TrustMode::ProviderPinned`]; in any other mode the base is zero by
    /// construction rather than by a check someone can forget to write.
    pub fn decide_from_view(
        &self,
        view: &VerifiedEconomyView<'_>,
        signals: &ReinvestmentSignals,
        policy: &ReinvestmentPolicy,
        now: u64,
    ) -> Result<ReinvestmentDecision> {
        validate_signals(signals)?;
        validate_policy(policy)?;

        let claims = view.unattested_nev()?;
        let verified = if view.trust_mode().can_attest() {
            Some(view.verified_nev()?)
        } else {
            None
        };
        let nev_i64 = verified
            .as_ref()
            .map(|v| v.nev_musd_micros())
            .unwrap_or(0);
        let provider = verified
            .as_ref()
            .map(|v| v.provider().to_string())
            .unwrap_or_default();

        let investable = if nev_i64 > 0 {
            (nev_i64 as u64).saturating_sub(policy.reserve_floor_musd_micros)
        } else {
            0
        };

        let records = self.records()?;
        let prior_commitments = records.iter().fold(0u64, |acc, r| {
            acc.saturating_add(r.commitment.amount_musd_micros)
        });
        let day_start = (now / 86_400) * 86_400;
        let day_end = day_start.saturating_add(86_400);
        let today_commitments = records
            .iter()
            .filter(|r| {
                r.commitment.created_at_unix >= day_start
                    && r.commitment.created_at_unix < day_end
            })
            .fold(0u64, |acc, r| {
                acc.saturating_add(r.commitment.amount_musd_micros)
            });

        // Safety risks are fail-conservative. The largest of liquidity,
        // fraud and partition risk becomes the common safety brake.
        let strongest_safety_risk = signals
            .liquidity_risk
            .max(signals.fraud_risk)
            .max(signals.partition_risk);
        let risk_brake = (1.0 - strongest_safety_risk).clamp(0.0, 1.0);
        let demand_brake = (1.0 - signals.demand_risk).clamp(0.0, 1.0);
        let worker_brake = (1.0 - 0.5 * signals.worker_risk).clamp(0.0, 1.0);
        let thermal_brake = if signals.thermal_headroom < policy.min_thermal_headroom {
            0.0
        } else {
            signals.thermal_headroom.clamp(0.0, 1.0)
        };

        let combined_brake = risk_brake
            .min(demand_brake)
            .min(worker_brake)
            .min(thermal_brake);
        let effective_rate_bps =
            ((policy.base_rate_bps as f64) * combined_brake).floor() as u64;

        let target = ((investable as u128) * (effective_rate_bps as u128)
            / 10_000u128)
            .min(u64::MAX as u128) as u64;
        let cumulative_remaining = target.saturating_sub(prior_commitments);
        let daily_remaining = policy
            .max_daily_commitment_musd_micros
            .saturating_sub(today_commitments);
        let available = cumulative_remaining.min(daily_remaining);

        let autonomy_head_hash = view
            .autonomy()
            .records()?
            .last()
            .map(|r| r.record_hash.clone())
            .unwrap_or_else(|| crate::autonomy::AUTONOMY_GENESIS_HASH.to_string());

        let unattested = claims.claimed_net_external_value_musd_micros;
        let reason = if !view.trust_mode().can_attest() {
            format!(
                "no chain-attested verified net external value: this decision ran in \
                 TrustMode={}, so the ledger's claim of {} mUSD is not investable. \
                 Pin a chain provider out-of-band to obtain an attested budget.",
                view.trust_mode(),
                unattested as f64 / 1_000_000.0
            )
        } else if nev_i64 <= 0 {
            format!(
                "no positive verified net external value; the pinned provider \
                 attributed none of the ledger's receipts"
            )
        } else if investable == 0 {
            "verified NEV does not exceed reserve floor".to_string()
        } else if thermal_brake == 0.0 {
            "thermal headroom below reinvestment floor".to_string()
        } else if risk_brake == 0.0 {
            "safety risk brake halted reinvestment".to_string()
        } else if demand_brake == 0.0 {
            "no useful demand for reinvestment".to_string()
        } else if available == 0 {
            "reinvestment target already committed or daily cap reached".to_string()
        } else {
            "verified NEV permits bounded adaptive reinvestment".to_string()
        };

        Ok(ReinvestmentDecision {
            schema_version: SCHEMA_VERSION,
            decided_at_unix: now,
            verified_nev_musd_micros: nev_i64,
            reserve_floor_musd_micros: policy.reserve_floor_musd_micros,
            investable_nev_musd_micros: investable,
            prior_commitments_musd_micros: prior_commitments,
            today_commitments_musd_micros: today_commitments,
            base_rate_bps: policy.base_rate_bps,
            effective_rate_bps,
            risk_brake,
            demand_brake,
            worker_brake,
            thermal_brake,
            target_cumulative_reinvestment_musd_micros: target,
            available_new_commitment_musd_micros: available,
            autonomy_head_hash,
            reason,
            trust_mode: view.trust_mode(),
            unattested_nev_musd_micros: unattested,
            nev_provider: provider,
            attestation_note: claims.note,
        })
    }

    /// The spending gate, on the offline view: always refused.
    ///
    /// This is the one function that turns a number into real spending
    /// authority, so it refuses rather than estimating. An operator who pinned a
    /// provider calls [`Self::commit_job_from_view`].
    pub fn commit_job(
        &self,
        autonomy: &AutonomousEconomy,
        agent: &EconomicAgentManifest,
        job: &JobIntent,
        signals: &ReinvestmentSignals,
        policy: &ReinvestmentPolicy,
        now: u64,
    ) -> Result<ReinvestmentCommitment> {
        let registry = ControlledAddressRegistry::new();
        let view = VerifiedEconomyView::unverified(autonomy, &registry);
        self.commit_job_from_view(&view, agent, job, signals, policy, now)
    }

    /// The authoritative spending gate. The budget it enforces comes from the
    /// view, so a ledger whose receipts do not survive re-derivation and a chain
    /// read cannot raise `available_new_commitment_musd_micros` at all.
    pub fn commit_job_from_view(
        &self,
        view: &VerifiedEconomyView<'_>,
        agent: &EconomicAgentManifest,
        job: &JobIntent,
        signals: &ReinvestmentSignals,
        policy: &ReinvestmentPolicy,
        now: u64,
    ) -> Result<ReinvestmentCommitment> {
        if !agent.enabled {
            return Err(EconomyError::Invalid(
                "cannot reinvest into a disabled agent".into(),
            ));
        }
        if agent.agent_id != job.agent_id {
            return Err(EconomyError::Invalid(
                "reinvestment agent/job identity mismatch".into(),
            ));
        }
        if job.max_cost_musd_micros == 0 {
            return Err(EconomyError::Invalid(
                "reinvestment job cost must be > 0".into(),
            ));
        }
        if job.max_cost_musd_micros > agent.max_job_cost_musd_micros {
            return Err(EconomyError::Invalid(
                "reinvestment job exceeds agent per-job limit".into(),
            ));
        }
        if !agent.allowed_job_types.contains(&job.job_type) {
            return Err(EconomyError::Invalid(
                "reinvestment job type not allowed for agent".into(),
            ));
        }

        if !view
            .autonomy()
            .job_intents()?
            .iter()
            .any(|j| j.job_intent_id == job.job_intent_id)
        {
            return Err(EconomyError::Invalid(
                "reinvestment can fund only a recorded autonomous JobIntent".into(),
            ));
        }
        if self
            .records()?
            .iter()
            .any(|r| r.commitment.job_intent_id == job.job_intent_id)
        {
            return Err(EconomyError::Conflict(
                "job intent already has a reinvestment commitment".into(),
            ));
        }

        // Refuse before the arithmetic when nothing behind the budget is
        // attested, so the message names the real reason instead of reporting a
        // budget of zero.
        if !view.trust_mode().can_attest() {
            return Err(EconomyError::Invalid(format!(
                "refusing to commit {} mUSD of reinvestment: this view is \
                 TrustMode={} and can attest no verified net external value, so \
                 there is no budget to spend. Pin a chain provider out-of-band \
                 (`payment-policy-pin-provider {}`) and re-run.",
                job.max_cost_musd_micros as f64 / 1_000_000.0,
                view.trust_mode(),
                crate::chain_provider::DEFAULT_PROVIDER_SOCKET_URI
            )));
        }

        let decision = self.decide_from_view(view, signals, policy, now)?;
        if job.max_cost_musd_micros > decision.available_new_commitment_musd_micros {
            return Err(EconomyError::Invalid(format!(
                "insufficient verified reinvestment budget: job={} available={}. {}",
                job.max_cost_musd_micros,
                decision.available_new_commitment_musd_micros,
                decision.attestation_note
            )));
        }

        let commitment = ReinvestmentCommitment {
            schema_version: SCHEMA_VERSION,
            commitment_id: stable_id(
                "reinvest",
                &[
                    &job.job_intent_id,
                    &job.agent_id,
                    &decision.autonomy_head_hash,
                    &now.to_string(),
                ],
            ),
            created_at_unix: now,
            agent_id: job.agent_id.clone(),
            opportunity_id: job.opportunity_id.clone(),
            job_intent_id: job.job_intent_id.clone(),
            amount_musd_micros: job.max_cost_musd_micros,
            autonomy_head_hash: decision.autonomy_head_hash,
            effective_rate_bps: decision.effective_rate_bps,
        };
        self.append(commitment.clone())?;
        Ok(commitment)
    }

    pub fn status(&self, now: u64) -> Result<ReinvestmentStatus> {
        let records = self.records()?;
        let day_start = (now / 86_400) * 86_400;
        let day_end = day_start.saturating_add(86_400);
        let total = records.iter().fold(0u64, |acc, r| {
            acc.saturating_add(r.commitment.amount_musd_micros)
        });
        let today = records
            .iter()
            .filter(|r| {
                r.commitment.created_at_unix >= day_start
                    && r.commitment.created_at_unix < day_end
            })
            .fold(0u64, |acc, r| {
                acc.saturating_add(r.commitment.amount_musd_micros)
            });
        Ok(ReinvestmentStatus {
            commitments: records.len() as u64,
            committed_total_musd: total as f64 / 1_000_000.0,
            committed_today_musd: today as f64 / 1_000_000.0,
            ledger_valid: true,
            head_hash: records
                .last()
                .map(|r| r.record_hash.clone())
                .unwrap_or_else(|| REINVESTMENT_GENESIS_HASH.to_string()),
        })
    }

    fn records(&self) -> Result<Vec<ReinvestmentRecord>> {
        // The lock covers the whole read: the head anchor is a second file, and
        // reading both outside one critical section can compare them at
        // different instants and return a phantom "truncated" verdict. The
        // append path uses `read_records` — it already holds this lock, which is
        // not reentrant.
        let _lock = crate::durability::LedgerLock::acquire_timeout(
            &self.root,
            REINVESTMENT_LEDGER_FILE,
            crate::durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery =
            crate::durability::recover_torn_tail(&self.ledger_path(), "reinvestment ledger")?;
        let records = self.read_records()?;
        self.verify_head(&records)?;
        if let Some(torn) = recovery {
            let head = records
                .last()
                .map_or(REINVESTMENT_GENESIS_HASH, |r| r.record_hash.as_str());
            crate::durability::store_head_anchor(
                &self.root,
                REINVESTMENT_LEDGER_FILE,
                records.last().map_or(0, |r| r.sequence),
                head,
                Some(torn.report(now_unix())),
            )?;
        }
        Ok(records)
    }

    /// Chain-verified head against the out-of-band anchor. Detects accidental
    /// truncation, corruption and a ledger swapped for an older copy; does not
    /// defend against a same-principal attacker who rewrites both files.
    fn verify_head(&self, records: &[ReinvestmentRecord]) -> Result<()> {
        let anchor = crate::durability::read_head_anchor(&self.root, REINVESTMENT_LEDGER_FILE)?;
        let head = records
            .last()
            .map_or(REINVESTMENT_GENESIS_HASH, |r| r.record_hash.as_str());
        let hash_at = |seq: u64| {
            records
                .iter()
                .find(|r| r.sequence == seq)
                .map(|r| r.record_hash.clone())
        };
        crate::durability::verify_head_anchor(
            anchor.as_ref(),
            records.last().map_or(0, |r| r.sequence),
            head,
            &hash_at,
            "reinvestment ledger",
        )
    }

    fn read_records(&self) -> Result<Vec<ReinvestmentRecord>> {
        let path = self.ledger_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(path)?;
        let mut out = Vec::new();
        let mut expected_seq = 1u64;
        let mut expected_prev = REINVESTMENT_GENESIS_HASH.to_string();

        for (idx, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: ReinvestmentRecord = serde_json::from_str(&line).map_err(|e| {
                EconomyError::Invalid(format!(
                    "reinvestment ledger line {} cannot be parsed: {}",
                    idx + 1,
                    e
                ))
            })?;
            if record.sequence != expected_seq {
                return Err(EconomyError::Invalid(format!(
                    "reinvestment sequence mismatch: expected {}, got {}",
                    expected_seq, record.sequence
                )));
            }
            if record.prev_hash != expected_prev {
                return Err(EconomyError::Invalid(format!(
                    "reinvestment hash-chain break at sequence {}",
                    record.sequence
                )));
            }
            let computed = record.computed_hash()?;
            if record.record_hash != computed {
                return Err(EconomyError::Invalid(format!(
                    "reinvestment hash mismatch at sequence {}",
                    record.sequence
                )));
            }
            expected_prev = record.record_hash.clone();
            expected_seq += 1;
            out.push(record);
        }
        Ok(out)
    }

    fn append(&self, commitment: ReinvestmentCommitment) -> Result<()> {
        // Lock across read-tail → derive → write, not just the write.
        let _lock = crate::durability::LedgerLock::acquire_timeout(
            &self.root,
            REINVESTMENT_LEDGER_FILE,
            crate::durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery = crate::durability::recover_torn_tail(
            &self.ledger_path(),
            "reinvestment ledger",
        )?;

        let existing = self.read_records()?;
        let mut record = ReinvestmentRecord {
            sequence: existing.last().map(|r| r.sequence + 1).unwrap_or(1),
            recorded_at_unix: now_unix(),
            prev_hash: existing
                .last()
                .map(|r| r.record_hash.clone())
                .unwrap_or_else(|| REINVESTMENT_GENESIS_HASH.to_string()),
            record_hash: String::new(),
            commitment,
        };
        record.record_hash = record.computed_hash()?;

        // One buffer, one `write_all`, one `sync_data`.
        let line = serde_json::to_vec(&record)?;
        crate::durability::append_line(&self.ledger_path(), &line)?;
        crate::durability::store_head_anchor(
            &self.root,
            REINVESTMENT_LEDGER_FILE,
            record.sequence,
            &record.record_hash,
            recovery.map(|t| t.report(now_unix())),
        )
    }
}

fn validate_signals(s: &ReinvestmentSignals) -> Result<()> {
    for (name, value) in [
        ("worker_risk", s.worker_risk),
        ("liquidity_risk", s.liquidity_risk),
        ("fraud_risk", s.fraud_risk),
        ("partition_risk", s.partition_risk),
        ("demand_risk", s.demand_risk),
        ("thermal_headroom", s.thermal_headroom),
    ] {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(EconomyError::Invalid(format!(
                "reinvestment signal {name} must be in [0,1]"
            )));
        }
    }
    Ok(())
}

fn validate_policy(p: &ReinvestmentPolicy) -> Result<()> {
    if p.base_rate_bps > 10_000 {
        return Err(EconomyError::Invalid(
            "reinvestment base_rate_bps must be <= 10000".into(),
        ));
    }
    if p.max_daily_commitment_musd_micros == 0 {
        return Err(EconomyError::Invalid(
            "reinvestment daily cap must be > 0".into(),
        ));
    }
    if !p.min_thermal_headroom.is_finite()
        || !(0.0..=1.0).contains(&p.min_thermal_headroom)
    {
        return Err(EconomyError::Invalid(
            "reinvestment min_thermal_headroom must be in [0,1]".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        autonomy::{
            AgentClass, EconomicAgentManifest, EconomicPolicy,
            ExternalValueClass, ExternalValueReceipt, OpportunityCandidate,
            RiskProfile,
        },
        base_usdc::{BaseUsdcVerifier, BASE_CHAIN_ID, BASE_USDC},
        boundary::{BoundaryEvidence, RealAsset},
        chain_provider::{resolve, PinnedChainProvider},
        rpc_test_server::FakeRpcSocket,
        JobType,
    };
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    const PAYOUT: &str = "0xe83331104f5f3c41e49abc46c810f9d71133e48c";
    const COUNTERPARTY: &str = "0x1234567890abcdef1234567890abcdef12345678";

    fn tx_hash() -> String {
        format!("0x{}", "11".repeat(32))
    }

    fn block_hash() -> String {
        format!("0x{}", "22".repeat(32))
    }

    fn registry() -> ControlledAddressRegistry {
        ControlledAddressRegistry::new()
            .with_address(PAYOUT)
            .unwrap()
    }

    /// A pinned provider that actually serves the transfer the evidence cites.
    /// `FakeRpcSocket` binds a real owner-only Unix socket, so the kernel
    /// identity check runs for real rather than being stubbed.
    fn serving_socket(dir: &std::path::Path, amount_raw: u64) -> FakeRpcSocket {
        let log = serde_json::json!({
            "address": BASE_USDC,
            "topics": [
                crate::base_usdc::ERC20_TRANSFER_TOPIC,
                format!("0x{:0>64}", COUNTERPARTY.trim_start_matches("0x")),
                format!("0x{:0>64}", PAYOUT.trim_start_matches("0x")),
            ],
            "data": format!("0x{amount:064x}", amount = amount_raw),
            "logIndex": "0x1",
        });
        FakeRpcSocket::with_responses(
            dir.join("verifier.sock"),
            vec![
                ("eth_chainId", serde_json::json!("0x2105")),
                ("eth_blockNumber", serde_json::json!("0x6e")),
                ("eth_getTransactionReceipt", serde_json::json!({
                    "status": "0x1",
                    "blockNumber": "0x65",
                    "blockHash": block_hash(),
                    "transactionHash": tx_hash(),
                    "logs": [log],
                })),
                ("eth_getBlockByNumber", serde_json::json!({
                    "hash": block_hash(),
                    "timestamp": "0x6553f0d0",
                })),
            ],
        )
    }

    /// An owned pinned view. The socket has to outlive the verifier that talks to
    /// it, and the registry and verifier have to outlive the view, so they live
    /// here rather than in a function that hands a borrow back. The authority
    /// lives here too: since P4b the pinned mode requires a validated policy,
    /// and the pin's temp directory has to outlive the validated value.
    struct Pinned<'a> {
        _socket: FakeRpcSocket,
        registry: ControlledAddressRegistry,
        verifier: BaseUsdcVerifier,
        _auth: crate::receipt_auth::testkit::AuthFixture,
        policy: crate::policy_auth::ValidatedOutcomePolicy,
        autonomy: &'a AutonomousEconomy,
    }

    impl<'a> Pinned<'a> {
        fn view(&'a self) -> VerifiedEconomyView<'a> {
            VerifiedEconomyView::provider_pinned(
                self.autonomy,
                &self.registry,
                &self.verifier,
                &self.policy,
            )
            .unwrap()
        }
    }

    /// Books the given net value as chain-attested: evidence recorded, crossing
    /// derived against the operator's registry, receipt booked against it, and a
    /// provider that will re-confirm the same transfer on read.
    fn pin_attested_inflow<'a>(
        dir: &std::path::Path,
        autonomy: &'a AutonomousEconomy,
        gross: u64,
        cost: u64,
    ) -> Pinned<'a> {
        let registry = registry();
        let evidence = BoundaryEvidence {
            chain_id: BASE_CHAIN_ID,
            asset: RealAsset::base_usdc(),
            from_address: COUNTERPARTY.into(),
            to_address: PAYOUT.into(),
            amount_raw: gross,
            tx_hash: tx_hash(),
            block_hash: block_hash(),
        };
        let socket = serving_socket(dir, gross);
        let provider =
            PinnedChainProvider::unix_socket(socket.path(), Some(socket.uid()))
                .unwrap();
        let verifier =
            BaseUsdcVerifier::from_resolved(&resolve(None, Some(&provider)).unwrap(), 2)
                .unwrap();
        // P4b: an authority scoped to this very socket, because the provider
        // identity digest is part of the signed policy payload.
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        // The write-time proof comes from the same chain read the reader will
        // make, so what is booked is what will be re-derived.
        let crossing = autonomy
            .record_boundary_crossing(&evidence, &registry)
            .unwrap()
            .with_verified_proof(
                verifier
                    .verify_transfer(&tx_hash(), PAYOUT, gross)
                    .unwrap(),
            )
            .unwrap();
        let receipt = ExternalValueReceipt {
            schema_version: SCHEMA_VERSION,
            source_id: "source".into(),
            agent_id: "s1".into(),
            opportunity_id: "opp".into(),
            value_class: ExternalValueClass::ExternalTradingPnl,
            network: "base".into(),
            asset: "USDC".into(),
            gross_inflow_musd_micros: gross,
            external_cost_musd_micros: cost,
            net_external_value_musd_micros: gross as i64 - cost as i64,
            proof_hash: tx_hash(),
            proof_verified: true,
            realized_at_unix: 1_700_000_200,
            verifier_id: "test".into(),
        };
        // P4b: the delegated verifier signs the same bytes it just read, and the
        // signature is recorded beside the receipt. Without this the view has
        // nothing to verify and the budget stays at zero — which is the point,
        // not an inconvenience.
        let attestation = auth
            .verifier
            .attest(&policy, &receipt, &evidence)
            .unwrap();
        autonomy.record_receipt_attestation(&attestation).unwrap();
        autonomy
            .record_external_value_with_crossing(receipt, &crossing)
            .unwrap();
        Pinned {
            _socket: socket,
            registry,
            verifier,
            _auth: auth,
            policy,
            autonomy,
        }
    }

    fn agent() -> EconomicAgentManifest {
        EconomicAgentManifest {
            schema_version: SCHEMA_VERSION,
            agent_id: "s1".into(),
            public_key: "ed25519:s1".into(),
            agent_class: AgentClass::Finance,
            allowed_job_types: vec![JobType::Simulation],
            daily_budget_musd_micros: 100_000_000,
            max_job_cost_musd_micros: 2_000_000,
            risk_profile: RiskProfile::Conservative,
            enabled: true,
            created_at_unix: 1_700_000_000,
        }
    }

    fn setup(nev_micros: Option<(u64, u64)>) -> (
        tempfile::TempDir,
        AutonomousEconomy,
        JobIntent,
    ) {
        let dir = tempdir().unwrap();
        let autonomy = AutonomousEconomy::open(dir.path()).unwrap();
        autonomy.register_agent(agent()).unwrap();
        autonomy
            .submit_opportunity(OpportunityCandidate {
                schema_version: SCHEMA_VERSION,
                opportunity_id: "opp".into(),
                agent_id: "s1".into(),
                observed_at_unix: 1_700_000_000,
                expires_at_unix: 1_700_010_000,
                job_type: JobType::Simulation,
                input_hash: "blake3:input".into(),
                evidence_hash: "blake3:evidence".into(),
                expected_gross_musd_micros: 5_000_000,
                expected_external_cost_musd_micros: 500_000,
                estimated_job_cost_musd_micros: 500_000,
                risk_buffer_musd_micros: 500_000,
                metadata: BTreeMap::new(),
            })
            .unwrap();
        let out = autonomy
            .orchestrate("opp", &EconomicPolicy::default(), 1_700_000_100)
            .unwrap();
        let job = out.job_intent.unwrap();

        if let Some((gross, cost)) = nev_micros {
            autonomy
                .record_external_value(ExternalValueReceipt {
                    schema_version: SCHEMA_VERSION,
                    source_id: "source".into(),
                    agent_id: "s1".into(),
                    opportunity_id: "opp".into(),
                    value_class: ExternalValueClass::ExternalTradingPnl,
                    network: "base".into(),
                    asset: "USDC".into(),
                    gross_inflow_musd_micros: gross,
                    external_cost_musd_micros: cost,
                    net_external_value_musd_micros: gross as i64 - cost as i64,
                    proof_hash: "0xproof".into(),
                    proof_verified: true,
                    realized_at_unix: 1_700_000_200,
                    verifier_id: "test".into(),
                })
                .unwrap();
        }
        (dir, autonomy, job)
    }

    #[test]
    fn no_verified_nev_means_zero_reinvestment() {
        let (dir, autonomy, _job) = setup(None);
        let c = ReinvestmentController::open(dir.path()).unwrap();
        let d = c
            .decide(
                &autonomy,
                &ReinvestmentSignals::default(),
                &ReinvestmentPolicy::default(),
                1_700_000_300,
            )
            .unwrap();
        assert_eq!(d.available_new_commitment_musd_micros, 0);
        assert_eq!(d.verified_nev_musd_micros, 0);
    }

    #[test]
    fn verified_nev_can_fund_bounded_job() {
        let (dir, autonomy, job) = setup(None);
        // The base is chain-attested: a boundary crossing re-derived on read and
        // re-confirmed by a provider whose socket identity the kernel enforces.
        // Before P3 this test booked a receipt whose only claim to being real was
        // its own `proof_verified: true`; the arithmetic below is unchanged, but
        // the number behind it is no longer an assertion.
        let pinned = pin_attested_inflow(dir.path(), &autonomy, 100_000_000, 0);
        let view = pinned.view();
        let c = ReinvestmentController::open(dir.path()).unwrap();
        let policy = ReinvestmentPolicy::default();
        let d = c
            .decide_from_view(
                &view,
                &ReinvestmentSignals::default(),
                &policy,
                1_700_000_300,
            )
            .unwrap();
        assert_eq!(d.trust_mode, TrustMode::ProviderPinned);
        // (100 - 10 reserve) * 20% = 18 mUSD.
        assert_eq!(d.target_cumulative_reinvestment_musd_micros, 18_000_000);
        assert_eq!(d.available_new_commitment_musd_micros, 18_000_000);

        let commitment = c
            .commit_job_from_view(
                &view,
                &agent(),
                &job,
                &ReinvestmentSignals::default(),
                &policy,
                1_700_000_300,
            )
            .unwrap();
        assert_eq!(commitment.amount_musd_micros, 500_000);
        let after = c
            .decide_from_view(
                &view,
                &ReinvestmentSignals::default(),
                &policy,
                1_700_000_301,
            )
            .unwrap();
        assert_eq!(after.available_new_commitment_musd_micros, 17_500_000);

        // The same ledger read offline funds nothing, even though every byte of
        // it is genuine. That is the trust mode doing its job.
        let offline_registry = ControlledAddressRegistry::new();
        let offline =
            VerifiedEconomyView::unverified(&autonomy, &offline_registry);
        let offline_decision = c
            .decide_from_view(
                &offline,
                &ReinvestmentSignals::default(),
                &policy,
                1_700_000_300,
            )
            .unwrap();
        assert_eq!(offline_decision.verified_nev_musd_micros, 0);
        assert_eq!(offline_decision.available_new_commitment_musd_micros, 0);
        assert_eq!(offline_decision.trust_mode, TrustMode::Unverified);
    }

    #[test]
    fn partition_or_thermal_brake_can_halt_reinvestment() {
        let (dir, autonomy, _job) = setup(Some((100_000_000, 0)));
        let c = ReinvestmentController::open(dir.path()).unwrap();

        let mut signals = ReinvestmentSignals::default();
        signals.partition_risk = 1.0;
        let d = c
            .decide(
                &autonomy,
                &signals,
                &ReinvestmentPolicy::default(),
                1_700_000_300,
            )
            .unwrap();
        assert_eq!(d.effective_rate_bps, 0);
        assert_eq!(d.available_new_commitment_musd_micros, 0);

        let mut thermal = ReinvestmentSignals::default();
        thermal.thermal_headroom = 0.10;
        let d2 = c
            .decide(
                &autonomy,
                &thermal,
                &ReinvestmentPolicy::default(),
                1_700_000_300,
            )
            .unwrap();
        assert_eq!(d2.thermal_brake, 0.0);
        assert_eq!(d2.available_new_commitment_musd_micros, 0);
    }

    #[test]
    fn verified_loss_reduces_reinvestment_base() {
        let (dir, autonomy, _job) = setup(None);
        autonomy
            .record_external_value(ExternalValueReceipt {
                schema_version: SCHEMA_VERSION,
                source_id: "loss".into(),
                agent_id: "s1".into(),
                opportunity_id: "opp".into(),
                value_class: ExternalValueClass::ExternalTradingPnl,
                network: "base".into(),
                asset: "USDC".into(),
                gross_inflow_musd_micros: 0,
                external_cost_musd_micros: 80_000_000,
                net_external_value_musd_micros: -80_000_000,
                proof_hash: "0xloss".into(),
                proof_verified: true,
                realized_at_unix: 1_700_000_250,
                verifier_id: "test".into(),
            })
            .unwrap();

        let c = ReinvestmentController::open(dir.path()).unwrap();
        let policy = ReinvestmentPolicy::default();
        // P3 changed the honest answer here, and the change is deliberate. The
        // loss receipt cites no transaction, so the view cannot attest it, so it
        // is not in the base. Its old expectation (net 20, target 2) required
        // *both* receipts to be believed on their own `proof_verified: true`, and
        // the reason that was wrong is symmetric: a ledger that can also write a
        // gain would have been able to write this loss to shrink a budget, or
        // omit it to grow one, with no chain read anywhere.
        let registry = ControlledAddressRegistry::new();
        let d = c
            .decide_from_view(
                &VerifiedEconomyView::unverified(&autonomy, &registry),
                &ReinvestmentSignals::default(),
                &policy,
                1_700_000_300,
            )
            .unwrap();
        assert_eq!(d.trust_mode, TrustMode::Unverified);
        assert_eq!(d.verified_nev_musd_micros, 0);
        assert_eq!(d.target_cumulative_reinvestment_musd_micros, 0);
        assert_eq!(d.available_new_commitment_musd_micros, 0);
        // What the ledger claims is reported, so a downgraded value is visible
        // instead of looking like a zero. This loss cites "0xloss", which is not a
        // transaction, so it does not even re-derive into a claim: it is counted
        // as a receipt, explained in the note, and worth nothing. A loss citing a
        // real transaction would land in this field instead of vanishing.
        assert_eq!(d.unattested_nev_musd_micros, 0);
        assert!(d.attestation_note.contains("cites no transaction"), "{}", d.attestation_note);
        assert!(d.reason.contains("TrustMode=unverified"), "{}", d.reason);

        // A negative net on an inflow is not attestable today: the typed crossing
        // path admits inflows only, so a booked loss is always a claim. This is
        // a known limit, not a silent one.
        let pinned = pin_attested_inflow(dir.path(), &autonomy, 100_000_000, 0);
        let evidence = pinned.view().receipt_evidence().unwrap();
        let loss = evidence
            .iter()
            .find(|e| e.source_id == "loss")
            .expect("the loss receipt is still on the ledger");
        assert!(!loss.counted);
        assert_eq!(loss.offline_ok, false);
    }

    #[test]
    fn same_job_cannot_be_committed_twice() {
        let (dir, autonomy, job) = setup(None);
        // The first commit has to clear the real budget, which means the base
        // has to be chain-attested. Before P3 the first commit succeeded on the
        // strength of a stored boolean.
        let pinned = pin_attested_inflow(dir.path(), &autonomy, 100_000_000, 0);
        let view = pinned.view();
        let c = ReinvestmentController::open(dir.path()).unwrap();
        let policy = ReinvestmentPolicy::default();

        // First, while nothing is committed: the offline path has no budget and
        // says so, instead of reporting zero and looking like a spend cap.
        let registry = ControlledAddressRegistry::new();
        let offline = VerifiedEconomyView::unverified(&autonomy, &registry);
        let err = c
            .commit_job_from_view(
                &offline,
                &agent(),
                &job,
                &ReinvestmentSignals::default(),
                &policy,
                1_700_000_300,
            )
            .unwrap_err();
        assert!(err.to_string().contains("no budget to spend"), "{err}");

        // Then the pinned path commits, and the second attempt is still refused.
        c.commit_job_from_view(
            &view,
            &agent(),
            &job,
            &ReinvestmentSignals::default(),
            &policy,
            1_700_000_300,
        )
        .unwrap();
        let again = c
            .commit_job_from_view(
                &view,
                &agent(),
                &job,
                &ReinvestmentSignals::default(),
                &policy,
                1_700_000_301,
            )
            .unwrap_err();
        assert!(again.to_string().contains("already has"), "{again}");
    }
}
