//! Autonomous machine-to-machine economy for Mycelium.
//!
//! This layer deliberately separates internal bot/job activity from verified
//! external value. Internal circulation can be useful activity, but it is
//! never booked as external revenue.

use crate::{
    boundary::{
        BoundaryCrossing, BoundaryEvidence, ControlledAddressRegistry,
        NevSign, SettlementAsset,
    },
    now_unix, stable_id, EconomyError, JobRequest, JobType, Result,
    receipt_auth::{
        AuthenticatedExternalValueReceipt, ATTESTATION_LEDGER_FILE,
    },
    SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

pub const AUTONOMY_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Autonomy ledger file name; also the append lock name and the head
/// anchor's ledger identifier.
pub const AUTONOMY_LEDGER_FILE: &str = "autonomous-ledger.jsonl";

/// Public genesis anchor of the P4b attestation ledger. A constant, exactly like
/// the autonomy ledger's: it binds the *chain*, it is not a secret, and it does
/// not authenticate anything. Authenticity is the signature's job.
pub const ATTESTATION_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// One line of the attestation ledger.
///
/// Same shape and same hashing rule as [`AutonomyRecord`]: the hash is
/// committed over the record with an empty `record_hash`, so it is a chain, not
/// a checksum of the final bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRecord {
    pub sequence: u64,
    pub recorded_at_unix: u64,
    pub prev_hash: String,
    pub record_hash: String,
    pub attestation: AuthenticatedExternalValueReceipt,
}

impl AttestationRecord {
    fn computed_hash(&self) -> Result<String> {
        let mut copy = self.clone();
        copy.record_hash.clear();
        Ok(blake3::hash(&serde_json::to_vec(&copy)?)
            .to_hex()
            .to_string())
    }
}

/// Chain-verifies the attestation ledger file. A missing file is an empty
/// ledger, which is the legacy shape; a present but broken one is an error, so a
/// corrupted attestation file can never degrade into "no attestations".
fn read_attestation_file(path: &Path) -> Result<Vec<AttestationRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(path)?;
    let mut out = Vec::new();
    let mut expected_seq = 1u64;
    let mut expected_prev = ATTESTATION_GENESIS_HASH.to_string();
    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: AttestationRecord = serde_json::from_str(&line).map_err(|e| {
            EconomyError::Invalid(format!(
                "receipt attestation ledger line {} cannot be parsed: {}",
                idx + 1,
                e
            ))
        })?;
        if record.sequence != expected_seq {
            return Err(EconomyError::Invalid(format!(
                "receipt attestation ledger sequence mismatch: expected {}, got {}",
                expected_seq, record.sequence
            )));
        }
        if record.prev_hash != expected_prev {
            return Err(EconomyError::Invalid(format!(
                "receipt attestation ledger hash-chain break at sequence {}",
                record.sequence
            )));
        }
        let computed = record.computed_hash()?;
        if record.record_hash != computed {
            return Err(EconomyError::Invalid(format!(
                "receipt attestation ledger hash mismatch at sequence {}",
                record.sequence
            )));
        }
        expected_prev = record.record_hash.clone();
        expected_seq += 1;
        out.push(record);
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentClass {
    Finance,
    Research,
    Compute,
    Storage,
    MarketMaker,
    Solver,
    Validator,
    Data,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RiskProfile {
    Conservative,
    Balanced,
    Experimental,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicAgentManifest {
    pub schema_version: u32,
    pub agent_id: String,
    pub public_key: String,
    pub agent_class: AgentClass,
    pub allowed_job_types: Vec<JobType>,
    pub daily_budget_musd_micros: u64,
    pub max_job_cost_musd_micros: u64,
    pub risk_profile: RiskProfile,
    pub enabled: bool,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpportunityCandidate {
    pub schema_version: u32,
    pub opportunity_id: String,
    pub agent_id: String,
    pub observed_at_unix: u64,
    pub expires_at_unix: u64,
    pub job_type: JobType,
    pub input_hash: String,
    pub evidence_hash: String,
    pub expected_gross_musd_micros: u64,
    pub expected_external_cost_musd_micros: u64,
    pub estimated_job_cost_musd_micros: u64,
    pub risk_buffer_musd_micros: u64,
    pub metadata: BTreeMap<String, String>,
}

impl OpportunityCandidate {
    pub fn robust_net_micros(&self) -> i64 {
        let v = self.expected_gross_musd_micros as i128
            - self.expected_external_cost_musd_micros as i128
            - self.estimated_job_cost_musd_micros as i128
            - self.risk_buffer_musd_micros as i128;
        v.clamp(i64::MIN as i128, i64::MAX as i128) as i64
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionCode {
    Accepted,
    AgentDisabled,
    JobTypeNotAllowed,
    Expired,
    JobCostLimit,
    DailyBudget,
    NoRobustEdge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EconomicDecision {
    pub schema_version: u32,
    pub decision_id: String,
    pub opportunity_id: String,
    pub agent_id: String,
    pub decided_at_unix: u64,
    pub code: DecisionCode,
    pub accepted: bool,
    pub robust_net_musd_micros: i64,
    pub required_net_edge_musd_micros: u64,
    pub daily_spend_before_musd_micros: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMode {
    DeterministicHash,
    ExactReplay,
    Quorum,
    ExternalProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobIntent {
    pub schema_version: u32,
    pub job_intent_id: String,
    pub opportunity_id: String,
    pub agent_id: String,
    pub job_type: JobType,
    pub input_hash: String,
    pub max_cost_musd_micros: u64,
    pub deadline_unix: u64,
    pub verification: VerificationMode,
    pub created_at_unix: u64,
}

impl JobIntent {
    pub fn as_job_request(&self) -> JobRequest {
        JobRequest {
            schema_version: SCHEMA_VERSION,
            job_id: stable_id(
                "job",
                &[
                    &self.job_intent_id,
                    &self.agent_id,
                    &self.input_hash,
                ],
            ),
            created_at_unix: self.created_at_unix,
            requester_id: self.agent_id.clone(),
            job_type: self.job_type.clone(),
            input_hash: self.input_hash.clone(),
            max_price_musd_micros: self.max_cost_musd_micros,
            // A bot buying work from the same Mycelium economy is an internal
            // activity even if it later helps create external value.
            internal_work: true,
            description: format!(
                "autonomous job for opportunity {}",
                self.opportunity_id
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalValueClass {
    ExternalTradingPnl,
    ExternalServicePayment,
    ExternalSolverReward,
    ExternalProtocolFee,
    InternalTransfer,
    BotServiceSpend,
    MycEmission,
    WsrPayout,
    TreasuryTransfer,
}

impl ExternalValueClass {
    pub fn can_create_external_value(&self) -> bool {
        matches!(
            self,
            Self::ExternalTradingPnl
                | Self::ExternalServicePayment
                | Self::ExternalSolverReward
                | Self::ExternalProtocolFee
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalValueReceipt {
    pub schema_version: u32,
    pub source_id: String,
    pub agent_id: String,
    pub opportunity_id: String,
    pub value_class: ExternalValueClass,
    pub network: String,
    pub asset: String,
    pub gross_inflow_musd_micros: u64,
    pub external_cost_musd_micros: u64,
    pub net_external_value_musd_micros: i64,
    /// The transaction this receipt claims as its evidence.
    pub proof_hash: String,
    /// DIAGNOSTICS ONLY. This is not an authority input and no economic path
    /// reads it: `TrustedNEV = VerifyChain(VerifyPolicy(DeriveBoundary(Evidence)))`,
    /// never `TrustedNEV = receipt.proof_verified`. It is kept in the serialized
    /// form so `autonomy-audit` and a human comparing a record against the
    /// adapter that wrote it still see what the writer claimed, and it is
    /// mirrored in `ReceiptEvidence::stored_proof_verified` for the same reason.
    /// A value recorded before the boundary existed reads `true` here and
    /// contributes nothing.
    pub proof_verified: bool,
    pub realized_at_unix: u64,
    pub verifier_id: String,
}

impl ExternalValueReceipt {
    /// Shape check on the stored claim. Diagnostics only.
    ///
    /// This reads `proof_verified` and is therefore NOT an authority predicate;
    /// see [`crate::verified_view`]. It stays because removing it would not make
    /// anything safer — the view never calls it — and because the honest
    /// diagnosis of an old ledger needs to know what it claimed.
    pub fn counts_as_external_value(&self) -> bool {
        self.value_class.can_create_external_value()
            && self.proof_verified
            && !self.proof_hash.trim().is_empty()
            && !self.verifier_id.trim().is_empty()
    }

    pub fn positive_external_value(&self) -> bool {
        self.counts_as_external_value()
            && self.net_external_value_musd_micros > 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicPolicy {
    pub min_net_edge_musd_micros: u64,
    pub default_verification: VerificationMode,
}

impl Default for EconomicPolicy {
    fn default() -> Self {
        Self {
            min_net_edge_musd_micros: 10_000, // 0.01 mUSD
            default_verification: VerificationMode::DeterministicHash,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrchestrationResult {
    pub decision: EconomicDecision,
    pub job_intent: Option<JobIntent>,
    pub job_request_template: Option<JobRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AutonomousSummary {
    pub agents: u64,
    pub enabled_agents: u64,
    pub opportunities: u64,
    pub accepted_opportunities: u64,
    pub rejected_opportunities: u64,
    pub job_intents: u64,
    pub internal_job_spend_musd: f64,
    pub external_value_receipts: u64,
    /// Value events the [`crate::verified_view::VerifiedEconomyView`] could
    /// attest. Zero in [`crate::verified_view::TrustMode::Unverified`], which is
    /// the honest answer: nothing on an offline view is attested.
    pub verified_external_value_receipts: u64,
    /// The attested net, in mUSD. Zero for the same reason; the number the
    /// ledger *claims* is reported under `unattested_*` below instead of being
    /// silently dropped.
    pub net_external_value_musd: f64,
    /// How much of the derivation the reporting view actually performed.
    #[serde(default)]
    pub trust_mode: crate::verified_view::TrustMode,
    /// Receipts that re-derive offline but are not attested.
    #[serde(default)]
    pub unattested_external_value_receipts: u64,
    /// What those receipts claim. NOT verified value.
    #[serde(default)]
    pub unattested_net_external_value_musd: f64,
    #[serde(default)]
    pub attestation_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArvStatus {
    pub level: String,
    pub verified_external_events: u64,
    pub net_external_value_musd_total: f64,
    pub net_external_value_musd_per_day_30d: f64,
    pub full_30d_window: bool,
    pub next_target_musd_per_day: Option<f64>,
    pub arv0_pass: bool,
    pub note: String,
    /// Which derivation produced the four fields above.
    #[serde(default)]
    pub trust_mode: crate::verified_view::TrustMode,
    /// Receipts that re-derive offline, with no chain read behind them. They
    /// are reported so a downgraded value is visible instead of looking like
    /// zero.
    #[serde(default)]
    pub unattested_external_events: u64,
    #[serde(default)]
    pub unattested_net_external_value_musd: f64,
    #[serde(default)]
    pub unattested_net_external_value_musd_per_day_30d: f64,
    #[serde(default)]
    pub attestation_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AutonomyPayload {
    Agent { manifest: EconomicAgentManifest },
    Opportunity { opportunity: OpportunityCandidate },
    Decision { decision: EconomicDecision },
    JobIntent { intent: JobIntent },
    ExternalValue { receipt: ExternalValueReceipt },
    /// Boundary evidence only. Each side's `ControlDomain` is derived on read
    /// from a `ControlledAddressRegistry`, so this variant stores addresses
    /// and hashes and nothing a writer could assert a domain through.
    BoundaryCrossing { evidence: BoundaryEvidence },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyRecord {
    pub sequence: u64,
    pub recorded_at_unix: u64,
    pub prev_hash: String,
    pub record_hash: String,
    pub payload: AutonomyPayload,
}

impl AutonomyRecord {
    /// Commits the canonical SEMANTIC record, not the exact persisted bytes:
    /// the value hashed here is this struct re-serialized with an empty
    /// `record_hash`. Any key serde would drop on the way in is therefore
    /// outside the hash, which is why the payloads above are closed with
    /// `deny_unknown_fields`.
    fn computed_hash(&self) -> Result<String> {
        let mut copy = self.clone();
        copy.record_hash.clear();
        Ok(blake3::hash(&serde_json::to_vec(&copy)?)
            .to_hex()
            .to_string())
    }
}

#[derive(Debug, Clone)]
pub struct AutonomousEconomy {
    root: PathBuf,
}

impl AutonomousEconomy {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        // 0700 on the root: a default umask would otherwise leave every autonomy
        // record world-readable. A pre-existing looser mode is corrected and the
        // correction reported, not refused — installations created before this
        // existed must keep opening.
        crate::durability::ensure_private_dir(&root)?;
        Ok(Self { root })
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.root.join(AUTONOMY_LEDGER_FILE)
    }

    /// Where this ledger lives. Exposed so a caller that has to reach another
    /// file in the same economy directory — the attestation ledger, the
    /// reinvestment controller — does not have to be handed a path that could
    /// disagree with this one's.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Head anchor for the autonomy ledger, or `None` on a ledger written
    /// before anchoring existed. `discarded_bytes_total > 0` means this ledger
    /// has survived at least one interrupted append.
    pub fn head_anchor(&self) -> Result<Option<crate::durability::HeadAnchor>> {
        crate::durability::read_head_anchor(&self.root, AUTONOMY_LEDGER_FILE)
    }

    pub fn records(&self) -> Result<Vec<AutonomyRecord>> {
        // The lock covers the whole read, not just the repair: the head anchor is
        // a second file, and reading both outside one critical section can
        // compare them at different instants and return a phantom "truncated"
        // verdict on a healthy ledger. The append path uses `read_records` for
        // the same reason — it already holds this lock, which is not reentrant.
        let _lock = crate::durability::LedgerLock::acquire_timeout(
            &self.root,
            AUTONOMY_LEDGER_FILE,
            crate::durability::LEDGER_LOCK_WAIT,
        )?;
        // A crash mid-append leaves a partial final line. Those bytes were never
        // a completed record, so they are discarded — loudly.
        let recovery =
            crate::durability::recover_torn_tail(&self.ledger_path(), "autonomy ledger")?;
        let records = self.read_records()?;
        self.verify_head(&records)?;
        // Record what the repair discarded, so the anchor does not claim a clean
        // history that the log line contradicts.
        if let Some(torn) = recovery {
            let head = records
                .last()
                .map_or(AUTONOMY_GENESIS_HASH, |r| r.record_hash.as_str());
            crate::durability::store_head_anchor(
                &self.root,
                AUTONOMY_LEDGER_FILE,
                records.last().map_or(0, |r| r.sequence),
                head,
                Some(torn.report(now_unix())),
            )?;
        }
        Ok(records)
    }

    /// Chain-verified head against the out-of-band anchor. Detects an
    /// accidentally truncated tail, a corrupted ledger and one swapped for an
    /// older copy. It does **not** defend against an attacker who can write
    /// both files — see [`crate::durability`] for why only an external anchor
    /// would, and why that is out of scope here.
    fn verify_head(&self, records: &[AutonomyRecord]) -> Result<()> {
        let anchor = crate::durability::read_head_anchor(&self.root, AUTONOMY_LEDGER_FILE)?;
        let head = records
            .last()
            .map_or(AUTONOMY_GENESIS_HASH, |r| r.record_hash.as_str());
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
            "autonomy ledger",
        )
    }

    fn read_records(&self) -> Result<Vec<AutonomyRecord>> {
        let path = self.ledger_path();
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = fs::File::open(path)?;
        let mut out = Vec::new();
        let mut expected_seq = 1u64;
        let mut expected_prev = AUTONOMY_GENESIS_HASH.to_string();

        for (idx, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: AutonomyRecord = serde_json::from_str(&line).map_err(|e| {
                EconomyError::Invalid(format!(
                    "autonomous ledger line {} cannot be parsed: {}",
                    idx + 1,
                    e
                ))
            })?;
            if record.sequence != expected_seq {
                return Err(EconomyError::Invalid(format!(
                    "autonomous ledger sequence mismatch: expected {}, got {}",
                    expected_seq, record.sequence
                )));
            }
            if record.prev_hash != expected_prev {
                return Err(EconomyError::Invalid(format!(
                    "autonomous ledger hash-chain break at sequence {}",
                    record.sequence
                )));
            }
            let computed = record.computed_hash()?;
            if record.record_hash != computed {
                return Err(EconomyError::Invalid(format!(
                    "autonomous ledger hash mismatch at sequence {}",
                    record.sequence
                )));
            }
            expected_prev = record.record_hash.clone();
            expected_seq += 1;
            out.push(record);
        }
        Ok(out)
    }

    pub fn register_agent(
        &self,
        mut manifest: EconomicAgentManifest,
    ) -> Result<EconomicAgentManifest> {
        validate_agent(&manifest)?;
        if self.agent(&manifest.agent_id)?.is_some() {
            return Err(EconomyError::Conflict(format!(
                "agent {} already registered",
                manifest.agent_id
            )));
        }
        manifest.schema_version = SCHEMA_VERSION;
        if manifest.created_at_unix == 0 {
            manifest.created_at_unix = now_unix();
        }
        self.append(AutonomyPayload::Agent {
            manifest: manifest.clone(),
        })?;
        Ok(manifest)
    }

    pub fn submit_opportunity(
        &self,
        mut opportunity: OpportunityCandidate,
    ) -> Result<OpportunityCandidate> {
        validate_opportunity(&opportunity)?;
        if self.agent(&opportunity.agent_id)?.is_none() {
            return Err(EconomyError::NotFound(format!(
                "agent {}",
                opportunity.agent_id
            )));
        }
        if self.opportunity(&opportunity.opportunity_id)?.is_some() {
            return Err(EconomyError::Conflict(format!(
                "opportunity {} already exists",
                opportunity.opportunity_id
            )));
        }
        opportunity.schema_version = SCHEMA_VERSION;
        self.append(AutonomyPayload::Opportunity {
            opportunity: opportunity.clone(),
        })?;
        Ok(opportunity)
    }

    pub fn orchestrate(
        &self,
        opportunity_id: &str,
        policy: &EconomicPolicy,
        now: u64,
    ) -> Result<OrchestrationResult> {
        if let Some(existing) = self.decision_for_opportunity(opportunity_id)? {
            let intent = self.job_intent_for_opportunity(opportunity_id)?;
            return Ok(OrchestrationResult {
                job_request_template: intent.as_ref().map(JobIntent::as_job_request),
                decision: existing,
                job_intent: intent,
            });
        }

        let opp = self
            .opportunity(opportunity_id)?
            .ok_or_else(|| EconomyError::NotFound(format!(
                "opportunity {opportunity_id}"
            )))?;
        let agent = self
            .agent(&opp.agent_id)?
            .ok_or_else(|| EconomyError::NotFound(format!(
                "agent {}",
                opp.agent_id
            )))?;

        let day_start = (now / 86_400) * 86_400;
        let day_end = day_start.saturating_add(86_400);
        let daily_spend = self
            .job_intents()?
            .into_iter()
            .filter(|j| {
                j.agent_id == agent.agent_id
                    && j.created_at_unix >= day_start
                    && j.created_at_unix < day_end
            })
            .fold(0u64, |acc, j| acc.saturating_add(j.max_cost_musd_micros));

        let robust_net = opp.robust_net_micros();
        let (code, accepted, reason) = if !agent.enabled {
            (
                DecisionCode::AgentDisabled,
                false,
                "agent is disabled".to_string(),
            )
        } else if !agent.allowed_job_types.contains(&opp.job_type) {
            (
                DecisionCode::JobTypeNotAllowed,
                false,
                "requested job type is not allowed for this agent".to_string(),
            )
        } else if now > opp.expires_at_unix {
            (
                DecisionCode::Expired,
                false,
                "opportunity expired before orchestration".to_string(),
            )
        } else if opp.estimated_job_cost_musd_micros > agent.max_job_cost_musd_micros {
            (
                DecisionCode::JobCostLimit,
                false,
                "estimated job cost exceeds agent per-job limit".to_string(),
            )
        } else if daily_spend.saturating_add(opp.estimated_job_cost_musd_micros)
            > agent.daily_budget_musd_micros
        {
            (
                DecisionCode::DailyBudget,
                false,
                "job would exceed agent daily budget".to_string(),
            )
        } else if robust_net < policy.min_net_edge_musd_micros as i64 {
            (
                DecisionCode::NoRobustEdge,
                false,
                "robust expected net value is below required edge".to_string(),
            )
        } else {
            (
                DecisionCode::Accepted,
                true,
                "bounded positive robust edge".to_string(),
            )
        };

        let decision = EconomicDecision {
            schema_version: SCHEMA_VERSION,
            decision_id: stable_id(
                "decision",
                &[opportunity_id, &now.to_string(), &format!("{code:?}")],
            ),
            opportunity_id: opportunity_id.to_string(),
            agent_id: opp.agent_id.clone(),
            decided_at_unix: now,
            code,
            accepted,
            robust_net_musd_micros: robust_net,
            required_net_edge_musd_micros: policy.min_net_edge_musd_micros,
            daily_spend_before_musd_micros: daily_spend,
            reason,
        };
        self.append(AutonomyPayload::Decision {
            decision: decision.clone(),
        })?;

        let job_intent = if accepted {
            let intent = JobIntent {
                schema_version: SCHEMA_VERSION,
                job_intent_id: stable_id(
                    "jobintent",
                    &[opportunity_id, &opp.agent_id, &opp.input_hash],
                ),
                opportunity_id: opportunity_id.to_string(),
                agent_id: opp.agent_id.clone(),
                job_type: opp.job_type.clone(),
                input_hash: opp.input_hash.clone(),
                max_cost_musd_micros: opp.estimated_job_cost_musd_micros,
                deadline_unix: opp.expires_at_unix,
                verification: policy.default_verification.clone(),
                created_at_unix: now,
            };
            self.append(AutonomyPayload::JobIntent {
                intent: intent.clone(),
            })?;
            Some(intent)
        } else {
            None
        };

        Ok(OrchestrationResult {
            job_request_template: job_intent.as_ref().map(JobIntent::as_job_request),
            decision,
            job_intent,
        })
    }

    /// Records an externally verified value event. The caller is expected to
    /// be a connector/verifier, not a user-controlled boolean toggle.
    pub fn record_external_value(
        &self,
        mut receipt: ExternalValueReceipt,
    ) -> Result<ExternalValueReceipt> {
        validate_external_value(&receipt)?;
        let opp = self
            .opportunity(&receipt.opportunity_id)?
            .ok_or_else(|| EconomyError::NotFound(format!(
                "opportunity {}",
                receipt.opportunity_id
            )))?;
        if opp.agent_id != receipt.agent_id {
            return Err(EconomyError::Invalid(
                "external value agent does not own the opportunity".into(),
            ));
        }

        if self.external_value_source_used(&receipt.source_id)? {
            return Err(EconomyError::Conflict(format!(
                "external source {} already recorded",
                receipt.source_id
            )));
        }
        if receipt.proof_verified && self.external_value_proof_used(&receipt.proof_hash)? {
            return Err(EconomyError::Conflict(
                "external value proof already recorded".into(),
            ));
        }

        let expected_net_i128 = receipt.gross_inflow_musd_micros as i128
            - receipt.external_cost_musd_micros as i128;
        if expected_net_i128 < i64::MIN as i128 || expected_net_i128 > i64::MAX as i128 {
            return Err(EconomyError::Invalid(
                "net external value exceeds signed 64-bit micros ABI".into(),
            ));
        }
        let expected_net = expected_net_i128 as i64;
        if receipt.net_external_value_musd_micros != expected_net {
            return Err(EconomyError::Invalid(
                "net external value does not equal gross inflow minus external cost".into(),
            ));
        }

        receipt.schema_version = SCHEMA_VERSION;
        self.append(AutonomyPayload::ExternalValue {
            receipt: receipt.clone(),
        })?;
        Ok(receipt)
    }

    /// Records boundary evidence and returns the derived crossing.
    ///
    /// The stored payload is the evidence; the returned `BoundaryCrossing` is
    /// computed from it against the supplied registry, so a reader can never
    /// take a domain out of the file. The registry is a parameter because a
    /// registry-free derivation would be an assertion.
    pub fn record_boundary_crossing(
        &self,
        evidence: &BoundaryEvidence,
        registry: &ControlledAddressRegistry,
    ) -> Result<BoundaryCrossing> {
        let crossing = BoundaryCrossing::derive(evidence, registry)?;
        self.append(AutonomyPayload::BoundaryCrossing {
            evidence: evidence.clone(),
        })?;
        Ok(crossing)
    }

    /// Re-derives every recorded crossing against the registry as it stands
    /// now. Nothing here is read from the ledger except the evidence.
    pub fn crossings(
        &self,
        registry: &ControlledAddressRegistry,
    ) -> Result<Vec<BoundaryCrossing>> {
        self.boundary_evidence()?
            .iter()
            .map(|e| BoundaryCrossing::derive(e, registry))
            .collect()
    }

    pub fn boundary_evidence(&self) -> Result<Vec<BoundaryEvidence>> {
        Ok(self
            .records()?
            .into_iter()
            .filter_map(|r| match r.payload {
                AutonomyPayload::BoundaryCrossing { evidence } => Some(evidence),
                _ => None,
            })
            .collect())
    }

    // ---- P4b: the attestation ledger -------------------------------------
    //
    // Attestations live beside the autonomy ledger rather than inside it, in
    // their own hash-chained, head-anchored file. Two reasons:
    //
    //  * the autonomy ledger's wire format is not changed, so a ledger written
    //    before this step keeps deserializing byte for byte and every existing
    //    `record_hash` still recomputes;
    //  * an attestation is not an economic event. It must never reach a count, a
    //    total or a summary, and a separate file makes it impossible for it to
    //    be mistaken for one by a `match` that only ever learned about receipts.
    //
    // It is still protected by the same durability machinery as the ledger it
    // gates, because an attestation that can be lost between the signature and
    // the read is a receipt that stops counting for no visible reason.

    /// Where the attestation ledger lives.
    pub fn attestation_ledger_path(&self) -> PathBuf {
        self.root.join(ATTESTATION_LEDGER_FILE)
    }

    /// Records a verifier signature over a receipt.
    ///
    /// The attestation ledger is chain-verified before the append, so a
    /// corrupted or truncated file refuses the write instead of extending it.
    /// Nothing here decides whether the receipt is genuine: the signature is
    /// re-verified against the current validated policy on every read.
    pub fn record_receipt_attestation(
        &self,
        attestation: &AuthenticatedExternalValueReceipt,
    ) -> Result<()> {
        self.append_attestation(attestation.clone())
    }

    /// Every recorded attestation, in ledger order.
    ///
    /// Chain-verified and head-anchored, like the autonomy ledger. An empty
    /// vector for a ledger that does not exist is the legacy case, not an error:
    /// a directory written before P4b has no attestations, and every receipt in
    /// it is reported as unattested with the reason.
    pub fn receipt_attestations(&self) -> Result<Vec<AuthenticatedExternalValueReceipt>> {
        Ok(self
            .read_attestation_records()?
            .into_iter()
            .map(|r| r.attestation)
            .collect())
    }

    fn append_attestation(
        &self,
        attestation: AuthenticatedExternalValueReceipt,
    ) -> Result<()> {
        let _lock = crate::durability::LedgerLock::acquire_timeout(
            &self.root,
            ATTESTATION_LEDGER_FILE,
            crate::durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery = crate::durability::recover_torn_tail(
            &self.attestation_ledger_path(),
            "receipt attestation ledger",
        )?;
        // `read_attestation_file`, not `read_attestation_records`: the ledger
        // lock is not reentrant, and the append path holds it. The head anchor
        // is checked here explicitly for the same reason — refusing to extend a
        // rewritten ledger is part of the append, not an optional extra.
        let existing = read_attestation_file(&self.attestation_ledger_path())?;
        self.verify_attestation_head(&existing)?;
        let sequence = existing.last().map(|r| r.sequence + 1).unwrap_or(1);
        let prev_hash = existing
            .last()
            .map(|r| r.record_hash.clone())
            .unwrap_or_else(|| ATTESTATION_GENESIS_HASH.to_string());
        let mut record = AttestationRecord {
            sequence,
            recorded_at_unix: now_unix(),
            prev_hash,
            record_hash: String::new(),
            attestation,
        };
        record.record_hash = record.computed_hash()?;
        let line = serde_json::to_vec(&record)?;
        crate::durability::append_line(&self.attestation_ledger_path(), &line)?;
        crate::durability::store_head_anchor(
            &self.root,
            ATTESTATION_LEDGER_FILE,
            record.sequence,
            &record.record_hash,
            recovery.map(|t| t.report(now_unix())),
        )
    }

    fn verify_attestation_head(&self, records: &[AttestationRecord]) -> Result<()> {
        let anchor = crate::durability::read_head_anchor(
            &self.root,
            ATTESTATION_LEDGER_FILE,
        )?;
        let head = records
            .last()
            .map_or(ATTESTATION_GENESIS_HASH, |r| r.record_hash.as_str());
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
            "receipt attestation ledger",
        )
    }

    /// Chain-verifies the attestation ledger under its own lock, then checks it
    /// against the head anchor. Mirrors [`Self::records`] exactly, including the
    /// separate lock name: the two ledgers are distinct files and must not share
    /// a lock, or an append to one would refuse while the other is held.
    fn read_attestation_records(&self) -> Result<Vec<AttestationRecord>> {
        let _lock = crate::durability::LedgerLock::acquire_timeout(
            &self.root,
            ATTESTATION_LEDGER_FILE,
            crate::durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery = crate::durability::recover_torn_tail(
            &self.attestation_ledger_path(),
            "receipt attestation ledger",
        )?;
        let records = read_attestation_file(&self.attestation_ledger_path())?;
        self.verify_attestation_head(&records)?;
        if let Some(torn) = recovery {
            let head = records
                .last()
                .map_or(ATTESTATION_GENESIS_HASH, |r| r.record_hash.as_str());
            crate::durability::store_head_anchor(
                &self.root,
                ATTESTATION_LEDGER_FILE,
                records.last().map_or(0, |r| r.sequence),
                head,
                Some(torn.report(now_unix())),
            )?;
        }
        Ok(records)
    }

    /// Records an externally verified value event justified by a crossing.
    ///
    /// This is the P1 path: the receipt's class, asset, cited transaction and
    /// net sign must all agree with a crossing whose domains were derived
    /// from a registry. `record_external_value` stays available and
    /// unchanged for records written before the boundary existed; it does not
    /// consult a crossing, so a value event booked through it carries no
    /// boundary evidence.
    pub fn record_external_value_with_crossing(
        &self,
        receipt: ExternalValueReceipt,
        crossing: &BoundaryCrossing,
    ) -> Result<ExternalValueReceipt> {
        if crossing.value_class_domain() != receipt.value_class.value_class_domain()
        {
            return Err(EconomyError::Invalid(format!(
                "crossing {:?} cannot justify external value class {:?}",
                crossing.kind(),
                receipt.value_class
            )));
        }
        let asset = SettlementAsset::classify_symbol(&receipt.asset)?;
        let receipt_asset = asset.real_asset().ok_or_else(|| {
            EconomyError::Invalid(format!(
                "settlement asset {} is synthetic and cannot book external value",
                asset.symbol()
            ))
        })?;
        if receipt_asset != crossing.asset() {
            return Err(EconomyError::Invalid(
                "external value receipt asset does not match the crossing asset"
                    .into(),
            ));
        }
        let proof = crossing.proof().ok_or_else(|| {
            EconomyError::Invalid(
                "external value receipt needs a crossing with a verified proof"
                    .into(),
            )
        })?;
        if !receipt
            .proof_hash
            .eq_ignore_ascii_case(&proof.transaction_hash)
        {
            return Err(EconomyError::Invalid(
                "external value receipt must cite the crossing transaction"
                    .into(),
            ));
        }
        if crossing.kind().produces_external_value()
            && receipt.net_external_value_musd_micros <= 0
        {
            return Err(EconomyError::Invalid(
                "an external inflow cannot book a non-positive net".into(),
            ));
        }
        if crossing.nev_sign() == NevSign::Negative
            && receipt.net_external_value_musd_micros > 0
        {
            return Err(EconomyError::Invalid(
                "an external outflow cannot book a positive net".into(),
            ));
        }
        self.record_external_value(receipt)
    }

    pub fn agent(&self, agent_id: &str) -> Result<Option<EconomicAgentManifest>> {
        Ok(self.records()?.into_iter().find_map(|r| match r.payload {
            AutonomyPayload::Agent { manifest } if manifest.agent_id == agent_id => {
                Some(manifest)
            }
            _ => None,
        }))
    }

    pub fn agents(&self) -> Result<Vec<EconomicAgentManifest>> {
        Ok(self
            .records()?
            .into_iter()
            .filter_map(|r| match r.payload {
                AutonomyPayload::Agent { manifest } => Some(manifest),
                _ => None,
            })
            .collect())
    }

    pub fn opportunity(
        &self,
        opportunity_id: &str,
    ) -> Result<Option<OpportunityCandidate>> {
        Ok(self.records()?.into_iter().find_map(|r| match r.payload {
            AutonomyPayload::Opportunity { opportunity }
                if opportunity.opportunity_id == opportunity_id =>
            {
                Some(opportunity)
            }
            _ => None,
        }))
    }

    pub fn decision_for_opportunity(
        &self,
        opportunity_id: &str,
    ) -> Result<Option<EconomicDecision>> {
        Ok(self.records()?.into_iter().find_map(|r| match r.payload {
            AutonomyPayload::Decision { decision }
                if decision.opportunity_id == opportunity_id =>
            {
                Some(decision)
            }
            _ => None,
        }))
    }

    pub fn job_intent_for_opportunity(
        &self,
        opportunity_id: &str,
    ) -> Result<Option<JobIntent>> {
        Ok(self.records()?.into_iter().find_map(|r| match r.payload {
            AutonomyPayload::JobIntent { intent }
                if intent.opportunity_id == opportunity_id =>
            {
                Some(intent)
            }
            _ => None,
        }))
    }

    pub fn job_intents(&self) -> Result<Vec<JobIntent>> {
        Ok(self
            .records()?
            .into_iter()
            .filter_map(|r| match r.payload {
                AutonomyPayload::JobIntent { intent } => Some(intent),
                _ => None,
            })
            .collect())
    }

    pub fn external_values(&self) -> Result<Vec<ExternalValueReceipt>> {
        Ok(self
            .records()?
            .into_iter()
            .filter_map(|r| match r.payload {
                AutonomyPayload::ExternalValue { receipt } => Some(receipt),
                _ => None,
            })
            .collect())
    }

    /// Activity counters plus the view-derived value columns.
    ///
    /// The value columns come from [`crate::verified_view::VerifiedEconomyView`].
    /// Called with no registry and no provider, this is the offline view, and
    /// the honest answer is that nothing here is attested: the claimed numbers
    /// are reported under `unattested_*`. Use [`Self::view`] with the operator's
    /// registry, and a pinned provider, for the authoritative figures.
    pub fn summary(&self) -> Result<AutonomousSummary> {
        let registry = ControlledAddressRegistry::new();
        self.view(&registry).autonomy_summary()
    }

    /// The read-side authority over this ledger. The registry is a parameter
    /// because a registry-free derivation would be an assertion, and because
    /// nothing in this directory may decide which addresses are controlled.
    pub fn view<'a>(
        &'a self,
        registry: &'a ControlledAddressRegistry,
    ) -> crate::verified_view::VerifiedEconomyView<'a> {
        crate::verified_view::VerifiedEconomyView::unverified(self, registry)
    }

    /// Counter assembly. Public so the view can hand in the evidence it
    /// re-derived instead of making this walk the ledger twice.
    pub(crate) fn summary_with_evidence(
        &self,
        mode: crate::verified_view::TrustMode,
        evidence: &[crate::verified_view::ReceiptEvidence],
        note: &str,
    ) -> Result<AutonomousSummary> {
        let mut agents = 0u64;
        let mut enabled_agents = 0u64;
        let mut opportunities = 0u64;
        let mut accepted = 0u64;
        let mut rejected = 0u64;
        let mut job_intents = 0u64;
        let mut internal_spend = 0u64;

        for record in self.records()? {
            match record.payload {
                AutonomyPayload::Agent { manifest } => {
                    agents += 1;
                    if manifest.enabled {
                        enabled_agents += 1;
                    }
                }
                AutonomyPayload::Opportunity { .. } => opportunities += 1,
                AutonomyPayload::Decision { decision } => {
                    if decision.accepted {
                        accepted += 1;
                    } else {
                        rejected += 1;
                    }
                }
                AutonomyPayload::JobIntent { intent } => {
                    job_intents += 1;
                    internal_spend =
                        internal_spend.saturating_add(intent.max_cost_musd_micros);
                }
                // Value is counted from the view's evidence, never from the
                // record's own `proof_verified`.
                AutonomyPayload::ExternalValue { .. } => {}
                // Boundary evidence is not value on its own. It is the
                // justification a value receipt is checked against, and it
                // carries no micros, so it stays out of the NEV total.
                AutonomyPayload::BoundaryCrossing { .. } => {}
            }
        }

        let verified: i64 = evidence
            .iter()
            .filter(|e| e.counted)
            .map(|e| e.net_external_value_musd_micros)
            .sum();
        let claimed: i64 = evidence
            .iter()
            .filter(|e| e.offline_ok)
            .map(|e| e.net_external_value_musd_micros)
            .sum();

        Ok(AutonomousSummary {
            agents,
            enabled_agents,
            opportunities,
            accepted_opportunities: accepted,
            rejected_opportunities: rejected,
            job_intents,
            internal_job_spend_musd: internal_spend as f64 / 1_000_000.0,
            external_value_receipts: evidence.len() as u64,
            verified_external_value_receipts: evidence
                .iter()
                .filter(|e| e.counted)
                .count() as u64,
            net_external_value_musd: verified as f64 / 1_000_000.0,
            trust_mode: mode,
            unattested_external_value_receipts: {
                evidence.iter().filter(|e| e.offline_ok).count() as u64
            },
            unattested_net_external_value_musd: claimed as f64 / 1_000_000.0,
            attestation_note: note.to_string(),
        })
    }

    /// ARV through the view. With no registry and no provider this is the
    /// offline view and cannot report a promoted level; see [`Self::view`] and
    /// [`crate::verified_view`].
    pub fn arv_status(&self, now: u64) -> Result<ArvStatus> {
        let registry = ControlledAddressRegistry::new();
        self.view(&registry).arv_status(now)
    }

    fn append(&self, payload: AutonomyPayload) -> Result<()> {
        // The lock spans read-tail → derive sequence/prev_hash → write, not just
        // the write: two appends racing derive the same sequence and interleave
        // their bytes. The duplicate is caught on read, never prevented.
        let _lock = crate::durability::LedgerLock::acquire_timeout(
            &self.root,
            AUTONOMY_LEDGER_FILE,
            crate::durability::LEDGER_LOCK_WAIT,
        )?;
        // Safe under the lock: no other writer can have bytes in flight.
        let recovery =
            crate::durability::recover_torn_tail(&self.ledger_path(), "autonomy ledger")?;

        let existing = self.read_records()?;
        let sequence = existing.last().map(|r| r.sequence + 1).unwrap_or(1);
        let prev_hash = existing
            .last()
            .map(|r| r.record_hash.clone())
            .unwrap_or_else(|| AUTONOMY_GENESIS_HASH.to_string());
        let mut record = AutonomyRecord {
            sequence,
            recorded_at_unix: now_unix(),
            prev_hash,
            record_hash: String::new(),
            payload,
        };
        record.record_hash = record.computed_hash()?;

        // One buffer, one `write_all`, one `sync_data`.
        let line = serde_json::to_vec(&record)?;
        crate::durability::append_line(&self.ledger_path(), &line)?;
        crate::durability::store_head_anchor(
            &self.root,
            AUTONOMY_LEDGER_FILE,
            record.sequence,
            &record.record_hash,
            recovery.map(|t| t.report(now_unix())),
        )
    }

    /// HYGIENE, P4.5b — and the distinction is the point, not a caveat.
    ///
    /// These two checks refuse a *repeated append*. They are keyed on
    /// `source_id` and on `proof_hash`, which are this node's own names for an
    /// event, and either can be stepped around by a writer who chooses a second
    /// `source_id` and leaves `proof_verified` off. Nothing here makes a total
    /// correct, and no property in this crate is allowed to rest on them.
    ///
    /// The economic guarantee is elsewhere and is not this file's to provide:
    /// [`crate::verified_view::VerifiedEconomyView::receipt_evidence`] counts one
    /// contribution per [`crate::event_id::ExternalEventId`], whatever the file
    /// physically contains and however the process that wrote it behaved. A
    /// ledger with a duplicate in it — written by a fork, restored from a
    /// backup, hand-appended, or replayed from another node — is not stopped by
    /// anything in this function and does not need to be, because the total is
    /// idempotent without it.
    ///
    /// `the_write_path_refuses_a_repeated_append_and_the_total_is_idempotent`
    /// asserts both halves separately, because passing one is not evidence about
    /// the other.
    fn external_value_source_used(&self, source_id: &str) -> Result<bool> {
        Ok(self.external_values()?.into_iter().any(|r| r.source_id == source_id))
    }

    fn external_value_proof_used(&self, proof_hash: &str) -> Result<bool> {
        Ok(self
            .external_values()?
            .into_iter()
            .any(|r| r.proof_verified && r.proof_hash.eq_ignore_ascii_case(proof_hash)))
    }
}

fn validate_agent(agent: &EconomicAgentManifest) -> Result<()> {
    nonempty("agent_id", &agent.agent_id)?;
    nonempty("public_key", &agent.public_key)?;
    if agent.allowed_job_types.is_empty() {
        return Err(EconomyError::Invalid(
            "agent must allow at least one job type".into(),
        ));
    }
    if agent.daily_budget_musd_micros == 0 || agent.max_job_cost_musd_micros == 0 {
        return Err(EconomyError::Invalid(
            "agent budgets must be > 0".into(),
        ));
    }
    if agent.max_job_cost_musd_micros > agent.daily_budget_musd_micros {
        return Err(EconomyError::Invalid(
            "max job cost cannot exceed daily budget".into(),
        ));
    }
    let unique = agent
        .allowed_job_types
        .iter()
        .map(|x| format!("{x:?}"))
        .collect::<BTreeSet<_>>();
    if unique.len() != agent.allowed_job_types.len() {
        return Err(EconomyError::Invalid(
            "allowed_job_types contains duplicates".into(),
        ));
    }
    Ok(())
}

fn validate_opportunity(opp: &OpportunityCandidate) -> Result<()> {
    for (name, value) in [
        ("expected_gross", opp.expected_gross_musd_micros),
        ("expected_external_cost", opp.expected_external_cost_musd_micros),
        ("estimated_job_cost", opp.estimated_job_cost_musd_micros),
        ("risk_buffer", opp.risk_buffer_musd_micros),
    ] {
        if value > i64::MAX as u64 {
            return Err(EconomyError::Invalid(format!(
                "{name} exceeds signed 64-bit micros ABI"
            )));
        }
    }
    nonempty("opportunity_id", &opp.opportunity_id)?;
    nonempty("agent_id", &opp.agent_id)?;
    nonempty("input_hash", &opp.input_hash)?;
    nonempty("evidence_hash", &opp.evidence_hash)?;
    if opp.expires_at_unix <= opp.observed_at_unix {
        return Err(EconomyError::Invalid(
            "opportunity expiry must be after observation".into(),
        ));
    }
    if opp.estimated_job_cost_musd_micros == 0 {
        return Err(EconomyError::Invalid(
            "estimated job cost must be > 0".into(),
        ));
    }
    Ok(())
}

/// The write-time rules, re-run on every read by the verified view.
///
/// Split out from [`validate_external_value`] because that function's contract
/// is conditional on the stored `proof_verified`, and a reader that called it
/// would inherit that dependency. Here `proof_verified` is not consulted at all:
/// the question is whether the record is internally consistent and complete, not
/// what the writer claimed about it.
pub fn revalidate_external_value(receipt: &ExternalValueReceipt) -> Result<()> {
    if receipt.gross_inflow_musd_micros > i64::MAX as u64
        || receipt.external_cost_musd_micros > i64::MAX as u64
    {
        return Err(EconomyError::Invalid(
            "external value exceeds signed 64-bit micros ABI".into(),
        ));
    }
    nonempty("source_id", &receipt.source_id)?;
    nonempty("agent_id", &receipt.agent_id)?;
    nonempty("opportunity_id", &receipt.opportunity_id)?;
    nonempty("network", &receipt.network)?;
    nonempty("asset", &receipt.asset)?;
    // gross - cost is an invariant of the record, so it is re-checked on read
    // and not only on write.
    let expected = receipt.gross_inflow_musd_micros as i128
        - receipt.external_cost_musd_micros as i128;
    if receipt.net_external_value_musd_micros != expected as i64 {
        return Err(EconomyError::Invalid(
            "net external value does not equal gross inflow minus external cost".into(),
        ));
    }
    Ok(())
}

fn validate_external_value(receipt: &ExternalValueReceipt) -> Result<()> {
    revalidate_external_value(receipt)?;
    if receipt.proof_verified {
        nonempty("proof_hash", &receipt.proof_hash)?;
        nonempty("verifier_id", &receipt.verifier_id)?;
        if !receipt.value_class.can_create_external_value() {
            return Err(EconomyError::Invalid(
                "internal value class cannot be marked as verified external value".into(),
            ));
        }
    }
    Ok(())
}

fn nonempty(name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(EconomyError::Invalid(format!("{name} cannot be empty")))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn agent() -> EconomicAgentManifest {
        EconomicAgentManifest {
            schema_version: SCHEMA_VERSION,
            agent_id: "s1-arb-01".into(),
            public_key: "ed25519:test".into(),
            agent_class: AgentClass::Finance,
            allowed_job_types: vec![JobType::Simulation, JobType::Validation],
            daily_budget_musd_micros: 100_000_000,
            max_job_cost_musd_micros: 2_000_000,
            risk_profile: RiskProfile::Conservative,
            enabled: true,
            created_at_unix: 1_700_000_000,
        }
    }

    fn opportunity() -> OpportunityCandidate {
        OpportunityCandidate {
            schema_version: SCHEMA_VERSION,
            opportunity_id: "opp-1".into(),
            agent_id: "s1-arb-01".into(),
            observed_at_unix: 1_700_000_100,
            expires_at_unix: 1_700_001_000,
            job_type: JobType::Simulation,
            input_hash: "blake3:input".into(),
            evidence_hash: "blake3:evidence".into(),
            expected_gross_musd_micros: 8_000_000,
            expected_external_cost_musd_micros: 1_000_000,
            estimated_job_cost_musd_micros: 500_000,
            risk_buffer_musd_micros: 1_000_000,
            metadata: BTreeMap::new(),
        }
    }

    fn setup() -> (tempfile::TempDir, AutonomousEconomy) {
        let dir = tempdir().unwrap();
        let econ = AutonomousEconomy::open(dir.path()).unwrap();
        econ.register_agent(agent()).unwrap();
        econ.submit_opportunity(opportunity()).unwrap();
        (dir, econ)
    }

    #[test]
    fn positive_edge_creates_internal_job_intent() {
        let (_dir, econ) = setup();
        let out = econ
            .orchestrate(
                "opp-1",
                &EconomicPolicy::default(),
                1_700_000_200,
            )
            .unwrap();
        assert!(out.decision.accepted);
        let intent = out.job_intent.unwrap();
        assert_eq!(intent.max_cost_musd_micros, 500_000);
        let req = out.job_request_template.unwrap();
        assert!(req.internal_work);
        assert_eq!(req.requester_id, "s1-arb-01");
    }

    #[test]
    fn no_edge_rejects_without_job() {
        let (_dir, econ) = setup();
        let out = econ
            .orchestrate(
                "opp-1",
                &EconomicPolicy {
                    min_net_edge_musd_micros: 7_000_000,
                    ..EconomicPolicy::default()
                },
                1_700_000_200,
            )
            .unwrap();
        assert!(!out.decision.accepted);
        assert_eq!(out.decision.code, DecisionCode::NoRobustEdge);
        assert!(out.job_intent.is_none());
    }

    #[test]
    fn expired_opportunity_rejects() {
        let (_dir, econ) = setup();
        let out = econ
            .orchestrate(
                "opp-1",
                &EconomicPolicy::default(),
                1_700_002_000,
            )
            .unwrap();
        assert_eq!(out.decision.code, DecisionCode::Expired);
        assert!(!out.decision.accepted);
    }

    #[test]
    fn unverified_external_candidate_does_not_promote_arv() {
        let (_dir, econ) = setup();
        let mut r = external_receipt();
        r.proof_verified = false;
        r.verifier_id.clear();
        econ.record_external_value(r).unwrap();
        let arv = econ.arv_status(1_700_000_400).unwrap();
        assert_eq!(arv.level, "PRE-ARV0");
        assert!(!arv.arv0_pass);
    }

    /// The name is historical and deliberately kept: before P3 this test
    /// asserted `ARV0` here, and that expectation *was the bug*. It recorded a
    /// receipt whose only claim to being real was its own `proof_verified: true`,
    /// and asked `arv_status` — a reader — to believe it. A process that can
    /// append to this file could therefore reach `ARV4` and 100 mUSD/day of real
    /// reinvestment authority without a single byte existing on Base.
    ///
    /// The invariant the name still describes is real, and it is tested where the
    /// evidence lives: `boundary::tests::inflow_crossing_justifies_the_
    /// classification_and_net_survives` promotes to ARV0 through a pinned
    /// provider, and `verified_view::tests::pinned_mode_promotes_when_the_chain_
    /// confirms` covers the same promotion end to end. What this test now pins is
    /// the part that used to be missing: the stored flag is a claim, the
    /// diagnosis names the missing evidence, and the claim is reported instead of
    /// being dropped to a silent zero.
    #[test]
    fn verified_external_value_promotes_arv0() {
        let (_dir, econ) = setup();
        econ.record_external_value(external_receipt()).unwrap();

        // The old write-time predicate still says what it always said. It is a
        // diagnostic, and it is not an authority input.
        let stored = econ.external_values().unwrap();
        assert_eq!(stored.len(), 1);
        assert!(stored[0].counts_as_external_value());
        assert!(stored[0].positive_external_value());

        let arv = econ.arv_status(1_700_000_400).unwrap();
        assert_eq!(arv.trust_mode, crate::verified_view::TrustMode::Unverified);
        assert_eq!(arv.level, "PRE-ARV0");
        assert!(!arv.arv0_pass);
        // The verified fields are zero because nothing here is attested, and the
        // claim is reported under names that cannot be read as a level.
        assert_eq!(arv.verified_external_events, 0);
        assert_eq!(arv.net_external_value_musd_total, 0.0);
        // `proof_hash` here is "0xproof", not a transaction, so the receipt does
        // not even re-derive into a claim. It is counted, it is explained, and it
        // is worth nothing.
        assert_eq!(arv.unattested_external_events, 0);
        assert_eq!(arv.unattested_net_external_value_musd, 0.0);
        assert!(arv
            .attestation_note
            .contains("cites no transaction"), "{arv:?}");
    }

    /// The same ledger, read through a registry, still does not promote: an
    /// offline re-derivation cannot manufacture a transaction.
    #[test]
    fn a_receipt_with_only_a_stored_flag_never_promotes_arv0() {
        let (_dir, econ) = setup();
        econ.record_external_value(external_receipt()).unwrap();
        let registry = ControlledAddressRegistry::new()
            .with_address("0x2222222222222222222222222222222222222222")
            .unwrap();
        let view = econ.view(&registry);
        let arv = view.arv_status(1_700_000_400).unwrap();
        assert_eq!(arv.level, "PRE-ARV0");
        assert_eq!(arv.verified_external_events, 0);
        // And the operator is told what the ledger is claiming.
        assert_eq!(arv.unattested_net_external_value_musd, 0.0);
        assert!(arv.attestation_note.contains("TrustMode=unverified"), "{arv:?}");
    }

    #[test]
    fn verified_external_loss_reduces_nev_and_does_not_promote_arv() {
        let (_dir, econ) = setup();

        let mut gain = external_receipt();
        gain.source_id = "gain".into();
        gain.proof_hash = "0xgain".into();
        gain.gross_inflow_musd_micros = 6_000_000;
        gain.external_cost_musd_micros = 1_000_000;
        gain.net_external_value_musd_micros = 5_000_000;
        econ.record_external_value(gain).unwrap();

        let mut loss = external_receipt();
        loss.source_id = "loss".into();
        loss.proof_hash = "0xloss".into();
        loss.gross_inflow_musd_micros = 1_000_000;
        loss.external_cost_musd_micros = 9_000_000;
        loss.net_external_value_musd_micros = -8_000_000;
        loss.realized_at_unix += 1;
        econ.record_external_value(loss).unwrap();

        // The net of a loss still nets against a gain — but only for receipts the
        // view can attest, and offline it can attest none of them. The arithmetic
        // is unchanged; what changed is which receipts are allowed into it.
        let summary = econ.summary().unwrap();
        assert_eq!(summary.external_value_receipts, 2);
        assert_eq!(summary.verified_external_value_receipts, 0);
        assert_eq!(summary.net_external_value_musd, 0.0);

        let arv = econ.arv_status(1_700_000_500).unwrap();
        assert_eq!(arv.level, "PRE-ARV0");
        assert!(!arv.arv0_pass);
        assert_eq!(arv.net_external_value_musd_total, 0.0);
    }

    #[test]
    fn internal_transfer_cannot_be_verified_external_value() {
        let (_dir, econ) = setup();
        let mut r = external_receipt();
        r.value_class = ExternalValueClass::InternalTransfer;
        assert!(econ.record_external_value(r).is_err());
    }

    #[test]
    fn external_value_proof_cannot_be_reused() {
        let (_dir, econ) = setup();
        econ.record_external_value(external_receipt()).unwrap();
        let mut r2 = external_receipt();
        r2.source_id = "source-2".into();
        assert!(econ.record_external_value(r2).is_err());
    }

    #[test]
    fn internal_job_spend_is_not_external_value() {
        let (_dir, econ) = setup();
        econ.orchestrate(
            "opp-1",
            &EconomicPolicy::default(),
            1_700_000_200,
        )
        .unwrap();
        let s = econ.summary().unwrap();
        assert_eq!(s.internal_job_spend_musd, 0.5);
        assert_eq!(s.net_external_value_musd, 0.0);
    }

    #[test]
    fn autonomy_ledger_detects_tampering() {
        let (dir, econ) = setup();
        let raw = fs::read_to_string(econ.ledger_path()).unwrap();
        fs::write(
            dir.path().join("autonomous-ledger.jsonl"),
            raw.replace("s1-arb-01", "evil-agent"),
        )
        .unwrap();
        assert!(econ.records().is_err());
    }

    fn external_receipt() -> ExternalValueReceipt {
        ExternalValueReceipt {
            schema_version: SCHEMA_VERSION,
            source_id: "source-1".into(),
            agent_id: "s1-arb-01".into(),
            opportunity_id: "opp-1".into(),
            value_class: ExternalValueClass::ExternalTradingPnl,
            network: "base".into(),
            asset: "USDC".into(),
            gross_inflow_musd_micros: 6_000_000,
            external_cost_musd_micros: 1_000_000,
            net_external_value_musd_micros: 5_000_000,
            proof_hash: "0xproof".into(),
            proof_verified: true,
            realized_at_unix: 1_700_000_300,
            verifier_id: "base-reconcile".into(),
        }
    }
}
