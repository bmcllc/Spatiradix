//! TERR passive-only research adapter and orchestrator.
//!
//! TERR may allocate bounded research attention to validation/backtest/data
//! jobs. It never authorizes capital, execution, settlement or external value.

use crate::{
    autonomy::{AgentClass, EconomicAgentManifest, JobIntent, VerificationMode},
    now_unix, stable_id, EconomyError, JobRequest, JobType, Result,
    SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

pub const TERR_RESEARCH_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// TERR research ledger file name; also the append lock name and the head
/// anchor's ledger identifier.
pub const TERR_RESEARCH_LEDGER_FILE: &str = "terr-research-ledger.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerrResearchHint {
    pub schema_version: u32,
    pub hint_id: String,
    pub agent_id: String,
    pub source_hash: String,
    pub source_format: String,
    pub source_timestamp_unix: u64,
    pub expires_at_unix: u64,
    pub requested_job_type: JobType,
    pub requested_job_cost_musd_micros: u64,
    pub transition_probability: f64,
    pub uncertainty: f64,
    pub direction: f64,
    pub terr_score: f64,
    pub expected_sigma: f64,
    pub tau_expected_bars: u64,
    pub attractor_flux: f64,
    pub passive_only: bool,
    pub influences_execution: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerrResearchPolicy {
    pub min_transition_probability: f64,
    pub max_uncertainty: f64,
    pub min_abs_terr_score: f64,
}

impl Default for TerrResearchPolicy {
    fn default() -> Self {
        Self {
            min_transition_probability: 0.20,
            max_uncertainty: 0.80,
            min_abs_terr_score: 0.01,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResearchDecisionCode {
    Accepted,
    NotPassive,
    AgentDisabled,
    WrongAgentClass,
    JobTypeNotAllowed,
    InvalidResearchJobType,
    Expired,
    WeakTransition,
    HighUncertainty,
    WeakTerrScore,
    JobCostLimit,
    DailyBudget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerrResearchDecision {
    pub schema_version: u32,
    pub decision_id: String,
    pub hint_id: String,
    pub agent_id: String,
    pub decided_at_unix: u64,
    pub code: ResearchDecisionCode,
    pub accepted: bool,
    pub daily_spend_before_musd_micros: u64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerrResearchPlan {
    pub decision: TerrResearchDecision,
    pub job_intent: Option<JobIntent>,
    pub job_request_template: Option<JobRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ResearchPayload {
    Hint { hint: TerrResearchHint },
    Decision { decision: TerrResearchDecision },
    JobPlan { intent: JobIntent },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResearchRecord {
    sequence: u64,
    recorded_at_unix: u64,
    prev_hash: String,
    record_hash: String,
    payload: ResearchPayload,
}

impl ResearchRecord {
    fn computed_hash(&self) -> Result<String> {
        let mut copy = self.clone();
        copy.record_hash.clear();
        Ok(blake3::hash(&serde_json::to_vec(&copy)?)
            .to_hex()
            .to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerrResearchSummary {
    pub hints: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub job_plans: u64,
    pub committed_research_spend_musd: f64,
    pub ledger_valid: bool,
    pub head_hash: String,
}

#[derive(Debug, Clone)]
pub struct TerrResearchEngine {
    root: PathBuf,
}

impl TerrResearchEngine {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        crate::durability::ensure_private_dir(&root)?;
        Ok(Self { root })
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.root.join(TERR_RESEARCH_LEDGER_FILE)
    }

    /// Head anchor for the TERR research ledger, or `None` on a ledger written
    /// before anchoring existed.
    pub fn head_anchor(&self) -> Result<Option<crate::durability::HeadAnchor>> {
        crate::durability::read_head_anchor(&self.root, TERR_RESEARCH_LEDGER_FILE)
    }

    pub fn record_hint(&self, hint: TerrResearchHint) -> Result<TerrResearchHint> {
        validate_hint(&hint)?;
        if self.hint(&hint.hint_id)?.is_some() {
            return Err(EconomyError::Conflict(format!(
                "TERR hint {} already recorded",
                hint.hint_id
            )));
        }
        self.append(ResearchPayload::Hint { hint: hint.clone() })?;
        Ok(hint)
    }

    pub fn orchestrate(
        &self,
        hint_id: &str,
        agent: &EconomicAgentManifest,
        policy: &TerrResearchPolicy,
        now: u64,
    ) -> Result<TerrResearchPlan> {
        if let Some(decision) = self.decision(hint_id)? {
            let intent = self.job_plan(hint_id)?;
            return Ok(TerrResearchPlan {
                job_request_template: intent.as_ref().map(JobIntent::as_job_request),
                decision,
                job_intent: intent,
            });
        }

        validate_policy(policy)?;
        let hint = self
            .hint(hint_id)?
            .ok_or_else(|| EconomyError::NotFound(format!("TERR hint {hint_id}")))?;

        if hint.agent_id != agent.agent_id {
            return Err(EconomyError::Invalid(
                "TERR hint agent does not match orchestrated agent".into(),
            ));
        }

        let day_start = (now / 86_400) * 86_400;
        let day_end = day_start.saturating_add(86_400);
        let daily_spend = self
            .job_plans()?
            .into_iter()
            .filter(|j| {
                j.agent_id == agent.agent_id
                    && j.created_at_unix >= day_start
                    && j.created_at_unix < day_end
            })
            .fold(0u64, |acc, j| acc.saturating_add(j.max_cost_musd_micros));

        let research_type_ok = matches!(
            hint.requested_job_type,
            JobType::Validation | JobType::Backtest | JobType::DataTransform
        );

        let (code, accepted, reason) = if !hint.passive_only || hint.influences_execution {
            (
                ResearchDecisionCode::NotPassive,
                false,
                "TERR evidence is not passive-only".to_string(),
            )
        } else if !agent.enabled {
            (
                ResearchDecisionCode::AgentDisabled,
                false,
                "research agent is disabled".to_string(),
            )
        } else if agent.agent_class != AgentClass::Research {
            (
                ResearchDecisionCode::WrongAgentClass,
                false,
                "TERR requires agent_class=research".to_string(),
            )
        } else if !research_type_ok {
            (
                ResearchDecisionCode::InvalidResearchJobType,
                false,
                "TERR may request only validation/backtest/data_transform jobs".to_string(),
            )
        } else if !agent.allowed_job_types.contains(&hint.requested_job_type) {
            (
                ResearchDecisionCode::JobTypeNotAllowed,
                false,
                "requested research job type is not allowed".to_string(),
            )
        } else if now > hint.expires_at_unix {
            (
                ResearchDecisionCode::Expired,
                false,
                "TERR hint expired".to_string(),
            )
        } else if hint.transition_probability < policy.min_transition_probability {
            (
                ResearchDecisionCode::WeakTransition,
                false,
                "TERR transition probability below research threshold".to_string(),
            )
        } else if hint.uncertainty > policy.max_uncertainty {
            (
                ResearchDecisionCode::HighUncertainty,
                false,
                "TERR uncertainty exceeds research threshold".to_string(),
            )
        } else if hint.terr_score.abs() < policy.min_abs_terr_score {
            (
                ResearchDecisionCode::WeakTerrScore,
                false,
                "absolute TERR score below research threshold".to_string(),
            )
        } else if hint.requested_job_cost_musd_micros > agent.max_job_cost_musd_micros {
            (
                ResearchDecisionCode::JobCostLimit,
                false,
                "research job exceeds per-job budget".to_string(),
            )
        } else if daily_spend.saturating_add(hint.requested_job_cost_musd_micros)
            > agent.daily_budget_musd_micros
        {
            (
                ResearchDecisionCode::DailyBudget,
                false,
                "research job would exceed daily research budget".to_string(),
            )
        } else {
            (
                ResearchDecisionCode::Accepted,
                true,
                "passive TERR attention qualifies for bounded research work".to_string(),
            )
        };

        let decision = TerrResearchDecision {
            schema_version: SCHEMA_VERSION,
            decision_id: stable_id(
                "terrdecision",
                &[hint_id, &agent.agent_id, &now.to_string(), &format!("{code:?}")],
            ),
            hint_id: hint_id.to_string(),
            agent_id: agent.agent_id.clone(),
            decided_at_unix: now,
            code,
            accepted,
            daily_spend_before_musd_micros: daily_spend,
            reason,
        };
        self.append(ResearchPayload::Decision {
            decision: decision.clone(),
        })?;

        let job_intent = if accepted {
            let intent = JobIntent {
                schema_version: SCHEMA_VERSION,
                job_intent_id: stable_id(
                    "terrjob",
                    &[hint_id, &agent.agent_id, &hint.source_hash],
                ),
                // JobIntent reuses opportunity_id as the causal provenance ID.
                opportunity_id: hint_id.to_string(),
                agent_id: agent.agent_id.clone(),
                job_type: hint.requested_job_type.clone(),
                input_hash: format!("blake3:{}", hint.source_hash),
                max_cost_musd_micros: hint.requested_job_cost_musd_micros,
                deadline_unix: hint.expires_at_unix,
                verification: VerificationMode::DeterministicHash,
                created_at_unix: now,
            };
            self.append(ResearchPayload::JobPlan {
                intent: intent.clone(),
            })?;
            Some(intent)
        } else {
            None
        };

        Ok(TerrResearchPlan {
            job_request_template: job_intent.as_ref().map(JobIntent::as_job_request),
            decision,
            job_intent,
        })
    }

    pub fn hint(&self, hint_id: &str) -> Result<Option<TerrResearchHint>> {
        Ok(self.records()?.into_iter().find_map(|r| match r.payload {
            ResearchPayload::Hint { hint } if hint.hint_id == hint_id => Some(hint),
            _ => None,
        }))
    }

    pub fn decision(&self, hint_id: &str) -> Result<Option<TerrResearchDecision>> {
        Ok(self.records()?.into_iter().find_map(|r| match r.payload {
            ResearchPayload::Decision { decision } if decision.hint_id == hint_id => {
                Some(decision)
            }
            _ => None,
        }))
    }

    pub fn job_plan(&self, hint_id: &str) -> Result<Option<JobIntent>> {
        Ok(self.records()?.into_iter().find_map(|r| match r.payload {
            ResearchPayload::JobPlan { intent } if intent.opportunity_id == hint_id => {
                Some(intent)
            }
            _ => None,
        }))
    }

    pub fn job_plans(&self) -> Result<Vec<JobIntent>> {
        Ok(self
            .records()?
            .into_iter()
            .filter_map(|r| match r.payload {
                ResearchPayload::JobPlan { intent } => Some(intent),
                _ => None,
            })
            .collect())
    }

    pub fn summary(&self) -> Result<TerrResearchSummary> {
        let records = self.records()?;
        let mut hints = 0;
        let mut accepted = 0;
        let mut rejected = 0;
        let mut jobs = 0;
        let mut spend = 0u64;

        for r in &records {
            match &r.payload {
                ResearchPayload::Hint { .. } => hints += 1,
                ResearchPayload::Decision { decision } => {
                    if decision.accepted {
                        accepted += 1;
                    } else {
                        rejected += 1;
                    }
                }
                ResearchPayload::JobPlan { intent } => {
                    jobs += 1;
                    spend = spend.saturating_add(intent.max_cost_musd_micros);
                }
            }
        }

        Ok(TerrResearchSummary {
            hints,
            accepted,
            rejected,
            job_plans: jobs,
            committed_research_spend_musd: spend as f64 / 1_000_000.0,
            ledger_valid: true,
            head_hash: records
                .last()
                .map(|r| r.record_hash.clone())
                .unwrap_or_else(|| TERR_RESEARCH_GENESIS_HASH.to_string()),
        })
    }

    fn records(&self) -> Result<Vec<ResearchRecord>> {
        // The lock covers the whole read: the head anchor is a second file, and
        // reading both outside one critical section can compare them at
        // different instants and return a phantom "truncated" verdict. The
        // append path uses `read_records` — it already holds this lock, which is
        // not reentrant.
        let _lock = crate::durability::LedgerLock::acquire_timeout(
            &self.root,
            TERR_RESEARCH_LEDGER_FILE,
            crate::durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery =
            crate::durability::recover_torn_tail(&self.ledger_path(), "TERR research ledger")?;
        let records = self.read_records()?;
        self.verify_head(&records)?;
        if let Some(torn) = recovery {
            let head = records
                .last()
                .map_or(TERR_RESEARCH_GENESIS_HASH, |r| r.record_hash.as_str());
            crate::durability::store_head_anchor(
                &self.root,
                TERR_RESEARCH_LEDGER_FILE,
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
    fn verify_head(&self, records: &[ResearchRecord]) -> Result<()> {
        let anchor = crate::durability::read_head_anchor(&self.root, TERR_RESEARCH_LEDGER_FILE)?;
        let head = records
            .last()
            .map_or(TERR_RESEARCH_GENESIS_HASH, |r| r.record_hash.as_str());
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
            "TERR research ledger",
        )
    }

    fn read_records(&self) -> Result<Vec<ResearchRecord>> {
        let path = self.ledger_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(path)?;
        let mut out = Vec::new();
        let mut expected_seq = 1u64;
        let mut expected_prev = TERR_RESEARCH_GENESIS_HASH.to_string();

        for (idx, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: ResearchRecord = serde_json::from_str(&line).map_err(|e| {
                EconomyError::Invalid(format!(
                    "TERR research ledger line {} cannot be parsed: {}",
                    idx + 1,
                    e
                ))
            })?;
            if record.sequence != expected_seq {
                return Err(EconomyError::Invalid(format!(
                    "TERR research sequence mismatch: expected {}, got {}",
                    expected_seq, record.sequence
                )));
            }
            if record.prev_hash != expected_prev {
                return Err(EconomyError::Invalid(format!(
                    "TERR research hash-chain break at sequence {}",
                    record.sequence
                )));
            }
            let computed = record.computed_hash()?;
            if record.record_hash != computed {
                return Err(EconomyError::Invalid(format!(
                    "TERR research hash mismatch at sequence {}",
                    record.sequence
                )));
            }
            expected_prev = record.record_hash.clone();
            expected_seq += 1;
            out.push(record);
        }
        Ok(out)
    }

    fn append(&self, payload: ResearchPayload) -> Result<()> {
        // Lock across read-tail → derive → write, not just the write.
        let _lock = crate::durability::LedgerLock::acquire_timeout(
            &self.root,
            TERR_RESEARCH_LEDGER_FILE,
            crate::durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery = crate::durability::recover_torn_tail(
            &self.ledger_path(),
            "TERR research ledger",
        )?;

        let existing = self.read_records()?;
        let mut record = ResearchRecord {
            sequence: existing.last().map(|r| r.sequence + 1).unwrap_or(1),
            recorded_at_unix: now_unix(),
            prev_hash: existing
                .last()
                .map(|r| r.record_hash.clone())
                .unwrap_or_else(|| TERR_RESEARCH_GENESIS_HASH.to_string()),
            record_hash: String::new(),
            payload,
        };
        record.record_hash = record.computed_hash()?;
        // One buffer, one `write_all`, one `sync_data`.
        let line = serde_json::to_vec(&record)?;
        crate::durability::append_line(&self.ledger_path(), &line)?;
        crate::durability::store_head_anchor(
            &self.root,
            TERR_RESEARCH_LEDGER_FILE,
            record.sequence,
            &record.record_hash,
            recovery.map(|t| t.report(now_unix())),
        )
    }
}

pub fn import_terr_snapshot(
    path: impl AsRef<Path>,
    agent_id: &str,
    requested_job_type: JobType,
    requested_job_cost_musd_micros: u64,
    ttl_seconds: u64,
) -> Result<TerrResearchHint> {
    if agent_id.trim().is_empty() {
        return Err(EconomyError::Invalid(
            "TERR research import requires agent_id".into(),
        ));
    }
    if requested_job_cost_musd_micros == 0 || ttl_seconds == 0 {
        return Err(EconomyError::Invalid(
            "TERR research job cost and TTL must be > 0".into(),
        ));
    }

    let bytes = fs::read(path.as_ref())?;
    let source_hash = blake3::hash(&bytes).to_hex().to_string();
    let value: Value = serde_json::from_slice(&bytes)?;

    let (source_format, timestamp, terr, passive_only, influences_execution) =
        if value.get("kind").and_then(Value::as_str) == Some("TERR_CAUSAL_SNAPSHOT") {
            if value.get("schema_version").and_then(Value::as_u64) != Some(2) {
                return Err(EconomyError::Invalid(
                    "TERR causal snapshot schema_version must be 2".into(),
                ));
            }
            if value.get("causal_only").and_then(Value::as_bool) != Some(true)
                || value.get("lookahead_used").and_then(Value::as_bool) != Some(false)
            {
                return Err(EconomyError::Invalid(
                    "TERR snapshot must be causal_only with lookahead_used=false".into(),
                ));
            }
            (
                "terr_causal_snapshot".to_string(),
                finite_timestamp(&value, "timestamp_unix")?,
                value
                    .get("terr")
                    .ok_or_else(|| EconomyError::Invalid(
                        "TERR snapshot missing terr object".into(),
                    ))?
                    .clone(),
                true,
                false,
            )
        } else {
            if value.get("status").and_then(Value::as_str) != Some("READY") {
                return Err(EconomyError::Invalid(
                    "TERR context is not READY".into(),
                ));
            }
            let passive = value.get("passive_only").and_then(Value::as_bool)
                == Some(true);
            let influences = value
                .get("influences_execution")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if !passive || influences {
                return Err(EconomyError::Invalid(
                    "TERR context must be passive_only and not influence execution".into(),
                ));
            }
            (
                "s1_terr_context".to_string(),
                finite_timestamp(&value, "timestamp_unix")?,
                value
                    .get("terr")
                    .ok_or_else(|| EconomyError::Invalid(
                        "TERR context missing terr object".into(),
                    ))?
                    .clone(),
                passive,
                influences,
            )
        };

    let transition = finite_metric(&terr, "T_transition_probability")?;
    let uncertainty = finite_metric(&terr, "U_uncertainty")?;
    let direction = finite_metric(&terr, "D_direction")?;
    let terr_score = finite_metric(&terr, "S_terr_score")?;
    let expected_sigma = finite_metric(&terr, "V_expected_sigma")?;
    let tau = terr
        .get("tau_expected_bars")
        .and_then(Value::as_u64)
        .ok_or_else(|| EconomyError::Invalid(
            "TERR tau_expected_bars must be a positive integer".into(),
        ))?;
    let attractor_flux = finite_metric(&terr, "attractor_flux")?;

    if !(0.0..=1.0).contains(&transition)
        || !(0.0..=1.0).contains(&uncertainty)
        || !(-1.0..=1.0).contains(&direction)
        || !(-1.0..=1.0).contains(&terr_score)
        || expected_sigma < 0.0
        || tau == 0
    {
        return Err(EconomyError::Invalid(
            "TERR metrics outside causal runtime bounds".into(),
        ));
    }

    let hint_id = stable_id(
        "terrhint",
        &[
            agent_id,
            &source_hash,
            &timestamp.to_string(),
            &format!("{requested_job_type:?}"),
        ],
    );

    Ok(TerrResearchHint {
        schema_version: SCHEMA_VERSION,
        hint_id,
        agent_id: agent_id.to_string(),
        source_hash,
        source_format,
        source_timestamp_unix: timestamp,
        expires_at_unix: timestamp.saturating_add(ttl_seconds),
        requested_job_type,
        requested_job_cost_musd_micros,
        transition_probability: transition,
        uncertainty,
        direction,
        terr_score,
        expected_sigma,
        tau_expected_bars: tau,
        attractor_flux,
        passive_only,
        influences_execution,
    })
}

fn finite_timestamp(v: &Value, key: &str) -> Result<u64> {
    let x = v
        .get(key)
        .and_then(Value::as_f64)
        .ok_or_else(|| EconomyError::Invalid(format!(
            "TERR {key} must be numeric"
        )))?;
    if !x.is_finite() || x < 0.0 || x > u64::MAX as f64 {
        return Err(EconomyError::Invalid(format!(
            "TERR {key} is invalid"
        )));
    }
    Ok(x.floor() as u64)
}

fn finite_metric(v: &Value, key: &str) -> Result<f64> {
    let x = v
        .get(key)
        .and_then(Value::as_f64)
        .ok_or_else(|| EconomyError::Invalid(format!(
            "TERR metric {key} missing or non-numeric"
        )))?;
    if !x.is_finite() {
        return Err(EconomyError::Invalid(format!(
            "TERR metric {key} is non-finite"
        )));
    }
    Ok(x)
}

fn validate_hint(h: &TerrResearchHint) -> Result<()> {
    if h.agent_id.trim().is_empty() || h.source_hash.trim().is_empty() {
        return Err(EconomyError::Invalid(
            "TERR hint identity/source cannot be empty".into(),
        ));
    }
    if !h.passive_only || h.influences_execution {
        return Err(EconomyError::Invalid(
            "TERR research hint must remain passive-only".into(),
        ));
    }
    if h.expires_at_unix <= h.source_timestamp_unix {
        return Err(EconomyError::Invalid(
            "TERR research hint expiry must follow source timestamp".into(),
        ));
    }
    Ok(())
}

fn validate_policy(p: &TerrResearchPolicy) -> Result<()> {
    if !(0.0..=1.0).contains(&p.min_transition_probability)
        || !(0.0..=1.0).contains(&p.max_uncertainty)
        || !(0.0..=1.0).contains(&p.min_abs_terr_score)
    {
        return Err(EconomyError::Invalid(
            "TERR research policy thresholds must be in [0,1]".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autonomy::{RiskProfile};
    use tempfile::tempdir;

    fn research_agent() -> EconomicAgentManifest {
        EconomicAgentManifest {
            schema_version: SCHEMA_VERSION,
            agent_id: "terr-research".into(),
            public_key: "ed25519:terr".into(),
            agent_class: AgentClass::Research,
            allowed_job_types: vec![
                JobType::Validation,
                JobType::Backtest,
                JobType::DataTransform,
            ],
            daily_budget_musd_micros: 10_000_000,
            max_job_cost_musd_micros: 1_000_000,
            risk_profile: RiskProfile::Experimental,
            enabled: true,
            created_at_unix: 1_700_000_000,
        }
    }

    fn snapshot_json() -> String {
        serde_json::json!({
            "schema_version": 2,
            "kind": "TERR_CAUSAL_SNAPSHOT",
            "causal_only": true,
            "lookahead_used": false,
            "timestamp_unix": 1700000100.0,
            "samples": 600,
            "terr": {
                "T_transition_probability": 0.70,
                "U_uncertainty": 0.20,
                "D_direction": 0.35,
                "S_terr_score": 0.245,
                "V_expected_sigma": 1.1,
                "tau_expected_bars": 8,
                "attractor_flux": 0.12
            }
        })
        .to_string()
    }

    fn write_snapshot() -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("terr.json");
        fs::write(&path, snapshot_json()).unwrap();
        (dir, path)
    }

    #[test]
    fn causal_snapshot_imports_as_passive_research_hint() {
        let (_dir, path) = write_snapshot();
        let hint = import_terr_snapshot(
            &path,
            "terr-research",
            JobType::Validation,
            100_000,
            300,
        )
        .unwrap();
        assert!(hint.passive_only);
        assert!(!hint.influences_execution);
        assert_eq!(hint.transition_probability, 0.70);
    }

    #[test]
    fn strong_hint_creates_internal_research_job() {
        let (_srcdir, path) = write_snapshot();
        let hint = import_terr_snapshot(
            &path,
            "terr-research",
            JobType::Validation,
            100_000,
            300,
        )
        .unwrap();
        let dir = tempdir().unwrap();
        let engine = TerrResearchEngine::open(dir.path()).unwrap();
        engine.record_hint(hint.clone()).unwrap();
        let plan = engine
            .orchestrate(
                &hint.hint_id,
                &research_agent(),
                &TerrResearchPolicy::default(),
                1_700_000_150,
            )
            .unwrap();
        assert!(plan.decision.accepted);
        let req = plan.job_request_template.unwrap();
        assert!(req.internal_work);
        assert_eq!(req.requester_id, "terr-research");
        assert_eq!(req.job_type, JobType::Validation);
    }

    #[test]
    fn weak_or_uncertain_hint_is_rejected() {
        let (_srcdir, path) = write_snapshot();
        let mut hint = import_terr_snapshot(
            &path,
            "terr-research",
            JobType::Validation,
            100_000,
            300,
        )
        .unwrap();
        hint.transition_probability = 0.05;
        let dir = tempdir().unwrap();
        let engine = TerrResearchEngine::open(dir.path()).unwrap();
        engine.record_hint(hint.clone()).unwrap();
        let plan = engine
            .orchestrate(
                &hint.hint_id,
                &research_agent(),
                &TerrResearchPolicy::default(),
                1_700_000_150,
            )
            .unwrap();
        assert_eq!(plan.decision.code, ResearchDecisionCode::WeakTransition);
        assert!(plan.job_intent.is_none());
    }

    #[test]
    fn terr_cannot_request_financial_execution_job() {
        let (_srcdir, path) = write_snapshot();
        let hint = import_terr_snapshot(
            &path,
            "terr-research",
            JobType::Quote,
            100_000,
            300,
        )
        .unwrap();
        let dir = tempdir().unwrap();
        let engine = TerrResearchEngine::open(dir.path()).unwrap();
        engine.record_hint(hint.clone()).unwrap();
        let mut agent = research_agent();
        agent.allowed_job_types.push(JobType::Quote);
        let plan = engine
            .orchestrate(
                &hint.hint_id,
                &agent,
                &TerrResearchPolicy::default(),
                1_700_000_150,
            )
            .unwrap();
        assert_eq!(
            plan.decision.code,
            ResearchDecisionCode::InvalidResearchJobType
        );
        assert!(!plan.decision.accepted);
    }

    #[test]
    fn noncausal_snapshot_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("terr.json");
        let mut v: Value = serde_json::from_str(&snapshot_json()).unwrap();
        v["lookahead_used"] = Value::Bool(true);
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(import_terr_snapshot(
            &path,
            "terr-research",
            JobType::Validation,
            100_000,
            300,
        )
        .is_err());
    }
}
