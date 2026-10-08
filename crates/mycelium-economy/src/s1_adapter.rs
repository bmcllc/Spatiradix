//! Read-only adapter from S1 shadow-scan JSON into Mycelium opportunities.
//!
//! S1 modeled candidates are opportunities, never realized external value.
//! This adapter refuses unmeasured files, broadcast artifacts and files that
//! claim the modeled profit is already real.

use crate::{
    autonomy::OpportunityCandidate, stable_id, EconomyError, JobType, Result,
    SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone, Deserialize)]
struct S1EdgeReport {
    #[serde(rename = "chainId")]
    chain_id: u64,
    measured: bool,
    broadcast: bool,
    #[serde(rename = "profitIsReal")]
    profit_is_real: bool,
    #[serde(rename = "candidateDetail", default)]
    candidate_detail: Vec<S1Candidate>,
    #[serde(rename = "firstBlock")]
    first_block: Option<u64>,
    #[serde(rename = "lastBlock")]
    last_block: Option<u64>,
    mode: Option<String>,
    verdict: Option<String>,
    result: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct S1Candidate {
    index: Option<u64>,
    economics: Option<S1Economics>,
    observation: Option<Value>,
    verdict: Option<String>,
    reasons: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
struct S1Economics {
    #[serde(rename = "modeledBeneficiaryProfitUSDC")]
    modeled_beneficiary_profit_usdc: i64,
    #[serde(rename = "networkCostUSDC")]
    network_cost_usdc: Option<u64>,
    #[serde(rename = "principalUSDC")]
    principal_usdc: Option<u64>,
    #[serde(rename = "safetyMarginUSDC")]
    safety_margin_usdc: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S1ImportReport {
    pub source_path: String,
    pub source_hash: String,
    pub chain_id: u64,
    pub measured: bool,
    pub broadcast: bool,
    pub profit_is_real: bool,
    pub imported: usize,
    pub opportunities: Vec<OpportunityCandidate>,
}

pub fn import_shadow_scan(
    path: impl AsRef<Path>,
    agent_id: &str,
    estimated_job_cost_musd_micros: u64,
    observed_at_unix: u64,
    ttl_seconds: u64,
) -> Result<S1ImportReport> {
    if agent_id.trim().is_empty() {
        return Err(EconomyError::Invalid(
            "S1 import requires a non-empty agent_id".into(),
        ));
    }
    if estimated_job_cost_musd_micros == 0 {
        return Err(EconomyError::Invalid(
            "S1 import estimated job cost must be > 0".into(),
        ));
    }
    if ttl_seconds == 0 {
        return Err(EconomyError::Invalid(
            "S1 import TTL must be > 0".into(),
        ));
    }

    let path = path.as_ref();
    let bytes = fs::read(path)?;
    let source_hash = blake3::hash(&bytes).to_hex().to_string();
    let report: S1EdgeReport = serde_json::from_slice(&bytes)?;

    if report.chain_id != 8453 {
        return Err(EconomyError::Invalid(format!(
            "S1 report chainId must be 8453, got {}",
            report.chain_id
        )));
    }
    if !report.measured {
        return Err(EconomyError::Invalid(
            "S1 report has no completed measurement".into(),
        ));
    }
    if report.broadcast {
        return Err(EconomyError::Invalid(
            "S1 opportunity import only accepts non-broadcast shadow evidence".into(),
        ));
    }
    if report.profit_is_real {
        return Err(EconomyError::Invalid(
            "S1 shadow importer refuses profitIsReal=true; realized value requires a separate reconciler"
                .into(),
        ));
    }
    if report.candidate_detail.is_empty() {
        return Err(EconomyError::Invalid(
            "S1 report contains no candidateDetail entries".into(),
        ));
    }

    let expires_at_unix = observed_at_unix.saturating_add(ttl_seconds);
    let mut opportunities = Vec::with_capacity(report.candidate_detail.len());

    for (position, candidate) in report.candidate_detail.into_iter().enumerate() {
        let economics = candidate.economics.ok_or_else(|| {
            EconomyError::Invalid(format!(
                "S1 candidate {} missing economics",
                position
            ))
        })?;
        let candidate_index = candidate.index.unwrap_or(position as u64);
        let modeled_profit = economics.modeled_beneficiary_profit_usdc;
        // S1's modeled beneficiary profit is already after its external cost
        // and safety model. We do NOT subtract network cost a second time.
        // Negative modeled value maps to zero expected gross so the Mycelium
        // job cost alone is sufficient to reject it. The signed value remains
        // in metadata for diagnostics.
        let expected_value = modeled_profit.max(0) as u64;

        let evidence_hash = format!(
            "blake3:{}",
            blake3::hash(
                format!("{}:{}", source_hash, candidate_index).as_bytes()
            )
            .to_hex()
        );
        let opportunity_id = stable_id(
            "s1opp",
            &[
                agent_id,
                &source_hash,
                &candidate_index.to_string(),
                &observed_at_unix.to_string(),
            ],
        );

        let mut metadata = BTreeMap::new();
        metadata.insert("source".into(), "s1_shadow_scan".into());
        metadata.insert("source_hash".into(), source_hash.clone());
        metadata.insert(
            "modeled_beneficiary_profit_usdc_raw".into(),
            modeled_profit.to_string(),
        );
        metadata.insert(
            "network_cost_usdc_raw".into(),
            economics.network_cost_usdc.unwrap_or(0).to_string(),
        );
        metadata.insert(
            "principal_usdc_raw".into(),
            economics.principal_usdc.unwrap_or(0).to_string(),
        );
        metadata.insert(
            "safety_margin_usdc_raw".into(),
            economics.safety_margin_usdc.unwrap_or(0).to_string(),
        );
        metadata.insert(
            "s1_candidate_verdict".into(),
            candidate.verdict.unwrap_or_else(|| "UNKNOWN".into()),
        );
        metadata.insert(
            "s1_reasons".into(),
            candidate.reasons.unwrap_or_default().join(","),
        );
        metadata.insert(
            "s1_report_verdict".into(),
            report.verdict.clone().unwrap_or_default(),
        );
        metadata.insert(
            "s1_report_result".into(),
            report.result.clone().unwrap_or_default(),
        );
        metadata.insert(
            "s1_mode".into(),
            report.mode.clone().unwrap_or_default(),
        );
        metadata.insert(
            "first_block".into(),
            report.first_block.unwrap_or(0).to_string(),
        );
        metadata.insert(
            "last_block".into(),
            report.last_block.unwrap_or(0).to_string(),
        );
        if let Some(observation) = candidate.observation {
            metadata.insert(
                "observation_hash".into(),
                format!(
                    "blake3:{}",
                    blake3::hash(&serde_json::to_vec(&observation)?).to_hex()
                ),
            );
        }

        opportunities.push(OpportunityCandidate {
            schema_version: SCHEMA_VERSION,
            opportunity_id,
            agent_id: agent_id.to_string(),
            observed_at_unix,
            expires_at_unix,
            job_type: JobType::Simulation,
            input_hash: evidence_hash.clone(),
            evidence_hash,
            expected_gross_musd_micros: expected_value,
            // Already reflected by modeledBeneficiaryProfitUSDC.
            expected_external_cost_musd_micros: 0,
            estimated_job_cost_musd_micros,
            // S1 safety margin is already reflected by its modeled profit.
            risk_buffer_musd_micros: 0,
            metadata,
        });
    }

    Ok(S1ImportReport {
        source_path: path.display().to_string(),
        source_hash,
        chain_id: report.chain_id,
        measured: report.measured,
        broadcast: report.broadcast,
        profit_is_real: report.profit_is_real,
        imported: opportunities.len(),
        opportunities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_report(json: &str) -> std::path::PathBuf {
        let dir = tempdir().unwrap();
        let path = dir.path().join("report.json");
        fs::write(&path, json).unwrap();
        // Keep the file after TempDir drops.
        //
        // The pid is part of the name on purpose: keying the path by content
        // alone means two test binaries running at the same moment — or two
        // tests sharing a fixture — copy over each other's file and then read
        // back whatever the other one wrote, which surfaces as an unrelated
        // assertion failure in whoever loses the race.
        let keep = std::env::temp_dir().join(format!(
            "s1-adapter-test-{}-{}.json",
            std::process::id(),
            blake3::hash(json.as_bytes()).to_hex()
        ));
        fs::copy(path, &keep).unwrap();
        keep
    }

    #[test]
    fn imports_measured_shadow_candidate_without_calling_it_real_profit() {
        let path = write_report(
            r#"{
              "chainId":8453,
              "measured":true,
              "broadcast":false,
              "profitIsReal":false,
              "candidateDetail":[{
                "index":0,
                "economics":{
                  "modeledBeneficiaryProfitUSDC":2500000,
                  "networkCostUSDC":12900,
                  "principalUSDC":10000000,
                  "safetyMarginUSDC":500000
                },
                "observation":{"amount_usdc_raw":10000000},
                "verdict":"CANDIDATE",
                "reasons":[]
              }],
              "firstBlock":1,
              "lastBlock":1,
              "mode":"read_only_shadow_scan",
              "verdict":"CANDIDATE",
              "result":"EDGE"
            }"#,
        );
        let report =
            import_shadow_scan(&path, "s1", 100_000, 1000, 60).unwrap();
        assert_eq!(report.imported, 1);
        let opp = &report.opportunities[0];
        assert_eq!(opp.expected_gross_musd_micros, 2_500_000);
        assert_eq!(opp.expected_external_cost_musd_micros, 0);
        assert_eq!(opp.risk_buffer_musd_micros, 0);
        assert_eq!(opp.estimated_job_cost_musd_micros, 100_000);
        assert_eq!(
            opp.metadata["modeled_beneficiary_profit_usdc_raw"],
            "2500000"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn negative_modeled_profit_becomes_non_actionable_expected_value() {
        let path = write_report(
            r#"{
              "chainId":8453,
              "measured":true,
              "broadcast":false,
              "profitIsReal":false,
              "candidateDetail":[{
                "index":0,
                "economics":{
                  "modeledBeneficiaryProfitUSDC":-721258,
                  "networkCostUSDC":12900,
                  "principalUSDC":10000000,
                  "safetyMarginUSDC":500000
                },
                "verdict":"REJECTED",
                "reasons":["NO_GROSS_EDGE"]
              }]
            }"#,
        );
        let report =
            import_shadow_scan(&path, "s1", 50_000, 1000, 60).unwrap();
        assert_eq!(report.opportunities[0].expected_gross_musd_micros, 0);
        assert_eq!(
            report.opportunities[0].metadata["modeled_beneficiary_profit_usdc_raw"],
            "-721258"
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_unmeasured_report() {
        let path = write_report(
            r#"{
              "chainId":8453,
              "measured":false,
              "broadcast":false,
              "profitIsReal":false,
              "candidateDetail":[]
            }"#,
        );
        let err =
            import_shadow_scan(&path, "s1", 50_000, 1000, 60).unwrap_err();
        assert!(err.to_string().contains("no completed measurement"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_profit_is_real_claim_in_shadow_importer() {
        let path = write_report(
            r#"{
              "chainId":8453,
              "measured":true,
              "broadcast":false,
              "profitIsReal":true,
              "candidateDetail":[{"economics":{
                "modeledBeneficiaryProfitUSDC":1,
                "networkCostUSDC":0,
                "principalUSDC":1,
                "safetyMarginUSDC":0
              }}]
            }"#,
        );
        let err =
            import_shadow_scan(&path, "s1", 50_000, 1000, 60).unwrap_err();
        assert!(err.to_string().contains("separate reconciler"));
        let _ = fs::remove_file(path);
    }
}
