//! Adapter for the native S1 PERCEPTION_SHADOW report.
//!
//! Perception is read-only evidence. A candidate may request an exact
//! simulation job, but never becomes realized external value.

use crate::{
    autonomy::OpportunityCandidate, stable_id, EconomyError, JobType, Result,
    SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S1PerceptionImportReport {
    pub source_path: String,
    pub source_hash: String,
    pub status: String,
    pub cycles_requested: u64,
    pub cycles_completed: u64,
    pub candidates_seen: usize,
    pub imported: usize,
    pub best_observed_token_edge_usdc_raw: Option<i64>,
    pub best_observed_robust_net_usdc_raw: Option<i64>,
    pub thermal_start_max_c: Option<f64>,
    pub end_temp_c: Option<f64>,
    pub broadcast: bool,
    pub anvil: bool,
    pub profit_is_real: bool,
    pub opportunities: Vec<OpportunityCandidate>,
}

pub fn import_perception_report(
    path: impl AsRef<Path>,
    agent_id: &str,
    estimated_job_cost_musd_micros: u64,
    ttl_seconds: u64,
) -> Result<S1PerceptionImportReport> {
    if agent_id.trim().is_empty() {
        return Err(EconomyError::Invalid(
            "perception import requires a non-empty agent_id".into(),
        ));
    }
    if estimated_job_cost_musd_micros == 0 || ttl_seconds == 0 {
        return Err(EconomyError::Invalid(
            "perception import job cost and TTL must be > 0".into(),
        ));
    }

    let path = path.as_ref();
    let bytes = fs::read(path)?;
    let source_hash = blake3::hash(&bytes).to_hex().to_string();
    let value: Value = serde_json::from_slice(&bytes)?;

    if value.get("mode").and_then(Value::as_str) != Some("PERCEPTION_SHADOW") {
        return Err(EconomyError::Invalid(
            "S1 report mode must be PERCEPTION_SHADOW".into(),
        ));
    }
    let broadcast = value
        .get("broadcast")
        .and_then(Value::as_bool)
        .ok_or_else(|| EconomyError::Invalid(
            "perception report missing broadcast flag".into(),
        ))?;
    let anvil = value
        .get("anvil")
        .and_then(Value::as_bool)
        .ok_or_else(|| EconomyError::Invalid(
            "perception report missing anvil flag".into(),
        ))?;
    if broadcast || anvil {
        return Err(EconomyError::Invalid(
            "perception importer accepts only read-only non-Anvil evidence".into(),
        ));
    }

    let status = value
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| EconomyError::Invalid(
            "perception report missing status".into(),
        ))?
        .to_string();

    if !matches!(
        status.as_str(),
        "COMPLETED" | "CANDIDATE_REQUIRES_EXACT_SIM"
    ) {
        return Err(EconomyError::Invalid(format!(
            "perception report did not complete: {status}"
        )));
    }

    let cycles_requested = value
        .get("cycles_requested")
        .and_then(Value::as_u64)
        .ok_or_else(|| EconomyError::Invalid(
            "perception report missing cycles_requested".into(),
        ))?;
    let cycles_completed = value
        .get("cycles_completed")
        .and_then(Value::as_u64)
        .ok_or_else(|| EconomyError::Invalid(
            "perception report missing cycles_completed".into(),
        ))?;
    if cycles_completed == 0 || cycles_completed > cycles_requested {
        return Err(EconomyError::Invalid(
            "invalid perception cycle accounting".into(),
        ));
    }

    let started_at = value
        .get("started_at")
        .and_then(Value::as_f64)
        .ok_or_else(|| EconomyError::Invalid(
            "perception report missing started_at".into(),
        ))?;
    if !started_at.is_finite() || started_at < 0.0 {
        return Err(EconomyError::Invalid(
            "invalid perception started_at".into(),
        ));
    }
    let observed_at_unix = started_at.floor() as u64;

    let events = value
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| EconomyError::Invalid(
            "perception report missing events".into(),
        ))?;

    let mut best_edge: Option<i64> = None;
    let mut best_robust: Option<i64> = None;
    for event in events {
        if let Some(near) = event.get("near_edge_refinement") {
            if let Some(v) = signed_field_any(
                near,
                &["best_refined_edge_usdc_raw", "edge_usdc_raw"],
            )? {
                best_edge = Some(best_edge.map(|x| x.max(v)).unwrap_or(v));
            }
            if let Some(v) = signed_field_any(
                near,
                &[
                    "best_refined_robust_net_usdc_raw",
                    "coarse_robust_net_usdc_raw",
                ],
            )? {
                best_robust =
                    Some(best_robust.map(|x| x.max(v)).unwrap_or(v));
            }
        }
    }

    let candidates = value
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or_else(|| EconomyError::Invalid(
            "perception report missing candidates".into(),
        ))?;

    if status == "CANDIDATE_REQUIRES_EXACT_SIM" && candidates.is_empty() {
        return Err(EconomyError::Invalid(
            "candidate status without candidate evidence".into(),
        ));
    }

    let mut opportunities = Vec::new();
    for (index, candidate) in candidates.iter().enumerate() {
        if candidate.get("status").and_then(Value::as_str)
            != Some("CANDIDATE_REQUIRES_EXACT_SIM")
        {
            return Err(EconomyError::Invalid(format!(
                "perception candidate {index} has invalid status"
            )));
        }

        let near = candidate
            .get("near_edge_refinement")
            .ok_or_else(|| EconomyError::Invalid(format!(
                "perception candidate {index} missing near_edge_refinement"
            )))?;

        let robust_net = signed_field_any(
            near,
            &[
                "best_refined_robust_net_usdc_raw",
                "coarse_robust_net_usdc_raw",
            ],
        )?
        .ok_or_else(|| EconomyError::Invalid(format!(
            "perception candidate {index} missing robust net evidence"
        )))?;

        if robust_net <= 0 {
            return Err(EconomyError::Invalid(format!(
                "perception candidate {index} has non-positive robust net"
            )));
        }

        let route_hash = candidate
            .get("route_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| EconomyError::Invalid(format!(
                "perception candidate {index} missing route_sha256"
            )))?;
        if route_hash.trim().is_empty() {
            return Err(EconomyError::Invalid(
                "perception candidate route hash is empty".into(),
            ));
        }

        let evidence_hash = format!(
            "blake3:{}",
            blake3::hash(
                format!("{source_hash}:{index}:{route_hash}").as_bytes()
            )
            .to_hex()
        );
        let opportunity_id = stable_id(
            "s1perception",
            &[
                agent_id,
                &source_hash,
                &index.to_string(),
                route_hash,
            ],
        );

        let mut metadata = BTreeMap::new();
        metadata.insert("source".into(), "s1_perception_shadow".into());
        metadata.insert("source_hash".into(), source_hash.clone());
        metadata.insert("requires_exact_sim".into(), "true".into());
        metadata.insert("profit_is_real".into(), "false".into());
        metadata.insert("route_sha256".into(), route_hash.to_string());
        metadata.insert(
            "robust_net_usdc_raw".into(),
            robust_net.to_string(),
        );
        if let Some(v) = candidate
            .get("preliminary_surplus_usdc_raw")
            .and_then(Value::as_i64)
        {
            metadata.insert(
                "preliminary_surplus_usdc_raw".into(),
                v.to_string(),
            );
        }
        if let Some(v) = candidate.get("block").and_then(Value::as_str) {
            metadata.insert("block".into(), v.to_string());
        }
        if let Some(v) = candidate
            .get("intermediate_token")
            .and_then(Value::as_str)
        {
            metadata.insert("intermediate_token".into(), v.to_string());
        }
        if let Some(v) = candidate.get("amount_usdc_raw").and_then(Value::as_u64)
        {
            metadata.insert("amount_usdc_raw".into(), v.to_string());
        }
        if let Some(v) = candidate.get("fee_pair") {
            metadata.insert("fee_pair".into(), v.to_string());
        }

        opportunities.push(OpportunityCandidate {
            schema_version: SCHEMA_VERSION,
            opportunity_id,
            agent_id: agent_id.to_string(),
            observed_at_unix,
            expires_at_unix: observed_at_unix.saturating_add(ttl_seconds),
            job_type: JobType::Simulation,
            input_hash: evidence_hash.clone(),
            evidence_hash,
            // S1 robust net already includes the S1 cost/risk model.
            expected_gross_musd_micros: robust_net as u64,
            expected_external_cost_musd_micros: 0,
            estimated_job_cost_musd_micros,
            risk_buffer_musd_micros: 0,
            metadata,
        });
    }

    Ok(S1PerceptionImportReport {
        source_path: path.display().to_string(),
        source_hash,
        status,
        cycles_requested,
        cycles_completed,
        candidates_seen: candidates.len(),
        imported: opportunities.len(),
        best_observed_token_edge_usdc_raw: best_edge,
        best_observed_robust_net_usdc_raw: best_robust,
        thermal_start_max_c: value
            .get("thermal_start_window")
            .and_then(|x| x.get("max"))
            .and_then(Value::as_f64),
        end_temp_c: value.get("end_temp_c").and_then(Value::as_f64),
        broadcast,
        anvil,
        profit_is_real: false,
        opportunities,
    })
}

fn signed_field_any(v: &Value, names: &[&str]) -> Result<Option<i64>> {
    for name in names {
        if let Some(raw) = v.get(*name) {
            if raw.is_null() {
                continue;
            }
            if let Some(n) = raw.as_i64() {
                return Ok(Some(n));
            }
            if let Some(n) = raw.as_u64() {
                if n > i64::MAX as u64 {
                    return Err(EconomyError::Invalid(format!(
                        "{name} exceeds signed 64-bit ABI"
                    )));
                }
                return Ok(Some(n as i64));
            }
            return Err(EconomyError::Invalid(format!(
                "{name} must be an integer"
            )));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(v: Value) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("perception.json");
        fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
        (dir, path)
    }

    fn completed_no_candidate() -> Value {
        serde_json::json!({
            "mode":"PERCEPTION_SHADOW",
            "broadcast":false,
            "anvil":false,
            "started_at":1700000000.0,
            "status":"COMPLETED",
            "cycles_requested":2,
            "cycles_completed":2,
            "candidates":[],
            "events":[
              {
                "cycle":1,
                "state":"IDLE",
                "near_edge_refinement":{
                  "best_refined_edge_usdc_raw":-44499,
                  "best_refined_robust_net_usdc_raw":-2044499
                }
              },
              {
                "cycle":2,
                "state":"IDLE",
                "near_edge_refinement":{
                  "edge_usdc_raw":-32674,
                  "coarse_robust_net_usdc_raw":-2032674
                }
              }
            ],
            "thermal_start_window":{"max":69.0},
            "end_temp_c":57.0
        })
    }

    #[test]
    fn completed_negative_scan_is_valid_with_zero_opportunities() {
        let (_dir, path) = write(completed_no_candidate());
        let r = import_perception_report(&path, "s1", 50_000, 120).unwrap();
        assert_eq!(r.status, "COMPLETED");
        assert_eq!(r.imported, 0);
        assert_eq!(r.candidates_seen, 0);
        assert_eq!(r.best_observed_token_edge_usdc_raw, Some(-32674));
        assert_eq!(r.best_observed_robust_net_usdc_raw, Some(-2032674));
        assert_eq!(r.thermal_start_max_c, Some(69.0));
        assert_eq!(r.end_temp_c, Some(57.0));
    }

    #[test]
    fn thermal_blocked_scan_is_not_importable() {
        let mut v = completed_no_candidate();
        v["status"] = Value::String("THERMAL_START_BLOCKED".into());
        v.as_object_mut().unwrap().remove("cycles_completed");
        let (_dir, path) = write(v);
        assert!(import_perception_report(&path, "s1", 50_000, 120).is_err());
    }

    #[test]
    fn positive_robust_candidate_becomes_exact_sim_opportunity() {
        let mut v = completed_no_candidate();
        v["status"] = Value::String("CANDIDATE_REQUIRES_EXACT_SIM".into());
        v["cycles_completed"] = serde_json::json!(1);
        v["candidates"] = serde_json::json!([{
            "status":"CANDIDATE_REQUIRES_EXACT_SIM",
            "block":"0x123",
            "intermediate_token":"0xabc",
            "fee_pair":[500,100],
            "amount_usdc_raw":10000000,
            "preliminary_surplus_usdc_raw":3000000,
            "route_sha256":"abcd",
            "near_edge_refinement":{
                "best_refined_robust_net_usdc_raw":900000
            }
        }]);
        let (_dir, path) = write(v);
        let r = import_perception_report(&path, "s1", 50_000, 120).unwrap();
        assert_eq!(r.imported, 1);
        let o = &r.opportunities[0];
        assert_eq!(o.expected_gross_musd_micros, 900_000);
        assert_eq!(o.job_type, JobType::Simulation);
        assert_eq!(o.metadata["requires_exact_sim"], "true");
        assert_eq!(o.metadata["profit_is_real"], "false");
    }

    #[test]
    fn candidate_without_positive_robust_net_is_rejected() {
        let mut v = completed_no_candidate();
        v["status"] = Value::String("CANDIDATE_REQUIRES_EXACT_SIM".into());
        v["cycles_completed"] = serde_json::json!(1);
        v["candidates"] = serde_json::json!([{
            "status":"CANDIDATE_REQUIRES_EXACT_SIM",
            "route_sha256":"abcd",
            "near_edge_refinement":{
                "best_refined_robust_net_usdc_raw":-1
            }
        }]);
        let (_dir, path) = write(v);
        assert!(import_perception_report(&path, "s1", 50_000, 120).is_err());
    }
}
