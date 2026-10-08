//! Adapter from S1-MUPP local hardware state into Mycelium economy gates.
//!
//! MUPP is monotonic here: it may only reduce thermal headroom. It never
//! invents demand, lowers economic risk, authorizes capital or bypasses the
//! original MUPP thermal/execution policy.

use crate::{
    reinvestment::ReinvestmentSignals,
    scaling::ScaleTelemetry,
    EconomyError, Result, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuppAdapterPolicy {
    pub max_age_seconds: f64,
    /// H at or above this value maps to thermal_headroom=1.
    pub full_headroom_c: f64,
}

impl Default for MuppAdapterPolicy {
    fn default() -> Self {
        Self {
            max_age_seconds: 5.0,
            full_headroom_c: 20.0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct MuppState {
    schema_version: u32,
    timestamp_unix: f64,
    mode: String,
    regime: String,
    phase: String,
    #[serde(rename = "T")]
    temperature_c: Option<f64>,
    #[serde(rename = "H")]
    headroom_c: Option<f64>,
    #[serde(rename = "RecoveryDebt")]
    recovery_debt: f64,
    sensor_ok: bool,
    sensor_warmup_complete: bool,
    allow_execution: bool,
    cpu_temp_c: Option<f64>,
    gpu_temp_c: Option<f64>,
    cpu_util_pct: Option<f64>,
    gpu_util_pct: Option<f64>,
    queue: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MuppPhysicalGate {
    pub schema_version: u32,
    pub source_mode: String,
    pub timestamp_unix: f64,
    pub age_seconds: f64,
    pub fresh: bool,
    pub regime: String,
    pub phase: String,
    pub temperature_c: Option<f64>,
    pub headroom_c: Option<f64>,
    pub recovery_debt: f64,
    pub sensor_valid: bool,
    pub allow_execution: bool,
    pub cpu_temp_c: Option<f64>,
    pub gpu_temp_c: Option<f64>,
    pub cpu_util_pct: Option<f64>,
    pub gpu_util_pct: Option<f64>,
    pub queue: i64,
    pub thermal_headroom: f64,
    pub reason: String,
}

pub fn read_mupp_gate(
    path: impl AsRef<Path>,
    now_unix: f64,
    policy: &MuppAdapterPolicy,
) -> Result<MuppPhysicalGate> {
    validate_policy(policy)?;
    if !now_unix.is_finite() || now_unix < 0.0 {
        return Err(EconomyError::Invalid(
            "MUPP adapter now_unix must be finite and non-negative".into(),
        ));
    }

    let state: MuppState = serde_json::from_slice(&fs::read(path)?)?;
    if state.schema_version != 1 {
        return Err(EconomyError::Invalid(
            "unsupported MUPP state schema".into(),
        ));
    }
    if state.mode != "MUPP_LOCAL_CONTROL" {
        return Err(EconomyError::Invalid(
            "unexpected MUPP state mode".into(),
        ));
    }
    if !state.timestamp_unix.is_finite() || state.timestamp_unix < 0.0 {
        return Err(EconomyError::Invalid(
            "invalid MUPP timestamp".into(),
        ));
    }

    let age = (now_unix - state.timestamp_unix).max(0.0);
    // A future timestamp cannot establish freshness after a clock change.
    let future_timestamp = state.timestamp_unix > now_unix;
    let fresh = !future_timestamp && age <= policy.max_age_seconds;
    let sensor_valid = state.sensor_ok
        && state.sensor_warmup_complete
        && finite_optional(state.temperature_c)
        && finite_optional(state.headroom_c);

    let hard_block = !fresh
        || !sensor_valid
        || !state.allow_execution
        || matches!(state.phase.as_str(), "COLLAPSE" | "COOLDOWN");

    let thermal_headroom = if hard_block {
        0.0
    } else {
        (state.headroom_c.unwrap_or(0.0) / policy.full_headroom_c)
            .clamp(0.0, 1.0)
    };

    let reason = if future_timestamp {
        "MUPP timestamp is in the future".to_string()
    } else if !fresh {
        "MUPP state is stale".to_string()
    } else if !sensor_valid {
        "MUPP sensors are invalid or not warmed up".to_string()
    } else if matches!(state.phase.as_str(), "COLLAPSE" | "COOLDOWN") {
        "MUPP is in collapse/cooldown phase".to_string()
    } else if !state.allow_execution {
        "MUPP execution gate is closed".to_string()
    } else {
        "fresh MUPP state permits bounded thermal headroom".to_string()
    };

    Ok(MuppPhysicalGate {
        schema_version: SCHEMA_VERSION,
        source_mode: state.mode,
        timestamp_unix: state.timestamp_unix,
        age_seconds: age,
        fresh,
        regime: state.regime,
        phase: state.phase,
        temperature_c: state.temperature_c,
        headroom_c: state.headroom_c,
        recovery_debt: state.recovery_debt,
        sensor_valid,
        allow_execution: state.allow_execution,
        cpu_temp_c: state.cpu_temp_c,
        gpu_temp_c: state.gpu_temp_c,
        cpu_util_pct: state.cpu_util_pct,
        gpu_util_pct: state.gpu_util_pct,
        queue: state.queue,
        thermal_headroom,
        reason,
    })
}

pub fn merge_reinvestment_signals(
    mut signals: ReinvestmentSignals,
    gate: &MuppPhysicalGate,
) -> ReinvestmentSignals {
    // Monotonic safety composition: MUPP can only tighten the caller's
    // thermal budget, never relax it.
    signals.thermal_headroom =
        signals.thermal_headroom.min(gate.thermal_headroom);
    signals
}

pub fn merge_scale_telemetry(
    mut telemetry: ScaleTelemetry,
    gate: &MuppPhysicalGate,
) -> ScaleTelemetry {
    // CPU utilization is not EconomicEquivalent utilization and MUPP queue is
    // not automatically the paid-work queue. Only thermal headroom is merged.
    telemetry.thermal_headroom =
        telemetry.thermal_headroom.min(gate.thermal_headroom);
    telemetry
}

fn validate_policy(p: &MuppAdapterPolicy) -> Result<()> {
    if !p.max_age_seconds.is_finite()
        || p.max_age_seconds <= 0.0
        || !p.full_headroom_c.is_finite()
        || p.full_headroom_c <= 0.0
    {
        return Err(EconomyError::Invalid(
            "invalid MUPP adapter policy".into(),
        ));
    }
    Ok(())
}

fn finite_optional(v: Option<f64>) -> bool {
    v.map(|x| x.is_finite()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_state(timestamp: f64, allow: bool, h: f64) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("mupp.json");
        let value = serde_json::json!({
            "schema_version": 1,
            "timestamp_unix": timestamp,
            "mode": "MUPP_LOCAL_CONTROL",
            "regime": "ECO",
            "phase": "IDLE",
            "T": 68.0,
            "H": h,
            "RecoveryDebt": 0.0,
            "sensor_ok": true,
            "sensor_warmup_complete": true,
            "allow_execution": allow,
            "cpu_temp_c": 68.0,
            "gpu_temp_c": 50.0,
            "cpu_util_pct": 10.0,
            "gpu_util_pct": 0.0,
            "queue": 0
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        (dir, path)
    }

    #[test]
    fn fresh_safe_state_maps_headroom() {
        let (_dir, path) = write_state(100.0, true, 10.0);
        let gate = read_mupp_gate(
            &path,
            102.0,
            &MuppAdapterPolicy {
                max_age_seconds: 5.0,
                full_headroom_c: 20.0,
            },
        )
        .unwrap();
        assert!(gate.fresh);
        assert_eq!(gate.thermal_headroom, 0.5);
    }

    #[test]
    fn stale_state_fails_closed() {
        let (_dir, path) = write_state(100.0, true, 20.0);
        let gate = read_mupp_gate(&path, 200.0, &MuppAdapterPolicy::default()).unwrap();
        assert!(!gate.fresh);
        assert_eq!(gate.thermal_headroom, 0.0);
    }

    #[test]
    fn future_state_fails_closed_until_clock_catches_up() {
        let (_dir, path) = write_state(110.0, true, 20.0);
        let gate = read_mupp_gate(&path, 100.0, &MuppAdapterPolicy::default()).unwrap();
        assert!(!gate.fresh);
        assert_eq!(gate.thermal_headroom, 0.0);
        assert!(gate.reason.contains("future"));
        let recovered = read_mupp_gate(&path, 110.0, &MuppAdapterPolicy::default()).unwrap();
        assert!(recovered.fresh);
        assert_eq!(recovered.thermal_headroom, 1.0);
    }

    #[test]
    fn closed_execution_gate_fails_closed() {
        let (_dir, path) = write_state(100.0, false, 20.0);
        let gate = read_mupp_gate(&path, 101.0, &MuppAdapterPolicy::default()).unwrap();
        assert_eq!(gate.thermal_headroom, 0.0);
    }

    #[test]
    fn mupp_can_only_reduce_reinvestment_headroom() {
        let (_dir, path) = write_state(100.0, true, 10.0);
        let gate = read_mupp_gate(&path, 101.0, &MuppAdapterPolicy::default()).unwrap();
        let mut s = ReinvestmentSignals::default();
        s.thermal_headroom = 0.3;
        let merged = merge_reinvestment_signals(s, &gate);
        assert_eq!(merged.thermal_headroom, 0.3);

        let mut s2 = ReinvestmentSignals::default();
        s2.thermal_headroom = 0.9;
        let merged2 = merge_reinvestment_signals(s2, &gate);
        assert_eq!(merged2.thermal_headroom, 0.5);
    }

    #[test]
    fn mupp_does_not_redefine_economic_utilization() {
        let (_dir, path) = write_state(100.0, true, 10.0);
        let gate = read_mupp_gate(&path, 101.0, &MuppAdapterPolicy::default()).unwrap();
        let t = ScaleTelemetry {
            paid_work_musd_per_day: 10.0,
            utilization: 0.77,
            queue_depth: 3,
            queue_growth_per_hour: 1.0,
            p95_latency_ms: 500.0,
            revenue_per_equivalent_musd_per_day: 2.0,
            thermal_headroom: 0.9,
            current_capacity_equivalents: 4.0,
        };
        let merged = merge_scale_telemetry(t, &gate);
        assert_eq!(merged.utilization, 0.77);
        assert_eq!(merged.queue_depth, 3);
        assert_eq!(merged.thermal_headroom, 0.5);
    }
}
