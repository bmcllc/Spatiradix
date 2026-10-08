//! Offline CQR-C0 worker. NO signing, payments, token issuance, or network calls.
//! Independent live MUPP + hardware thermal gate even if called outside Python.
//! NOTE: For bounded local scientific compute, NOT externally verified revenue.
use mycelium_economy::{
    cqr::{
        job::{
            ClassicalSpec, CqrComputeLevel, CqrJobSpec, CqrResourceBudget, IntegratorSpec,
            PrecisionPolicy, TolerancePolicy,
        },
        kernel::PhaseSpacePoint,
        oscillators::{run_benchmark_with_telemetry, SystemThermalSource, ThermalSource},
        state_bus::hash_component,
        validation::validate_job,
    },
    mupp_adapter::{read_mupp_gate, MuppAdapterPolicy},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    io::{self, Read},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_INPUT_BYTES: u64 = 65_536;
const MAX_STEPS: u64 = 5_000;
const MAX_MEMORY_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    spec: CqrJobSpec,
    initial_state: PhaseSpacePoint,
}

fn unix_now() -> Result<f64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .map_err(|_| "invalid system time".to_string())
}

fn require_live_gate() -> Result<f64, String> {
    let gate = read_mupp_gate(
        "/tmp/s1-mupp-state.json",
        unix_now()?,
        &MuppAdapterPolicy::default(),
    )
    .map_err(|_| "S1-MUPP missing or invalid".to_string())?;
    if !gate.fresh
        || !gate.sensor_valid
        || !gate.allow_execution
        || gate.thermal_headroom <= 0.0
        || matches!(gate.phase.as_str(), "COLLAPSE" | "COOLDOWN")
    {
        return Err("independent S1-MUPP gate refused execution".into());
    }
    let temperature = SystemThermalSource
        .read_celsius()
        .map_err(|_| "hardware thermal sensor unavailable".to_string())?;
    if !temperature.is_finite() || temperature >= 75.0 {
        return Err("hardware thermal ceiling reached".into());
    }
    Ok(temperature)
}

#[cfg(target_os = "linux")]
fn install_resource_limits(spec: &CqrJobSpec) -> Result<(), String> {
    let memory = spec.resource_budget.max_memory_bytes;
    let cpu_ms = spec.resource_budget.max_cpu_time_ms;
    if !(128 * 1024 * 1024..=MAX_MEMORY_BYTES).contains(&memory) || !(1..=10_000).contains(&cpu_ms)
    {
        return Err("invalid CPU or memory budget".into());
    }
    let cpu_secs = cpu_ms.saturating_add(999) / 1000;
    let cpu_limit = libc::rlimit {
        rlim_cur: cpu_secs as libc::rlim_t,
        rlim_max: cpu_secs as libc::rlim_t,
    };
    let memory_limit = libc::rlimit {
        rlim_cur: memory as libc::rlim_t,
        rlim_max: memory as libc::rlim_t,
    };
    // SAFETY: valid initialized structs, current process only, no child workers.
    if unsafe { libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) } != 0 {
        return Err("could not enforce CPU limit".into());
    }
    if unsafe { libc::setrlimit(libc::RLIMIT_AS, &memory_limit) } != 0 {
        return Err("could not enforce memory limit".into());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_resource_limits(_spec: &CqrJobSpec) -> Result<(), String> {
    Err("resource-limited worker currently requires Linux".into())
}

fn run() -> Result<serde_json::Value, String> {
    // Gate BEFORE parsing potentially untrusted job JSON.
    require_live_gate()?;
    let mut bytes = Vec::new();
    io::stdin()
        .take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "failed reading bounded input".to_string())?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("CQR input exceeds 64 KiB".into());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "invalid CQR job JSON".to_string())?;
    let spec = &request.spec;
    if spec.schema_version != 1
        || spec.compute_level != CqrComputeLevel::C0ClassicalSymplectic
        || spec.model_id != "coupled_oscillators_64"
        || spec.model_version != "1.0.0"
        || spec.integrator_spec != IntegratorSpec::VelocityVerlet
        || spec.precision_policy != PrecisionPolicy::Float64Strict
        || !spec.classical_spec.periodic_boundary
        || spec.expected_observables.len() != 1
        || spec.expected_observables.first().map(String::as_str) != Some("energy")
        || spec.validation_suite.len() != 1
        || spec.validation_suite.first().map(String::as_str) != Some("symplectic_conservation")
        || !spec.time_step.is_finite()
        || !(0.0..=1.0).contains(&spec.time_step)
        || spec.time_step == 0.0
        || spec.classical_spec.oscillator_count != 64
        || request.initial_state.dim() != 64
        || request.initial_state.p.len() != 64
        || !(1..=MAX_STEPS).contains(&spec.step_count)
        || spec.resource_budget.max_wall_time_ms == 0
        || spec.resource_budget.max_wall_time_ms > 30_000
        || spec.resource_budget.thermal_ceiling_celsius > 75
        || spec.resource_budget.thermal_ceiling_celsius < 70
    {
        return Err("only bounded CQR-C0/64 jobs are accepted".into());
    }
    install_resource_limits(spec)?;
    require_live_gate()?;
    // The Rust CQR engine checks real sensors at step 0, during and after steps.
    let (result, thermal) =
        run_benchmark_with_telemetry(spec, request.initial_state.clone(), &SystemThermalSource)
            .map_err(|e| format!("CQR compute refused: {e}"))?;
    if !result.validation_passed {
        return Err("CQR numerical validation failed".into());
    }
    require_live_gate()?;
    let validation = validate_job(spec, &request.initial_state)
        .map_err(|e| format!("CQR reproducibility verification refused: {e}"))?;
    require_live_gate()?;
    if !validation.numerical_valid
        || !validation.physical_known_answer_valid
        || !validation.bitwise_reproducible
    {
        return Err("CQR known-answer/reproducibility validation failed".into());
    }
    Ok(json!({
        "scope": "LOCAL_CQR_C0_SCIENTIFIC_VALIDATION_NOT_EXTERNAL_SETTLEMENT",
        "job_id": spec.job_id,
        "job_hash": result.job_hash,
        "result_digest": result.result_digest,
        "validation_passed": true,
        "validation_report": validation,
        "maximum_thermal_c": thermal.maximum_c,
        "result": result,
        "received_revenue": false,
        "verified_nev": null,
        "wallet_signing": false,
        "onchain_execution": false,
    }))
}

fn sample_job() -> serde_json::Value {
    let n = 64;
    let state = PhaseSpacePoint {
        q: (0..n)
            .map(|i| {
                let angle = (i as f64 * std::f64::consts::PI) / 32.0;
                0.5 * angle.sin()
            })
            .collect(),
        p: (0..n)
            .map(|i| {
                let angle = (i as f64 * std::f64::consts::PI) / 32.0;
                0.1 * angle.cos()
            })
            .collect(),
    };
    let spec = CqrJobSpec {
        schema_version: 1,
        job_id: "cqr-c0-explicit-local-demo".into(),
        model_id: "coupled_oscillators_64".into(),
        model_version: "1.0.0".into(),
        compute_level: CqrComputeLevel::C0ClassicalSymplectic,
        initial_state_hash: hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes()),
        classical_spec: ClassicalSpec {
            oscillator_count: 64,
            mass: 1.0,
            spring_constant: 2.0,
            periodic_boundary: true,
        },
        integrator_spec: IntegratorSpec::VelocityVerlet,
        precision_policy: PrecisionPolicy::Float64Strict,
        tolerance_policy: TolerancePolicy {
            max_energy_drift_fraction: 1e-5,
            ..TolerancePolicy::default()
        },
        step_count: 45,
        time_step: 0.005,
        seed: None,
        resource_budget: CqrResourceBudget::default(),
        expected_observables: vec!["energy".into()],
        validation_suite: vec!["symplectic_conservation".into()],
    };
    json!({"spec": spec, "initial_state": state})
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() == 1 && args[0] == "--make-sample-job" {
        println!("{}", sample_job());
        return;
    }
    if !args.is_empty() {
        eprintln!("Usage: mycelium-cqr-worker [--make-sample-job]");
        std::process::exit(2);
    }
    match run() {
        Ok(output) => println!("{}", output),
        Err(reason) => {
            eprintln!("CQR worker refusal: {reason}");
            std::process::exit(2);
        }
    }
}
