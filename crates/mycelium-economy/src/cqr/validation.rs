//! CQR Validation and Reproducibility Harness.
//!
//! Enforces the epistemic separation of validation levels:
//! 1. `NumericalValidity`: Integrator convergence, symplectic volume preservation, bounded energy drift.
//! 2. `PhysicalKnownAnswerValidity`: Agreement with analytical known solutions (e.g. normal mode frequencies).
//! 3. `Reproducibility`: Bitwise or tolerance-bound identical results across multiple executions.
//! 4. `ScientificInterpretation`: Non-authoritative theoretical hypothesis exploration (cannot be used for economic authority).

use super::job::CqrJobSpec;
use super::oscillators::{
    run_benchmark_with_thermal, CoupledOscillators, SystemThermalSource, ThermalSource,
};
use super::kernel::{HamiltonianSystem, PhaseSpacePoint};
use serde::{Deserialize, Serialize};

/// Epistemic validation levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationLevel {
    NumericalValidity,
    PhysicalKnownAnswerValidity,
    Reproducibility,
    ScientificInterpretation,
}

/// Comprehensive report of CQR validation checks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CqrValidationReport {
    pub job_id: String,
    pub numerical_valid: bool,
    pub physical_known_answer_valid: bool,
    pub bitwise_reproducible: bool,
    pub energy_drift_fraction: f64,
    pub frequency_error_max: f64,
    pub details: Vec<String>,
}

/// Runs full validation harness on a CQR benchmark job with an injected
/// [`ThermalSource`].
///
/// The thermal source is a parameter so a caller can drive the harness
/// deterministically: a test can pin a cool reading instead of inheriting
/// whatever this host's sensors report. Only the *source* of the reading
/// changes — every check below runs identically on this entry point and on
/// [`validate_job`], and the error strings are the ones the executions
/// produce.
pub fn validate_job_with_thermal(
    spec: &CqrJobSpec,
    initial_state: &PhaseSpacePoint,
    thermal_source: &dyn ThermalSource,
) -> Result<CqrValidationReport, String> {
    let mut details = Vec::new();

    // 1. Run primary execution
    let run1 = run_benchmark_with_thermal(spec, initial_state.clone(), thermal_source)
        .map(|(result, _)| result)
        .map_err(|e| e.to_string())?;

    // 2. Run secondary execution for reproducibility check
    let run2 = run_benchmark_with_thermal(spec, initial_state.clone(), thermal_source)
        .map(|(result, _)| result)
        .map_err(|e| e.to_string())?;

    let bitwise_reproducible = run1.output_state_hash == run2.output_state_hash
        && run1.observables_hash == run2.observables_hash
        && run1.result_digest == run2.result_digest;

    if bitwise_reproducible {
        details.push("reproducibility passed: independent runs produced bitwise identical digests".into());
    } else {
        details.push("reproducibility failed: independent runs produced diverging digests".into());
    }

    let numerical_valid = run1.validation_passed;
    if numerical_valid {
        details.push(format!(
            "numerical validity passed: energy drift {:.2e}",
            run1.observables.energy_drift_fraction
        ));
    } else {
        details.push(format!(
            "numerical validity failed: energy drift {:.2e}",
            run1.observables.energy_drift_fraction
        ));
    }

    // 3. Known-answer check: compare normal mode frequency with analytical dispersion
    let system = CoupledOscillators::new(
        spec.classical_spec.oscillator_count,
        spec.classical_spec.mass,
        spec.classical_spec.spring_constant,
        spec.classical_spec.periodic_boundary,
    );
    let analytical_omega1 = system.normal_mode_frequency(1);
    // Measure the implemented force operator on a periodic normal mode.
    // This checks dispersion, not trajectory convergence or experimental physics.
    let mode: Vec<f64> = (0..system.n)
        .map(|i| (2.0 * std::f64::consts::PI * i as f64 / system.n as f64).cos())
        .collect();
    let forces = system.compute_forces(&mode);
    let norm: f64 = mode.iter().map(|q| q * q).sum();
    let omega_squared = -mode.iter().zip(&forces).map(|(q, f)| q * f).sum::<f64>()
        / (system.mass * norm);
    let measured_omega = omega_squared.sqrt();
    let frequency_error_max = (measured_omega - analytical_omega1).abs();
    let allowed_error = spec.tolerance_policy.absolute_tolerance
        + spec.tolerance_policy.relative_tolerance * analytical_omega1.abs();
    let physical_known_answer_valid = system.periodic
        && measured_omega.is_finite()
        && frequency_error_max <= allowed_error;

    details.push(format!(
        "periodic force-operator mode 1: analytical {analytical_omega1:.8} rad/s, measured {measured_omega:.8} rad/s, absolute error {frequency_error_max:.2e} rad/s; passed={physical_known_answer_valid} (nonperiodic boundaries unsupported)"
    ));

    Ok(CqrValidationReport {
        job_id: spec.job_id.clone(),
        numerical_valid,
        physical_known_answer_valid,
        bitwise_reproducible,
        energy_drift_fraction: run1.observables.energy_drift_fraction,
        frequency_error_max,
        details,
    })
}

/// Runs full validation harness on a CQR benchmark job.
///
/// Reads live host sensors: both executions run under
/// [`SystemThermalSource`], i.e. the machine's real thermal zones and hwmon
/// entries. The harness is therefore as warm as the host running it, which is
/// not a property of the computation under test. Pass
/// [`validate_job_with_thermal`] to inject the thermal source instead; this is
/// the same harness with the sensor-backed source and every check intact.
pub fn validate_job(
    spec: &CqrJobSpec,
    initial_state: &PhaseSpacePoint,
) -> Result<CqrValidationReport, String> {
    validate_job_with_thermal(spec, initial_state, &SystemThermalSource)
}
