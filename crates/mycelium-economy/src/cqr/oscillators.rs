//! CQR-C0 Benchmark: 64 Coupled Harmonic Oscillators.
//!
//! # Physical Model
//!
//! Hamiltonian with periodic boundary conditions:
//! $$H = \sum_{i=0}^{N-1} \frac{p_i^2}{2m} + \sum_{i=0}^{N-1} \frac{k}{2} (q_{(i+1)\%N} - q_i)^2$$
//!
//! Equations of motion:
//! $$\dot{q}_i = \frac{p_i}{m}$$
//! $$\dot{p}_i = k (q_{(i+1)\%N} - 2q_i + q_{(i-1+N)\%N})$$
//!
//! Observables:
//! * Energy: Total $H$, Kinetic $T$, Potential $V$, drift fraction $|\Delta E / E_0|$
//! * Temperature: Equipartition $T_{\text{eff}} = \frac{1}{N} \sum_i \frac{p_i^2}{m}$
//! * Statistical Entropy: Gibbs entropy of coarse-grained phase-space distribution
//! * Quantum Interface: Subsystem entanglement entropy via symplectic spectrum
//! * Correlations: Nearest-neighbour displacement correlation trace
//! * Stress-Energy: Coarse-grained energy density profile

use super::job::CqrJobSpec;
use super::kernel::{HamiltonianSystem, PhaseSpacePoint, VelocityVerlet};
use super::result::{CqrObservables, CqrResult};
use super::state_bus::hash_component;

pub const DEFAULT_OSCILLATOR_COUNT: usize = 64;

/// 1D ring of coupled harmonic oscillators.
#[derive(Debug, Clone)]
pub struct CoupledOscillators {
    pub n: usize,
    pub mass: f64,
    pub spring_constant: f64,
    pub periodic: bool,
}

impl CoupledOscillators {
    pub fn new(n: usize, mass: f64, spring_constant: f64, periodic: bool) -> Self {
        assert!(n >= 2, "oscillator count must be >= 2");
        assert!(mass > 0.0, "mass must be positive");
        assert!(spring_constant > 0.0, "spring constant must be positive");
        Self {
            n,
            mass,
            spring_constant,
            periodic,
        }
    }

    /// Theoretical dispersion relation for normal modes:
    /// $$\omega_j = 2 \sqrt{\frac{k}{m}} \sin\left(\frac{j \pi}{N}\right)$$
    pub fn normal_mode_frequency(&self, mode_j: usize) -> f64 {
        let omega0 = (self.spring_constant / self.mass).sqrt();
        2.0 * omega0 * ((mode_j as f64 * std::f64::consts::PI) / self.n as f64).sin().abs()
    }
}

impl HamiltonianSystem for CoupledOscillators {
    fn degrees_of_freedom(&self) -> usize {
        self.n
    }

    fn kinetic_energy(&self, p: &[f64]) -> f64 {
        let mut t = 0.0;
        let factor = 0.5 / self.mass;
        for &pi in p {
            t += pi * pi * factor;
        }
        t
    }

    fn potential_energy(&self, q: &[f64]) -> f64 {
        let mut v = 0.0;
        let factor = 0.5 * self.spring_constant;
        let n = self.n;
        let limit = if self.periodic { n } else { n - 1 };

        for i in 0..limit {
            let next_i = (i + 1) % n;
            let diff = q[next_i] - q[i];
            v += diff * diff * factor;
        }
        v
    }

    fn compute_forces(&self, q: &[f64]) -> Vec<f64> {
        let n = self.n;
        let mut forces = vec![0.0; n];
        let k = self.spring_constant;

        for i in 0..n {
            let left_idx = if i == 0 {
                if self.periodic { n - 1 } else { 0 }
            } else {
                i - 1
            };
            let right_idx = if i == n - 1 {
                if self.periodic { 0 } else { n - 1 }
            } else {
                i + 1
            };

            let left_pull = if left_idx == i { 0.0 } else { k * (q[left_idx] - q[i]) };
            let right_pull = if right_idx == i { 0.0 } else { k * (q[right_idx] - q[i]) };
            forces[i] = left_pull + right_pull;
        }
        forces
    }

    fn compute_velocities(&self, p: &[f64]) -> Vec<f64> {
        let inv_m = 1.0 / self.mass;
        p.iter().map(|&pi| pi * inv_m).collect()
    }
}

/// Computes Gibbs entropy of phase space distribution using coarse-graining bins.
pub fn compute_gibbs_entropy(z: &PhaseSpacePoint, bins: usize) -> f64 {
    let n = z.dim();
    if n == 0 {
        return 0.0;
    }
    // Find bounds for momentum
    let mut min_p = f64::INFINITY;
    let mut max_p = f64::NEG_INFINITY;
    for &pi in &z.p {
        if pi < min_p { min_p = pi; }
        if pi > max_p { max_p = pi; }
    }
    if (max_p - min_p).abs() < 1e-12 {
        return 0.0;
    }

    let bin_width = (max_p - min_p) / bins as f64;
    let mut counts = vec![0usize; bins];

    for &pi in &z.p {
        let idx = (((pi - min_p) / bin_width).floor() as usize).min(bins - 1);
        counts[idx] += 1;
    }

    let mut entropy = 0.0;
    let total = n as f64;
    for &c in &counts {
        if c > 0 {
            let p_k = c as f64 / total;
            entropy -= p_k * p_k.ln();
        }
    }
    entropy
}

/// Computes bipartite subsystem entanglement entropy for a small block of size $M$.
/// In a harmonic chain, the Gaussian subsystem entanglement entropy can be extracted
/// from the covariance matrix of the subsystem degrees of freedom.
pub fn compute_subsystem_entanglement_entropy(z: &PhaseSpacePoint, subsystem_size: usize) -> f64 {
    let m = subsystem_size.min(z.dim());
    if m == 0 {
        return 0.0;
    }
    // Correlation estimate from coordinates
    let mut q_var = 0.0;
    let mut p_var = 0.0;
    for i in 0..m {
        q_var += z.q[i] * z.q[i];
        p_var += z.p[i] * z.p[i];
    }
    q_var /= m as f64;
    p_var /= m as f64;

    // Approximate symplectic eigenvalue nu = sqrt(var_q * var_p)
    let nu = (q_var * p_var).sqrt();
    if nu <= 0.5 {
        0.0
    } else {
        // von Neumann entropy for single-mode bosonic state:
        // S = (nu + 1/2) ln(nu + 1/2) - (nu - 1/2) ln(nu - 1/2)
        let c_plus = nu + 0.5;
        let c_minus = (nu - 0.5).max(1e-12);
        (c_plus * c_plus.ln()) - (c_minus * c_minus.ln())
    }
}

/// Source of hardware or simulated thermal readings in Celsius.
pub trait ThermalSource: Send + Sync {
    /// Reads the current maximum temperature in Celsius.
    fn read_celsius(&self) -> Result<f64, String>;
}

/// Real hardware thermal reader reading from Linux sysfs (/sys/class/thermal/thermal_zone*/temp).
pub struct SystemThermalSource;

impl ThermalSource for SystemThermalSource {
    fn read_celsius(&self) -> Result<f64, String> {
        let mut paths = Vec::new();
        if let Ok(entries) = std::fs::read_dir("/sys/class/thermal") {
            for entry in entries.flatten() {
                if entry.file_name().to_string_lossy().starts_with("thermal_zone") {
                    paths.push(entry.path().join("temp"));
                }
            }
        }
        // CPU package/core sensors are commonly exposed only through hwmon.
        if let Ok(entries) = std::fs::read_dir("/sys/class/hwmon") {
            for entry in entries.flatten() {
                let sensors = std::fs::read_dir(entry.path()).map_err(|e| e.to_string())?;
                for sensor in sensors {
                    let sensor = sensor.map_err(|e| e.to_string())?;
                    let name = sensor.file_name();
                    let name = name.to_string_lossy();
                    if name.starts_with("temp") && name.ends_with("_input") {
                        paths.push(sensor.path());
                    }
                }
            }
        }
        let mut maximum: Option<f64> = None;
        for path in paths {
            let content = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let value = content.trim().parse::<f64>().map_err(|e| e.to_string())? / 1000.0;
            if !value.is_finite() || !(0.0..=150.0).contains(&value) {
                return Err("invalid hardware thermal reading".into());
            }
            maximum = Some(maximum.map_or(value, |old| old.max(value)));
        }
        maximum.ok_or_else(|| "hardware thermal sensors unavailable".into())
    }
}

/// Controllable fake thermal source for tests.
pub struct FakeThermalSource {
    temperature: std::sync::atomic::AtomicU64,
}

impl FakeThermalSource {
    pub fn new(celsius: f64) -> Self {
        Self {
            temperature: std::sync::atomic::AtomicU64::new(celsius.to_bits()),
        }
    }

    pub fn set_celsius(&self, celsius: f64) {
        self.temperature.store(celsius.to_bits(), std::sync::atomic::Ordering::SeqCst);
    }
}

impl ThermalSource for FakeThermalSource {
    fn read_celsius(&self) -> Result<f64, String> {
        Ok(f64::from_bits(self.temperature.load(std::sync::atomic::Ordering::SeqCst)))
    }
}

/// Errors occurring during physical CQR computation.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum CqrExecutionError {
    #[error("thermal ceiling breached: observed {observed_c:.1} °C >= ceiling {ceiling_c:.1} °C at step {step}")]
    ThermalStop {
        observed_c: f64,
        ceiling_c: f64,
        step: usize,
    },
    #[error("thermal telemetry unavailable or invalid: {0}")]
    ThermalUnavailable(String),
    #[error("job execution aborted: wall clock timeout exceeded {0} ms")]
    Timeout(u64),
    #[error("invalid spec or state: {0}")]
    InvalidInput(String),
}

fn read_valid_temperature(source: &dyn ThermalSource) -> Result<f64, CqrExecutionError> {
    let value = source.read_celsius().map_err(CqrExecutionError::ThermalUnavailable)?;
    if !value.is_finite() || !(0.0..=150.0).contains(&value) {
        return Err(CqrExecutionError::ThermalUnavailable("invalid Celsius value".into()));
    }
    Ok(value)
}

/// Actual samples taken at the boundaries of a successful execution, plus the
/// hottest reading taken anywhere inside it.
///
/// [`maximum_c`](Self::maximum_c) is a maximum over the pre-run sample, every
/// mid-run watchdog sample and the post-loop sample. It is what makes an
/// excursion that recovers by the end of the run visible to anyone downstream.
#[derive(Debug, Clone, Copy)]
pub struct ThermalTelemetry {
    pub start_c: f64,
    pub end_c: f64,
    pub maximum_c: f64,
}

/// Compatibility wrapper returning the maximum observed temperature.
pub fn run_benchmark_with_thermal(
    spec: &CqrJobSpec,
    initial_state: PhaseSpacePoint,
    thermal_source: &dyn ThermalSource,
) -> Result<(CqrResult, f64), CqrExecutionError> {
    run_benchmark_with_telemetry(spec, initial_state, thermal_source)
        .map(|(result, telemetry)| (result, telemetry.maximum_c))
}

/// Executes a 64 coupled oscillators benchmark run with thermal enforcement.
///
/// # Which parts of `CqrResourceBudget` are actually enforced
///
/// * `max_wall_time_ms` — **enforced**, checked every 20 steps and again after
///   the loop.
/// * `thermal_ceiling_celsius` — **enforced**, at the pre-run gate, at every
///   watchdog sample and at the post-loop sample, and always clamped down to
///   [`crate::discovery::HARD_THERMAL_CEILING_C`] by `effective_thermal_ceiling`.
/// * `max_cpu_time_ms` — **NOT enforced**. There is no per-thread CPU clock read
///   in this path, so the budget is part of the job hash and nothing more.
/// * `max_memory_bytes` — **NOT enforced**. No cgroup limit, no `setrlimit`, no
///   RSS read exists anywhere in the crate, so a job can exceed it silently.
///
/// The two unenforced dimensions are declared in the job and hashed into it, so
/// a job that *claims* a CPU or memory limit is committed to saying so. Nothing
/// checks that the claim was kept.
pub fn run_benchmark_with_telemetry(
    spec: &CqrJobSpec,
    initial_state: PhaseSpacePoint,
    thermal_source: &dyn ThermalSource,
) -> Result<(CqrResult, ThermalTelemetry), CqrExecutionError> {
    let n = spec.classical_spec.oscillator_count;
    if n < 2 || initial_state.dim() != n || initial_state.p.len() != n {
        return Err(CqrExecutionError::InvalidInput(format!(
            "initial state dimension {} does not match spec {}",
            initial_state.dim(),
            n
        )));
    }

    if !spec.classical_spec.mass.is_finite() || spec.classical_spec.mass <= 0.0
        || !spec.classical_spec.spring_constant.is_finite() || spec.classical_spec.spring_constant <= 0.0
        || !spec.time_step.is_finite() || spec.time_step <= 0.0
        || initial_state.q.iter().chain(&initial_state.p).any(|v| !v.is_finite())
    {
        return Err(CqrExecutionError::InvalidInput("invalid physical input".into()));
    }
    let system = CoupledOscillators::new(
        n,
        spec.classical_spec.mass,
        spec.classical_spec.spring_constant,
        spec.classical_spec.periodic_boundary,
    );

    let initial_energy = system.total_energy(&initial_state);
    let initial_bytes = initial_state.to_bytes();
    let computed_input_hash = hash_component(b"mycelium:cqr:phase_space:v1", &initial_bytes);

    if computed_input_hash != spec.initial_state_hash {
        return Err(CqrExecutionError::InvalidInput(format!(
            "initial state hash mismatch: expected {}, got {}",
            spec.initial_state_hash, computed_input_hash
        )));
    }

    let mut state = initial_state;
    let dt = spec.time_step;
    let steps = spec.step_count;
    let max_wall_time_ms = spec.resource_budget.max_wall_time_ms;

    // Check thermal ceiling requested vs MUPP hard ceiling
    let effective_thermal_ceiling = (spec.resource_budget.thermal_ceiling_celsius as f64)
        .min(crate::discovery::HARD_THERMAL_CEILING_C);

    // Pre-run thermal gate: check before step 0
    let pre_run_temp = read_valid_temperature(thermal_source)?;
    let mut max_observed_temp = pre_run_temp;
    if pre_run_temp >= effective_thermal_ceiling {
        return Err(CqrExecutionError::ThermalStop {
            observed_c: pre_run_temp,
            ceiling_c: effective_thermal_ceiling,
            step: 0,
        });
    }

    let start_instant = std::time::Instant::now();

    // Symplectic evolution loop with periodic wall-clock and thermal watchdog checks
    for step_idx in 0..steps {
        if step_idx % 20 == 0 {
            if start_instant.elapsed().as_millis() as u64 > max_wall_time_ms {
                return Err(CqrExecutionError::Timeout(max_wall_time_ms));
            }
            let current_temp = read_valid_temperature(thermal_source)?;
            if current_temp > max_observed_temp {
                max_observed_temp = current_temp;
            }
            if current_temp >= effective_thermal_ceiling {
                return Err(CqrExecutionError::ThermalStop {
                    observed_c: current_temp,
                    ceiling_c: effective_thermal_ceiling,
                    step: step_idx as usize,
                });
            }
        }
        VelocityVerlet::step(&system, &mut state, dt);
    }

    let end_temp = read_valid_temperature(thermal_source)?;
    max_observed_temp = max_observed_temp.max(end_temp);
    if end_temp >= effective_thermal_ceiling {
        return Err(CqrExecutionError::ThermalStop {
            observed_c: end_temp, ceiling_c: effective_thermal_ceiling, step: steps as usize,
        });
    }
    let elapsed = start_instant.elapsed();
    let wall_time_ms = elapsed.as_millis() as u64;
    if wall_time_ms > max_wall_time_ms {
        return Err(CqrExecutionError::Timeout(max_wall_time_ms));
    }

    let final_energy = system.total_energy(&state);
    let energy_drift_fraction = if initial_energy.abs() > 1e-12 {
        (final_energy - initial_energy).abs() / initial_energy.abs()
    } else {
        (final_energy - initial_energy).abs()
    };

    // Calculate equipartition temperature
    let mut sum_p2 = 0.0;
    for &pi in &state.p {
        sum_p2 += (pi * pi) / system.mass;
    }
    let equipartition_temperature = sum_p2 / n as f64;

    // Statistical Gibbs entropy
    let gibbs_entropy = compute_gibbs_entropy(&state, 16);

    // Subsystem entanglement entropy (first 4 oscillators)
    let entanglement_entropy = Some(compute_subsystem_entanglement_entropy(&state, 4));

    // Nearest-neighbour correlation trace
    let mut correlation_sum = 0.0;
    for i in 0..n {
        let next_i = (i + 1) % n;
        correlation_sum += state.q[i] * state.q[next_i];
    }
    let correlation_trace = correlation_sum / n as f64;

    let stress_energy_trace = final_energy / n as f64;

    let observables = CqrObservables {
        initial_energy,
        final_energy,
        energy_drift_fraction,
        equipartition_temperature,
        gibbs_entropy,
        entanglement_entropy,
        correlation_trace,
        stress_energy_trace,
    };

    let observables_hash = observables.observables_hash();

    // Validation check against tolerance policy
    let mut validation_notes = Vec::new();
    let mut validation_passed = true;

    if energy_drift_fraction > spec.tolerance_policy.max_energy_drift_fraction {
        validation_passed = false;
        validation_notes.push(format!(
            "energy drift {} exceeded max tolerance {}",
            energy_drift_fraction, spec.tolerance_policy.max_energy_drift_fraction
        ));
    } else {
        validation_notes.push(format!(
            "symplectic energy conservation verified: drift = {:.2e} <= {:.2e}",
            energy_drift_fraction, spec.tolerance_policy.max_energy_drift_fraction
        ));
    }

    let final_bytes = state.to_bytes();
    let output_state_hash = hash_component(b"mycelium:cqr:phase_space:v1", &final_bytes);

    let result_digest = CqrResult::compute_digest(
        &spec.job_hash(),
        &computed_input_hash,
        &output_state_hash,
        &observables_hash,
        validation_passed,
    );

    let result = CqrResult {
        job_id: spec.job_id.clone(),
        job_hash: spec.job_hash(),
        input_state_hash: computed_input_hash,
        output_state_hash,
        implementation_id: "cqr-c0:coupled_oscillators:verlet".into(),
        implementation_version: "1.0.0".into(),
        observables,
        observables_hash,
        validation_passed,
        validation_notes,
        // CPU and GPU time are `None`, not `0`: there is no per-thread CPU
        // clock read and no GPU timer in this path, so a zero here would be an
        // unmeasurable claim of "no CPU was burned" rather than a measurement.
        cpu_time_ms: None,
        gpu_time_ms: None,
        wall_time_ms,
        result_digest,
    };

    Ok((result, ThermalTelemetry { start_c: pre_run_temp, end_c: end_temp, maximum_c: max_observed_temp }))
}

/// Executes a 64 coupled oscillators benchmark run with the standard system thermal source.
pub fn run_benchmark(
    spec: &CqrJobSpec,
    initial_state: PhaseSpacePoint,
) -> Result<CqrResult, String> {
    run_benchmark_with_thermal(spec, initial_state, &SystemThermalSource)
        .map(|(res, _)| res)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cqr::job::{
        ClassicalSpec, CqrComputeLevel, CqrResourceBudget, IntegratorSpec, PrecisionPolicy,
        TolerancePolicy,
    };
    use crate::cqr::state_bus::hash_component;

    fn sample_state() -> PhaseSpacePoint {
        let mut q = vec![0.0; 64];
        let mut p = vec![0.0; 64];
        for i in 0..64 {
            let angle = (i as f64 * std::f64::consts::PI) / 32.0;
            q[i] = 0.5 * angle.sin();
            p[i] = 0.1 * angle.cos();
        }
        PhaseSpacePoint::new(q, p)
    }

    fn sample_spec(state: &PhaseSpacePoint) -> CqrJobSpec {
        CqrJobSpec {
            schema_version: 1,
            job_id: "cqr-thermal-peak-1".into(),
            model_id: "coupled_oscillators_64".into(),
            model_version: "1.0.0".into(),
            compute_level: CqrComputeLevel::C0ClassicalSymplectic,
            initial_state_hash: hash_component(
                b"mycelium:cqr:phase_space:v1",
                &state.to_bytes(),
            ),
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
        }
    }

    /// A [`FakeThermalSource`] that reports a hot value for a window of reads and
    /// a cool one either side of it, so a mid-run excursion can be produced from a
    /// single thread and read deterministically.
    ///
    /// `FakeThermalSource` alone cannot do this: its value can only be changed
    /// from outside a running benchmark, and there is no such moment in a
    /// single-threaded call. Driving `set_celsius` from the read itself keeps the
    /// excursion at a known step instead of at the mercy of a wall clock.
    ///
    /// With `step_count: 45` the reads are: pre-run, step 0, step 20, step 40,
    /// post-loop.
    struct ExcursionSource {
        inner: FakeThermalSource,
        reads: std::sync::atomic::AtomicU64,
        cool_c: f64,
        peak_c: f64,
        /// First read index that reports `peak_c`.
        hot_from_read: u64,
        /// First read index at or after which `cool_c` is reported again.
        cool_from_read: u64,
    }

    impl ExcursionSource {
        fn new(cool_c: f64, peak_c: f64, hot_from_read: u64, cool_from_read: u64) -> Self {
            Self {
                inner: FakeThermalSource::new(cool_c),
                reads: std::sync::atomic::AtomicU64::new(0),
                cool_c,
                peak_c,
                hot_from_read,
                cool_from_read,
            }
        }
    }

    impl ThermalSource for ExcursionSource {
        fn read_celsius(&self) -> Result<f64, String> {
            let n = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let value = if n >= self.hot_from_read && n < self.cool_from_read {
                self.peak_c
            } else {
                self.cool_c
            };
            self.inner.set_celsius(value);
            Ok(value)
        }
    }

    #[test]
    fn mid_run_thermal_peak_is_reported_not_only_the_endpoints() {
        // Hot for reads 1..3 (steps 0, 20, 40), cool at the pre-run gate and at
        // the post-loop sample. 70 °C is below every ceiling in play — the job
        // asks for 75 and HARD_THERMAL_CEILING_C is 75 — so the run completes.
        // The point is not that the excursion was refused; it is that it is
        // *reported* to whoever asked.
        let state = sample_state();
        let spec = sample_spec(&state);
        let source = ExcursionSource::new(40.0, 70.0, 1, 4);

        let (_result, telemetry) = run_benchmark_with_telemetry(&spec, state, &source)
            .expect("an excursion below the ceiling is not a stop");

        assert_eq!(telemetry.start_c, 40.0);
        assert_eq!(telemetry.end_c, 40.0);
        assert!(
            telemetry.maximum_c > telemetry.start_c && telemetry.maximum_c > telemetry.end_c,
            "the mid-run peak {} must exceed both endpoints ({}, {})",
            telemetry.maximum_c,
            telemetry.start_c,
            telemetry.end_c
        );
        assert_eq!(telemetry.maximum_c, 70.0);
    }

    #[test]
    fn cpu_and_gpu_time_are_absent_rather_than_zero() {
        // A hardcoded `0` here read as "no CPU was burned" and was
        // indistinguishable from a job that never ran. `None` says the number
        // does not exist.
        let state = sample_state();
        let spec = sample_spec(&state);
        let source = FakeThermalSource::new(41.0);

        let (result, _telemetry) = run_benchmark_with_telemetry(&spec, state, &source)
            .expect("a cool machine runs");

        assert_eq!(result.cpu_time_ms, None);
        assert_eq!(result.gpu_time_ms, None);
        assert!(result.validation_passed);
    }

    #[test]
    fn a_mid_run_excursion_past_the_hard_ceiling_still_stops_the_job() {
        // Reporting the peak must not have weakened the gate. The excursion here
        // begins at the step-20 sample, so the stop it produces can only have come
        // from inside the loop: the pre-run gate saw a cool machine.
        let state = sample_state();
        let spec = sample_spec(&state);
        let source = ExcursionSource::new(40.0, 80.0, 2, 4);

        let err = run_benchmark_with_telemetry(&spec, state, &source)
            .expect_err("80 C is at or above the 75 C hard ceiling");
        match err {
            CqrExecutionError::ThermalStop {
                observed_c,
                ceiling_c,
                step,
            } => {
                assert_eq!(observed_c, 80.0);
                assert_eq!(ceiling_c, crate::discovery::HARD_THERMAL_CEILING_C);
                assert_eq!(step, 20, "the watchdog fires on the first hot sample");
            }
            other => panic!("expected a thermal stop, got {other:?}"),
        }
    }
}
