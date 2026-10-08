//! CQR Job Model — Specification of verifiable multiscale physical compute jobs.

use super::state_bus::blake3_derive_key;
use serde::{Deserialize, Serialize};

/// Domain separation string for BLAKE3 hashes on CQR Job Specs.
pub const CQR_JOB_DOMAIN: &[u8] = b"mycelium:cqr:job_spec:v1";

/// Compute levels of the CQR-ME hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CqrComputeLevel {
    /// CQR-C0: Classical Hamiltonian / symplectic mechanics.
    C0ClassicalSymplectic,
    /// CQR-C1: Statistical mechanics / Monte Carlo ensembles.
    C1StatisticalMonteCarlo,
    /// CQR-C2: Quantum / MPS subsystem.
    C2QuantumMps,
    /// CQR-C3: Relativistic background metric / geodesics.
    C3RelativisticBackground,
    /// CQR-C4: Semiclassical backreaction.
    C4SemiclassicalBackreaction,
    /// CQR-C5: Speculative / experimental quantum geometry (Research-only!).
    C5QuantumGeometryResearch,
}

impl CqrComputeLevel {
    /// Whether this level has an objective, deterministic validation protocol
    /// suitable for verifiable production compute reward.
    ///
    /// Currently only C0 (Classical Hamiltonian / Symplectic Mechanics) has a
    /// complete, verified execution and analytical validation engine.
    /// Higher levels (C1-C5) are experimental or research-only.
    pub fn is_verifiable_compute_reward_ready(&self) -> bool {
        matches!(self, Self::C0ClassicalSymplectic)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::C0ClassicalSymplectic => "CQR-C0",
            Self::C1StatisticalMonteCarlo => "CQR-C1",
            Self::C2QuantumMps => "CQR-C2",
            Self::C3RelativisticBackground => "CQR-C3",
            Self::C4SemiclassicalBackreaction => "CQR-C4",
            Self::C5QuantumGeometryResearch => "CQR-C5",
        }
    }
}

/// Integrator algorithms for analytical and symplectic physics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegratorSpec {
    VelocityVerlet,
    Leapfrog,
    Yoshida4,
    RungeKutta4NonSymplectic,
}

impl IntegratorSpec {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VelocityVerlet => "velocity_verlet",
            Self::Leapfrog => "leapfrog",
            Self::Yoshida4 => "yoshida4",
            Self::RungeKutta4NonSymplectic => "runge_kutta4_non_symplectic",
        }
    }
}

/// Floating point precision policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrecisionPolicy {
    Float64Strict,
    Float32Standard,
}

impl PrecisionPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Float64Strict => "float64_strict",
            Self::Float32Standard => "float32_standard",
        }
    }
}

/// Tolerance policy for numerical verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TolerancePolicy {
    pub absolute_tolerance: f64,
    pub relative_tolerance: f64,
    pub max_energy_drift_fraction: f64,
}

impl Default for TolerancePolicy {
    fn default() -> Self {
        Self {
            absolute_tolerance: 1e-9,
            relative_tolerance: 1e-7,
            max_energy_drift_fraction: 1e-6,
        }
    }
}

/// Resource budget allowed for job execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CqrResourceBudget {
    pub max_cpu_time_ms: u64,
    pub max_wall_time_ms: u64,
    pub max_memory_bytes: u64,
    pub thermal_ceiling_celsius: u32,
}

impl Default for CqrResourceBudget {
    fn default() -> Self {
        Self {
            max_cpu_time_ms: 10_000,
            max_wall_time_ms: 30_000,
            max_memory_bytes: 512 * 1024 * 1024,
            thermal_ceiling_celsius: 75,
        }
    }
}

/// Classical specification (e.g. coupled oscillators).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassicalSpec {
    pub oscillator_count: usize,
    pub mass: f64,
    pub spring_constant: f64,
    pub periodic_boundary: bool,
}

/// Immutable, versioned specification of a CQR computational job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CqrJobSpec {
    pub schema_version: u32,
    pub job_id: String,
    pub model_id: String,
    pub model_version: String,
    pub compute_level: CqrComputeLevel,
    pub initial_state_hash: String,
    pub classical_spec: ClassicalSpec,
    pub integrator_spec: IntegratorSpec,
    pub precision_policy: PrecisionPolicy,
    pub tolerance_policy: TolerancePolicy,
    pub step_count: u64,
    pub time_step: f64,
    pub seed: Option<u64>,
    pub resource_budget: CqrResourceBudget,
    pub expected_observables: Vec<String>,
    pub validation_suite: Vec<String>,
}

fn push_str(hasher: &mut blake3::Hasher, s: &str) {
    let bytes = s.as_bytes();
    hasher.update(&(bytes.len() as u32).to_le_bytes());
    hasher.update(bytes);
}

fn push_vec_str(hasher: &mut blake3::Hasher, list: &[String]) {
    hasher.update(&(list.len() as u32).to_le_bytes());
    for s in list {
        push_str(hasher, s);
    }
}

impl CqrJobSpec {
    /// Computes the canonical cryptographic job hash committing to all semantic fields.
    pub fn job_hash(&self) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&blake3_derive_key(CQR_JOB_DOMAIN));
        hasher.update(&self.schema_version.to_le_bytes());
        push_str(&mut hasher, &self.job_id);
        push_str(&mut hasher, &self.model_id);
        push_str(&mut hasher, &self.model_version);
        push_str(&mut hasher, self.compute_level.as_str());
        push_str(&mut hasher, &self.initial_state_hash);
        
        // Classical spec
        hasher.update(&(self.classical_spec.oscillator_count as u64).to_le_bytes());
        hasher.update(&self.classical_spec.mass.to_le_bytes());
        hasher.update(&self.classical_spec.spring_constant.to_le_bytes());
        hasher.update(&[self.classical_spec.periodic_boundary as u8]);

        // Integrator & precision
        push_str(&mut hasher, self.integrator_spec.as_str());
        push_str(&mut hasher, self.precision_policy.as_str());

        // Tolerance policy
        hasher.update(&self.tolerance_policy.absolute_tolerance.to_le_bytes());
        hasher.update(&self.tolerance_policy.relative_tolerance.to_le_bytes());
        hasher.update(&self.tolerance_policy.max_energy_drift_fraction.to_le_bytes());

        // Steps & time
        hasher.update(&self.step_count.to_le_bytes());
        hasher.update(&self.time_step.to_le_bytes());

        // Seed with explicit presence tag (prevents Some(0) vs None collision)
        match self.seed {
            Some(s) => {
                hasher.update(&[1u8]);
                hasher.update(&s.to_le_bytes());
            }
            None => {
                hasher.update(&[0u8]);
            }
        }

        // Resource budget
        hasher.update(&self.resource_budget.max_cpu_time_ms.to_le_bytes());
        hasher.update(&self.resource_budget.max_wall_time_ms.to_le_bytes());
        hasher.update(&self.resource_budget.max_memory_bytes.to_le_bytes());
        hasher.update(&self.resource_budget.thermal_ceiling_celsius.to_le_bytes());

        // Observables and validation suite
        push_vec_str(&mut hasher, &self.expected_observables);
        push_vec_str(&mut hasher, &self.validation_suite);

        hasher.finalize().to_hex().to_string()
    }
}
