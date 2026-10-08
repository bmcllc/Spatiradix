//! CQR Result — Output and observable commitments from physical execution.

use super::state_bus::blake3_derive_key;
use serde::{Deserialize, Serialize};

/// Domain separation string for BLAKE3 hashes on CQR Results.
pub const CQR_RESULT_DOMAIN: &[u8] = b"mycelium:cqr:result:v1";

/// Physical observables computed during simulation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CqrObservables {
    pub initial_energy: f64,
    pub final_energy: f64,
    pub energy_drift_fraction: f64,
    pub equipartition_temperature: f64,
    pub gibbs_entropy: f64,
    pub entanglement_entropy: Option<f64>,
    pub correlation_trace: f64,
    pub stress_energy_trace: f64,
}

impl CqrObservables {
    /// Computes canonical hash of observables.
    pub fn observables_hash(&self) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&blake3_derive_key(b"mycelium:cqr:observables:v1"));
        hasher.update(&self.initial_energy.to_le_bytes());
        hasher.update(&self.final_energy.to_le_bytes());
        hasher.update(&self.energy_drift_fraction.to_le_bytes());
        hasher.update(&self.equipartition_temperature.to_le_bytes());
        hasher.update(&self.gibbs_entropy.to_le_bytes());
        if let Some(ee) = self.entanglement_entropy {
            hasher.update(&ee.to_le_bytes());
        }
        hasher.update(&self.correlation_trace.to_le_bytes());
        hasher.update(&self.stress_energy_trace.to_le_bytes());
        hasher.finalize().to_hex().to_string()
    }
}

/// Verifiable result of a CQR computation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CqrResult {
    pub job_id: String,
    pub job_hash: String,
    pub input_state_hash: String,
    pub output_state_hash: String,
    pub implementation_id: String,
    pub implementation_version: String,
    pub observables: CqrObservables,
    pub observables_hash: String,
    pub validation_passed: bool,
    pub validation_notes: Vec<String>,
    /// MEASURED_ONLY, and currently NOT MEASURED AT ALL.
    ///
    /// There is no per-thread CPU clock read anywhere in the execution path —
    /// `run_benchmark_with_telemetry` measures wall clock and temperature, and
    /// nothing else — so this is `None` rather than a number. It used to be a
    /// hardcoded `0`, which is the worst of both: indistinguishable from a real
    /// zero-millisecond measurement, and therefore indistinguishable from a job
    /// that never ran.
    pub cpu_time_ms: Option<u64>,
    /// Not measured: the CQR kernel is CPU-only, and no GPU timer is read on
    /// either path. `None` for the same reason as [`Self::cpu_time_ms`].
    pub gpu_time_ms: Option<u64>,
    /// The one execution-side number that is real: read from a monotonic
    /// instant, and the only CPU-or-wall dimension the execution path actually
    /// enforces against `resource_budget.max_wall_time_ms`.
    pub wall_time_ms: u64,
    pub result_digest: String,
}

impl CqrResult {
    /// Computes the canonical result digest.
    pub fn compute_digest(
        job_hash: &str,
        input_hash: &str,
        output_hash: &str,
        observables_hash: &str,
        validation_passed: bool,
    ) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&blake3_derive_key(CQR_RESULT_DOMAIN));
        hasher.update(job_hash.as_bytes());
        hasher.update(input_hash.as_bytes());
        hasher.update(output_hash.as_bytes());
        hasher.update(observables_hash.as_bytes());
        hasher.update(&[validation_passed as u8]);
        hasher.finalize().to_hex().to_string()
    }
}
