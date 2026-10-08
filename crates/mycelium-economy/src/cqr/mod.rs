//! CQR-ME — Computação Quântico-Relativística Mecânico-Estatística.
//!
//! Subsystem integrating multiscale physical computation into Mycelium useful work
//! and System One P6 Opportunity Search.
//!
//! Layers:
//! * Analytical / Symplectic Mechanics Kernel (`kernel`)
//! * Coupled Harmonic Oscillators Benchmark (`oscillators`)
//! * Physical State Bus (`state_bus`)
//! * Job Specification (`job`)
//! * Compute Result (`result`)
//! * Cryptographic Proof Binding (`proof`)
//! * Validation and Reproducibility Harness (`validation`)
//! * P6 Compute Reward Adapter (`adapter`)

pub mod adapter;
pub mod job;
pub mod kernel;
pub mod oscillators;
pub mod proof;
pub mod result;
pub mod state_bus;
pub mod validation;

pub use adapter::{
    create_cqr_work_receipt, AuthenticatedComputeEvidence, ComputeExecutionIntent,
    ComputeOpportunity, ComputeRewardAdapter, ComputeRewardStatus, CqrSearchMetrics,
    ExternalRewardEvidence, UnverifiedComputeEvidence, ValidatedComputeOpportunity,
};
pub use job::{
    ClassicalSpec, CqrComputeLevel, CqrJobSpec, CqrResourceBudget, IntegratorSpec,
    PrecisionPolicy, TolerancePolicy,
};
pub use kernel::{HamiltonianSystem, PhaseSpacePoint, VelocityVerlet};
pub use oscillators::{
    compute_gibbs_entropy, compute_subsystem_entanglement_entropy, run_benchmark,
    run_benchmark_with_thermal, run_benchmark_with_telemetry, CoupledOscillators,
    CqrExecutionError, FakeThermalSource, SystemThermalSource, ThermalSource,
};
pub use proof::{CqrResultAttestation, CqrResultProof};
pub use result::{CqrObservables, CqrResult};
pub use state_bus::PhysicalStateSnapshot;
pub use validation::{
    validate_job, validate_job_with_thermal, CqrValidationReport, ValidationLevel,
};
