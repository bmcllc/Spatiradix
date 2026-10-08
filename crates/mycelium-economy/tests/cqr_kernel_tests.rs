//! CQR-ME Physics Kernel, State Bus, Job Spec, and Result Proof Invariant Tests.

use mycelium_economy::boundary::ControlledAddressRegistry;
use mycelium_economy::cqr::{
    validate_job_with_thermal, ClassicalSpec, ComputeOpportunity, ComputeRewardAdapter,
    CqrComputeLevel, CqrExecutionError, CqrJobSpec, CqrResourceBudget, CqrResultAttestation,
    CqrResultProof, ExternalRewardEvidence, FakeThermalSource, IntegratorSpec, PhaseSpacePoint,
    PhysicalStateSnapshot, PrecisionPolicy, ThermalSource, TolerancePolicy,
    UnverifiedComputeEvidence,
};
// `run_benchmark_with_telemetry` is re-exported flat from `cqr` too, but naming
// it through its module keeps this file working against either surface.
use mycelium_economy::cqr::oscillators::run_benchmark_with_telemetry;
use mycelium_economy::cqr::adapter::REWARD_BINDING_INCOMPLETE;
use mycelium_economy::cqr::state_bus::hash_component;
use mycelium_economy::discovery::HARD_THERMAL_CEILING_C;
use mycelium_economy::policy_auth::{PolicyError, ValidatedOutcomePolicy, VerifierRuntimeKey};
use mycelium_economy::testkit::{AuthFixture, FakeRpcSocket};
use mycelium_economy::EconomyError;
use std::sync::atomic::{AtomicU64, Ordering};

fn sample_64_oscillator_state() -> PhaseSpacePoint {
    let mut q = vec![0.0; 64];
    let mut p = vec![0.0; 64];

    // Excite the first normal mode
    for i in 0..64 {
        let angle = (i as f64 * std::f64::consts::PI) / 32.0;
        q[i] = 0.5 * angle.sin();
        p[i] = 0.1 * angle.cos();
    }
    PhaseSpacePoint::new(q, p)
}

fn sample_job_spec(initial_hash: &str) -> CqrJobSpec {
    CqrJobSpec {
        schema_version: 1,
        job_id: "cqr-job-001".into(),
        model_id: "coupled_oscillators_64".into(),
        model_version: "1.0.0".into(),
        compute_level: CqrComputeLevel::C0ClassicalSymplectic,
        initial_state_hash: initial_hash.into(),
        classical_spec: ClassicalSpec {
            oscillator_count: 64,
            mass: 1.0,
            spring_constant: 2.0,
            periodic_boundary: true,
        },
        integrator_spec: IntegratorSpec::VelocityVerlet,
        precision_policy: PrecisionPolicy::Float64Strict,
        tolerance_policy: TolerancePolicy {
            absolute_tolerance: 1e-9,
            relative_tolerance: 1e-7,
            max_energy_drift_fraction: 1e-5,
        },
        step_count: 100,
        time_step: 0.005,
        seed: None,
        resource_budget: CqrResourceBudget::default(),
        expected_observables: vec!["energy".into(), "temperature".into(), "gibbs_entropy".into()],
        validation_suite: vec!["symplectic_conservation".into(), "dispersion_check".into()],
    }
}

// ---------------------------------------------------------------------------
// Local thermal sources
// ---------------------------------------------------------------------------

/// A [`ThermalSource`] that reports a cool value for the first reads and a hot
/// one from a fixed read index onwards.
///
/// `FakeThermalSource` on its own cannot produce a mid-run excursion from a
/// single-threaded call: its value can only be changed from outside a running
/// benchmark, and there is no such moment. Driving the fake from the read
/// itself keeps the excursion at a known step instead of at the mercy of a wall
/// clock, and keeps the whole thing deterministic.
///
/// With the sample job's `step_count: 100` the reads are, in order: the pre-run
/// gate, the watchdog at steps 0, 20, 40, 60 and 80, and the post-loop sample.
/// `hot_from_read = 2` therefore means the excursion is first seen at step 20.
///
/// `Send + Sync` structurally: the only interior-mutable state is an
/// `AtomicU64`, which is what the watchdog's `&dyn ThermalSource` requires.
struct ScriptedThermalSource {
    inner: FakeThermalSource,
    reads: AtomicU64,
    cool_c: f64,
    peak_c: f64,
    hot_from_read: u64,
}

impl ScriptedThermalSource {
    fn new(cool_c: f64, peak_c: f64, hot_from_read: u64) -> Self {
        Self {
            inner: FakeThermalSource::new(cool_c),
            reads: AtomicU64::new(0),
            cool_c,
            peak_c,
            hot_from_read,
        }
    }
}

impl ThermalSource for ScriptedThermalSource {
    fn read_celsius(&self) -> Result<f64, String> {
        let n = self.reads.fetch_add(1, Ordering::SeqCst);
        let value = if n >= self.hot_from_read {
            self.peak_c
        } else {
            self.cool_c
        };
        self.inner.set_celsius(value);
        Ok(value)
    }
}

/// A host with no working thermal sensor at all. Fail-closed by construction:
/// there is no reading to compare against a ceiling, so the run must not start.
struct DeadThermalSensor;

impl ThermalSource for DeadThermalSensor {
    fn read_celsius(&self) -> Result<f64, String> {
        Err("no thermal sensor is readable on this host".into())
    }
}

// ---------------------------------------------------------------------------
// The authority the attestation tests are signed under
// ---------------------------------------------------------------------------

/// A validated outcome policy from the crate's canonical `testkit` fixture —
/// the same `AuthFixture` + `FakeRpcSocket` pair the receipt and CQR adapter
/// tests use, rather than a second copy of the fixture that would have to be
/// kept in step with it.
///
/// The `TempDir` and the socket come back with it: the pinned trust anchor lives
/// in a directory that a dropped `TempDir` deletes, and the provider identity
/// digest inside the signed policy describes that socket, so all three have to
/// outlive the policy.
fn authority() -> (
    tempfile::TempDir,
    FakeRpcSocket,
    AuthFixture,
    ValidatedOutcomePolicy,
) {
    let dir = tempfile::tempdir().unwrap();
    let socket = FakeRpcSocket::bind(dir.path().join("rpc.sock"));
    let auth = AuthFixture::new(socket.path(), socket.uid(), ControlledAddressRegistry::new());
    let policy = auth.validated();
    (dir, socket, auth, policy)
}

const SAMPLE_PROOF_JOB_ID: &str = "cqr-attest-job-1";
const SAMPLE_PROOF_RESULT_DIGEST: &str =
    "0xresultdigest0000000000000000000000000000000000000000000000000005";

/// A proof built from literal components rather than from a real run.
///
/// The attestation tests are about *what the signature covers*. Producing the
/// proof by executing the benchmark would drag this machine's hardware
/// temperature into every one of them, for no extra coverage: the proof digest
/// is a pure function of the strings below.
fn sample_proof(job_id: &str, result_digest: &str) -> CqrResultProof {
    CqrResultProof::new(
        "proof-attestation-1",
        job_id,
        "0xjobhash0000000000000000000000000000000000000000000000000000000001",
        "0xinputhash00000000000000000000000000000000000000000000000000000002",
        "0xoutputhash000000000000000000000000000000000000000000000000000003",
        "cqr-c0:coupled_oscillators:verlet",
        "1.0.0",
        "0xsuitedigest00000000000000000000000000000000000000000000000000004",
        result_digest,
        "worker-node-alpha",
    )
}

/// Reward evidence whose `job_id` and `result_digest` are supplied by the caller
/// and whose entire payment identity is invented.
fn reward_evidence(job_id: &str, result_digest: &str) -> ExternalRewardEvidence {
    ExternalRewardEvidence {
        settlement_tx_hash: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        chain_id: 8453,
        payer: "0xPAYERSENTINEL0000000000000000".into(),
        recipient: "0xRECIPIENTSENTINEL00000000000".into(),
        gross_amount_musd_micros: SENTINEL_REWARD_AMOUNT,
        job_id: job_id.into(),
        result_digest: result_digest.into(),
    }
}

/// A reward amount whose decimal and hexadecimal spellings are both long and
/// distinctive, so that "the preimage does not contain the amount" is a real
/// absence rather than a substring that could have matched something else.
const SENTINEL_REWARD_AMOUNT: u64 = 7_777_777_777;

/// The refusal `verify` produced, as the crate's own error value, so a test
/// asserts on what the crate said rather than on a string built next to it.
///
/// Both arms are refusals; they differ in which check refused. The three checks
/// that fire *before* the terminal one — proof integrity, the `job_id` binding
/// and the `result_digest` binding — are still `Invalid` and still carry their
/// original messages. The terminal refusal is the typed
/// [`EconomyError::RewardBindingIncomplete`], whose `Display` opens with
/// [`REWARD_BINDING_INCOMPLETE`] and then names the reason.
fn binding_refusal(
    proof: &CqrResultProof,
    reward: ExternalRewardEvidence,
    attestation: &CqrResultAttestation,
    policy: &ValidatedOutcomePolicy,
) -> EconomyError {
    match UnverifiedComputeEvidence::new(proof.clone(), reward, attestation.clone()).verify(policy) {
        Err(error @ EconomyError::Invalid(_)) => error,
        Err(error @ EconomyError::RewardBindingIncomplete(_)) => error,
        Err(other) => panic!("expected a refusal from verify, got {other}"),
        Ok(_) => panic!("an unauthenticated payment identity must never authenticate"),
    }
}

#[test]
fn same_deterministic_job_produces_same_result_commitment() {
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let spec = sample_job_spec(&initial_hash);

    // A fixed reading rather than this host's: the determinism under test is a
    // property of the integrator and the hashes, not of how warm the machine
    // running the test happens to be. 40 °C is comfortably under every ceiling.
    let source = FakeThermalSource::new(40.0);

    let result1 = run_benchmark_with_telemetry(&spec, state.clone(), &source)
        .expect("run 1 should succeed")
        .0;
    let result2 = run_benchmark_with_telemetry(&spec, state.clone(), &source)
        .expect("run 2 should succeed")
        .0;

    assert_eq!(result1.output_state_hash, result2.output_state_hash);
    assert_eq!(result1.observables_hash, result2.observables_hash);
    assert_eq!(result1.result_digest, result2.result_digest);
    assert!(result1.validation_passed);
}

#[test]
fn different_input_produces_different_job_hash_and_output() {
    let state1 = sample_64_oscillator_state();
    let hash1 = hash_component(b"mycelium:cqr:phase_space:v1", &state1.to_bytes());
    let spec1 = sample_job_spec(&hash1);

    let mut state2 = sample_64_oscillator_state();
    state2.q[0] += 0.5; // perturb single oscillator
    let hash2 = hash_component(b"mycelium:cqr:phase_space:v1", &state2.to_bytes());
    let mut spec2 = spec1.clone();
    spec2.initial_state_hash = hash2;

    assert_ne!(spec1.job_hash(), spec2.job_hash());

    let source = FakeThermalSource::new(40.0);
    let res1 = run_benchmark_with_telemetry(&spec1, state1, &source)
        .expect("run 1 should succeed")
        .0;
    let res2 = run_benchmark_with_telemetry(&spec2, state2, &source)
        .expect("run 2 should succeed")
        .0;

    assert_ne!(res1.output_state_hash, res2.output_state_hash);
    assert_ne!(res1.result_digest, res2.result_digest);
}

#[test]
fn symplectic_integrator_bounds_energy_drift() {
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let spec = sample_job_spec(&initial_hash);

    let source = FakeThermalSource::new(40.0);
    let res = run_benchmark_with_telemetry(&spec, state, &source)
        .expect("40 °C is under the hard ceiling")
        .0;

    assert!(res.validation_passed);
    // Over 100 steps of dt=0.005, Velocity Verlet maintains drift << 1e-5
    assert!(res.observables.energy_drift_fraction < 1e-5);
    assert!(res.observables.equipartition_temperature > 0.0);
    assert!(res.observables.gibbs_entropy > 0.0);
    assert!(res.observables.entanglement_entropy.is_some());
}

#[test]
fn result_proof_cryptographically_binds_job_inputs_and_outputs() {
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let spec = sample_job_spec(&initial_hash);

    let source = FakeThermalSource::new(40.0);
    let res = run_benchmark_with_telemetry(&spec, state, &source)
        .expect("40 °C is under the hard ceiling")
        .0;

    let proof = CqrResultProof::new(
        "proof-001",
        &res.job_id,
        &res.job_hash,
        &res.input_state_hash,
        &res.output_state_hash,
        &res.implementation_id,
        &res.implementation_version,
        "suite-digest-v1",
        &res.result_digest,
        "worker-node-alpha",
    );

    assert!(proof.verify_integrity());

    // Tampering with any field invalidates the proof digest
    let mut tampered = proof.clone();
    tampered.output_state_hash = "forged_output_hash".into();
    assert!(!tampered.verify_integrity());
}

#[test]
fn unsupported_compute_level_is_rejected_for_verifiable_reward() {
    assert!(CqrComputeLevel::C0ClassicalSymplectic.is_verifiable_compute_reward_ready());
    assert!(!CqrComputeLevel::C1StatisticalMonteCarlo.is_verifiable_compute_reward_ready());
    assert!(!CqrComputeLevel::C2QuantumMps.is_verifiable_compute_reward_ready());

    // CQR-C5 is speculative research only
    assert!(!CqrComputeLevel::C5QuantumGeometryResearch.is_verifiable_compute_reward_ready());

    let state = sample_64_oscillator_state();
    let hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let mut spec = sample_job_spec(&hash);
    spec.compute_level = CqrComputeLevel::C5QuantumGeometryResearch;

    let opp = ComputeOpportunity {
        opportunity_id: "opp-c5".into(),
        source: "research-node".into(),
        compute_level: CqrComputeLevel::C5QuantumGeometryResearch,
        offered_reward_musd_micros: 50_000,
        estimated_cost_musd_micros: 10_000,
        job_spec: spec,
        initial_state: state,
    };

    let adapter = ComputeRewardAdapter::new_experimental("cqr-adapter");
    let validation_err = adapter.validate(&opp);
    assert!(validation_err.is_err());
    let err_msg = validation_err.unwrap_err().to_string();
    assert!(err_msg.contains("is not verifiable for compute reward"));
}

#[test]
fn full_validation_harness_verifies_reproducibility_and_known_answer() {
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let spec = sample_job_spec(&initial_hash);

    // The thermal source is injected rather than read from this host's sensors,
    // so the harness runs the same way on a cool machine and a warm one. Only
    // where the temperature comes from changed: the harness still runs every
    // check it always ran, and the assertions below are unchanged.
    let source = FakeThermalSource::new(40.0);

    let report = validate_job_with_thermal(&spec, &state, &source)
        .expect("validation should succeed");

    assert!(report.numerical_valid);
    assert!(report.physical_known_answer_valid);
    assert!(report.bitwise_reproducible);
}

// ---------------------------------------------------------------------------
// Thermal enforcement
// ---------------------------------------------------------------------------

#[test]
fn a_job_whose_ceiling_is_already_reached_never_runs_a_step() {
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let mut spec = sample_job_spec(&initial_hash);
    spec.resource_budget.thermal_ceiling_celsius = 70;

    // The ceiling this job is actually held to is min(70, 75) = 70, and the
    // machine is sitting exactly on it. "At" is not "under": the comparison is
    // `>=`, so the pre-run gate refuses before any integration happens.
    let job_ceiling = 70.0_f64;
    let source = FakeThermalSource::new(job_ceiling);

    let err = run_benchmark_with_telemetry(&spec, state, &source)
        .expect_err("a machine already at the ceiling cannot start a job");

    match err {
        CqrExecutionError::ThermalStop { observed_c, ceiling_c, step } => {
            assert_eq!(observed_c, job_ceiling);
            assert_eq!(ceiling_c, job_ceiling);
            assert_eq!(step, 0, "no step may be executed once the gate has spoken");
        }
        other => panic!("expected ThermalStop at step 0, got: {other:?}"),
    }
}

#[test]
fn the_hard_ceiling_is_never_exceeded_by_a_job_that_asks_for_more() {
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let mut spec = sample_job_spec(&initial_hash);

    // A job may declare whatever ceiling it likes; it is clamped before use.
    let requested = 120.0_f64;
    assert!(requested > HARD_THERMAL_CEILING_C, "the premise of this test");
    spec.resource_budget.thermal_ceiling_celsius = requested as u32;

    let observed = 95.0_f64;
    let source = FakeThermalSource::new(observed);

    let err = run_benchmark_with_telemetry(&spec, state, &source)
        .expect_err("95 °C is over the hard ceiling");

    match err {
        CqrExecutionError::ThermalStop { observed_c, ceiling_c, step } => {
            assert_eq!(observed_c, observed);
            assert_eq!(ceiling_c, HARD_THERMAL_CEILING_C, "the clamp, not the request");
            assert_ne!(ceiling_c, requested, "the job's larger request must not be honoured");
            assert_eq!(step, 0);
        }
        other => panic!("expected ThermalStop, got: {other:?}"),
    }
}

#[test]
fn a_job_may_ask_for_a_lower_ceiling_than_the_hard_one() {
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let mut spec = sample_job_spec(&initial_hash);

    // min(job, hard) is not hard: a job that is more careful than the machine
    // policy is held to its own, tighter number.
    let job_ceiling = 60.0_f64;
    assert!(job_ceiling < HARD_THERMAL_CEILING_C, "the premise of this test");
    spec.resource_budget.thermal_ceiling_celsius = job_ceiling as u32;

    let source = FakeThermalSource::new(job_ceiling - 1.0);
    let (result, telemetry) = run_benchmark_with_telemetry(&spec, state.clone(), &source)
        .expect("59 °C is below a 60 °C ceiling");
    assert!(result.validation_passed);
    assert_eq!(telemetry.maximum_c, job_ceiling - 1.0);

    // The same job on a machine that has reached its own ceiling stops, and
    // reports the job's number rather than the hard one.
    source.set_celsius(job_ceiling);
    let err = run_benchmark_with_telemetry(&spec, state, &source)
        .expect_err("60 °C is at a 60 °C ceiling");

    match err {
        CqrExecutionError::ThermalStop { observed_c, ceiling_c, step } => {
            assert_eq!(observed_c, job_ceiling);
            assert_eq!(ceiling_c, job_ceiling);
            assert_ne!(ceiling_c, HARD_THERMAL_CEILING_C);
            assert_eq!(step, 0);
        }
        other => panic!("expected ThermalStop, got: {other:?}"),
    }
}

#[test]
fn a_mid_run_thermal_excursion_stops_the_job_and_is_not_a_timeout_or_a_numerical_failure() {
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let mut spec = sample_job_spec(&initial_hash);
    spec.step_count = 100;
    spec.resource_budget.thermal_ceiling_celsius = 75;

    // Cool at the pre-run gate and at step 0, hot from the step-20 watchdog
    // sample onwards. The stop therefore cannot have come from the gate: the run
    // was already under way when the temperature went.
    let peak = 85.0_f64;
    let source = ScriptedThermalSource::new(40.0, peak, 2);

    let err = run_benchmark_with_telemetry(&spec, state, &source)
        .expect_err("85 °C is over the ceiling");

    assert!(
        !matches!(&err, CqrExecutionError::Timeout(_)),
        "a thermal excursion must not be reported as a wall-clock timeout: {err:?}"
    );
    assert!(
        !matches!(&err, CqrExecutionError::InvalidInput(_)),
        "a thermal excursion must not be reported as a bad spec: {err:?}"
    );

    match err {
        CqrExecutionError::ThermalStop { observed_c, ceiling_c, step } => {
            assert_eq!(observed_c, peak);
            assert_eq!(ceiling_c, HARD_THERMAL_CEILING_C);
            assert_eq!(step, 20, "the first hot watchdog sample is step 20");
            assert!(step > 0, "a mid-run stop cannot be the pre-run gate");
        }
        other => panic!("expected ThermalStop mid-run, got: {other:?}"),
    }
}

#[test]
fn thermal_unavailable_fails_closed() {
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let spec = sample_job_spec(&initial_hash);

    let err = run_benchmark_with_telemetry(&spec, state.clone(), &DeadThermalSensor)
        .expect_err("a host with no readable sensor must not run the job");

    assert!(
        !matches!(&err, CqrExecutionError::ThermalStop { .. }),
        "an unreadable sensor is not a temperature reading that happened to be high"
    );

    match err {
        CqrExecutionError::ThermalUnavailable(message) => {
            assert!(!message.is_empty(), "the refusal must say why");
        }
        other => panic!("expected ThermalUnavailable, got: {other:?}"),
    }

    // No result is produced: the signature returns
    // `Result<(CqrResult, ThermalTelemetry), CqrExecutionError>`, so an `Err`
    // is the only shape a refusal can take — there is no partially-populated
    // result to confuse a caller with.
    assert!(run_benchmark_with_telemetry(&spec, state, &DeadThermalSensor)
        .expect_err("still refused")
        .to_string()
        .contains("thermal telemetry unavailable"));
}

#[test]
fn an_invalid_temperature_fails_closed() {
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let spec = sample_job_spec(&initial_hash);

    // Non-finite readings and readings outside 0..=150 °C are all "no usable
    // sensor". None of them may be treated as a cool machine.
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 151.0] {
        let err = run_benchmark_with_telemetry(&spec, state.clone(), &FakeThermalSource::new(bad))
            .expect_err("an invalid reading must not run the job");
        assert!(
            matches!(&err, CqrExecutionError::ThermalUnavailable(_)),
            "{bad} should be refused as unusable, got: {err:?}"
        );
        assert!(
            !matches!(&err, CqrExecutionError::ThermalStop { .. }),
            "{bad} must not be silently clamped into a ThermalStop: {err:?}"
        );
    }
}

#[test]
fn the_wall_clock_budget_is_enforced_and_is_typed_apart_from_thermal() {
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let mut spec = sample_job_spec(&initial_hash);

    // An impossible budget. The guard compares whole milliseconds
    // (`elapsed.as_millis() > max_wall_time_ms`), so a sub-millisecond job would
    // never trip a zero budget and the outcome would be a race against the
    // clock. A hundred thousand Velocity Verlet steps on 64 oscillators cannot
    // finish inside one millisecond, which makes the refusal deterministic.
    spec.step_count = 100_000;
    spec.resource_budget.max_wall_time_ms = 0;

    // Cool throughout: nothing else is available to refuse the job, so whatever
    // comes back came from the wall clock and nothing else.
    let source = FakeThermalSource::new(40.0);
    let err = run_benchmark_with_telemetry(&spec, state, &source)
        .expect_err("a zero wall-clock budget cannot be met");

    assert!(
        !matches!(&err, CqrExecutionError::ThermalStop { .. }),
        "an exhausted wall clock is not a thermal stop: {err:?}"
    );
    assert!(
        !matches!(&err, CqrExecutionError::ThermalUnavailable(_)),
        "a cool machine is not a dead machine: {err:?}"
    );

    match &err {
        CqrExecutionError::Timeout(budget) => {
            assert_eq!(*budget, 0, "the reported budget is the one that was exceeded");
        }
        other => panic!("expected Timeout, got: {other:?}"),
    }
}

#[test]
fn cpu_and_memory_budgets_are_committed_but_not_enforced() {
    // `max_cpu_time_ms` and `max_memory_bytes` are part of the job hash and
    // nothing else. There is no per-thread CPU clock read anywhere in the
    // execution path and no cgroup limit, `setrlimit` or RSS read in the crate,
    // so a job can overrun either dimension silently. They are commitments that
    // the job *declares* a limit, not limits: `max_wall_time_ms` and the
    // thermal ceiling are the two that are actually checked.
    let state = sample_64_oscillator_state();
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let mut spec = sample_job_spec(&initial_hash);
    spec.resource_budget.max_cpu_time_ms = 1;
    spec.resource_budget.max_memory_bytes = 1024;

    // Both dimensions are committed: changing either changes the job hash.
    let committed = spec.job_hash();
    let mut wider = spec.clone();
    wider.resource_budget.max_cpu_time_ms = 2;
    wider.resource_budget.max_memory_bytes = 2048;
    assert_ne!(
        committed,
        wider.job_hash(),
        "the two unenforced dimensions are still hashed into the job"
    );

    // ... and neither is enforced: 64 oscillators run comfortably inside a
    // 1 ms CPU budget and a 1 KiB memory budget, because nothing measures them.
    let source = FakeThermalSource::new(45.0);
    let (result, telemetry) = run_benchmark_with_telemetry(&spec, state, &source)
        .expect("a 64-oscillator run fits in 1 KiB and 1 ms as far as any check is concerned");

    assert!(result.validation_passed);

    // "Not measured", which is what `Option` is for. These were `u64` and read
    // back as a hardcoded `0`, which is indistinguishable from a real
    // zero-millisecond measurement and therefore from a job that never ran.
    assert!(
        result.cpu_time_ms.is_none(),
        "CPU time is unmeasured, not zero: {:?}",
        result.cpu_time_ms
    );
    assert!(
        result.gpu_time_ms.is_none(),
        "GPU time is unmeasured, not zero: {:?}",
        result.gpu_time_ms
    );

    // The one figure that is real is the wall clock, and it is the one the
    // execution path holds against the budget.
    assert!(result.wall_time_ms < spec.resource_budget.max_wall_time_ms);
    assert_eq!(telemetry.maximum_c, 45.0);
    assert!(telemetry.maximum_c < HARD_THERMAL_CEILING_C);
}

// ---------------------------------------------------------------------------
// The state bus
// ---------------------------------------------------------------------------

#[test]
fn a_length_prefixed_state_hash_separates_ab_c_from_a_bc() {
    // `["ab", "c"]` and `["a", "bc"]` are the same byte string under plain
    // concatenation and different snapshots under length prefixing: every string
    // component is written as `len:u32le || bytes`.
    let ab_c = PhysicalStateSnapshot {
        schema_version: 1,
        step: 10,
        time: "1.000".into(),
        geometry_hash: "flat".into(),
        classical_state_hash: "ab".into(),
        quantum_state_hash: "c".into(),
        statistical_state_hash: "stat".into(),
        stress_energy_hash: "tuv".into(),
        observables_hash: "obs".into(),
    };

    let a_bc = PhysicalStateSnapshot {
        schema_version: 1,
        step: 10,
        time: "1.000".into(),
        geometry_hash: "flat".into(),
        classical_state_hash: "a".into(),
        quantum_state_hash: "bc".into(),
        statistical_state_hash: "stat".into(),
        stress_energy_hash: "tuv".into(),
        observables_hash: "obs".into(),
    };

    // The premise: if the components were concatenated unframed these two would
    // be the same message, and there would be nothing for the hash to separate.
    assert_eq!(
        format!("{}{}", ab_c.classical_state_hash, ab_c.quantum_state_hash),
        format!("{}{}", a_bc.classical_state_hash, a_bc.quantum_state_hash)
    );

    assert_ne!(
        ab_c.state_hash(),
        a_bc.state_hash(),
        "moving one character across a component boundary must change the commitment"
    );

    // The separation survives into the job: a job spec takes the snapshot hash
    // as its `initial_state_hash`, so two snapshots that differ only in where
    // the boundary falls are two different jobs.
    assert_ne!(
        sample_job_spec(&ab_c.state_hash()).job_hash(),
        sample_job_spec(&a_bc.state_hash()).job_hash()
    );
}

#[test]
fn physical_state_bus_mutation_alters_canonical_state_hash() {
    let baseline = PhysicalStateSnapshot {
        schema_version: 1,
        step: 42,
        time: "0.420".into(),
        geometry_hash: "geom_hash_0".into(),
        classical_state_hash: "class_hash_0".into(),
        quantum_state_hash: "quant_hash_0".into(),
        statistical_state_hash: "stat_hash_0".into(),
        stress_energy_hash: "stress_hash_0".into(),
        observables_hash: "obs_hash_0".into(),
    };

    let base_hash = baseline.state_hash();

    // Mutating any single component must alter the state hash
    let mut m1 = baseline.clone();
    m1.step = 43;
    assert_ne!(m1.state_hash(), base_hash);

    let mut m2 = baseline.clone();
    m2.time = "0.421".into();
    assert_ne!(m2.state_hash(), base_hash);

    let mut m3 = baseline.clone();
    m3.geometry_hash = "geom_hash_1".into();
    assert_ne!(m3.state_hash(), base_hash);

    let mut m4 = baseline.clone();
    m4.classical_state_hash = "class_hash_1".into();
    assert_ne!(m4.state_hash(), base_hash);

    let mut m5 = baseline.clone();
    m5.quantum_state_hash = "quant_hash_1".into();
    assert_ne!(m5.state_hash(), base_hash);

    let mut m6 = baseline.clone();
    m6.statistical_state_hash = "stat_hash_1".into();
    assert_ne!(m6.state_hash(), base_hash);

    let mut m7 = baseline.clone();
    m7.stress_energy_hash = "stress_hash_1".into();
    assert_ne!(m7.state_hash(), base_hash);

    let mut m8 = baseline.clone();
    m8.observables_hash = "obs_hash_1".into();
    assert_ne!(m8.state_hash(), base_hash);
}

// ---------------------------------------------------------------------------
// The job hash: every committed field, one mutation at a time
// ---------------------------------------------------------------------------

#[test]
fn every_committed_job_field_changes_the_job_hash() {
    let base = sample_job_spec("initial");
    let base_hash = base.job_hash();

    // The seed is presence-tagged in the preimage, so "no seed at all" and "seed
    // equal to zero" are two different jobs. Without the tag, `None` and
    // `Some(0)` would contribute the same eight zero bytes.
    assert_eq!(base.seed, None);
    let mut untagged_zero = base.clone();
    untagged_zero.seed = Some(0);
    assert_ne!(untagged_zero.seed, base.seed);
    assert_ne!(
        untagged_zero.job_hash(),
        base_hash,
        "an untagged zero must not collide with the absence of a seed"
    );

    let mutations: Vec<(&'static str, Box<dyn Fn(&mut CqrJobSpec)>)> = vec![
        ("integrator_spec", Box::new(|j| j.integrator_spec = IntegratorSpec::Leapfrog)),
        ("precision_policy", Box::new(|j| j.precision_policy = PrecisionPolicy::Float32Standard)),
        ("tolerance_policy.absolute_tolerance", Box::new(|j| j.tolerance_policy.absolute_tolerance *= 2.0)),
        ("tolerance_policy.relative_tolerance", Box::new(|j| j.tolerance_policy.relative_tolerance *= 2.0)),
        // The third tolerance field is named `max_energy_drift_fraction`, not
        // `energy_drift_tolerance`; it is the same quantity, the largest
        // `|ΔE / E₀|` the result may show before validation fails.
        ("tolerance_policy.max_energy_drift_fraction", Box::new(|j| j.tolerance_policy.max_energy_drift_fraction *= 2.0)),
        ("step_count", Box::new(|j| j.step_count += 1)),
        ("time_step", Box::new(|j| j.time_step *= 2.0)),
        ("seed", Box::new(|j| j.seed = Some(0))),
        ("resource_budget.max_cpu_time_ms", Box::new(|j| j.resource_budget.max_cpu_time_ms += 1)),
        ("resource_budget.max_wall_time_ms", Box::new(|j| j.resource_budget.max_wall_time_ms += 1)),
        ("resource_budget.max_memory_bytes", Box::new(|j| j.resource_budget.max_memory_bytes += 1)),
        ("resource_budget.thermal_ceiling_celsius", Box::new(|j| j.resource_budget.thermal_ceiling_celsius -= 1)),
        ("expected_observables", Box::new(|j| j.expected_observables.push("extra".into()))),
        ("validation_suite", Box::new(|j| j.validation_suite.push("extra".into()))),
        ("model_version", Box::new(|j| j.model_version.push('2'))),
        ("compute_level", Box::new(|j| j.compute_level = CqrComputeLevel::C1StatisticalMonteCarlo)),
    ];

    let variants: Vec<(&'static str, CqrJobSpec)> = mutations
        .into_iter()
        .map(|(field, mutate)| {
            let mut spec = base.clone();
            mutate(&mut spec);
            (field, spec)
        })
        .collect();

    // Every single-field change moves the hash...
    for (field, spec) in &variants {
        assert_ne!(spec.job_hash(), base_hash, "{field} did not change the job hash");
    }

    // ...and no two different changes land on the same one. Two mutations that
    // hashed alike would be two jobs the chain could not tell apart.
    let mut distinct: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (field, spec) in &variants {
        assert!(
            distinct.insert(spec.job_hash()),
            "{field} collided with an earlier mutation"
        );
    }
    assert_eq!(
        distinct.len(),
        variants.len(),
        "every mutation must produce its own job hash"
    );
}

// ---------------------------------------------------------------------------
// Attestation: integrity, authentication, and what is NOT signed
// ---------------------------------------------------------------------------

#[test]
fn proof_integrity_is_not_authentication() {
    let (_dir, _socket, auth, policy) = authority();
    let proof = sample_proof(SAMPLE_PROOF_JOB_ID, SAMPLE_PROOF_RESULT_DIGEST);
    assert!(proof.verify_integrity());

    let attestation = CqrResultAttestation::attest(&proof, &policy, &auth.verifier)
        .expect("the delegated verifier signs this proof");
    assert!(attestation.verify(&proof, &policy).is_ok());

    // Rewriting a proof field and re-deriving the proof digest yields a proof
    // that is perfectly self-consistent. Integrity is a hash matching itself:
    // it says nothing about who vouched for the result.
    let mut rewritten = proof.clone();
    rewritten.output_state_hash =
        "0xrewrittenoutput000000000000000000000000000000000000000000000000".into();
    rewritten.proof_digest = CqrResultProof::compute_proof_digest(
        &rewritten.job_hash,
        &rewritten.input_state_hash,
        &rewritten.output_state_hash,
        &rewritten.implementation_id,
        &rewritten.implementation_version,
        &rewritten.validation_suite_digest,
        &rewritten.result_digest,
        &rewritten.worker_identity,
    );
    assert!(
        rewritten.verify_integrity(),
        "a re-digested forgery is internally consistent by construction"
    );
    assert_ne!(rewritten.proof_digest, proof.proof_digest);

    match attestation.verify(&rewritten, &policy) {
        Err(PolicyError::InvalidField { field, .. }) => {
            assert_eq!(field, "proof_digest", "the attestation commits to the proof digest");
        }
        Err(other) => panic!("expected a proof_digest refusal, got: {other}"),
        Ok(()) => panic!("an attestation must not carry over to a rewritten proof"),
    }

    // The other shape: editing the digest itself breaks integrity, which is
    // caught before the attestation is even reached.
    let mut naive = proof.clone();
    naive.proof_digest = format!("0x{}", "0".repeat(64));
    assert!(!naive.verify_integrity());
    assert!(attestation.verify(&naive, &policy).is_err());

    // And the genuine pair still verifies, so none of the refusals above is
    // "the signature is broken".
    assert!(attestation.verify(&proof, &policy).is_ok());
}

#[test]
fn an_attestation_under_the_wrong_policy_is_refused() {
    let (_dir, _socket, auth, policy) = authority();
    let proof = sample_proof(SAMPLE_PROOF_JOB_ID, SAMPLE_PROOF_RESULT_DIGEST);

    let attestation = CqrResultAttestation::attest(&proof, &policy, &auth.verifier)
        .expect("the delegated verifier signs this proof");
    assert!(attestation.verify(&proof, &policy).is_ok());

    // The same anchor, the same registry, the same provider and the same
    // delegated verifier — one version higher. A genuinely valid policy that
    // this attestation was simply not signed under.
    let other = auth
        .rotated(9)
        .validate()
        .expect("the rotated policy validates against the same pin");
    assert_ne!(other.policy_hash().unwrap(), policy.policy_hash().unwrap());

    match attestation.verify(&proof, &other) {
        Err(PolicyError::InvalidField { field, .. }) => {
            assert_eq!(field, "policy_hash", "the signature is bound to the policy hash");
        }
        Err(other) => panic!("expected a policy_hash refusal, got: {other}"),
        Ok(()) => panic!("an attestation from one policy must not verify under another"),
    }
}

#[test]
fn an_attestation_from_the_wrong_verifier_key_is_refused() {
    let (_dir, _socket, auth, policy) = authority();
    let proof = sample_proof(SAMPLE_PROOF_JOB_ID, SAMPLE_PROOF_RESULT_DIGEST);

    // A key the policy does not delegate to. Signing succeeds locally — nothing
    // in the key material stops it — so the refusal has to come from the policy.
    let impostor = VerifierRuntimeKey::generate();
    assert_ne!(impostor.key_id().to_string(), auth.verifier.key_id().to_string());

    let forged = CqrResultAttestation::attest(&proof, &policy, &impostor)
        .expect("an undelegated key can still sign bytes");
    assert_eq!(forged.verifier_key_id, impostor.key_id().to_string());

    match forged.verify(&proof, &policy) {
        Err(PolicyError::InvalidField { field, .. }) => {
            assert_eq!(field, "verifier_key_id");
        }
        Err(other) => panic!("expected a verifier_key_id refusal, got: {other}"),
        Ok(()) => panic!("a signature from an undelegated key must not verify"),
    }

    // The inverse: the genuine delegated key, read back under a policy that
    // delegates to somebody else. Changing the delegated key necessarily changes
    // the policy document and therefore its hash, so the policy_hash check is
    // the one that fires first — this shows the binding is checked in that order.
    let elsewhere = auth
        .with_other_verifier()
        .validate()
        .expect("the re-delegated policy validates against the same pin");
    let honest = CqrResultAttestation::attest(&proof, &policy, &auth.verifier)
        .expect("the delegated verifier signs this proof");
    assert!(honest.verify(&proof, &policy).is_ok());

    match honest.verify(&proof, &elsewhere) {
        Err(PolicyError::InvalidField { field, .. }) => {
            assert_eq!(field, "policy_hash");
        }
        Err(other) => panic!("expected a refusal, got: {other}"),
        Ok(()) => panic!("a key the policy in force does not delegate to must not verify"),
    }
}

#[test]
fn a_tampered_proof_after_signing_is_refused() {
    let (_dir, _socket, auth, policy) = authority();
    let proof = sample_proof(SAMPLE_PROOF_JOB_ID, SAMPLE_PROOF_RESULT_DIGEST);

    let attestation = CqrResultAttestation::attest(&proof, &policy, &auth.verifier)
        .expect("the delegated verifier signs this proof");
    assert!(attestation.verify(&proof, &policy).is_ok());

    // Change a proof field after the signature exists, without re-deriving the
    // digest: the proof's own integrity check is what catches it.
    let mut tampered = proof.clone();
    tampered.result_digest =
        "0xtamperedresult0000000000000000000000000000000000000000000000000".into();
    assert!(
        !tampered.verify_integrity(),
        "editing a signed field without re-digesting breaks the proof digest"
    );

    match attestation.verify(&tampered, &policy) {
        Err(PolicyError::InvalidField { field, .. }) => {
            assert_eq!(field, "proof_digest");
        }
        Err(other) => panic!("expected a proof_digest refusal, got: {other}"),
        Ok(()) => panic!("a tampered proof must not verify"),
    }

    // The signature over the original preimage is untouched by any of this.
    assert!(attestation.verify(&proof, &policy).is_ok());
}

#[test]
fn a_tampered_reward_binding_is_refused() {
    let (_dir, _socket, auth, policy) = authority();
    let proof = sample_proof(SAMPLE_PROOF_JOB_ID, SAMPLE_PROOF_RESULT_DIGEST);
    let attestation = CqrResultAttestation::attest(&proof, &policy, &auth.verifier)
        .expect("the delegated verifier signs this proof");

    // The honest shape first: the reward agrees with the proof on both fields
    // the adapter checks, so nothing but the payment binding is wrong.
    let honest = reward_evidence(SAMPLE_PROOF_JOB_ID, SAMPLE_PROOF_RESULT_DIGEST);
    assert_eq!(honest.job_id, proof.job_id);
    assert_eq!(honest.result_digest, proof.result_digest);
    let honest_refusal = binding_refusal(&proof, honest.clone(), &attestation, &policy);
    assert!(
        matches!(honest_refusal, EconomyError::RewardBindingIncomplete(_)),
        "the terminal refusal is the typed variant, got: {honest_refusal}"
    );
    // The constant is the prefix of the message, not the whole of it: the
    // variant appends the reason the binding is missing.
    assert!(
        honest_refusal
            .to_string()
            .starts_with(REWARD_BINDING_INCOMPLETE),
        "the refusal must open with the crate's stable marker: {honest_refusal}"
    );

    // A reward claiming a different job...
    let wrong_job = reward_evidence("cqr-attest-job-999", SAMPLE_PROOF_RESULT_DIGEST);
    let wrong_job_refusal = binding_refusal(&proof, wrong_job, &attestation, &policy);
    assert!(
        matches!(wrong_job_refusal, EconomyError::Invalid(_)),
        "the job_id mismatch is caught earlier and is still Invalid, got: {wrong_job_refusal}"
    );
    let message = wrong_job_refusal.to_string();
    assert!(
        message.contains("job_id 'cqr-attest-job-999' does not match proof job_id"),
        "unexpected refusal: {message}"
    );
    assert!(
        !message.starts_with(REWARD_BINDING_INCOMPLETE),
        "the mismatch is caught before the binding refusal: {message}"
    );

    // ...and a reward claiming a different result digest.
    let wrong_result = reward_evidence(
        SAMPLE_PROOF_JOB_ID,
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    );
    let wrong_result_refusal = binding_refusal(&proof, wrong_result, &attestation, &policy);
    assert!(
        matches!(wrong_result_refusal, EconomyError::Invalid(_)),
        "the result_digest mismatch is caught earlier and is still Invalid, got: {wrong_result_refusal}"
    );
    let message = wrong_result_refusal.to_string();
    assert!(
        message.contains("result_digest '") && message.contains("does not match proof result_digest"),
        "unexpected refusal: {message}"
    );
    assert!(
        !message.starts_with(REWARD_BINDING_INCOMPLETE),
        "the mismatch is caught before the binding refusal: {message}"
    );
}

#[test]
fn the_attestation_preimage_carries_no_payment_identity() {
    let (_dir, _socket, auth, policy) = authority();
    let proof = sample_proof(SAMPLE_PROOF_JOB_ID, SAMPLE_PROOF_RESULT_DIGEST);
    let policy_hash = policy.policy_hash().expect("a validated policy hashes");

    let preimage = proof.attestation_preimage(policy_hash.as_str());
    let text = String::from_utf8_lossy(&preimage);

    // Positive control. Everything the preimage *does* carry is findable in it,
    // so each `!contains` below is a real absence rather than a search that
    // silently never matched anything.
    for (label, component) in [
        ("domain", "MYCELIUM-ECONOMY/CQR-ATTESTATION/V1"),
        ("policy_hash", policy_hash.as_str()),
        ("proof_digest", proof.proof_digest.as_str()),
        ("result_digest", proof.result_digest.as_str()),
        ("job_hash", proof.job_hash.as_str()),
    ] {
        assert!(text.contains(component), "the preimage must carry its {label}");
    }

    // A payment, with sentinel values chosen so that an accidental match on a
    // common substring is not possible: a repeated-deadbeef transaction hash, two
    // addresses that appear in no address list, and an amount whose decimal and
    // hexadecimal spellings are both long.
    let reward = reward_evidence(SAMPLE_PROOF_JOB_ID, SAMPLE_PROOF_RESULT_DIGEST);
    assert_eq!(reward.job_id, proof.job_id);
    assert_eq!(reward.result_digest, proof.result_digest);
    let amount_decimal = reward.gross_amount_musd_micros.to_string();
    assert_eq!(amount_decimal, "7777777777");
    let amount_hex = format!("{:x}", reward.gross_amount_musd_micros);
    let amount_hex_prefixed = format!("0x{amount_hex}");

    for (label, sentinel) in [
        ("settlement_tx_hash", reward.settlement_tx_hash.as_str()),
        ("payer", reward.payer.as_str()),
        ("recipient", reward.recipient.as_str()),
        ("reward amount, decimal", amount_decimal.as_str()),
        ("reward amount, hex", amount_hex.as_str()),
        ("reward amount, 0x-prefixed hex", amount_hex_prefixed.as_str()),
    ] {
        assert!(
            !text.contains(sentinel),
            "the attestation preimage must not carry the {label}"
        );
    }

    // This is the structural reason `UnverifiedComputeEvidence::verify` must
    // refuse with `REWARD_BINDING_INCOMPLETE`: the delegated verifier signs the
    // domain, the policy hash, the proof digest, the result digest and the job
    // hash — and no part of the payment. A perfectly valid signature over a
    // perfectly valid proof therefore says nothing about whether anybody paid,
    // so there is no value of `AuthenticatedComputeEvidence` for it to
    // authenticate. The refusal below is that fact, not a missing feature.
    let attestation = CqrResultAttestation::attest(&proof, &policy, &auth.verifier)
        .expect("the delegated verifier signs this proof");
    assert!(attestation.verify(&proof, &policy).is_ok());

    match UnverifiedComputeEvidence::new(proof.clone(), reward, attestation).verify(&policy) {
        Err(error @ EconomyError::RewardBindingIncomplete(_)) => {
            // The typed variant is the stronger assertion; the constant is the
            // stable prefix of its `Display`, with the reason appended.
            assert!(
                error.to_string().starts_with(REWARD_BINDING_INCOMPLETE),
                "the refusal must open with the crate's stable marker: {error}"
            );
        }
        Err(other) => panic!("expected a typed binding refusal, got: {other}"),
        Ok(_) => panic!("an unsigned payment identity must never authenticate"),
    }
}

#[test]
fn periodic_known_answer_does_not_accept_nonperiodic_boundary() {
    let state = sample_64_oscillator_state();
    let hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());
    let mut spec = sample_job_spec(&hash);
    spec.classical_spec.periodic_boundary = false;
    let report = validate_job_with_thermal(&spec, &state, &FakeThermalSource::new(40.0))
        .expect("validation report");
    assert!(!report.physical_known_answer_valid);
}
