//! Economic Bridge Tests — CQR Compute vs NEV Invariants.
//!
//! CRITICAL PRINCIPLES ENFORCED:
//! 1. CQR computation != NEV
//! 2. Useful work != NEV
//! 3. MYC issuance != NEV
//! 4. Synthetic PnL != NEV
//! 5. Experimental / Verifiable ComputeReward cannot masquerade as REAL
//! 6. NEV requires: external counterparty -> external real payment -> authenticated evidence
//!    -> complete settlement -> trusted valuation -> VerifiedNev.

use mycelium_economy::boundary::{
    BoundaryCrossing, BoundaryDirection, BoundaryEvidence, ControlledAddressRegistry, RealAsset,
};
use mycelium_economy::base_usdc::{BaseUsdcVerifier, TransactionLogScan, BASE_CHAIN_ID, BASE_USDC};
use mycelium_economy::chain_provider::{resolve, PinnedChainProvider};
use mycelium_economy::cqr::oscillators::{run_benchmark_with_telemetry, FakeThermalSource};
use mycelium_economy::cqr::{
    create_cqr_work_receipt, ClassicalSpec, ComputeRewardAdapter, ComputeRewardStatus,
    CqrComputeLevel, CqrJobSpec, CqrResourceBudget, CqrResult, CqrResultAttestation,
    CqrResultProof, ExternalRewardEvidence, IntegratorSpec, PhaseSpacePoint, PrecisionPolicy,
    TolerancePolicy,
};
use mycelium_economy::cqr::state_bus::hash_component;
use mycelium_economy::discovery::{
    AdapterRegistry, ClassSupport, OpportunityClass,
};
use mycelium_economy::event_id::{ExternalEventFact, ExternalEventId};
use mycelium_economy::nev0::{
    CostBasis, EvidenceAuthentication, EvidenceProvenance, Nev0Gate, Nev0Inputs,
    ProviderStanding, SettlementCompleteness,
};
use mycelium_economy::nev_tier::{NevTier, NevTierEvaluator, VerifiedNevEvent};
use mycelium_economy::policy_auth::{PolicyError, ValidatedOutcomePolicy, VerifierRuntimeKey};
use mycelium_economy::autonomy::ExternalValueClass;
use mycelium_economy::settlement::{
    ComparableSettlementResult, LegState, SettlementInputs, SettlementOutcome, VerifiedSettlement,
};
use mycelium_economy::testkit::{AuthFixture, FakeRpcSocket};
use mycelium_economy::trusted_valuation::ValidatedPriceSource;
use mycelium_economy::EconomyError;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// The controlled side. Exactly one address, so "which direction" has a single
/// answer in every test below.
const CONTROLLED: &str = "0x1111111111111111111111111111111111111111";
/// The external counterparty on the other side of the perimeter.
const COUNTERPARTY: &str = "0x3333333333333333333333333333333333333333";
/// A contract this build cannot identify: a Transfer on it makes a chain read
/// non-exhaustive rather than a leg.
const UNIDENTIFIED_TOKEN: &str = "0x2222222222222222222222222222222222222222";

/// The block timestamp every chain fixture below settles in (`0x6553f100`).
const SETTLE_TIMESTAMP_UNIX: u64 = 0x6553f100;
/// Evaluated at the first UTC midnight at or after the settling block, so the
/// event sits in the current partial day rather than in the rolling window.
const EVAL_NOW_UNIX: u64 = (SETTLE_TIMESTAMP_UNIX / 86_400 + 1) * 86_400;
/// The routine monthly operating cost every evaluator below is given. It only
/// ever matters at NEV3, and nothing here reaches NEV3.
const MONTHLY_OPERATING_COST_MICROS: i64 = 10_000_000;

/// The transaction every settlement fixture below settles in.
fn payment_tx() -> String {
    format!("0x{}", "cd".repeat(32))
}

/// A transaction hash nobody in these tests has any receipt for.
fn other_tx() -> String {
    format!("0x{}", "ef".repeat(32))
}

/// The block every chain fixture below settles in.
fn block_hash() -> String {
    format!("0x{}", "ab".repeat(32))
}

/// One ERC-20 `Transfer` log, spelled the way a receipt spells one.
fn transfer_log(
    log_index: &str,
    token: &str,
    from: &str,
    to: &str,
    amount_raw: u64,
) -> serde_json::Value {
    serde_json::json!({
        "address": token,
        "topics": [
            mycelium_economy::base_usdc::ERC20_TRANSFER_TOPIC,
            format!("0x{:0>64}", from.trim_start_matches("0x")),
            format!("0x{:0>64}", to.trim_start_matches("0x")),
        ],
        "data": format!("0x{amount_raw:064x}"),
        "logIndex": log_index,
    })
}

/// A receipt body for `tx` carrying exactly `logs`, plus the gas fields.
///
/// Gas is a parameter rather than a constant so the "a settlement with no
/// native cost is promotable" and the "a settlement that burned gas needs a
/// price" cases can be told apart in the same fixture shape.
fn receipt_for(
    tx: &str,
    logs: Vec<serde_json::Value>,
    gas_used: &str,
    effective_gas_price: &str,
) -> serde_json::Value {
    serde_json::json!({
        "status": "0x1",
        "blockNumber": "0x65",
        "blockHash": block_hash(),
        "transactionHash": tx,
        "logs": logs,
        "gasUsed": gas_used,
        "effectiveGasPrice": effective_gas_price,
    })
}

/// The stored evidence row for one external -> controlled transfer.
fn inflow_evidence(tx: &str, amount_raw: u64) -> BoundaryEvidence {
    BoundaryEvidence {
        chain_id: BASE_CHAIN_ID,
        asset: RealAsset::base_usdc(),
        from_address: COUNTERPARTY.into(),
        to_address: CONTROLLED.into(),
        amount_raw,
        tx_hash: tx.into(),
        block_hash: block_hash(),
    }
}

/// The stored evidence row for one controlled -> external transfer: the
/// outward leg, the half of an operation that leaves nothing to promote.
fn outflow_evidence(tx: &str, amount_raw: u64) -> BoundaryEvidence {
    BoundaryEvidence {
        chain_id: BASE_CHAIN_ID,
        asset: RealAsset::base_usdc(),
        from_address: CONTROLLED.into(),
        to_address: COUNTERPARTY.into(),
        amount_raw,
        tx_hash: tx.into(),
        block_hash: block_hash(),
    }
}

/// The whole chain of authority a settlement test walks, assembled once: a
/// pinned unix socket serving one receipt, the verifier that reads the chain
/// through it, the controlled registry that decides direction, the validated
/// outcome policy, and the delegated verifier key that policy names.
///
/// Field order is drop order, so the socket is dropped — and its accept loop
/// joined — while the temporary directory holding its path still exists.
struct SettlementChain {
    _socket: FakeRpcSocket,
    _dir: tempfile::TempDir,
    registry: ControlledAddressRegistry,
    verifier: BaseUsdcVerifier,
    policy: ValidatedOutcomePolicy,
    delegated_verifier: VerifierRuntimeKey,
}

impl SettlementChain {
    /// Serves `receipt` for every transaction asked about.
    fn serving(receipt: serde_json::Value) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = FakeRpcSocket::with_dispatch(
            dir.path().join("verifier.sock"),
            move |method: &str, _params: &serde_json::Value| -> Option<serde_json::Value> {
                Some(match method {
                    "eth_chainId" => serde_json::json!("0x2105"),
                    "eth_blockNumber" => serde_json::json!("0x100"),
                    "eth_getTransactionReceipt" => receipt.clone(),
                    "eth_getBlockByNumber" => serde_json::json!({
                        "hash": block_hash(),
                        "timestamp": format!("0x{SETTLE_TIMESTAMP_UNIX:x}"),
                    }),
                    _ => return None,
                })
            },
        );

        let registry = ControlledAddressRegistry::new()
            .with_address(CONTROLLED)
            .expect("valid controlled address");
        let provider =
            PinnedChainProvider::unix_socket(socket.path(), Some(socket.uid())).unwrap();
        let resolved = resolve(None, Some(&provider)).unwrap();
        let verifier = BaseUsdcVerifier::from_resolved(&resolved, 2).unwrap();
        let auth = AuthFixture::new(socket.path(), socket.uid(), registry.clone());
        let policy = auth.validated();
        let delegated_verifier = auth.verifier.clone();

        Self {
            _socket: socket,
            _dir: dir,
            registry,
            verifier,
            policy,
            delegated_verifier,
        }
    }

    /// The scan the pinned verifier produced, through the real RPC path rather
    /// than from a hand-built value.
    fn scan(&self, tx: &str) -> TransactionLogScan {
        self.verifier.scan_transaction(tx).expect("a confirmed transaction")
    }

    /// The price source this policy authorises, bound. Holding one is the
    /// statement "the policy in force named this price source".
    fn price_source(&self) -> ValidatedPriceSource {
        ValidatedPriceSource::bind(
            &self.policy,
            &mycelium_economy::trusted_valuation::testkit::canonical(BASE_CHAIN_ID),
        )
        .expect("the fixture policy authorises the canonical price source")
    }
}

/// A validated outcome policy over a real pinned socket, with the fixture kept
/// alive beside it. The CQR half of these tests needs no chain read — only an
/// authority to sign under and to be read back under.
///
/// Field order is drop order: the socket goes before the directory that holds
/// its path.
struct CqrAuthority {
    _socket: FakeRpcSocket,
    _dir: tempfile::TempDir,
    auth: AuthFixture,
}

impl CqrAuthority {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = FakeRpcSocket::bind(dir.path().join("policy.sock"));
        let auth = AuthFixture::new(
            socket.path(),
            socket.uid(),
            ControlledAddressRegistry::new(),
        );
        Self {
            _socket: socket,
            _dir: dir,
            auth,
        }
    }

    /// Re-reads the pin and re-validates, the way a process that has just
    /// started would.
    fn policy(&self) -> ValidatedOutcomePolicy {
        self.auth.validated()
    }
}

fn sample_oscillator_job() -> (CqrJobSpec, PhaseSpacePoint) {
    let mut q = vec![0.0; 64];
    let mut p = vec![0.0; 64];
    for i in 0..64 {
        q[i] = (i as f64 * 0.1).sin();
        p[i] = (i as f64 * 0.1).cos();
    }
    let state = PhaseSpacePoint::new(q, p);
    let initial_hash = hash_component(b"mycelium:cqr:phase_space:v1", &state.to_bytes());

    let spec = CqrJobSpec {
        schema_version: 1,
        job_id: "job-cqr-econ-1".into(),
        model_id: "coupled_oscillators_64".into(),
        model_version: "1.0.0".into(),
        compute_level: CqrComputeLevel::C0ClassicalSymplectic,
        initial_state_hash: initial_hash,
        classical_spec: ClassicalSpec {
            oscillator_count: 64,
            mass: 1.0,
            spring_constant: 1.5,
            periodic_boundary: true,
        },
        integrator_spec: IntegratorSpec::VelocityVerlet,
        precision_policy: PrecisionPolicy::Float64Strict,
        tolerance_policy: TolerancePolicy::default(),
        step_count: 50,
        time_step: 0.01,
        seed: None,
        resource_budget: CqrResourceBudget::default(),
        expected_observables: vec!["energy".into()],
        validation_suite: vec!["symplectic".into()],
    };

    (spec, state)
}

/// One real CQR run, on a scripted thermal source.
///
/// Deliberately NOT `run_benchmark`: that reads this host's real CPU package
/// temperature, and a hot machine would refuse at the thermal gate — a fact
/// about the machine, not about what these tests are about.
fn run_sample_cqr(spec: &CqrJobSpec, state: PhaseSpacePoint) -> CqrResult {
    let source = FakeThermalSource::new(40.0);
    run_benchmark_with_telemetry(spec, state, &source)
        .expect("benchmark run succeeds on a scripted 40 °C source")
        .0
}

/// The proof the crate builds for a real result: every component taken from the
/// run itself.
fn sample_proof(proof_id: &str, result: &CqrResult) -> CqrResultProof {
    CqrResultProof::new(
        proof_id,
        &result.job_id,
        &result.job_hash,
        &result.input_state_hash,
        &result.output_state_hash,
        &result.implementation_id,
        &result.implementation_version,
        "suite-v1",
        &result.result_digest,
        "worker-local",
    )
}

/// A reward label whose `job_id` and `result_digest` both MATCH a real proof, so
/// every string-equality binding check in the crate passes. The payment
/// identity inside it is invented: no chain in this test file says any of it.
fn matching_reward(result: &CqrResult) -> ExternalRewardEvidence {
    ExternalRewardEvidence {
        settlement_tx_hash: other_tx(),
        chain_id: BASE_CHAIN_ID,
        payer: COUNTERPARTY.to_string(),
        recipient: CONTROLLED.to_string(),
        gross_amount_musd_micros: 50_000,
        job_id: result.job_id.clone(),
        result_digest: result.result_digest.clone(),
    }
}

/// The same signature with its final nibble changed: still valid hex of the same
/// length, so it decodes into a 64-byte signature and is rejected by the
/// signature check rather than by the encoding.
fn corrupt_signature_hex(signature_hex: &str) -> String {
    let mut bytes = signature_hex.as_bytes().to_vec();
    if let Some(last) = bytes.len().checked_sub(1) {
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
    }
    String::from_utf8(bytes).expect("hex is ascii")
}

// ---------------------------------------------------------------------------
// Useful work is not value
// ---------------------------------------------------------------------------

#[test]
fn cqr_result_and_useful_work_receipt_alone_produce_zero_nev() {
    let (spec, state) = sample_oscillator_job();
    let result = run_sample_cqr(&spec, state);
    let proof = sample_proof("proof-1", &result);

    // Creates useful work receipt
    let work_receipt = create_cqr_work_receipt(
        &spec,
        &result,
        &proof,
        "work-receipt-1",
        "worker-local",
        "verifier-local",
        1_000,
        1_010,
    );

    assert!(work_receipt.verified);
    assert_eq!(work_receipt.useful_work_units, 64 * 50);

    // But NEV evaluator with no external payments produces PreNev0
    let mut nev_evaluator = NevTierEvaluator::new(MONTHLY_OPERATING_COST_MICROS);
    let status = nev_evaluator.evaluate(EVAL_NOW_UNIX);
    assert_eq!(status.current_verified_tier, NevTier::PreNev0);
    assert_eq!(status.cumulative_verified_nev_micros, 0);
}

#[test]
fn experimental_compute_reward_adapter_does_not_masquerade_as_real() {
    let adapter = ComputeRewardAdapter::new_experimental("cqr-exp-adapter");
    assert_eq!(adapter.status(), ComputeRewardStatus::Experimental);

    let mut registry = AdapterRegistry::new();
    assert_eq!(registry.support(OpportunityClass::ComputeReward), ClassSupport::Unsupported);

    registry.register(Box::new(adapter));
    assert_eq!(registry.support(OpportunityClass::ComputeReward), ClassSupport::Implemented);
}

#[test]
fn nev0_gate_refuses_synthetic_internal_or_unauthenticated_compute_evidence() {
    // 1. Synthetic origin refused
    let inputs_synthetic = Nev0Inputs {
        class: OpportunityClass::ComputeReward,
        provenance: EvidenceProvenance::Synthetic {
            label: "internal_cqr_useful_work".into(),
        },
        provider: ProviderStanding::KernelEnforced {
            endpoint: "unix:///run/mycelium-verifier.sock".into(),
            identity_hash: "id-hash".into(),
        },
        authentication: EvidenceAuthentication::DelegatedVerifierSignature {
            key_id: "key-1".into(),
        },
        value_classes: &[ExternalValueClass::ExternalServicePayment],
        settlement: SettlementCompleteness::Complete {
            legs: 1,
            scanned_exhaustively: true,
        },
        cost: CostBasis::NetOfOutflows {
            gross_inflow_musd_micros: 50_000,
            external_cost_musd_micros: 2_000,
            native_cost_musd_micros: 1_000,
        },
        anchor: None,
        verified_nev: None,
    };

    let adjudication = Nev0Gate::adjudicate(&inputs_synthetic);
    assert!(!adjudication.is_granted());
    assert!(adjudication.refusals().iter().any(|r| r.category() == "synthetic_value"));

    // 2. Unsigned evidence refused
    let inputs_unsigned = Nev0Inputs {
        class: OpportunityClass::ComputeReward,
        provenance: EvidenceProvenance::LiveChain {
            chain_id: 8453,
            block_number: 10_000,
        },
        provider: ProviderStanding::KernelEnforced {
            endpoint: "unix:///run/mycelium-verifier.sock".into(),
            identity_hash: "id-hash".into(),
        },
        authentication: EvidenceAuthentication::Unsigned,
        value_classes: &[ExternalValueClass::ExternalServicePayment],
        settlement: SettlementCompleteness::Complete {
            legs: 1,
            scanned_exhaustively: true,
        },
        cost: CostBasis::NetOfOutflows {
            gross_inflow_musd_micros: 50_000,
            external_cost_musd_micros: 2_000,
            native_cost_musd_micros: 1_000,
        },
        anchor: None,
        verified_nev: None,
    };

    let adjudication2 = Nev0Gate::adjudicate(&inputs_unsigned);
    assert!(!adjudication2.is_granted());
    assert!(adjudication2.refusals().iter().any(|r| r.category() == "unsigned_evidence"));

    // 3. Incomplete settlement refused
    let inputs_incomplete = Nev0Inputs {
        class: OpportunityClass::ComputeReward,
        provenance: EvidenceProvenance::LiveChain {
            chain_id: 8453,
            block_number: 10_000,
        },
        provider: ProviderStanding::KernelEnforced {
            endpoint: "unix:///run/mycelium-verifier.sock".into(),
            identity_hash: "id-hash".into(),
        },
        authentication: EvidenceAuthentication::DelegatedVerifierSignature {
            key_id: "key-1".into(),
        },
        value_classes: &[ExternalValueClass::ExternalServicePayment],
        settlement: SettlementCompleteness::Incomplete {
            gaps: vec![mycelium_economy::discovery::SettlementGap::Absent {
                why: "missing return leg".into(),
            }],
        },
        cost: CostBasis::NetOfOutflows {
            gross_inflow_musd_micros: 50_000,
            external_cost_musd_micros: 2_000,
            native_cost_musd_micros: 1_000,
        },
        anchor: None,
        verified_nev: None,
    };

    let adjudication3 = Nev0Gate::adjudicate(&inputs_incomplete);
    assert!(!adjudication3.is_granted());
    assert!(adjudication3.refusals().iter().any(|r| r.category() == "incomplete_settlement"));
}

// ---------------------------------------------------------------------------
// The positive control: a real chain payment reaches NEV0
// ---------------------------------------------------------------------------

#[test]
fn chain_boundary_settlement_valuation_produces_verified_nev_event() {
    let tx = payment_tx();
    // Single external fee payment inflow leg of 50_000 USDC micros (0.05 USDC)
    let chain = SettlementChain::serving(receipt_for(
        &tx,
        vec![transfer_log("0x1", BASE_USDC, COUNTERPARTY, CONTROLLED, 50_000)],
        "0x0",
        "0x0",
    ));

    let scan = chain.scan(&tx);
    let evidence = vec![inflow_evidence(&tx, 50_000)];

    let inputs = SettlementInputs::new(vec![&scan], &chain.registry, &evidence, Some(&chain.policy));
    let outcome = VerifiedSettlement::assemble(&inputs).unwrap();
    let settlement = match outcome {
        SettlementOutcome::Complete(s) => s,
        SettlementOutcome::Incomplete(i) => panic!("settlement must be complete: {:?}", i.reasons()),
    };

    let comparable = match settlement.compare(&chain.price_source(), &[]) {
        ComparableSettlementResult::Comparable(c) => c,
        ComparableSettlementResult::NoComparableNetValue(r) => panic!("settlement must be comparable: {r:?}"),
    };

    // No `ExternalEventId` is computed here any more and none can be passed in.
    // The constructor derives the identity from the settlement's own authenticated
    // facts — this receipt's block anchor, its operation id and the canonical event
    // id of its one established leg — and a complete, exhaustive, single-leg
    // settlement is exactly the shape that always derives one.
    let event = VerifiedNevEvent::from_comparable_settlement(
        &comparable,
        OpportunityClass::Arbitrage,
    )
    .expect("a complete settlement derives an economic identity");

    let mut evaluator = NevTierEvaluator::new(MONTHLY_OPERATING_COST_MICROS);
    evaluator.record_event(event).expect("recording valid event succeeds");
    let status = evaluator.evaluate(EVAL_NOW_UNIX);

    assert_eq!(status.current_verified_tier, NevTier::Nev0);
    assert_eq!(status.highest_ever_verified_tier, NevTier::Nev0);
    assert_eq!(status.cumulative_verified_nev_micros, 50_000);
    assert_eq!(status.current_window_net_nev_micros, 50_000);
    assert_eq!(status.cumulative_event_count, 1);
}

// ---------------------------------------------------------------------------
// What the CQR side really does bind, and what it does not
// ---------------------------------------------------------------------------

#[test]
fn compute_reward_evidence_binding_mismatch_fails_verification() {
    let authority = CqrAuthority::new();
    let policy = authority.policy();

    let (spec, state) = sample_oscillator_job();
    let result = run_sample_cqr(&spec, state);
    let proof = sample_proof("proof-binding-1", &result);

    let attestation = CqrResultAttestation::attest(&proof, &policy, &authority.auth.verifier).unwrap();
    let adapter = ComputeRewardAdapter::new_experimental("test-adapter");

    // Case 1: Mismatched job_id
    let mismatched_job_reward = ExternalRewardEvidence {
        settlement_tx_hash: "0x1234".into(),
        chain_id: 8453,
        payer: "0xpayer".into(),
        recipient: "0xrecipient".into(),
        gross_amount_musd_micros: 50_000,
        job_id: "forged-job-id".into(),
        result_digest: result.result_digest.clone(),
    };
    let unverified1 = adapter.package_evidence(proof.clone(), mismatched_job_reward, attestation.clone());
    let err1 = unverified1.verify(&policy).unwrap_err();
    assert!(err1.to_string().contains("job_id 'forged-job-id' does not match"));

    // Case 2: Mismatched result_digest
    let mismatched_digest_reward = ExternalRewardEvidence {
        settlement_tx_hash: "0x1234".into(),
        chain_id: 8453,
        payer: "0xpayer".into(),
        recipient: "0xrecipient".into(),
        gross_amount_musd_micros: 50_000,
        job_id: result.job_id.clone(),
        result_digest: "forged-result-digest".into(),
    };
    let unverified2 = adapter.package_evidence(proof, mismatched_digest_reward, attestation);
    let err2 = unverified2.verify(&policy).unwrap_err();
    assert!(err2.to_string().contains("result_digest 'forged-result-digest' does not match"));
}

#[test]
fn unauthenticated_cqr_attestation_fails_verification() {
    let authority = CqrAuthority::new();
    let policy = authority.policy();

    let (spec, state) = sample_oscillator_job();
    let result = run_sample_cqr(&spec, state);
    let proof = sample_proof("proof-auth-1", &result);

    // Impostor verifier key not in policy
    let impostor = VerifierRuntimeKey::generate();
    let forged_attestation = CqrResultAttestation::attest(&proof, &policy, &impostor).unwrap();

    let valid_reward = ExternalRewardEvidence {
        settlement_tx_hash: "0x1234".into(),
        chain_id: 8453,
        payer: "0xpayer".into(),
        recipient: "0xrecipient".into(),
        gross_amount_musd_micros: 50_000,
        job_id: result.job_id.clone(),
        result_digest: result.result_digest.clone(),
    };

    let adapter = ComputeRewardAdapter::new_experimental("test-adapter");
    let unverified = adapter.package_evidence(proof, valid_reward, forged_attestation);
    let err = unverified.verify(&policy).unwrap_err();
    assert!(err.to_string().contains("CQR attestation cryptographic verification failed"));
}

/// THE SEAM, TRAVERSED END TO END IN ONE FUNCTION.
///
/// Half one is the strongest thing the CQR side can produce: a real benchmark
/// run, a real result proof over it, and a real delegated-verifier attestation
/// that verifies against the policy in force. That part genuinely works.
///
/// Half two is the strongest thing the settlement side can produce: a genuine
/// ERC-20 `Transfer` log read through a pinned unix socket, a complete
/// settlement, a priced comparison, a `VerifiedNevEvent` and `Nev0`.
///
/// They are not connected, and this test is where that is visible rather than
/// asserted in prose.
#[test]
fn cqr_authenticated_computation_cannot_mint_nev_but_a_real_settled_payment_reaches_nev0() {
    let tx = payment_tx();
    // One fixture serves both halves: the same policy signs the CQR attestation
    // and authorises the settlement. What differs is only what is being claimed.
    let chain = SettlementChain::serving(receipt_for(
        &tx,
        vec![transfer_log("0x1", BASE_USDC, COUNTERPARTY, CONTROLLED, 50_000)],
        "0x0",
        "0x0",
    ));
    let policy = chain.policy.clone();

    // ---- (a) A real CQR job, really executed. ---------------------------
    let (spec, state) = sample_oscillator_job();
    let result = run_sample_cqr(&spec, state);

    // ---- (b) A real proof over it, really attested by the delegated key. --
    let proof = sample_proof("proof-cqr-seam", &result);
    let attestation = CqrResultAttestation::attest(&proof, &policy, &chain.delegated_verifier)
        .expect("the delegated verifier signs a real proof");

    // ---- (c) The computation really is authenticated. --------------------
    assert!(
        attestation.verify(&proof, &policy).is_ok(),
        "an attestation over a real proof, by the key the policy delegates to, verifies"
    );
    assert_eq!(
        attestation.verifier_key_id,
        chain.delegated_verifier.key_id().to_string()
    );
    assert_eq!(attestation.proof_digest, proof.proof_digest);

    // ---- (d) A payment label that passes every binding check. -----------
    //
    // `job_id` and `result_digest` both match the proof, so the crate's two
    // string-equality bindings are satisfied. The payment identity is invented:
    // `other_tx()` is a transaction no chain in this file has a receipt for, and
    // the amount is a number, not a transfer.
    let fabricated = matching_reward(&result);
    assert_eq!(fabricated.job_id, proof.job_id);
    assert_eq!(fabricated.result_digest, proof.result_digest);

    let adapter = ComputeRewardAdapter::new_experimental("cqr-seam-adapter");
    let unverified =
        adapter.package_evidence(proof.clone(), fabricated, attestation.clone());
    let refusal = unverified.verify(&policy).unwrap_err();

    assert!(
        matches!(&refusal, EconomyError::RewardBindingIncomplete(_)),
        "an authenticated computation plus a payment label is still not an \
         authenticated payment: {refusal}"
    );
    assert!(
        refusal.to_string().contains("RewardBindingIncomplete"),
        "{refusal}"
    );

    // Therefore no `AuthenticatedComputeEvidence` exists, therefore there is
    // nothing to record: the evaluator is still empty after half one.
    let mut evaluator = NevTierEvaluator::new(MONTHLY_OPERATING_COST_MICROS);
    let after_cqr = evaluator.evaluate(EVAL_NOW_UNIX);
    assert_eq!(after_cqr.current_verified_tier, NevTier::PreNev0);
    assert_eq!(after_cqr.cumulative_verified_nev_micros, 0);
    assert_eq!(after_cqr.cumulative_event_count, 0);

    // ---- (e) The same fixture's real payment, traversed in full. ---------
    let scan = chain.scan(&tx);
    let evidence = vec![inflow_evidence(&tx, 50_000)];
    let inputs =
        SettlementInputs::new(vec![&scan], &chain.registry, &evidence, Some(&policy));
    let outcome = VerifiedSettlement::assemble(&inputs).unwrap();
    let settlement = match outcome {
        SettlementOutcome::Complete(s) => s,
        SettlementOutcome::Incomplete(i) => {
            panic!("settlement must be complete: {:?}", i.reasons())
        }
    };
    let comparable = match settlement.compare(&chain.price_source(), &[]) {
        ComparableSettlementResult::Comparable(c) => c,
        ComparableSettlementResult::NoComparableNetValue(r) => {
            panic!("settlement must be comparable: {r:?}")
        }
    };

    // The identity is derived inside the constructor from this settlement's own
    // authenticated facts, so there is no `ExternalEventId` to build here at all:
    // the payment this settlement settled is named by its anchor and its leg.
    let event = VerifiedNevEvent::from_comparable_settlement(
        &comparable,
        OpportunityClass::Arbitrage,
    )
    .expect("a complete settlement derives an economic identity");
    evaluator
        .record_event(event)
        .expect("recording the settled payment succeeds");
    let after_settlement = evaluator.evaluate(EVAL_NOW_UNIX);

    assert_eq!(after_settlement.current_verified_tier, NevTier::Nev0);
    assert!(
        after_settlement.cumulative_verified_nev_micros > 0,
        "a real settled payment is worth strictly more than nothing"
    );
    assert_eq!(after_settlement.cumulative_verified_nev_micros, 50_000);
    assert_eq!(after_settlement.cumulative_event_count, 1);

    // SEAM:
    //
    // The unconnected step is between `CqrResultAttestation` and
    // `ExternalRewardEvidence.settlement_tx_hash` / `payer` / `recipient` /
    // `gross_amount_musd_micros`. Everything before it is real and everything
    // after it is real, and nothing joins them.
    //
    // Why, precisely: `CqrResultProof::attestation_preimage` signs exactly
    // `domain || policy_hash || proof_digest || result_digest || job_hash`.
    // Those five fields are what `attestation.verify` re-derives and checks.
    // The entire payment identity of an `ExternalRewardEvidence` appears in
    // NO signed preimage — not in the attestation preimage and not in the
    // proof digest. The two reward fields the crate does compare, `job_id` and
    // `result_digest`, are checked by equality against values the proof
    // already fixes, so making them match proves only that whoever assembled
    // the evidence read the proof. It does not prove a payment bought it.
    //
    // Why there is no honest way around it here: there is no external compute
    // market this adapter is paid by, so no on-chain artefact references a CQR
    // `result_digest`. There is no receipt, no `Transfer`, no attested event
    // naming the digest. `AuthenticatedComputeEvidence` therefore has no
    // constructor at all, by construction rather than by omission, and the
    // CQR branch terminates at `EconomyError::RewardBindingIncomplete`.
    //
    // What would have to exist first: a chain-verifiable claim that NAMES the
    // CQR result digest. Concretely, either (a) an on-chain artefact — a
    // receipt or attested event — whose bytes contain `result_digest`, so a
    // chain read can bind a payment to this exact computation; or (b) a
    // delegated attestation whose preimage additionally signs
    // `settlement_tx_hash`, `chain_id`, `payer`, `recipient` and
    // `gross_amount_musd_micros`. Either one would put the payment identity
    // inside the signed statement, and only then could `verify` return `Ok`.
    //
    // NEV in this build comes from the settlement branch alone. That is the
    // honest reading, not a gap papered over.
}

/// A `CqrResult` and a `CqrResultProof` over it, with a useful-work receipt
/// and not one byte of chain state: nothing to record, so nothing is recorded.
#[test]
fn cqr_result_alone_produces_no_nev_event() {
    let (spec, state) = sample_oscillator_job();
    let result = run_sample_cqr(&spec, state);
    let proof = sample_proof("proof-result-alone", &result);

    assert!(proof.verify_integrity(), "the worker's own commitment holds");

    // The strongest artefact the CQR side produces on its own: a verified
    // useful-work receipt saying the work happened and how much of it there was.
    let work_receipt = create_cqr_work_receipt(
        &spec,
        &result,
        &proof,
        "work-receipt-alone",
        "worker-local",
        "verifier-local",
        1_000,
        1_010,
    );
    assert!(work_receipt.verified);
    assert_eq!(work_receipt.useful_work_units, 64 * 50);

    // No socket, no receipt, no `BoundaryEvidence`: there is no external
    // counterparty anywhere in this test.
    let mut evaluator = NevTierEvaluator::new(MONTHLY_OPERATING_COST_MICROS);
    let status = evaluator.evaluate(EVAL_NOW_UNIX);
    assert_eq!(status.current_verified_tier, NevTier::PreNev0);
    assert_eq!(status.cumulative_verified_nev_micros, 0);
    assert_eq!(status.cumulative_event_count, 0);
}

/// A commitment is not a signature. Three ways to hold a `CqrResultProof` that
/// no attestation covers.
#[test]
fn a_cqr_commitment_without_an_attestation_is_refused() {
    let authority = CqrAuthority::new();
    let policy = authority.policy();

    let (spec, state) = sample_oscillator_job();
    let result = run_sample_cqr(&spec, state);
    let proof = sample_proof("proof-commitment-unattested", &result);
    let adapter = ComputeRewardAdapter::new_experimental("cqr-unattested-adapter");

    // Case 1: an attestation that names the right proof, the right policy and
    // the right key, and carries no signature at all.
    let bare = CqrResultAttestation {
        proof_digest: proof.proof_digest.clone(),
        policy_hash: policy.policy_hash().unwrap().to_string(),
        verifier_key_id: authority.auth.verifier.key_id().to_string(),
        signature_hex: "0x".into(),
    };
    let err = bare.verify(&proof, &policy).unwrap_err();
    assert!(
        matches!(&err, PolicyError::BadSignature),
        "an empty signature is not a signature: {err}"
    );
    let packaged = adapter.package_evidence(proof.clone(), matching_reward(&result), bare);
    let gated = packaged.verify(&policy).unwrap_err();
    assert!(
        gated
            .to_string()
            .contains("CQR attestation cryptographic verification failed"),
        "{gated}"
    );

    // Case 2: an otherwise perfectly real attestation whose signature bytes have
    // been altered. Same encoding, same length, different bytes.
    let real =
        CqrResultAttestation::attest(&proof, &policy, &authority.auth.verifier).unwrap();
    let mut corrupted = real.clone();
    corrupted.signature_hex = corrupt_signature_hex(&real.signature_hex);
    let err = corrupted.verify(&proof, &policy).unwrap_err();
    assert!(
        matches!(&err, PolicyError::BadSignature),
        "a tampered signature does not verify: {err}"
    );

    // Case 3: a real attestation, over a proof that has been altered since. The
    // integrity check runs first, so the tampering is caught before the
    // signature is even consulted.
    let mut tampered = proof.clone();
    tampered.result_digest = format!("0x{}", "7a".repeat(32));
    let err = real.verify(&tampered, &policy).unwrap_err();
    assert!(
        matches!(
            &err,
            PolicyError::InvalidField { field, .. } if *field == "proof_digest"
        ),
        "the signed statement no longer describes the proof: {err}"
    );
}

/// A cryptographically perfect signature is not an authorised one.
#[test]
fn an_attestation_signed_by_the_wrong_verifier_is_refused() {
    let authority = CqrAuthority::new();
    let policy = authority.policy();

    let (spec, state) = sample_oscillator_job();
    let result = run_sample_cqr(&spec, state);
    let proof = sample_proof("proof-wrong-verifier", &result);

    // A freshly generated key the policy does not delegate to. It signs
    // successfully — this is a real signature — and must still be refused.
    let impostor = VerifierRuntimeKey::generate();
    assert_ne!(
        impostor.key_id().to_string(),
        authority.auth.verifier.key_id().to_string()
    );
    let forged = CqrResultAttestation::attest(&proof, &policy, &impostor)
        .expect("an untrusted key can still produce bytes");

    let err = forged.verify(&proof, &policy).unwrap_err();
    assert!(
        matches!(
            &err,
            PolicyError::InvalidField { field, .. } if *field == "verifier_key_id"
        ),
        "the policy names one delegated key and this is not it: {err}"
    );
    assert!(err.to_string().contains("attestation key"), "{err}");

    // And through the evidence gate, where the refusal is named as an
    // attestation verification failure.
    let adapter = ComputeRewardAdapter::new_experimental("cqr-wrong-verifier-adapter");
    let unverified =
        adapter.package_evidence(proof, matching_reward(&result), forged);
    let refusal = unverified.verify(&policy).unwrap_err();
    assert!(
        refusal
            .to_string()
            .contains("CQR attestation cryptographic verification failed"),
        "{refusal}"
    );
}

/// Rotation is visible, not silent: the same key, a different policy version,
/// and an attestation that no longer verifies.
#[test]
fn an_attestation_under_a_different_policy_is_refused() {
    let authority = CqrAuthority::new();
    let policy_in_force = authority.policy();
    let rotated = authority.auth.rotated(99);
    let other_policy = rotated
        .validate()
        .expect("a rotated policy over the same anchor validates");

    let (spec, state) = sample_oscillator_job();
    let result = run_sample_cqr(&spec, state);
    let proof = sample_proof("proof-other-policy", &result);

    assert_ne!(
        policy_in_force.policy_hash().unwrap(),
        other_policy.policy_hash().unwrap(),
        "two policy versions over one anchor are two policies"
    );

    // The attestation is genuine, under the policy that was in force.
    let old = CqrResultAttestation::attest(&proof, &policy_in_force, &authority.auth.verifier)
        .unwrap();
    assert!(old.verify(&proof, &policy_in_force).is_ok());

    // Read back under the rotated policy it was never issued under.
    let err = old.verify(&proof, &other_policy).unwrap_err();
    assert!(
        matches!(
            &err,
            PolicyError::InvalidField { field, .. } if *field == "policy_hash"
        ),
        "an attestation names the policy it was issued under: {err}"
    );

    // And the converse, so the test is not just "everything is refused": the
    // same delegated key over the same proof under the rotated policy verifies
    // there and only there.
    let new = CqrResultAttestation::attest(&proof, &other_policy, &rotated.verifier).unwrap();
    assert!(new.verify(&proof, &other_policy).is_ok());
    assert!(new.verify(&proof, &policy_in_force).is_err());
}

/// The maximum the CQR branch can reach: a real attestation plus a reward whose
/// bound fields match, and still no NEV.
#[test]
fn valid_cqr_attestation_plus_fabricated_reward_produces_no_nev() {
    let authority = CqrAuthority::new();
    let policy = authority.policy();

    let (spec, state) = sample_oscillator_job();
    let result = run_sample_cqr(&spec, state);
    let proof = sample_proof("proof-valid-attestation-fabricated-reward", &result);

    let attestation = CqrResultAttestation::attest(&proof, &policy, &authority.auth.verifier)
        .expect("the delegated verifier signs a real proof");
    assert!(
        attestation.verify(&proof, &policy).is_ok(),
        "the computation is authenticated; that part is real"
    );

    let fabricated = matching_reward(&result);
    let adapter = ComputeRewardAdapter::new_experimental("cqr-fabricated-reward-adapter");
    let unverified = adapter.package_evidence(proof, fabricated, attestation);
    let refusal = unverified.verify(&policy).unwrap_err();

    assert!(
        matches!(&refusal, EconomyError::RewardBindingIncomplete(_)),
        "{refusal}"
    );
    assert!(
        refusal.to_string().contains("RewardBindingIncomplete"),
        "{refusal}"
    );

    // No `AuthenticatedComputeEvidence` was produced, so nothing was recorded.
    let mut evaluator = NevTierEvaluator::new(MONTHLY_OPERATING_COST_MICROS);
    let status = evaluator.evaluate(EVAL_NOW_UNIX);
    assert_eq!(status.current_verified_tier, NevTier::PreNev0);
    assert_eq!(status.cumulative_verified_nev_micros, 0);
    assert_eq!(status.cumulative_event_count, 0);
}

/// The ledger says a payment happened; the chain does not show one. The node's
/// own record is a claim, and a claim cannot become a crossing.
#[test]
fn a_valid_payment_signature_without_the_chain_payment_yields_no_nev() {
    let tx = payment_tx();
    // The receipt carries a Transfer that LOOKS like the claimed payment — same
    // payer, same recipient, same amount — but of a token this build cannot
    // identify, so the chain read cannot classify it.
    let chain = SettlementChain::serving(receipt_for(
        &tx,
        vec![transfer_log(
            "0x1",
            UNIDENTIFIED_TOKEN,
            COUNTERPARTY,
            CONTROLLED,
            50_000,
        )],
        "0x0",
        "0x0",
    ));

    let scan = chain.scan(&tx);
    assert!(
        !scan.exhaustive(),
        "a Transfer of an unidentified token cannot be classified"
    );
    assert!(
        scan.transfers().is_empty(),
        "so the chain shows no identified Base USDC transfer for the claimed payment"
    );

    // The node holds a stored row for that transaction all the same.
    let evidence = vec![inflow_evidence(&tx, 50_000)];
    assert!(
        chain.verifier.verify_transfer(&tx, CONTROLLED, 50_000).is_err(),
        "and the chain will not confirm a Base USDC payment that is not there"
    );

    let inputs =
        SettlementInputs::new(vec![&scan], &chain.registry, &evidence, Some(&chain.policy));
    let outcome = VerifiedSettlement::assemble(&inputs).unwrap();

    // No arm of the outcome yields a `ComparableVerifiedSettlement` here: the
    // `Complete` arm is not taken, and the `Incomplete` arm has no `compare`.
    let comparable = match &outcome {
        SettlementOutcome::Complete(settlement) => settlement
            .compare(&chain.price_source(), &[])
            .as_comparable()
            .cloned(),
        SettlementOutcome::Incomplete(incomplete) => {
            let states = incomplete.missing_states();
            assert!(
                states.contains(&"scan_not_exhaustive"),
                "{states:?}"
            );
            None
        }
    };
    assert!(
        comparable.is_none(),
        "no ComparableVerifiedSettlement exists for a transaction whose chain read \
         could not classify every log"
    );

    let mut evaluator = NevTierEvaluator::new(MONTHLY_OPERATING_COST_MICROS);
    let status = evaluator.evaluate(EVAL_NOW_UNIX);
    assert_eq!(status.current_verified_tier, NevTier::PreNev0);
    assert_eq!(status.cumulative_verified_nev_micros, 0);
    assert_eq!(status.cumulative_event_count, 0);
}

/// Only the outward leg. A payment was made; nothing came back for it; and the
/// leg set cannot be shown complete.
#[test]
fn a_chain_payment_with_an_incomplete_settlement_yields_no_nev() {
    let tx = payment_tx();
    // One transfer, controlled -> external: money leaving, no return leg.
    let chain = SettlementChain::serving(receipt_for(
        &tx,
        vec![transfer_log(
            "0x1",
            BASE_USDC,
            CONTROLLED,
            COUNTERPARTY,
            100_000,
        )],
        "0x0",
        "0x0",
    ));

    let scan = chain.scan(&tx);
    assert_eq!(scan.transfers().len(), 1);
    assert!(scan.exhaustive(), "the read classified every log; there is simply one leg");

    // The direction really is outward: derived through the registry, not asserted.
    let outward = BoundaryCrossing::derive(&outflow_evidence(&tx, 100_000), &chain.registry)
        .expect("the stored row derives against the controlled registry");
    assert_eq!(
        outward.boundary_direction(),
        Some(BoundaryDirection::ControlledToExternal)
    );

    // This node holds no stored evidence for that leg, so it cannot be
    // established, and an unestablished leg is a reason rather than a zero.
    let evidence: Vec<BoundaryEvidence> = Vec::new();
    let inputs =
        SettlementInputs::new(vec![&scan], &chain.registry, &evidence, Some(&chain.policy));
    let outcome = VerifiedSettlement::assemble(&inputs).unwrap();

    let incomplete = match outcome {
        SettlementOutcome::Incomplete(i) => i,
        SettlementOutcome::Complete(s) => {
            panic!("a leg with no stored evidence cannot be complete: {s:?}")
        }
    };
    let states = incomplete.missing_states();
    assert!(states.contains(&"absent"), "{states:?}");
    assert!(
        !incomplete.reasons().is_empty(),
        "an incomplete settlement always names at least one reason"
    );
    assert_eq!(
        incomplete.confirmed_inflow_micros(),
        0,
        "nothing came in, and an unestablished leg contributes nothing rather than zero"
    );

    // `IncompleteSettlement` has no `compare`, so no `ComparableVerifiedSettlement`
    // and therefore no `VerifiedNevEvent` can be built from this transaction.
    let mut evaluator = NevTierEvaluator::new(MONTHLY_OPERATING_COST_MICROS);
    let status = evaluator.evaluate(EVAL_NOW_UNIX);
    assert_eq!(status.current_verified_tier, NevTier::PreNev0);
    assert_eq!(status.cumulative_verified_nev_micros, 0);
    assert_eq!(status.cumulative_event_count, 0);
}

/// A complete settlement that burned native value has a cost in wei, and a
/// figure in wei is not a figure in micro-USD.
#[test]
fn a_complete_settlement_without_a_price_is_not_comparable() {
    let tx = payment_tx();
    // 21000 gas at 1 wei. The settlement IS complete — one established inflow
    // leg, exhaustive read — but it burned native value, so the token net is not
    // the whole answer.
    let chain = SettlementChain::serving(receipt_for(
        &tx,
        vec![transfer_log("0x1", BASE_USDC, COUNTERPARTY, CONTROLLED, 50_000)],
        "0x5208",
        "0x1",
    ));

    let scan = chain.scan(&tx);
    let evidence = vec![inflow_evidence(&tx, 50_000)];
    let inputs =
        SettlementInputs::new(vec![&scan], &chain.registry, &evidence, Some(&chain.policy));
    let settlement = match VerifiedSettlement::assemble(&inputs).unwrap() {
        SettlementOutcome::Complete(s) => s,
        SettlementOutcome::Incomplete(i) => {
            panic!("settlement must be complete: {:?}", i.reasons())
        }
    };

    assert!(settlement.has_native_cost());
    assert_eq!(settlement.total_native_cost_wei(), 21_000);
    assert_eq!(
        settlement.comparable_net_value_micros(),
        None,
        "the unpriced route refuses to hand out a net for a gas-bearing operation"
    );

    // No validated price observation was supplied, and none could be: a
    // `ValidatedPriceObservation` can only exist if the delegated verifier
    // signed those exact bytes under this policy.
    let source = chain.price_source();
    let result = settlement.compare(&source, &[]);
    assert!(result.as_comparable().is_none());
    assert_eq!(
        result.refusal_states(),
        vec!["no_price"],
        "the refusal names the missing price and nothing else"
    );

    // No comparable settlement, so no `VerifiedNevEvent`, so nothing recorded.
    let mut evaluator = NevTierEvaluator::new(MONTHLY_OPERATING_COST_MICROS);
    let status = evaluator.evaluate(EVAL_NOW_UNIX);
    assert_eq!(status.current_verified_tier, NevTier::PreNev0);
    assert_eq!(status.cumulative_verified_nev_micros, 0);
}

/// The positive control, written as a chain-shape proof rather than a second
/// copy of the arithmetic: at every step the AUTHORITY VARIANT of the next type
/// has to exist, and each of those types has no other constructor.
#[test]
fn a_fully_attested_chain_settlement_reaches_nev0() {
    let tx = payment_tx();
    let chain = SettlementChain::serving(receipt_for(
        &tx,
        vec![transfer_log("0x1", BASE_USDC, COUNTERPARTY, CONTROLLED, 50_000)],
        "0x0",
        "0x0",
    ));
    let source = chain.price_source();

    // -- Step 1: `BoundaryCrossing`. ---------------------------------------
    // No public fields and no `Deserialize`: the only way to hold one is
    // `derive` from stored evidence through the controlled registry, and the
    // only way to make it carry authority is a chain proof bound to it.
    let evidence = inflow_evidence(&tx, 50_000);
    let payment_proof = chain
        .verifier
        .verify_transfer(&tx, CONTROLLED, 50_000)
        .expect("the chain confirms a USDC transfer to the controlled address");
    assert!(payment_proof.verified);
    assert!(payment_proof.provider_identity_verified);

    let crossing = BoundaryCrossing::derive(&evidence, &chain.registry)
        .expect("the stored row derives against the controlled registry");
    let crossing = crossing
        .with_verified_proof(payment_proof)
        .expect("the proof describes this crossing");
    assert_eq!(
        crossing.boundary_direction(),
        Some(BoundaryDirection::ExternalToControlled),
        "money arrived from outside the controlled set"
    );
    assert!(
        crossing.proof().is_some(),
        "a crossing with no chain proof attached is a claim, not evidence"
    );

    // -- Step 2: `VerifiedSettlement`, through `SettlementOutcome::Complete`. -
    let scan = chain.scan(&tx);
    let stored = vec![evidence.clone()];
    let inputs =
        SettlementInputs::new(vec![&scan], &chain.registry, &stored, Some(&chain.policy));
    let outcome = VerifiedSettlement::assemble(&inputs).unwrap();
    let settlement: VerifiedSettlement = match outcome {
        SettlementOutcome::Complete(s) => s,
        SettlementOutcome::Incomplete(i) => {
            panic!("settlement must be complete: {:?}", i.reasons())
        }
    };
    assert_eq!(settlement.legs().len(), 1);
    assert!(settlement
        .legs()
        .iter()
        .all(|leg| leg.state() == LegState::Confirmed));
    assert_eq!(
        settlement.legs()[0].direction(),
        BoundaryDirection::ExternalToControlled
    );
    assert!(
        settlement.legs()[0].event_id().is_some(),
        "a confirmed leg is named on the chain"
    );
    assert_eq!(settlement.token_net_delta_micros(), 50_000);

    // -- Step 3: `ComparableVerifiedSettlement`, through `Comparable`. ------
    // This type has exactly one construction site, `VerifiedSettlement::compare`,
    // so holding one is the statement "a price was applied under this policy".
    let comparable = match settlement.compare(&source, &[]) {
        ComparableSettlementResult::Comparable(c) => c,
        ComparableSettlementResult::NoComparableNetValue(r) => {
            panic!("settlement must be comparable: {r:?}")
        }
    };
    assert_eq!(comparable.legs().len(), 1);
    assert_eq!(comparable.comparable_net_value_micros(), 50_000);
    assert!(
        comparable.price().is_none(),
        "nothing was burned, so no price was consulted and none is named"
    );

    // -- Step 4: `VerifiedNevEvent`. ----------------------------------------
    // Its only production constructor takes a `ComparableVerifiedSettlement`, so
    // this value cannot exist without step 3, and its identity is DERIVED inside
    // that constructor from the settlement's own authenticated facts — this
    // receipt's block anchor, its operation id and the canonical external event id
    // of its one established leg. No identity crosses this call.
    let fact = ExternalEventFact::from_parts(
        BASE_CHAIN_ID,
        &tx,
        1,
        &RealAsset::base_usdc(),
        COUNTERPARTY,
        CONTROLLED,
        50_000,
    )
    .unwrap();
    let event = VerifiedNevEvent::from_comparable_settlement(
        &comparable,
        OpportunityClass::Arbitrage,
    )
    .expect("a complete settlement derives an economic identity");

    // The assertion that stood here was
    //
    //     assert_eq!(event.event_id(), &event_id);
    //
    // and it is no longer valid, not because the property it checked was
    // unimportant but because its subject is gone. `from_comparable_settlement`
    // takes no `ExternalEventId`, so there is no `event_id` for the event to equal
    // and no local for the comparison to name. Read literally, that assertion would
    // now say the derivation reproduces a digest computed under a DIFFERENT domain
    // — `SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN` over the whole operation, against
    // `EVENT_ID_DOMAIN` over one log — which is false by construction; and read as
    // intended, it would assert the very thing this change removed, that a NEV
    // event's identity is whatever a caller computed. The property is restated
    // below as the three claims that actually replace it: a canonical digest
    // spelling, determinism per settlement, and an identity the caller does not
    // choose.
    let id_text = event.event_id().as_str();
    assert!(
        id_text.starts_with("0x")
            && id_text.trim_start_matches("0x").len() == 64
            && id_text
                .trim_start_matches("0x")
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "a derived economic identity is spelled as one canonical digest, never as a \
         label: {id_text}"
    );

    // Determinism: the SAME settlement, converted a second time through the same
    // production constructor and the same class, yields the SAME identity. Nothing
    // was cached and nothing was carried across — the equality is a property of the
    // derivation, and it is the property that makes a second NEV event for one
    // operation a replay rather than a new event.
    let reconverted =
        VerifiedNevEvent::from_comparable_settlement(&comparable, OpportunityClass::Arbitrage)
            .expect("a complete settlement derives an economic identity");
    assert_eq!(
        event.event_id(),
        reconverted.event_id(),
        "one settlement has exactly one economic identity however many times it is converted"
    );

    // And it is NOT the id this test used to hand the constructor. The two digests
    // are domain-separated, so no caller-computed id can coincide with a derived
    // one: the identity is the settlement's, not the caller's.
    assert_ne!(
        event.event_id(),
        &ExternalEventId::logged(&fact).unwrap(),
        "the event's identity is derived from the settlement, not supplied by the caller"
    );

    assert_eq!(event.timestamp_unix(), SETTLE_TIMESTAMP_UNIX);
    assert_eq!(event.net_nev_musd_micros(), 50_000);
    assert!(
        event.real_capability().is_some(),
        "an arbitrage settlement carries the arbitrage capability"
    );

    // -- Step 5: `NevTier::Nev0`. -------------------------------------------
    let mut evaluator = NevTierEvaluator::new(MONTHLY_OPERATING_COST_MICROS);
    evaluator
        .record_event(event)
        .expect("an event built from a comparable settlement is recordable");
    let status = evaluator.evaluate(EVAL_NOW_UNIX);

    assert_eq!(status.current_verified_tier, NevTier::Nev0);
    assert!(
        status.cumulative_verified_nev_micros > 0,
        "the whole chain produced strictly positive verified NEV"
    );
}
