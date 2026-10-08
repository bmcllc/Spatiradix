//! End-to-end checks on the P3 read-side authority.
//!
//! The regression these guard is the audit's headline finding: a process that
//! can append to `~/.mycelium/economy/*.jsonl` could fabricate an
//! `Agent + Opportunity + ExternalValue` set with a valid hash chain, and the
//! economic commands would believe it — reaching `ARV4` and 100 mUSD/day of real
//! reinvestment authority without a single byte existing on Base.
//!
//! Everything here drives the real binary. The ledger is written by hand, with
//! correct sequence/prev_hash/record_hash and `proof_verified: true`, which is
//! exactly what a forger can do: the genesis hash is a public constant and
//! nothing in the file is signed. The records are built from the crate's own
//! types so the bytes are exactly the ones the real writer would emit — a forgery
//! that failed to parse would test nothing.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use mycelium_economy::{
    autonomy::{
        AgentClass, AutonomyPayload, AutonomyRecord, EconomicAgentManifest,
        ExternalValueClass, ExternalValueReceipt, JobIntent,
        OpportunityCandidate, RiskProfile, VerificationMode,
        AUTONOMY_GENESIS_HASH,
    },
    boundary::{BoundaryEvidence, RealAsset},
    JobType, SCHEMA_VERSION,
};
use tempfile::tempdir;

const BIN: &str = env!("CARGO_BIN_EXE_mycelium-economy");
const DEV_PROVIDER_ENV: &str = "MYCELIUM_DEV_BASE_PROVIDER";
const PAYOUT: &str = "0xe83331104f5f3c41e49abc46c810f9d71133e48c";
const COUNTERPARTY: &str = "0x1234567890abcdef1234567890abcdef12345678";

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(BIN)
        .arg("--home")
        .arg(home)
        .args(args)
        // The dev override can drive a verifier but can never attest, so it is
        // removed here and set on purpose in the test that checks that.
        .env_remove(DEV_PROVIDER_ENV)
        .output()
        .expect("run mycelium-economy")
}

fn json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("valid json")
}

fn manifest() -> EconomicAgentManifest {
    EconomicAgentManifest {
        schema_version: SCHEMA_VERSION,
        agent_id: "s1-arb-01".into(),
        public_key: "ed25519:forged".into(),
        agent_class: AgentClass::Finance,
        allowed_job_types: vec![JobType::Simulation],
        daily_budget_musd_micros: 100_000_000,
        max_job_cost_musd_micros: 2_000_000,
        risk_profile: RiskProfile::Conservative,
        enabled: true,
        created_at_unix: 1_700_000_000,
    }
}

fn opportunity() -> OpportunityCandidate {
    OpportunityCandidate {
        schema_version: SCHEMA_VERSION,
        opportunity_id: "opp-1".into(),
        agent_id: "s1-arb-01".into(),
        observed_at_unix: 1_700_000_100,
        expires_at_unix: 1_700_002_000,
        job_type: JobType::Simulation,
        input_hash: "blake3:input".into(),
        evidence_hash: "blake3:evidence".into(),
        expected_gross_musd_micros: 100_000_000,
        expected_external_cost_musd_micros: 0,
        estimated_job_cost_musd_micros: 500_000,
        risk_buffer_musd_micros: 0,
        metadata: BTreeMap::new(),
    }
}

fn job_intent() -> JobIntent {
    JobIntent {
        schema_version: SCHEMA_VERSION,
        job_intent_id: "job-forged".into(),
        opportunity_id: "opp-1".into(),
        agent_id: "s1-arb-01".into(),
        job_type: JobType::Simulation,
        input_hash: "blake3:input".into(),
        max_cost_musd_micros: 500_000,
        deadline_unix: 1_700_010_000,
        verification: VerificationMode::ExternalProof,
        created_at_unix: 1_700_000_200,
    }
}

fn signals() -> String {
    serde_json::json!({
        "worker_risk": 0.0,
        "liquidity_risk": 0.0,
        "fraud_risk": 0.0,
        "partition_risk": 0.0,
        "demand_risk": 0.0,
        "thermal_headroom": 0.5,
    })
    .to_string()
}

fn policy() -> String {
    serde_json::json!({
        "base_rate_bps": 2000u64,
        "reserve_floor_musd_micros": 10_000_000u64,
        "max_daily_commitment_musd_micros": 100_000_000u64,
        "min_thermal_headroom": 0.05,
    })
    .to_string()
}

/// Writes a ledger the real reader accepts: correct sequence, prev_hash and
/// record_hash on every line, `proof_verified: true` on the value receipt, and
/// boundary evidence naming a transfer that never happened.
fn forge(ledger: &PathBuf) {
    let tx = format!("0x{}", "99".repeat(32));
    let payloads = vec![
        AutonomyPayload::Agent { manifest: manifest() },
        AutonomyPayload::Opportunity { opportunity: opportunity() },
        AutonomyPayload::JobIntent { intent: job_intent() },
        AutonomyPayload::BoundaryCrossing {
            evidence: BoundaryEvidence {
                chain_id: mycelium_economy::base_usdc::BASE_CHAIN_ID,
                asset: RealAsset::base_usdc(),
                from_address: COUNTERPARTY.into(),
                to_address: PAYOUT.into(),
                amount_raw: 100_000_000,
                tx_hash: tx.clone(),
                block_hash: format!("0x{}", "22".repeat(32)),
            },
        },
        AutonomyPayload::ExternalValue {
            receipt: ExternalValueReceipt {
                schema_version: SCHEMA_VERSION,
                source_id: "forged-1".into(),
                agent_id: "s1-arb-01".into(),
                opportunity_id: "opp-1".into(),
                value_class: ExternalValueClass::ExternalTradingPnl,
                network: "base".into(),
                asset: "USDC".into(),
                gross_inflow_musd_micros: 100_000_000,
                external_cost_musd_micros: 0,
                net_external_value_musd_micros: 100_000_000,
                proof_hash: tx,
                proof_verified: true,
                realized_at_unix: 1_700_000_400,
                verifier_id: "base-reconcile".into(),
            },
        },
    ];

    let mut prev = AUTONOMY_GENESIS_HASH.to_string();
    let mut lines: Vec<String> = Vec::new();
    for (i, payload) in payloads.into_iter().enumerate() {
        let mut record = AutonomyRecord {
            sequence: i as u64 + 1,
            recorded_at_unix: 1_700_000_900,
            prev_hash: prev.clone(),
            record_hash: String::new(),
            payload,
        };
        // The same rule the crate's own writer uses: hash the record with an
        // empty hash field, then store it.
        record.record_hash =
            blake3::hash(&serde_json::to_vec(&record).unwrap())
                .to_hex()
                .to_string();
        prev = record.record_hash.clone();
        lines.push(serde_json::to_string(&record).unwrap());
    }
    fs::create_dir_all(ledger.parent().unwrap()).unwrap();
    fs::write(ledger, format!("{}\n", lines.join("\n"))).unwrap();
}

/// A forged ledger in a directory that also has the payment policy a running
/// node would have. Without a policy the controlled set is empty, every crossing
/// re-derives as an irrelevant external-to-external hop, and the forgery is
/// rejected one step earlier — true, and tested in
/// `a_forged_ledger_without_a_controlled_set_is_refused_one_step_earlier`.
fn forged_economy() -> (tempfile::TempDir, PathBuf) {
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    forge(&econ.join("autonomous-ledger.jsonl"));
    let policy = run(&econ, &["payment-policy-init", PAYOUT, "2"]);
    assert!(policy.status.success(), "{policy:?}");
    (home, econ)
}

#[test]
fn a_forged_ledger_does_not_promote_through_the_cli() {
    let (_home, econ) = forged_economy();

    let arv = json(&run(&econ, &["arv-status"]));
    assert_eq!(arv["trust_mode"], "unverified");
    assert_eq!(arv["level"], "PRE-ARV0");
    assert_eq!(arv["arv0_pass"], false);
    assert_eq!(arv["verified_external_events"], 0);
    assert_eq!(arv["net_external_value_musd_total"], 0.0);
    // The claim is reported rather than swallowed.
    assert_eq!(arv["unattested_external_events"], 1);
    assert_eq!(arv["unattested_net_external_value_musd"], 100.0);
    let note = arv["attestation_note"].as_str().unwrap();
    assert!(note.contains("TrustMode=unverified"), "{note}");
    assert!(note.contains("no pinned provider"), "{note}");

    // The authority identity is in the output, so an operator can tell which
    // derivation produced the number they are reading.
    let dashboard = json(&run(&econ, &["economy-dashboard"]));
    assert_eq!(dashboard["trust"]["trust_mode"], "unverified");
    assert_eq!(dashboard["autonomous_economy"]["arv"]["level"], "PRE-ARV0");
    assert_eq!(
        dashboard["invariants"]["stored_proof_verified_is_authority"],
        false
    );
    assert_eq!(
        dashboard["trust"]["authority_identity"],
        "VerifiedNev = VerifyChain(DeriveBoundary(VerifyReceiptSig(VerifyPolicy(Evidence))))"
    );
    // P4b: the signed-attestation gate is reported next to the identity, and on
    // this directory it is not in force — there is no policy file and no trust
    // anchor, so nothing on this ledger could be attested even if the provider
    // were pinned.
    assert_eq!(dashboard["trust"]["outcome_policy"]["validated"], false);
    assert!(dashboard["trust"]["outcome_policy"]["note"]
        .as_str()
        .unwrap()
        .contains("no signed outcome policy"));

    // The summary separates what is verified from what is claimed.
    let summary = json(&run(&econ, &["autonomy-status"]));
    assert_eq!(summary["verified_external_value_receipts"], 0);
    assert_eq!(summary["net_external_value_musd"], 0.0);
    assert_eq!(summary["unattested_external_value_receipts"], 1);
    assert_eq!(summary["unattested_net_external_value_musd"], 100.0);
}

#[test]
fn a_forged_ledger_cannot_fund_a_commitment_through_the_cli() {
    let (home, econ) = forged_economy();

    let signals_path = home.path().join("signals.json");
    fs::write(&signals_path, signals()).unwrap();
    let policy_path = home.path().join("policy.json");
    fs::write(&policy_path, policy()).unwrap();
    let s = signals_path.display().to_string();
    let p = policy_path.display().to_string();

    let decision = json(&run(&econ, &["reinvestment-decision", &s, &p]));
    assert_eq!(decision["trust_mode"], "unverified");
    assert_eq!(decision["verified_nev_musd_micros"], 0);
    assert_eq!(decision["available_new_commitment_musd_micros"], 0);
    assert_eq!(decision["target_cumulative_reinvestment_musd_micros"], 0);
    // The claim the ledger makes is visible, and cannot be mistaken for a budget.
    assert_eq!(decision["unattested_nev_musd_micros"], 100_000_000i64);
    assert!(decision["reason"]
        .as_str()
        .unwrap()
        .contains("TrustMode=unverified"));

    // The spending gate refuses, and says why in terms an operator can act on.
    let commit = run(
        &econ,
        &["reinvestment-commit", "job-forged", "s1-arb-01", &s, &p],
    );
    assert!(!commit.status.success());
    let err = String::from_utf8_lossy(&commit.stderr);
    assert!(err.contains("no budget to spend"), "{err}");
    assert!(err.contains("TrustMode=unverified"), "{err}");
}

#[test]
fn the_dev_loopback_override_still_cannot_attest() {
    // A dev override drives the verifier, so a chain read is attempted, but it
    // authenticates nothing: the commands must stay in the offline mode.
    let (_home, econ) = forged_economy();
    let output = Command::new(BIN)
        .arg("--home")
        .arg(&econ)
        .arg("arv-status")
        .env(DEV_PROVIDER_ENV, "http://127.0.0.1:1")
        .output()
        .expect("run mycelium-economy");
    let arv = json(&output);
    assert_eq!(arv["trust_mode"], "unverified");
    assert_eq!(arv["level"], "PRE-ARV0");
    assert_eq!(arv["verified_external_events"], 0);
}

#[test]
fn the_rv_side_reports_its_trust_mode_too() {
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    fs::create_dir_all(&econ).unwrap();
    // An empty economy: nothing is paid, and the report says which derivation
    // produced the zero rather than leaving it ambiguous.
    let rv = json(&run(&econ, &["rv-status"]));
    assert_eq!(rv["trust_mode"], "unverified");
    assert_eq!(rv["level"], "PRE-RV0");
    assert_eq!(rv["external_paid_jobs"], 0);
    assert_eq!(rv["unattested_external_paid_jobs"], 0);
    assert!(rv["attestation_note"]
        .as_str()
        .unwrap()
        .contains("TrustMode=unverified"));

    let revenue = json(&run(&econ, &["revenue"]));
    assert_eq!(revenue["trust_mode"], "unverified");
    assert_eq!(revenue["external_paid_jobs"], 0);
    assert_eq!(revenue["paid_demand_musd_micros"], 0);
}

#[test]
fn the_audit_command_keeps_reading_the_stored_claim() {
    // Diagnostics still see what the writer claimed, because diagnosing an old
    // ledger needs it. It is reported, and explicitly labelled as not authority.
    let (_home, econ) = forged_economy();
    let audit = json(&run(&econ, &["autonomy-audit"]));
    assert_eq!(audit["valid"], true);
    assert_eq!(audit["records"], 5);
    assert_eq!(audit["stored_proof_verified_claims"], 1);
    assert!(audit["note"]
        .as_str()
        .unwrap()
        .contains("not an authority input"));
}

#[test]
fn the_cli_reports_the_signed_attestation_gate_and_it_is_not_in_force() {
    // P4b. The read side needs a validated outcome policy before it can attest
    // anything, and the CLI reports that requirement rather than hiding it.
    let home = tempdir().unwrap();

    // Nothing installed: no policy document, no trust anchor, no provider.
    let out = json(&run(home.path(), &["outcome-policy-show"]));
    assert_eq!(
        out["validated"],
        serde_json::json!(false),
        "no policy, nothing attested: {out}"
    );
    assert!(
        out["path"]
            .as_str()
            .unwrap()
            .ends_with("outcome-policy.json"),
        "{out}"
    );
    assert!(
        out["note"]
            .as_str()
            .unwrap()
            .contains("no signed outcome policy"),
        "{out}"
    );
    assert_eq!(out["policy_hash"], serde_json::json!(null));

    // A policy document that does not validate is reported as such, not ignored:
    // an authority the process did not verify is not an authority.
    //
    // P4.6: the payload now carries `price_source_hash`, so this hand-written
    // document has to carry it too — otherwise it would stop *parsing* and the
    // test would no longer exercise what it was written for (a well-formed
    // document that fails validation). The schema version stays 1 on purpose:
    // with the field present the document parses, and the refusal it reaches is
    // `UnsupportedSchema`, which is the honest first gate of a signed
    // preimage. `signing_cli.rs::a_signed_policy_on_a_mismatched_chain_is_refused`
    // covers a fully schema-2 document that fails on its chain.
    let price_source_hash = format!("0x{}", "44".repeat(32));
    fs::write(
        home.path().join("outcome-policy.json"),
        serde_json::to_vec(&serde_json::json!({
            "payload": {
                "schema_version": 1,
                "policy_version": 1,
                "chain_id": 8453,
                "executor": "0x1111111111111111111111111111111111111111",
                "min_confirmations": 12,
                "controlled_registry_hash": format!("0x{}", "00".repeat(32)),
                "provider_identity_hash": format!("0x{}", "00".repeat(32)),
                "price_source_hash": price_source_hash,
                "verifier_key_id": format!("verifier-runtime:0x{}", "11".repeat(32)),
                "verifier_public_key": format!("0x{}", "22".repeat(32)),
                "created_at_unix": 1_700_000_000,
            },
            "authority_key_id": format!("policy-authority:0x{}", "33".repeat(32)),
            "signature": "ab".repeat(64),
        }))
        .unwrap(),
    )
    .unwrap();
    let out = json(&run(home.path(), &["outcome-policy-show"]));
    assert_eq!(out["validated"], serde_json::json!(false), "{out}");
    // The pin is checked before the policy is even parsed for meaning: without
    // a trust anchor there is nothing to validate against, so that is the first
    // refusal and it names the path it wanted.
    let note = out["note"].as_str().unwrap();
    assert!(
        note.contains("no usable policy authority pin")
            || note.contains("did not validate"),
        "the reason must be an anchor or validation refusal, got: {note}"
    );
    if note.contains("no usable policy authority pin") {
        assert!(
            note.contains("/etc/mycelium/trust/policy-authority.pub"),
            "and it must name the path an operator has to create: {note}"
        );
    }

    // And with a policy-shaped file present but no provider pinned, the trust
    // mode is still unverified, so no economic command reports a number derived
    // from a chain read.
    let out = json(&run(home.path(), &["economy-dashboard"]));
    assert_eq!(out["trust"]["trust_mode"], serde_json::json!("unverified"));
    assert_eq!(
        out["trust"]["outcome_policy"]["validated"],
        serde_json::json!(false)
    );
    assert_eq!(
        out["trust"]["authority_identity"],
        serde_json::json!(
            "VerifiedNev = VerifyChain(DeriveBoundary(VerifyReceiptSig(VerifyPolicy(Evidence))))"
        )
    );
    assert_eq!(
        out["autonomous_economy"]["arv"]["trust_mode"],
        serde_json::json!("unverified")
    );
    assert_eq!(
        out["autonomous_economy"]["arv"]["level"],
        serde_json::json!("PRE-ARV0")
    );
    assert_eq!(
        out["autonomous_economy"]["arv"]["verified_external_events"],
        serde_json::json!(0)
    );
    assert_eq!(
        out["invariants"]["stored_proof_verified_is_authority"],
        serde_json::json!(false),
        "the telemetry flag is still named as non-authoritative, next to the \
         new signature gate"
    );
}

#[test]
fn a_forged_ledger_without_a_controlled_set_is_refused_one_step_earlier() {
    // No payment policy means no controlled addresses. The crossing still
    // re-derives, but as an external-to-external hop worth nothing, and the
    // note says which of the two reasons applied.
    let home = tempdir().unwrap();
    let econ = home.path().join("econ");
    forge(&econ.join("autonomous-ledger.jsonl"));
    let arv = json(&run(&econ, &["arv-status"]));
    assert_eq!(arv["level"], "PRE-ARV0");
    assert_eq!(arv["verified_external_events"], 0);
    assert_eq!(arv["unattested_external_events"], 0);
    let note = arv["attestation_note"].as_str().unwrap();
    assert!(note.contains("not money arriving from outside"), "{note}");
}
