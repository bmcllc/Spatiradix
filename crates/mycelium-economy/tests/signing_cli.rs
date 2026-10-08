//! End-to-end checks on the CLI **signing** path — the one P4a/P4b/P4c left
//! unreachable.
//!
//! The regression these guard is exactly what it says: `settle-base-usdc` and
//! `external-value-candidate-json` both record ledger entries that no command
//! could ever sign, because the delegated verifier's private key had no
//! operational source. A settlement therefore stayed in the
//! `UnsignedSettlement` gap forever, and the paid-demand figure an operator
//! read was always the "unattested" one.
//!
//! Everything here drives the real binary and provisions a real trust root, so
//! the whole chain is exercised: an authority key installed as the pinned
//! anchor, a verifier key installed beside it, a policy signed by the authority
//! and validated by the CLI against the pin, and a signature the read side then
//! re-verifies. Nothing is stubbed except the chain itself.
//!
//! The policy is signed here in the test because the authority's private half
//! is not in the repository and is not in the binary. That is deliberate: it
//! means the CLI genuinely cannot manufacture its own policy, and a test that
//! could do so would be testing a weaker system than the one that ships.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt as _, PermissionsExt},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use mycelium_economy::{
    autonomy::{
        AgentClass, AutonomyPayload, AutonomyRecord, EconomicAgentManifest,
        ExternalValueClass, ExternalValueReceipt, OpportunityCandidate,
        RiskProfile, AUTONOMY_GENESIS_HASH,
    },
    base_usdc::BASE_CHAIN_ID,
    boundary::{BoundaryEvidence, ControlledAddressRegistry, RealAsset},
    chain_provider::PinnedChainProvider,
    policy_auth::{
        controlled_registry_hash, Address, OutcomePolicyPayload,
        PolicyAuthorityKey, ProviderIdentityConstraints, PinnedTrustStore,
        OUTCOME_POLICY_FILE, OUTCOME_POLICY_SCHEMA_VERSION,
    },
    verifier_key_store::{
        install_verifier_runtime_key, TrustRoot, VerifierKeyStoreConfig,
        TRUST_ROOT_ENV,
    },
    trusted_valuation::{PriceSourceId, PriceSourcePolicy},
    LocalEconomy, JobType, SCHEMA_VERSION,
};
use tempfile::tempdir;

const BIN: &str = env!("CARGO_BIN_EXE_mycelium-economy");
const DEV_PROVIDER_ENV: &str = "MYCELIUM_DEV_BASE_PROVIDER";
const PAYOUT: &str = "0xe83331104f5f3c41e49abc46c810f9d71133e48c";
const COUNTERPARTY: &str = "0x1234567890abcdef1234567890abcdef12345678";
const EXECUTOR_HEX: &str = "0x1111111111111111111111111111111111111111";

/// Latest block reported by `eth_blockNumber`, and the increment applied per
/// call.
const FIRST_LATEST_BLOCK: u64 = 100;
const BLOCK_ADVANCE: u64 = 10;
/// The block the fake payment transaction sits in. Strictly after the anchor
/// taken at `FIRST_LATEST_BLOCK`, and old enough that
/// `latest - block + 1 >= min_confirmations`.
const PAYMENT_BLOCK: u64 = 105;
const AMOUNT_RAW: u64 = 5_000_000;
const TX_HASH: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

/// The external-value ledger's transaction: a *different* transfer, so the
/// receipt test exercises its own chain read rather than borrowing the
/// settlement's proof.
const RECEIPT_TX_HASH: &str =
    "0x2222222222222222222222222222222222222222222222222222222222222222";
const RECEIPT_AMOUNT_RAW: u64 = 100_000_000;
const RECEIPT_BLOCK: u64 = PAYMENT_BLOCK + 1;

fn block_hash(n: u64) -> String {
    format!("0x{n:064x}")
}

fn transfer_log(amount_raw: u64) -> serde_json::Value {
    serde_json::json!({
        "address": mycelium_economy::base_usdc::BASE_USDC,
        "topics": [
            mycelium_economy::base_usdc::ERC20_TRANSFER_TOPIC,
            format!("0x{:0>64}", COUNTERPARTY.trim_start_matches("0x")),
            format!("0x{:0>64}", PAYOUT.trim_start_matches("0x")),
        ],
        "data": format!("0x{amount_raw:064x}"),
        "logIndex": "0x3",
    })
}

// ---------------------------------------------------------------------------
// The fake verifier socket
// ---------------------------------------------------------------------------

/// A read-only JSON-RPC responder standing in for the dedicated verifier
/// service, with a *moving* head.
///
/// The moving head matters: `payment-instructions` anchors the payment intent at
/// the current head, and `settle-base-usdc` then requires the payment block to
/// be strictly after that anchor while still having enough confirmations. A
/// frozen head cannot satisfy both, and a socket that quietly answers with
/// whatever makes the test pass would be testing nothing.
///
/// The caller owns the temporary directory the socket lives in: the accept loop
/// blocks forever, so dropping the listener before the directory would hang.
struct SocketService {
    path: PathBuf,
}

impl SocketService {
    fn bind(dir: &Path) -> Self {
        let path = dir.join("verifier.sock");
        let listener = UnixListener::bind(&path).expect("bind service socket");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let head = Arc::new(AtomicU64::new(FIRST_LATEST_BLOCK));
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Ok(raw) = read_request(&mut stream) else { continue };
                let method = serde_json::from_str::<serde_json::Value>(
                    raw.split("\r\n\r\n").nth(1).unwrap_or("{}"),
                )
                .ok()
                .and_then(|v| {
                    v.get("method").and_then(|m| m.as_str()).map(String::from)
                })
                .unwrap_or_default();
                let result = match method.as_str() {
                    "eth_chainId" => serde_json::json!(format!("0x{BASE_CHAIN_ID:x}")),
                    "eth_blockNumber" => {
                        // Reports the current head, then advances: the
                        // payment intent is anchored at the first value the
                        // CLI sees, and every later read sees a later block.
                        let n = head.fetch_add(BLOCK_ADVANCE, Ordering::SeqCst);
                        serde_json::json!(format!("0x{n:x}"))
                    }
                    "eth_getBlockByNumber" => {
                        let n = block_of(&raw).unwrap_or(0);
                        serde_json::json!({
                            "hash": block_hash(n),
                            "timestamp": format!("0x{:x}", 1_700_000_000u64 + n),
                        })
                    }
                    // Answers per transaction, the way a real node does: one
                    // receipt per hash, describing that transfer and no other.
                    "eth_getTransactionReceipt" => {
                        match hash_of(&raw).as_deref() {
                            Some(RECEIPT_TX_HASH) => serde_json::json!({
                                "status": "0x1",
                                "blockNumber": format!("0x{RECEIPT_BLOCK:x}"),
                                "blockHash": block_hash(RECEIPT_BLOCK),
                                "transactionHash": RECEIPT_TX_HASH,
                                "logs": [transfer_log(RECEIPT_AMOUNT_RAW)],
                            }),
                            Some(TX_HASH) => serde_json::json!({
                                "status": "0x1",
                                "blockNumber": format!("0x{PAYMENT_BLOCK:x}"),
                                "blockHash": block_hash(PAYMENT_BLOCK),
                                "transactionHash": TX_HASH,
                                "logs": [transfer_log(AMOUNT_RAW)],
                            }),
                            _ => serde_json::Value::Null,
                        }
                    }
                    "eth_getCode" => serde_json::json!("0x6080604052"),
                    _ => serde_json::Value::Null,
                };
                let body =
                    serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result})
                        .to_string();
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            }
        });
        Self { path }
    }

    fn uri(&self) -> String {
        format!("unix://{}", self.path.display())
    }

    fn uid(&self) -> u32 {
        fs::metadata(&self.path).unwrap().uid()
    }
}

fn first_param(raw: &str) -> Option<String> {
    let body = serde_json::from_str::<serde_json::Value>(
        raw.split("\r\n\r\n").nth(1).unwrap_or("{}"),
    )
    .ok()?;
    body.get("params")?.get(0)?.as_str().map(String::from)
}

fn hash_of(raw: &str) -> Option<String> {
    first_param(raw).map(|h| h.to_ascii_lowercase())
}

fn block_of(raw: &str) -> Option<u64> {
    let body = serde_json::from_str::<serde_json::Value>(
        raw.split("\r\n\r\n").nth(1).unwrap_or("{}"),
    )
    .ok()?;
    let first = body.get("params")?.get(0)?.as_str()?;
    u64::from_str_radix(first.trim_start_matches("0x"), 16).ok()
}

fn read_request(stream: &mut std::os::unix::net::UnixStream) -> std::io::Result<String> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => return Err(e),
        };
        raw.extend_from_slice(&buf[..n]);
        if String::from_utf8_lossy(&raw).contains("\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&raw).to_string())
}

// ---------------------------------------------------------------------------
// The provisioned trust root
// ---------------------------------------------------------------------------

/// A trust root an operator provisioned: pinned authority public key plus the
/// delegated verifier's private key, both under one directory.
struct ProvisionedTrust {
    root: TrustRoot,
    authority: PolicyAuthorityKey,
    verifier: mycelium_economy::policy_auth::VerifierRuntimeKey,
    _dir: tempfile::TempDir,
}

impl ProvisionedTrust {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let uid = std::fs::metadata("/proc/self").unwrap().uid();
        let root = TrustRoot::at(dir.path(), uid);
        let authority = PolicyAuthorityKey::generate();
        PinnedTrustStore::install(&root.trust_store_config(), &authority).unwrap();
        // The delegated key, from the seed an operator would have stored.
        // Restored from a seed rather than handed to `install` as a key object:
        // the crate deliberately has no accessor for a key's secret bytes.
        let seed = [0x42u8; 32];
        let verifier =
            mycelium_economy::policy_auth::VerifierRuntimeKey::from_seed(seed);
        install_verifier_runtime_key(&root.key_store_config(), seed).unwrap();
        Self {
            root,
            authority,
            verifier,
            _dir: dir,
        }
    }
}

/// Writes an outcome policy the CLI can validate: signed by the pinned
/// authority and scoped to the *live* registry and provider this directory has.
fn write_validated_policy(
    home: &Path,
    trust: &ProvisionedTrust,
    provider_uri: &str,
    socket_uid: u32,
    min_confirmations: u64,
) {
    let econ = LocalEconomy::open(home).unwrap();
    let payment_policy = econ.payment_policy().unwrap();
    let registry = ControlledAddressRegistry::from_policy(&payment_policy).unwrap();
    let pin = PinnedChainProvider::parse(provider_uri, Some(socket_uid)).unwrap();
    let constraints = ProviderIdentityConstraints::from_pinned_provider(&pin);
    let payload = OutcomePolicyPayload {
        schema_version: OUTCOME_POLICY_SCHEMA_VERSION,
        policy_version: 1,
        chain_id: BASE_CHAIN_ID,
        executor: Address::parse(EXECUTOR_HEX).unwrap(),
        min_confirmations,
        controlled_registry_hash: controlled_registry_hash(&registry).unwrap(),
        provider_identity_hash: constraints.identity_hash(),
        // P4.6: a policy must authorise at least one price source, or
        // `validate_outcome_policy` refuses it at step 10. Built here from the
        // public API rather than from a test fixture, because this is the shape
        // an operator has.
        price_source_hash: PriceSourcePolicy::new(
            BASE_CHAIN_ID,
            [PriceSourceId::parse("base-rpc/eth-musd").unwrap()],
            300,
        )
        .unwrap()
        .binding_hash(),
        verifier_key_id: trust.verifier.key_id(),
        verifier_public_key: trust.verifier.public_key(),
        created_at_unix: 1_700_000_000,
    };
    let signed = trust.authority.sign(payload, &trust.verifier).unwrap();
    fs::write(
        home.join(OUTCOME_POLICY_FILE),
        serde_json::to_vec(&signed).unwrap(),
    )
    .unwrap();
}

/// Writes a policy that delegates to a *different* verifier key than the one
/// installed in the trust root.
fn write_policy_delegating_elsewhere(
    home: &Path,
    trust: &ProvisionedTrust,
    provider_uri: &str,
    socket_uid: u32,
    min_confirmations: u64,
) -> mycelium_economy::policy_auth::VerifierRuntimeKey {
    let econ = LocalEconomy::open(home).unwrap();
    let payment_policy = econ.payment_policy().unwrap();
    let registry = ControlledAddressRegistry::from_policy(&payment_policy).unwrap();
    let pin = PinnedChainProvider::parse(provider_uri, Some(socket_uid)).unwrap();
    let constraints = ProviderIdentityConstraints::from_pinned_provider(&pin);
    // A real key the authority really delegates to — the only difference from
    // the working policy is which key it names. So the refusal under test is
    // the delegation check, not a malformed document.
    let other =
        mycelium_economy::policy_auth::VerifierRuntimeKey::generate();
    let payload = OutcomePolicyPayload {
        schema_version: OUTCOME_POLICY_SCHEMA_VERSION,
        policy_version: 1,
        chain_id: BASE_CHAIN_ID,
        executor: Address::parse(EXECUTOR_HEX).unwrap(),
        min_confirmations,
        controlled_registry_hash: controlled_registry_hash(&registry).unwrap(),
        provider_identity_hash: constraints.identity_hash(),
        // P4.6: a policy must authorise at least one price source, or
        // `validate_outcome_policy` refuses it at step 10. Built here from the
        // public API rather than from a test fixture, because this is the shape
        // an operator has.
        price_source_hash: PriceSourcePolicy::new(
            BASE_CHAIN_ID,
            [PriceSourceId::parse("base-rpc/eth-musd").unwrap()],
            300,
        )
        .unwrap()
        .binding_hash(),
        verifier_key_id: other.key_id(),
        verifier_public_key: other.public_key(),
        created_at_unix: 1_700_000_000,
    };
    let signed = trust.authority.sign(payload, &other).unwrap();
    fs::write(
        home.join(OUTCOME_POLICY_FILE),
        serde_json::to_vec(&signed).unwrap(),
    )
    .unwrap();
    other
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

struct Env {
    home: PathBuf,
    trust_root: Option<PathBuf>,
}

impl Env {
    fn new(home: PathBuf) -> Self {
        Self {
            home,
            trust_root: None,
        }
    }

    /// Points the process at a provisioned trust root, which is the operator's
    /// explicit opt-in and the only thing that makes signing possible.
    fn with_trust_root(mut self, trust: &ProvisionedTrust) -> Self {
        self.trust_root = Some(trust.root.dir().to_path_buf());
        self
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(BIN);
        cmd.arg("--home").arg(&self.home).args(args).env_remove(DEV_PROVIDER_ENV);
        match &self.trust_root {
            Some(dir) => cmd.env(TRUST_ROOT_ENV, dir),
            None => cmd.env_remove(TRUST_ROOT_ENV),
        };
        cmd.output().expect("run mycelium-economy")
    }

    fn ok(&self, args: &[&str]) -> serde_json::Value {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "{args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("valid json")
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// A home with a payment policy, a pinned provider, a job, a verified work
/// receipt and a payment intent: everything `settle-base-usdc` needs, and
/// nothing signed.
struct ReadyToSettle {
    env: Env,
    service: SocketService,
    socket_dir: tempfile::TempDir,
    job_id: String,
}

fn ready_to_settle(trust: &ProvisionedTrust) -> ReadyToSettle {
    let socket_dir = tempdir().unwrap();
    let service = SocketService::bind(socket_dir.path());
    let home = tempdir().unwrap().keep();
    let env = Env::new(home.clone()).with_trust_root(trust);

    let init = env.ok(&[
        "payment-policy-init",
        PAYOUT,
        "2",
        &service.uri(),
    ]);
    assert_eq!(init["payout_address"], serde_json::json!(PAYOUT));
    env.ok(&[
        "payment-policy-pin-provider",
        &service.uri(),
        &service.uid().to_string(),
    ]);

    let created = env.ok(&[
        "job-create",
        "simulation",
        "requester-1",
        "blake3:input",
        "5",
        "false",
        "an opportunity",
    ]);
    let job_id = created["job_id"]
        .as_str()
        .expect("job id")
        .to_string();
    env.ok(&[
        "work-verify",
        &job_id,
        "worker-1",
        &format!("blake3:{}", "22".repeat(32)),
        "42",
        "verifier-node",
    ]);
    let intent = env.ok(&["payment-instructions", &job_id]);
    assert_eq!(intent["exact_amount_raw"], serde_json::json!(AMOUNT_RAW));

    write_validated_policy(&home, trust, &service.uri(), service.uid(), 2);

    // The pre-condition of every signing test: the policy is in force.
    let show = env.ok(&["outcome-policy-show"]);
    assert_eq!(show["validated"], serde_json::json!(true), "{show}");
    assert_eq!(
        show["verifier_key_id"],
        serde_json::json!(trust.verifier.key_id().to_string())
    );

    ReadyToSettle {
        env,
        service,
        socket_dir,
        job_id,
    }
}

fn settle_id(r: &ReadyToSettle) -> String {
    let out = r.env.ok(&["settle-base-usdc", &r.job_id, TX_HASH]);
    out["settlement"]["settlement_id"]
        .as_str()
        .expect("settlement id")
        .to_string()
}

// ---------------------------------------------------------------------------
// 1. The regression: settlement, end to end, reaching paid demand
// ---------------------------------------------------------------------------

#[test]
fn the_cli_can_attest_a_settlement_and_it_reaches_paid_demand() {
    let trust = ProvisionedTrust::new();
    let r = ready_to_settle(&trust);
    let settlement_id = settle_id(&r);

    // Before signing: re-derived and chain-confirmed, and worth nothing.
    let before = r.env.ok(&["rv-status"]);
    assert_eq!(before["trust_mode"], serde_json::json!("provider_pinned"), "{before}");
    assert_eq!(before["level"], serde_json::json!("PRE-RV0"), "{before}");
    assert_eq!(before["external_paid_jobs"], serde_json::json!(0), "{before}");
    assert_eq!(before["paid_demand_musd_total"], serde_json::json!(0.0), "{before}");
    // The note is the precise signal: how many of the re-derived settlements
    // carry a signature. (`unattested_external_paid_jobs` is a different
    // column — it counts every settlement that passes P3's re-derivation, so it
    // is 1 both before and after and says nothing about signatures.)
    assert!(
        before["attestation_note"]
            .as_str()
            .unwrap()
            .contains("0 of 1 paid settlements are attested"),
        "{before}"
    );

    // The signing command.
    let signed = r.env.ok(&["settlement-attest", &settlement_id]);
    assert_eq!(signed["settlement_id"], serde_json::json!(settlement_id));
    assert_eq!(
        signed["attestation"]["verifier_key_id"],
        serde_json::json!(trust.verifier.key_id().to_string()),
        "the signature must be the one the validated policy delegated to"
    );
    assert!(
        signed["attestation"]["attestation_hash"]
            .as_str()
            .unwrap()
            .starts_with("0x"),
        "{signed}"
    );

    // After signing: the same settlement now counts.
    let after = r.env.ok(&["rv-status"]);
    assert_eq!(after["trust_mode"], serde_json::json!("provider_pinned"), "{after}");
    assert_eq!(after["external_paid_jobs"], serde_json::json!(1), "{after}");
    assert_eq!(after["level"], serde_json::json!("RV0"), "{after}");
    assert_eq!(after["rv0_pass"], serde_json::json!(true), "{after}");
    assert_eq!(
        after["paid_demand_musd_total"],
        serde_json::json!(5.0),
        "{after}"
    );
    assert!(
        after["attestation_note"]
            .as_str()
            .unwrap()
            .contains("1 of 1 paid settlements are attested"),
        "{after}"
    );

    // And it is the attestation ledger, not the revenue ledger, that carries it.
    let path = signed["ledger"].as_str().unwrap().to_string();
    assert!(path.ends_with("settlement-attestations.jsonl"), "{path}");
    assert!(fs::metadata(&path).unwrap().len() > 0, "the ledger was not written");
    let _ = r.socket_dir.path();
}

// ---------------------------------------------------------------------------
// 2. The autonomy-side ledger
// ---------------------------------------------------------------------------

/// Writes a *genuine* autonomy ledger: an agent, its opportunity, a boundary
/// crossing and the receipt that cites it, all correctly hash-chained.
///
/// Genuine, not forged — the records are exactly what the real writer would
/// emit and the receipt is a real value event. The boundary crossing has to be
/// written directly because no CLI command records one; what is under test
/// here is the signing, not the record keeping.
fn write_autonomy_ledger(ledger: &Path, tx: &str) -> String {
    let source_id = "src-1";
    let manifest = EconomicAgentManifest {
        schema_version: SCHEMA_VERSION,
        agent_id: "s1-arb-01".into(),
        public_key: "ed25519:test".into(),
        agent_class: AgentClass::Finance,
        allowed_job_types: vec![JobType::Simulation],
        daily_budget_musd_micros: 100_000_000,
        max_job_cost_musd_micros: 2_000_000,
        risk_profile: RiskProfile::Conservative,
        enabled: true,
        created_at_unix: 1_700_000_000,
    };
    let opportunity = OpportunityCandidate {
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
    };
    let payloads = vec![
        AutonomyPayload::Agent { manifest },
        AutonomyPayload::Opportunity { opportunity },
        AutonomyPayload::BoundaryCrossing {
            evidence: BoundaryEvidence {
                chain_id: BASE_CHAIN_ID,
                asset: RealAsset::base_usdc(),
                from_address: COUNTERPARTY.into(),
                to_address: PAYOUT.into(),
                amount_raw: RECEIPT_AMOUNT_RAW,
                tx_hash: tx.into(),
                block_hash: block_hash(RECEIPT_BLOCK),
            },
        },
        AutonomyPayload::ExternalValue {
            receipt: ExternalValueReceipt {
                schema_version: SCHEMA_VERSION,
                source_id: source_id.into(),
                agent_id: "s1-arb-01".into(),
                opportunity_id: "opp-1".into(),
                value_class: ExternalValueClass::ExternalTradingPnl,
                network: "base".into(),
                asset: "USDC".into(),
                gross_inflow_musd_micros: RECEIPT_AMOUNT_RAW,
                external_cost_musd_micros: 0,
                net_external_value_musd_micros: RECEIPT_AMOUNT_RAW as i64,
                proof_hash: tx.into(),
                // A stored claim, not an authority input: it grants nothing and
                // the view is required to ignore it in both directions.
                proof_verified: false,
                realized_at_unix: 1_700_000_400,
                verifier_id: String::new(),
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
        record.record_hash =
            blake3::hash(&serde_json::to_vec(&record).unwrap())
                .to_hex()
                .to_string();
        prev = record.record_hash.clone();
        lines.push(serde_json::to_string(&record).unwrap());
    }
    fs::create_dir_all(ledger.parent().unwrap()).unwrap();
    fs::write(ledger, format!("{}\n", lines.join("\n"))).unwrap();
    source_id.into()
}

#[test]
fn the_cli_can_attest_an_external_value_receipt_end_to_end() {
    let trust = ProvisionedTrust::new();
    let r = ready_to_settle(&trust);
    let source_id = write_autonomy_ledger(
        &r.env.home.join("autonomous-ledger.jsonl"),
        RECEIPT_TX_HASH,
    );

    // Before: the receipt is on the ledger and worth nothing, because there is
    // no signature behind it. In `ProviderPinned` mode the unsigned receipt does
    // not even reach the offline checks, so the counter to watch is the
    // verified one, and the note names the gap.
    let before = r.env.ok(&["autonomy-status"]);
    assert_eq!(
        before["external_value_receipts"],
        serde_json::json!(1),
        "{before}"
    );
    assert_eq!(
        before["verified_external_value_receipts"],
        serde_json::json!(0),
        "{before}"
    );
    assert_eq!(before["net_external_value_musd"], serde_json::json!(0.0), "{before}");
    let note = before["attestation_note"].as_str().unwrap();
    assert!(note.contains("no signed attestation covers this receipt"), "{note}");

    let signed = r.env.ok(&["receipt-attest", &source_id]);
    assert_eq!(signed["source_id"], serde_json::json!(source_id));
    assert_eq!(
        signed["attestation"]["verifier_key_id"],
        serde_json::json!(trust.verifier.key_id().to_string()),
        "the signature must be the one the validated policy delegated to"
    );
    assert_eq!(
        signed["attestation"]["signed_over_evidence"]["tx_hash"],
        serde_json::json!(RECEIPT_TX_HASH),
        "the signature must cover the ledger's own evidence, looked up by the \
         receipt's proof_hash"
    );

    let after = r.env.ok(&["autonomy-status"]);
    assert_eq!(
        after["verified_external_value_receipts"],
        serde_json::json!(1),
        "{after}"
    );
    assert_eq!(
        after["net_external_value_musd"],
        serde_json::json!(100.0),
        "{after}"
    );

    let ledger = signed["ledger"].as_str().unwrap().to_string();
    assert!(fs::metadata(&ledger).unwrap().len() > 0, "the ledger was not written");
    let _ = r.service.uri();
}

// ---------------------------------------------------------------------------
// 3, 4, 5. The refusals
// ---------------------------------------------------------------------------

#[test]
fn signing_without_a_validated_policy_is_refused() {
    // A trust root, a delegated verifier key, a pinned provider and a settled
    // settlement: everything except the policy. Signing must be impossible, not
    // merely discouraged, and nothing may reach the attestation ledger.
    let trust = ProvisionedTrust::new();
    let socket_dir = tempdir().unwrap();
    let service = SocketService::bind(socket_dir.path());
    let home = tempdir().unwrap().keep();
    let env = Env::new(home.clone()).with_trust_root(&trust);
    env.ok(&["payment-policy-init", PAYOUT, "2", &service.uri()]);
    env.ok(&[
        "payment-policy-pin-provider",
        &service.uri(),
        &service.uid().to_string(),
    ]);
    let job = env.ok(&[
        "job-create", "simulation", "r1", "blake3:in", "5", "false", "d",
    ]);
    let job_id = job["job_id"].as_str().unwrap().to_string();
    env.ok(&[
        "work-verify",
        &job_id,
        "w1",
        &format!("blake3:{}", "22".repeat(32)),
        "42",
        "v1",
    ]);
    env.ok(&["payment-instructions", &job_id]);
    let settlement_id = env.ok(&["settle-base-usdc", &job_id, TX_HASH])["settlement"]
        ["settlement_id"]
        .as_str()
        .unwrap()
        .to_string();

    for args in [
        vec!["settlement-attest", settlement_id.as_str()],
        vec!["receipt-attest", "src-1"],
    ] {
        let out = env.run(&args);
        assert!(!out.status.success(), "{args:?} signed without a policy");
        let err = stderr(&out);
        assert!(err.contains("refusing to sign"), "{args:?}: {err}");
        assert!(err.contains("signed outcome policy"), "{args:?}: {err}");
    }

    // No signature was produced, so nothing was written.
    assert!(
        !home.join("settlement-attestations.jsonl").exists(),
        "an attestation was recorded without a validated policy"
    );
}

#[test]
fn signing_with_a_key_the_policy_does_not_delegate_to_is_refused() {
    // The load-bearing invariant. A key planted at a path this process can read
    // must not become authoritative: the validated policy names a different
    // verifier, and the refusal happens before any signature exists.
    let trust = ProvisionedTrust::new();
    let r = ready_to_settle(&trust);
    let settlement_id = settle_id(&r);

    // The trust root is writable by this principal, which is exactly the
    // premise. Re-sign the policy to delegate somewhere else.
    let other = write_policy_delegating_elsewhere(
        &r.env.home,
        &trust,
        &r.service.uri(),
        r.service.uid(),
        2,
    );
    let show = r.env.ok(&["outcome-policy-show"]);
    assert_eq!(show["validated"], serde_json::json!(true), "{show}");
    assert_eq!(
        show["verifier_key_id"],
        serde_json::json!(other.key_id().to_string()),
        "the policy must still validate; only the delegation moved"
    );

    let out = r.env.run(&["settlement-attest", &settlement_id]);
    assert!(!out.status.success(), "an undelegated key signed a settlement");
    let err = stderr(&out);
    assert!(err.contains("refusing to sign"), "{err}");
    assert!(err.contains("delegates to"), "{err}");
    assert!(
        err.contains(&trust.verifier.key_id().to_string()),
        "the message must name the key that was offered: {err}"
    );
    assert!(err.contains(&other.key_id().to_string()), "{err}");
    assert!(
        !r.env
            .home
            .join("settlement-attestations.jsonl")
            .exists(),
        "an attestation was recorded by an undelegated key"
    );

    // The same refusal on the autonomy side.
    write_autonomy_ledger(
        &r.env.home.join("autonomous-ledger.jsonl"),
        RECEIPT_TX_HASH,
    );
    let out = r.env.run(&["receipt-attest", "src-1"]);
    assert!(!out.status.success(), "an undelegated key signed a receipt");
    assert!(stderr(&out).contains("refusing to sign"), "{}", stderr(&out));
}

#[test]
fn a_missing_key_is_an_actionable_error_not_a_silent_success_and_not_a_panic() {
    let trust = ProvisionedTrust::new();
    let r = ready_to_settle(&trust);
    let settlement_id = settle_id(&r);

    // Remove the key the operator provisioned. The policy still validates and
    // still delegates — to a key that is now not there.
    fs::remove_file(trust.root.verifier_key_path()).unwrap();

    let out = r.env.run(&["settlement-attest", &settlement_id]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("refusing to sign"), "{err}");
    assert!(err.contains("verifier-runtime.key"), "{err}");
    assert!(err.contains(TRUST_ROOT_ENV), "{err}");
    assert!(err.contains("0400"), "{err}");
    // No panic, no traceback, no empty success.
    assert!(!err.contains("panicked"), "{err}");
    assert!(!err.contains("RUST_BACKTRACE"), "{err}");

    // The read-only report says the same thing without attempting to sign.
    let report = r.env.ok(&["verifier-key-show"]);
    assert_eq!(report["verifier_key_id"], serde_json::json!(null), "{report}");
    assert_eq!(report["bound_to_policy"], serde_json::json!(false), "{report}");
    assert_eq!(
        report["policy_delegates_to"],
        serde_json::json!(trust.verifier.key_id().to_string()),
        "{report}: the policy is still valid; only the key is gone"
    );
    assert!(report["error"]
        .as_str()
        .unwrap()
        .contains("no verifier runtime signing key"), "{report}");

    assert!(
        !r.env.home.join("settlement-attestations.jsonl").exists(),
        "something was signed with no key present"
    );
}

#[test]
fn a_world_readable_key_is_refused_rather_than_used() {
    let trust = ProvisionedTrust::new();
    let r = ready_to_settle(&trust);
    let settlement_id = settle_id(&r);
    let key_path = trust.root.verifier_key_path();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o444)).unwrap();

    let out = r.env.run(&["settlement-attest", &settlement_id]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("refusing to sign"), "{err}");
    assert!(err.contains("chmod 0400"), "{err}");
    assert!(
        !r.env.home.join("settlement-attestations.jsonl").exists(),
        "a group/other-readable signing key was used"
    );
}

// ---------------------------------------------------------------------------
// 6. The documented behaviour of a relocated, principal-writable trust root
// ---------------------------------------------------------------------------

#[test]
fn a_relocated_trust_root_is_reported_and_is_what_the_documented_exposure_is() {
    // The design says a relocated trust root is a directory the invoking
    // principal controls, and that this is reported rather than inferred. This
    // test asserts exactly that much — and asserts no more, because nothing
    // else about a relocated root is protected.
    let trust = ProvisionedTrust::new();
    let r = ready_to_settle(&trust);

    let report = r.env.ok(&["verifier-key-show"]);
    assert_eq!(report["trust_root_relocated"], serde_json::json!(true), "{report}");
    assert_eq!(
        report["trust_root"],
        serde_json::json!(trust.root.dir().display().to_string()),
        "{report}"
    );
    assert_eq!(
        report["verifier_key_path"],
        serde_json::json!(trust.root.verifier_key_path().display().to_string()),
        "{report}"
    );
    assert_eq!(
        report["bound_to_policy"],
        serde_json::json!(true),
        "{report}"
    );

    // The pin and the key are in the same directory and cannot be configured
    // apart: the whole point is that planting a key requires authority you
    // cannot get by writing one file.
    assert_eq!(
        Path::new(report["policy_authority_pin"].as_str().unwrap()).parent(),
        Path::new(report["verifier_key_path"].as_str().unwrap()).parent(),
        "{report}"
    );

    // The trust report every economic command carries says so too.
    let dashboard = r.env.ok(&["economy-dashboard"]);
    assert_eq!(
        dashboard["trust"]["signing_key"]["trust_root_relocated"],
        serde_json::json!(true),
        "{dashboard}"
    );

    // What is NOT claimed: the directory really is writable by this process, so
    // the residual exposure is real rather than theoretical.
    let probe = trust.root.dir().join("probe");
    fs::write(&probe, b"x").unwrap();
    assert!(probe.exists(), "the trust root is not writable after all");
    fs::remove_file(&probe).unwrap();
}

#[test]
fn without_the_relocation_opt_in_the_cli_refuses_to_sign_at_all() {
    // The default trust root is /etc/mycelium/trust owned by root. On any host
    // that has not provisioned it — which is every host this test can run on —
    // signing must fail closed and say where the key would have to be.
    let trust = ProvisionedTrust::new();
    let r = ready_to_settle(&trust);
    let settlement_id = settle_id(&r);

    // Same directory, same policy, same key — but the operator did not point the
    // process at the trust root.
    let unpointed = Env::new(r.env.home.clone());
    // The first precondition is the policy, and without a policy there is
    // nothing to bind a key to — so the refusal names the pin, not the key.
    let out = unpointed.run(&["settlement-attest", &settlement_id]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("refusing to sign"), "{err}");
    assert!(
        err.contains("/etc/mycelium/trust/policy-authority.pub"),
        "the message must name the path an operator has to create: {err}"
    );

    let report = unpointed.ok(&["verifier-key-show"]);
    assert!(
        report["verifier_key_path"]
            .as_str()
            .unwrap()
            .ends_with("/etc/mycelium/trust/verifier-runtime.key"),
        "and the key path must be the one under the default trust root: {report}"
    );
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains(TRUST_ROOT_ENV),
        "{report}"
    );

    assert_eq!(report["trust_root_relocated"], serde_json::json!(false), "{report}");
    assert_eq!(
        report["trust_root"],
        serde_json::json!("/etc/mycelium/trust"),
        "{report}"
    );
    assert_eq!(report["expected_owner_uid"], serde_json::json!(0), "{report}");
}

// ---------------------------------------------------------------------------
// 7. The two-step flow is discoverable, not a trap
// ---------------------------------------------------------------------------

#[test]
fn settle_reports_that_it_did_not_sign_and_how_to_sign() {
    let trust = ProvisionedTrust::new();
    let r = ready_to_settle(&trust);
    let out = r.env.ok(&["settle-base-usdc", &r.job_id, TX_HASH]);
    let settlement_id = out["settlement"]["settlement_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(out["attestation"]["signed"], serde_json::json!(false), "{out}");
    assert!(
        out["attestation"]["next_command"]
            .as_str()
            .unwrap()
            .contains(&settlement_id),
        "the follow-up command must name the settlement it applies to: {out}"
    );
    assert!(
        out["attestation"]["signing_key"]["verifier_key_id"]
            .as_str()
            .unwrap()
            .starts_with("verifier-runtime:"),
        "{out}"
    );

    // The chained command in that field is the one that works.
    let attested = r
        .env
        .ok(&["settlement-attest", &settlement_id]);
    assert_eq!(
        attested["settlement_id"],
        serde_json::json!(settlement_id)
    );
}

#[test]
fn an_unknown_settlement_or_receipt_names_the_command_that_creates_it() {
    let trust = ProvisionedTrust::new();
    let r = ready_to_settle(&trust);

    let out = r.env.run(&["settlement-attest", "settle-does-not-exist"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("settle-base-usdc"), "{err}");

    let out = r.env.run(&["receipt-attest", "src-does-not-exist"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("external-value-candidate-json"),
        "{err}"
    );
}

/// The key store's own surface, asserted through the public API a third party
/// would use, so the unit tests above and this one cannot drift apart.
#[test]
fn the_provisioned_key_is_the_only_one_the_store_will_hand_out() {
    let dir = tempdir().unwrap();
    let uid = std::fs::metadata("/proc/self").unwrap().uid();
    let cfg = VerifierKeyStoreConfig::new(dir.path().join("verifier-runtime.key"), uid);
    install_verifier_runtime_key(&cfg, [1u8; 32]).unwrap();
    let loaded = mycelium_economy::verifier_key_store::load_verifier_runtime_key(&cfg).unwrap();
    assert_eq!(
        loaded.key_id(),
        mycelium_economy::policy_auth::VerifierRuntimeKey::from_seed([1u8; 32]).key_id()
    );
    // `create_new`: a second install refuses rather than rotating silently.
    assert!(
        install_verifier_runtime_key(&cfg, [2u8; 32]).is_err(),
        "install must not replace an existing signing key in place"
    );
}
// ---------------------------------------------------------------------------
// 8. Re-running the signing command
// ---------------------------------------------------------------------------

#[test]
fn re_running_the_settlement_attest_is_idempotent_not_a_conflict() {
    // An operator re-running a command is a normal thing to do, and the answer
    // must not be a hash-chain break or a "duplicate attestation" gap. ed25519
    // is deterministic, so the second signature is byte-identical and the read
    // side's index filters it; what matters is that neither write is refused.
    let trust = ProvisionedTrust::new();
    let r = ready_to_settle(&trust);
    let settlement_id = settle_id(&r);

    let first = r.env.ok(&["settlement-attest", &settlement_id]);
    let second = r.env.ok(&["settlement-attest", &settlement_id]);
    assert_eq!(
        first["attestation"]["attestation_hash"],
        second["attestation"]["attestation_hash"],
        "the same settlement and the same key produce the same signature"
    );

    // Still exactly one counted settlement, not two.
    let rv = r.env.ok(&["rv-status"]);
    assert_eq!(rv["external_paid_jobs"], serde_json::json!(1), "{rv}");
    assert_eq!(rv["paid_demand_musd_total"], serde_json::json!(5.0), "{rv}");
    assert!(
        rv["attestation_note"]
            .as_str()
            .unwrap()
            .contains("1 of 1 paid settlements are attested"),
        "{rv}"
    );
}

#[test]
fn a_simulated_settlement_cannot_be_attested() {
    // `settle-sim` books a ledger unit, not a transfer. It must be refused at
    // signing time, with the reason, rather than signed and left to the reader.
    let trust = ProvisionedTrust::new();
    let r = ready_to_settle(&trust);
    // One work receipt per job, and `ready_to_settle` already made one.
    let sim = r
        .env
        .ok(&["settle-sim", &r.job_id, "USDC_BASE", "5"]);
    let settlement_id = sim["settlement_id"]
        .as_str()
        .expect("simulated settlement id")
        .to_string();

    let out = r.env.run(&["settlement-attest", &settlement_id]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(err.contains("refusing to sign"), "{err}");
    assert!(err.contains("external settlement"), "{err}");
    assert!(
        !r.env.home.join("settlement-attestations.jsonl").exists(),
        "a simulated settlement was attested"
    );
}
