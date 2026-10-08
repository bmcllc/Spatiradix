//! NEV Tier Evaluation Integration Tests (NEV0 through NEV4).
//!
//! CRITICAL PRINCIPLES ENFORCED:
//! 1. Zero scalar backdoor constructors in integration tests: every `VerifiedNevEvent`
//!    traverses the real chain of authority:
//!    `FakeRpcSocket` -> `BaseUsdcVerifier` -> `AuthFixture` -> `SettlementInputs`
//!    -> `VerifiedSettlement` -> `ComparableVerifiedSettlement` -> `VerifiedNevEvent::from_comparable_settlement`.
//! 2. Zero arbitrary event IDs — and now zero *supplied* ones: `from_comparable_settlement`
//!    takes no `ExternalEventId` and derives the identity from the settlement's own
//!    authenticated facts, so no call site below can choose one. Where a test still
//!    computes an `ExternalEventId::logged`, it does so for one purpose only: to show
//!    that the derived identity is not that value.
//! 3. `RealOpportunityClass` capability: only verified real classes (Arbitrage) provide capability.
//!    Experimental / unpromoted classes (ComputeReward) do not provide `RealOpportunityClass`,
//!    preventing artificial promotion to NEV4.
//! 4. 30 continuous observed days are required for NEV1–NEV4.
//! 5. Historical cumulative losses do not freeze an active profitable 30-day window,
//!    while a net loss inside the 30-day window drops the current tier to PreNev0.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use serde_json::{json, Value};

use mycelium_economy::base_usdc::{BaseUsdcVerifier, BASE_CHAIN_ID, BASE_USDC, ERC20_TRANSFER_TOPIC};
use mycelium_economy::boundary::{BoundaryEvidence, ControlledAddressRegistry, RealAsset};
use mycelium_economy::chain_provider::{resolve, PinnedChainProvider};
use mycelium_economy::discovery::OpportunityClass;
use mycelium_economy::event_id::{ExternalEventFact, ExternalEventId};
use mycelium_economy::nev_durable::{NevLedger, NevObservationEvidence};
use mycelium_economy::nev_tier::{NevTier, NevTierEvaluator, VerifiedNevEvent, SECONDS_PER_DAY};
use mycelium_economy::policy_auth::ValidatedOutcomePolicy;
use mycelium_economy::settlement::{
    ComparableSettlementResult, SettlementInputs, SettlementOutcome, VerifiedSettlement,
};
use mycelium_economy::testkit::{AuthFixture, FakeRpcSocket};
use mycelium_economy::trusted_valuation::ValidatedPriceSource;

const CONTROLLED: &str = "0x1111111111111111111111111111111111111111";
const COUNTERPARTY: &str = "0x3333333333333333333333333333333333333333";

struct AuthenticHarness {
    /// Declared FIRST so it is dropped FIRST. `Drop for FakeRpcSocket` stops
    /// the accept loop and joins its thread, and the loop can only be told to
    /// stop while the socket *file* is still reachable; Rust drops struct
    /// fields in declaration order, so a `_dir` above this line unlinks that
    /// file first and the join waits on a thread that never wakes. DO NOT
    /// reorder these two fields.
    _socket: FakeRpcSocket,
    /// Keeps the socket's directory alive for as long as the socket.
    _dir: tempfile::TempDir,
    registry: ControlledAddressRegistry,
    policy: ValidatedOutcomePolicy,
    source: ValidatedPriceSource,
    verifier: BaseUsdcVerifier,
    receipts: Arc<Mutex<HashMap<String, Value>>>,
    blocks: Arc<Mutex<HashMap<String, Value>>>,
    seq: AtomicU64,
}

impl AuthenticHarness {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("create temp dir");
        let socket_path = dir.path().join("verifier.sock");

        let receipts: Arc<Mutex<HashMap<String, Value>>> = Arc::new(Mutex::new(HashMap::new()));
        let blocks: Arc<Mutex<HashMap<String, Value>>> = Arc::new(Mutex::new(HashMap::new()));

        let receipts_clone = Arc::clone(&receipts);
        let blocks_clone = Arc::clone(&blocks);

        let socket = FakeRpcSocket::with_dispatch(socket_path, move |method, params| match method {
            "eth_chainId" => Some(json!("0x2105")),
            "eth_blockNumber" => Some(json!("0x1000000")),
            "eth_getTransactionReceipt" => {
                let tx = params.get(0)?.as_str()?;
                receipts_clone.lock().unwrap().get(tx).cloned()
            }
            "eth_getBlockByNumber" => {
                let num = params.get(0)?.as_str()?;
                blocks_clone.lock().unwrap().get(num).cloned()
            }
            _ => None,
        });

        let registry = ControlledAddressRegistry::new()
            .with_address(CONTROLLED)
            .expect("valid controlled address");

        let provider = PinnedChainProvider::unix_socket(socket.path(), Some(socket.uid()))
            .expect("valid unix provider");
        let resolved = resolve(None, Some(&provider)).expect("resolve provider");
        let verifier = BaseUsdcVerifier::from_resolved(&resolved, 1).expect("create verifier");
        let auth = AuthFixture::new(socket.path(), socket.uid(), registry.clone());
        let policy = auth.validated();
        let source = ValidatedPriceSource::bind(
            &policy,
            &mycelium_economy::trusted_valuation::testkit::canonical(BASE_CHAIN_ID),
        )
        .expect("bind price source");

        Self {
            _socket: socket,
            _dir: dir,
            registry,
            policy,
            source,
            verifier,
            receipts,
            blocks,
            seq: AtomicU64::new(1),
        }
    }

    fn create_inflow_event(
        &self,
        timestamp_unix: u64,
        amount_micros: u64,
        class: OpportunityClass,
    ) -> VerifiedNevEvent {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let tx = format!("0x{:064x}", seq);
        let block_num_u64 = 0x100 + seq;
        let block_num_hex = format!("0x{block_num_u64:x}");
        let block_hash = format!("0x{:064x}", 0x10000 + seq);

        let log = json!({
            "address": BASE_USDC,
            "topics": [
                ERC20_TRANSFER_TOPIC,
                format!("0x{:0>64}", COUNTERPARTY.trim_start_matches("0x")),
                format!("0x{:0>64}", CONTROLLED.trim_start_matches("0x")),
            ],
            "data": format!("0x{:064x}", amount_micros),
            "logIndex": "0x1",
        });

        self.receipts.lock().unwrap().insert(
            tx.clone(),
            json!({
                "status": "0x1",
                "blockNumber": block_num_hex,
                "blockHash": block_hash,
                "transactionHash": tx,
                "logs": [log],
                "gasUsed": "0x0",
                "effectiveGasPrice": "0x0",
            }),
        );

        self.blocks.lock().unwrap().insert(
            block_num_hex,
            json!({
                "hash": block_hash,
                "timestamp": format!("0x{timestamp_unix:x}"),
            }),
        );

        let scan = self.verifier.scan_transaction(&tx).expect("scan tx");
        let evidence = vec![BoundaryEvidence {
            chain_id: BASE_CHAIN_ID,
            asset: RealAsset::base_usdc(),
            from_address: COUNTERPARTY.into(),
            to_address: CONTROLLED.into(),
            amount_raw: amount_micros,
            tx_hash: tx.clone(),
            block_hash,
        }];

        let inputs = SettlementInputs::new(vec![&scan], &self.registry, &evidence, Some(&self.policy));
        let outcome = VerifiedSettlement::assemble(&inputs).expect("assemble settlement");
        let settlement = match outcome {
            SettlementOutcome::Complete(s) => s,
            SettlementOutcome::Incomplete(i) => panic!("settlement must be complete: {:?}", i.reasons()),
        };

        let comparable = match settlement.compare(&self.source, &[]) {
            ComparableSettlementResult::Comparable(c) => c,
            ComparableSettlementResult::NoComparableNetValue(r) => {
                panic!("settlement must be comparable: {r:?}")
            }
        };

        // No `ExternalEventId` is computed here any more and none can be passed in:
        // the constructor derives the identity from the settlement's own
        // authenticated facts. The chain read above produced a complete settlement
        // whose legs are all established, so a derivation here can fail only if the
        // chain never named a fact it had already given us.
        VerifiedNevEvent::from_comparable_settlement(&comparable, class)
            .expect("a complete settlement derives an economic identity")
    }

    fn create_loss_event(
        &self,
        timestamp_unix: u64,
        loss_amount_micros: u64,
        class: OpportunityClass,
    ) -> VerifiedNevEvent {
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let tx = format!("0x{:064x}", seq);
        let block_num_u64 = 0x100 + seq;
        let block_num_hex = format!("0x{block_num_u64:x}");
        let block_hash = format!("0x{:064x}", 0x10000 + seq);

        // Outflow transfer: controlled -> counterparty
        let log = json!({
            "address": BASE_USDC,
            "topics": [
                ERC20_TRANSFER_TOPIC,
                format!("0x{:0>64}", CONTROLLED.trim_start_matches("0x")),
                format!("0x{:0>64}", COUNTERPARTY.trim_start_matches("0x")),
            ],
            "data": format!("0x{:064x}", loss_amount_micros),
            "logIndex": "0x1",
        });

        self.receipts.lock().unwrap().insert(
            tx.clone(),
            json!({
                "status": "0x1",
                "blockNumber": block_num_hex,
                "blockHash": block_hash,
                "transactionHash": tx,
                "logs": [log],
                "gasUsed": "0x0",
                "effectiveGasPrice": "0x0",
            }),
        );

        self.blocks.lock().unwrap().insert(
            block_num_hex,
            json!({
                "hash": block_hash,
                "timestamp": format!("0x{timestamp_unix:x}"),
            }),
        );

        let scan = self.verifier.scan_transaction(&tx).expect("scan tx");
        let evidence = vec![BoundaryEvidence {
            chain_id: BASE_CHAIN_ID,
            asset: RealAsset::base_usdc(),
            from_address: CONTROLLED.into(),
            to_address: COUNTERPARTY.into(),
            amount_raw: loss_amount_micros,
            tx_hash: tx.clone(),
            block_hash,
        }];

        let inputs = SettlementInputs::new(vec![&scan], &self.registry, &evidence, Some(&self.policy));
        let outcome = VerifiedSettlement::assemble(&inputs).expect("assemble settlement");
        let settlement = match outcome {
            SettlementOutcome::Complete(s) => s,
            SettlementOutcome::Incomplete(i) => panic!("settlement must be complete: {:?}", i.reasons()),
        };

        let comparable = match settlement.compare(&self.source, &[]) {
            ComparableSettlementResult::Comparable(c) => c,
            ComparableSettlementResult::NoComparableNetValue(r) => {
                panic!("settlement must be comparable: {r:?}")
            }
        };

        // As above: the identity is derived, not supplied, and this settlement's
        // single outflow leg is as established as the inflow leg above.
        VerifiedNevEvent::from_comparable_settlement(&comparable, class)
            .expect("a complete settlement derives an economic identity")
    }
}

/// One real Base settlement whose receipt carries TWO USDC transfer logs in one
/// transaction: a small inflow at `logIndex 0x0` and an outflow at `logIndex 0x1`.
///
/// `AuthenticHarness` answers per request through `with_dispatch`, because it has
/// to mint a fresh transaction per event. This harness instead uses
/// `FakeRpcSocket::with_responses`, the fixed method→response map, because the
/// subject of the tests below is a single operation that moved value in *both*
/// directions: the outflow has to sit in the same receipt as the inflow for the
/// negative net to be a fact about one operation rather than two unrelated ones.
/// A one-log harness cannot express that at all — its settlement only ever has
/// one leg, so its net is whatever that one transfer says.
struct TwoLegHarness {
    /// Declared FIRST so it is dropped FIRST. `Drop for FakeRpcSocket` stops
    /// the accept loop and joins its thread, and the loop can only be told to
    /// stop while the socket *file* is still reachable; Rust drops struct
    /// fields in declaration order, so a `_dir` above this line unlinks that
    /// file first and the join waits on a thread that never wakes. DO NOT
    /// reorder these two fields.
    _socket: FakeRpcSocket,
    /// Keeps the socket's directory alive for as long as the socket.
    _dir: tempfile::TempDir,
    registry: ControlledAddressRegistry,
    policy: ValidatedOutcomePolicy,
    source: ValidatedPriceSource,
    verifier: BaseUsdcVerifier,
    tx_hash: String,
    block_hash: String,
    inflow_raw: u64,
    outflow_raw: u64,
}

impl TwoLegHarness {
    /// `inflow_raw` lands on log `0x0` (counterparty → controlled) and
    /// `outflow_raw` on log `0x1` (controlled → counterparty). Base USDC has six
    /// decimals and the micro unit has six, so raw units are already micros and
    /// the settlement's net is exactly `inflow_raw - outflow_raw`.
    ///
    /// `tx_seq` only has to be distinct between harnesses built in the same
    /// process: each one owns its own socket and its own transaction hash.
    fn new(tx_seq: u64, timestamp_unix: u64, inflow_raw: u64, outflow_raw: u64) -> Self {
        let dir = tempfile::tempdir().expect("create temp dir");
        let socket_path = dir.path().join("two-leg.sock");

        let tx_hash = format!("0x{:064x}", 0x9_0000 + tx_seq);
        let block_num_hex = format!("0x{:x}", 0x200 + tx_seq);
        let block_hash = format!("0x{:064x}", 0x2_0000 + tx_seq);

        let receipt = json!({
            "status": "0x1",
            "blockNumber": block_num_hex.clone(),
            "blockHash": block_hash.clone(),
            "transactionHash": tx_hash.clone(),
            "logs": [
                {
                    "address": BASE_USDC,
                    "topics": [
                        ERC20_TRANSFER_TOPIC,
                        format!("0x{:0>64}", COUNTERPARTY.trim_start_matches("0x")),
                        format!("0x{:0>64}", CONTROLLED.trim_start_matches("0x")),
                    ],
                    "data": format!("0x{:064x}", inflow_raw),
                    "logIndex": "0x0",
                },
                {
                    "address": BASE_USDC,
                    "topics": [
                        ERC20_TRANSFER_TOPIC,
                        format!("0x{:0>64}", CONTROLLED.trim_start_matches("0x")),
                        format!("0x{:0>64}", COUNTERPARTY.trim_start_matches("0x")),
                    ],
                    "data": format!("0x{:064x}", outflow_raw),
                    "logIndex": "0x1",
                },
            ],
            "gasUsed": "0x0",
            "effectiveGasPrice": "0x0",
        });

        let socket = FakeRpcSocket::with_responses(
            socket_path,
            vec![
                ("eth_chainId", json!("0x2105")),
                ("eth_blockNumber", json!("0x1000000")),
                ("eth_getTransactionReceipt", receipt),
                (
                    "eth_getBlockByNumber",
                    json!({
                        "hash": block_hash.clone(),
                        "timestamp": format!("0x{timestamp_unix:x}"),
                    }),
                ),
            ],
        );

        let registry = ControlledAddressRegistry::new()
            .with_address(CONTROLLED)
            .expect("valid controlled address");
        let provider = PinnedChainProvider::unix_socket(socket.path(), Some(socket.uid()))
            .expect("valid unix provider");
        let resolved = resolve(None, Some(&provider)).expect("resolve provider");
        let verifier = BaseUsdcVerifier::from_resolved(&resolved, 1).expect("create verifier");
        let auth = AuthFixture::new(socket.path(), socket.uid(), registry.clone());
        let policy = auth.validated();
        let source = ValidatedPriceSource::bind(
            &policy,
            &mycelium_economy::trusted_valuation::testkit::canonical(BASE_CHAIN_ID),
        )
        .expect("bind price source");

        Self {
            _socket: socket,
            _dir: dir,
            registry,
            policy,
            source,
            verifier,
            tx_hash,
            block_hash,
            inflow_raw,
            outflow_raw,
        }
    }

    /// Traverses the whole real chain for this harness's single transaction and
    /// builds the event the production constructor builds.
    ///
    /// The `dominant_*` arguments name the on-chain leg whose facts the id this
    /// harness *used to* hand the constructor was computed from: the leg that
    /// dominates this operation's net, identified by its real `logIndex`, parties
    /// and raw amount. The constructor no longer accepts an identity, so those
    /// arguments no longer reach it; they are still fed to
    /// `ExternalEventId::logged` here for one purpose only — to assert that the
    /// derived identity is NOT the caller's value. The class is passed to
    /// `from_comparable_settlement` and nowhere else, so nothing about REAL-ness is
    /// asserted here.
    fn event(
        &self,
        dominant_log_index: u64,
        dominant_from: &str,
        dominant_to: &str,
        dominant_amount_raw: u64,
        class: OpportunityClass,
    ) -> VerifiedNevEvent {
        let scan = self
            .verifier
            .scan_transaction(&self.tx_hash)
            .expect("scan tx");
        assert!(
            scan.exhaustive(),
            "both logs must classify or the leg set is not provably complete"
        );
        assert_eq!(
            scan.transfers().len(),
            2,
            "the receipt must yield both an inflow and an outflow leg"
        );

        // Stored evidence: this node's own record of both crossings. A claim,
        // not authority — `assemble` re-derives each leg from the chain read
        // and binds the claim to it field for field.
        let evidence = vec![
            BoundaryEvidence {
                chain_id: BASE_CHAIN_ID,
                asset: RealAsset::base_usdc(),
                from_address: COUNTERPARTY.into(),
                to_address: CONTROLLED.into(),
                amount_raw: self.inflow_raw,
                tx_hash: self.tx_hash.clone(),
                block_hash: self.block_hash.clone(),
            },
            BoundaryEvidence {
                chain_id: BASE_CHAIN_ID,
                asset: RealAsset::base_usdc(),
                from_address: CONTROLLED.into(),
                to_address: COUNTERPARTY.into(),
                amount_raw: self.outflow_raw,
                tx_hash: self.tx_hash.clone(),
                block_hash: self.block_hash.clone(),
            },
        ];

        let inputs = SettlementInputs::new(
            vec![&scan],
            &self.registry,
            &evidence,
            Some(&self.policy),
        );
        let outcome = VerifiedSettlement::assemble(&inputs).expect("assemble settlement");
        let settlement = match outcome {
            SettlementOutcome::Complete(s) => s,
            SettlementOutcome::Incomplete(i) => {
                panic!("settlement must be complete: {:?}", i.reasons())
            }
        };

        let comparable = match settlement.compare(&self.source, &[]) {
            ComparableSettlementResult::Comparable(c) => c,
            ComparableSettlementResult::NoComparableNetValue(r) => {
                panic!("settlement must be comparable: {r:?}")
            }
        };

        // The identity is DERIVED here, from the anchor, the operation id and the
        // canonical event ids of both legs and of any external cost. The class is
        // the caller's to state and is deliberately not part of that derivation: a
        // valuation — or a label — is a reading of an operation, not the operation.
        let event = VerifiedNevEvent::from_comparable_settlement(&comparable, class)
            .expect("a complete settlement derives an economic identity");

        // The id this harness would have passed in under the old signature, built
        // from the dominant leg's real on-chain facts. It is computed for one
        // purpose only, and that purpose is this assertion: the event's identity is
        // not the caller's to choose. The two digests are domain-separated
        // (`SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN` over the whole operation, against
        // `EVENT_ID_DOMAIN` over one log), so no caller-computed id can coincide
        // with a derived one — and there is no longer any parameter through which a
        // caller could offer one.
        let fact = ExternalEventFact::from_parts(
            BASE_CHAIN_ID,
            &self.tx_hash,
            dominant_log_index,
            &RealAsset::base_usdc(),
            dominant_from,
            dominant_to,
            dominant_amount_raw,
        )
        .expect("build external event fact");
        let caller_supplied = ExternalEventId::logged(&fact).expect("compute external event id");

        assert_ne!(
            event.event_id(),
            &caller_supplied,
            "the event's identity is derived from the settlement's own authenticated \
             facts, so it is not the id this caller computed"
        );

        event
    }
}

/// Marks `count` consecutive UTC days observed, starting at `first_day`, through
/// the durable runtime-checkpoint path.
///
/// P6.N8 closed the arbitrary-day API: coverage can no longer be asserted by
/// naming a day, so it has to come from a checkpoint the ledger produced. Each
/// day is completed by calling `complete_previous_utc_day` at the END of that
/// day (`(day + 1) * SECONDS_PER_DAY`), which is the last complete UTC day at
/// that instant.
fn observe_days_durably(evaluator: &mut NevTierEvaluator, first_day: u64, count: u64) {
    let dir = tempfile::tempdir().expect("tempdir for durable coverage");
    let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
    for offset in 0..count {
        let day = first_day + offset;
        let checkpoint = ledger
            .complete_previous_utc_day(
                (day + 1) * SECONDS_PER_DAY,
                NevObservationEvidence {
                    cycles_attempted: 1,
                    cycles_completed: 1,
                    classes_observed: vec![OpportunityClass::Arbitrage],
                    thermal_stops: 0,
                    budget_stops: 0,
                    started_at_unix: day * SECONDS_PER_DAY,
                    completed_at_unix: (day + 1) * SECONDS_PER_DAY,
                },
            )
            .expect("complete a UTC day through the durable path");
        evaluator
            .apply_durable_coverage(&checkpoint)
            .expect("apply a durable observation checkpoint");
    }
}

#[test]
fn pre_nev0_state_and_zero_events_remain_pre_nev0() {
    let mut evaluator = NevTierEvaluator::new(15_000_000);
    let status = evaluator.evaluate(2_000_000);

    assert_eq!(status.current_verified_tier, NevTier::PreNev0);
    assert_eq!(status.highest_ever_verified_tier, NevTier::PreNev0);
    assert_eq!(status.cumulative_verified_nev_micros, 0);
    assert_eq!(status.current_window_net_nev_micros, 0);
    assert!(!status.operational_self_funding_healthy);
    assert!(status.window_metrics.is_none());
}

#[test]
fn nev0_is_established_by_the_first_positive_net_external_event() {
    let harness = AuthenticHarness::new();
    let mut evaluator = NevTierEvaluator::new(15_000_000);

    // 0.01 USDC (10,000 micros) net external value through authentic settlement
    let event = harness.create_inflow_event(1_000_000, 10_000, OpportunityClass::Arbitrage);
    evaluator.record_event(event).expect("record event succeeds");

    let status = evaluator.evaluate(1_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY + SECONDS_PER_DAY);
    assert_eq!(status.current_verified_tier, NevTier::Nev0);
    assert_eq!(status.highest_ever_verified_tier, NevTier::Nev0);
    assert_eq!(status.cumulative_verified_nev_micros, 10_000);
    assert_eq!(status.current_window_net_nev_micros, 10_000);
    assert_eq!(status.cumulative_event_count, 1);
}

#[test]
fn nev1_requires_repeatability_across_days_and_events_and_continuous_observation() {
    let harness = AuthenticHarness::new();
    let mut evaluator = NevTierEvaluator::new(15_000_000);
    let base_ts = 10_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;

    // Single large event cannot satisfy NEV1 (repeatability required)
    let single_large = harness.create_inflow_event(base_ts, 480_000, OpportunityClass::Arbitrage);
    evaluator.record_event(single_large).unwrap();

    let status_one_off = evaluator.evaluate(base_ts + SECONDS_PER_DAY);
    assert_eq!(status_one_off.current_verified_tier, NevTier::Nev0);

    // Distribute 5 events over 3 distinct days
    for i in 1..=5 {
        let day = (i / 2) as u64; // days 0, 1, 2
        let evt = harness.create_inflow_event(
            base_ts + day * SECONDS_PER_DAY + (i * 10),
            90_000,
            OpportunityClass::Arbitrage,
        );
        evaluator.record_event(evt).unwrap();
    }

    // Evaluating before complete 30-day observation window keeps tier at NEV0
    let status_early = evaluator.evaluate(base_ts + 3 * SECONDS_PER_DAY);
    assert_eq!(status_early.current_verified_tier, NevTier::Nev0);

    // Provide 30 continuous observed days
    let now = base_ts + 30 * SECONDS_PER_DAY;
    let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);
    observe_days_durably(&mut evaluator, start_day, 30);

    // After full 30-day continuous observation coverage, NEV1 qualifies
    let status_repeat = evaluator.evaluate(now);
    assert_eq!(status_repeat.current_verified_tier, NevTier::Nev1);
    assert_eq!(status_repeat.highest_ever_verified_tier, NevTier::Nev1);
}

#[test]
fn nev2_evaluates_robust_economics_and_tail_metrics() {
    let harness = AuthenticHarness::new();
    let mut evaluator = NevTierEvaluator::new(15_000_000);
    let base_ts = 20_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;

    // 15 events over 10 distinct days with 30d avg > 100 mUSD/day (> 3,000,000 total)
    for i in 0..15 {
        let day = i as u64 * 2;
        let evt = harness.create_inflow_event(
            base_ts + day * SECONDS_PER_DAY,
            240_000,
            OpportunityClass::Arbitrage,
        );
        evaluator.record_event(evt).unwrap();
    }

    let now = base_ts + 30 * SECONDS_PER_DAY;
    let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);
    observe_days_durably(&mut evaluator, start_day, 30);

    let status = evaluator.evaluate(now);
    assert_eq!(status.current_verified_tier, NevTier::Nev2);

    let m = status.window_metrics.unwrap();
    assert!(m.daily_average_nev_micros >= 100_000);
    assert!(m.median_event_nev_micros > 0);
    assert!(m.p10_event_nev_micros > 0);
}

#[test]
fn nev3_enforces_operational_self_funding() {
    let harness = AuthenticHarness::new();
    let monthly_operating_cost = 10_000_000; // 10 USDC monthly operating cost
    let mut evaluator = NevTierEvaluator::new(monthly_operating_cost);
    let base_ts = 30_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;

    // Generate events totaling 16,000,000 net (> 500 mUSD/day avg = 15,000,000 total)
    for i in 0..20 {
        let day = i as u64;
        let evt = harness.create_inflow_event(
            base_ts + day * SECONDS_PER_DAY,
            800_000,
            OpportunityClass::Arbitrage,
        );
        evaluator.record_event(evt).unwrap();
    }

    let now = base_ts + 30 * SECONDS_PER_DAY;
    let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);
    observe_days_durably(&mut evaluator, start_day, 30);

    let status = evaluator.evaluate(now);
    assert_eq!(status.current_verified_tier, NevTier::Nev3);
    assert!(status.operational_self_funding_healthy);
}

#[test]
fn nev4_requires_multiple_real_classes_and_compute_reward_alone_cannot_unlock_nev4() {
    let harness = AuthenticHarness::new();
    let mut evaluator = NevTierEvaluator::new(10_000_000);
    let base_ts = 40_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;

    // Class 1: Arbitrage (high volume > 2,000,000 mUSD/day = 60,000,000 total)
    for i in 0..30 {
        let day = i as u64;
        let evt = harness.create_inflow_event(
            base_ts + day * SECONDS_PER_DAY,
            2_000_000,
            OpportunityClass::Arbitrage,
        );
        assert!(evt.real_capability().is_some());
        evaluator.record_event(evt).unwrap();
    }

    // Class 2: ComputeReward (external paid CQR compute)
    // CRITICAL: ComputeReward is NOT a RealOpportunityClass capability!
    for i in 0..10 {
        let day = (i * 2) as u64;
        let evt = harness.create_inflow_event(
            base_ts + day * SECONDS_PER_DAY + 100,
            460_000,
            OpportunityClass::ComputeReward,
        );
        assert!(evt.real_capability().is_none(), "ComputeReward cannot possess RealOpportunityClass capability");
        evaluator.record_event(evt).unwrap();
    }

    let now = base_ts + 30 * SECONDS_PER_DAY + 500;
    let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);
    observe_days_durably(&mut evaluator, start_day, 30);

    let status = evaluator.evaluate(now);
    // Tier MUST be capped at NEV3 because active REAL classes == 1
    assert_eq!(status.current_verified_tier, NevTier::Nev3);
    assert!(status
        .tier_qualification_notes
        .iter()
        .any(|n| n.contains("NEV4 gated: daily avg reached but only 1 active REAL classes")));

    let m = status.window_metrics.unwrap();
    assert_eq!(m.active_real_classes_count, 1);
}

#[test]
fn replay_attack_with_duplicate_event_id_is_strictly_rejected() {
    let harness = AuthenticHarness::new();
    let mut evaluator = NevTierEvaluator::new(10_000_000);

    let event1 = harness.create_inflow_event(1_000_000, 47_000, OpportunityClass::Arbitrage);
    // A clone carries the DERIVED identity with it, unchanged: the id is a field of
    // the event, so a copied event is refused for exactly the reason a re-read of
    // the chain is — the two are the same economic fact, and the replay set is
    // keyed on the id the constructor derived.
    let event2 = event1.clone();

    assert!(evaluator.record_event(event1).is_ok());
    let err = evaluator.record_event(event2).unwrap_err();
    assert!(err.contains("replay forbidden"));
}

#[test]
fn historical_losses_do_not_freeze_active_profitable_window_and_net_loss_drops_to_pre_nev0() {
    let harness = AuthenticHarness::new();
    let mut evaluator = NevTierEvaluator::new(10_000_000);
    let past_ts = 1_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;

    // In the distant past (60 days ago), we had an authentic net loss event of -500,000 micros
    let loss_evt = harness.create_loss_event(past_ts, 500_000, OpportunityClass::Arbitrage);
    assert_eq!(loss_evt.net_nev_musd_micros(), -500_000);
    evaluator.record_event(loss_evt).unwrap();

    // 60 days later, we have a fresh 30-day active profitable window (+1,000,000 micros across 5 events)
    let now = past_ts + 60 * SECONDS_PER_DAY;
    let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);
    observe_days_durably(&mut evaluator, start_day, 30);

    for i in 0..5 {
        let day_offset = (i * 5) as u64 * SECONDS_PER_DAY;
        let evt = harness.create_inflow_event(
            (past_ts + 35 * SECONDS_PER_DAY) + day_offset,
            200_000,
            OpportunityClass::Arbitrage,
        );
        evaluator.record_event(evt).unwrap();
    }

    let status = evaluator.evaluate(now);
    // Cumulative includes ancient loss: -500_000 + 5 * 200_000 = +500_000
    assert_eq!(status.cumulative_verified_nev_micros, 500_000);
    // Current rolling window is +1,000,000 micros!
    assert_eq!(status.current_window_net_nev_micros, 1_000_000);
    // Active profitable window qualifies for Nev1!
    assert_eq!(status.current_verified_tier, NevTier::Nev1);

    // Now inject a net loss inside the rolling window (-1,500_000 micros)
    let window_loss = harness.create_loss_event(now - 100, 1_500_000, OpportunityClass::Arbitrage);
    assert_eq!(window_loss.net_nev_musd_micros(), -1_500_000);
    evaluator.record_event(window_loss).unwrap();

    // Now rolling window net is 1_000_000 - 1_500_000 = -500_000 micros <= 0!
    let status_loss = evaluator.evaluate(now);
    assert_eq!(status_loss.current_window_net_nev_micros, -500_000);
    // Rolling window net loss MUST drop tier to PreNev0!
    assert_eq!(status_loss.current_verified_tier, NevTier::PreNev0);
    assert_eq!(status_loss.highest_ever_verified_tier, NevTier::Nev1);
}

/// A real settlement in which the OUTBOUND leg dominates produces a genuinely
/// negative NEV event, and the evaluator accounts for it at full signed value:
/// nothing is floored at zero, nothing is dropped, and a later positive event
/// simply sums with it.
#[test]
fn a_real_settled_outflow_dominant_operation_produces_a_negative_nev_event() {
    let ts = 200_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;
    // Two complete UTC days after the block, so both transactions sit in the
    // last 30 COMPLETE days and the current partial day is not the one measured.
    let now = ts + 2 * SECONDS_PER_DAY;

    // ONE receipt, TWO transfer logs: a 1_000 inflow at logIndex 0x0 and a
    // 50_000 outflow at logIndex 0x1, in a single transaction.
    let outflow_dominant = TwoLegHarness::new(1, ts + 100, 1_000, 50_000);
    // The mirror image, so the same evaluator can also hold a positive event
    // over the same window: 90_000 in at 0x0 against a 1_000 out at 0x1.
    let inflow_dominant = TwoLegHarness::new(2, ts + 200, 90_000, 1_000);

    // The event identity is DERIVED from this whole operation — its block anchor,
    // its operation id and the canonical event ids of BOTH its legs — so the two
    // operations below are separately identifiable and separately recordable. The
    // arguments that follow name the DOMINANT leg's real on-chain facts (log 0x1,
    // controlled -> counterparty, 50_000 raw units) only so `event` can show the
    // derived id is not a caller's id over that leg.
    let negative = outflow_dominant.event(
        1,
        CONTROLLED,
        COUNTERPARTY,
        50_000,
        OpportunityClass::Arbitrage,
    );
    let negative_net = negative.net_nev_musd_micros();
    assert_eq!(
        negative_net, -49_000,
        "1_000 in minus 50_000 out is a real -49_000, not a clipped zero"
    );
    assert!(negative_net < 0, "an outflow-dominant settlement must be negative");
    assert_eq!(negative.gross_inflow_musd_micros(), 1_000);
    assert_eq!(negative.external_cost_musd_micros(), 50_000);

    let mut evaluator = NevTierEvaluator::new(10_000_000);
    evaluator
        .record_event(negative)
        .expect("a negative real event is recordable");

    let after_loss = evaluator.evaluate(now);
    assert_eq!(after_loss.current_verified_tier, NevTier::PreNev0);
    assert_eq!(
        after_loss.cumulative_verified_nev_micros, negative_net,
        "the cumulative figure is the negative value EXACTLY: nothing clipped, nothing discarded"
    );
    assert_eq!(after_loss.cumulative_verified_nev_micros, -49_000);
    assert!(
        after_loss.current_window_net_nev_micros < 0,
        "the rolling window itself is negative, not merely the history"
    );
    assert_eq!(after_loss.current_window_net_nev_micros, -49_000);
    assert_eq!(after_loss.cumulative_event_count, 1);
    assert_eq!(
        after_loss.window_metrics.unwrap().total_net_nev_micros,
        -49_000
    );

    // The signed sum, in the SAME evaluator and the SAME window. This is the
    // assertion that the loss was never sanitised: a saturating_abs, a
    // max(0, ..) or a skip-on-negative anywhere in the accumulator would make
    // the total 89_000 here instead of 40_000.
    let positive = inflow_dominant.event(
        0,
        COUNTERPARTY,
        CONTROLLED,
        90_000,
        OpportunityClass::Arbitrage,
    );
    let positive_net = positive.net_nev_musd_micros();
    assert_eq!(positive_net, 89_000);
    let signed_sum = negative_net + positive_net;
    assert_eq!(signed_sum, 40_000, "-49_000 + 89_000, kept signed");

    evaluator
        .record_event(positive)
        .expect("a positive real event is recordable");
    let after_both = evaluator.evaluate(now);

    assert_eq!(after_both.cumulative_verified_nev_micros, signed_sum);
    assert_eq!(after_both.cumulative_verified_nev_micros, 40_000);
    assert_eq!(after_both.current_window_net_nev_micros, signed_sum);
    assert_eq!(after_both.cumulative_event_count, 2);
    // The negative event is still counted as history; it simply no longer
    // dominates the window, so the tier is no longer pinned to PreNev0.
    assert_eq!(
        after_both.current_verified_tier,
        NevTier::Nev0,
        "a positive window net leaves PreNev0 — the earlier loss is not what holds the tier"
    );
}

/// 30 consecutive observed UTC days are a gate of their own: real settled
/// events supply VALUE, and only an explicit coverage statement supplies the
/// 30 days. Neither alone promotes.
#[test]
fn real_settled_events_alone_do_not_grant_tier_promotion_without_thirty_observed_days() {
    let harness = AuthenticHarness::new();
    let mut evaluator = NevTierEvaluator::new(15_000_000);
    let base_ts = 300_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;
    let now = base_ts + 30 * SECONDS_PER_DAY;

    // ONE deliberately small genuine settlement: +10_000 micros on one day.
    //
    // The event values are chosen so the value criteria are NOT met and are not
    // reachable by this one small event under any reading: the 30-day daily
    // average is 10_000/30 = 333 micros against NEV1's 10_000 floor, there is
    // 1 positive event against a floor of 5, and 1 distinct positive day
    // against a floor of 3. That is what makes the coverage gate — and not a
    // value threshold — the only thing under test in this test.
    let small = harness.create_inflow_event(base_ts + 60, 10_000, OpportunityClass::Arbitrage);
    assert_eq!(small.net_nev_musd_micros(), 10_000);
    evaluator
        .record_event(small)
        .expect("a real settled event is recordable");

    let without_coverage = evaluator.evaluate(now);
    assert_eq!(
        without_coverage.current_verified_tier,
        NevTier::Nev0,
        "one real settled event establishes NEV0, and nothing more"
    );
    assert!(
        without_coverage
            .tier_qualification_notes
            .iter()
            .any(|n| n.contains("observation coverage incomplete")
                && n.contains("missing 30 of 30")),
        "the evaluator must name the coverage gap in its own words: {:?}",
        without_coverage.tier_qualification_notes
    );

    // THE ASSERTION THAT PROVES THE COVERAGE GATE RATHER THAN A VALUE
    // THRESHOLD is the pair below, read together: the window metrics show the
    // value criteria are unmet by a wide margin (333 micros/day against 10_000,
    // 1 event against 5, 1 positive day against 3), so no value threshold is
    // within reach of this single event — while the note above shows the
    // evaluator's OWN stated reason for not promoting is the missing coverage.
    // `record_event` never marks a day observed, so nothing but coverage can be
    // holding the tier at NEV0 here.
    let thin = without_coverage.window_metrics.expect("a window is active");
    assert_eq!(thin.total_events, 1);
    assert_eq!(thin.distinct_positive_days, 1);
    assert!(
        thin.daily_average_nev_micros < 10_000,
        "the value criteria are unreachable here, by construction: {}",
        thin.daily_average_nev_micros
    );

    // Now supply the 30 consecutive UTC days and nothing else. Coverage
    // completeness alone must NOT promote: the tier is unchanged.
    let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);
    observe_days_durably(&mut evaluator, start_day, 30);

    let covered_but_thin = evaluator.evaluate(now);
    assert!(
        !covered_but_thin
            .tier_qualification_notes
            .iter()
            .any(|n| n.contains("observation coverage incomplete")),
        "coverage is complete now, so the coverage gate must stop firing: {:?}",
        covered_but_thin.tier_qualification_notes
    );
    assert_eq!(
        covered_but_thin.current_verified_tier,
        NevTier::Nev0,
        "30 observed days are necessary but not sufficient"
    );

    // And with coverage already in place, the value criteria become the ONLY
    // remaining limiter: five more real settled events across three more days
    // take the 30-day total to 10_000 + 5*90_000 = 460_000, the daily average to
    // 15_333 (>= 10_000), the positive events to 6 (>= 5) and the distinct
    // positive days to 3 (>= 3), which is NEV1 and not NEV2.
    for i in 1..=5u64 {
        let day = i / 2; // days 0, 1, 2
        let evt = harness.create_inflow_event(
            base_ts + day * SECONDS_PER_DAY + (i * 10),
            90_000,
            OpportunityClass::Arbitrage,
        );
        evaluator.record_event(evt).expect("record real settled event");
    }

    let qualified = evaluator.evaluate(now);
    assert_eq!(
        qualified.current_verified_tier,
        NevTier::Nev1,
        "coverage present plus the value criteria met is what promotes"
    );
}

/// REAL-ness is decided inside `from_comparable_settlement` from the class, and
/// cannot be supplied by the caller: real settlements of the same shape, priced
/// once each, yield a capability-bearing event for Arbitrage and a capability-free
/// event for ComputeReward, and only the former counts toward NEV4's
/// diversification.
///
/// Two *operations* are settled here rather than one operation read twice. That is
/// not a weakening of the isolation this test is about — it is forced by the
/// derived identity, and forced in the direction of the property being tested.
/// Because the identity is derived from the settlement's own facts, one settlement
/// converted under two classes yields the SAME identity, so the second event could
/// not be recorded at all: it would be refused as a replay of the first. That is
/// the next test's claim, and it is why two distinct transactions are what make
/// these two events separately recordable. Everything else about them is identical
/// — same receipt shape, same two established legs, same amounts, same +49_000 net
/// — and the only input that differs is the class.
#[test]
fn a_verify_nnev_event_built_from_a_real_settlement_carries_no_fabricated_real_capability() {
    let ts = 400_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;
    let now = ts + 2 * SECONDS_PER_DAY;

    // Inflow-dominant, so each operation's net is positive and a class that
    // counts as REAL would be visible in the window metrics. Distinct `tx_seq`, so
    // distinct transactions, distinct blocks and therefore distinct derived
    // identities.
    let compute_reward_harness = TwoLegHarness::new(3, ts + 100, 50_000, 1_000);
    let arbitrage_harness = TwoLegHarness::new(5, ts + 200, 50_000, 1_000);

    // Each event is traversed for real: its own receipt over its own pinned
    // socket, its own block, its own two established legs, its own +49_000 net. The
    // only difference between the two events is the class handed to the production
    // constructor — there is no REAL flag anywhere in this path to set. The
    // `dominant_*` arguments name the inflow leg, which is the leg that dominates
    // each of these two operations.
    let compute_reward = compute_reward_harness.event(
        0,
        COUNTERPARTY,
        CONTROLLED,
        50_000,
        OpportunityClass::ComputeReward,
    );
    let arbitrage = arbitrage_harness.event(
        0,
        COUNTERPARTY,
        CONTROLLED,
        50_000,
        OpportunityClass::Arbitrage,
    );

    assert_ne!(
        compute_reward.event_id(),
        arbitrage.event_id(),
        "two distinct operations derive two distinct identities, which is what makes \
         both of these events separately recordable"
    );
    assert_eq!(compute_reward.net_nev_musd_micros(), 49_000);
    assert_eq!(
        compute_reward.net_nev_musd_micros(),
        arbitrage.net_nev_musd_micros(),
        "the same settled shape yields the same net, whatever class it is labelled with"
    );
    assert_eq!(compute_reward.class(), OpportunityClass::ComputeReward);
    assert_eq!(arbitrage.class(), OpportunityClass::Arbitrage);

    assert!(
        compute_reward.real_capability().is_none(),
        "ComputeReward cannot fabricate a REAL capability: the constructor is the only \
         source of one and it withholds it"
    );
    assert!(
        arbitrage.real_capability().is_some(),
        "Arbitrage carries the REAL capability"
    );

    let mut evaluator = NevTierEvaluator::new(10_000_000);
    evaluator
        .record_event(compute_reward)
        .expect("record the ComputeReward event");

    // Alone, with positive net, it contributes ZERO active REAL classes.
    let only_compute_reward = evaluator.evaluate(now);
    let before = only_compute_reward.window_metrics.expect("a window is active");
    assert_eq!(before.active_real_classes_count, 0);
    assert_eq!(
        before.nev_by_class.get(&OpportunityClass::ComputeReward),
        Some(&49_000),
        "its VALUE was counted in full — it is the REAL-ness that was withheld"
    );
    assert!(!before.nev_by_class.contains_key(&OpportunityClass::Arbitrage));

    evaluator
        .record_event(arbitrage)
        .expect("record the Arbitrage event");

    // Adding the Arbitrage event moves the count 0 -> 1 and no further: the
    // ComputeReward event's presence is what a fabricated flag would have
    // inflated this to 2.
    let both = evaluator.evaluate(now);
    let after = both.window_metrics.expect("a window is still active");
    assert_eq!(after.active_real_classes_count, 1);
    assert_eq!(
        after.nev_by_class.get(&OpportunityClass::ComputeReward),
        Some(&49_000)
    );
    assert_eq!(after.nev_by_class.get(&OpportunityClass::Arbitrage), Some(&49_000));
    assert_eq!(both.cumulative_event_count, 2);
}

/// Replay protection is keyed on the production event identity, so it holds for
/// a re-observation of the chain rather than only for a copied value.
#[test]
fn a_replayed_real_event_id_is_refused() {
    let ts = 500_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;
    let harness = TwoLegHarness::new(4, ts + 100, 90_000, 1_000);
    let mut evaluator = NevTierEvaluator::new(10_000_000);

    // Two INDEPENDENT traversals of the same transaction. Nothing is cloned and
    // no id is carried across: each call re-reads the receipt over the pinned
    // socket, re-derives both legs under the policy and re-prices the settlement.
    //
    // They collide because the identity is DERIVED, identically, from the same
    // settlement's own authenticated facts — the block anchor, the operation id and
    // the canonical event ids of both legs and of every external cost. That is the
    // whole reason the refusal below still holds, and it holds for a *stronger*
    // reason than it used to: no caller is asked for, or could offer, a second
    // spelling of this operation, so there is no longer any way to record the same
    // settlement twice under two different ids. The replay set is keyed on the
    // DERIVED id, which is the only id there is.
    let first = harness.event(
        0,
        COUNTERPARTY,
        CONTROLLED,
        90_000,
        OpportunityClass::Arbitrage,
    );
    let second = harness.event(
        0,
        COUNTERPARTY,
        CONTROLLED,
        90_000,
        OpportunityClass::Arbitrage,
    );

    assert_eq!(
        first.event_id(),
        second.event_id(),
        "the same on-chain facts must produce the same identity, derived twice"
    );
    assert_eq!(first.net_nev_musd_micros(), 89_000);

    evaluator
        .record_event(first)
        .expect("the first sighting of this on-chain fact is accepted");

    let err = evaluator
        .record_event(second)
        .expect_err("the same on-chain fact seen twice must be refused");
    assert!(
        err.contains("replay"),
        "the refusal must name the replay it refuses: {err}"
    );

    let status = evaluator.evaluate(ts + 2 * SECONDS_PER_DAY);
    assert_eq!(
        status.cumulative_event_count, 1,
        "the refused replay must not be counted at all"
    );
    assert_eq!(status.cumulative_verified_nev_micros, 89_000);
    assert_eq!(status.current_window_net_nev_micros, 89_000);
}
