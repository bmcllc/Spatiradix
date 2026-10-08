//! Durable, hash-chained record of verified economic events.
//!
//! # Why a sidecar and not a field on an existing record
//!
//! Every record in this crate is sealed by `blake3` over its own re-serialised
//! body with `record_hash` cleared, and every payload is `deny_unknown_fields`.
//! Adding a field to an existing record type therefore changes the hash of every
//! record already written, which would invalidate historical artifacts. That is
//! exactly why the crate already keeps `settlement-attestations.jsonl` separate
//! from the revenue ledger (see the comment on `append_settlement` in
//! `lib.rs`). This module follows that precedent: NEV durable state lives in its
//! own file, and no historical schema is touched.
//!
//! # What this ledger is NOT
//!
//! It is **not a second source of authority.** A record cannot assert NEV into
//! existence. A [`NevEconomicEventRecord`] is only ever built by
//! [`NevEconomicEventRecord::from_verified_event`], which takes a
//! `&VerifiedNevEvent` — a type whose only production constructor derives its
//! identity from a settlement's own authenticated facts. So the free economic
//! number that would make this file an authority, `{"nev": 100000000}`, has no
//! path into a record at all.
//!
//! The stored `net_nev_musd_micros` is a **cached claim**, not a fresh
//! derivation: reproducing it needs the chain read that produced the settlement,
//! which is deliberately not repeated on every replay. What is *not* cached is
//! the gate. [`NevReplay`] counts an event only when its stored
//! `revalidation_state` is `confirmed`, so the number is inert unless the
//! runtime recorded that the event survived revalidation. See
//! `RESIDUAL_EXPOSURE_CACHED_NET` below for the honest limit of that.
//!
//! # What this ledger IS for
//!
//! Replay protection that survives a restart. Before this existed,
//! `NevTierEvaluator::seen_event_ids` was a plain in-memory `BTreeSet` that
//! came back empty after every restart, so a duplicate external settlement
//! recorded after a restart would be counted as new NEV. The refusal is now
//! checked against this durable ledger, and the evaluator's replay set is
//! *derived* from it rather than being the authority.
//!
//! Nothing derived from this file is itself persisted. Persisting a derived
//! snapshot would recreate exactly the parallel hidden database this design
//! exists to avoid — the same discipline [`crate::event_id::CountedEvents`]
//! already follows when it is rebuilt from the ledger on every read.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    discovery::OpportunityClass,
    durability,
    nev_tier::SECONDS_PER_DAY,
    EconomyError, Result,
};

/// Durable NEV ledger file name; also the append lock name and the head-anchor
/// name, exactly as for every other ledger in this crate.
pub const NEV_LEDGER_FILE: &str = "nev-events.jsonl";

/// Hash-chain genesis, matching the convention the other ledgers use.
pub const NEV_LEDGER_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Schema version of the record bodies in this file.
pub const NEV_LEDGER_SCHEMA_VERSION: u32 = 1;

/// Stable spelling of [`crate::revalidation::RevalidationState::Confirmed`].
///
/// These four mirror `RevalidationState::state()` verbatim. They are restated
/// here as constants because a durable record stores the *name*, and reading one
/// back must not require constructing a `RevalidationState` just to ask what its
/// name is.
pub const REVALIDATION_STATE_CONFIRMED: &str = "confirmed";
pub const REVALIDATION_STATE_PENDING_FINALITY: &str = "pending_finality";
pub const REVALIDATION_STATE_LEFT_CANONICAL_CHAIN: &str = "left_canonical_chain";
pub const REVALIDATION_STATE_NEEDS_REVALIDATION: &str = "needs_revalidation";

/// The one revalidation state that contributes NEV. Every other state is stored
/// and stays visible, and contributes zero.
pub const COUNTING_REVALIDATION_STATE: &str = REVALIDATION_STATE_CONFIRMED;

/// Honest limit of this module, stated here rather than only in a report.
///
/// The net value stored on a record is a cached claim. This module does **not**
/// re-read the chain on replay, so it cannot itself re-derive that number; what
/// it verifies is the hash chain, the identity, and the recorded revalidation
/// gate. Closing this properly means re-deriving the settlement from a pinned
/// provider during rebuild, which is a larger change than this milestone and is
/// not attempted here.
pub const RESIDUAL_EXPOSURE_CACHED_NET: &str =
    "a record's net_nev_musd_micros is a cached claim verified by the hash chain and \
     the revalidation gate, not re-derived from the chain on every replay";

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// One durable row: the projection of a single verified economic event.
///
/// Closed with `deny_unknown_fields` so a stored field can never be silently
/// dropped on read and then fall outside the record hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NevEconomicEventRecord {
    pub schema_version: u32,
    /// The canonical settlement-economic identity, derived in P6.N6. This is
    /// the replay key.
    pub economic_event_id: String,
    /// The economic class the event was recorded under.
    pub class: OpportunityClass,
    /// Cached claim — see [`RESIDUAL_EXPOSURE_CACHED_NET`].
    pub net_nev_musd_micros: i64,
    pub gross_inflow_musd_micros: u64,
    pub external_cost_musd_micros: u64,
    pub native_gas_cost_musd_micros: u64,
    /// Anchor timestamp; fixes the event's place in the rolling window and its
    /// UTC day.
    pub anchor_block_timestamp_unix: u64,
    /// `anchor_block_timestamp_unix / SECONDS_PER_DAY`, stored so a reader does
    /// not have to recompute the window arithmetic to place the event.
    pub observed_day_index: u64,
    /// One of the four `REVALIDATION_STATE_*` spellings. Only
    /// [`COUNTING_REVALIDATION_STATE`] counts.
    pub revalidation_state: String,
}

impl NevEconomicEventRecord {
    /// Builds a record from an already-authority-typed event and a REAL
    /// revalidation outcome.
    ///
    /// # Why this is `pub(crate)` and not public (P6.N7.1)
    ///
    /// This is a WIRE record: it derives `Serialize`/`Deserialize` because its
    /// whole job is to be the bytes on disk, and every field is public so serde
    /// can round-trip it. That makes the TYPE fabricable — anyone can write the
    /// JSON, or fill the struct field by field. What is no longer possible is for
    /// that fabrication to reach authority:
    ///
    /// - the only append entry point is [`NevLedger::append_verified_event`],
    ///   which takes a `&VerifiedNevEvent` and a `&RevalidationOutcome`, not this
    ///   struct;
    /// - `RevalidationOutcome` has private fields, no `Deserialize`, and no public
    ///   constructor except one that runs a real chain check, so `confirmed`
    ///   cannot be asserted here.
    ///
    /// So a fabricated wire record can be *read*, never *authored into*. The hash
    /// chain proves a stored line was not edited; it does not grant authority,
    /// and nothing in this path treats it as if it did.
    pub(crate) fn from_verified_event(
        event: &crate::nev_tier::VerifiedNevEvent,
        outcome: &crate::revalidation::RevalidationOutcome,
    ) -> Result<Self> {
        let revalidation_state = outcome.state_name();
        let economic_event_id = event.event_id().as_str().to_string();
        validate_economic_event_id(&economic_event_id)?;
        Ok(Self {
            schema_version: NEV_LEDGER_SCHEMA_VERSION,
            economic_event_id,
            class: event.class(),
            net_nev_musd_micros: event.net_nev_musd_micros(),
            gross_inflow_musd_micros: event.gross_inflow_musd_micros(),
            external_cost_musd_micros: event.external_cost_musd_micros(),
            native_gas_cost_musd_micros: event.native_gas_cost_musd_micros(),
            anchor_block_timestamp_unix: event.timestamp_unix(),
            observed_day_index: event.timestamp_unix() / SECONDS_PER_DAY,
            revalidation_state: revalidation_state.to_string(),
        })
    }

    /// Whether this record's revalidation state lets it contribute NEV.
    pub fn counts_toward_nev(&self) -> bool {
        self.revalidation_state == COUNTING_REVALIDATION_STATE
    }

    /// # Cached value, not authority
    ///
    /// `net_nev_musd_micros` here is a CACHE of a number that was already
    /// authorised when the `VerifiedNevEvent` was built from a settlement. It is
    /// not a second, independent grant of value, and replay never mints a fresh
    /// capability from it. Re-deriving it from the pinned chain on every read is
    /// [`RESIDUAL_EXPOSURE_CACHED_NET`], reported rather than hidden.
    pub fn cached_net_nev_musd_micros(&self) -> i64 {
        self.net_nev_musd_micros
    }
}

/// Durable record of a revalidation TRANSITION for an already-recorded event.
///
/// Append-only: the original `EconomicEvent` line keeps whatever state was true
/// when it was written, and this line records what a later real check found. The
/// ledger therefore reads as a history of facts rather than a mutable status
/// field, and replay takes the latest transition as authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NevRevalidationUpdate {
    pub schema_version: u32,
    /// The event this transition is about.
    pub economic_event_id: String,
    /// The state a real [`crate::revalidation::RevalidationOutcome`] reported.
    pub new_state: String,
    pub anchor_block_number: Option<u64>,
    pub anchor_block_hash: Option<String>,
    pub confirmations: Option<u64>,
    pub required_confirmations: Option<u64>,
}

impl NevRevalidationUpdate {
    /// Built only from a real revalidation outcome — never from a state string a
    /// caller chose. `pub(crate)` for the same reason as the event record.
    pub(crate) fn from_outcome(
        economic_event_id: &str,
        outcome: &crate::revalidation::RevalidationOutcome,
    ) -> Self {
        let anchor = outcome.anchor();
        // Only the depth-bearing states carry a confirmation count; the revocation
        // and unknown states do not, and inventing a zero for them would read as
        // "confirmed at depth 0".
        let (confirmations, required_confirmations) = match outcome.state() {
            crate::revalidation::RevalidationState::Confirmed {
                confirmations,
                required_confirmations,
                ..
            }
            | crate::revalidation::RevalidationState::PendingFinality {
                confirmations,
                required_confirmations,
                ..
            } => (Some(*confirmations), Some(*required_confirmations)),
            _ => (None, None),
        };
        Self {
            schema_version: NEV_LEDGER_SCHEMA_VERSION,
            economic_event_id: economic_event_id.to_string(),
            new_state: outcome.state_name().to_string(),
            anchor_block_number: anchor.map(|a| a.block_number),
            anchor_block_hash: anchor.map(|a| a.block_hash.as_str().to_string()),
            confirmations,
            required_confirmations,
        }
    }
}

/// The state an event currently holds, derived from the event line plus every
/// later transition, in sequence order. `None` when the ledger has never heard
/// of the event.
fn current_revalidation_state<'a>(
    records: &'a [NevDurableRecord],
    economic_event_id: &str,
) -> Option<&'a str> {
    let mut current: Option<&str> = None;
    for record in records {
        if let Some(event) = record.event() {
            if event.economic_event_id == economic_event_id {
                current = Some(event.revalidation_state.as_str());
            }
        } else if let Some(update) = record.update() {
            if update.economic_event_id == economic_event_id {
                current = Some(update.new_state.as_str());
            }
        }
    }
    current
}

/// Refuses a revalidation state spelling the crate does not define, so a stored
/// line cannot introduce a fifth state that quietly counts.
fn validate_revalidation_state_name(state: &str) -> Result<()> {
    if matches!(
        state,
        REVALIDATION_STATE_CONFIRMED
            | REVALIDATION_STATE_PENDING_FINALITY
            | REVALIDATION_STATE_LEFT_CANONICAL_CHAIN
            | REVALIDATION_STATE_NEEDS_REVALIDATION
    ) {
        Ok(())
    } else {
        Err(EconomyError::Invalid(format!(
            "NEV ledger carries an unknown revalidation state {state:?}"
        )))
    }
}

/// Refuses anything that is not one canonical digest spelling.
///
/// The identity is a digest, never a label. Accepting a bare label here would
/// reopen the P6.N6 hole from the storage side even though the constructor is
/// gone.
fn validate_economic_event_id(id: &str) -> Result<()> {
    let body = id.strip_prefix("0x").ok_or_else(|| {
        EconomyError::Invalid(format!(
            "NEV economic event id {id:?} is not spelled as a 0x digest"
        ))
    })?;
    if body.len() != 64 || !body.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(EconomyError::Invalid(format!(
            "NEV economic event id {id:?} is not a canonical lowercase 32-byte hex digest"
        )));
    }
    Ok(())
}

/// Domain of a durable observation-coverage checkpoint.
pub const NEV_OBSERVATION_CHECKPOINT_DOMAIN: &str =
    "MYCELIUM-ECONOMY/NEV-OBSERVATION-CHECKPOINT/V1";

/// How much of a UTC day the runtime actually covered.
///
/// The distinction exists because a day that was *attempted* is not a day that
/// was *covered*. Deriving coverage from elapsed time, or from a caller's
/// assertion about a past day, is exactly the hole P6.N8 closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationCompleteness {
    /// At least one search cycle finished. This is the only state that grants a
    /// coverage day.
    Complete,
    /// Cycles were attempted but the day ended on a thermal stop before any of
    /// them completed. Deliberately NOT full coverage: a partial run says
    /// nothing about what the rest of the day would have observed, and inventing
    /// a full day from it would be the same fabrication as a caller asserting
    /// the day outright.
    PartialThermalAbort,
    /// No cycle completed and nothing aborted. The runtime was not covering.
    NotStarted,
}

impl ObservationCompleteness {
    /// Only a genuinely completed day is an observed day.
    pub fn grants_coverage(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// What the runtime observed while a day was running.
///
/// Every field is a fact about execution. There is deliberately no `day_index`
/// here: the day is derived from the clock by the caller of
/// [`NevLedger::complete_previous_utc_day`], never chosen here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NevObservationEvidence {
    pub cycles_attempted: u64,
    pub cycles_completed: u64,
    /// Classes the runtime actually searched, sorted and deduplicated. A class
    /// that merely appears in a registry is not searched and must not be listed.
    pub classes_observed: Vec<OpportunityClass>,
    pub thermal_stops: u64,
    pub budget_stops: u64,
    pub started_at_unix: u64,
    pub completed_at_unix: u64,
}

impl NevObservationEvidence {
    /// Derives completeness from execution, never from a caller-supplied verdict.
    pub fn completeness(&self) -> ObservationCompleteness {
        if self.cycles_completed > 0 {
            ObservationCompleteness::Complete
        } else if self.thermal_stops > 0 {
            ObservationCompleteness::PartialThermalAbort
        } else {
            ObservationCompleteness::NotStarted
        }
    }
}

/// A durable, self-hashed record that one UTC day was covered.
///
/// `day_index` is `unix_timestamp / SECONDS_PER_DAY`. The record is only ever
/// built by [`Self::from_completed_day`] from execution evidence, and the only
/// production producer of one is
/// [`NevLedger::complete_previous_utc_day`], which derives the day from the
/// current clock. There is no entry point that takes a day index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NevObservationCheckpoint {
    pub schema_version: u32,
    pub day_index: u64,
    pub cycles_attempted: u64,
    pub cycles_completed: u64,
    pub classes_observed: Vec<OpportunityClass>,
    pub thermal_stops: u64,
    pub budget_stops: u64,
    pub started_at_unix: u64,
    pub completed_at_unix: u64,
    pub completeness: ObservationCompleteness,
    pub checkpoint_hash: String,
}

impl NevObservationCheckpoint {
    /// Builds a checkpoint from what actually ran.
    ///
    /// `checkpoint_hash` is computed here, never supplied, so a caller cannot
    /// hand over a hash that does not match the evidence.
    pub fn from_completed_day(day_index: u64, evidence: NevObservationEvidence) -> Result<Self> {
        let mut classes_observed = evidence.classes_observed.clone();
        classes_observed.sort_by_key(|c| format!("{c:?}"));
        classes_observed.dedup();
        let completeness = evidence.completeness();
        let checkpoint_hash = observation_checkpoint_hash(
            day_index,
            &evidence,
            &classes_observed,
            completeness,
        )?;
        Ok(Self {
            schema_version: NEV_LEDGER_SCHEMA_VERSION,
            day_index,
            cycles_attempted: evidence.cycles_attempted,
            cycles_completed: evidence.cycles_completed,
            classes_observed,
            thermal_stops: evidence.thermal_stops,
            budget_stops: evidence.budget_stops,
            started_at_unix: evidence.started_at_unix,
            completed_at_unix: evidence.completed_at_unix,
            completeness,
            checkpoint_hash,
        })
    }

    /// Whether this checkpoint grants an observed day.
    pub fn grants_coverage(&self) -> bool {
        self.completeness.grants_coverage()
    }

    /// Recomputes the hash and compares. Called on every read, so a hand-edited
    /// checkpoint cannot sit in the ledger silently.
    pub fn verify_checkpoint_hash(&self) -> Result<()> {
        let recomputed = observation_checkpoint_hash(
            self.day_index,
            &NevObservationEvidence {
                cycles_attempted: self.cycles_attempted,
                cycles_completed: self.cycles_completed,
                classes_observed: self.classes_observed.clone(),
                thermal_stops: self.thermal_stops,
                budget_stops: self.budget_stops,
                started_at_unix: self.started_at_unix,
                completed_at_unix: self.completed_at_unix,
            },
            &self.classes_observed,
            self.completeness,
        )?;
        if recomputed != self.checkpoint_hash {
            return Err(EconomyError::Invalid(format!(
                "NEV observation checkpoint for day {} does not match its own hash",
                self.day_index
            )));
        }
        Ok(())
    }
}

/// Tagged, length-prefixed, domain-separated checkpoint preimage.
fn observation_checkpoint_hash(
    day_index: u64,
    evidence: &NevObservationEvidence,
    classes_observed: &[OpportunityClass],
    completeness: ObservationCompleteness,
) -> Result<String> {
    let mut buf = Vec::new();
    crate::policy_auth::push_tagged(
        &mut buf,
        b"domain",
        NEV_OBSERVATION_CHECKPOINT_DOMAIN.as_bytes(),
    );
    crate::policy_auth::push_tagged(
        &mut buf,
        b"schema_version",
        &NEV_LEDGER_SCHEMA_VERSION.to_be_bytes(),
    );
    crate::policy_auth::push_tagged(&mut buf, b"day_index", &day_index.to_be_bytes());
    crate::policy_auth::push_tagged(
        &mut buf,
        b"cycles_attempted",
        &evidence.cycles_attempted.to_be_bytes(),
    );
    crate::policy_auth::push_tagged(
        &mut buf,
        b"cycles_completed",
        &evidence.cycles_completed.to_be_bytes(),
    );
    for class in classes_observed {
        crate::policy_auth::push_tagged(
            &mut buf,
            b"class_observed",
            format!("{class:?}").as_bytes(),
        );
    }
    crate::policy_auth::push_tagged(
        &mut buf,
        b"thermal_stops",
        &evidence.thermal_stops.to_be_bytes(),
    );
    crate::policy_auth::push_tagged(
        &mut buf,
        b"budget_stops",
        &evidence.budget_stops.to_be_bytes(),
    );
    crate::policy_auth::push_tagged(
        &mut buf,
        b"started_at_unix",
        &evidence.started_at_unix.to_be_bytes(),
    );
    crate::policy_auth::push_tagged(
        &mut buf,
        b"completed_at_unix",
        &evidence.completed_at_unix.to_be_bytes(),
    );
    crate::policy_auth::push_tagged(
        &mut buf,
        b"completeness",
        format!("{completeness:?}").as_bytes(),
    );
    Ok(blake3::hash(&buf).to_hex().to_string())
}

/// The hash-chained envelope. Extend by adding a variant: the `kind` tag
/// discriminates, so a variant added later leaves every existing line's bytes and
/// therefore its `record_hash` untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NevDurableRecord {
    EconomicEvent {
        sequence: u64,
        recorded_at_unix: u64,
        prev_hash: String,
        record_hash: String,
        event: NevEconomicEventRecord,
    },
    /// A later real revalidation check found something different about an
    /// already-recorded event. Added in P6.N7.2; the `kind` tag means every
    /// pre-existing line still deserialises and still hashes to the same value.
    RevalidationUpdate {
        sequence: u64,
        recorded_at_unix: u64,
        prev_hash: String,
        record_hash: String,
        update: NevRevalidationUpdate,
    },
    /// Durable proof that one UTC day was covered by the runtime. Added in
    /// P6.N8; the `kind` tag means every pre-existing line still deserialises and
    /// still hashes to the same value.
    ObservationCheckpoint {
        sequence: u64,
        recorded_at_unix: u64,
        prev_hash: String,
        record_hash: String,
        checkpoint: NevObservationCheckpoint,
    },
}

impl NevDurableRecord {
    pub fn sequence(&self) -> u64 {
        match self {
            Self::EconomicEvent { sequence, .. }
            | Self::RevalidationUpdate { sequence, .. }
            | Self::ObservationCheckpoint { sequence, .. } => *sequence,
        }
    }

    pub fn prev_hash(&self) -> &str {
        match self {
            Self::EconomicEvent { prev_hash, .. }
            | Self::RevalidationUpdate { prev_hash, .. }
            | Self::ObservationCheckpoint { prev_hash, .. } => prev_hash,
        }
    }

    pub fn record_hash(&self) -> &str {
        match self {
            Self::EconomicEvent { record_hash, .. }
            | Self::RevalidationUpdate { record_hash, .. }
            | Self::ObservationCheckpoint { record_hash, .. } => record_hash,
        }
    }

    pub fn event(&self) -> Option<&NevEconomicEventRecord> {
        match self {
            Self::EconomicEvent { event, .. } => Some(event),
            _ => None,
        }
    }

    pub fn update(&self) -> Option<&NevRevalidationUpdate> {
        match self {
            Self::RevalidationUpdate { update, .. } => Some(update),
            _ => None,
        }
    }

    pub fn checkpoint(&self) -> Option<&NevObservationCheckpoint> {
        match self {
            Self::ObservationCheckpoint { checkpoint, .. } => Some(checkpoint),
            _ => None,
        }
    }

    /// Commits the canonical SEMANTIC record, not the exact persisted bytes: the
    /// value hashed is this record re-serialised with an empty `record_hash`, so
    /// key order and whitespace are outside the hash.
    fn computed_hash(&self) -> Result<String> {
        let mut copy = self.clone();
        match &mut copy {
            Self::EconomicEvent { record_hash, .. }
            | Self::RevalidationUpdate { record_hash, .. }
            | Self::ObservationCheckpoint { record_hash, .. } => record_hash.clear(),
        }
        Ok(blake3::hash(&serde_json::to_vec(&copy)?)
            .to_hex()
            .to_string())
    }
}

/// The durable NEV ledger.
#[derive(Debug, Clone)]
pub struct NevLedger {
    root: PathBuf,
}

impl NevLedger {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        durability::ensure_private_dir(&root)?;
        Ok(Self { root })
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.root.join(NEV_LEDGER_FILE)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn head_anchor(&self) -> Result<Option<durability::HeadAnchor>> {
        durability::read_head_anchor(&self.root, NEV_LEDGER_FILE)
    }

    /// Chain-verified read with out-of-band head-anchor verification.
    pub fn records(&self) -> Result<Vec<NevDurableRecord>> {
        let _lock = durability::LedgerLock::acquire_timeout(
            &self.root,
            NEV_LEDGER_FILE,
            durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery = durability::recover_torn_tail(&self.ledger_path(), "NEV ledger")?;
        let records = self.read_records()?;
        self.verify_head(&records)?;
        if let Some(torn) = recovery {
            let head = records
                .last()
                .map_or(NEV_LEDGER_GENESIS_HASH, |r| r.record_hash());
            durability::store_head_anchor(
                &self.root,
                NEV_LEDGER_FILE,
                records.last().map_or(0, |r| r.sequence()),
                head,
                Some(torn.report(now_unix())),
            )?;
        }
        Ok(records)
    }

    fn verify_head(&self, records: &[NevDurableRecord]) -> Result<()> {
        let anchor = durability::read_head_anchor(&self.root, NEV_LEDGER_FILE)?;
        let head = records
            .last()
            .map_or(NEV_LEDGER_GENESIS_HASH, |r| r.record_hash());
        let hash_at = |seq: u64| {
            records
                .iter()
                .find(|r| r.sequence() == seq)
                .map(|r| r.record_hash().to_string())
        };
        durability::verify_head_anchor(
            anchor.as_ref(),
            records.last().map_or(0, |r| r.sequence()),
            head,
            &hash_at,
            "NEV ledger",
        )
    }

    fn read_records(&self) -> Result<Vec<NevDurableRecord>> {
        let path = self.ledger_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(path)?;
        let mut out = Vec::new();
        let mut expected_seq = 1u64;
        let mut expected_prev = NEV_LEDGER_GENESIS_HASH.to_string();

        for (idx, line) in BufReader::new(file).lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: NevDurableRecord = serde_json::from_str(&line).map_err(|e| {
                EconomyError::Invalid(format!(
                    "NEV ledger line {} cannot be parsed: {}",
                    idx + 1,
                    e
                ))
            })?;
            if record.sequence() != expected_seq {
                return Err(EconomyError::Invalid(format!(
                    "NEV ledger sequence mismatch: expected {}, got {}",
                    expected_seq,
                    record.sequence()
                )));
            }
            if record.prev_hash() != expected_prev {
                return Err(EconomyError::Invalid(format!(
                    "NEV ledger hash-chain break at sequence {}",
                    record.sequence()
                )));
            }
            let computed = record.computed_hash()?;
            if record.record_hash() != computed {
                return Err(EconomyError::Invalid(format!(
                    "NEV ledger hash mismatch at sequence {}",
                    record.sequence()
                )));
            }
            match (record.event(), record.update(), record.checkpoint()) {
                (Some(event), _, _) => validate_economic_event_id(&event.economic_event_id)?,
                (None, Some(update), _) => {
                    validate_economic_event_id(&update.economic_event_id)?;
                    validate_revalidation_state_name(&update.new_state)?;
                }
                (None, None, Some(checkpoint)) => checkpoint.verify_checkpoint_hash()?,
                (None, None, None) => {}
            }
            expected_prev = record.record_hash().to_string();
            expected_seq += 1;
            out.push(record);
        }
        Ok(out)
    }

    /// Appends one verified economic event.
    ///
    /// # Durable replay refusal
    ///
    /// The duplicate check reads the LEDGER, not any in-memory set. That is what
    /// makes the refusal survive a restart: a settlement already recorded here
    /// stays refused after the process that recorded it is gone. The check is
    /// against the *seen* set, not the *counted* set, so an event that later left
    /// the canonical chain still cannot be re-appended — history is not deleted
    /// to make a reorg convenient.
    pub fn append_verified_event(
        &self,
        event: &crate::nev_tier::VerifiedNevEvent,
        outcome: &crate::revalidation::RevalidationOutcome,
    ) -> Result<()> {
        let record = NevEconomicEventRecord::from_verified_event(event, outcome)?;
        self.append(NevDurableRecord::EconomicEvent {
            sequence: 0,
            recorded_at_unix: now_unix(),
            prev_hash: String::new(),
            record_hash: String::new(),
            event: record,
        })
    }

    /// Records a NEW revalidation result for an already-recorded event.
    ///
    /// # Append-only, by construction (P6.N7.2)
    ///
    /// A ledger line is never rewritten. When an event that was `confirmed` later
    /// leaves the canonical chain, the old line still says `confirmed` — which is
    /// correct, it is what was true then — and this appends the transition. Replay
    /// derives the LATEST state from the sequence, so history stays intact while
    /// authority follows the truth.
    ///
    /// Takes a `&RevalidationOutcome` for the same reason the initial append
    /// does: the new state cannot be a caller-supplied string or boolean. It must
    /// come from a real revalidation check.
    ///
    /// Refuses an update naming an event this ledger has never seen: an update may
    /// change what is known about a recorded event, never conjure one.
    pub fn append_revalidation_outcome(
        &self,
        economic_event_id: &str,
        outcome: &crate::revalidation::RevalidationOutcome,
    ) -> Result<()> {
        validate_economic_event_id(economic_event_id)?;
        let _lock = durability::LedgerLock::acquire_timeout(
            &self.root,
            NEV_LEDGER_FILE,
            durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery = durability::recover_torn_tail(&self.ledger_path(), "NEV ledger")?;
        let existing = self.read_records()?;

        let known = existing
            .iter()
            .filter_map(|r| r.event())
            .any(|e| e.economic_event_id == economic_event_id);
        if !known {
            return Err(EconomyError::Invalid(format!(
                "revalidation update names economic event {economic_event_id}, which this \
                 ledger has never recorded; an update may change what is known about an \
                 existing event, not create one"
            )));
        }

        let update = NevRevalidationUpdate::from_outcome(economic_event_id, outcome);
        if let Some(current) = current_revalidation_state(&existing, economic_event_id) {
            if current == update.new_state {
                return Err(EconomyError::Conflict(format!(
                    "economic event {economic_event_id} is already recorded as {}; a duplicate \
                     revalidation update is refused rather than appended again",
                    update.new_state
                )));
            }
        }

        let sequence = existing.last().map(|r| r.sequence() + 1).unwrap_or(1);
        let prev_hash = existing
            .last()
            .map(|r| r.record_hash().to_string())
            .unwrap_or_else(|| NEV_LEDGER_GENESIS_HASH.to_string());
        let mut record = NevDurableRecord::RevalidationUpdate {
            sequence,
            recorded_at_unix: now_unix(),
            prev_hash,
            record_hash: String::new(),
            update,
        };
        let sealed = record.computed_hash()?;
        if let NevDurableRecord::RevalidationUpdate { record_hash, .. } = &mut record {
            *record_hash = sealed;
        }

        let line = serde_json::to_vec(&record)?;
        durability::append_line(&self.ledger_path(), &line)?;
        durability::store_head_anchor(
            &self.root,
            NEV_LEDGER_FILE,
            record.sequence(),
            record.record_hash(),
            recovery.map(|t| t.report(now_unix())),
        )
    }

    /// Records the day that just completed, derived from the clock.
    ///
    /// # Why this is the only production way to record coverage
    ///
    /// The day is `now_unix / SECONDS_PER_DAY - 1` — the last COMPLETE UTC day.
    /// It is derived from the current clock, so there is no argument through
    /// which a caller can name an arbitrary past day. That is the whole P6.N8
    /// property: the previous build exposed
    /// `NevTierEvaluator::record_day_observed(day_index)`, which let any caller
    /// assert coverage for any day they liked and so manufacture the 30-day
    /// maturity the tier gate demands. That entry point is gone from the
    /// production API.
    ///
    /// The returned checkpoint is appended durably. Coverage is therefore
    /// reconstructed by [`NevLedger::replay`] after a restart rather than held in
    /// a process-local set.
    pub fn complete_previous_utc_day(
        &self,
        now_unix: u64,
        evidence: NevObservationEvidence,
    ) -> Result<NevObservationCheckpoint> {
        let current_day = now_unix / SECONDS_PER_DAY;
        if current_day == 0 {
            return Err(EconomyError::Invalid(
                "cannot derive a previous UTC day before the unix epoch".into(),
            ));
        }
        let day_index = current_day - 1;
        let checkpoint = NevObservationCheckpoint::from_completed_day(day_index, evidence)?;
        self.append(NevDurableRecord::ObservationCheckpoint {
            sequence: 0,
            recorded_at_unix: now_unix,
            prev_hash: String::new(),
            record_hash: String::new(),
            checkpoint: checkpoint.clone(),
        })?;
        Ok(checkpoint)
    }

    /// Appends an already-built checkpoint. Prefer
    /// [`Self::complete_previous_utc_day`], which is what derives the day from the
    /// clock; this exists so a checkpoint recovered from elsewhere in the same
    /// ledger can be re-sealed.
    pub fn append_observation_checkpoint(
        &self,
        checkpoint: NevObservationCheckpoint,
    ) -> Result<()> {
        checkpoint.verify_checkpoint_hash()?;
        self.append(NevDurableRecord::ObservationCheckpoint {
            sequence: 0,
            recorded_at_unix: now_unix(),
            prev_hash: String::new(),
            record_hash: String::new(),
            checkpoint,
        })
    }

    fn append(&self, mut record: NevDurableRecord) -> Result<()> {
        // The lock spans read-tail -> derive sequence/prev_hash -> write, not just
        // the write: two racing appends would derive the same sequence.
        let _lock = durability::LedgerLock::acquire_timeout(
            &self.root,
            NEV_LEDGER_FILE,
            durability::LEDGER_LOCK_WAIT,
        )?;
        let recovery = durability::recover_torn_tail(&self.ledger_path(), "NEV ledger")?;
        let existing = self.read_records()?;

        if let NevDurableRecord::EconomicEvent { event, .. } = &record {
            if let Some(prior) = existing.iter().find(|r| {
                r.event().map(|e| &e.economic_event_id) == Some(&event.economic_event_id)
            }) {
                return Err(EconomyError::Conflict(format!(
                    "NEV ledger already holds economic event {} at sequence {}; a settlement \
                     cannot be counted twice, and this refusal is durable rather than \
                     in-process",
                    event.economic_event_id,
                    prior.sequence()
                )));
            }
        }
        if let NevDurableRecord::ObservationCheckpoint { checkpoint, .. } = &record {
            if let Some(prior) = existing
                .iter()
                .filter_map(|r| r.checkpoint())
                .find(|c| c.day_index == checkpoint.day_index)
            {
                return Err(EconomyError::Conflict(format!(
                    "NEV ledger already holds an observation checkpoint for UTC day {}; a day \
                     is completed once and cannot be re-completed with better numbers",
                    prior.day_index
                )));
            }
        }

        let sequence = existing.last().map(|r| r.sequence() + 1).unwrap_or(1);
        let prev_hash = existing
            .last()
            .map(|r| r.record_hash().to_string())
            .unwrap_or_else(|| NEV_LEDGER_GENESIS_HASH.to_string());
        // Stamp the chain fields first, then hash, then write the hash back. The
        // mutable borrow has to end before `computed_hash` takes `&record`.
        match &mut record {
            NevDurableRecord::EconomicEvent {
                sequence: s,
                prev_hash: p,
                ..
            }
            | NevDurableRecord::RevalidationUpdate {
                sequence: s,
                prev_hash: p,
                ..
            }
            | NevDurableRecord::ObservationCheckpoint {
                sequence: s,
                prev_hash: p,
                ..
            } => {
                *s = sequence;
                *p = prev_hash;
            }
        }
        let sealed = record.computed_hash()?;
        match &mut record {
            NevDurableRecord::EconomicEvent { record_hash, .. }
            | NevDurableRecord::RevalidationUpdate { record_hash, .. }
            | NevDurableRecord::ObservationCheckpoint { record_hash, .. } => *record_hash = sealed,
        }

        let line = serde_json::to_vec(&record)?;
        durability::append_line(&self.ledger_path(), &line)?;
        durability::store_head_anchor(
            &self.root,
            NEV_LEDGER_FILE,
            record.sequence(),
            record.record_hash(),
            recovery.map(|t| t.report(now_unix())),
        )
    }

    /// Derives replay state from the durable ledger.
    ///
    /// Nothing here is stored; it is recomputed on every call, so nothing can be
    /// forgotten between runs or quietly diverge from the ledger it came from.
    pub fn replay(&self) -> Result<NevReplay> {
        NevReplay::from_records(&self.records()?)
    }
}

/// One event as the durable ledger reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReplayedNevEvent {
    pub economic_event_id: String,
    pub class: OpportunityClass,
    pub net_nev_musd_micros: i64,
    pub anchor_block_timestamp_unix: u64,
    pub observed_day_index: u64,
    pub revalidation_state: String,
    /// Whether this event contributes to current NEV.
    pub counted: bool,
}

/// How many stored events were excluded from NEV, and why. Reported so a status
/// view can be honest about what it left out instead of showing a quiet zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExcludedNevCounts {
    pub pending_finality: u64,
    pub left_canonical_chain: u64,
    pub needs_revalidation: u64,
}

impl ExcludedNevCounts {
    pub fn total(&self) -> u64 {
        self.pending_finality + self.left_canonical_chain + self.needs_revalidation
    }
}

/// State derived from the durable ledger.
///
/// This is a DERIVATION. It must never itself be persisted: writing a derived
/// snapshot back to disk would create the second, hidden authority this design
/// exists to remove.
#[derive(Debug, Clone, Serialize)]
pub struct NevReplay {
    seen: BTreeSet<String>,
    counted: BTreeSet<String>,
    events: Vec<ReplayedNevEvent>,
    cumulative_verified_nev_micros: i64,
    excluded: ExcludedNevCounts,
    first_event_unix: Option<u64>,
    by_class: BTreeMap<String, i64>,
    observed_utc_days: BTreeSet<u64>,
    non_covered_days: Vec<u64>,
}

impl NevReplay {
    /// Builds replay state from records.
    ///
    /// # `pub(crate)` since P6.N7.4 — this is the boundary, not a convenience
    ///
    /// When this was `pub`, the whole authority chain could be skipped: a caller
    /// could construct a [`NevDurableRecord::EconomicEvent`] by hand — every field
    /// is public because serde needs it — hand it straight here, and reach
    /// [`crate::nev_tier::NevTierEvaluator::rebuild`] without ever opening a
    /// ledger. That reopened exactly the scalar-to-counted-NEV route N7.1 closed at
    /// the append boundary, one layer downstream.
    ///
    /// Making it crate-private is what closes it, because the only remaining way
    /// to obtain a [`NevReplay`] is [`NevLedger::replay`], and that goes through
    /// the filesystem: lock, torn-tail recovery, hash-chain verification,
    /// head-anchor verification, then semantic validation. So the only inputs a
    /// caller can reach are records that survived all of it.
    pub(crate) fn from_records(records: &[NevDurableRecord]) -> Result<Self> {
        let mut seen = BTreeSet::new();
        let mut counted = BTreeSet::new();
        let mut events = Vec::new();
        let mut cumulative_verified_nev_micros = 0i64;
        let mut excluded = ExcludedNevCounts {
            pending_finality: 0,
            left_canonical_chain: 0,
            needs_revalidation: 0,
        };
        let mut first_event_unix: Option<u64> = None;
        let mut by_class: BTreeMap<String, i64> = BTreeMap::new();
        let mut observed_utc_days: BTreeSet<u64> = BTreeSet::new();
        let mut non_covered_days: Vec<u64> = Vec::new();
        // Pass 1 collects the LATEST revalidation state per event, so a
        // Confirmed -> LeftCanonicalChain transition changes what replay counts
        // without the original line ever being rewritten.
        let mut latest_state: BTreeMap<String, String> = BTreeMap::new();
        let mut event_rows: Vec<&NevEconomicEventRecord> = Vec::new();

        for record in records {
            if let Some(event) = record.event() {
                latest_state.insert(event.economic_event_id.clone(), event.revalidation_state.clone());
                event_rows.push(event);
            } else if let Some(update) = record.update() {
                // Transitions MUST be collected in this pass, not the second one.
                // A transition line always follows its event line, so a later pass
                // would reach it only after the event had already been judged by
                // the state the event line carried — the revocation would be
                // written to disk and then ignored. Because this pass walks the
                // whole chain first, the LAST word on any event wins regardless of
                // which line came later.
                latest_state.insert(
                    update.economic_event_id.clone(),
                    update.new_state.clone(),
                );
            }
        }

        for record in records {
            // A revalidation transition. It never creates an event and never
            // removes one; it only changes the state replay will use. Because this
            // is a first pass over the whole chain, an update that appears BEFORE
            // its event line is still honoured — the event line re-asserts its
            // original state and the later sequence wins, which is why the two
            // passes below are ordered rather than interleaved.
            if let Some(update) = record.update() {
                latest_state.insert(
                    update.economic_event_id.clone(),
                    update.new_state.clone(),
                );
                continue;
            }
            let Some(event) = record.event() else {
                // A coverage checkpoint. It grants a day only when the runtime
                // actually completed a cycle: a thermally aborted or never-started
                // day stays on the ledger as an audit fact and contributes no
                // coverage.
                if let Some(checkpoint) = record.checkpoint() {
                    checkpoint.verify_checkpoint_hash()?;
                    if checkpoint.grants_coverage() {
                        observed_utc_days.insert(checkpoint.day_index);
                    } else {
                        non_covered_days.push(checkpoint.day_index);
                    }
                }
                continue;
            };
            // `seen` is unconditional: an event that later left the canonical
            // chain has still been seen, and must stay un-reappendable.
            seen.insert(event.economic_event_id.clone());

            // The state replay must judge by is the LATEST one for this event,
            // not the one its original line happened to carry.
            let effective_state = latest_state
                .get(&event.economic_event_id)
                .map(String::as_str)
                .unwrap_or(event.revalidation_state.as_str());

            let counts = effective_state == COUNTING_REVALIDATION_STATE;
            if counts {
                counted.insert(event.economic_event_id.clone());
                cumulative_verified_nev_micros = cumulative_verified_nev_micros
                    .saturating_add(event.net_nev_musd_micros);
                *by_class
                    .entry(class_name(event.class))
                    .or_insert(0) += event.net_nev_musd_micros;
                first_event_unix = Some(match first_event_unix {
                    Some(first) => first.min(event.anchor_block_timestamp_unix),
                    None => event.anchor_block_timestamp_unix,
                });
            } else {
                match effective_state {
                    REVALIDATION_STATE_PENDING_FINALITY => excluded.pending_finality += 1,
                    REVALIDATION_STATE_LEFT_CANONICAL_CHAIN => {
                        excluded.left_canonical_chain += 1
                    }
                    REVALIDATION_STATE_NEEDS_REVALIDATION => excluded.needs_revalidation += 1,
                    other => {
                        return Err(EconomyError::Invalid(format!(
                            "NEV ledger record {} carries an unknown revalidation state \
                             {other:?}",
                            event.economic_event_id
                        )))
                    }
                }
            }

            events.push(ReplayedNevEvent {
                economic_event_id: event.economic_event_id.clone(),
                class: event.class,
                net_nev_musd_micros: event.net_nev_musd_micros,
                anchor_block_timestamp_unix: event.anchor_block_timestamp_unix,
                observed_day_index: event.observed_day_index,
                revalidation_state: effective_state.to_string(),
                counted: counts,
            });
        }
        // `event_rows` was only needed to build `latest_state`; assert the two
        // passes agree rather than leaving a silently unused collection.
        debug_assert_eq!(event_rows.len(), seen.len());

        Ok(Self {
            seen,
            counted,
            events,
            cumulative_verified_nev_micros,
            excluded,
            first_event_unix,
            by_class,
            observed_utc_days,
            non_covered_days,
        })
    }

    /// UTC days the runtime durably recorded as covered, reconstructed from the
    /// ledger. Survives a restart because it is derived, not remembered.
    pub fn observed_utc_days(&self) -> &BTreeSet<u64> {
        &self.observed_utc_days
    }

    /// Days the runtime recorded a checkpoint for but which did NOT complete —
    /// thermally aborted or never started. Kept visible so a report can say why a
    /// day is missing instead of showing an unexplained hole.
    pub fn non_covered_days(&self) -> &[u64] {
        &self.non_covered_days
    }

    /// Every id ever appended, whatever its revalidation state.
    pub fn seen_economic_event_ids(&self) -> &BTreeSet<String> {
        &self.seen
    }

    /// Only ids whose stored revalidation state is `confirmed`.
    pub fn counted_economic_event_ids(&self) -> &BTreeSet<String> {
        &self.counted
    }

    pub fn per_event(&self) -> &[ReplayedNevEvent] {
        &self.events
    }

    /// Signed sum over counted events only.
    pub fn cumulative_verified_nev_micros(&self) -> i64 {
        self.cumulative_verified_nev_micros
    }

    pub fn excluded_counts(&self) -> ExcludedNevCounts {
        self.excluded
    }

    pub fn counted_event_count(&self) -> usize {
        self.counted.len()
    }

    pub fn first_event_unix(&self) -> Option<u64> {
        self.first_event_unix
    }

    /// Signed net per economic class, counted events only.
    pub fn net_by_class(&self) -> &BTreeMap<String, i64> {
        &self.by_class
    }
}

fn class_name(class: OpportunityClass) -> String {
    format!("{class:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        event_id::ExternalEventId,
        nev_tier::{NevTier, NevTierEvaluator, RealOpportunityClass, VerifiedNevEvent},
        policy_auth::Hash,
        revalidation::{RevalidationOutcome, RevalidationState, SettlementAnchor},
    };
    use std::io::Write;
    use tempfile::tempdir;

    const DAY: u64 = SECONDS_PER_DAY;
    const T0: u64 = 1_700_000_000;

    /// Deterministic block hashes, so a failing assertion names a value a reader
    /// can check rather than one that depends on anything but its tag.
    fn block_hash(tag: u8) -> Hash {
        let mut b = [0u8; 32];
        b[0] = tag;
        Hash::from_bytes(b)
    }

    fn settlement_anchor(block_number: u64, tag: u8) -> SettlementAnchor {
        SettlementAnchor::new(block_number, block_hash(tag))
    }

    fn event(seed: &str, day: u64, net_micros: i64) -> VerifiedNevEvent {
        VerifiedNevEvent::new_test(
            ExternalEventId::from_test_seed(seed),
            T0 + day * DAY,
            OpportunityClass::Arbitrage,
            Some(RealOpportunityClass::arbitrage()),
            net_micros.unsigned_abs(),
            0,
            0,
            net_micros,
        )
    }

    /// Test-only revalidation outcomes, built through the same
    /// `RevalidationOutcome` type production uses. This is `#[cfg(test)]`-gated in
    /// `revalidation.rs`, so it cannot exist in a production build — which is the
    /// whole point: the tests exercise the real capability, not a private back
    /// door.
    fn outcome(state: &str) -> RevalidationOutcome {
        match state {
            REVALIDATION_STATE_CONFIRMED => {
                RevalidationOutcome::for_test(RevalidationState::Confirmed {
                    anchor: settlement_anchor(95, 95),
                    confirmations: 6,
                    required_confirmations: 6,
                })
            }
            REVALIDATION_STATE_PENDING_FINALITY => {
                RevalidationOutcome::for_test(RevalidationState::PendingFinality {
                    anchor: settlement_anchor(95, 95),
                    confirmations: 2,
                    required_confirmations: 6,
                })
            }
            REVALIDATION_STATE_LEFT_CANONICAL_CHAIN => {
                RevalidationOutcome::for_test(RevalidationState::LeftCanonicalChain {
                    anchor: settlement_anchor(95, 95),
                    canonical_block_hash: block_hash(0xAB),
                    head_block_number: 100,
                })
            }
            REVALIDATION_STATE_NEEDS_REVALIDATION => {
                RevalidationOutcome::for_test(RevalidationState::NeedsRevalidation {
                    anchor: Some(settlement_anchor(95, 95)),
                    why: "the provider no longer serves block 95".to_string(),
                })
            }
            other => panic!(
                "{other:?} is not a RevalidationState spelling; a test may name only one of the \
                 four states the crate defines"
            ),
        }
    }

    fn record(seed: &str, day: u64, net_micros: i64, state: &str) -> NevEconomicEventRecord {
        NevEconomicEventRecord::from_verified_event(&event(seed, day, net_micros), &outcome(state))
            .expect("a verified event yields a durable record")
    }

    /// Appends `(seed, day, net, state)` tuples through the only production
    /// append entry point, `append_verified_event`.
    ///
    /// The fixture used to take pre-built wire records and hand them to
    /// `append_economic_event`. There is no longer any way to do that: nothing
    /// will append a record a caller assembled, so the fixture has to carry the
    /// two things the API now demands instead — a `VerifiedNevEvent` and a
    /// `RevalidationOutcome`.
    fn ledger_with(specs: &[(&str, u64, i64, &str)]) -> (tempfile::TempDir, NevLedger) {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        for (seed, day, net_micros, state) in specs {
            ledger
                .append_verified_event(&event(seed, *day, *net_micros), &outcome(state))
                .expect("append a verified event");
        }
        (dir, ledger)
    }

    /// Hand-writes a `revalidation_update` line with a caller-chosen `new_state`,
    /// correctly sealed and correctly chained onto whatever the ledger already
    /// holds.
    ///
    /// This is the forgery a caller would attempt if it could name the state
    /// itself. It is only expressible here because the test module can see the
    /// private sealing and chain-derivation code — which is precisely the
    /// capability production does not hand out.
    fn forge_update_line(ledger: &NevLedger, economic_event_id: &str, new_state: &str) -> Result<()> {
        let existing = ledger.read_records()?;
        let sequence = existing.last().map_or(1, |r| r.sequence() + 1);
        let prev_hash = existing
            .last()
            .map_or_else(|| NEV_LEDGER_GENESIS_HASH.to_string(), |r| {
                r.record_hash().to_string()
            });
        let mut record = NevDurableRecord::RevalidationUpdate {
            sequence,
            recorded_at_unix: T0,
            prev_hash,
            record_hash: String::new(),
            update: NevRevalidationUpdate {
                schema_version: NEV_LEDGER_SCHEMA_VERSION,
                economic_event_id: economic_event_id.to_string(),
                new_state: new_state.to_string(),
                anchor_block_number: Some(95),
                anchor_block_hash: Some(block_hash(95).as_str().to_string()),
                confirmations: Some(6),
                required_confirmations: Some(6),
            },
        };
        let seal = record.computed_hash()?;
        match &mut record {
            NevDurableRecord::RevalidationUpdate { record_hash, .. } => *record_hash = seal,
            other => panic!("the fixture is a revalidation_update line, got {other:?}"),
        }
        let mut line = serde_json::to_vec(&record)?;
        line.push(b'\n');
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(ledger.ledger_path())?;
        file.write_all(&line)?;
        file.sync_all()?;
        Ok(())
    }

    #[test]
    fn a_nev_event_remains_seen_after_restart() {
        let (dir, ledger) = ledger_with(&[("a", 1, 500, REVALIDATION_STATE_CONFIRMED)]);
        // Drop every handle and reopen from the path alone: this is the restart.
        drop(ledger);
        let reopened = NevLedger::open(dir.path()).expect("reopen after restart");
        let replay = reopened.replay().expect("replay after restart");
        assert_eq!(replay.seen_economic_event_ids().len(), 1);
        assert!(replay
            .seen_economic_event_ids()
            .contains(&record("a", 1, 500, REVALIDATION_STATE_CONFIRMED).economic_event_id));
    }

    #[test]
    fn a_duplicate_event_after_restart_is_rejected() {
        let (dir, ledger) = ledger_with(&[("a", 1, 500, REVALIDATION_STATE_CONFIRMED)]);
        drop(ledger);
        let reopened = NevLedger::open(dir.path()).expect("reopen after restart");
        // The same economic settlement, offered again after the restart. It now
        // goes in as the pair the API demands — a `VerifiedNevEvent` and a real
        // `RevalidationOutcome` — because there is no longer an entry point that
        // would take a record instead.
        let err = reopened
            .append_verified_event(
                &event("a", 1, 500),
                &outcome(REVALIDATION_STATE_CONFIRMED),
            )
            .expect_err("a duplicate must not be appended after a restart");
        assert!(
            matches!(err, EconomyError::Conflict(ref m) if m.contains("cannot be counted twice")),
            "expected a durable duplicate refusal, got {err:?}"
        );
        // And the refusal really kept the total at one event, not two.
        assert_eq!(reopened.replay().unwrap().counted_event_count(), 1);
    }

    #[test]
    fn rebuilding_from_the_same_ledger_produces_the_same_nev_state() {
        let (_dir, ledger) = ledger_with(&[
            ("a", 1, 900_000, REVALIDATION_STATE_CONFIRMED),
            ("b", 2, -250_000, REVALIDATION_STATE_CONFIRMED),
        ]);
        let replay = ledger.replay().expect("replay");
        let now = T0 + 10 * DAY;

        let mut first = NevTierEvaluator::rebuild(&replay, 100);
        let first_status = first.evaluate(now);

        let mut second = NevTierEvaluator::rebuild(&replay, 100);
        let second_status = second.evaluate(now);

        assert_eq!(first_status, second_status, "a rebuild is deterministic");
        assert_eq!(first_status.cumulative_verified_nev_micros, 650_000);
        assert_eq!(first_status.current_window_net_nev_micros, 650_000);
        // Losses are kept, not clipped away.
        assert_eq!(replay.cumulative_verified_nev_micros(), 650_000);
    }

    #[test]
    fn confirmed_event_counts_exactly_once() {
        let (_dir, ledger) = ledger_with(&[
            ("a", 1, 700_000, REVALIDATION_STATE_CONFIRMED),
            ("b", 2, 700_000, REVALIDATION_STATE_CONFIRMED),
        ]);
        let replay = ledger.replay().expect("replay");
        assert_eq!(replay.counted_event_count(), 2);
        assert_eq!(replay.cumulative_verified_nev_micros(), 1_400_000);

        // And a rebuilt evaluator refuses a third copy of one already counted.
        let mut evaluator = NevTierEvaluator::rebuild(&replay, 0);
        assert!(evaluator
            .record_event(event("a", 1, 700_000))
            .is_err());
    }

    #[test]
    fn pending_finality_does_not_grant_current_nev() {
        let (_dir, ledger) = ledger_with(&[(
            "p",
            1,
            5_000_000,
            REVALIDATION_STATE_PENDING_FINALITY,
        )]);
        let replay = ledger.replay().expect("replay");
        assert_eq!(replay.cumulative_verified_nev_micros(), 0);
        assert_eq!(replay.counted_economic_event_ids().len(), 0);
        // Still seen, and still on the books as an audit trail.
        assert_eq!(replay.seen_economic_event_ids().len(), 1);
        assert_eq!(replay.excluded_counts().pending_finality, 1);

        let mut evaluator = NevTierEvaluator::rebuild(&replay, 0);
        let status = evaluator.evaluate(T0 + 5 * DAY);
        assert_eq!(status.cumulative_verified_nev_micros, 0);
        assert_eq!(status.current_verified_tier, NevTier::PreNev0);
    }

    #[test]
    fn needs_revalidation_does_not_grant_current_nev() {
        let (_dir, ledger) = ledger_with(&[(
            "n",
            1,
            5_000_000,
            REVALIDATION_STATE_NEEDS_REVALIDATION,
        )]);
        let replay = ledger.replay().expect("replay");
        assert_eq!(replay.cumulative_verified_nev_micros(), 0);
        assert_eq!(replay.excluded_counts().needs_revalidation, 1);
        assert_eq!(replay.seen_economic_event_ids().len(), 1);
    }

    #[test]
    fn a_left_canonical_chain_event_remains_seen_but_is_not_counted() {
        let (_dir, ledger) = ledger_with(&[
            ("g", 1, 400_000, REVALIDATION_STATE_CONFIRMED),
            ("r", 2, 900_000, REVALIDATION_STATE_LEFT_CANONICAL_CHAIN),
        ]);
        let replay = ledger.replay().expect("replay");

        // The reorg does not delete history: both ids are still on the ledger.
        assert_eq!(replay.seen_economic_event_ids().len(), 2);
        // But only the surviving one counts.
        assert_eq!(replay.counted_economic_event_ids().len(), 1);
        assert_eq!(replay.cumulative_verified_nev_micros(), 400_000);
        assert_eq!(replay.excluded_counts().left_canonical_chain, 1);

        // And the reorged event is still refused for re-append, which is what
        // stops "it left the chain, so let me record it again later".
        let mut evaluator = NevTierEvaluator::rebuild(&replay, 0);
        assert!(evaluator.record_event(event("r", 2, 900_000)).is_err());
    }

    #[test]
    fn a_torn_nev_tail_is_recovered_without_double_counting() {
        let (dir, ledger) = ledger_with(&[
            ("a", 1, 500, REVALIDATION_STATE_CONFIRMED),
            ("b", 2, 700, REVALIDATION_STATE_CONFIRMED),
        ]);
        let path = ledger.ledger_path();
        drop(ledger);

        // Simulate a crash partway through appending a third record: a truncated
        // JSON prefix with no terminating newline.
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open ledger for torn append");
        use std::io::Write;
        file.write_all(br#"{"kind":"economic_event","sequence":3,"recorded_at_un"#)
            .expect("write torn fragment");
        file.sync_all().expect("sync torn fragment");
        drop(file);

        let reopened = NevLedger::open(dir.path()).expect("reopen after crash");
        let records = reopened.records().expect("recovery truncates the torn tail");
        assert_eq!(records.len(), 2, "A and B survive; C was never completed");
        assert_eq!(records[1].sequence(), 2);

        let replay = reopened.replay().expect("replay after recovery");
        assert_eq!(replay.cumulative_verified_nev_micros(), 1_200);
        assert_eq!(replay.counted_event_count(), 2);

        // The discarded bytes are reported rather than silently swallowed.
        let anchor = reopened.head_anchor().expect("head anchor").expect("anchor written");
        assert!(
            anchor.discarded_bytes_total > 0,
            "a torn tail must be recorded in the anchor, not hidden"
        );
    }

    #[test]
    fn a_tampered_ledger_record_is_refused_on_read() {
        let (_dir, ledger) = ledger_with(&[("a", 1, 500, REVALIDATION_STATE_CONFIRMED)]);
        let path = ledger.ledger_path();
        drop(ledger);

        let original = fs::read_to_string(&path).expect("read ledger");
        let tampered = original.replacen("\"net_nev_musd_micros\":500", "\"net_nev_musd_micros\":900", 1);
        assert_ne!(original, tampered, "the fixture must actually change the number");
        fs::write(&path, tampered).expect("write tampered ledger");

        let reopened = NevLedger::open(_dir.path()).expect("reopen tampered ledger");
        let err = reopened
            .records()
            .expect_err("a hash mismatch must be refused, not accepted");
        assert!(
            matches!(err, EconomyError::Invalid(ref m) if m.contains("hash mismatch")),
            "expected a hash-mismatch refusal, got {err:?}"
        );
    }

    #[test]
    fn a_large_claimed_amount_still_counts_zero_unless_the_state_is_confirmed() {
        // The net on a record is a cached claim. What stops a big number from
        // becoming authority is not the number's size but the revalidation gate,
        // so exercise the gate directly on in-memory records.
        let huge = NevEconomicEventRecord {
            schema_version: NEV_LEDGER_SCHEMA_VERSION,
            economic_event_id: ExternalEventId::from_test_seed("huge").as_str().to_string(),
            class: OpportunityClass::Arbitrage,
            net_nev_musd_micros: 999_000_000,
            gross_inflow_musd_micros: 999_000_000,
            external_cost_musd_micros: 0,
            native_gas_cost_musd_micros: 0,
            anchor_block_timestamp_unix: T0,
            observed_day_index: T0 / DAY,
            revalidation_state: REVALIDATION_STATE_LEFT_CANONICAL_CHAIN.to_string(),
        };
        let revoked = NevDurableRecord::EconomicEvent {
            sequence: 1,
            recorded_at_unix: T0,
            prev_hash: NEV_LEDGER_GENESIS_HASH.to_string(),
            record_hash: String::new(),
            event: huge,
        };
        let replay = NevReplay::from_records(std::slice::from_ref(&revoked))
            .expect("a revoked record still replays");
        assert_eq!(
            replay.cumulative_verified_nev_micros(),
            0,
            "a revoked claim contributes zero no matter how large it claims to be"
        );
        assert_eq!(replay.excluded_counts().left_canonical_chain, 1);
        assert_eq!(
            replay.seen_economic_event_ids().len(),
            1,
            "a revoked event is still seen, so it stays un-reappendable"
        );
    }

    #[test]
    fn an_economic_event_id_must_be_a_canonical_digest_not_a_label() {
        let mut r = record("a", 1, 500, REVALIDATION_STATE_CONFIRMED);
        for bad in ["settled", "0xABC", "0x00", &"g".repeat(64)] {
            r.economic_event_id = bad.to_string();
            assert!(
                validate_economic_event_id(bad).is_err(),
                "{bad:?} must not be accepted as an economic identity"
            );
        }
    }

    /// MIGRATED (P6.N7.1). This test used to assert that
    /// `from_verified_event(&event, "totally_fine")` was refused. That
    /// constructor no longer takes a state at all — the state arrives inside a
    /// `RevalidationOutcome` — so "an unknown state is refused AT CONSTRUCTION"
    /// is no longer a property any type in this file can have, and a test named
    /// for it would be asserting a fiction. What replaced it is strictly
    /// stronger and is asserted below: the four spellings are the only ones the
    /// ledger will accept, from either direction, and an outcome's state can only
    /// be reached by naming one of those four in the first place.
    #[test]
    fn an_unknown_revalidation_state_is_refused_at_the_ledger_boundary() {
        for good in [
            REVALIDATION_STATE_CONFIRMED,
            REVALIDATION_STATE_PENDING_FINALITY,
            REVALIDATION_STATE_LEFT_CANONICAL_CHAIN,
            REVALIDATION_STATE_NEEDS_REVALIDATION,
        ] {
            assert!(
                validate_revalidation_state_name(good).is_ok(),
                "{good} must be a state the crate defines"
            );
            // And the spelling the durable record is given is that same spelling,
            // reached the way production reaches it: through an outcome.
            assert_eq!(outcome(good).state_name(), good);
        }
        for bad in ["totally_fine", "", "CONFIRMED", "confirmed ", "left-canonical-chain"] {
            assert!(
                validate_revalidation_state_name(bad).is_err(),
                "{bad:?} must not be accepted as a revalidation state"
            );
        }

        // A zero net is still storable: it is a real settlement whose value nets
        // to nothing, and refusing it here would lose the economic fact.
        assert!(NevEconomicEventRecord::from_verified_event(
            &event("z", 1, 0),
            &outcome(REVALIDATION_STATE_CONFIRMED)
        )
        .is_ok());
    }

    #[test]
    fn a_record_reports_whether_it_counts() {
        let counted = record("a", 1, 500, REVALIDATION_STATE_CONFIRMED);
        assert!(counted.counts_toward_nev());
        for state in [
            REVALIDATION_STATE_PENDING_FINALITY,
            REVALIDATION_STATE_LEFT_CANONICAL_CHAIN,
            REVALIDATION_STATE_NEEDS_REVALIDATION,
        ] {
            assert!(
                !record("a", 1, 500, state).counts_toward_nev(),
                "{state} must not count"
            );
        }
    }

    // --------------------------------------------------------------- N7.1 ---
    //
    // The authority boundary: a durable economic record is a WIRE type — every
    // field public, `Serialize`/`Deserialize` derived — so it is fabricable by
    // construction. These tests pin down what stops a fabrication from becoming
    // authority, and they assert their preconditions FIRST, because the previous
    // round of this file passed vacuously against an empty ledger more than once.

    /// An empty ledger with no head anchor, asserted. Every refusal below is then
    /// attributable to the line under test rather than to leftover state.
    fn assert_empty(ledger: &NevLedger, why: &str) {
        assert!(
            ledger.records().expect("read the ledger").is_empty(),
            "{why}: the ledger must start empty or the test proves nothing"
        );
        let replay = ledger.replay().expect("replay the ledger");
        assert_eq!(replay.counted_event_count(), 0, "{why}: nothing is counted yet");
        assert_eq!(replay.cumulative_verified_nev_micros(), 0, "{why}: no net yet");
    }

    #[test]
    fn raw_json_economic_record_cannot_be_appended_as_authority() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");

        // PRECONDITION, asserted before anything else: an empty ledger, no lines,
        // no head anchor — so no refusal below can be blamed on a previous append.
        assert_empty(&ledger, "raw_json_economic_record_cannot_be_appended_as_authority");
        assert!(
            ledger.head_anchor().expect("head anchor").is_none(),
            "no anchor exists yet, so no verdict below can be a head-anchor verdict"
        );

        // The wire record IS fabricable. Every field is public and it derives
        // Serialize precisely because its job is to BE the bytes on disk, so this
        // struct literal is legal and consults nothing. The claim is large and
        // the state is the one that counts.
        let forged_event = NevEconomicEventRecord {
            schema_version: NEV_LEDGER_SCHEMA_VERSION,
            economic_event_id: ExternalEventId::from_test_seed("forged").as_str().to_string(),
            class: OpportunityClass::Arbitrage,
            net_nev_musd_micros: 900_000_000,
            gross_inflow_musd_micros: 900_000_000,
            external_cost_musd_micros: 0,
            native_gas_cost_musd_micros: 0,
            anchor_block_timestamp_unix: T0,
            observed_day_index: T0 / DAY,
            revalidation_state: REVALIDATION_STATE_CONFIRMED.to_string(),
        };
        let mut forged_line = NevDurableRecord::EconomicEvent {
            sequence: 1,
            recorded_at_unix: T0,
            prev_hash: NEV_LEDGER_GENESIS_HASH.to_string(),
            record_hash: String::new(),
            event: forged_event,
        };

        // Pin the claim in the bytes, so the fixture cannot quietly stop being a
        // forgery: this is exactly the JSON an attacker would write.
        let bytes = serde_json::to_string(&forged_line).expect("serialise the hand-written line");
        assert!(
            bytes.contains("\"revalidation_state\":\"confirmed\""),
            "the hand-written line really does claim confirmed: {bytes}"
        );
        assert!(
            bytes.contains("\"net_nev_musd_micros\":900000000"),
            "the hand-written line really does claim a large net: {bytes}"
        );

        // Write it to the file by hand, the way filesystem access would: no
        // `record_hash`, because nothing in the append API computes one for a
        // caller-assembled record any more.
        let path = ledger.ledger_path();
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("open the ledger for a hand-written line");
        file.write_all(bytes.as_bytes()).expect("write the line");
        file.write_all(b"\n").expect("terminate the line");
        file.sync_all().expect("sync");
        drop(file);

        // THE REFUSAL, concretely: every line is verified against its own seal on
        // read, so a line the ledger did not seal is refused rather than read.
        let err = ledger
            .read_records()
            .expect_err("a hand-written, unsealed line must not be read as a record");
        assert!(
            matches!(err, EconomyError::Invalid(ref m) if m.contains("hash mismatch")),
            "expected a hash-mismatch refusal on the hand-written line, got {err:?}"
        );

        // The strongest fabrication available to someone who has read the hashing
        // code: the SAME record, re-sealed correctly. It is indistinguishable from
        // a line the ledger wrote, and it IS read. This is asserted plainly rather
        // than hidden, because claiming otherwise would be the same fabrication in
        // reverse: the hash chain is an anti-TAMPER control, not an anti-FORGERY
        // one. What makes the difference is that no public append entry point will
        // produce this line, and `NevLedger::open` puts the file in a private
        // directory. A hash chain proves a record was not edited; it grants no
        // authority, and nothing in this path treats it as if it did.
        fs::remove_file(&path).expect("remove the hand-written ledger");
        assert_empty(&ledger, "the forged line is gone, so the next step starts clean");

        let seal = forged_line.computed_hash().expect("re-seal the forged line");
        match &mut forged_line {
            NevDurableRecord::EconomicEvent { record_hash, .. } => *record_hash = seal,
            other => panic!("the fixture is an economic_event line, got {other:?}"),
        }
        let mut resealed_bytes = serde_json::to_vec(&forged_line).expect("serialise the re-sealed line");
        resealed_bytes.push(b'\n');
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("reopen the ledger");
        file.write_all(&resealed_bytes).expect("write the re-sealed line");
        file.sync_all().expect("sync");
        drop(file);

        let records = ledger
            .read_records()
            .expect("a correctly sealed, correctly chained hand-written line is READABLE");
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].event().expect("an event line").net_nev_musd_micros,
            900_000_000,
            "and it carries the number it claimed"
        );

        // The consequence that IS enforced: the id the forgery claimed is now
        // spoken for, so the genuine event cannot be recorded behind it. A forged
        // line cannot be used as a placeholder to have one real settlement counted
        // twice.
        let err = ledger
            .append_verified_event(
                &event("forged", 1, 900_000_000),
                &outcome(REVALIDATION_STATE_CONFIRMED),
            )
            .expect_err("the forged line already occupies this economic id");
        assert!(
            matches!(err, EconomyError::Conflict(ref m) if m.contains("cannot be counted twice")),
            "expected a durable duplicate refusal, got {err:?}"
        );
    }

    #[test]
    fn append_api_does_not_accept_a_caller_supplied_confirmed_string() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "append_api_does_not_accept_a_caller_supplied_confirmed_string");

        // STRUCTURAL, and the part that cannot be an assertion because it is a
        // compile-time property: neither append entry point takes a state.
        // `append_verified_event` and `append_revalidation_outcome` both take a
        // `&RevalidationOutcome`, whose single field is private, which derives no
        // `Deserialize`, and whose only production constructor is
        // `RevalidationOutcome::check_trusted` — the production constructor, which
        // requires a `TrustedCanonicalChainView` and therefore cannot return
        // `Confirmed` without a kernel-enforced pinned provider behind it. The
        // bare `check` over a `&dyn CanonicalChainView` is `pub(crate)` and grants
        // nothing. The
        // one constructor that takes a state is `for_test`, and it is
        // `#[cfg(test)] pub(crate)`: it does not exist in a production build and is
        // not reachable from an integration test. There is therefore no expression
        // of any kind that reads `confirmed` without a check having produced it,
        // and the caller-supplied-`&str` signature that used to be here is gone.
        let ev = event("a", 1, 500);
        ledger
            .append_verified_event(&ev, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect("a real outcome appends");
        let records = ledger.records().expect("read after the append");
        assert_eq!(
            records.len(),
            1,
            "the append produced exactly one line and no update line"
        );
        assert!(
            records[0].update().is_none(),
            "an initial append is never an update"
        );

        // What `state_name()` can produce, exhaustively: the four spellings the
        // crate defines, and nothing else. A fifth cannot be written down here,
        // because `outcome` panics on one.
        for good in [
            REVALIDATION_STATE_CONFIRMED,
            REVALIDATION_STATE_PENDING_FINALITY,
            REVALIDATION_STATE_LEFT_CANONICAL_CHAIN,
            REVALIDATION_STATE_NEEDS_REVALIDATION,
        ] {
            assert_eq!(outcome(good).state_name(), good);
        }

        // The runtime half: a spelling the crate does not define is still refused
        // where the ledger reads it back, so an invented state can neither be
        // written through the API nor believed when it arrives on disk.
        assert!(
            validate_revalidation_state_name("totally_fine").is_err(),
            "an invented spelling must not validate"
        );
        forge_update_line(&ledger, ev.event_id().as_str(), "totally_fine")
            .expect("hand-write an update line naming an invented state");
        let err = ledger
            .read_records()
            .expect_err("an invented state spelling must be refused on read");
        assert!(
            matches!(err, EconomyError::Invalid(ref m) if m.contains("unknown revalidation state")),
            "expected an unknown-state refusal, got {err:?}"
        );
    }

    #[test]
    fn a_caller_cannot_deserialize_a_revalidation_outcome() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "a_caller_cannot_deserialize_a_revalidation_outcome");

        // TYPE-LEVEL, and the reason it is documented here rather than asserted:
        // `RevalidationOutcome` derives `Debug, Clone, PartialEq, Eq, Serialize`
        // and deliberately NOT `Deserialize`, and its `state` field is private. So
        // `serde_json::from_str::<RevalidationOutcome>(..)` and
        // `RevalidationOutcome { state: .. }` are both compile errors — a caller
        // cannot write them, which is exactly the property. Writing either as a
        // test would break the build rather than assert anything.
        //
        // The observable consequence is what this test does assert: the durable
        // line carries a state SPELLING, and an invented spelling is refused where
        // the ledger reads it back, so it can never become the state replay judges
        // by.
        let confirmed = outcome(REVALIDATION_STATE_CONFIRMED);
        let json = serde_json::to_string(&confirmed).expect("an outcome serialises");
        assert!(
            json.contains("\"confirmed\""),
            "the outcome's own JSON does carry the state: {json}"
        );
        let as_line = serde_json::from_str::<NevDurableRecord>(&json);
        assert!(
            as_line.is_err(),
            "an outcome's JSON is not a ledger line — it carries no `kind` tag — so it \
             cannot be appended by deserialising it into one: {json}"
        );

        let ev = event("a", 1, 500);
        ledger
            .append_verified_event(&ev, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect("append the genuine event first");
        assert_eq!(
            ledger.read_records().expect("read before the forgery").len(),
            1,
            "precondition: exactly one line to chain the forgery onto"
        );

        forge_update_line(&ledger, ev.event_id().as_str(), "confirmed-ish")
            .expect("hand-write an update line naming an invented state");
        let err = ledger
            .read_records()
            .expect_err("an invented state spelling must be refused on read");
        assert!(
            matches!(err, EconomyError::Invalid(ref m) if m.contains("unknown revalidation state")),
            "expected an unknown-state refusal, got {err:?}"
        );
    }

    #[test]
    fn only_a_verified_event_can_enter_the_append_path() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "only_a_verified_event_can_enter_the_append_path");

        let ev = event("a", 1, 700_000);
        ledger
            .append_verified_event(&ev, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect("a VerifiedNevEvent with a real outcome enters the ledger");

        let records = ledger.records().expect("read after the append");
        assert_eq!(records.len(), 1, "one append is one line");
        assert_eq!(records[0].sequence(), 1);
        assert_eq!(
            records[0].prev_hash(),
            NEV_LEDGER_GENESIS_HASH,
            "and it chains from genesis"
        );
        let stored = records[0].event().expect("the line is an economic event");
        assert_eq!(stored.economic_event_id, ev.event_id().as_str());
        assert_eq!(stored.net_nev_musd_micros, 700_000);
        assert_eq!(stored.revalidation_state, REVALIDATION_STATE_CONFIRMED);

        let replay = ledger.replay().expect("replay");
        assert_eq!(replay.counted_event_count(), 1);
        assert_eq!(replay.per_event().len(), 1, "replay shows exactly one event");
        assert_eq!(replay.cumulative_verified_nev_micros(), 700_000);
        assert_eq!(replay.seen_economic_event_ids().len(), 1);
    }

    #[test]
    fn tampering_with_the_cached_net_breaks_the_ledger_hash() {
        let (dir, ledger) = ledger_with(&[("a", 1, 500, REVALIDATION_STATE_CONFIRMED)]);
        let path = ledger.ledger_path();
        drop(ledger);

        // PRECONDITION, asserted on the untampered file: exactly one line, and it
        // reads back clean, so the refusal below is caused by the edit alone.
        let clean = NevLedger::open(dir.path()).expect("reopen the clean ledger");
        assert_eq!(clean.records().expect("read the clean ledger").len(), 1);
        assert_eq!(
            clean.replay().expect("replay the clean ledger").cumulative_verified_nev_micros(),
            500
        );
        drop(clean);

        let original = fs::read_to_string(&path).expect("read the ledger");
        let tampered =
            original.replacen("\"net_nev_musd_micros\":500", "\"net_nev_musd_micros\":900", 1);
        assert_ne!(original, tampered, "the fixture must actually change the number");
        fs::write(&path, tampered).expect("write the tampered ledger");

        let reopened = NevLedger::open(dir.path()).expect("reopen the tampered ledger");
        let err = reopened
            .records()
            .expect_err("a cached net that was edited must be refused");
        assert!(
            matches!(err, EconomyError::Invalid(ref m) if m.contains("hash mismatch")),
            "expected a hash-mismatch refusal, got {err:?}"
        );
        // And the replay refuses too, rather than quietly reporting the edit.
        assert!(
            reopened.replay().is_err(),
            "replay reads the same records, so it must refuse the same line"
        );
    }

    #[test]
    fn editing_the_cached_net_and_resealing_only_the_line_still_fails_the_chain() {
        let (dir, ledger) = ledger_with(&[
            ("a", 1, 500, REVALIDATION_STATE_CONFIRMED),
            ("b", 2, 700, REVALIDATION_STATE_CONFIRMED),
        ]);
        let path = ledger.ledger_path();
        drop(ledger);

        // PRECONDITION, asserted before the tamper: the fixture really is a valid
        // two-line chain, so the refusal below cannot be blamed on a fixture that
        // was already broken.
        let clean = NevLedger::open(dir.path()).expect("reopen the clean chain");
        let clean_records = clean.records().expect("read the clean chain");
        assert_eq!(clean_records.len(), 2);
        assert_eq!(
            clean_records[1].prev_hash(),
            clean_records[0].record_hash(),
            "line 2 chains onto line 1's seal"
        );
        assert_eq!(
            clean.replay().expect("replay the clean chain").cumulative_verified_nev_micros(),
            1_200
        );
        drop(clean);

        let original = fs::read_to_string(&path).expect("read the ledger");
        let mut lines: Vec<&str> = original.lines().collect();
        assert_eq!(lines.len(), 2, "the fixture is two lines");

        // Re-seal ONE line — its own `record_hash` is recomputed correctly, so the
        // per-line hash check passes — and leave the next line's `prev_hash`
        // pointing at the OLD seal. This is strictly stronger than editing the
        // number alone, because it defeats the check that catches a bare edit.
        let mut first: NevDurableRecord =
            serde_json::from_str(lines[0]).expect("line 1 parses on its own");
        let original_seal = first.record_hash().to_string();
        match &mut first {
            NevDurableRecord::EconomicEvent { event, .. } => event.net_nev_musd_micros = 900,
            other => panic!("line 1 is the economic_event line, got {other:?}"),
        }
        let resealed = first.computed_hash().expect("re-seal line 1");
        match &mut first {
            NevDurableRecord::EconomicEvent { record_hash, .. } => *record_hash = resealed.clone(),
            other => panic!("line 1 is the economic_event line, got {other:?}"),
        }
        assert_ne!(resealed, original_seal, "the re-seal must actually change the seal");
        assert_eq!(
            first.record_hash(),
            first.computed_hash().expect("recompute"),
            "the re-sealed line is now self-consistent, which is the point"
        );
        let resealed_line = serde_json::to_string(&first).expect("serialise the re-sealed line");
        lines[0] = &resealed_line;
        // Line 2 is left byte-for-byte alone, so its `prev_hash` is the stale one.
        assert!(
            lines[1].contains(&original_seal),
            "only one line was re-sealed; line 2 still names the old seal"
        );
        fs::write(&path, lines.join("\n") + "\n").expect("write the re-sealed chain");

        let reopened = NevLedger::open(dir.path()).expect("reopen the re-sealed chain");
        let err = reopened
            .read_records()
            .expect_err("re-sealing one line must not repair the chain");
        assert!(
            matches!(err, EconomyError::Invalid(ref m)
                if m.contains("hash-chain break at sequence 2")),
            "expected a chain break at sequence 2, got {err:?}"
        );
    }

    #[test]
    fn restart_preserves_exactly_one_event() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "restart_preserves_exactly_one_event");

        ledger
            .append_verified_event(
                &event("a", 1, 900_000),
                &outcome(REVALIDATION_STATE_CONFIRMED),
            )
            .expect("append one verified event");
        assert_eq!(
            ledger.records().expect("read before the restart").len(),
            1,
            "precondition: one line was written"
        );

        // Drop every handle: this is a restart, not a second open of the same
        // object.
        drop(ledger);
        let reopened = NevLedger::open(dir.path()).expect("reopen after restart");

        let records = reopened.records().expect("read after restart");
        assert_eq!(records.len(), 1, "one append is still one line");
        assert_eq!(records[0].sequence(), 1);
        assert_eq!(
            records[0].event().expect("an event line").net_nev_musd_micros,
            900_000
        );

        let replay = reopened.replay().expect("replay after restart");
        assert_eq!(replay.counted_event_count(), 1);
        assert_eq!(replay.seen_economic_event_ids().len(), 1);
        assert_eq!(replay.cumulative_verified_nev_micros(), 900_000);
    }

    // --------------------------------------------------------------- N7.2 ---
    //
    // Dynamic revalidation. A `RevalidationUpdate` line never rewrites history and
    // never mints an event: replay derives the LATEST state per event from the
    // sequence, so `Confirmed` followed by a revocation stops counting while the
    // id stays seen and therefore stays un-reappendable.

    #[test]
    fn confirmed_event_counts_before_reorg() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "confirmed_event_counts_before_reorg");

        ledger
            .append_verified_event(
                &event("a", 1, 700_000),
                &outcome(REVALIDATION_STATE_CONFIRMED),
            )
            .expect("append a confirmed event");

        let records = ledger.records().expect("read after the append");
        assert_eq!(records.len(), 1, "the event is one line and no update line");
        assert!(
            records[0].update().is_none(),
            "and it is an event line, not a transition"
        );

        // The behaviour under test, with no update in sight: a confirmed event
        // counts, before any reorg can be blamed for changing that.
        let replay = ledger.replay().expect("replay");
        assert_eq!(replay.counted_event_count(), 1);
        assert_eq!(replay.cumulative_verified_nev_micros(), 700_000);
        assert_eq!(replay.seen_economic_event_ids().len(), 1);
        assert_eq!(
            replay.excluded_counts().total(),
            0,
            "nothing is excluded before any transition"
        );
    }

    #[test]
    fn confirmed_then_left_canonical_stops_counting() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "confirmed_then_left_canonical_stops_counting");

        let ev = event("a", 1, 700_000);
        let id = ev.event_id().as_str().to_string();
        ledger
            .append_verified_event(&ev, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect("append a confirmed event");

        // PRECONDITION, asserted BEFORE the update exists: the event genuinely
        // counted. Without this, "it stopped counting" would also be satisfied by
        // an event that never counted at all.
        let before = ledger.replay().expect("replay before the reorg");
        assert_eq!(before.counted_event_count(), 1, "it counted first");
        assert_eq!(before.cumulative_verified_nev_micros(), 700_000);
        assert_eq!(before.excluded_counts().left_canonical_chain, 0);

        ledger
            .append_revalidation_outcome(&id, &outcome(REVALIDATION_STATE_LEFT_CANONICAL_CHAIN))
            .expect("a real reorg is recorded");

        let after = ledger.replay().expect("replay after the reorg");
        assert_eq!(after.counted_event_count(), 0, "a reorg stops it counting");
        assert_eq!(after.cumulative_verified_nev_micros(), 0);
        assert_eq!(after.excluded_counts().left_canonical_chain, 1);

        // The original line is untouched: the ledger is append-only.
        let records = ledger.records().expect("read after the reorg");
        assert_eq!(records.len(), 2, "the reorg is its own line");
        assert_eq!(records[1].sequence(), 2);
        assert_eq!(
            records[0].event().expect("line 1 is the event").revalidation_state,
            REVALIDATION_STATE_CONFIRMED,
            "history is not rewritten"
        );
        assert_eq!(
            records[1].update().expect("line 2 is the transition").new_state,
            REVALIDATION_STATE_LEFT_CANONICAL_CHAIN
        );
    }

    #[test]
    fn left_canonical_event_remains_seen() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "left_canonical_event_remains_seen");

        let ev = event("a", 1, 700_000);
        let id = ev.event_id().as_str().to_string();
        ledger
            .append_verified_event(&ev, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect("append a confirmed event");

        // PRECONDITION: the id is seen while it counts, so "still seen" below is a
        // change of state and not a permanent property.
        let before = ledger.replay().expect("replay before the reorg");
        assert!(before.seen_economic_event_ids().contains(&id));
        assert_eq!(before.counted_event_count(), 1);

        ledger
            .append_revalidation_outcome(&id, &outcome(REVALIDATION_STATE_LEFT_CANONICAL_CHAIN))
            .expect("record the reorg");

        let after = ledger.replay().expect("replay after the reorg");
        assert!(
            after.seen_economic_event_ids().contains(&id),
            "a revoked event is still seen: history is not deleted to make a reorg convenient"
        );
        assert_eq!(after.seen_economic_event_ids().len(), 1);
        assert_eq!(after.counted_event_count(), 0);

        // And because it is still seen, an evaluator rebuilt from this ledger
        // refuses it for re-recording.
        let mut evaluator = NevTierEvaluator::rebuild(&after, 0);
        assert!(evaluator.record_event(ev).is_err());
    }

    #[test]
    fn restart_preserves_revocation() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "restart_preserves_revocation");

        let ev = event("a", 1, 700_000);
        let id = ev.event_id().as_str().to_string();
        ledger
            .append_verified_event(&ev, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect("append a confirmed event");
        ledger
            .append_revalidation_outcome(&id, &outcome(REVALIDATION_STATE_LEFT_CANONICAL_CHAIN))
            .expect("record the reorg");

        // PRECONDITION before the restart: not counted, and the revocation is a
        // durable line rather than in-memory state.
        let before = ledger.replay().expect("replay before the restart");
        assert_eq!(before.counted_event_count(), 0);
        assert_eq!(ledger.records().expect("read before the restart").len(), 2);

        drop(ledger);
        let reopened = NevLedger::open(dir.path()).expect("reopen after restart");

        let records = reopened.records().expect("read after restart");
        assert_eq!(records.len(), 2, "the revocation is durable, not in memory");
        assert_eq!(records[1].sequence(), 2);
        assert_eq!(
            records[1].update().expect("line 2 is the transition").new_state,
            REVALIDATION_STATE_LEFT_CANONICAL_CHAIN
        );

        let after = reopened.replay().expect("replay after restart");
        assert_eq!(after.counted_event_count(), 0, "the revocation survives a restart");
        assert_eq!(after.cumulative_verified_nev_micros(), 0);
        assert_eq!(after.excluded_counts().left_canonical_chain, 1);
        assert!(
            after.seen_economic_event_ids().contains(&id),
            "and the revoked event is still seen"
        );
    }

    #[test]
    fn confirmed_then_needs_revalidation_stops_counting() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "confirmed_then_needs_revalidation_stops_counting");

        let ev = event("a", 1, 700_000);
        let id = ev.event_id().as_str().to_string();
        ledger
            .append_verified_event(&ev, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect("append a confirmed event");

        // PRECONDITION, asserted before the update exists: it counted first.
        let before = ledger.replay().expect("replay before the update");
        assert_eq!(before.counted_event_count(), 1);
        assert_eq!(before.cumulative_verified_nev_micros(), 700_000);

        ledger
            .append_revalidation_outcome(&id, &outcome(REVALIDATION_STATE_NEEDS_REVALIDATION))
            .expect("record that it stopped being checkable");

        let after = ledger.replay().expect("replay after the update");
        assert_eq!(after.counted_event_count(), 0);
        assert_eq!(after.cumulative_verified_nev_micros(), 0);
        assert_eq!(after.excluded_counts().needs_revalidation, 1);
        assert!(
            after.seen_economic_event_ids().contains(&id),
            "'we did not check' is not the same as 'it never happened'"
        );
        assert_eq!(
            after.per_event()[0].revalidation_state,
            REVALIDATION_STATE_NEEDS_REVALIDATION,
            "replay judges by the LATEST state, not the one the original line carried"
        );
    }

    #[test]
    fn pending_then_confirmed_counts_only_after_real_confirmation() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "pending_then_confirmed_counts_only_after_real_confirmation");

        let ev = event("a", 1, 700_000);
        let id = ev.event_id().as_str().to_string();
        ledger
            .append_verified_event(&ev, &outcome(REVALIDATION_STATE_PENDING_FINALITY))
            .expect("append a pending event");

        // PRECONDITION of the whole test, asserted first: a shallow anchor is not
        // a small grant, it is no grant. The event is on the ledger and still
        // contributes nothing.
        let pending = ledger.replay().expect("replay while pending");
        assert_eq!(pending.counted_event_count(), 0);
        assert_eq!(pending.cumulative_verified_nev_micros(), 0);
        assert_eq!(pending.excluded_counts().pending_finality, 1);
        assert_eq!(pending.seen_economic_event_ids().len(), 1);

        // Only a later REAL check can move it, and it appends its own line.
        ledger
            .append_revalidation_outcome(&id, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect("a later confirmation is recorded");
        assert_eq!(
            ledger.records().expect("read after the confirmation").len(),
            2,
            "the confirmation is a second line, not an edit of the first"
        );

        let confirmed = ledger.replay().expect("replay after the confirmation");
        assert_eq!(confirmed.counted_event_count(), 1, "counted exactly once");
        assert_eq!(confirmed.cumulative_verified_nev_micros(), 700_000);
        assert_eq!(confirmed.seen_economic_event_ids().len(), 1);
        assert_eq!(confirmed.excluded_counts().pending_finality, 0);
        assert_eq!(confirmed.excluded_counts().total(), 0);
    }

    #[test]
    fn revalidation_update_for_unknown_event_is_refused() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        ledger
            .append_verified_event(
                &event("a", 1, 700_000),
                &outcome(REVALIDATION_STATE_CONFIRMED),
            )
            .expect("append the one known event");

        // PRECONDITION, asserted before the refusal: exactly one line, and the id
        // the update will name is genuinely not among them.
        let before = ledger.records().expect("read before").len();
        assert_eq!(before, 1);
        let unknown = ExternalEventId::from_test_seed("never-recorded")
            .as_str()
            .to_string();
        assert!(
            !ledger
                .replay()
                .expect("replay before")
                .seen_economic_event_ids()
                .contains(&unknown),
            "precondition: this ledger has never recorded {unknown}"
        );

        let err = ledger
            .append_revalidation_outcome(&unknown, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect_err("an update may not name an event that does not exist");
        assert!(
            matches!(err, EconomyError::Invalid(ref m) if m.contains("never recorded")),
            "expected an unknown-event refusal, got {err:?}"
        );

        // The refusal is total: no line was gained, and no event was conjured.
        assert_eq!(
            ledger.records().expect("read after").len(),
            before,
            "the refused update gained no line"
        );
        let after = ledger.replay().expect("replay after");
        assert_eq!(after.seen_economic_event_ids().len(), 1);
        assert!(!after.seen_economic_event_ids().contains(&unknown));
        assert_eq!(after.counted_event_count(), 1, "the known event is untouched");
    }

    #[test]
    fn revalidation_update_cannot_create_a_new_event() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");

        // PRECONDITION, asserted first: the ledger is COMPLETELY empty — no events,
        // no lines, no anchor. If an update can conjure an event it is unmistakable
        // here, where there is nothing it could possibly be updating.
        assert_empty(&ledger, "revalidation_update_cannot_create_a_new_event");
        assert!(ledger.head_anchor().expect("head anchor").is_none());

        let id = ExternalEventId::from_test_seed("conjured").as_str().to_string();
        // Every state is tried, `confirmed` last: none may mint an event, and
        // `confirmed` is the dangerous one because it is the only state that counts.
        for state in [
            REVALIDATION_STATE_LEFT_CANONICAL_CHAIN,
            REVALIDATION_STATE_NEEDS_REVALIDATION,
            REVALIDATION_STATE_PENDING_FINALITY,
            REVALIDATION_STATE_CONFIRMED,
        ] {
            let err = ledger
                .append_revalidation_outcome(&id, &outcome(state))
                .expect_err("an update never mints an event");
            assert!(
                matches!(err, EconomyError::Invalid(ref m)
                    if m.contains("never recorded") && m.contains("not create one")),
                "{state}: expected an unknown-event refusal, got {err:?}"
            );
            assert_eq!(
                ledger.records().expect("read after").len(),
                0,
                "{state}: the refused update wrote no line"
            );
        }

        let replay = ledger.replay().expect("replay");
        assert!(
            replay.seen_economic_event_ids().is_empty(),
            "no id was ever seen, so nothing can be counted, revoked or replayed"
        );
        assert_eq!(replay.counted_event_count(), 0);
        assert_eq!(replay.cumulative_verified_nev_micros(), 0);
        assert_eq!(replay.per_event().len(), 0);
    }

    #[test]
    fn a_duplicate_revalidation_update_is_explicitly_refused() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "a_duplicate_revalidation_update_is_explicitly_refused");

        let ev = event("a", 1, 700_000);
        let id = ev.event_id().as_str().to_string();
        ledger
            .append_verified_event(&ev, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect("append a confirmed event");
        ledger
            .append_revalidation_outcome(&id, &outcome(REVALIDATION_STATE_LEFT_CANONICAL_CHAIN))
            .expect("record the reorg");

        // PRECONDITION of the refusal: two lines, and the current state really is
        // already the one the duplicate would write.
        let before_records = ledger.records().expect("read before");
        assert_eq!(before_records.len(), 2);
        assert_eq!(
            current_revalidation_state(&before_records, &id),
            Some(REVALIDATION_STATE_LEFT_CANONICAL_CHAIN),
            "precondition: the current state is already left_canonical_chain"
        );

        let err = ledger
            .append_revalidation_outcome(&id, &outcome(REVALIDATION_STATE_LEFT_CANONICAL_CHAIN))
            .expect_err("the same state twice is refused, not appended twice");
        assert!(
            matches!(err, EconomyError::Conflict(ref m) if m.contains("duplicate revalidation update")),
            "expected a duplicate-update refusal, got {err:?}"
        );

        assert_eq!(
            ledger.records().expect("read after").len(),
            before_records.len(),
            "the refused duplicate gained no line"
        );
        assert_eq!(ledger.replay().expect("replay").counted_event_count(), 0);
    }

    #[test]
    fn a_revocation_can_be_restored_only_by_a_later_real_confirmation() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open NEV ledger");
        assert_empty(&ledger, "a_revocation_can_be_restored_only_by_a_later_real_confirmation");

        let ev = event("a", 1, 700_000);
        let id = ev.event_id().as_str().to_string();

        ledger
            .append_verified_event(&ev, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect("1. confirmed");
        let first = ledger.replay().expect("replay 1");
        assert_eq!(first.counted_event_count(), 1, "precondition: it counted");
        assert_eq!(first.cumulative_verified_nev_micros(), 700_000);
        assert_eq!(ledger.records().expect("read 1").len(), 1);

        ledger
            .append_revalidation_outcome(&id, &outcome(REVALIDATION_STATE_LEFT_CANONICAL_CHAIN))
            .expect("2. reorg");
        let revoked = ledger.replay().expect("replay 2");
        assert_eq!(revoked.counted_event_count(), 0, "the reorg is what stopped it");
        assert_eq!(revoked.cumulative_verified_nev_micros(), 0);

        // Nothing else changes on the ledger between here and the third append, so
        // counting can only return because of it.
        ledger
            .append_revalidation_outcome(&id, &outcome(REVALIDATION_STATE_CONFIRMED))
            .expect("3. re-confirmed");
        let restored = ledger.replay().expect("replay 3");
        assert_eq!(restored.counted_event_count(), 1, "counting returns only now");
        assert_eq!(restored.cumulative_verified_nev_micros(), 700_000);
        assert_eq!(restored.excluded_counts().total(), 0);

        // Each transition is its own line: nothing was rewritten.
        let records = ledger.records().expect("read 3");
        assert_eq!(records.len(), 3, "three appends, three lines");
        assert_eq!(records[0].sequence(), 1);
        assert_eq!(records[1].sequence(), 2);
        assert_eq!(records[2].sequence(), 3);
        assert!(records[0].event().is_some(), "line 1 is the event");
        assert_eq!(
            records[0].event().expect("line 1").revalidation_state,
            REVALIDATION_STATE_CONFIRMED,
            "history still says what was true at the time"
        );
        assert_eq!(
            records[1].update().expect("line 2 is the reorg").new_state,
            REVALIDATION_STATE_LEFT_CANONICAL_CHAIN
        );
        assert_eq!(
            records[2].update().expect("line 3 is the re-confirmation").new_state,
            REVALIDATION_STATE_CONFIRMED
        );
        assert_eq!(
            restored.seen_economic_event_ids().len(),
            1,
            "and the whole history is still one event, counted once"
        );
    }

    // ---------------------------------------------------------------- N8 ----

    fn evidence(
        cycles_completed: u64,
        thermal_stops: u64,
        day_index: u64,
    ) -> NevObservationEvidence {
        NevObservationEvidence {
            cycles_attempted: cycles_completed + thermal_stops,
            cycles_completed,
            classes_observed: vec![OpportunityClass::Arbitrage],
            thermal_stops,
            budget_stops: 0,
            started_at_unix: day_index * DAY,
            completed_at_unix: (day_index + 1) * DAY,
        }
    }

    /// Appends `count` consecutive COMPLETE days ending the day before
    /// `now_unix`, going through the production clock-derived entry point.
    fn observed_days_via_runtime(
        ledger: &NevLedger,
        now_unix: u64,
        count: u64,
    ) -> u64 {
        let first_completed = now_unix / DAY - count;
        for offset in 0..count {
            let day_end = (first_completed + offset + 1) * DAY;
            ledger
                .complete_previous_utc_day(day_end, evidence(1, 0, first_completed + offset))
                .expect("complete a day");
        }
        first_completed
    }

    #[test]
    fn a_completed_day_is_recorded_from_the_clock_not_a_named_day() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open");
        // now is mid-day 100; the last COMPLETE day is 99.
        let now = 100 * DAY + 3_600;
        let checkpoint = ledger
            .complete_previous_utc_day(now, evidence(1, 0, 99))
            .expect("complete previous day");
        assert_eq!(checkpoint.day_index, 99, "the current partial day is never covered");
        assert!(checkpoint.grants_coverage());

        let replay = ledger.replay().expect("replay");
        assert_eq!(replay.observed_utc_days().len(), 1);
        assert!(replay.observed_utc_days().contains(&99));
    }

    #[test]
    fn a_zero_event_completed_day_counts_as_observed_coverage() {
        // No economic events at all in this ledger — only a coverage checkpoint.
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open");
        ledger
            .complete_previous_utc_day(50 * DAY, evidence(1, 0, 49))
            .expect("complete a day");
        let replay = ledger.replay().expect("replay");
        assert_eq!(
            replay.observed_utc_days().len(),
            1,
            "a silent day is still an observed day"
        );
        assert_eq!(replay.counted_event_count(), 0);
    }

    #[test]
    fn a_day_with_no_runtime_checkpoint_does_not_count() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open");
        // An event on a day is NOT coverage for that day.
        ledger
            .append_verified_event(
                &event("a", 10, 900_000),
                &outcome(REVALIDATION_STATE_CONFIRMED),
            )
            .expect("append event");
        let replay = ledger.replay().expect("replay");
        assert!(
            replay.observed_utc_days().is_empty(),
            "recording an event must not record observation coverage"
        );
    }

    #[test]
    fn a_thermal_abort_before_completion_does_not_fake_a_full_day() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open");
        let checkpoint = ledger
            .complete_previous_utc_day(60 * DAY, evidence(0, 3, 59))
            .expect("record the attempted day anyway");
        assert_eq!(checkpoint.completeness, ObservationCompleteness::PartialThermalAbort);
        assert!(!checkpoint.grants_coverage());

        let replay = ledger.replay().expect("replay");
        assert!(
            replay.observed_utc_days().is_empty(),
            "a day that thermally aborted before completing a cycle is not full coverage"
        );
        assert_eq!(replay.non_covered_days(), &[59], "but it stays visible as an audit fact");
    }

    #[test]
    fn a_day_the_runtime_never_ran_is_not_coverage() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open");
        let checkpoint = ledger
            .complete_previous_utc_day(70 * DAY, evidence(0, 0, 69))
            .expect("record");
        assert_eq!(checkpoint.completeness, ObservationCompleteness::NotStarted);
        assert!(!checkpoint.grants_coverage());
    }

    #[test]
    fn observation_coverage_survives_restart() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open");
        // A counted event, so the assertion below is about coverage surviving a
        // restart and not about the empty-ledger path. `now` must be expressed on
        // the SAME clock as `T0`: `evaluate` filters on `timestamp <= now_unix`,
        // so a `now` of `100 * DAY` against a `T0` of 1.7e9 would put every
        // seeded event in the future and silently drop them.
        ledger
            .append_verified_event(
                &event("e", 95, 500),
                &outcome(REVALIDATION_STATE_CONFIRMED),
            )
            .expect("append a counted event");
        let now = T0 + 100 * DAY;
        observed_days_via_runtime(&ledger, now, 30);
        drop(ledger);

        let reopened = NevLedger::open(dir.path()).expect("reopen after restart");
        let replay = reopened.replay().expect("replay after restart");
        assert_eq!(
            replay.observed_utc_days().len(),
            30,
            "30 durable observed days are still 30 after a restart, not 0"
        );

        let mut evaluator = NevTierEvaluator::rebuild(&replay, 0);
        let status = evaluator.evaluate(now);
        // A counted event is present, so reaching here means the coverage gate was
        // genuinely satisfied rather than the empty-ledger path short-circuiting.
        assert_eq!(status.cumulative_verified_nev_micros, 500);
        assert!(
            !status.tier_qualification_notes.iter().any(|n| n.contains("observation")),
            "coverage survived, so no coverage complaint: {:?}",
            status.tier_qualification_notes
        );
    }

    #[test]
    fn twenty_nine_durable_days_do_not_unlock_the_tier_and_thirty_do() {
        // Every one of these assertions must be read against the COVERAGE GATE, not
        // against the empty-ledger short-circuit. `evaluate` returns early with
        // "no verified NEV events exist" when there are zero counted events, which
        // would make a coverage assertion pass for the wrong reason — or fail,
        // depending on which way it was written. So each case seeds one counted
        // positive event first.
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open");
        let now = T0 + 100 * DAY;
        ledger
            .append_verified_event(
                &event("e", 95, 5_000_000),
                &outcome(REVALIDATION_STATE_CONFIRMED),
            )
            .expect("append a counted event");

        // 29 durable days: coverage must still be reported as missing.
        observed_days_via_runtime(&ledger, now, 29);
        let replay = ledger.replay().expect("replay");
        assert_eq!(replay.observed_utc_days().len(), 29);
        let mut evaluator = NevTierEvaluator::rebuild(&replay, 0);
        let status = evaluator.evaluate(now);
        assert!(
            status.tier_qualification_notes.iter().any(|n| n.contains("observation")),
            "29 days must still report missing coverage: {:?}",
            status.tier_qualification_notes
        );

        // Exactly one more durable day reaches 30. Only the previously unrecorded
        // day is appended: re-completing a day already on the ledger is refused.
        let thirtieth = now / DAY - 30;
        ledger
            .complete_previous_utc_day((thirtieth + 1) * DAY, evidence(1, 0, thirtieth))
            .expect("complete the 30th day");
        let replay = ledger.replay().expect("replay");
        assert_eq!(replay.observed_utc_days().len(), 30);
        let mut evaluator = NevTierEvaluator::rebuild(&replay, 0);
        let status = evaluator.evaluate(now);
        assert!(
            !status
                .tier_qualification_notes
                .iter()
                .any(|n| n.contains("observation")),
            "30 durable days satisfy the coverage gate: {:?}",
            status.tier_qualification_notes
        );
    }

    #[test]
    fn a_five_day_gap_in_durable_coverage_still_blocks_the_tier() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open");
        let now = T0 + 200 * DAY;
        // A counted event, so the coverage gate is what blocks — not the
        // empty-ledger short-circuit.
        ledger
            .append_verified_event(
                &event("e", 195, 5_000_000),
                &outcome(REVALIDATION_STATE_CONFIRMED),
            )
            .expect("append a counted event");
        // 25 completed days; the last five are never completed.
        let first_day = now / DAY - 30;
        for offset in 0..25 {
            let day_index = first_day + offset;
            ledger
                .complete_previous_utc_day((day_index + 1) * DAY, evidence(1, 0, day_index))
                .expect("complete");
        }
        let replay = ledger.replay().expect("replay");
        assert_eq!(replay.observed_utc_days().len(), 25);
        let mut evaluator = NevTierEvaluator::rebuild(&replay, 0);
        let status = evaluator.evaluate(now);
        assert!(
            status.tier_qualification_notes.iter().any(|n| n.contains("observation")),
            "a five-day gap must block promotion: {:?}",
            status.tier_qualification_notes
        );
    }

    #[test]
    fn a_day_cannot_be_completed_twice() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open");
        ledger
            .complete_previous_utc_day(100 * DAY, evidence(1, 0, 99))
            .expect("first completion");
        let err = ledger
            .complete_previous_utc_day(100 * DAY, evidence(9, 0, 99))
            .expect_err("a day is completed once");
        assert!(
            matches!(err, EconomyError::Conflict(ref m) if m.contains("completed once")),
            "expected a durable duplicate-day refusal, got {err:?}"
        );
    }

    #[test]
    fn a_tampered_observation_checkpoint_is_refused_on_read() {
        let dir = tempdir().expect("tempdir");
        let ledger = NevLedger::open(dir.path()).expect("open");
        ledger
            .complete_previous_utc_day(100 * DAY, evidence(1, 0, 99))
            .expect("complete");
        let path = ledger.ledger_path();
        drop(ledger);

        let text = fs::read_to_string(&path).expect("read");
        // Claim a day that was thermally aborted actually completed.
        let tampered = text.replacen("\"cycles_completed\":1", "\"cycles_completed\":0", 1);
        assert_ne!(text, tampered);
        fs::write(&path, tampered).expect("write tampered");

        let reopened = NevLedger::open(dir.path()).expect("reopen");
        let err = reopened
            .records()
            .expect_err("a checkpoint that no longer matches its own hash must be refused");
        assert!(
            matches!(err, EconomyError::Invalid(ref m) if m.contains("hash")),
            "expected a refusal, got {err:?}"
        );
    }

    #[test]
    fn a_checkpoint_hash_changes_when_any_bound_field_changes() {
        let base = NevObservationCheckpoint::from_completed_day(42, evidence(3, 0, 42))
            .expect("base checkpoint");
        let variants = vec![
            NevObservationCheckpoint::from_completed_day(43, evidence(3, 0, 42)).unwrap(),
            NevObservationCheckpoint::from_completed_day(42, evidence(4, 0, 42)).unwrap(),
            NevObservationCheckpoint::from_completed_day(42, evidence(3, 1, 42)).unwrap(),
            NevObservationCheckpoint::from_completed_day(42, evidence(0, 0, 42)).unwrap(),
        ];
        for v in &variants {
            assert_ne!(
                v.checkpoint_hash, base.checkpoint_hash,
                "a changed bound field must change the checkpoint hash"
            );
            assert!(v.verify_checkpoint_hash().is_ok());
        }
        assert!(base.verify_checkpoint_hash().is_ok());
    }

    #[test]
    fn the_observation_checkpoint_domain_is_distinct() {
        // The domain is what stops a checkpoint hash colliding with any other
        // preimage in the crate.
        assert!(NEV_OBSERVATION_CHECKPOINT_DOMAIN.ends_with("NEV-OBSERVATION-CHECKPOINT/V1"));
        assert_ne!(
            NEV_OBSERVATION_CHECKPOINT_DOMAIN,
            crate::event_id::SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN
        );
        assert_ne!(NEV_OBSERVATION_CHECKPOINT_DOMAIN, "MYCELIUM-ECONOMY/NEV-COVERAGE-CHECKPOINT/V1");
    }
}
