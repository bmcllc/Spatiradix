//! NEV0–NEV4 Tiered Evaluator.
//!
//! # The NEV Tier Hierarchy
//!
//! Net External Value (NEV) represents external, net-of-costs, authenticated,
//! and complete economic value created across the system boundary:
//!
//! ```text
//! NEV = ΣVerifiedInflows − ΣVerifiedOutflows − ΣVerifiedExternalCosts
//! ```
//!
//! This module formalizes the verification and progression through the six
//! economic tiers:
//!
//! * **PreNev0**: Initial state. Zero positive verified net external value.
//! * **Nev0**: The first positive verified NEV event ($> 0$, even +0.01 USDC).
//!   Proves non-zero external value creation is possible.
//! * **Nev1**: Initial repeatability. Rolling 30-day average $\ge 10\text{ mUSD/day}$,
//!   with $\ge 5$ independent positive events across $\ge 3$ distinct calendar days.
//! * **Nev2**: Robust positive economics. Rolling 30-day average $\ge 100\text{ mUSD/day}$.
//!   Evaluates cost/inflow ratio, settlement completeness, and distribution tails.
//! * **Nev3**: Self-funding operational scale. Rolling 30-day average $\ge 500\text{ mUSD/day}$.
//!   External routine operational costs are fully covered by Verified NEV, and
//!   reinvestment is strictly bounded by Verified NEV (never synthetic PnL).
//! * **Nev4**: Multi-class diversified scale. Rolling 30-day average $\ge 2,000\text{ mUSD/day}$,
//!   with at least 2 distinct `REAL` OpportunityClasses contributing. Evaluates
//!   class concentration ($\max(\text{NEV}_{\text{class}}) / \text{total NEV}$).
//!
//! # Revocability Principle
//!
//! Tiers are **not irrevocable badges**.
//! * `current_verified_tier` reflects the rolling window's current qualification.
//!   If economic activity drops below tier thresholds, `current_verified_tier`
//!   downgrades accordingly.
//! * `highest_ever_verified_tier` preserves the historical watermark achieved.
//! * Only verified settlement-derived events (originating from complete
//!   settlements and trusted valuations) can satisfy these evaluations. No
//!   synthetic, mock, or internal issuance (MYC, smUSD) can promote any tier.
//!
//! # Observation Coverage Semantics
//!
//! NEV1 and above require proof of *continuous observation*, not merely proof
//! of value. The rules are exact and are not negotiable at the call site:
//!
//! * **A UTC day is `timestamp_unix / SECONDS_PER_DAY`** (integer division over
//!   86,400 s). There is no local time, no offset, and no DST anywhere in this
//!   module.
//! * **The eligible window is the last 30 COMPLETE UTC calendar days strictly
//!   before the current incomplete day**, i.e. the half-open interval
//!   `[floor_to_utc_midnight(now_unix) - 30*SECONDS_PER_DAY,
//!   floor_to_utc_midnight(now_unix))`. The current partial day is never inside
//!   the window. A day that started one second ago has not earned its place yet,
//!   and recording an event into it changes nothing about the window.
//! * **NEV1–NEV4 additionally require that every one of those same 30 days is
//!   present in `observed_utc_days`.** All 30, no gaps, no substitutes. One
//!   unobserved day holds the evaluator at NEV0 no matter how large the
//!   verified net, because an unobserved day is an unknown day, not a zero day.
//! * **Recording a NEV event does NOT imply the day was observed, and must
//!   never.** `record_event` appends value; it never marks a day observed. A day
//!   on which a settlement happened to be verified is still a day about which
//!   nothing is known for the remaining hours, and a day with no events at all
//!   is *not* thereby observed — it is merely silent. Coverage is a separate,
//!   explicit act, via durable runtime checkpoints recorded by
//!   [`crate::nev_durable::NevLedger::complete_previous_utc_day`] and rebuilt
//!   through [`NevTierEvaluator::rebuild`].
//!
//! This is the same honesty `ObservedThermal` insists on in `discovery`: an
//! unmeasured reading is `None`, and `None` is never quietly promoted to a pass.
//! An unobserved day is not an observed day.

use crate::discovery::OpportunityClass;
use crate::event_id::{EventIdError, ExternalEventId, SettlementEconomicFact};
use crate::settlement::ComparableVerifiedSettlement;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Day duration in seconds.
pub const SECONDS_PER_DAY: u64 = 86_400;

/// Rolling evaluation window in days.
pub const EVALUATION_WINDOW_DAYS: usize = 30;

/// Tier threshold in micro-USD (mUSD) per day: 10 mUSD/day = 10,000 micros.
pub const NEV1_DAILY_AVG_MICROS: i64 = 10_000;

/// Tier threshold in micro-USD per day: 100 mUSD/day = 100,000 micros.
pub const NEV2_DAILY_AVG_MICROS: i64 = 100_000;

/// Tier threshold in micro-USD per day: 500 mUSD/day = 500,000 micros.
pub const NEV3_DAILY_AVG_MICROS: i64 = 500_000;

/// Tier threshold in micro-USD per day: 2,000 mUSD/day = 2,000,000 micros.
pub const NEV4_DAILY_AVG_MICROS: i64 = 2_000_000;

/// Capability proving an OpportunityClass is proven REAL with production market counterparties.
///
/// Cannot be forged from a raw string or unverified enum variant.
/// Currently only Arbitrage is an implemented REAL class in production.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RealOpportunityClass(OpportunityClass);

impl RealOpportunityClass {
    /// The canonical Arbitrage real opportunity class.
    pub fn arbitrage() -> Self {
        Self(OpportunityClass::Arbitrage)
    }

    /// Access the underlying class enum.
    pub fn class(&self) -> OpportunityClass {
        self.0
    }

    /// Test-only capability constructor to test multi-class NEV4 requirements.
    #[cfg(test)]
    pub(crate) fn test_second_real_class() -> Self {
        Self(OpportunityClass::NetworkFee)
    }
}

/// The six formalized tiers of Net External Value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NevTier {
    PreNev0,
    Nev0,
    Nev1,
    Nev2,
    Nev3,
    Nev4,
}

impl NevTier {
    pub const ALL: [NevTier; 6] = [
        NevTier::PreNev0,
        NevTier::Nev0,
        NevTier::Nev1,
        NevTier::Nev2,
        NevTier::Nev3,
        NevTier::Nev4,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PreNev0 => "pre_nev0",
            Self::Nev0 => "nev0",
            Self::Nev1 => "nev1",
            Self::Nev2 => "nev2",
            Self::Nev3 => "nev3",
            Self::Nev4 => "nev4",
        }
    }
}

impl std::fmt::Display for NevTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An authenticated, chain-confirmed, and completely settled NEV event.
///
/// Private fields with no `Deserialize`: cannot be constructed by arbitrary callers
/// or forged from JSON payloads.
///
/// The only production constructor is
/// [`VerifiedNevEvent::from_comparable_settlement`], which consumes one authority
/// type and derives both the identity and every numeric field from the priced
/// settlement. There is deliberately no constructor that accepts caller-chosen
/// scalars, and — since P6.N6 — none that accepts a caller-chosen *identity*
/// either: a NEV event is an authenticated fact about a completed settlement,
/// not a report a caller may fill in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedNevEvent {
    event_id: ExternalEventId,
    timestamp_unix: u64,
    class: OpportunityClass,
    real_capability: Option<RealOpportunityClass>,
    gross_inflow_musd_micros: u64,
    external_cost_musd_micros: u64,
    native_gas_cost_musd_micros: u64,
    net_nev_musd_micros: i64,
}

impl VerifiedNevEvent {
    /// Constructs a verified NEV event from a priced `ComparableVerifiedSettlement`.
    ///
    /// # P6.N6 — the economic identity is DERIVED here, never passed in
    ///
    /// This constructor used to take an `ExternalEventId` as its first argument.
    /// That was the double-counting hole this milestone closes: the identity of
    /// an economic event was a *caller's choice*, so the same settlement could
    /// be recorded under two different ids by two call sites — or by one call
    /// site run twice — and NEV would add it up twice.
    /// [`NevTierEvaluator::record_event`]'s `seen_event_ids` set only knows it has
    /// already seen *one* id; it cannot know that the two ids under which it saw
    /// one operation are one operation.
    ///
    /// The id is now [`ExternalEventId::settlement_economic`], derived from facts
    /// the settlement itself carries: its operation id, its block anchor, the
    /// canonical external event id of every leg, and the canonical external event
    /// id of every external cost. There is no parameter through which a caller
    /// could supply, override or reuse one, and none is added back.
    ///
    /// Note what is deliberately **not** consulted for the identity: the price,
    /// the policy hash, the native cost in micro-USD, the token net delta and the
    /// comparable net value. A valuation is a *reading* of an operation, not the
    /// operation. The same on-chain operation priced under two policies, or
    /// valued at two different signed price observations, is one economic event
    /// with one identity — which is exactly what stops it being counted twice.
    /// That omission is enforced inside the preimage, not merely by omission here.
    ///
    /// # No fallback identity
    ///
    /// This returns a `Result` because the derivation can fail, and a failure
    /// means **no NEV event at all**:
    ///
    /// * a leg whose `event_id()` is `None` — a transfer the chain enumerated
    ///   but this node never named — has no canonical identity to bind. The
    ///   derivation **fails**. It does not substitute a placeholder, a zero, or
    ///   the leg's index: any of those would give a settlement whose leg set is
    ///   incomplete a *stable* id, and a stable id over an incomplete fact is
    ///   precisely how one operation acquires two identities and is counted
    ///   twice. (The leg index appears only in the error message, where it
    ///   diagnoses; it never enters a digest.)
    /// * an anchor block hash that will not parse and validate fails for the
    ///   same reason `settlement_digest` refuses one.
    ///
    /// A settlement whose economic identity cannot be derived yields no NEV
    /// event at all. That is the intended outcome, not a degraded one: an event
    /// carrying a synthesised id is exactly the record this milestone exists to
    /// make impossible, and a missing event is recoverable in a way a
    /// double-counted total is not.
    ///
    /// `class` is the caller's to state, and only `class`: REAL-ness is decided
    /// here, from the class, and never by the caller.
    pub fn from_comparable_settlement(
        settlement: &ComparableVerifiedSettlement,
        class: OpportunityClass,
    ) -> Result<Self, EventIdError> {
        let event_id = ExternalEventId::settlement_economic(&settlement_economic_fact(settlement)?)?;
        let net = settlement.comparable_net_value_micros();
        let mut gross = 0u64;
        let mut ext_cost = 0u64;
        for leg in settlement.legs() {
            match leg.direction() {
                crate::boundary::BoundaryDirection::ExternalToControlled => {
                    gross = gross.saturating_add(leg.amount_micros())
                }
                crate::boundary::BoundaryDirection::ControlledToExternal => {
                    ext_cost = ext_cost.saturating_add(leg.amount_micros())
                }
            }
        }
        let gas_cost = settlement.native_cost_musd() as u64;
        let real_capability = if class == OpportunityClass::Arbitrage {
            Some(RealOpportunityClass::arbitrage())
        } else {
            None
        };

        Ok(Self {
            event_id,
            timestamp_unix: settlement.anchor().block_timestamp_unix(),
            class,
            real_capability,
            gross_inflow_musd_micros: gross,
            external_cost_musd_micros: ext_cost,
            native_gas_cost_musd_micros: gas_cost,
            net_nev_musd_micros: net,
        })
    }

    /// Rehydrates an event from the durable NEV ledger.
    ///
    /// `pub(crate)` on purpose. This is NOT a scalar constructor on the public
    /// API and it is not a way to mint an event from loose numbers: its only
    /// input is a [`crate::nev_durable::NevEconomicEventRecord`], and that type's
    /// only constructor takes a `&VerifiedNevEvent`. So the chain still runs
    /// settlement -> authority-typed event -> durable record; this step only walks
    /// it back. The identity is re-read through
    /// [`ExternalEventId::from_canonical_text`], which validates the digest
    /// spelling rather than trusting the stored text.
    pub(crate) fn from_durable_record(
        record: &crate::nev_durable::NevEconomicEventRecord,
    ) -> Result<Self, EventIdError> {
        let event_id = ExternalEventId::from_canonical_text(&record.economic_event_id)?;
        let real_capability = if record.class == OpportunityClass::Arbitrage {
            Some(RealOpportunityClass::arbitrage())
        } else {
            None
        };
        Ok(Self {
            event_id,
            timestamp_unix: record.anchor_block_timestamp_unix,
            class: record.class,
            real_capability,
            gross_inflow_musd_micros: record.gross_inflow_musd_micros,
            external_cost_musd_micros: record.external_cost_musd_micros,
            native_gas_cost_musd_micros: record.native_gas_cost_musd_micros,
            net_nev_musd_micros: record.net_nev_musd_micros,
        })
    }

    /// Internal test-only constructor with explicit invariants. Strictly crate-internal in test builds.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_test(
        event_id: ExternalEventId,
        timestamp_unix: u64,
        class: OpportunityClass,
        real_capability: Option<RealOpportunityClass>,
        gross_inflow_musd_micros: u64,
        external_cost_musd_micros: u64,
        native_gas_cost_musd_micros: u64,
        net_nev_musd_micros: i64,
    ) -> Self {
        Self {
            event_id,
            timestamp_unix,
            class,
            real_capability,
            gross_inflow_musd_micros,
            external_cost_musd_micros,
            native_gas_cost_musd_micros,
            net_nev_musd_micros,
        }
    }

    pub fn event_id(&self) -> &ExternalEventId {
        &self.event_id
    }

    pub fn timestamp_unix(&self) -> u64 {
        self.timestamp_unix
    }

    pub fn class(&self) -> OpportunityClass {
        self.class
    }

    /// The REAL capability carried by this event, if any.
    ///
    /// This is the only REAL-ness accessor. There is deliberately no
    /// `is_real_class() -> bool`: a boolean lets a caller reason about
    /// "is this REAL?" and then act on a class label, whereas the capability is
    /// the thing that actually proves it. `None` means the event carries no
    /// REAL capability, whatever its `class` says.
    pub fn real_capability(&self) -> Option<RealOpportunityClass> {
        self.real_capability
    }

    pub fn gross_inflow_musd_micros(&self) -> u64 {
        self.gross_inflow_musd_micros
    }

    pub fn external_cost_musd_micros(&self) -> u64 {
        self.external_cost_musd_micros
    }

    pub fn native_gas_cost_musd_micros(&self) -> u64 {
        self.native_gas_cost_musd_micros
    }

    pub fn net_nev_musd_micros(&self) -> i64 {
        self.net_nev_musd_micros
    }
}

/// Builds the [`SettlementEconomicFact`] for a priced settlement, out of that
/// settlement's own authenticated facts.
///
/// This is where "the caller may not choose the identity" is enforced in
/// practice. The only inputs are [`ComparableVerifiedSettlement`]'s own
/// accessors — its block anchor, its operation id, and the canonical external
/// event ids its legs and external costs already carry — so there is no value
/// here that a caller could have chosen instead of the truth.
///
/// The one way it refuses is by having nothing canonical to bind: a leg with no
/// `event_id()` names no external fact, so the operation's leg set cannot be
/// named and the settlement gets no economic identity. The leg's index and
/// state appear in the message as a diagnosis and nowhere else.
fn settlement_economic_fact(
    settlement: &ComparableVerifiedSettlement,
) -> Result<SettlementEconomicFact, EventIdError> {
    let anchor = settlement.anchor();
    let leg_event_ids: Vec<&ExternalEventId> = settlement
        .legs()
        .iter()
        .enumerate()
        .map(|(index, leg)| {
            leg.event_id().ok_or_else(|| {
                EventIdError::UnusableSettlementEconomicFact(format!(
                    "settlement {} leg {index} ({}) carries no canonical external event id, \
                     so the operation's economic identity cannot be derived and no NEV \
                     event is produced for this settlement",
                    settlement.operation_id().as_str(),
                    leg.state().as_str(),
                ))
            })
        })
        .collect::<std::result::Result<Vec<_>, EventIdError>>()?;
    let cost_event_ids: Vec<&ExternalEventId> = settlement
        .external_costs()
        .iter()
        .map(|cost| cost.event_id())
        .collect();
    SettlementEconomicFact::from_parts(
        anchor.chain_id(),
        anchor.block_number(),
        anchor.block_hash(),
        settlement.operation_id().as_str(),
        &leg_event_ids,
        &cost_event_ids,
    )
}

/// Telemetry and statistics of a rolling 30-day evaluation window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollingWindowMetrics {
    /// Start timestamp of the window (now - 30 days).
    pub window_start_unix: u64,
    /// End timestamp of the window (now).
    pub window_end_unix: u64,
    /// Total number of verified NEV events in the window.
    pub total_events: usize,
    /// Number of distinct calendar days with positive events in the window.
    pub distinct_positive_days: usize,
    /// Sum of all net NEV in the window in micro-USD (signed).
    pub total_net_nev_micros: i64,
    /// 30-day daily average net NEV in micro-USD/day (signed).
    pub daily_average_nev_micros: i64,
    /// Total external costs (external + gas) in micro-USD.
    pub total_costs_micros: u64,
    /// Total gross external inflows in micro-USD.
    pub total_gross_inflows_micros: u64,
    /// Cost to inflow ratio in basis points (10000 = 100%).
    pub cost_inflow_ratio_bps: u64,
    /// Net NEV breakdown by opportunity class (signed).
    pub nev_by_class: BTreeMap<OpportunityClass, i64>,
    /// Class concentration ratio in basis points (max_class / total_net).
    pub class_concentration_bps: u64,
    /// Number of distinct REAL contributing classes with net NEV > 0.
    pub active_real_classes_count: usize,
    /// Median event net NEV in micro-USD.
    pub median_event_nev_micros: i64,
    /// 10th percentile event net NEV (lower tail) in micro-USD.
    pub p10_event_nev_micros: i64,
}

/// Status of the NEV tiered economic evaluator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NevTierStatus {
    /// Currently qualified tier based on active rolling evaluation window.
    pub current_verified_tier: NevTier,
    /// Highest tier ever achieved historically (monotonic watermark).
    pub highest_ever_verified_tier: NevTier,
    /// Total historical verified NEV accumulated across all time (signed micro-USD).
    pub cumulative_verified_nev_micros: i64,
    /// Net verified NEV inside the current 30-day rolling window (signed micro-USD).
    pub current_window_net_nev_micros: i64,
    /// Total count of all historical verified NEV events.
    pub cumulative_event_count: u64,
    /// Whether routine external operating costs are fully funded by net NEV.
    pub operational_self_funding_healthy: bool,
    /// Total span of observed history in seconds.
    pub observation_history_span_secs: u64,
    /// Active rolling window metrics (None if no window is active).
    pub window_metrics: Option<RollingWindowMetrics>,
    /// Reasons for current tier qualification or non-promotion.
    pub tier_qualification_notes: Vec<String>,
}

/// Evaluator that determines NEV tiers deterministically without mocks.
///
/// # Observation coverage is a separate, explicit act
///
/// The evaluator tracks two independent histories:
///
/// * `events` — verified NEV *value*. Appended by [`Self::record_event`].
/// * `observed_utc_days` — verified *coverage*. Appended only by
///   [`Self::apply_durable_coverage`] and [`Self::rebuild`], in production, and by
///   [`Self::record_day_observed`] in test builds only. The public arbitrary-day
///   entry point was the hole P6.N8 closed: a caller could assert coverage for any
///   day it liked — including days long past — and so manufacture the 30-day
///   maturity the tier gate demands, without anything having run.
///
///
/// [`Self::record_event`] never inserts into `observed_utc_days`, and must never
/// do so. A verified settlement on day D says that value existed on day D; it says
/// nothing about the rest of day D, and nothing at all about the days with no
/// settlement. Treating ingestion as observation would make an unobserved gap
/// indistinguishable from a quiet zero, which is exactly the failure mode the
/// coverage gate exists to prevent. An unmeasured day is not an observed day —
/// the same rule `ObservedThermal` applies to an absent temperature reading.
///
/// A UTC day is `timestamp_unix / SECONDS_PER_DAY`. At `now_unix` the eligible
/// window is the half-open interval
/// `[floor_to_utc_midnight(now_unix) - 30*SECONDS_PER_DAY, floor_to_utc_midnight(now_unix))`
/// — the last 30 **complete** UTC calendar days, excluding the current partial
/// day — and NEV1–NEV4 require all 30 of those same day indices to be present in
/// `observed_utc_days`.
pub struct NevTierEvaluator {
    /// All historical events in chronological order.
    events: Vec<VerifiedNevEvent>,
    /// Set of seen canonical event IDs to prevent double counting.
    seen_event_ids: BTreeSet<ExternalEventId>,
    /// Earliest recorded event timestamp.
    first_event_unix: Option<u64>,
    /// Highest tier ever validated.
    highest_ever: NevTier,
    /// Cumulative external routine operating cost to compare against for NEV3.
    monthly_operating_cost_micros: i64,
    /// Set of distinct UTC calendar days (`timestamp_unix / SECONDS_PER_DAY`)
    /// that were explicitly observed.
    ///
    /// Since P6.N8 populated only by [`Self::rebuild`], from durable runtime
    /// checkpoints written by
    /// [`crate::nev_durable::NevLedger::complete_previous_utc_day`]. Recording an
    /// event must not populate it, and neither may elapsed time.
    ///
    /// The arbitrary-day recorder that used to feed this set is gone from the
    /// production API; see [`Self::apply_durable_coverage`].
    observed_utc_days: BTreeSet<u64>,
}

impl NevTierEvaluator {
    /// Creates a new evaluator with a specified monthly operating cost baseline.
    pub fn new(monthly_operating_cost_micros: i64) -> Self {
        Self {
            events: Vec::new(),
            seen_event_ids: BTreeSet::new(),
            first_event_unix: None,
            highest_ever: NevTier::PreNev0,
            monthly_operating_cost_micros,
            observed_utc_days: BTreeSet::new(),
        }
    }

    /// Rebuilds an evaluator from durable replay state.
    ///
    /// This is the P6.N7 restart path, and it is what makes replay protection
    /// durable: the in-memory `seen_event_ids` is not the authority, it is a
    /// cache rebuilt from [`crate::nev_durable::NevReplay`], which is itself
    /// derived from the hash-chained ledger on every read.
    ///
    /// Two properties matter and are deliberately different:
    ///
    /// - **seen** takes EVERY id the ledger holds, whatever its revalidation
    ///   state. An event that later left the canonical chain stays un-reappendable,
    ///   because deleting history is how a reorg turns into a double count.
    /// - **events** takes only the COUNTED ones. A `PendingFinality`,
    ///   `LeftCanonicalChain` or `NeedsRevalidation` event contributes nothing to
    ///   cumulative or current-window NEV, and grants no coverage.
    ///
    /// Events are inserted directly rather than through [`Self::record_event`]:
    /// that method's duplicate and zero-net refusals are for a live caller
    /// offering a new event, whereas this is rehydrating what the ledger already
    /// accepted, including a legitimately recorded zero.
    ///
    /// `highest_ever` is deliberately left at [`NevTier::PreNev0`] and
    /// `observed_utc_days` empty. Both are re-derived by [`Self::evaluate`] from
    /// the rebuilt history, so neither is a value read back from storage.
    pub fn rebuild(
        replay: &crate::nev_durable::NevReplay,
        monthly_operating_cost_micros: i64,
    ) -> Self {
        let mut events: Vec<VerifiedNevEvent> = Vec::new();
        let mut seen_event_ids: BTreeSet<ExternalEventId> = BTreeSet::new();

        // Every id, counted or not, must stay refused.
        for id in replay.seen_economic_event_ids() {
            if let Ok(parsed) = ExternalEventId::from_canonical_text(id) {
                seen_event_ids.insert(parsed);
            }
        }

        let counted = replay.counted_economic_event_ids();
        for replayed in replay.per_event() {
            if !counted.contains(&replayed.economic_event_id) {
                continue;
            }
            let record = crate::nev_durable::NevEconomicEventRecord {
                schema_version: crate::nev_durable::NEV_LEDGER_SCHEMA_VERSION,
                economic_event_id: replayed.economic_event_id.clone(),
                class: replayed.class,
                net_nev_musd_micros: replayed.net_nev_musd_micros,
                gross_inflow_musd_micros: 0,
                external_cost_musd_micros: 0,
                native_gas_cost_musd_micros: 0,
                anchor_block_timestamp_unix: replayed.anchor_block_timestamp_unix,
                observed_day_index: replayed.observed_day_index,
                revalidation_state: replayed.revalidation_state.clone(),
            };
            // A stored id that will not parse has already been refused by the
            // ledger's own validation, so a failure here means the two
            // disagreed; skipping is strictly safer than inserting a broken event.
            if let Ok(event) = VerifiedNevEvent::from_durable_record(&record) {
                events.push(event);
            }
        }
        events.sort_by_key(|e| e.timestamp_unix());
        let first_event_unix = events.first().map(|e| e.timestamp_unix());

        // Coverage comes from the durable checkpoints in the same replay, not from
        // any in-memory accumulation. This is what makes 30 observed days survive a
        // restart, and it is why the arbitrary-day recorder is test-only.
        let observed_utc_days: BTreeSet<u64> = replay.observed_utc_days().clone();

        Self {
            events,
            seen_event_ids,
            first_event_unix,
            highest_ever: NevTier::PreNev0,
            monthly_operating_cost_micros,
            observed_utc_days,
        }
    }

    /// Applies one durably-produced observation checkpoint.
    ///
    /// This is how coverage reaches an evaluator that is being driven live, and it
    /// deliberately takes a CHECKPOINT rather than a day index: the day is no
    /// longer something a caller names.
    ///
    /// # Honest limit of this method
    ///
    /// It trusts the checkpoint's own hash, which proves internal consistency but
    /// NOT that the day was derived from a clock. A caller holding
    /// [`crate::nev_durable::NevObservationCheckpoint`] could have built it for an
    /// arbitrary day. The production authority for coverage is [`Self::rebuild`],
    /// which takes coverage only from a hash-chained ledger; this method exists so
    /// a live evaluator can be brought up to date and so integration tests can
    /// exercise the real checkpoint path. Closing the remaining gap means making
    /// the checkpoint type unconstructible outside the ledger, which is a
    /// follow-up and is reported as an open residual rather than claimed closed.
    pub fn apply_durable_coverage(
        &mut self,
        checkpoint: &crate::nev_durable::NevObservationCheckpoint,
    ) -> Result<(), crate::EconomyError> {
        checkpoint.verify_checkpoint_hash()?;
        if checkpoint.grants_coverage() {
            self.observed_utc_days.insert(checkpoint.day_index);
        }
        Ok(())
    }

    /// Records observation coverage for a full UTC calendar day index.
    ///
    /// TEST-ONLY since P6.N8. The public arbitrary-day entry point is deliberately
    /// gone; there is no `record_day_observed(day_index)` a production caller can
    /// reach.
    ///
    /// `day_index` is `timestamp_unix / SECONDS_PER_DAY`. Observing a day that
    /// happens to carry no events is normal and correct: a silent day is still an
    /// observed day, and saying so is precisely what the coverage gate needs.
    #[cfg(test)]
    pub(crate) fn record_day_observed(&mut self, day_index: u64) {
        self.observed_utc_days.insert(day_index);
    }

    /// Appends a verified NEV event with replay protection and maintains canonical order.
    ///
    /// This records VALUE only. It deliberately does not mark the event's UTC day
    /// observed: coverage comes from durable runtime checkpoints and arrives via
    /// [`Self::rebuild`].
    pub fn record_event(&mut self, event: VerifiedNevEvent) -> Result<(), &'static str> {
        if self.seen_event_ids.contains(event.event_id()) {
            return Err("duplicate external event ID rejected; replay forbidden");
        }
        if event.net_nev_musd_micros == 0 {
            return Err("verified NEV event must have non-zero net_nev");
        }

        self.seen_event_ids.insert(event.event_id().clone());
        if self.first_event_unix.is_none() || Some(event.timestamp_unix()) < self.first_event_unix {
            self.first_event_unix = Some(event.timestamp_unix());
        }
        self.events.push(event);
        self.events.sort_by_key(|e| e.timestamp_unix());
        Ok(())
    }

    /// Evaluates the current NEV tier status at a given reference timestamp `now_unix`.
    ///
    /// Value and coverage share one window: the last 30 COMPLETE UTC calendar days
    /// before the current partial day, `[floor_to_utc_midnight(now) - 30d,
    /// floor_to_utc_midnight(now))`. NEV0 requires positive net value in that
    /// window; NEV1–NEV4 additionally require all 30 of those days to be present in
    /// `observed_utc_days`. When coverage is missing, the returned
    /// `tier_qualification_notes` say how many days are missing.
    pub fn evaluate(&mut self, now_unix: u64) -> NevTierStatus {
        let total_historical_nev: i64 = self
            .events
            .iter()
            .filter(|e| e.timestamp_unix() <= now_unix)
            .map(|e| e.net_nev_musd_micros())
            .fold(0i64, |acc, v| acc.saturating_add(v));
        let total_historical_events = self.events.iter().filter(|e| e.timestamp_unix() <= now_unix).count() as u64;

        let observation_span = match self.first_event_unix {
            Some(first) => now_unix.saturating_sub(first),
            None => 0,
        };

        let min_required_span = (EVALUATION_WINDOW_DAYS as u64) * SECONDS_PER_DAY;
        let window_duration_secs = (EVALUATION_WINDOW_DAYS as u64) * SECONDS_PER_DAY;
        // Eligible economics and coverage use the same 30 complete UTC days.
        let window_end_unix = now_unix / SECONDS_PER_DAY * SECONDS_PER_DAY;
        let window_start_unix = window_end_unix.saturating_sub(window_duration_secs);

        if total_historical_events == 0 {
            return NevTierStatus {
                current_verified_tier: NevTier::PreNev0,
                highest_ever_verified_tier: self.highest_ever,
                cumulative_verified_nev_micros: 0,
                current_window_net_nev_micros: 0,
                cumulative_event_count: 0,
                operational_self_funding_healthy: false,
                observation_history_span_secs: 0,
                window_metrics: None,
                tier_qualification_notes: vec![
                    "no verified NEV events exist; tier is PreNev0".to_string(),
                ],
            };
        }

        let window_events: Vec<&VerifiedNevEvent> = self
            .events
            .iter()
            .filter(|e| e.timestamp_unix() >= window_start_unix && e.timestamp_unix() < window_end_unix)
            .collect();

        let window_metrics = compute_window_metrics(&window_events, window_start_unix, window_end_unix);
        let window_net_nev = window_metrics.total_net_nev_micros;

        // Check continuous observation coverage: 30 consecutive UTC calendar days
        let current_day = now_unix / SECONDS_PER_DAY;
        let required_start_day = current_day.saturating_sub(EVALUATION_WINDOW_DAYS as u64);
        let mut missing_observed_days = 0usize;
        if current_day >= EVALUATION_WINDOW_DAYS as u64 {
            for day in required_start_day..current_day {
                if !self.observed_utc_days.contains(&day) {
                    missing_observed_days += 1;
                }
            }
        } else {
            missing_observed_days = EVALUATION_WINDOW_DAYS;
        }
        let has_full_30_consecutive_observed_days = missing_observed_days == 0;

        // If rolling window net NEV is non-positive, tier drops to PreNev0
        if window_net_nev <= 0 {
            return NevTierStatus {
                current_verified_tier: NevTier::PreNev0,
                highest_ever_verified_tier: self.highest_ever,
                cumulative_verified_nev_micros: total_historical_nev,
                current_window_net_nev_micros: window_net_nev,
                cumulative_event_count: total_historical_events,
                operational_self_funding_healthy: false,
                observation_history_span_secs: observation_span,
                window_metrics: Some(window_metrics),
                tier_qualification_notes: vec![
                    format!(
                        "current 30-day rolling window net NEV is non-positive ({} micros); tier drops to PreNev0",
                        window_net_nev
                    ),
                ],
            };
        }

        // Determine current tier based on rolling metrics
        let mut notes = Vec::new();
        let mut qualified_tier = NevTier::Nev0;
        notes.push("NEV0 achieved: verified positive net external value exists in rolling window".to_string());

        if !has_full_30_consecutive_observed_days {
            notes.push(format!(
                "Tiers NEV1-NEV4 gated: observation coverage incomplete (missing {} of 30 required consecutive UTC calendar days, span {}/{} s)",
                missing_observed_days, observation_span, min_required_span
            ));
        } else {
            // Check NEV1 criteria
            let nev1_eligible = window_metrics.daily_average_nev_micros >= NEV1_DAILY_AVG_MICROS
                && window_events.iter().filter(|e| e.net_nev_musd_micros() > 0).count() >= 5
                && window_metrics.distinct_positive_days >= 3;

            if nev1_eligible {
                qualified_tier = NevTier::Nev1;
                notes.push(format!(
                    "NEV1 qualified: 30d avg {} mUSD/day >= 10 mUSD/day with {} events across {} days",
                    window_metrics.daily_average_nev_micros / 1000,
                    window_metrics.total_events,
                    window_metrics.distinct_positive_days
                ));

                // Check NEV2 criteria
                let nev2_eligible = window_metrics.daily_average_nev_micros >= NEV2_DAILY_AVG_MICROS
                    && window_metrics.total_events >= 10
                    && window_metrics.distinct_positive_days >= 7;

                if nev2_eligible {
                    qualified_tier = NevTier::Nev2;
                    notes.push(format!(
                        "NEV2 qualified: 30d avg {} mUSD/day >= 100 mUSD/day, cost ratio {} bps",
                        window_metrics.daily_average_nev_micros / 1000,
                        window_metrics.cost_inflow_ratio_bps
                    ));

                    // Check NEV3 criteria: self-funding condition
                    let self_funding = window_metrics.total_net_nev_micros
                        >= self.monthly_operating_cost_micros
                        && window_metrics.daily_average_nev_micros >= NEV3_DAILY_AVG_MICROS;

                    if self_funding {
                        qualified_tier = NevTier::Nev3;
                        notes.push(format!(
                            "NEV3 qualified: 30d avg {} mUSD/day >= 500 mUSD/day and operations self-funded",
                            window_metrics.daily_average_nev_micros / 1000
                        ));

                        // Check NEV4 criteria: scale >= 2000 mUSD/day and >= 2 REAL contributing classes
                        let nev4_eligible = window_metrics.daily_average_nev_micros
                            >= NEV4_DAILY_AVG_MICROS
                            && window_metrics.active_real_classes_count >= 2;

                        if nev4_eligible {
                            qualified_tier = NevTier::Nev4;
                            notes.push(format!(
                                "NEV4 qualified: 30d avg {} mUSD/day >= 2000 mUSD/day across {} active REAL classes",
                                window_metrics.daily_average_nev_micros / 1000,
                                window_metrics.active_real_classes_count
                            ));
                        } else if window_metrics.daily_average_nev_micros >= NEV4_DAILY_AVG_MICROS {
                            notes.push(format!(
                                "NEV4 gated: daily avg reached but only {} active REAL classes (requires >= 2 REAL classes)",
                                window_metrics.active_real_classes_count
                            ));
                        }
                    } else if window_metrics.daily_average_nev_micros >= NEV3_DAILY_AVG_MICROS {
                        notes.push(format!(
                            "NEV3 gated: daily avg reached but net NEV {} < monthly operating cost {}",
                            window_metrics.total_net_nev_micros, self.monthly_operating_cost_micros
                        ));
                    }
                }
            }
        }

        if qualified_tier > self.highest_ever {
            self.highest_ever = qualified_tier;
        }

        let self_funding_healthy =
            window_metrics.total_net_nev_micros >= self.monthly_operating_cost_micros;

        NevTierStatus {
            current_verified_tier: qualified_tier,
            highest_ever_verified_tier: self.highest_ever,
            cumulative_verified_nev_micros: total_historical_nev,
            current_window_net_nev_micros: window_net_nev,
            cumulative_event_count: total_historical_events,
            operational_self_funding_healthy: self_funding_healthy,
            observation_history_span_secs: observation_span,
            window_metrics: Some(window_metrics),
            tier_qualification_notes: notes,
        }
    }
}

fn compute_window_metrics(
    events: &[&VerifiedNevEvent],
    window_start: u64,
    window_end: u64,
) -> RollingWindowMetrics {
    let mut total_net: i64 = 0;
    let mut total_costs: u64 = 0;
    let mut total_gross: u64 = 0;
    let mut distinct_days = BTreeSet::new();
    let mut nev_by_class: BTreeMap<OpportunityClass, i64> = BTreeMap::new();
    let mut real_classes_with_positive_net = BTreeSet::new();
    let mut event_nets: Vec<i64> = Vec::with_capacity(events.len());

    for e in events {
        total_net = total_net.saturating_add(e.net_nev_musd_micros());
        let event_cost = e
            .external_cost_musd_micros()
            .saturating_add(e.native_gas_cost_musd_micros());
        total_costs = total_costs.saturating_add(event_cost);
        total_gross = total_gross.saturating_add(e.gross_inflow_musd_micros());

        if e.net_nev_musd_micros() > 0 {
            let day_index = e.timestamp_unix() / SECONDS_PER_DAY;
            distinct_days.insert(day_index);
            if let Some(real_cap) = e.real_capability() {
                real_classes_with_positive_net.insert(real_cap.class());
            }
        }

        let class_net = nev_by_class.entry(e.class()).or_insert(0);
        *class_net = class_net.saturating_add(e.net_nev_musd_micros());
        event_nets.push(e.net_nev_musd_micros());
    }

    real_classes_with_positive_net.retain(|class| nev_by_class.get(class).copied().unwrap_or(0) > 0);
    event_nets.sort_unstable();

    let median_event_nev = if event_nets.is_empty() {
        0
    } else {
        event_nets[event_nets.len() / 2]
    };

    let p10_event_nev = if event_nets.is_empty() {
        0
    } else {
        let idx = (event_nets.len() as f64 * 0.10).floor() as usize;
        event_nets[idx.min(event_nets.len() - 1)]
    };

    let daily_average_nev = total_net / (EVALUATION_WINDOW_DAYS as i64);

    let cost_inflow_ratio_bps = if total_gross == 0 {
        0
    } else {
        ((total_costs as u128 * 10_000) / total_gross as u128) as u64
    };

    let max_class_nev = nev_by_class.values().copied().max().unwrap_or(0);
    let class_concentration_bps = if total_net <= 0 {
        10_000
    } else {
        let max_pos = max_class_nev.max(0) as u128;
        ((max_pos * 10_000) / total_net as u128) as u64
    };

    RollingWindowMetrics {
        window_start_unix: window_start,
        window_end_unix: window_end,
        total_events: events.len(),
        distinct_positive_days: distinct_days.len(),
        total_net_nev_micros: total_net,
        daily_average_nev_micros: daily_average_nev,
        total_costs_micros: total_costs,
        total_gross_inflows_micros: total_gross,
        cost_inflow_ratio_bps,
        nev_by_class,
        class_concentration_bps,
        active_real_classes_count: real_classes_with_positive_net.len(),
        median_event_nev_micros: median_event_nev,
        p10_event_nev_micros: p10_event_nev,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Marks `count` consecutive UTC calendar days as observed, starting at `start_day`.
    fn observe_days(evaluator: &mut NevTierEvaluator, start_day: u64, count: u64) {
        for offset in 0..count {
            evaluator.record_day_observed(start_day + offset);
        }
    }

    /// The first note a run hits when it clears the NEV3 daily average but lacks
    /// a second genuine REAL capability.
    const NEV4_GATED_NOTE: &str = "NEV4 gated: daily avg reached but only";
    /// The coverage-gate note emitted whenever 30/30 observed days are not present.
    const COVERAGE_GATED_NOTE: &str = "Tiers NEV1-NEV4 gated: observation coverage incomplete";

    #[test]
    fn initial_state_is_pre_nev0() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let status = evaluator.evaluate(1_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY + SECONDS_PER_DAY);
        assert_eq!(status.current_verified_tier, NevTier::PreNev0);
        assert_eq!(status.highest_ever_verified_tier, NevTier::PreNev0);
        assert_eq!(status.cumulative_verified_nev_micros, 0);
        assert_eq!(status.cumulative_event_count, 0);
    }

    #[test]
    fn a_single_event_qualifies_nev0_even_one_cent() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        evaluator
            .record_event(VerifiedNevEvent::new_test(
                ExternalEventId::from_test_seed("evt-1"),
                100_000,
                OpportunityClass::Arbitrage,
                Some(RealOpportunityClass::arbitrage()),
                20_000,
                5_000,
                5_000,
                10_000, // 0.01 USDC
            ))
            .unwrap();

        let status = evaluator.evaluate(2 * SECONDS_PER_DAY);
        assert_eq!(status.current_verified_tier, NevTier::Nev0);
        assert_eq!(status.highest_ever_verified_tier, NevTier::Nev0);
        assert_eq!(status.cumulative_verified_nev_micros, 10_000);
        assert_eq!(status.current_window_net_nev_micros, 10_000);
    }

    #[test]
    fn replay_protection_refuses_identical_event_id() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let evt_id = ExternalEventId::from_test_seed("replay-seed-1");

        evaluator
            .record_event(VerifiedNevEvent::new_test(
                evt_id.clone(),
                100_000,
                OpportunityClass::Arbitrage,
                Some(RealOpportunityClass::arbitrage()),
                20_000,
                5_000,
                5_000,
                10_000,
            ))
            .expect("first record succeeds");

        // Attempt duplicate insertion
        let dup_err = evaluator.record_event(VerifiedNevEvent::new_test(
            evt_id,
            100_001,
            OpportunityClass::Arbitrage,
            Some(RealOpportunityClass::arbitrage()),
            20_000,
            5_000,
            5_000,
            10_000,
        ));
        assert!(dup_err.is_err());
        assert!(dup_err.unwrap_err().contains("replay forbidden"));
    }

    #[test]
    fn negative_loss_events_are_accounted_and_can_downgrade_tier() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base_ts = 1_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;

        // Distribute events over 31 days to clear the 30-day window requirement
        for i in 0..10 {
            let day_offset = (i as u64 * 3) * SECONDS_PER_DAY; // spans 0..27 days
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("gain-{i}")),
                    base_ts + day_offset,
                    OpportunityClass::Arbitrage,
                    Some(RealOpportunityClass::arbitrage()),
                    150_000,
                    10_000,
                    10_000,
                    130_000,
                ))
                .unwrap();
        }

        let eval_time = base_ts + 30 * SECONDS_PER_DAY;
        let start_day = (eval_time / SECONDS_PER_DAY).saturating_sub(30);
        observe_days(&mut evaluator, start_day, 30);

        let status = evaluator.evaluate(eval_time);
        assert_eq!(status.current_verified_tier, NevTier::Nev1);
        // Coverage was complete here, so the downgrade below can only be caused by
        // the loss event entering the window — not by a coverage gap.
        assert!(!status.tier_qualification_notes.iter().any(|n| n.contains(COVERAGE_GATED_NOTE)));
        assert_eq!(status.current_window_net_nev_micros, 10 * 130_000);

        // Record a verified negative loss event (-1,200_000 micros)
        evaluator
            .record_event(VerifiedNevEvent::new_test(
                ExternalEventId::from_test_seed("loss-1"),
                eval_time - 100,
                OpportunityClass::Arbitrage,
                Some(RealOpportunityClass::arbitrage()),
                10_000,
                100_000,
                1_110_000,
                -1_200_000,
            ))
            .unwrap();

        // Re-evaluating now must reflect the net loss and downgrade the tier!
        let status_after_loss = evaluator.evaluate(eval_time);
        assert_eq!(status_after_loss.current_window_net_nev_micros, 10 * 130_000 - 1_200_000);
        assert_eq!(status_after_loss.cumulative_verified_nev_micros, 10 * 130_000 - 1_200_000);
        assert_eq!(status_after_loss.current_verified_tier, NevTier::Nev0);
        assert!(status_after_loss.current_verified_tier < NevTier::Nev1);
        // The historical watermark is monotonic: the loss cannot revoke what was
        // already earned, it only stops the CURRENT window from qualifying.
        assert_eq!(status_after_loss.highest_ever_verified_tier, NevTier::Nev1);
        // Coverage is still complete, so nothing disappeared and nothing was gated.
        assert!(!status_after_loss.tier_qualification_notes.iter().any(|n| n.contains(COVERAGE_GATED_NOTE)));
    }

    #[test]
    fn thirty_complete_observed_days_required_for_nev1() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base_ts = 1_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;

        // Add 5 events over 3 days, but only 3 days total history
        for i in 0..5 {
            let day_offset = (i % 3) as u64 * SECONDS_PER_DAY;
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("evt-{i}")),
                    base_ts + day_offset + (i as u64 * 10),
                    OpportunityClass::Arbitrage,
                    Some(RealOpportunityClass::arbitrage()),
                    70_000,
                    5_000,
                    5_000,
                    60_000,
                ))
                .unwrap();
        }

        // At day 3 (observation span = 2 days < 30 days) -> GATED at Nev0!
        let now_early = base_ts + 2 * SECONDS_PER_DAY;
        let status_early = evaluator.evaluate(now_early);
        assert_eq!(status_early.current_verified_tier, NevTier::Nev0);
        assert!(status_early
            .tier_qualification_notes
            .iter()
            .any(|n| n.contains("Tiers NEV1-NEV4 gated: observation coverage incomplete")));

        // At day 30 exact with full observation coverage -> NEV1 unlocks!
        let now_mature = base_ts + 30 * SECONDS_PER_DAY;
        let start_day = (now_mature / SECONDS_PER_DAY).saturating_sub(30);
        for d in 0..30 {
            evaluator.record_day_observed(start_day + d);
        }
        let status_mature = evaluator.evaluate(now_mature);
        assert_eq!(status_mature.current_verified_tier, NevTier::Nev1);
    }

    #[test]
    fn tier_is_revocable_when_window_slides_past_events() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base_ts = 1_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;

        // Seed 5 events spanning across 30 days
        for i in 0..5 {
            let day_offset = (i as u64 * 7) * SECONDS_PER_DAY;
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("evt-{i}")),
                    base_ts + day_offset + (i as u64 * 10),
                    OpportunityClass::Arbitrage,
                    Some(RealOpportunityClass::arbitrage()),
                    120_000,
                    10_000,
                    10_000,
                    100_000,
                ))
                .unwrap();
        }

        // At 30 days: NEV1
        let now = base_ts + 30 * SECONDS_PER_DAY;
        let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);
        for d in 0..30 {
            evaluator.record_day_observed(start_day + d);
        }
        let status = evaluator.evaluate(now);
        assert_eq!(status.current_verified_tier, NevTier::Nev1);
        assert_eq!(status.highest_ever_verified_tier, NevTier::Nev1);

        // 35 days later: window slid past the events!
        let later = now + 35 * SECONDS_PER_DAY;
        let status_later = evaluator.evaluate(later);
        // Current tier downgrades to PreNev0 (since no events exist in active window)
        assert_eq!(status_later.current_verified_tier, NevTier::PreNev0);
        // Highest ever remains Nev1
        assert_eq!(status_later.highest_ever_verified_tier, NevTier::Nev1);
    }

    #[test]
    fn nev4_requires_multiple_real_classes_capability() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base_ts = 1_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;

        // Single REAL class (Arbitrage) with huge volume (3,000 mUSD/day avg)
        for i in 0..30 {
            let day_offset = i as u64 * SECONDS_PER_DAY;
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("arb-evt-{i}")),
                    base_ts + day_offset,
                    OpportunityClass::Arbitrage,
                    Some(RealOpportunityClass::arbitrage()), // REAL
                    3_100_000,
                    50_000,
                    50_000,
                    3_000_000,
                ))
                .unwrap();
        }

        let now = base_ts + 30 * SECONDS_PER_DAY + 100;
        let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);
        for d in 0..30 {
            evaluator.record_day_observed(start_day + d);
        }
        let status = evaluator.evaluate(now);
        // Gated at NEV3 because only 1 REAL class is active
        assert_eq!(status.current_verified_tier, NevTier::Nev3);
        assert!(status
            .tier_qualification_notes
            .iter()
            .any(|n| n.contains("NEV4 gated: daily avg reached but only 1 active REAL classes")));

        // Adding ComputeReward events with None CANNOT unlock NEV4!
        for i in 0..10 {
            let day_offset = (i * 2) as u64 * SECONDS_PER_DAY;
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("comp-evt-{i}")),
                    base_ts + day_offset + 50,
                    OpportunityClass::ComputeReward,
                    None, // NOT REAL (no capability)
                    300_000,
                    10_000,
                    10_000,
                    280_000,
                ))
                .unwrap();
        }

        let status2 = evaluator.evaluate(now);
        // Still NEV3!
        assert_eq!(status2.current_verified_tier, NevTier::Nev3);

        // Only when a second genuine REAL class contributes does NEV4 unlock!
        for i in 0..10 {
            let day_offset = (i * 2) as u64 * SECONDS_PER_DAY;
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("real2-evt-{i}")),
                    base_ts + day_offset + 60,
                    OpportunityClass::NetworkFee,
                    Some(RealOpportunityClass::test_second_real_class()), // Second REAL class
                    300_000,
                    10_000,
                    10_000,
                    280_000,
                ))
                .unwrap();
        }

        let status3 = evaluator.evaluate(now);
        assert_eq!(status3.current_verified_tier, NevTier::Nev4);
        assert_eq!(status3.highest_ever_verified_tier, NevTier::Nev4);
    }

    #[test]
    fn historical_losses_do_not_freeze_active_profitable_window_and_net_loss_drops_to_pre_nev0() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let past_ts = 1_000_000 / SECONDS_PER_DAY * SECONDS_PER_DAY;

        // In the distant past (60 days ago), we had a catastrophic loss event of -5,000,000 micros
        evaluator
            .record_event(VerifiedNevEvent::new_test(
                ExternalEventId::from_test_seed("ancient-loss"),
                past_ts,
                OpportunityClass::Arbitrage,
                Some(RealOpportunityClass::arbitrage()),
                0,
                5_000_000,
                0,
                -5_000_000,
            ))
            .unwrap();

        // 60 days later, we have a fresh 30-day active profitable window (+200,000 micros across 5 events)
        let now = past_ts + 60 * SECONDS_PER_DAY;
        let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);
        for d in 0..30 {
            evaluator.record_day_observed(start_day + d);
        }

        for i in 0..5 {
            let day_offset = (i * 5) as u64 * SECONDS_PER_DAY;
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("fresh-gain-{i}")),
                    (past_ts + 35 * SECONDS_PER_DAY) + day_offset,
                    OpportunityClass::Arbitrage,
                    Some(RealOpportunityClass::arbitrage()),
                    250_000,
                    10_000,
                    10_000,
                    230_000,
                ))
                .unwrap();
        }

        let status = evaluator.evaluate(now);
        // Ancient loss makes all-time cumulative negative (-3,850,000 micros)
        assert_eq!(status.cumulative_verified_nev_micros, -5_000_000 + 5 * 230_000);
        assert!(status.cumulative_verified_nev_micros < 0);

        // BUT current 30-day rolling window is positive (+1,150,000 micros)!
        assert_eq!(status.current_window_net_nev_micros, 5 * 230_000);
        // Therefore, historical loss does NOT freeze the active profitable window: qualifies for Nev1!
        assert_eq!(status.current_verified_tier, NevTier::Nev1);

        // Now inject a net loss inside the rolling window (-1,500,000 micros)
        evaluator
            .record_event(VerifiedNevEvent::new_test(
                ExternalEventId::from_test_seed("window-loss"),
                now - 100,
                OpportunityClass::Arbitrage,
                Some(RealOpportunityClass::arbitrage()),
                100_000,
                1_600_000,
                0,
                -1_500_000,
            ))
            .unwrap();

        // Now rolling window net is 1,150,000 - 1,500,000 = -350,000 micros <= 0!
        let status_loss = evaluator.evaluate(now);
        assert_eq!(status_loss.current_window_net_nev_micros, -350_000);
        // Rolling window net loss MUST drop tier to PreNev0!
        assert_eq!(status_loss.current_verified_tier, NevTier::PreNev0);
        assert_eq!(status_loss.highest_ever_verified_tier, NevTier::Nev1);
    }
    #[test]
    fn observation_requires_every_complete_day_and_ingestion_does_not_supply_it() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base = 100 * SECONDS_PER_DAY;
        for i in 0..5 {
            evaluator.record_event(VerifiedNevEvent::new_test(
                ExternalEventId::from_test_seed(&format!("coverage-{i}")),
                base + i * SECONDS_PER_DAY, OpportunityClass::Arbitrage,
                Some(RealOpportunityClass::arbitrage()), 100_000, 0, 0, 100_000,
            )).unwrap();
        }
        let now = base + 30 * SECONDS_PER_DAY;
        assert_eq!(evaluator.evaluate(now).current_verified_tier, NevTier::Nev0);
        for day in 100..129 { evaluator.record_day_observed(day); }
        evaluator.record_day_observed(130); // Incomplete current day cannot fill the gap.
        assert_eq!(evaluator.evaluate(now).current_verified_tier, NevTier::Nev0);
        evaluator.record_day_observed(129); // Zero-event days still count as observed.
        assert_eq!(evaluator.evaluate(now).current_verified_tier, NevTier::Nev1);
        for day in 110..115 { evaluator.observed_utc_days.remove(&day); }
        assert_eq!(evaluator.evaluate(now).current_verified_tier, NevTier::Nev0);
    }

    #[test]
    fn signed_losses_are_not_clipped_and_negative_real_class_is_inactive() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        // Signed nets: one large gain followed by two losses. A clipping
        // implementation (saturating each event at zero, or abs()-ing the loss)
        // would report +1,000,000 or +1,400,000 here. Nothing disappears.
        for (i, net) in [1_000_000i64, -900_000, -400_000].into_iter().enumerate() {
            evaluator.record_event(VerifiedNevEvent::new_test(
                ExternalEventId::from_test_seed(&format!("signed-{i}")),
                100 * SECONDS_PER_DAY + i as u64, OpportunityClass::Arbitrage,
                Some(RealOpportunityClass::arbitrage()), 0, 0, 0, net,
            )).unwrap();
        }
        let status = evaluator.evaluate(101 * SECONDS_PER_DAY);
        // 1,000,000 - 900,000 - 400,000 = -300,000, reported as such in the
        // window, in the all-time cumulative, and in the window metrics alike.
        assert_eq!(status.current_window_net_nev_micros, -300_000);
        assert_eq!(status.cumulative_verified_nev_micros, -300_000);
        assert_eq!(status.current_verified_tier, NevTier::PreNev0);
        assert_eq!(status.cumulative_event_count, 3);
        let metrics = status.window_metrics.unwrap();
        assert_eq!(metrics.total_net_nev_micros, -300_000);
        assert_eq!(metrics.active_real_classes_count, 0);
    }

    #[test]
    fn thirty_days_elapsed_without_a_single_observation_record_stays_nev0() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base_ts = 100 * SECONDS_PER_DAY;
        evaluator
            .record_event(VerifiedNevEvent::new_test(
                ExternalEventId::from_test_seed("elapsed-no-coverage"),
                base_ts + 60,
                OpportunityClass::Arbitrage,
                Some(RealOpportunityClass::arbitrage()),
                1_000_000,
                0,
                0,
                1_000_000,
            ))
            .unwrap();

        // 30 complete UTC days later, with ZERO calls to record_day_observed or
        // record_observation anywhere above. Elapsed time is not observation, and
        // neither is verified value.
        let now = base_ts + 30 * SECONDS_PER_DAY;
        let status = evaluator.evaluate(now);
        assert_eq!(status.observation_history_span_secs, 30 * SECONDS_PER_DAY - 60);
        assert!(status.current_window_net_nev_micros > 0);
        assert_eq!(status.current_verified_tier, NevTier::Nev0);
        assert!(status.tier_qualification_notes.iter().any(|n| n.contains(COVERAGE_GATED_NOTE)));
        assert!(status
            .tier_qualification_notes
            .iter()
            .any(|n| n.contains("missing 30 of 30 required consecutive UTC calendar days")));
    }

    #[test]
    fn twenty_nine_consecutive_observed_days_are_not_thirty() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base_ts = 100 * SECONDS_PER_DAY;

        // 6 events x 100,000 micros on 6 distinct days = 600,000 window net,
        // a 20,000 micros/day average that already clears NEV1's value bar.
        for i in 0..6u64 {
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("twenty9-{i}")),
                    base_ts + i * SECONDS_PER_DAY + 60,
                    OpportunityClass::Arbitrage,
                    Some(RealOpportunityClass::arbitrage()),
                    100_000,
                    0,
                    0,
                    100_000,
                ))
                .unwrap();
        }

        let now = base_ts + 30 * SECONDS_PER_DAY;
        let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);
        assert_eq!(start_day, 100, "eligible window is UTC days 100 through 129");

        // Every required day except the last one.
        observe_days(&mut evaluator, start_day, 29);
        let status = evaluator.evaluate(now);
        assert!(status.current_window_net_nev_micros > 0);
        assert_eq!(status.current_verified_tier, NevTier::Nev0);
        assert!(status.tier_qualification_notes.iter().any(|n| n.contains(COVERAGE_GATED_NOTE)));
        assert!(status
            .tier_qualification_notes
            .iter()
            .any(|n| n.contains("missing 1 of 30 required consecutive UTC calendar days")));

        // Only the 30th day is missing, and adding it is what unlocks NEV1.
        evaluator.record_day_observed(start_day + 29);
        let status_full = evaluator.evaluate(now);
        assert_eq!(status_full.current_window_net_nev_micros, 600_000);
        assert_eq!(status_full.current_verified_tier, NevTier::Nev1);
    }

    #[test]
    fn thirty_consecutive_observed_days_with_value_qualify_nev1() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base_ts = 100 * SECONDS_PER_DAY;
        for i in 0..6u64 {
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("thirty-{i}")),
                    base_ts + i * SECONDS_PER_DAY + 60,
                    OpportunityClass::Arbitrage,
                    Some(RealOpportunityClass::arbitrage()),
                    100_000,
                    0,
                    0,
                    100_000,
                ))
                .unwrap();
        }
        let now = base_ts + 30 * SECONDS_PER_DAY;
        observe_days(&mut evaluator, (now / SECONDS_PER_DAY).saturating_sub(30), 30);
        let status = evaluator.evaluate(now);
        assert_eq!(status.current_window_net_nev_micros, 600_000);
        assert_eq!(status.current_verified_tier, NevTier::Nev1);
        assert_eq!(status.highest_ever_verified_tier, NevTier::Nev1);
        assert!(!status.tier_qualification_notes.iter().any(|n| n.contains(COVERAGE_GATED_NOTE)));
        assert!(status.tier_qualification_notes.iter().any(|n| n.contains("NEV1 qualified")));
    }

    #[test]
    fn a_five_day_observation_gap_inside_thirty_elapsed_days_blocks_nev1() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base_ts = 100 * SECONDS_PER_DAY;
        for i in 0..6u64 {
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("gap5-{i}")),
                    base_ts + i * SECONDS_PER_DAY + 60,
                    OpportunityClass::Arbitrage,
                    Some(RealOpportunityClass::arbitrage()),
                    100_000,
                    0,
                    0,
                    100_000,
                ))
                .unwrap();
        }
        let now = base_ts + 30 * SECONDS_PER_DAY;
        let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);

        // 25 of the 30 required days, with one contiguous 5-day hole at 112..=116.
        observe_days(&mut evaluator, start_day, 12);
        observe_days(&mut evaluator, start_day + 17, 13);
        assert_eq!(evaluator.observed_utc_days.len(), 25);

        let status = evaluator.evaluate(now);
        assert!(status.current_window_net_nev_micros > 0);
        assert_eq!(status.current_verified_tier, NevTier::Nev0);
        assert!(status.tier_qualification_notes.iter().any(|n| n.contains(COVERAGE_GATED_NOTE)));
        assert!(status
            .tier_qualification_notes
            .iter()
            .any(|n| n.contains("missing 5 of 30 required consecutive UTC calendar days")));

        // Filling the hole — nothing about the value changes — promotes to NEV1.
        observe_days(&mut evaluator, start_day + 12, 5);
        assert_eq!(evaluator.observed_utc_days.len(), 30);
        assert_eq!(evaluator.evaluate(now).current_verified_tier, NevTier::Nev1);
    }

    #[test]
    fn observed_days_with_no_events_still_count_as_coverage() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base_ts = 100 * SECONDS_PER_DAY;
        // 6 events x 200,000 micros spread over just 3 days: 1,200,000 window net,
        // a 40,000 micros/day average with >=5 positive events and >=3 positive
        // days, i.e. every NEV1 VALUE criterion is satisfied.
        for i in 0..6u64 {
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("sparse-{i}")),
                    base_ts + (i % 3) * SECONDS_PER_DAY + 60,
                    OpportunityClass::Arbitrage,
                    Some(RealOpportunityClass::arbitrage()),
                    200_000,
                    0,
                    0,
                    200_000,
                ))
                .unwrap();
        }
        let now = base_ts + 30 * SECONDS_PER_DAY;
        let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);
        observe_days(&mut evaluator, start_day, 30);

        // THE assertion that proves "zero-event days count": only 3 of the 30
        // required days carry an event, yet the coverage gate demands 30 of 30
        // observed days. Reaching NEV1 is therefore only possible if the other 27
        // silent days were accepted as coverage.
        let status = evaluator.evaluate(now);
        assert_eq!(status.window_metrics.unwrap().distinct_positive_days, 3);
        assert_eq!(status.current_window_net_nev_micros, 1_200_000);
        assert_eq!(status.current_verified_tier, NevTier::Nev1);

        // And the converse: un-observing ONE of those silent days closes the gate
        // again, which shows the NEV1 above was earned by coverage, not by the
        // three event days.
        assert!(evaluator.observed_utc_days.remove(&126));
        let status_gap = evaluator.evaluate(now);
        assert_eq!(status.current_verified_tier, NevTier::Nev1);
        assert_eq!(status_gap.current_verified_tier, NevTier::Nev0);
        assert!(status_gap
            .tier_qualification_notes
            .iter()
            .any(|n| n.contains("missing 1 of 30 required consecutive UTC calendar days")));
    }

    #[test]
    fn a_recorded_event_does_not_imply_the_day_was_observed() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base_ts = 100 * SECONDS_PER_DAY;
        // One positive event on EVERY one of the 30 eligible days: 30 events,
        // 30 distinct positive days, a 100,000 micros/day average. Every value
        // criterion up to NEV3 is met by value alone.
        for day in 0..30u64 {
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("dense-{day}")),
                    base_ts + day * SECONDS_PER_DAY + 60,
                    OpportunityClass::Arbitrage,
                    Some(RealOpportunityClass::arbitrage()),
                    100_000,
                    0,
                    0,
                    100_000,
                ))
                .unwrap();
        }
        // Not one record_day_observed / record_observation call in this test.
        let now = base_ts + 30 * SECONDS_PER_DAY;
        let status = evaluator.evaluate(now);
        assert_eq!(status.cumulative_event_count, 30);
        assert_eq!(status.window_metrics.unwrap().distinct_positive_days, 30);
        assert_eq!(status.current_window_net_nev_micros, 3_000_000);
        assert_eq!(status.current_verified_tier, NevTier::Nev0);
        assert_eq!(status.highest_ever_verified_tier, NevTier::Nev0);
        assert!(status.tier_qualification_notes.iter().any(|n| n.contains(COVERAGE_GATED_NOTE)));
        assert!(status
            .tier_qualification_notes
            .iter()
            .any(|n| n.contains("missing 30 of 30 required consecutive UTC calendar days")));

        // Now observe every one of those event-bearing days, and NEV2 unlocks.
        observe_days(&mut evaluator, (now / SECONDS_PER_DAY).saturating_sub(30), 30);
        assert_eq!(evaluator.evaluate(now).current_verified_tier, NevTier::Nev2);
    }

    #[test]
    fn a_compute_reward_label_with_positive_net_does_not_count_as_a_real_class() {
        let mut evaluator = NevTierEvaluator::new(10_000_000);
        let base_ts = 100 * SECONDS_PER_DAY;
        // 10 ComputeReward events x 7,000,000 micros = a 2,333,333 micros/day
        // average, above NEV4's 2,000,000 micros/day bar, so the NEV4 gate is
        // reached on value and refused on diversification alone. `new_test` lets
        // a test attach any class label, so `real_capability` is passed as None to
        // model the production reality: a ComputeReward event never carries a
        // REAL capability, because only a RealOpportunityClass proves that.
        for i in 0..10u64 {
            evaluator
                .record_event(VerifiedNevEvent::new_test(
                    ExternalEventId::from_test_seed(&format!("compute-{i}")),
                    base_ts + i * SECONDS_PER_DAY + 60,
                    OpportunityClass::ComputeReward,
                    None,
                    7_000_000,
                    0,
                    0,
                    7_000_000,
                ))
                .unwrap();
        }
        let now = base_ts + 30 * SECONDS_PER_DAY;
        observe_days(&mut evaluator, (now / SECONDS_PER_DAY).saturating_sub(30), 30);

        let status = evaluator.evaluate(now);
        let metrics = status.window_metrics.unwrap();
        assert_eq!(metrics.total_net_nev_micros, 70_000_000);
        assert!(metrics.daily_average_nev_micros >= NEV4_DAILY_AVG_MICROS);
        assert_eq!(metrics.active_real_classes_count, 0);
        // Class labels are plentiful; capabilities are not. NEV3 volume is
        // reached, NEV4 diversification is not.
        assert_eq!(status.current_verified_tier, NevTier::Nev3);
        assert!(status.tier_qualification_notes.iter().any(|n| n.contains(NEV4_GATED_NOTE)));
        assert!(status
            .tier_qualification_notes
            .iter()
            .any(|n| n.contains("only 0 active REAL classes")));
    }

    #[test]
    fn two_genuine_real_capabilities_satisfy_nev4_diversification() {
        // Two independent runs over identical value: one with both genuine REAL
        // capabilities contributing, one with the second capability removed.
        fn event_of(
            seed: &str,
            ts: u64,
            class: OpportunityClass,
            real_capability: Option<RealOpportunityClass>,
        ) -> VerifiedNevEvent {
            // 3,000,000 micros/day per class -> 6,000,000 micros/day combined,
            // above NEV4's 2,000,000 micros/day.
            VerifiedNevEvent::new_test(
                ExternalEventId::from_test_seed(seed),
                ts,
                class,
                real_capability,
                3_000_000,
                0,
                0,
                3_000_000,
            )
        }

        let base_ts = 100 * SECONDS_PER_DAY;
        let now = base_ts + 30 * SECONDS_PER_DAY;
        let start_day = (now / SECONDS_PER_DAY).saturating_sub(30);

        let mut both = NevTierEvaluator::new(10_000_000);
        let mut single = NevTierEvaluator::new(10_000_000);
        for day in 0..30u64 {
            let ts = base_ts + day * SECONDS_PER_DAY + 60;
            let arb_seed = format!("div-arb-{day}");
            let fee_seed = format!("div-fee-{day}");

            both.record_event(event_of(
                &arb_seed,
                ts,
                OpportunityClass::Arbitrage,
                Some(RealOpportunityClass::arbitrage()),
            ))
            .unwrap();
            both.record_event(event_of(
                &fee_seed,
                ts + 60,
                OpportunityClass::NetworkFee,
                Some(RealOpportunityClass::test_second_real_class()),
            ))
            .unwrap();

            // The "second capability removed" run keeps the same second class
            // label but strips the capability, which is the only REAL evidence.
            single
                .record_event(event_of(
                    &arb_seed,
                    ts,
                    OpportunityClass::Arbitrage,
                    Some(RealOpportunityClass::arbitrage()),
                ))
                .unwrap();
            single
                .record_event(event_of(
                    &fee_seed,
                    ts + 60,
                    OpportunityClass::NetworkFee,
                    None,
                ))
                .unwrap();
        }
        observe_days(&mut both, start_day, 30);
        observe_days(&mut single, start_day, 30);

        let both_status = both.evaluate(now);
        let both_metrics = both_status.window_metrics.unwrap();
        assert_eq!(both_metrics.active_real_classes_count, 2);
        assert_eq!(both_status.current_verified_tier, NevTier::Nev4);
        assert_eq!(both_status.highest_ever_verified_tier, NevTier::Nev4);
        assert!(both_status.tier_qualification_notes.iter().any(|n| n.contains("NEV4 qualified")));

        let single_status = single.evaluate(now);
        let single_metrics = single_status.window_metrics.unwrap();
        assert_eq!(single_metrics.active_real_classes_count, 1);
        assert_eq!(single_status.current_verified_tier, NevTier::Nev3);
        assert!(single_status.tier_qualification_notes.iter().any(|n| n.contains(NEV4_GATED_NOTE)));
        assert!(single_status
            .tier_qualification_notes
            .iter()
            .any(|n| n.contains("only 1 active REAL classes")));
    }

    // ---- P6.N6: the identity is derived, not supplied --------------------

    /// THE load-bearing test of this milestone, and it is a *compile-time* one.
    ///
    /// Assigning the constructor to a function pointer of the exact new
    /// signature type only compiles while the signature is exactly that: no
    /// `ExternalEventId` parameter, in any position, of any type. The previous
    /// signature — `(ExternalEventId, &ComparableVerifiedSettlement,
    /// OpportunityClass) -> Self` — is a different type, so this line is the
    /// proof that a caller can no longer hand a NEV event its own identity.
    /// Reintroducing that parameter breaks the build here rather than in review.
    #[test]
    fn the_nev_constructor_takes_no_event_id_and_derives_one() {
        // The annotation is the assertion: this binding only type-checks while
        // the signature is exactly this one, so no `ExternalEventId` parameter
        // exists anywhere in it.
        let _derived_only: fn(
            &ComparableVerifiedSettlement,
            OpportunityClass,
        ) -> Result<VerifiedNevEvent, EventIdError> =
            VerifiedNevEvent::from_comparable_settlement;
    }

    /// `ExternalEventId` is unchanged by P6.N6, and an identity is a digest —
    /// never something a caller can name by typing a label.
    ///
    /// Its only text form is the canonical `0x`-prefixed 64-hex-digit spelling of
    /// a 32-byte digest, which is what `blake3` produced; producing one requires
    /// running the derivation, not writing a string. (`VerifiedNevEvent` itself
    /// derives `Serialize` only — no `Deserialize` — so there is no stored
    /// document from which an identity could be asserted either.)
    #[test]
    fn a_nev_event_id_is_a_digest_and_not_a_typed_label() {
        let id = ExternalEventId::from_test_seed("nev-constructor-has-no-id-parameter");
        assert_ne!(
            id.as_str(),
            "nev-constructor-has-no-id-parameter",
            "a seed is not an identity"
        );
        assert!(
            id.as_str().starts_with("0x"),
            "an identity is spelled as a digest: {}",
            id.as_str()
        );
        assert_eq!(
            id.as_str().trim_start_matches("0x").len(),
            64,
            "one canonical digest spelling, fixed length, so no label can pose as one"
        );
        assert!(id.as_str().trim_start_matches("0x").chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        // And it is the same id however many times the same seed is used, which
        // is the whole reason the constructor can afford to derive it: there is
        // nothing for a caller to vary.
        assert_eq!(
            id,
            ExternalEventId::from_test_seed("nev-constructor-has-no-id-parameter")
        );
    }
}
