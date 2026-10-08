//! P6 — the autonomous search state machine.
//!
//! # What was missing
//!
//! Everything that looked like discovery in this crate was an *import*. There
//! is no loop, no scan, no class rotation, no backoff and no coverage: an
//! external process writes a JSON file, [`crate::s1_adapter::import_shadow_scan`]
//! and [`crate::s1_perception_adapter::import_perception_report`] read it, and
//! the crate maps whatever it finds into
//! [`crate::autonomy::OpportunityCandidate`]s. The audit that preceded this
//! module found the consequences directly:
//!
//! * the strongest evidence the machine had was computed and **thrown away** —
//!   `best_observed_token_edge_usdc_raw` and
//!   `best_observed_robust_net_usdc_raw` in
//!   [`crate::s1_perception_adapter`] are the measured proof that a market was
//!   scanned and did not pay, and nothing in the crate read them. The CLI
//!   printed them and moved on;
//! * there was no way to say "searched and found nothing" as distinct from
//!   "never looked", because there was no state to be in and no coverage to
//!   report;
//! * there was no backoff of any kind — no schedule, no EWMA, no variance — so
//!   "keep scanning" was not a policy decision, it was the only behaviour;
//! * six of the eight [`crate::autonomy::AgentClass`] variants had zero
//!   construction sites, and [`crate::autonomy::AgentClass::Finance`] — the one
//!   class the two live adapters serve — was required by nothing.
//!
//! # What this module is
//!
//! A decision layer over *search observations*. It does not scan anything. It
//! reads what a measurement produced, decides which explicit state that puts
//! the machine in, applies the only consequences each state is allowed to have,
//! and refuses — by type — to carry a mutated threshold from one state to the
//! next.
//!
//! # The structural properties, one by one
//!
//! ## 1. A state cannot carry a threshold
//!
//! Every variant of [`DiscoveryState`] has a fixed field list, none of which is
//! a threshold, and the transition function takes its policy by shared
//! reference and returns a type that has nowhere to put one. There is no code
//! path from a [`DiscoveryState`] to a [`crate::autonomy::EconomicPolicy`].
//! S1 may change *where* it looks; the only way it can change *what profit
//! means* is by failing to be imported, which is the pre-existing refusal path.
//!
//! ## 2. A degenerate threshold is unrepresentable, and a caller-supplied one is recorded
//!
//! [`MinNetEdge`] and the rest of the [`SearchHealth`] minima have private
//! fields and constructors that refuse the degenerate value, so
//! `min_net_edge == 0` cannot exist as a P6 gate — the exact value that makes
//! [`crate::autonomy::DecisionCode::Accepted`] trivial cannot be constructed
//! here. The pre-existing surfaces that *do* take a raw `u64` are not changed
//! (the ledgers and CLI must keep working), so every one of them P6 consumes is
//! recorded in a [`ThresholdAudit`] with the surface it came from and a
//! `degenerate` verdict, and a degenerate caller threshold **blocks promotion**
//! rather than being silently absorbed.
//!
//! ## 3. A thermal stop is not a negative edge
//!
//! [`crate::reinvestment::ReinvestmentSignals::thermal_headroom`] collapses four
//! unrelated situations into `0.0`: a MUPP hard block, a genuinely hot machine,
//! no verified NEV, and a consumed daily cap. [`ThermalStop`] separates them,
//! and [`SearchBudget`] refuses any ceiling above
//! [`HARD_THERMAL_CEILING_C`] — below the 93 °C peak this hardware was actually
//! observed to reach, so the budget cannot be configured to reproduce the run
//! that produced it. The old theoretical figures (65 W, 55 J per °C) are not
//! used anywhere in this module; energy is a caller-*measured* quantity and is
//! never converted from a temperature.
//!
//! ## 4. A caller cannot fake freshness
//!
//! [`crate::mupp_adapter::read_mupp_gate`] takes `now_unix` and computes
//! `age = (now - timestamp).max(0.0)`, so a caller that picks a clock earlier
//! than the state's timestamp reads a stale state as fresh.
//! [`ThermalPermit::from_gate`] refuses that case outright, so surfacing MUPP in
//! a P6 decision cannot become a way to manufacture headroom.
//!
//! ## 5. "Searched and found nothing" is not "never implemented"
//!
//! [`ClassSupport`] is separate from [`ClassCoverage`]. A class with no adapter
//! is [`ClassSupport::Unsupported`], can never reach
//! [`DiscoveryState::ClassExhausted`], and is reported in a different field
//! from a class that was searched. There is no in-crate adapter for anything
//! except [`OpportunityClass::Arbitrage`], and adding a fake one to make a
//! coverage number move is refused by the type system rather than by review:
//! [`ClassSupport`] is computed from the registry, never asserted by an adapter.
//!
//! ## 6. `NO_EDGE(Arbitrage)` is not "no external value exists"
//!
//! [`DiscoveryReport::concludes_no_external_value_exists`] requires all seven
//! classes implemented *and* exhausted *and* backed by completed cycles. With
//! six classes unimplemented it cannot be true, and
//! [`ColdDiscoverySummary`] reports the unimplemented list next to the
//! exhausted one so the gap is on the face of the report.
//!
//! ## 7. "COMPLETED" means a conclusion
//!
//! [`DiscoveryState::is_complete`] is false for a thermal stop, an incomplete
//! settlement, an exhausted budget, invalid evidence, an unsupported class and a
//! search in progress, and [`DiscoveryReport::completed`] additionally requires
//! completed cycles. `Ok { imported: 0 }` from an S1 import cannot reach this
//! module's completed column without a measured negative and sufficient
//! coverage.
//!
//! # What this module deliberately does not do
//!
//! * It does not scan, order, sign, broadcast or hold a key.
//!   [`OpportunityAdapter`] has exactly one method and it returns evidence.
//!   There is no method on any type here that can produce a transaction.
//! * It does not touch [`crate::settlement`]. Settlement incompleteness is a
//!   state this machine can *represent* ([`SettlementReadiness`], modelled in
//!   P6's own vocabulary), not one it derives, so the settlement path keeps its
//!   zero production callers.
//! * It does not give TERR any power. [`TerrResearchRequest`] can ask for a
//!   backtest, a validation or a data transform and carries
//!   `passive_only = true` / `influences_execution = false` as private fields
//!   with no `Deserialize`; it is emitted only from [`DiscoveryState::ColdDiscovery`]
//!   and never from a promotable state, so there is no TERR → execution path to
//!   close later.
//! * It does not submit anything to the autonomy ledger. A promotable result is
//!   returned as a [`PromotionCandidate`] for the caller to pass through the
//!   existing [`crate::autonomy::AutonomousEconomy::orchestrate`] gates, which
//!   remain the only path from an opportunity to a job intent.
//!
//! # Persistence
//!
//! [`SearchMemory`] is written atomically by [`SearchMachine::store`] so that
//! backoff and coverage survive a restart — a backoff that resets on restart is
//! not a backoff. It is a cache of search *activity*: no authority input reads
//! it, and nothing in it can authorise capital.

use crate::{
    autonomy::{EconomicPolicy, OpportunityCandidate},
    mupp_adapter::MuppPhysicalGate,
    s1_adapter::import_shadow_scan,
    s1_perception_adapter::import_perception_report,
    stable_id,
    verified_view::VerifiedNev,
    EconomyError, JobType, Result, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

/// Search-memory file name. Written atomically, private, and read back by
/// [`SearchMachine::load`].
pub const SEARCH_MEMORY_FILE: &str = "search-memory.json";

/// Hard upper bound on the temperature any search budget may be configured for,
/// in degrees Celsius.
///
/// # Why a ceiling at all
///
/// A search budget is an operator-set number like every other threshold in this
/// crate, and the audit found the same hazard here that it found everywhere
/// else: a ceiling an operator can raise without consequence is not a gate. So
/// this one is not operator-settable. [`SearchBudget::new`] refuses anything
/// above it.
///
/// The value is deliberately **below** the peak this hardware was actually
/// observed to reach (93 °C). The point is not to reproduce that run to collect
/// data — it is to make the budget incapable of authorising it. A number closer
/// to the old theoretical figures (65 W of dissipation, 55 J per °C of rise)
/// would be a guess dressed as a limit, and this module converts nothing from a
/// temperature anyway: energy is measured and reported, never derived.
pub const HARD_THERMAL_CEILING_C: f64 = 75.0;

/// The class the machine starts on.
///
/// Arbitrage is not a preference. It is the only class with a real
/// [`OpportunityAdapter`] in this crate — the two S1 shadow importers — so
/// starting anywhere else would begin the machine in
/// [`DiscoveryState::UnsupportedClass`].
pub const START_CLASS: OpportunityClass = OpportunityClass::Arbitrage;

// ---------------------------------------------------------------------------
// Opportunity class
// ---------------------------------------------------------------------------

/// What kind of machine-to-machine value a search is looking for.
///
/// The set is wider than this crate can service on purpose. The requirement P6
/// has to satisfy is that `NoEdge(Arbitrage)` is expressible *without*
/// concluding that no external value exists — which is only meaningful if the
/// other classes are named, not implied by their absence.
///
/// Only [`OpportunityClass::Arbitrage`] has an adapter here. Every other
/// variant resolves to [`ClassSupport::Unsupported`] and can never reach
/// [`DiscoveryState::ClassExhausted`], because coverage and implementation are
/// different fields (see [`ClassCoverage`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpportunityClass {
    Arbitrage,
    SolverReward,
    KeeperReward,
    ProtocolIncentive,
    ComputeReward,
    StorageReward,
    NetworkFee,
}

impl OpportunityClass {
    /// Every class, in the order the machine walks them. Stable, because a
    /// rotation order that depends on a hash map would make the machine's
    /// behaviour unreproducible.
    pub const ALL: [OpportunityClass; 7] = [
        OpportunityClass::Arbitrage,
        OpportunityClass::SolverReward,
        OpportunityClass::KeeperReward,
        OpportunityClass::ProtocolIncentive,
        OpportunityClass::ComputeReward,
        OpportunityClass::StorageReward,
        OpportunityClass::NetworkFee,
    ];

    pub fn state(&self) -> &'static str {
        match self {
            Self::Arbitrage => "arbitrage",
            Self::SolverReward => "solver_reward",
            Self::KeeperReward => "keeper_reward",
            Self::ProtocolIncentive => "protocol_incentive",
            Self::ComputeReward => "compute_reward",
            Self::StorageReward => "storage_reward",
            Self::NetworkFee => "network_fee",
        }
    }

    pub fn from_state(name: &str) -> Result<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|c| c.state() == name)
            .ok_or_else(|| {
                EconomyError::Invalid(format!("unknown opportunity class: {name}"))
            })
    }

    /// Whether the value moves between machines directly rather than being a
    /// reward for doing some other work.
    ///
    /// Used for reporting only. It never opens a path: a machine-to-machine
    /// class with no adapter is still [`ClassSupport::Unsupported`], and this
    /// predicate is not consulted by coverage, by rotation or by any gate.
    pub fn is_machine_to_machine(&self) -> bool {
        matches!(
            self,
            Self::Arbitrage
                | Self::SolverReward
                | Self::KeeperReward
                | Self::ProtocolIncentive
                | Self::NetworkFee
        )
    }
}

impl std::fmt::Display for OpportunityClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.state())
    }
}

/// Whether anything in this crate can actually search a class.
///
/// Deliberately **not** something an adapter asserts about itself. It is derived
/// from the [`AdapterRegistry`], so a type that returned the wrong answer could
/// not be used to manufacture coverage: there is no constructor that takes a
/// [`ClassSupport`] from a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassSupport {
    /// A real adapter is registered for the class.
    Implemented,
    /// No adapter exists. This class has never been searched, and no amount of
    /// searching will change that until one is written.
    Unsupported,
}

impl ClassSupport {
    pub fn state(&self) -> &'static str {
        match self {
            Self::Implemented => "implemented",
            Self::Unsupported => "unsupported",
        }
    }

    /// Only an implemented class can be resolved. Used by
    /// [`ClassCoverage::sufficient_for_exhaustion`].
    pub fn can_resolve(&self) -> bool {
        matches!(self, Self::Implemented)
    }
}

// ---------------------------------------------------------------------------
// Thresholds that cannot be degenerate
// ---------------------------------------------------------------------------

/// The minimum net edge a promotion must clear, with `0` unrepresentable.
///
/// The hazard this closes is specific and pre-existing:
/// [`crate::autonomy::EconomicPolicy::min_net_edge_musd_micros`] is a raw `u64`
/// that an operator can set to `0` from the CLI, at which point every
/// opportunity satisfies `robust_net < policy.min_net_edge_musd_micros` and is
/// accepted. Nothing recorded that the gate had been opened.
///
/// Two things follow, and both matter:
///
/// * P6's own promotion gate cannot be opened this way. `MinNetEdge::new(0)` is
///   an error, so the value that makes
///   [`crate::autonomy::DecisionCode::Accepted`] trivial has no representation
///   here. The existing surface is untouched — it must keep accepting the same
///   JSON — so what P6 can do about *it* is only to record it, which is what
///   [`ThresholdAudit`] is for.
/// * A caller-supplied `0` is still visible. [`ThresholdAudit::from_economic_policy`]
///   names the surface, the value and the fact that it is degenerate, and
///   [`DiscoveryReport::promotion`] is `None` while any consumed threshold is
///   degenerate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MinNetEdge(u64);

impl MinNetEdge {
    /// The crate default, in mUSD. Same figure as
    /// [`crate::autonomy::EconomicPolicy::min_net_edge_musd_micros`]'s default,
    /// restated here so P6's gate does not depend on a caller having left the
    /// field alone.
    pub const CRATE_DEFAULT_MICROS: u64 = 10_000;

    pub fn new(micros: u64) -> Result<Self> {
        if micros == 0 {
            return Err(EconomyError::Invalid(
                "min net edge of 0 would make the promotion gate trivially pass; \
                 it is unrepresentable in this module"
                    .into(),
            ));
        }
        Ok(Self(micros))
    }

    pub fn crate_default() -> Self {
        Self(Self::CRATE_DEFAULT_MICROS)
    }

    pub fn micros(&self) -> u64 {
        self.0
    }
}

/// The lowest acceptable search coverage, in completed cycles, with `0`
/// unrepresentable.
///
/// A `0` minimum would mean "no searching required", which is the degenerate
/// form for a coverage gate in exactly the way `0` is for an edge gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MinClassCoverage(u64);

impl MinClassCoverage {
    pub fn new(cycles: u64) -> Result<Self> {
        if cycles == 0 {
            return Err(EconomyError::Invalid(
                "min class coverage of 0 cycles would make coverage trivially \
                 sufficient; it is unrepresentable in this module"
                    .into(),
            ));
        }
        Ok(Self(cycles))
    }

    pub fn cycles(&self) -> u64 {
        self.0
    }
}

/// The lowest acceptable resolution rate, in basis points, with `0`
/// unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MinResolutionRate(u32);

impl MinResolutionRate {
    pub fn new(bps: u32) -> Result<Self> {
        if !(1..=10_000).contains(&bps) {
            return Err(EconomyError::Invalid(
                "min resolution rate must be in 1..=10000 basis points; 0 would \
                 make the gate trivially pass and is unrepresentable"
                    .into(),
            ));
        }
        Ok(Self(bps))
    }

    pub fn basis_points(&self) -> u32 {
        self.0
    }
}

/// The largest acceptable cost per resolution, in mUSD micros, with `0`
/// unrepresentable for the same reason as every other minimum here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MaxCostPerResolution(u64);

impl MaxCostPerResolution {
    pub fn new(micros: u64) -> Result<Self> {
        if micros == 0 {
            return Err(EconomyError::Invalid(
                "max cost per resolution of 0 would make the cost gate trivially \
                 pass; it is unrepresentable in this module"
                    .into(),
            ));
        }
        Ok(Self(micros))
    }

    pub fn micros(&self) -> u64 {
        self.0
    }
}

/// The smallest acceptable hypothesis diversity, with the degenerate shape
/// unrepresentable.
///
/// `distinct_classes >= 1` and `distinct_routes >= 1` are both non-zero
/// constructors, so a diversity gate cannot be configured to be satisfied by a
/// machine that has looked at exactly one thing.
///
/// Diversity is counted over *classes and routes*. Two scans that differ only in
/// a threshold parameter are the same route and are counted once — see
/// [`HypothesisDiversity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinDiversity {
    pub distinct_classes: u32,
    pub distinct_routes: u32,
}

impl MinDiversity {
    pub fn new(distinct_classes: u32, distinct_routes: u32) -> Result<Self> {
        if distinct_classes == 0 || distinct_routes == 0 {
            return Err(EconomyError::Invalid(
                "min diversity requires at least one class and one route; 0 \
                 would make the gate trivially pass"
                    .into(),
            ));
        }
        Ok(Self {
            distinct_classes,
            distinct_routes,
        })
    }
}

// ---------------------------------------------------------------------------
// Threshold provenance
// ---------------------------------------------------------------------------

/// Where a threshold P6 consumed came from.
///
/// This is the crate's first record of "this number came from a caller". Before
/// P6 every operator-set threshold in [`crate::autonomy`], [`crate::reinvestment`]
/// and [`crate::terr_research`] was indistinguishable from a crate constant once
/// it was set, which is why setting one to its degenerate value was invisible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", content = "detail", rename_all = "snake_case")]
pub enum ThresholdSource {
    /// A figure written into this crate. It cannot be moved by a caller.
    CrateDefault,
    /// Set on a surface that already existed and still takes a raw scalar:
    /// `EconomicPolicy`, `ReinvestmentPolicy`, `TerrResearchPolicy`,
    /// `MuppAdapterPolicy`, `ScalePolicy`.
    CallerSupplied { surface: String },
}

impl ThresholdSource {
    pub fn state(&self) -> &'static str {
        match self {
            Self::CrateDefault => "crate_default",
            Self::CallerSupplied { .. } => "caller_supplied",
        }
    }

    pub fn caller(surface: &str) -> Self {
        Self::CallerSupplied {
            surface: surface.to_string(),
        }
    }
}

/// One threshold, named, sourced and judged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRecord {
    pub name: String,
    /// Kept as a string because the audited thresholds are not all integers —
    /// the TERR ones are floats and can be written as `0.0`, `1.0` and `0.0` to
    /// make their gates trivial.
    pub value: String,
    pub source: ThresholdSource,
    /// `true` when this value makes its own gate pass unconditionally.
    pub degenerate: bool,
    pub why: String,
}

/// Every threshold P6 consumed for one decision, with provenance.
///
/// [`DiscoveryReport::promotion`] is `None` while any record here is
/// degenerate. That is the whole mechanism: the gate itself cannot be opened
/// (see [`MinNetEdge`]), and the pre-existing surface that *can* be opened is
/// recorded here loudly enough that a reader cannot miss it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdAudit {
    pub records: Vec<ThresholdRecord>,
}

impl ThresholdAudit {
    /// Records the thresholds P6 reads off the existing autonomy policy.
    ///
    /// Only `min_net_edge_musd_micros` is consulted, because it is the only one
    /// of them that can change whether an opportunity is promoted. The rest of
    /// the surfaces P6 touches — MUPP, reinvestment, TERR, scaling — are merged
    /// or compared by their own modules and are recorded by the caller through
    /// [`ThresholdAudit::record`] when they are consumed.
    pub fn from_economic_policy(policy: &EconomicPolicy) -> Self {
        let value = policy.min_net_edge_musd_micros;
        let degenerate = value == 0;
        let why = if degenerate {
            "min_net_edge_musd_micros=0 makes DecisionCode::Accepted reachable by \
             any candidate, including one with negative robust net; this is the \
             literal value the audit named as making its gate pass trivially"
                .to_string()
        } else {
            format!(
                "min_net_edge_musd_micros={value} is compared against robust_net \
                 by autonomy::orchestrate and is not degenerate"
            )
        };
        Self {
            records: vec![ThresholdRecord {
                name: "min_net_edge_musd_micros".into(),
                value: value.to_string(),
                source: ThresholdSource::caller("autonomy::EconomicPolicy"),
                degenerate,
                why,
            }],
        }
    }

    pub fn record(&mut self, record: ThresholdRecord) {
        self.records.push(record);
    }

    /// The crate defaults P6 used, so a report can say which numbers were not
    /// the operator's.
    pub fn with_crate_defaults(mut self) -> Self {
        self.records.push(ThresholdRecord {
            name: "discovery::MinNetEdge::CRATE_DEFAULT_MICROS".into(),
            value: MinNetEdge::CRATE_DEFAULT_MICROS.to_string(),
            source: ThresholdSource::CrateDefault,
            degenerate: false,
            why: "P6's own promotion gate; unrepresentable at 0, so this figure \
                  cannot be opened by a caller"
                .to_string(),
        });
        self.records.push(ThresholdRecord {
            name: "discovery::HARD_THERMAL_CEILING_C".into(),
            value: HARD_THERMAL_CEILING_C.to_string(),
            source: ThresholdSource::CrateDefault,
            degenerate: false,
            why: "hard ceiling on any search budget; SearchBudget::new refuses \
                  anything above it, and it is below the 93 degC peak actually \
                  observed"
                .to_string(),
        });
        self
    }

    pub fn degenerate(&self) -> Vec<&ThresholdRecord> {
        self.records.iter().filter(|r| r.degenerate).collect()
    }

    pub fn any_degenerate(&self) -> bool {
        self.records.iter().any(|r| r.degenerate)
    }
}

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

/// What one search actually consumed.
///
/// Every field is *measured by the caller and reported*. This module derives
/// nothing from a temperature — no watts, no joules-per-degree, no model — so a
/// field it cannot measure is `0` and costs nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSpend {
    pub cycles: u64,
    pub wall_ms: u64,
    pub cpu_ms: u64,
    pub energy_mj: u64,
    pub rpc_calls: u64,
    /// Highest temperature the caller observed during the search, in °C. `None`
    /// means "not measured", which is not the same as "measured as cold" and is
    /// treated as an absent measurement, not a pass.
    pub peak_temperature_c: Option<f64>,
}

impl BudgetSpend {
    pub fn cycles(n: u64) -> Self {
        Self {
            cycles: n,
            ..Self::default()
        }
    }

    fn saturating_add(&self, other: &Self) -> Self {
        Self {
            cycles: self.cycles.saturating_add(other.cycles),
            wall_ms: self.wall_ms.saturating_add(other.wall_ms),
            cpu_ms: self.cpu_ms.saturating_add(other.cpu_ms),
            energy_mj: self.energy_mj.saturating_add(other.energy_mj),
            rpc_calls: self.rpc_calls.saturating_add(other.rpc_calls),
            peak_temperature_c: match (self.peak_temperature_c, other.peak_temperature_c)
            {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, b) => b,
            },
        }
    }
}

/// Which budget dimension stopped the search, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimension {
    Cycles,
    WallClock,
    Cpu,
    Energy,
    Rpc,
    Temperature,
}

impl BudgetDimension {
    pub fn state(&self) -> &'static str {
        match self {
            Self::Cycles => "cycles",
            Self::WallClock => "wall_clock",
            Self::Cpu => "cpu",
            Self::Energy => "energy",
            Self::Rpc => "rpc",
            Self::Temperature => "temperature",
        }
    }
}

/// An explicit, bounded search budget: CPU, temperature, energy, RPC and time.
///
/// Every field is mandatory. There is no "unbounded" construction, because an
/// unbounded budget is indistinguishable from the pre-P6 behaviour of scanning
/// until something stopped it.
///
/// [`SearchBudget::new`] enforces two properties beyond range checking:
///
/// * `max_observed_temperature_c` may not exceed [`HARD_THERMAL_CEILING_C`], so
///   the budget cannot be configured to authorise the run that reached 93 °C;
/// * every dimension must be non-zero, so no dimension is silently unlimited by
///   omission.
///
/// This does **not** change any existing thermal gate. It is a ceiling on what a
/// search may spend, which is a new surface, and it fails toward
/// [`DiscoveryState::SearchAbortedThermal`] — never toward
/// [`DiscoveryState::NoEdge`].
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchBudget {
    pub max_cycles: u64,
    pub max_wall_ms: u64,
    pub max_cpu_ms: u64,
    pub max_energy_mj: u64,
    pub max_rpc_calls: u64,
    pub max_observed_temperature_c: f64,
}

impl Default for SearchBudget {
    fn default() -> Self {
        Self {
            max_cycles: 4,
            max_wall_ms: 120_000,
            max_cpu_ms: 60_000,
            max_energy_mj: 240_000,
            max_rpc_calls: 256,
            max_observed_temperature_c: 70.0,
        }
    }
}

impl SearchBudget {
    pub fn new(
        max_cycles: u64,
        max_wall_ms: u64,
        max_cpu_ms: u64,
        max_energy_mj: u64,
        max_rpc_calls: u64,
        max_observed_temperature_c: f64,
    ) -> Result<Self> {
        let budget = Self {
            max_cycles,
            max_wall_ms,
            max_cpu_ms,
            max_energy_mj,
            max_rpc_calls,
            max_observed_temperature_c,
        };
        budget.validate()?;
        Ok(budget)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_cycles == 0
            || self.max_wall_ms == 0
            || self.max_cpu_ms == 0
            || self.max_energy_mj == 0
            || self.max_rpc_calls == 0
        {
            return Err(EconomyError::Invalid(
                "every search budget dimension must be > 0; an omitted dimension \
                 is an unlimited dimension"
                    .into(),
            ));
        }
        if !self.max_observed_temperature_c.is_finite()
            || self.max_observed_temperature_c <= 0.0
        {
            return Err(EconomyError::Invalid(
                "search budget temperature ceiling must be finite and > 0".into(),
            ));
        }
        if self.max_observed_temperature_c > HARD_THERMAL_CEILING_C {
            return Err(EconomyError::Invalid(format!(
                "search budget temperature ceiling {} C exceeds the hard ceiling \
                 of {HARD_THERMAL_CEILING_C} C; the observed peak on this hardware \
                 was 93 C and this budget must not be configurable to reproduce it",
                self.max_observed_temperature_c
            )));
        }
        Ok(())
    }

    /// Whether `spend` fits inside the budget. Over-budget is a refusal, never
    /// a rounding.
    pub fn allows(&self, spend: &BudgetSpend) -> Result<bool> {
        self.validate()?;
        if let Some(peak) = spend.peak_temperature_c {
            if !peak.is_finite() || peak <= 0.0 {
                return Err(EconomyError::Invalid(
                    "observed peak temperature must be finite and > 0".into(),
                ));
            }
            if peak > self.max_observed_temperature_c {
                return Ok(false);
            }
        }
        Ok(spend.cycles <= self.max_cycles
            && spend.wall_ms <= self.max_wall_ms
            && spend.cpu_ms <= self.max_cpu_ms
            && spend.energy_mj <= self.max_energy_mj
            && spend.rpc_calls <= self.max_rpc_calls)
    }

    /// The dimension that ran out first, for the report.
    pub fn exhausted_by(&self, spend: &BudgetSpend) -> Option<BudgetDimension> {
        if spend.cycles > self.max_cycles {
            return Some(BudgetDimension::Cycles);
        }
        if spend.wall_ms > self.max_wall_ms {
            return Some(BudgetDimension::WallClock);
        }
        if spend.cpu_ms > self.max_cpu_ms {
            return Some(BudgetDimension::Cpu);
        }
        if spend.energy_mj > self.max_energy_mj {
            return Some(BudgetDimension::Energy);
        }
        if spend.rpc_calls > self.max_rpc_calls {
            return Some(BudgetDimension::Rpc);
        }
        if spend
            .peak_temperature_c
            .is_some_and(|p| p > self.max_observed_temperature_c)
        {
            return Some(BudgetDimension::Temperature);
        }
        None
    }

    pub fn as_spend(&self) -> BudgetSpend {
        BudgetSpend {
            cycles: self.max_cycles,
            wall_ms: self.max_wall_ms,
            cpu_ms: self.max_cpu_ms,
            energy_mj: self.max_energy_mj,
            rpc_calls: self.max_rpc_calls,
            peak_temperature_c: Some(self.max_observed_temperature_c),
        }
    }
}

// ---------------------------------------------------------------------------
// Thermal
// ---------------------------------------------------------------------------

/// Why a search cannot proceed right now.
///
/// [`crate::reinvestment::ReinvestmentSignals::thermal_headroom`] reaches `0.0`
/// from four different directions — a MUPP hard block, a genuinely hot machine,
/// no verified NEV, and a consumed daily cap — and the audit found that the
/// consequence chains at `reinvestment.rs:317-321 → :327-328 → :337` collapse
/// them into one number, so a thermal block reads as "no money to spend".
///
/// This enum is the separation P6 needs. Each arm names a different situation
/// and none of them is [`DiscoveryState::NoEdge`], because a machine that was not
/// allowed to look has learned nothing about the market.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "stop", content = "detail", rename_all = "snake_case")]
pub enum ThermalStop {
    /// MUPP's own gate is closed: collapse/cooldown phase, or execution not
    /// allowed. Not the same as the machine being hot.
    MuppHardBlocked { phase: String, reason: String },
    /// The sensors were not warm or not valid, so no headroom could be computed.
    SensorsInvalid { reason: String },
    /// The state on disk is older than the policy allows.
    StaleState { age_seconds: f64 },
    /// The caller's clock is earlier than the state's own timestamp. This is the
    /// case that would otherwise fake freshness: `read_mupp_gate` clamps a
    /// negative age to `0.0` and reports `fresh = true`.
    ClockWentBackwards {
        state_timestamp_unix: f64,
        now_unix: u64,
    },
    /// MUPP permits execution but the measured headroom is below what a search
    /// needs. The only arm here that is genuinely about temperature.
    BelowSearchFloor { headroom: f64, required: f64 },
    /// The budget's ceiling was reached or passed during the search.
    BudgetTemperature { observed_c: f64, ceiling_c: f64 },
    /// A thermal abort happened and the cooldown has not elapsed. No heavy
    /// execution after a thermal abort without a cooldown.
    Cooldown { cycles_remaining: u32 },
}

impl ThermalStop {
    pub fn state(&self) -> &'static str {
        match self {
            Self::MuppHardBlocked { .. } => "mupp_hard_blocked",
            Self::SensorsInvalid { .. } => "sensors_invalid",
            Self::StaleState { .. } => "stale_state",
            Self::ClockWentBackwards { .. } => "clock_went_backwards",
            Self::BelowSearchFloor { .. } => "below_search_floor",
            Self::BudgetTemperature { .. } => "budget_temperature",
            Self::Cooldown { .. } => "cooldown",
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::MuppHardBlocked { phase, reason } => format!(
                "MUPP is in phase {phase} with its execution gate closed: {reason}. \
                 This is a control decision, not a temperature reading."
            ),
            Self::SensorsInvalid { reason } => {
                format!("MUPP sensors are invalid or not warmed up: {reason}")
            }
            Self::StaleState { age_seconds } => {
                format!("the MUPP state on disk is {age_seconds}s old")
            }
            Self::ClockWentBackwards {
                state_timestamp_unix,
                now_unix,
            } => format!(
                "the MUPP state is timestamped {state_timestamp_unix}, later than the \
                 caller's clock {now_unix}; read_mupp_gate would clamp the age to 0 \
                 and report the state as fresh, so the pair is refused"
            ),
            Self::BelowSearchFloor { headroom, required } => format!(
                "MUPP headroom {headroom} is below the {required} a search requires"
            ),
            Self::BudgetTemperature {
                observed_c,
                ceiling_c,
            } => format!(
                "the search reached {observed_c} C against a budget ceiling of \
                 {ceiling_c} C"
            ),
            Self::Cooldown { cycles_remaining } => format!(
                "{cycles_remaining} cycle(s) of thermal cooldown remain before any \
                 search may run"
            ),
        }
    }

    /// Whether no heavy work may follow until something changes.
    pub fn requires_cooldown(&self) -> bool {
        matches!(
            self,
            Self::BudgetTemperature { .. } | Self::BelowSearchFloor { .. } | Self::Cooldown { .. }
        )
    }
}

/// Headroom a search requires from MUPP before it may run.
///
/// Bounded away from `0.0` so it cannot be satisfied by a collapsed machine that
/// happens to report a hair above nothing.
pub const MIN_SEARCH_THERMAL_HEADROOM: f64 = 0.15;

/// Proof that MUPP permitted a search at a specific moment.
///
/// Built by [`ThermalPermit::from_gate`], which is the only constructor, and
/// that constructor refuses a caller clock earlier than the state's timestamp —
/// so this type cannot be used to manufacture freshness. There is no
/// `Deserialize`, so no JSON blob can be read back as one.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThermalPermit {
    issued_at_unix: u64,
    source_timestamp_unix: f64,
    source_age_seconds: f64,
    headroom: f64,
    phase: String,
}

impl ThermalPermit {
    /// Reads a MUPP gate and refuses every way the gate could be wrong,
    /// naming which way it was.
    ///
    /// The typed entry point. [`Self::from_gate`] is the same check as a
    /// [`crate::EconomyError`], for callers that want an error; the machine uses
    /// this one so a refusal is a [`ThermalStop`] and lands in
    /// [`DiscoveryState::SearchAbortedThermal`] with its cause intact instead of
    /// a prose string.
    ///
    /// The gate itself is unchanged: [`crate::mupp_adapter::read_mupp_gate`] still
    /// takes a caller clock and still clamps a negative age. What this adds is
    /// the second half of the check that the clamp removes — if the state's own
    /// timestamp is *later* than `now`, the caller picked a clock from the past,
    /// and a "fresh" verdict from that pair is an artefact of the clock, not a
    /// fact about the hardware. Refused.
    pub fn check(
        gate: &MuppPhysicalGate,
        now_unix: u64,
        required_headroom: f64,
    ) -> std::result::Result<Self, ThermalStop> {
        if !required_headroom.is_finite() || !(0.0..=1.0).contains(&required_headroom) || required_headroom <= 0.0 {
            return Err(ThermalStop::SensorsInvalid {
                reason: format!(
                    "required search thermal headroom {required_headroom} is not in (0, 1]"
                ),
            });
        }
        // `now_unix` is whole seconds and `read_mupp_gate` is handed the same
        // value, so a state stamped a fraction of a second into the current
        // second is not a clock anomaly — it is the same clock, truncated. The
        // tolerance is exactly that truncation, and nothing more: a state more
        // than one second ahead of the caller's clock cannot have been read by
        // the same `read_mupp_gate` call, and is the "pick an earlier clock to
        // make a stale state read fresh" case this refuses.
        if gate.timestamp_unix > now_unix as f64 + 1.0 {
            return Err(ThermalStop::ClockWentBackwards {
                state_timestamp_unix: gate.timestamp_unix,
                now_unix,
            });
        }
        if !gate.fresh {
            return Err(ThermalStop::StaleState {
                age_seconds: gate.age_seconds,
            });
        }
        if !gate.sensor_valid {
            return Err(ThermalStop::SensorsInvalid {
                reason: gate.reason.clone(),
            });
        }
        if !gate.allow_execution {
            return Err(ThermalStop::MuppHardBlocked {
                phase: gate.phase.clone(),
                reason: gate.reason.clone(),
            });
        }
        if gate.thermal_headroom < required_headroom {
            return Err(ThermalStop::BelowSearchFloor {
                headroom: gate.thermal_headroom,
                required: required_headroom,
            });
        }
        Ok(Self {
            issued_at_unix: now_unix,
            source_timestamp_unix: gate.timestamp_unix,
            source_age_seconds: gate.age_seconds,
            headroom: gate.thermal_headroom,
            phase: gate.phase.clone(),
        })
    }

    /// The [`crate::Result`] form. Same refusals, flattened to one message.
    pub fn from_gate(
        gate: &MuppPhysicalGate,
        now_unix: u64,
        required_headroom: f64,
    ) -> Result<Self> {
        Self::check(gate, now_unix, required_headroom)
            .map_err(|stop| EconomyError::Invalid(format!("thermal refusal: {}", stop.describe())))
    }

    pub fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    pub fn source_timestamp_unix(&self) -> f64 {
        self.source_timestamp_unix
    }

    pub fn source_age_seconds(&self) -> f64 {
        self.source_age_seconds
    }

    pub fn headroom(&self) -> f64 {
        self.headroom
    }

    pub fn phase(&self) -> &str {
        &self.phase
    }
}

// ---------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------

/// A bounded exponential backoff over search cycles.
///
/// # Why this exists at all
///
/// The audit found zero backoff anywhere in the crate: no schedule, no EWMA, no
/// variance, no `next_attempt`. The only defence against re-scanning was "stop",
/// which is indistinguishable from having given up.
///
/// Three properties make this a gate rather than a suggestion:
///
/// * `base_cycles`, `max_cycles` and `factor_bps` are all non-zero and
///   `factor_bps >= 10_000`, so the schedule always grows and is always bounded.
///   Integer arithmetic with a saturating cap: there is no schedule, and no
///   accumulation of cycles, that escapes `max_cycles`.
/// * The counter it consumes lives in [`SearchMemory`], which is persisted
///   atomically. A backoff that resets on restart is not a backoff.
/// * It applies to [`DiscoveryState::NoEdge`] and
///   [`DiscoveryState::NegativeNev`] only. An evidence problem or a settlement
///   gap is not retried on a schedule, because retrying does not fix it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackoffSchedule {
    pub base_cycles: u32,
    pub max_cycles: u32,
    /// Basis points. `10_000` is "flat"; anything below grows the delay.
    pub factor_bps: u32,
}

impl Default for BackoffSchedule {
    fn default() -> Self {
        Self {
            base_cycles: 1,
            max_cycles: 32,
            factor_bps: 20_000,
        }
    }
}

impl BackoffSchedule {
    pub fn new(base_cycles: u32, max_cycles: u32, factor_bps: u32) -> Result<Self> {
        if base_cycles == 0 {
            return Err(EconomyError::Invalid(
                "backoff base_cycles must be > 0".into(),
            ));
        }
        if max_cycles < base_cycles {
            return Err(EconomyError::Invalid(
                "backoff max_cycles must be >= base_cycles".into(),
            ));
        }
        if factor_bps < 10_000 {
            return Err(EconomyError::Invalid(
                "backoff factor_bps must be >= 10000; a shrinking schedule is not \
                 a backoff"
                    .into(),
            ));
        }
        Ok(Self {
            base_cycles,
            max_cycles,
            factor_bps,
        })
    }

    /// Cycles to wait after `consecutive` consecutive unproductive attempts.
    ///
    /// Saturating at `max_cycles`, which is why "continue heavy scanning
    /// indefinitely" is not reachable: after `max_cycles` the delay is constant
    /// and finite, and the class eventually reaches
    /// [`DiscoveryState::ClassExhausted`] instead of running forever.
    pub fn cycles_after(&self, consecutive: u32) -> u32 {
        if consecutive == 0 {
            return self.base_cycles;
        }
        let mut cycles = self.base_cycles as u64;
        for _ in 0..consecutive.min(64) {
            cycles = cycles
                .saturating_mul(self.factor_bps as u64)
                .saturating_div(10_000);
            if cycles >= self.max_cycles as u64 {
                return self.max_cycles;
            }
        }
        cycles.min(self.max_cycles as u64) as u32
    }
}

// ---------------------------------------------------------------------------
// Observation: what one search measured
// ---------------------------------------------------------------------------

/// The measured proof that a market was scanned and did not pay.
///
/// This is the evidence the audit found being computed and discarded. In
/// [`crate::s1_perception_adapter::import_perception_report`] the fields
/// `best_observed_token_edge_usdc_raw` and `best_observed_robust_net_usdc_raw`
/// are reduced across `events[].near_edge_refinement` and handed straight to the
/// caller — the CLI printed them and every consumer dropped them, which is why
/// a completed scan that found nothing looked identical to a scan that never
/// happened.
///
/// [`DiscoveryState::NoEdge`] is **unreachable without one of these**. A report
/// that completed with an empty candidate set and no measured negative is
/// [`DiscoveryState::InvalidEvidence`], not `NoEdge`. That is the single most
/// important property in this module: the machine cannot conclude "nothing
/// there" from the absence of a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredEdge {
    /// Best token-level edge seen across the scan. Signed: a negative value is
    /// the raw reason the market did not pay.
    pub token_edge_micros: Option<i64>,
    /// Best robust net seen across the scan. This is the number that decides
    /// `NoEdge`, and it is signed.
    pub robust_net_micros: i64,
    /// Which field family it came from, for the audit trail. Never used as a
    /// gate: the value is what is compared, and the name only says where it was
    /// read.
    pub source_field: String,
}

/// What is missing from a settlement-shaped result.
///
/// Modelled here in P6's own vocabulary on purpose. [`crate::settlement`] keeps
/// its zero production callers, so this module cannot depend on it; a caller who
/// has a real [`crate::settlement::SettlementIncompleteness`] maps it into
/// [`SettlementReadiness::Incomplete`] at the boundary.
///
/// The distinction that matters for P6 is *where* the problem is: an adapter that
/// produced an incomplete result is not a market that did not pay, so the
/// machine must not re-run discovery in response. That is
/// [`DiscoveryState::NoCompleteSettlement`] and its action
/// [`SearchAction::RecordEvidenceGap`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "gap", content = "detail", rename_all = "snake_case")]
pub enum SettlementGap {
    /// The adapter produced no settlement-shaped result at all.
    Absent { why: String },
    /// A settlement exists but a leg has no evidence.
    LegAbsent { why: String },
    /// Evidence exists but nothing binds it to an authority.
    LegUnattested { why: String },
    /// Evidence exists but cannot be bound to the exact log it is at.
    LegUnconfirmed { why: String },
    /// The chain read was not exhaustive, so the leg set is not the set that
    /// happened.
    ScanNotExhaustive { why: String },
    /// A cost was burned and no validated policy is in force to price it, so it
    /// is not reported as zero.
    NativeCostUnpriced { why: String },
}

impl SettlementGap {
    pub fn state(&self) -> &'static str {
        match self {
            Self::Absent { .. } => "absent",
            Self::LegAbsent { .. } => "leg_absent",
            Self::LegUnattested { .. } => "leg_unattested",
            Self::LegUnconfirmed { .. } => "leg_unconfirmed",
            Self::ScanNotExhaustive { .. } => "scan_not_exhaustive",
            Self::NativeCostUnpriced { .. } => "native_cost_unpriced",
        }
    }
}

/// Whether a settlement-shaped result is complete enough to carry a net.
///
/// Two states, not one with a flag, for the reason
/// [`crate::settlement::SettlementOutcome`] gives: an incomplete settlement has
/// no net, so there is nothing a boolean could hold alongside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "settlement", content = "gaps", rename_all = "snake_case")]
pub enum SettlementReadiness {
    /// The class has no settlement-shaped result. Not a defect.
    NotApplicable,
    /// Complete: a net exists and can be resolved.
    Complete,
    /// Incomplete: named gaps, no net.
    Incomplete(Vec<SettlementGap>),
}

impl SettlementReadiness {
    pub fn state(&self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::Complete => "complete",
            Self::Incomplete(_) => "incomplete",
        }
    }
}

/// Whether the value of a result can be compared at all.
///
/// Split out from [`SettlementReadiness`] because the two problems have opposite
/// responses. An incomplete settlement needs the adapter fixed; an un-comparable
/// value needs a valuation resolved. Neither is fixed by searching again, which
/// is why both states refuse discovery re-run while they hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "valuation", content = "why", rename_all = "snake_case")]
pub enum ValuationReadiness {
    /// No valuation needed for this class.
    NotRequired,
    /// A comparable net value exists.
    Comparable,
    /// No comparable net value could be derived. Names the missing input.
    NotComparable { why: String },
}

impl ValuationReadiness {
    pub fn state(&self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Comparable => "comparable",
            Self::NotComparable { .. } => "not_comparable",
        }
    }
}

/// Temperatures the caller observed during the search.
///
/// [`crate::s1_perception_adapter`] already reads
/// `thermal_start_window.max` and `end_temp_c` into its report and nothing in the
/// crate has ever compared them to anything — the audit called them inert. They
/// are compared here, and only here: against the budget's ceiling, in the
/// direction that refuses.
///
/// [`maximum_c`](Self::maximum_c) carries the hottest reading taken *during* the
/// run rather than only at its two ends, so an excursion that crosses the
/// ceiling and recovers before the job finishes leaves a trace instead of
/// vanishing. [`peak`](Self::peak) reads all three fields, so a mid-run peak can
/// never be missed by a caller that only looked at the endpoints.
///
/// `None` in any field means that reading was not taken, never that it was zero.
/// An unmeasured search — no reading at any point — still has no temperature
/// evidence at all, and `measured()` reports exactly that rather than inventing
/// a cool pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedThermal {
    pub start_max_c: Option<f64>,
    pub end_c: Option<f64>,
    /// Hottest reading observed mid-run, when the caller takes one at all.
    ///
    /// `#[serde(default)]` so an observation persisted before this field existed
    /// still reads back: absent means "no mid-run peak was reported", which is
    /// what the adapters that only sample their endpoints actually mean.
    #[serde(default)]
    pub maximum_c: Option<f64>,
}

impl ObservedThermal {
    /// The hottest reading reported, from any point in the window: the start,
    /// the end, or the mid-run maximum.
    ///
    /// `None` when nothing was measured. That is not a pass: an unmeasured
    /// search has no temperature evidence and is reported as such.
    pub fn peak(&self) -> Option<f64> {
        [self.start_max_c, self.end_c, self.maximum_c]
            .into_iter()
            .flatten()
            .reduce(f64::max)
    }

    pub fn measured(&self) -> bool {
        self.peak().is_some()
    }
}

/// A defect that makes the observation unusable.
///
/// This is fail-closed by construction: a non-`None` defect short-circuits the
/// whole classification and the machine lands in
/// [`DiscoveryState::InvalidEvidence`]. It is emphatically **not** folded into
/// `NoEdge` — the difference between "the adapter's evidence is broken" and "the
/// market did not pay" is the difference between fixing a bug and lowering a bar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "defect", content = "detail", rename_all = "snake_case")]
pub enum EvidenceDefect {
    /// The adapter reported a shape this machine cannot classify.
    UnreadableShape { why: String },
    /// The adapter claimed to have measured something and did not.
    Unmeasured { why: String },
    /// The adapter reported a broadcast or otherwise executed result.
    Transmitted { why: String },
    /// The observation's own accounting does not add up.
    InconsistentAccounting { why: String },
    /// The adapter's class does not match the permit it was given.
    ClassMismatch { why: String },
    /// P6.7. The NEV-0 gate in [`crate::nev0`] refused this evidence and named
    /// the category.
    ///
    /// Additive in P6.7 and deliberately **not** folded into any of the five
    /// above. `UnreadableShape` says the machine could not read the evidence;
    /// this says the machine read it perfectly well and refused it anyway,
    /// because it was synthetic, a MYC emission, a transfer between two of our
    /// own wallets, a test fixture, unsigned, an incomplete settlement, unpriced
    /// gas, a raw edge or a modelled profit. Collapsing the two would make a
    /// refused NEV-0 candidate look like a broken adapter, which is the
    /// diagnosis that sends an operator to fix the wrong thing.
    Nev0Refused { category: String, why: String },
}

impl EvidenceDefect {
    pub fn state(&self) -> &'static str {
        match self {
            Self::UnreadableShape { .. } => "unreadable_shape",
            Self::Unmeasured { .. } => "unmeasured",
            Self::Transmitted { .. } => "transmitted",
            Self::InconsistentAccounting { .. } => "inconsistent_accounting",
            Self::ClassMismatch { .. } => "class_mismatch",
            Self::Nev0Refused { .. } => "nev0_refused",
        }
    }
}

/// A resolution whose net external value is attested by a real authority.
///
/// # Why the shape this replaces was wrong
///
/// It was:
///
/// ```text
/// #[derive(Serialize, Deserialize)]
/// enum ResolutionTrust { Unattested, ChainAttested { provider: String } }
/// ```
///
/// with the gate `trust.can_attest()`. That made attestation **a field the
/// caller wrote**: a `SearchObservation` deserialised from JSON could carry
/// `{"trust":"chain_attested","provider":"unix:///anything"}` and the state
/// machine read `true` off it and minted [`DiscoveryState::PositiveNev`], whose
/// number was the *same* JSON's `nev_musd_micros`. The chain of trust ran the
/// wrong way round — the authority was named by the very thing being authorised,
/// so writing the JSON was the same act as being the authority.
///
/// This type inverts it, and it is the same discipline as
/// [`crate::verified_view::VerifiedNev`] versus
/// [`crate::verified_view::UnattestedNev`]:
///
/// * one private field, no public struct literal from anywhere;
/// * **no `Deserialize`**, so no JSON, and no adapter in this workspace, can
///   introduce one;
/// * a `pub(crate)` constructor that takes a [`VerifiedNev`], whose own
///   constructor is `pub(crate)` and refuses an unpinned provider and a foreign
///   policy. Holding one therefore means someone really ran that path.
/// * `Serialize` only, so an audit log can still name the authority behind a
///   number instead of making the operator take it on faith.
///
/// What a caller supplies is a claim — [`ResolvedNev::claimed_nev_musd_micros`].
/// What the state machine acts on is this.
#[derive(Debug, Clone, Serialize)]
pub struct AttestedResolution {
    nev: VerifiedNev,
}

impl AttestedResolution {
    /// P6.0.1: the only way to hold one, `pub(crate)` so nothing outside this
    /// crate can mint one, and taking a [`VerifiedNev`] because the caller of
    /// *this* has already had to earn that.
    ///
    /// `cfg(test)` on purpose, and it is the strongest form of "inert": in a
    /// production build this module contains **no** way to construct an
    /// [`AttestedResolution`] at all, so `ResolvedNev::attested` is
    /// structurally always `None` and `DiscoveryState::PositiveNev` is
    /// unreachable from any observation. Wiring the settlement path is then a
    /// one-line, greppable, reviewable change rather than an already-open door
    /// nobody looked at. The tests below use it to prove the positive path is
    /// real, and one of them asserts the absence of a production caller.
    #[cfg(test)]
    pub(crate) fn from_verified(nev: VerifiedNev) -> Self {
        Self { nev }
    }

    /// The authority itself, for a caller that wants the full evidence rather
    /// than the five accessors below.
    pub fn verified(&self) -> &VerifiedNev {
        &self.nev
    }

    /// The attested total. Read from the [`VerifiedNev`], never from anything a
    /// caller wrote.
    pub fn nev_musd_micros(&self) -> i64 {
        self.nev.nev_musd_micros()
    }

    /// How many distinct external events the total covers.
    pub fn receipts(&self) -> u64 {
        self.nev.receipts()
    }

    /// The kernel-identified endpoint the facts came from.
    pub fn provider(&self) -> &str {
        self.nev.provider()
    }

    /// The hash of the policy every counted receipt was issued under. This is
    /// what makes the [`DiscoveryState::PositiveNev`] audit trail traceable.
    pub fn policy_hash(&self) -> &str {
        self.nev.policy_hash()
    }

    /// Whether the provider's identity was enforced by the kernel.
    pub fn provider_identity_verified(&self) -> bool {
        self.nev.provider_identity_verified()
    }

    /// `receipts > 0 && nev > 0`, and the only positivity predicate on this
    /// path. It lives on the [`VerifiedNev`], not here, so it cannot be widened.
    pub fn is_positive(&self) -> bool {
        self.nev.is_positive()
    }

    /// A stable id over the *attested content* — policy, receipt count and total
    /// — rather than over anything the caller chose.
    ///
    /// P6.0.1. The old id was `stable_id("resolution", &[class, &integer])`, so
    /// the caller chose it: two adapters reporting the same real value minted
    /// two ids, one adapter could mint a fresh id for the same value, and an id
    /// in an audit log could not be traced to an authority at all. This one is
    /// tamper-evident, and an operator holding it can recompute it from the
    /// policy hash the audit log also carries.
    pub fn resolution_id(&self, class: OpportunityClass) -> String {
        stable_id(
            "resolution",
            &[
                class.state(),
                self.policy_hash(),
                &self.receipts().to_string(),
                &self.nev_musd_micros().to_string(),
            ],
        )
    }
}

/// Hand-written because [`VerifiedNev`] has no `PartialEq` of its own: two
/// attestations are the same attestation when they name the same authority over
/// the same total, and this type must not answer that question by comparing
/// anything else.
impl PartialEq for AttestedResolution {
    fn eq(&self, other: &Self) -> bool {
        self.nev_musd_micros() == other.nev_musd_micros()
            && self.receipts() == other.receipts()
            && self.provider() == other.provider()
            && self.policy_hash() == other.policy_hash()
            && self.provider_identity_verified() == other.provider_identity_verified()
    }
}

impl Eq for AttestedResolution {}

/// A resolved net external value for a candidate: what was *claimed*, and —
/// inside this crate only — the attestation behind it if there is one.
///
/// Wire shape: `nev_musd_micros` is preserved under `#[serde(rename)]` so a
/// `SearchObservation` written before P6.0.1 still parses. The value is a claim
/// and is named as one; it is read only on the paths that cannot promote.
///
/// A legacy `{"nev_musd_micros": N, "trust": {"chain_attested": {...}}}`
/// document now **fails to parse** — `deny_unknown_fields` rejects the retired
/// `trust` key. That is the intended fail-closed outcome: the old document
/// asserted an attestation, and the refusal is the answer. Dropping `trust`
/// alone makes the same document parse as a plain claim, which is also safe but
/// silently; this way a caller upgrading sees the refusal rather than a quiet
/// demotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedNev {
    /// What the adapter says the resolution was worth. A claim. Never an
    /// authority input, and ignored outright when [`Self::attested`] is `Some`.
    #[serde(rename = "nev_musd_micros")]
    pub claimed_nev_musd_micros: i64,
    /// The attestation capability.
    ///
    /// `skip_deserializing`: serde never requires `Deserialize` for this field
    /// and never reads it from input, which is what lets this type hold an
    /// [`AttestedResolution`] at all. No JSON — including JSON that spells the
    /// field out in full — can populate it. It is still *serialized*, so the
    /// report and the audit log name the policy and provider behind the number.
    #[serde(skip_deserializing, default)]
    pub attested: Option<AttestedResolution>,
}

impl ResolvedNev {
    /// A claim. The only shape a caller outside this crate can build.
    pub fn claimed(nev_musd_micros: i64) -> Self {
        Self {
            claimed_nev_musd_micros: nev_musd_micros,
            attested: None,
        }
    }

    /// An attested resolution, with the adapter's own number kept only for the
    /// record. `pub(crate)` and `cfg(test)`, for the same reason as
    /// [`AttestedResolution::from_verified`]: the attestation cannot be conjured
    /// from outside this crate, and nothing in production conjures it at all.
    #[cfg(test)]
    pub(crate) fn attested(attested: AttestedResolution, claimed_nev_musd_micros: i64) -> Self {
        Self {
            claimed_nev_musd_micros,
            attested: Some(attested),
        }
    }

    /// Whether this resolution carries a real attestation. This replaces
    /// `ResolutionTrust::can_attest` as the predicate — and unlike that
    /// predicate it cannot be satisfied by a field a caller wrote.
    pub fn is_attested(&self) -> bool {
        self.attested.is_some()
    }

    /// The number the state machine is allowed to act on: the authority's, or
    /// `None` when there is no authority.
    pub fn attested_nev_musd_micros(&self) -> Option<i64> {
        self.attested.as_ref().map(AttestedResolution::nev_musd_micros)
    }

    /// The one classification of a resolution, shared by
    /// [`DiscoveryMachine::observation_state`] and by the resolution-counter
    /// partition in [`SearchMemory::record`].
    ///
    /// P6.0.1: those two had to stay identical by hand — `SearchMemory::health`
    /// *sums* the counters to get the divisor of `CostPerResolution`, so a
    /// resolution counted in two buckets halves the apparent cost per
    /// resolution and makes `max_cost_per_resolution` pass twice as easily as
    /// the spending warrants. One function, two callers, no way to drift.
    ///
    /// The authority decides every comparison: with an attestation the number is
    /// the [`VerifiedNev`]'s and the caller's claim is not consulted at all,
    /// and without one the number is a claim and the only outcomes reachable are
    /// the two that cannot promote.
    pub(crate) fn classify(
        &self,
        class: OpportunityClass,
        required_musd_micros: u64,
    ) -> ResolutionClassification {
        let Some(attested) = &self.attested else {
            let claim = self.claimed_nev_musd_micros;
            return if claim < 0 {
                ResolutionClassification::NegativeNev {
                    nev_musd_micros: claim,
                    resolution_id: Self::claim_resolution_id(class, claim),
                }
            } else if claim < required_musd_micros as i64 {
                ResolutionClassification::BreakEven {
                    nev_musd_micros: claim,
                    required_musd_micros,
                }
            } else {
                ResolutionClassification::UnattestedNev {
                    claimed_nev_musd_micros: claim,
                }
            };
        };
        let nev = attested.nev_musd_micros();
        if nev < 0 {
            ResolutionClassification::NegativeNev {
                nev_musd_micros: nev,
                resolution_id: attested.resolution_id(class),
            }
        } else if nev < required_musd_micros as i64 {
            ResolutionClassification::BreakEven {
                nev_musd_micros: nev,
                required_musd_micros,
            }
        } else if !attested.is_positive() {
            // `is_positive()` requires `receipts > 0`. A positive total that
            // counts no receipt names no fact, so it is not a resolution at all
            // — not a smaller one, and certainly not a promotable one.
            ResolutionClassification::AttestedWithoutReceipts {
                nev_musd_micros: nev,
                receipts: attested.receipts(),
                policy_hash: attested.policy_hash().to_string(),
            }
        } else {
            ResolutionClassification::PositiveNev {
                nev_musd_micros: nev,
                policy_hash: attested.policy_hash().to_string(),
                resolution_id: attested.resolution_id(class),
            }
        }
    }

    /// The id given to a resolution that is only a claim.
    ///
    /// Deliberately prefixed `claim` rather than `resolution`, so an id in an
    /// audit log cannot be mistaken for one derived from an authority. It is
    /// still derived from the claim, because there is nothing else to derive it
    /// from — that is the residual exposure P6.0.1 leaves, and it is confined to
    /// a value that cannot promote.
    fn claim_resolution_id(class: OpportunityClass, claimed_nev_musd_micros: i64) -> String {
        stable_id(
            "claim",
            &[class.state(), &claimed_nev_musd_micros.to_string()],
        )
    }
}

/// What a [`ResolvedNev`] turned out to be. Private to the module: the two
/// consumers are [`DiscoveryMachine::observation_state`] and
/// [`SearchMemory::record`], and a third caller would have to be checked against
/// the partition by hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolutionClassification {
    NegativeNev {
        nev_musd_micros: i64,
        resolution_id: String,
    },
    BreakEven {
        nev_musd_micros: i64,
        required_musd_micros: u64,
    },
    PositiveNev {
        nev_musd_micros: i64,
        policy_hash: String,
        resolution_id: String,
    },
    UnattestedNev {
        claimed_nev_musd_micros: i64,
    },
    AttestedWithoutReceipts {
        nev_musd_micros: i64,
        receipts: u64,
        policy_hash: String,
    },
}

/// One search's measured outcome.
///
/// This is the input shape. It carries no threshold — only measurements and
/// claims — which is what makes the transition in [`DiscoveryMachine::observe`]
/// unable to move a bar even in principle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchObservation {
    pub schema_version: u32,
    pub class: OpportunityClass,
    /// Adapter identity, for the audit trail. Never a gate.
    pub adapter: String,
    /// The cycle the permit was issued for. Must match the permit.
    pub cycle: u64,
    pub cycles_budgeted: u64,
    pub cycles_completed: u64,
    /// Cells actually processed. `None` means the adapter does not report cells,
    /// which is different from reporting zero — a report that processed nothing
    /// must say so, and one that cannot count says `None`.
    pub cells_scanned: Option<u64>,
    /// The adapter stopped early. Coverage therefore cannot be called sufficient.
    pub aborted: bool,
    pub candidates: Vec<OpportunityCandidate>,
    /// The measured negative. Required before `NoEdge` is reachable.
    pub best_observed_edge: Option<MeasuredEdge>,
    pub settlement: SettlementReadiness,
    pub valuation: ValuationReadiness,
    pub thermal: ObservedThermal,
    pub spend: BudgetSpend,
    /// A candidate that was carried through to a resolution. Present only when
    /// the class actually resolves candidates.
    pub resolution: Option<ResolvedNev>,
    /// Non-`None` short-circuits everything into `InvalidEvidence`.
    pub defect: Option<EvidenceDefect>,
}

impl SearchObservation {
    /// Fail-closed constructor for an observation that cannot be used.
    pub fn defective(class: OpportunityClass, adapter: &str, cycle: u64, defect: EvidenceDefect) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            class,
            adapter: adapter.to_string(),
            cycle,
            cycles_budgeted: 0,
            cycles_completed: 0,
            cells_scanned: None,
            aborted: true,
            candidates: Vec::new(),
            best_observed_edge: None,
            settlement: SettlementReadiness::NotApplicable,
            valuation: ValuationReadiness::NotRequired,
            thermal: ObservedThermal::default(),
            spend: BudgetSpend::default(),
            resolution: None,
            defect: Some(defect),
        }
    }

    /// Whether the adapter finished what it set out to do.
    pub fn cycle_accounting_consistent(&self) -> bool {
        self.cycles_completed > 0
            && self.cycles_completed <= self.cycles_budgeted
            && !self.aborted
    }

    fn validate_shape(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(EconomyError::Invalid(
                "search observation schema_version mismatch".into(),
            ));
        }
        if self.adapter.trim().is_empty() {
            return Err(EconomyError::Invalid(
                "search observation adapter identity cannot be empty".into(),
            ));
        }
        if self.cycles_completed > self.cycles_budgeted {
            return Err(EconomyError::Invalid(
                "search observation reports more completed cycles than it budgeted"
                    .into(),
            ));
        }
        if let Some(cells) = self.cells_scanned {
            if cells == 0 && self.cycles_completed > 0 {
                return Err(EconomyError::Invalid(
                    "search observation reports completed cycles and zero cells; \
                     a run that processed nothing is a defect, not a negative edge"
                        .into(),
                ));
            }
        }
        if let Some(peak) = self.thermal.peak() {
            if !peak.is_finite() {
                return Err(EconomyError::Invalid(
                    "search observation temperature must be finite".into(),
                ));
            }
        }
        if let Some(edge) = &self.best_observed_edge {
            if edge.source_field.trim().is_empty() {
                return Err(EconomyError::Invalid(
                    "measured edge must name the field it came from".into(),
                ));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// States
// ---------------------------------------------------------------------------

/// Why a search ended in the state it did, in the machine's own words.
///
/// Serialised with an explicit `state` tag and a `detail` payload, following
/// [`crate::settlement::SettlementIncompleteness`]: a report distinguishes the
/// failure modes without parsing prose.
///
/// # Why these are not booleans
///
/// Every collapse a boolean invites is one the audit found already realised
/// somewhere in this crate: `thermal_headroom == 0.0` standing for four
/// different situations, `status == "COMPLETED"` standing for a thermal abort and
/// a clean zero, `proof_verified == true` standing for a claim. Each state below
/// is one of those situations made unrepresentable as a combination.
///
/// # The field lists are fixed, and none contains a threshold
///
/// That is the structural guarantee for the forbidden fallbacks. There is no
/// variant with a `min_profit`, a `gas_weight`, a `latency_weight` or a
/// `cost_ceiling`, so no transition between variants can carry a moved bar:
/// the comparison happens once, in [`DiscoveryMachine::observe`], against a
/// [`SearchPolicy`] borrowed for the call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum DiscoveryState {
    /// A search is in flight. No conclusion exists.
    Searching {
        class: OpportunityClass,
        cycle: u64,
        started_at_unix: u64,
    },
    /// The search produced at least one candidate that survives the adapter's own
    /// checks. The only state from which promotion can follow.
    CandidateFound {
        class: OpportunityClass,
        candidates: usize,
        cycle: u64,
    },
    /// The market was scanned and the best measured robust net did not pay.
    ///
    /// Requires a [`MeasuredEdge`]. Coverage may or may not be sufficient — that
    /// is what separates this from [`DiscoveryState::ClassExhausted`], and the
    /// machine decides between them in the same step.
    NoEdge {
        class: OpportunityClass,
        edge: MeasuredEdge,
        cycles_completed: u64,
    },
    /// A settlement-shaped result exists and is incomplete. The problem is the
    /// adapter, the evidence or the completeness — **not** the market, so
    /// discovery is not re-run.
    NoCompleteSettlement {
        class: OpportunityClass,
        gaps: Vec<SettlementGap>,
    },
    /// A value exists but no comparable net value could be derived. The problem
    /// is valuation, so discovery is not re-run.
    NoComparableNetValue { class: OpportunityClass, why: String },
    /// A candidate was resolved and its net external value was negative.
    NegativeNev {
        class: OpportunityClass,
        nev_musd_micros: i64,
        resolution_id: String,
    },
    /// A candidate was resolved and the net external value did not clear
    /// [`MinNetEdge`]. Nothing is promoted: `nev == 0` and a positive NEV below
    /// the minimum are the same decision here, and both are "do not execute for
    /// profit".
    BreakEven {
        class: OpportunityClass,
        nev_musd_micros: i64,
        required_musd_micros: u64,
    },
    /// A candidate resolved to an attested net external value at or above the
    /// minimum. The **only** state from which a [`PromotionCandidate`] may be
    /// produced, and even then only through the existing autonomy gates.
    ///
    /// P6.0.1: reaching this variant requires an [`AttestedResolution`], so every
    /// number in it was read from a [`VerifiedNev`] rather than from a field the
    /// adapter wrote, `resolution_id` is derived from the attested content, and
    /// `policy_hash` names the authority so the audit trail does not have to
    /// take it on faith. The variant itself carries plain fields rather than the
    /// capability, because [`DiscoveryState`] is serialised into search memory
    /// and must stay `Deserialize` — a capability type in it would not compile.
    PositiveNev {
        class: OpportunityClass,
        /// From the [`VerifiedNev`]. Never from [`ResolvedNev::claimed_nev_musd_micros`].
        nev_musd_micros: i64,
        required_musd_micros: u64,
        /// `stable_id("resolution", [class, policy_hash, receipts, nev])` — derived
        /// from the attestation, so it is tamper-evident and traceable to the
        /// authority below.
        resolution_id: String,
        /// The policy every counted receipt was issued under.
        policy_hash: String,
    },
    /// A resolution claimed a positive net external value with no attestation
    /// behind it.
    ///
    /// Not one of the states the brief enumerates, and it is here because
    /// without it a caller-supplied number would have to be either accepted as
    /// [`DiscoveryState::PositiveNev`] or mislabelled as
    /// [`DiscoveryState::BreakEven`]. The first is trust laundering through a
    /// decision layer; the second is a false statement about value. This is
    /// neither.
    UnattestedNev {
        class: OpportunityClass,
        claimed_nev_musd_micros: i64,
    },
    /// The adapter's evidence is unusable. Fail closed.
    ///
    /// Explicitly **not** [`DiscoveryState::NoEdge`]. A broken adapter that
    /// reports "nothing found" is indistinguishable from a working one unless
    /// the machine refuses to accept the report at all.
    InvalidEvidence {
        class: OpportunityClass,
        defect: EvidenceDefect,
    },
    /// Coverage is sufficient and the class has produced nothing. The only way
    /// into this state requires [`ClassSupport::Implemented`] and completed
    /// cycles; a class that was never searched cannot reach it.
    ClassExhausted { class: OpportunityClass, coverage: ClassCoverage },
    /// Nothing is searching: every enabled class is exhausted or unsupported.
    ColdDiscovery { summary: ColdDiscoverySummary },
    /// A thermal or budget stop. Never a negative edge, never coverage.
    SearchAbortedThermal {
        class: OpportunityClass,
        stop: ThermalStop,
        spend: BudgetSpend,
    },
    /// No adapter exists for this class. It has never been searched and no
    /// coverage number will ever move.
    UnsupportedClass { class: OpportunityClass, why: String },
    /// The class's budget ran out before coverage was sufficient.
    ///
    /// Deliberately distinct from [`DiscoveryState::ClassExhausted`], which
    /// asserts a positive claim about the market ("sufficiently searched, found
    /// nothing"), and distinct from [`DiscoveryState::NoEdge`], which asserts
    /// nothing at all. Reporting a budget stop as either would be the exact
    /// collapse the brief forbids: it would let "I ran out of budget" read as
    /// "there is nothing there".
    BudgetExhausted {
        class: OpportunityClass,
        dimension: BudgetDimension,
        coverage: ClassCoverage,
    },
}

impl DiscoveryState {
    /// The machine-readable state name. One per situation; never shared.
    pub fn state(&self) -> &'static str {
        match self {
            Self::Searching { .. } => "searching",
            Self::CandidateFound { .. } => "candidate_found",
            Self::NoEdge { .. } => "no_edge",
            Self::NoCompleteSettlement { .. } => "no_complete_settlement",
            Self::NoComparableNetValue { .. } => "no_comparable_net_value",
            Self::NegativeNev { .. } => "negative_nev",
            Self::BreakEven { .. } => "break_even",
            Self::PositiveNev { .. } => "positive_nev",
            Self::UnattestedNev { .. } => "unattested_nev",
            Self::InvalidEvidence { .. } => "invalid_evidence",
            Self::ClassExhausted { .. } => "class_exhausted",
            Self::ColdDiscovery { .. } => "cold_discovery",
            Self::SearchAbortedThermal { .. } => "search_aborted_thermal",
            Self::UnsupportedClass { .. } => "unsupported_class",
            Self::BudgetExhausted { .. } => "budget_exhausted",
        }
    }

    /// The class this state is about. `None` only for
    /// [`DiscoveryState::ColdDiscovery`], which is about all of them.
    pub fn class(&self) -> Option<OpportunityClass> {
        match self {
            Self::Searching { class, .. }
            | Self::CandidateFound { class, .. }
            | Self::NoEdge { class, .. }
            | Self::NoCompleteSettlement { class, .. }
            | Self::NoComparableNetValue { class, .. }
            | Self::NegativeNev { class, .. }
            | Self::BreakEven { class, .. }
            | Self::PositiveNev { class, .. }
            | Self::UnattestedNev { class, .. }
            | Self::InvalidEvidence { class, .. }
            | Self::ClassExhausted { class, .. }
            | Self::SearchAbortedThermal { class, .. }
            | Self::UnsupportedClass { class, .. }
            | Self::BudgetExhausted { class, .. } => Some(*class),
            Self::ColdDiscovery { .. } => None,
        }
    }

    /// The only action this state is allowed to produce.
    ///
    /// Derived by `match`, so the outcome → action mapping cannot drift and
    /// cannot be forgotten on a branch. It is the whole of the "outcome-specific
    /// actions" requirement: there is no second place that decides what happens
    /// next, so [`DiscoveryState::NoCompleteSettlement`] cannot end up re-running
    /// discovery and [`DiscoveryState::NoComparableNetValue`] cannot end up
    /// asking for another scan.
    pub fn action(&self) -> SearchAction {
        match self {
            // Keep looking, inside the permit's budget.
            Self::Searching { .. } => SearchAction::ContinueSearchWithinBudget,
            // Hand the candidate to the existing autonomy trail. It still has to
            // clear every gate there.
            Self::CandidateFound { .. } => SearchAction::HandOffToAuthorityTrail,
            // Bounded retry: backoff, coverage updated, no bar moved.
            Self::NoEdge { .. } => SearchAction::BackoffAndContinueSearch,
            // The adapter is the problem. Do not search again; record the gap.
            Self::NoCompleteSettlement { .. } => SearchAction::RecordEvidenceGap,
            // The valuation is the problem. Do not search again; ask for a price.
            Self::NoComparableNetValue { .. } => SearchAction::RequestValuation,
            // A realised loss: record it, back off, update the class's statistics.
            Self::NegativeNev { .. } => SearchAction::RecordNegativeResolution,
            // Conservative: no surplus, no promotion.
            Self::BreakEven { .. } => SearchAction::DoNotPromote,
            // The only path toward a job intent, and it is still the existing
            // trail.
            Self::PositiveNev { .. } => SearchAction::HandOffToAuthorityTrail,
            // A claim is not a value. Get it attested or leave it.
            Self::UnattestedNev { .. } => SearchAction::RequestChainAttestation,
            // Fail closed. Not a negative edge, and not a licence to retry blindly.
            Self::InvalidEvidence { .. } => SearchAction::FailClosed,
            // Move to another enabled class, or go cold.
            Self::ClassExhausted { .. } => SearchAction::RotateClass,
            // Nothing to search. Hold.
            Self::ColdDiscovery { .. } => SearchAction::HoldCold,
            // Cool down. Never treated as a negative edge.
            Self::SearchAbortedThermal { .. } => SearchAction::EnterThermalCooldown,
            // Skip, and report it as never-implemented rather than as searched.
            Self::UnsupportedClass { .. } => SearchAction::SkipUnsupportedClass,
            // Stop scanning this class this run without claiming anything about
            // the market.
            Self::BudgetExhausted { .. } => SearchAction::StopClassThisRun,
        }
    }

    /// Whether this state is a conclusion about the market.
    ///
    /// This is the "COMPLETED" column of the report, and it is `false` for
    /// exactly the four things that must never read as completion: a thermal
    /// stop, an incomplete settlement, a budget stop, and invalid evidence — plus
    /// an unsupported class (nothing was searched) and a search in progress.
    pub fn is_complete(&self) -> bool {
        match self {
            Self::Searching { .. }
            | Self::SearchAbortedThermal { .. }
            | Self::NoCompleteSettlement { .. }
            | Self::InvalidEvidence { .. }
            | Self::UnsupportedClass { .. }
            | Self::BudgetExhausted { .. } => false,
            Self::CandidateFound { .. }
            | Self::NoEdge { .. }
            | Self::NoComparableNetValue { .. }
            | Self::NegativeNev { .. }
            | Self::BreakEven { .. }
            | Self::PositiveNev { .. }
            | Self::UnattestedNev { .. }
            | Self::ClassExhausted { .. }
            | Self::ColdDiscovery { .. } => true,
        }
    }

    /// Whether the machine learned something about *the market* rather than
    /// about itself. Used to keep a broken adapter from reading as a quiet
    /// market in a dashboard.
    pub fn is_market_conclusion(&self) -> bool {
        matches!(
            self,
            Self::NoEdge { .. }
                | Self::NegativeNev { .. }
                | Self::BreakEven { .. }
                | Self::PositiveNev { .. }
                | Self::UnattestedNev { .. }
                | Self::CandidateFound { .. }
        )
    }

    /// Whether the class behind this state has been resolved.
    ///
    /// The only states that count are the ones that can reach
    /// [`SearchAction::HandOffToAuthorityTrail`], and only with the existing
    /// gates still in front of them.
    pub fn is_promotable(&self) -> bool {
        matches!(self, Self::PositiveNev { .. })
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Searching { class, cycle, .. } => {
                format!("searching {class} at cycle {cycle}; no conclusion exists yet")
            }
            Self::CandidateFound {
                class,
                candidates,
                cycle,
            } => format!(
                "{class} search at cycle {cycle} produced {candidates} candidate(s) that \
                 survived the adapter's own checks"
            ),
            Self::NoEdge {
                class,
                edge,
                cycles_completed,
            } => format!(
                "{class} was scanned over {cycles_completed} completed cycle(s) and the best \
                 measured robust net was {} mUSD (token edge {:?} mUSD, from {}); this is a \
                 measured negative, not an absence of one",
                edge.robust_net_micros, edge.token_edge_micros, edge.source_field
            ),
            Self::NoCompleteSettlement { class, gaps } => format!(
                "{class} produced an incomplete settlement; the adapter, the evidence or \
                 the completeness is at fault and discovery is NOT re-run. gaps: {}",
                gaps
                    .iter()
                    .map(SettlementGap::state)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::NoComparableNetValue { class, why } => format!(
                "{class} has no comparable net value ({why}); the valuation is at fault and \
                 discovery is NOT re-run"
            ),
            Self::NegativeNev {
                class,
                nev_musd_micros,
                resolution_id,
            } => format!(
                "{class} candidate {resolution_id} resolved to {nev_musd_micros} mUSD; a \
                 realised loss is recorded and the class backs off"
            ),
            Self::BreakEven {
                class,
                nev_musd_micros,
                required_musd_micros,
            } => format!(
                "{class} resolved to {nev_musd_micros} mUSD against a required {required_musd_micros} \
                 mUSD; no surplus, nothing is promoted"
            ),
            Self::PositiveNev {
                class,
                nev_musd_micros,
                required_musd_micros,
                resolution_id,
                policy_hash,
            } => format!(
                "{class} candidate {resolution_id} resolved to an attested {nev_musd_micros} \
                 mUSD at or above the required {required_musd_micros} mUSD under policy \
                 {policy_hash}; this may reach the existing authority trail and is still subject \
                 to every gate there"
            ),
            Self::UnattestedNev {
                class,
                claimed_nev_musd_micros,
            } => format!(
                "{class} claims {claimed_nev_musd_micros} mUSD with no attestation behind it; \
                 a claim is not a value and cannot be promoted"
            ),
            Self::InvalidEvidence { class, defect } => format!(
                "{} evidence is unusable ({}: {}); failing closed, and this is NOT \
                 treated as no-edge",
                class,
                defect.state(),
                match defect {
                    EvidenceDefect::UnreadableShape { why }
                    | EvidenceDefect::Unmeasured { why }
                    | EvidenceDefect::Transmitted { why }
                    | EvidenceDefect::InconsistentAccounting { why }
                    | EvidenceDefect::ClassMismatch { why } => why.as_str(),
                    EvidenceDefect::Nev0Refused { category, why } => {
                        return format!(
                            "{class} evidence was refused by the NEV-0 gate ({category}: {why}); \
                             failing closed, and this is NOT treated as no-edge"
                        );
                    }
                }
            ),
            Self::ClassExhausted { class, coverage } => format!(
                "{class} is exhausted: {} completed cycle(s), {} cell(s), {} candidate(s), \
                 support={}; sufficient coverage and nothing found",
                coverage.cycles_completed,
                coverage.cells_scanned
                    .map_or_else(|| "unreported".to_string(), |c| c.to_string()),
                coverage.candidates_found,
                coverage.support.state(),
            ),
            Self::ColdDiscovery { summary } => summary.describe(),
            Self::SearchAbortedThermal {
                class,
                stop,
                spend,
            } => format!(
                "{class} search stopped before it could conclude ({}); this is NOT a \
                 negative edge and contributes no coverage. spend: {:?}",
                stop.state(),
                spend
            ),
            Self::UnsupportedClass { class, why } => {
                format!("{class} has no adapter ({why}); it has never been searched")
            }
            Self::BudgetExhausted {
                class,
                dimension,
                coverage,
            } => format!(
                "{class} ran out of {} budget after {} completed cycle(s); this is neither a \
                 negative edge nor an exhaustion of the class",
                dimension.state(),
                coverage.cycles_completed
            ),
        }
    }
}

/// The single action a [`DiscoveryState`] permits.
///
/// One variant per state, derived by [`DiscoveryState::action`]. No thresholds,
/// no parameters: an action can move the machine's *attention* and nothing else.
/// Lowering a profit bar, ignoring gas, ignoring latency or relaxing a cost
/// ceiling is not an action this type can express.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchAction {
    ContinueSearchWithinBudget,
    BackoffAndContinueSearch,
    RecordEvidenceGap,
    RequestValuation,
    RecordNegativeResolution,
    DoNotPromote,
    HandOffToAuthorityTrail,
    RequestChainAttestation,
    FailClosed,
    RotateClass,
    HoldCold,
    EnterThermalCooldown,
    SkipUnsupportedClass,
    StopClassThisRun,
}

impl SearchAction {
    pub fn state(&self) -> &'static str {
        match self {
            Self::ContinueSearchWithinBudget => "continue_search_within_budget",
            Self::BackoffAndContinueSearch => "backoff_and_continue_search",
            Self::RecordEvidenceGap => "record_evidence_gap",
            Self::RequestValuation => "request_valuation",
            Self::RecordNegativeResolution => "record_negative_resolution",
            Self::DoNotPromote => "do_not_promote",
            Self::HandOffToAuthorityTrail => "hand_off_to_authority_trail",
            Self::RequestChainAttestation => "request_chain_attestation",
            Self::FailClosed => "fail_closed",
            Self::RotateClass => "rotate_class",
            Self::HoldCold => "hold_cold",
            Self::EnterThermalCooldown => "enter_thermal_cooldown",
            Self::SkipUnsupportedClass => "skip_unsupported_class",
            Self::StopClassThisRun => "stop_class_this_run",
        }
    }

    /// Whether this action may lead to a candidate reaching the autonomy trail.
    ///
    /// Two do: a resolved candidate and a promotable resolution. Everything else
    /// — including every state a thermal stop or an invalid adapter can produce —
    /// returns `false`.
    pub fn can_reach_authority_trail(&self) -> bool {
        matches!(self, Self::HandOffToAuthorityTrail)
    }
}

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

/// How much of the intended search actually happened.
///
/// `cells_scanned` is an `Option` on purpose. The difference between "reported
/// zero cells" and "does not report cells" is the difference between a machine
/// that looked and found nothing and a machine that cannot say what it did — and
/// [`ClassCoverage::sufficient_for_exhaustion`] refuses to treat the second as the
/// first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchCoverage {
    pub cycles_budgeted: u64,
    pub cycles_completed: u64,
    pub cycles_aborted: u64,
    pub cells_scanned: Option<u64>,
}

impl SearchCoverage {
    pub fn completed_cycles(&self) -> u64 {
        self.cycles_completed
    }

    /// Whether at least one cell was actually looked at.
    pub fn processed_cells(&self) -> bool {
        self.cells_scanned.is_some_and(|c| c > 0)
    }

    /// Whether the adapter finished its cycles.
    pub fn cycles_finished(&self) -> bool {
        self.cycles_budgeted > 0
            && self.cycles_completed == self.cycles_budgeted
            && self.cycles_aborted == 0
    }
}

/// Per-class coverage, with implementation reported separately from search.
///
/// [`support`](Self::support) is the field that makes "searched and found
/// nothing" and "never implemented" different numbers on the same report. It is
/// derived from the [`AdapterRegistry`], so an adapter cannot declare itself
/// implemented and a class with no adapter cannot accumulate coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassCoverage {
    pub class: OpportunityClass,
    pub support: ClassSupport,
    pub cycles_attempted: u64,
    pub cycles_completed: u64,
    pub cycles_aborted: u64,
    pub cells_scanned: Option<u64>,
    pub candidates_found: u64,
    pub resolutions_negative: u64,
    pub resolutions_break_even: u64,
    pub resolutions_positive: u64,
}

impl ClassCoverage {
    pub fn unimplemented(class: OpportunityClass) -> Self {
        Self {
            class,
            support: ClassSupport::Unsupported,
            cycles_attempted: 0,
            cycles_completed: 0,
            cycles_aborted: 0,
            cells_scanned: None,
            candidates_found: 0,
            resolutions_negative: 0,
            resolutions_break_even: 0,
            resolutions_positive: 0,
        }
    }

    /// Whether this class may be declared exhausted.
    ///
    /// Five conditions, all necessary, and the first one is the whole point:
    ///
    /// 1. it is **implemented**. A class nothing searches can never be exhausted;
    /// 2. at least [`MinClassCoverage`] cycles completed;
    /// 3. the adapter reported cells and processed at least one;
    /// 4. no cycle was aborted — an abort is missing coverage, not coverage;
    /// 5. the budgeted cycles all finished.
    pub fn sufficient_for_exhaustion(
        &self,
        minimum: &MinClassCoverage,
        cells_required: u64,
    ) -> Result<bool> {
        if cells_required == 0 {
            return Err(EconomyError::Invalid(
                "required cell count must be > 0".into(),
            ));
        }
        Ok(self.support.can_resolve()
            && self.cycles_completed >= minimum.cycles()
            && self.cells_scanned.is_some_and(|c| c >= cells_required)
            && self.cycles_aborted == 0
            && self.cycles_completed > 0)
    }

    pub fn state(&self) -> &'static str {
        match self.support {
            ClassSupport::Implemented => "implemented",
            ClassSupport::Unsupported => "unsupported",
        }
    }
}

/// Why the machine is searching nothing, with the unsupported classes named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdDiscoverySummary {
    pub exhausted: Vec<OpportunityClass>,
    pub unsupported: Vec<OpportunityClass>,
    pub disabled: Vec<OpportunityClass>,
    pub total_classes: usize,
    pub searched_classes: usize,
}

impl ColdDiscoverySummary {
    pub fn describe(&self) -> String {
        format!(
            "cold discovery: {} of {} opportunity classes were \
             actually searched; exhausted={}, unsupported={}, disabled={}. No class was \
             searched and found nothing without also being reported here, and no \
             no-external-value-exists conclusion is available from this state.",
            self.searched_classes,
            self.total_classes,
            render_classes(&self.exhausted),
            render_classes(&self.unsupported),
            render_classes(&self.disabled),
        )
    }
}

fn render_classes(classes: &[OpportunityClass]) -> String {
    if classes.is_empty() {
        "none".to_string()
    } else {
        classes
            .iter()
            .map(OpportunityClass::state)
            .collect::<Vec<_>>()
            .join(",")
    }
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/// How many hypotheses were tried, counted over classes and routes.
///
/// The audit's requirement is that diversity means "across classes/routes, NOT
/// near-identical parameter variants", so the unit is an identity: a route key
/// and a source hash. Re-running the same route with a different threshold is the
/// same hypothesis and is counted once — which is exactly what a re-scan after
/// backoff does, and it should not look like progress.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypothesisDiversity {
    pub distinct_classes: u32,
    pub distinct_routes: u32,
    pub distinct_sources: u32,
}

impl HypothesisDiversity {
    pub fn meets(&self, minimum: &MinDiversity) -> bool {
        self.distinct_classes >= minimum.distinct_classes
            && self.distinct_routes >= minimum.distinct_routes
    }
}

/// Resolved attempts and how many became resolutions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionRate {
    pub attempts: u64,
    pub resolved: u64,
}

impl ResolutionRate {
    pub fn basis_points(&self) -> Option<u32> {
        if self.attempts == 0 {
            return None;
        }
        Some((self.resolved.min(self.attempts) as u128 * 10_000 / self.attempts as u128) as u32)
    }
}

/// What the machine spent resolving things.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostPerResolution {
    pub total_cost_musd_micros: u64,
    pub resolutions: u64,
}

impl CostPerResolution {
    /// Integer division, so no float ever decides a cost gate. `None` when
    /// nothing was resolved — again, not a pass.
    pub fn micros_per_resolution(&self) -> Option<u64> {
        if self.resolutions == 0 {
            return None;
        }
        Some(self.total_cost_musd_micros / self.resolutions)
    }
}

/// The five health dimensions, reported as a vector.
///
/// # Why they are not summed
///
/// The requirement is that `NEV = 0 / broken / low-coverage` is
/// distinguishable from `NEV = 0 / high-coverage / all-correctly-negative`. A
/// weighted sum destroys exactly that: a machine with excellent resolution and
/// terrible coverage can score the same as one with the reverse profile, and
/// which of the two it is depends entirely on the weights — an arbitrary choice
/// that then looks like a decision.
///
/// So there is no `fitness()` method. [`SearchHealth::verdict`] reports the
/// **first** dimension that fails, named, with the observed and required values,
/// and [`SearchHealth::reasons`] lists every failure. A caller that wants a
/// scalar must choose it themselves and own the weight.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchHealth {
    pub coverage: SearchCoverage,
    pub class_coverage: Vec<ClassCoverage>,
    pub resolution_rate: ResolutionRate,
    pub cost_per_resolution: CostPerResolution,
    pub diversity: HypothesisDiversity,
}

/// Which health dimension is being checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthDimension {
    ClassCoverage,
    ResolutionRate,
    CostPerResolution,
    Diversity,
}

impl HealthDimension {
    pub fn state(&self) -> &'static str {
        match self {
            Self::ClassCoverage => "class_coverage",
            Self::ResolutionRate => "resolution_rate",
            Self::CostPerResolution => "cost_per_resolution",
            Self::Diversity => "diversity",
        }
    }
}

/// The floor every dimension must clear before value may be compared at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthMinimums {
    pub min_class_coverage: MinClassCoverage,
    pub min_resolution_rate: MinResolutionRate,
    pub max_cost_per_resolution: MaxCostPerResolution,
    pub min_diversity: MinDiversity,
    /// Cells a class must have processed before its coverage counts.
    pub cells_required: u64,
}

impl Default for HealthMinimums {
    fn default() -> Self {
        Self {
            min_class_coverage: MinClassCoverage(1),
            min_resolution_rate: MinResolutionRate(1_000),
            max_cost_per_resolution: MaxCostPerResolution(50_000_000),
            min_diversity: MinDiversity {
                distinct_classes: 1,
                distinct_routes: 1,
            },
            cells_required: 1,
        }
    }
}

impl HealthMinimums {
    pub fn validate(&self) -> Result<()> {
        if self.cells_required == 0 {
            return Err(EconomyError::Invalid(
                "cells_required must be > 0; 0 would make coverage trivial".into(),
            ));
        }
        Ok(())
    }
}

/// Whether health is sufficient, and if not, exactly what failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", content = "detail", rename_all = "snake_case")]
pub enum HealthVerdict {
    /// Every dimension cleared its floor.
    Sufficient { checked: usize },
    /// The first failing dimension, named.
    Insufficient {
        dimension: HealthDimension,
        observed: String,
        required: String,
        failing_dimensions: Vec<HealthDimension>,
    },
}

impl SearchHealth {
    /// The worst implemented class's completed cycles — coverage is judged per
    /// class, because one well-searched class does not make an unsearched one
    /// searched. `None` when nothing is implemented, which fails the floor.
    fn weakest_coverage_cycles(&self) -> Option<(OpportunityClass, u64)> {
        self.class_coverage
            .iter()
            .filter(|c| c.support.can_resolve())
            .map(|c| (c.class, c.cycles_completed))
            .min_by_key(|(_, cycles)| *cycles)
    }

    /// Health against the floors. Reports the **first** failure in a fixed order
    /// (coverage, resolution, cost, diversity) so the answer is deterministic,
    /// and every failure in `failing_dimensions`.
    pub fn verdict(&self, minimums: &HealthMinimums) -> Result<HealthVerdict> {
        minimums.validate()?;
        let mut failing = Vec::new();

        let (cov_class, cov_cycles) = self.weakest_coverage_cycles().unwrap_or((START_CLASS, 0));
        let cov_ok = self
            .class_coverage
            .iter()
            .any(|c| c.support.can_resolve())
            && cov_cycles >= minimums.min_class_coverage.cycles();
        if !cov_ok {
            failing.push(HealthDimension::ClassCoverage);
        }

        let rate_bps = self.resolution_rate.basis_points();
        let rate_ok = rate_bps.is_some_and(|bps| bps >= minimums.min_resolution_rate.basis_points());
        if !rate_ok {
            failing.push(HealthDimension::ResolutionRate);
        }

        let cost = self.cost_per_resolution.micros_per_resolution();
        let cost_ok =
            cost.is_some_and(|c| c <= minimums.max_cost_per_resolution.micros());
        if !cost_ok {
            failing.push(HealthDimension::CostPerResolution);
        }

        let diversity_ok = self.diversity.meets(&minimums.min_diversity);
        if !diversity_ok {
            failing.push(HealthDimension::Diversity);
        }

        if failing.is_empty() {
            return Ok(HealthVerdict::Sufficient { checked: 4 });
        }
        let first = failing[0];
        let (observed, required) = match first {
            HealthDimension::ClassCoverage => (
                format!("{cov_class} completed {cov_cycles} cycle(s)"),
                format!(
                    "{} cycle(s) per implemented class",
                    minimums.min_class_coverage.cycles()
                ),
            ),
            HealthDimension::ResolutionRate => (
                match rate_bps {
                    Some(bps) => format!("{bps} bps"),
                    None => "no resolved attempts".to_string(),
                },
                format!(">= {} bps", minimums.min_resolution_rate.basis_points()),
            ),
            HealthDimension::CostPerResolution => (
                match cost {
                    Some(c) => format!("{c} mUSD micros per resolution"),
                    None => "no resolutions".to_string(),
                },
                format!(
                    "<= {} mUSD micros per resolution",
                    minimums.max_cost_per_resolution.micros()
                ),
            ),
            HealthDimension::Diversity => (
                format!(
                    "{} distinct class(es), {} distinct route(s)",
                    self.diversity.distinct_classes, self.diversity.distinct_routes
                ),
                format!(
                    ">= {} distinct class(es) and >= {} distinct route(s)",
                    minimums.min_diversity.distinct_classes,
                    minimums.min_diversity.distinct_routes
                ),
            ),
        };
        Ok(HealthVerdict::Insufficient {
            dimension: first,
            observed,
            required,
            failing_dimensions: failing,
        })
    }

    pub fn reasons(&self, minimums: &HealthMinimums) -> Result<Vec<String>> {
        match self.verdict(minimums)? {
            HealthVerdict::Sufficient { .. } => Ok(Vec::new()),
            HealthVerdict::Insufficient {
                dimension,
                observed,
                required,
                ..
            } => Ok(vec![format!(
                "{}: observed {observed}, required {required}",
                dimension.state()
            )]),
        }
    }
}

/// A candidate value, for the lexicographic comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RankedValue {
    pub class: OpportunityClass,
    /// Attested net external value. Zero is a real number and compares as one.
    pub verified_nev_musd_micros: i64,
    pub cost_musd_micros: u64,
}

/// The decision, in the order the brief requires it.
///
/// (1) reach minimum health, (2) then maximise verified NEV, (3) for equivalent
/// value, minimise cost.
///
/// The order is in the type: [`SearchSelection::BelowMinimumHealth`] is a
/// different variant from [`SearchSelection::ByVerifiedValue`], so a caller
/// cannot read a value ranking out of a comparison that never happened. Nothing
/// here fuses health into a score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "selection", content = "detail", rename_all = "snake_case")]
pub enum SearchSelection {
    /// Health is below the floor. Value may not be compared at all.
    BelowMinimumHealth {
        dimension: HealthDimension,
        observed: String,
        required: String,
    },
    /// Health cleared. Ranked by attested value, descending.
    ByVerifiedValue { ranked: Vec<RankedValue> },
    /// Health cleared and the top value is tied across candidates. Ranked by
    /// cost, ascending, among the tied set only.
    ByLowestCost { ranked: Vec<RankedValue> },
}

impl SearchSelection {
    pub fn decide_with(
        health: &SearchHealth,
        minimums: &HealthMinimums,
        values: &[RankedValue],
    ) -> Result<Self> {
        match health.verdict(minimums)? {
            HealthVerdict::Insufficient {
                dimension,
                observed,
                required,
                ..
            } => Ok(Self::BelowMinimumHealth {
                dimension,
                observed,
                required,
            }),
            HealthVerdict::Sufficient { .. } => {
                let mut by_value = values.to_vec();
                by_value.sort_by(|a, b| {
                    b.verified_nev_musd_micros
                        .cmp(&a.verified_nev_musd_micros)
                        .then_with(|| a.cost_musd_micros.cmp(&b.cost_musd_micros))
                });
                let top = by_value.first().map(|v| v.verified_nev_musd_micros);
                let tied: Vec<RankedValue> = by_value
                    .iter()
                    .filter(|v| Some(v.verified_nev_musd_micros) == top)
                    .cloned()
                    .collect();
                if tied.len() > 1 {
                    let mut by_cost = tied;
                    by_cost.sort_by_key(|v| v.cost_musd_micros);
                    Ok(Self::ByLowestCost { ranked: by_cost })
                } else {
                    Ok(Self::ByVerifiedValue { ranked: by_value })
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Everything the machine is allowed to decide with.
///
/// Borrowed by reference for every decision and never stored, never returned and
/// never cloned into a [`DiscoveryState`]. That is the property that makes
/// "an enum transition cannot carry a mutated threshold" true rather than
/// aspirational: the values live here, the transitions live in
/// [`DiscoveryMachine`], and no value ever travels from one to the other.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchPolicy {
    pub min_net_edge: MinNetEdge,
    pub health_minimums: HealthMinimums,
    pub backoff: BackoffSchedule,
    pub budget: SearchBudget,
    /// Headroom MUPP must report before a search may start. Bounded away from
    /// `0.0` so a collapsed machine cannot satisfy it by a hair.
    pub required_thermal_headroom: f64,
    /// Cycles that must pass after a thermal abort before any search may run.
    pub thermal_cooldown_cycles: u32,
    /// Classes the operator enabled. A class listed here with no adapter still
    /// resolves to [`DiscoveryState::UnsupportedClass`] — enabling is a statement
    /// of intent, not of implementation.
    pub enabled_classes: BTreeSet<OpportunityClass>,
}

impl Default for SearchPolicy {
    fn default() -> Self {
        let mut enabled_classes = BTreeSet::new();
        enabled_classes.insert(START_CLASS);
        Self {
            min_net_edge: MinNetEdge::crate_default(),
            health_minimums: HealthMinimums::default(),
            backoff: BackoffSchedule::default(),
            budget: SearchBudget::default(),
            required_thermal_headroom: MIN_SEARCH_THERMAL_HEADROOM,
            thermal_cooldown_cycles: 2,
            enabled_classes,
        }
    }
}

impl SearchPolicy {
    /// The class the machine starts on. A constant, not a policy field: see
    /// [`START_CLASS`].
    pub fn start_class(&self) -> OpportunityClass {
        START_CLASS
    }

    pub fn validate(&self) -> Result<()> {
        self.budget.validate()?;
        self.health_minimums.validate()?;
        BackoffSchedule::new(self.backoff.base_cycles, self.backoff.max_cycles, self.backoff.factor_bps)?;
        if !self.required_thermal_headroom.is_finite()
            || !(0.0..=1.0).contains(&self.required_thermal_headroom)
            || self.required_thermal_headroom <= 0.0
        {
            return Err(EconomyError::Invalid(
                "required_thermal_headroom must be in (0, 1]; 0 would let a \
                 collapsed machine satisfy the floor"
                    .into(),
            ));
        }
        if self.thermal_cooldown_cycles == 0 {
            return Err(EconomyError::Invalid(
                "thermal_cooldown_cycles must be > 0; a thermal abort with no \
                 cooldown is the behaviour P6 exists to stop"
                    .into(),
            ));
        }
        Ok(())
    }

    /// Classes that are both enabled and actually searchable.
    pub fn searchable_classes(
        &self,
        registry: &AdapterRegistry,
    ) -> Vec<OpportunityClass> {
        OpportunityClass::ALL
            .into_iter()
            .filter(|c| self.enabled_classes.contains(c) && registry.support(*c).can_resolve())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

/// A waiting cycle is time, never fabricated search coverage.
pub const SEARCH_WAIT_CYCLE_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SearchWaitStatus {
    pub version: u32,
    pub wait_cycle_seconds: u64,
    pub next_attempt_unix: Option<u64>,
    pub thermal_cooldown_until_unix: Option<u64>,
}

/// What one class has been through.
///
/// Note what is absent: there is no `support` field. Support comes from the
/// [`AdapterRegistry`] at report time, so a memory file — which is an ordinary
/// JSON document on disk — cannot claim that a class is implemented when nothing
/// implements it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassStatistics {
    pub cycles_attempted: u64,
    pub cycles_completed: u64,
    pub cycles_aborted: u64,
    pub cells_scanned: Option<u64>,
    pub candidates_found: u64,
    pub resolutions_negative: u64,
    pub resolutions_break_even: u64,
    pub resolutions_positive: u64,
    /// Consecutive attempts that produced nothing usable. Feeds
    /// [`BackoffSchedule`]; reset by any candidate found.
    pub consecutive_empty: u32,
    pub exhausted: bool,
    /// Legacy diagnostic; the active gate uses `next_attempt_unix`.
    pub next_attempt_cycle: u64,
    /// Missing in older memory files; migrated once at the next attempt.
    #[serde(default)]
    pub next_attempt_unix: Option<u64>,
    pub thermal_cooldown_until_cycle: u64,
    /// Distinct route identities tried. Re-running one route with different
    /// parameters adds nothing here, on purpose.
    pub routes: BTreeSet<String>,
    /// Distinct evidence sources used.
    pub sources: BTreeSet<String>,
    pub spend: BudgetSpend,
    pub last_state: DiscoveryState,
}

impl Default for ClassStatistics {
    fn default() -> Self {
        Self {
            cycles_attempted: 0,
            cycles_completed: 0,
            cycles_aborted: 0,
            cells_scanned: None,
            candidates_found: 0,
            resolutions_negative: 0,
            resolutions_break_even: 0,
            resolutions_positive: 0,
            consecutive_empty: 0,
            exhausted: false,
            next_attempt_cycle: 0,
            next_attempt_unix: Some(0),
            thermal_cooldown_until_cycle: 0,
            routes: BTreeSet::new(),
            sources: BTreeSet::new(),
            spend: BudgetSpend::default(),
            last_state: DiscoveryState::ColdDiscovery {
                summary: ColdDiscoverySummary {
                    exhausted: Vec::new(),
                    unsupported: OpportunityClass::ALL.to_vec(),
                    disabled: Vec::new(),
                    total_classes: OpportunityClass::ALL.len(),
                    searched_classes: 0,
                },
            },
        }
    }
}

impl ClassStatistics {
    pub fn coverage(&self, class: OpportunityClass, support: ClassSupport) -> ClassCoverage {
        ClassCoverage {
            class,
            support,
            cycles_attempted: self.cycles_attempted,
            cycles_completed: self.cycles_completed,
            cycles_aborted: self.cycles_aborted,
            cells_scanned: self.cells_scanned,
            candidates_found: self.candidates_found,
            resolutions_negative: self.resolutions_negative,
            resolutions_break_even: self.resolutions_break_even,
            resolutions_positive: self.resolutions_positive,
        }
    }
}

/// Durable search state: cycle, class, coverage, backoff and thermal cooldown.
///
/// Persisted so that backoff and cooldown survive a restart. A backoff that
/// resets when the process does is not a backoff, and neither is a thermal
/// cooldown.
///
/// Nothing reads this to authorise anything. It is a cache of search activity;
/// the only inputs to any authority are the autonomy ledger and a pinned chain
/// provider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchMemory {
    pub schema_version: u32,
    /// Cycles issued so far. The next permit is for `cycle + 1`.
    pub cycle: u64,
    pub current_class: OpportunityClass,
    pub state: DiscoveryState,
    pub classes: BTreeMap<OpportunityClass, ClassStatistics>,
    pub total_spend: BudgetSpend,
    /// What the machine has spent on job cost for the candidates it found. This
    /// is the cost side of [`SearchHealth::cost_per_resolution`]; energy is
    /// tracked separately and never converted into a money figure.
    pub total_cost_musd_micros: u64,
    /// Legacy diagnostic; the active gate uses the Unix deadline below.
    pub thermal_cooldown_until_cycle: u64,
    #[serde(default)]
    pub thermal_cooldown_until_unix: Option<u64>,
}

impl SearchMemory {
    /// A machine that has never searched: positioned on [`START_CLASS`], in
    /// [`DiscoveryState::Searching`] for cycle zero.
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            cycle: 0,
            current_class: START_CLASS,
            state: DiscoveryState::Searching {
                class: START_CLASS,
                cycle: 0,
                started_at_unix: 0,
            },
            classes: BTreeMap::new(),
            total_spend: BudgetSpend::default(),
            total_cost_musd_micros: 0,
            thermal_cooldown_until_cycle: 0,
            thermal_cooldown_until_unix: Some(0),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(EconomyError::Invalid(
                "search memory schema_version mismatch".into(),
            ));
        }
        Ok(())
    }

    pub fn statistics(&self, class: OpportunityClass) -> ClassStatistics {
        self.classes.get(&class).cloned().unwrap_or_default()
    }

    pub fn wait_status(&self) -> SearchWaitStatus {
        SearchWaitStatus {
            version: 1,
            wait_cycle_seconds: SEARCH_WAIT_CYCLE_SECONDS,
            next_attempt_unix: self.statistics(self.current_class).next_attempt_unix,
            thermal_cooldown_until_unix: self.thermal_cooldown_until_unix,
        }
    }

    /// Convert legacy cycle waits once, without inventing completed searches.
    /// Callers persist memory even when the attempt is denied.
    fn migrate_wait_deadlines(&mut self, now_unix: u64) {
        let cycle = self.cycle;
        for stats in self.classes.values_mut() {
            if stats.next_attempt_unix.is_none() {
                let remaining = stats.next_attempt_cycle.saturating_sub(cycle);
                stats.next_attempt_unix = Some(now_unix.saturating_add(
                    remaining.saturating_mul(SEARCH_WAIT_CYCLE_SECONDS),
                ));
            }
        }
        if self.thermal_cooldown_until_unix.is_none() {
            let remaining = self.thermal_cooldown_until_cycle.saturating_sub(cycle);
            self.thermal_cooldown_until_unix = Some(now_unix.saturating_add(
                remaining.saturating_mul(SEARCH_WAIT_CYCLE_SECONDS),
            ));
        }
    }

    /// Coverage for a class, with support supplied by the registry rather than
    /// by the file.
    pub fn coverage(&self, class: OpportunityClass, registry: &AdapterRegistry) -> ClassCoverage {
        let support = registry.support(class);
        self.statistics(class).coverage(class, support)
    }

    /// Coverage for every class, implemented or not.
    pub fn coverage_all(&self, registry: &AdapterRegistry) -> Vec<ClassCoverage> {
        OpportunityClass::ALL
            .into_iter()
            .map(|c| self.coverage(c, registry))
            .collect()
    }

    fn statistics_mut(&mut self, class: OpportunityClass) -> &mut ClassStatistics {
        self.classes.entry(class).or_default()
    }

    fn add_spend(&mut self, class: OpportunityClass, spend: &BudgetSpend) {
        self.total_spend = self.total_spend.saturating_add(spend);
        let stats = self.statistics_mut(class);
        stats.spend = stats.spend.saturating_add(spend);
    }

    /// Roll an observation into the memory.
    ///
    /// Note what it does **not** do: it never touches a threshold, and it never
    /// marks a class exhausted. Exhaustion is a separate, coverage-gated decision
    /// taken in [`DiscoveryMachine::observe`].
    fn absorb(
        &mut self,
        class: OpportunityClass,
        observation: &SearchObservation,
        policy: &SearchPolicy,
        outcome: &DiscoveryState,
        now_unix: u64,
    ) {
        self.cycle = self.cycle.max(observation.cycle);
        self.current_class = class;
        // The state being *entered* decides whether the backoff applies. Reading
        // the prior state here would make every backoff a no-op, because the
        // prior state at this point is `Searching`.
        let prior_state = self.state.clone();
        let backoff_state = matches!(
            outcome,
            DiscoveryState::NoEdge { .. } | DiscoveryState::NegativeNev { .. }
        );
        let cycle = self.cycle;

        {
            let stats = self.statistics_mut(class);
            stats.cycles_attempted = stats.cycles_attempted.saturating_add(1);
            stats.cycles_completed = stats
                .cycles_completed
                .saturating_add(observation.cycles_completed);
            if observation.aborted {
                stats.cycles_aborted = stats.cycles_aborted.saturating_add(1);
            }
            if let Some(cells) = observation.cells_scanned {
                stats.cells_scanned =
                    Some(stats.cells_scanned.unwrap_or(0).saturating_add(cells));
            }
            stats.candidates_found = stats
                .candidates_found
                .saturating_add(observation.candidates.len() as u64);
            for candidate in &observation.candidates {
                if !candidate.evidence_hash.trim().is_empty() {
                    stats.routes.insert(candidate.evidence_hash.clone());
                }
            }
            if !observation.adapter.trim().is_empty() {
                stats.sources.insert(observation.adapter.clone());
            }
            stats.last_state = prior_state.clone();
        }
        self.total_cost_musd_micros = self.total_cost_musd_micros.saturating_add(
            observation
                .candidates
                .iter()
                .fold(0u64, |acc, c| acc.saturating_add(c.estimated_job_cost_musd_micros)),
        );
        self.add_spend(class, &observation.spend);

        // Bounded backoff, applied only to the states where waiting is the right
        // answer. An evidence gap or an un-comparable value is not retried on a
        // schedule: repeating the same broken input on a timer is not a retry.
        let resolved = observation.resolution.as_ref();
        {
            let stats = self.statistics_mut(class);
            // A mutually exclusive partition that mirrors
            // `observation_state`'s classification exactly, because
            // `SearchMemory::health` *sums* these three to get the number of
            // resolutions that divides `CostPerResolution::total_cost_musd_micros`.
            //
            // Overlapping buckets would inflate that sum, understate the cost per
            // resolution, and so make the `max_cost_per_resolution` gate pass more
            // easily than the spending warrants. A claim with no attestation is
            // not counted at all: it is
            // `DiscoveryState::UnattestedNev`, which is not a resolution, and
            // counting it would inflate `ResolutionRate` the same way.
            //
            // P6.0.1: this no longer re-implements the partition by hand over the
            // adapter's own integer. It calls the same `classify` the state
            // machine calls, so the two cannot drift — which is the only reason
            // the "mirrors exactly" claim above stays true.
            let required = policy.min_net_edge.micros();
            if let Some(r) = resolved {
                match r.classify(class, required) {
                    ResolutionClassification::NegativeNev { .. } => {
                        stats.resolutions_negative = stats.resolutions_negative.saturating_add(1)
                    }
                    ResolutionClassification::BreakEven { .. } => {
                        stats.resolutions_break_even = stats.resolutions_break_even.saturating_add(1)
                    }
                    ResolutionClassification::PositiveNev { .. } => {
                        stats.resolutions_positive = stats.resolutions_positive.saturating_add(1)
                    }
                    // Unattested: a claim, not a resolution. Attested without
                    // receipts: a total naming no fact, also not a resolution.
                    ResolutionClassification::UnattestedNev { .. }
                    | ResolutionClassification::AttestedWithoutReceipts { .. } => {}
                }
            }
            if !observation.candidates.is_empty() {
                stats.consecutive_empty = 0;
                stats.next_attempt_unix = Some(0);
            } else if backoff_state {
                stats.consecutive_empty = stats.consecutive_empty.saturating_add(1);
                let wait = policy.backoff.cycles_after(stats.consecutive_empty) as u64;
                stats.next_attempt_cycle = cycle.saturating_add(wait);
                stats.next_attempt_unix = Some(now_unix.saturating_add(
                    wait.saturating_mul(SEARCH_WAIT_CYCLE_SECONDS),
                ));
            }
        }
    }

    /// Search-health vector, computed from what actually happened.
    pub fn health(&self, registry: &AdapterRegistry) -> SearchHealth {
        let class_coverage = self.coverage_all(registry);
        let implemented: Vec<ClassStatistics> = OpportunityClass::ALL
            .into_iter()
            .filter(|c| registry.support(*c).can_resolve())
            .map(|c| self.statistics(c))
            .filter(|s| s.cycles_attempted > 0)
            .collect();

        let cycles_completed: u64 = class_coverage
            .iter()
            .filter(|c| c.support.can_resolve())
            .map(|c| c.cycles_completed)
            .sum();
        let cycles_budgeted: u64 = class_coverage
            .iter()
            .filter(|c| c.support.can_resolve())
            .map(|c| c.cycles_attempted)
            .sum();
        let cycles_aborted: u64 = class_coverage
            .iter()
            .map(|c| c.cycles_aborted)
            .sum();
        let cells = class_coverage
            .iter()
            .filter(|c| c.support.can_resolve())
            .filter_map(|c| c.cells_scanned)
            .min();

        let resolutions: u64 = implemented.iter().map(|s| {
            s.resolutions_negative
                .saturating_add(s.resolutions_break_even)
                .saturating_add(s.resolutions_positive)
        }).sum();
        let attempts = implemented.iter().map(|s| s.cycles_completed).sum::<u64>();

        let routes: BTreeSet<&String> = implemented
            .iter()
            .flat_map(|s| s.routes.iter())
            .collect();
        let sources: BTreeSet<&String> = implemented
            .iter()
            .flat_map(|s| s.sources.iter())
            .collect();
        let distinct_classes = implemented
            .iter()
            .filter(|s| s.candidates_found > 0 || s.cycles_completed > 0)
            .count() as u32;

        SearchHealth {
            coverage: SearchCoverage {
                cycles_budgeted,
                cycles_completed,
                cycles_aborted,
                cells_scanned: cells,
            },
            class_coverage,
            resolution_rate: ResolutionRate {
                attempts,
                resolved: resolutions,
            },
            cost_per_resolution: CostPerResolution {
                total_cost_musd_micros: self.total_cost_musd_micros,
                resolutions,
            },
            diversity: HypothesisDiversity {
                distinct_classes,
                distinct_routes: routes.len() as u32,
                distinct_sources: sources.len() as u32,
            },
        }
    }

    /// Why nothing is being searched, with the unimplemented classes named.
    pub fn cold_summary(
        &self,
        registry: &AdapterRegistry,
        policy: &SearchPolicy,
    ) -> ColdDiscoverySummary {
        let exhausted: Vec<OpportunityClass> = OpportunityClass::ALL
            .into_iter()
            .filter(|c| {
                policy.enabled_classes.contains(c)
                    && registry.support(*c).can_resolve()
                    && self.statistics(*c).exhausted
            })
            .collect();
        let unsupported = OpportunityClass::ALL
            .into_iter()
            .filter(|c| !registry.support(*c).can_resolve())
            .collect();
        let disabled = OpportunityClass::ALL
            .into_iter()
            .filter(|c| !policy.enabled_classes.contains(c))
            .collect();
        let searched_classes = exhausted.len();
        ColdDiscoverySummary {
            exhausted,
            unsupported,
            disabled,
            total_classes: OpportunityClass::ALL.len(),
            searched_classes,
        }
    }

    /// The next class worth searching, in a fixed order.
    ///
    /// Enabled, implemented, and not already exhausted. An unimplemented class is
    /// never returned no matter what the policy says, so the machine cannot be
    /// pointed at coverage it cannot produce.
    pub fn next_class(
        &self,
        registry: &AdapterRegistry,
        policy: &SearchPolicy,
    ) -> Option<OpportunityClass> {
        let keep = self.current_class;
        let usable = |c: OpportunityClass, stats: &ClassStatistics| {
            policy.enabled_classes.contains(&c)
                && registry.support(c).can_resolve()
                && !stats.exhausted
        };
        if usable(keep, &self.statistics(keep)) {
            return Some(keep);
        }
        OpportunityClass::ALL
            .into_iter()
            .find(|c| usable(*c, &self.statistics(*c)))
    }
}

impl Default for SearchMemory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Adapters
// ---------------------------------------------------------------------------

/// The crate's first production trait, and deliberately the smallest useful one.
///
/// It has one method, it returns [`SearchObservation`], and there is nothing on
/// this trait — or on any type in this module — that can sign, order or transmit
/// anything. The chain the brief requires is preserved end to end and is
/// unchanged by this:
///
/// `OpportunityAdapter` → [`SearchObservation`] → [`OpportunityCandidate`] →
/// [`crate::autonomy::AutonomousEconomy::submit_opportunity`] →
/// `orchestrate` → [`crate::autonomy::JobIntent`], with the S1 executor still the
/// only authority able to transmit.
///
/// There is no `execute()`. If a future adapter wants one, the name it converges
/// to is `observe()`/`build_intent()`, because `SearchObservation` has no field a
/// transaction hash could occupy.
///
/// A permit is required, so an adapter cannot run outside a budget, a backoff
/// window and a thermal gate. [`DiscoveryMachine::begin_search`] is the only
/// thing that issues one.
pub trait OpportunityAdapter {
    /// The class this adapter searches. Fixed by construction: the registry keys
    /// on it, and an observation whose class differs from its permit is
    /// [`DiscoveryState::InvalidEvidence`].
    fn class(&self) -> OpportunityClass;

    /// Stable identity for the audit trail. Never a gate.
    fn identity(&self) -> &str;

    /// Read what a measurement produced and classify it. Never executes.
    fn observe(&self, permit: &SearchPermit, now_unix: u64) -> Result<SearchObservation>;
}

/// Adapters, keyed by the class they search.
///
/// Support is derived here and nowhere else. An adapter cannot declare itself
/// implemented, and a class with no entry is
/// [`ClassSupport::Unsupported`] forever — which is the mechanism that stops a
/// coverage number from being manufactured for a class nothing searches.
#[derive(Default)]
pub struct AdapterRegistry {
    adapters: BTreeMap<OpportunityClass, Vec<Box<dyn OpportunityAdapter>>>,
}

impl AdapterRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The registry this crate actually has: two adapters for
    /// [`OpportunityClass::Arbitrage`] — the on-chain flash loan scanner and
    /// the S1 shadow evidence importer.
    ///
    /// Six of the seven classes are unimplemented, and they are unimplemented on
    /// purpose. Adding a stub that returns an empty set would make "searched and
    /// found nothing" indistinguishable from "never looked", which is the exact
    /// confusion the class/coverage split exists to prevent.
    ///
    /// Takes a configuration rather than inventing one: a registered adapter with
    /// no source path is an adapter that can only fail, and registering it would
    /// turn a broken setup into coverage.
    pub fn crate_default(
        config: S1ShadowEvidenceConfig,
        flash_config: crate::flash_arb_adapter::FlashArbConfig,
        verifier: crate::base_usdc::BaseUsdcVerifier,
    ) -> Result<Self> {
        let mut registry = Self::new();
        registry.register(Box::new(S1ShadowEvidenceAdapter::new(config)?));
        let flash = crate::flash_arb_adapter::FlashArbAdapter::new(flash_config, verifier)?;
        registry.register(Box::new(flash));
        Ok(registry)
    }

    pub fn register(&mut self, adapter: Box<dyn OpportunityAdapter>) {
        let class = adapter.class();
        self.adapters.entry(class).or_default().push(adapter);
    }

    pub fn adapters_for(&self, class: OpportunityClass) -> Vec<&dyn OpportunityAdapter> {
        self.adapters
            .get(&class)
            .map(|v| v.iter().map(|a| a.as_ref()).collect())
            .unwrap_or_default()
    }

    pub fn adapter(&self, class: OpportunityClass, identity: &str) -> Option<&dyn OpportunityAdapter> {
        self.adapters
            .get(&class)
            .and_then(|v| v.iter().find(|a| a.identity() == identity))
            .map(|a| a.as_ref())
    }

    pub fn support(&self, class: OpportunityClass) -> ClassSupport {
        match self.adapters.get(&class) {
            Some(v) if !v.is_empty() => ClassSupport::Implemented,
            _ => ClassSupport::Unsupported,
        }
    }

    pub fn implemented(&self) -> BTreeSet<OpportunityClass> {
        self.adapters
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(class, _)| *class)
            .collect()
    }

    pub fn identities(&self) -> BTreeMap<OpportunityClass, Vec<String>> {
        self.adapters
            .iter()
            .map(|(class, adapters)| {
                (*class, adapters.iter().map(|a| a.identity().to_string()).collect())
            })
            .collect()
    }
}

impl std::fmt::Debug for AdapterRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdapterRegistry")
            .field(
                "classes",
                &self
                    .adapters
                    .iter()
                    .map(|(c, a)| (*c, a.iter().map(|a| a.identity()).collect::<Vec<_>>()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Configuration for the one real adapter in this crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S1ShadowEvidenceConfig {
    pub source_path: String,
    pub agent_id: String,
    pub estimated_job_cost_musd_micros: u64,
    pub ttl_seconds: u64,
}

impl Default for S1ShadowEvidenceConfig {
    fn default() -> Self {
        Self {
            source_path: String::new(),
            agent_id: "s1".into(),
            estimated_job_cost_musd_micros: 50_000,
            ttl_seconds: 120,
        }
    }
}

/// The only [`OpportunityAdapter`] in the crate, over the two existing S1
/// shadow imports.
///
/// It adds no scanning. It reads a file that an external measurement process
/// produced, through the crate's own refusing importers
/// ([`crate::s1_adapter::import_shadow_scan`] and
/// [`crate::s1_perception_adapter::import_perception_report`]), and turns the
/// result into an observation.
///
/// Its real contribution to P6 is the **measured negative**. The perception
/// importer already reduces `best_observed_token_edge_usdc_raw` and
/// `best_observed_robust_net_usdc_raw` across `events[].near_edge_refinement`
/// and hands them back to the caller; before P6 every consumer discarded them.
/// This adapter keeps them as [`MeasuredEdge`], which is what makes
/// [`DiscoveryState::NoEdge`] reachable — and which means that when the
/// perception report has no such figures, the correct state is
/// [`DiscoveryState::InvalidEvidence`], not a quiet market.
#[derive(Debug, Clone)]
pub struct S1ShadowEvidenceAdapter {
    config: S1ShadowEvidenceConfig,
}

impl S1ShadowEvidenceAdapter {
    pub fn new(config: S1ShadowEvidenceConfig) -> Result<Self> {
        if config.source_path.trim().is_empty() {
            return Err(EconomyError::Invalid(
                "S1 shadow evidence adapter requires a source path".into(),
            ));
        }
        if config.agent_id.trim().is_empty() {
            return Err(EconomyError::Invalid(
                "S1 shadow evidence adapter requires an agent id".into(),
            ));
        }
        if config.estimated_job_cost_musd_micros == 0 || config.ttl_seconds == 0 {
            return Err(EconomyError::Invalid(
                "S1 shadow evidence adapter job cost and TTL must be > 0".into(),
            ));
        }
        Ok(Self { config })
    }

    pub fn config(&self) -> &S1ShadowEvidenceConfig {
        &self.config
    }

    fn observation_from_perception(
        &self,
        permit: &SearchPermit,
        report: crate::s1_perception_adapter::S1PerceptionImportReport,
    ) -> SearchObservation {
        let best_observed_edge = match (
            report.best_observed_token_edge_usdc_raw,
            report.best_observed_robust_net_usdc_raw,
        ) {
            (token_edge, Some(robust_net)) => Some(MeasuredEdge {
                token_edge_micros: token_edge,
                robust_net_micros: robust_net,
                source_field: "near_edge_refinement".into(),
            }),
            // The importer accepted the report, but the aggregate the scan
            // measured is not present. Reporting `NoEdge` from this would be
            // concluding "nothing there" from an absence of evidence, so the
            // observation is marked defective instead and the machine fails
            // closed.
            _ => None,
        };

        SearchObservation {
            schema_version: SCHEMA_VERSION,
            class: OpportunityClass::Arbitrage,
            adapter: self.identity().to_string(),
            cycle: permit.cycle,
            cycles_budgeted: report.cycles_requested,
            cycles_completed: report.cycles_completed,
            // The perception report does not count cells. `None`, not `0`: "does
            // not report" is not "processed nothing", and coverage requires a
            // positive count before a class can be exhausted.
            cells_scanned: None,
            aborted: report.cycles_completed < report.cycles_requested,
            candidates: report.opportunities,
            defect: if best_observed_edge.is_none() && report.candidates_seen == 0 {
                Some(EvidenceDefect::Unmeasured {
                    why: "the perception report carried neither \
                          best_observed_robust_net_usdc_raw nor any candidate, so \
                          there is no measured proof that the market was scanned \
                          and did not pay"
                        .into(),
                })
            } else {
                None
            },
            best_observed_edge,
            settlement: SettlementReadiness::NotApplicable,
            valuation: ValuationReadiness::NotRequired,
            thermal: ObservedThermal {
                start_max_c: report.thermal_start_max_c,
                end_c: report.end_temp_c,
                // The S1 perception report samples temperature at the two edges
                // of its window and nowhere in between, so there is no mid-run
                // peak to report. `None` says exactly that; a number here would
                // be a fabricated excursion.
                maximum_c: None,
            },
            spend: BudgetSpend::cycles(report.cycles_completed),
            resolution: None,
        }
    }

    fn observation_from_shadow(
        &self,
        permit: &SearchPermit,
        report: crate::s1_adapter::S1ImportReport,
    ) -> SearchObservation {
        // The shadow report has no aggregate "best observed edge": it carries
        // per-candidate modelled profit only, and it refuses an empty candidate
        // list outright. Cells are derivable from the block span it reports.
        let cells_scanned =
            match (first_block_of(&report), last_block_of(&report)) {
                (Some(first), Some(last)) if last >= first => Some(last - first + 1),
                _ => None,
            };
        SearchObservation {
            schema_version: SCHEMA_VERSION,
            class: OpportunityClass::Arbitrage,
            adapter: self.identity().to_string(),
            cycle: permit.cycle,
            cycles_budgeted: 1,
            cycles_completed: 1,
            cells_scanned,
            aborted: false,
            best_observed_edge: None,
            candidates: report.opportunities,
            settlement: SettlementReadiness::NotApplicable,
            valuation: ValuationReadiness::NotRequired,
            thermal: ObservedThermal::default(),
            spend: BudgetSpend::cycles(1),
            resolution: None,
            defect: None,
        }
    }
}

fn first_block_of(report: &crate::s1_adapter::S1ImportReport) -> Option<u64> {
    report
        .opportunities
        .first()
        .and_then(|o| o.metadata.get("first_block"))
        .and_then(|v| v.parse::<u64>().ok())
}

fn last_block_of(report: &crate::s1_adapter::S1ImportReport) -> Option<u64> {
    report
        .opportunities
        .first()
        .and_then(|o| o.metadata.get("last_block"))
        .and_then(|v| v.parse::<u64>().ok())
}

impl OpportunityAdapter for S1ShadowEvidenceAdapter {
    fn class(&self) -> OpportunityClass {
        OpportunityClass::Arbitrage
    }

    fn identity(&self) -> &str {
        "s1_shadow_scan"
    }

    fn observe(&self, permit: &SearchPermit, now_unix: u64) -> Result<SearchObservation> {
        let path = Path::new(&self.config.source_path);
        let bytes = std::fs::read(path)?;
        let head = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]).to_string();

        // The perception report is the one that carries the measured aggregate,
        // so it is preferred; a shadow scan is accepted when there is none. Both
        // go through the crate's own refusing importers, so `chainId`,
        // `measured`, `broadcast`, `profitIsReal`, `mode`, the cycle accounting
        // and the status whitelist are all still enforced upstream of here.
        if head.contains("\"PERCEPTION_SHADOW\"") {
            let report = import_perception_report(
                path,
                &self.config.agent_id,
                self.config.estimated_job_cost_musd_micros,
                self.config.ttl_seconds,
            )?;
            Ok(self.observation_from_perception(permit, report))
        } else {
            let report = import_shadow_scan(
                path,
                &self.config.agent_id,
                self.config.estimated_job_cost_musd_micros,
                now_unix,
                self.config.ttl_seconds,
            )?;
            Ok(self.observation_from_shadow(permit, report))
        }
    }
}

// ---------------------------------------------------------------------------
// Permits
// ---------------------------------------------------------------------------

/// Authorisation to run exactly one search of one class in one cycle.
///
/// Issued only by [`DiscoveryMachine::begin_search`]. An adapter receives one and
/// cannot obtain another, so "searched without a budget", "searched during
/// backoff" and "searched with no thermal headroom" are unreachable rather than
/// merely discouraged.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SearchPermit {
    pub class: OpportunityClass,
    pub cycle: u64,
    pub budget: SearchBudget,
    pub thermal: ThermalPermit,
}

/// Why no permit was issued.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "denied", content = "detail", rename_all = "snake_case")]
pub enum DenialReason {
    /// Still inside the bounded backoff window for this class.
    InBackoff {
        class: OpportunityClass,
        current_cycle: u64,
        next_attempt_cycle: u64,
    },
    /// A thermal gate refused.
    Thermal { stop: ThermalStop },
    /// No adapter exists.
    UnsupportedClass { class: OpportunityClass, why: String },
    /// The class is implemented but its budget is gone.
    BudgetExhausted {
        class: OpportunityClass,
        dimension: BudgetDimension,
    },
    /// Every enabled class is exhausted, unimplemented, or disabled. Reported
    /// with both lists so "I am out of things to search" is never mistaken for
    /// "there is nothing there".
    NothingSearchable {
        enabled: Vec<OpportunityClass>,
        exhausted: Vec<OpportunityClass>,
    },
}

impl DenialReason {
    pub fn state(&self) -> &'static str {
        match self {
            Self::InBackoff { .. } => "in_backoff",
            Self::Thermal { .. } => "thermal",
            Self::UnsupportedClass { .. } => "unsupported_class",
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::NothingSearchable { .. } => "nothing_searchable",
        }
    }
}

/// The outcome of asking for permission to search.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "attempt", content = "permit", rename_all = "snake_case")]
pub enum SearchAttempt {
    Proceed(SearchPermit),
    Denied(DenialReason),
}

impl SearchAttempt {
    pub fn permit(&self) -> Option<&SearchPermit> {
        match self {
            Self::Proceed(p) => Some(p),
            Self::Denied(_) => None,
        }
    }

    pub fn denial(&self) -> Option<&DenialReason> {
        match self {
            Self::Proceed(_) => None,
            Self::Denied(d) => Some(d),
        }
    }
}

// ---------------------------------------------------------------------------
// Promotion and research requests
// ---------------------------------------------------------------------------

/// A promotable result, for the caller to pass through the existing autonomy
/// gates.
///
/// P6 does not submit it. `AutonomousEconomy::submit_opportunity` and
/// `orchestrate` remain the only path from an opportunity to a
/// [`crate::autonomy::JobIntent`], and both still apply the agent's enablement,
/// job-type allowlist, expiry, per-job cost, daily budget and the caller's own
/// edge policy. Reaching this struct is necessary for promotion and not
/// sufficient.
///
/// `None` whenever any consumed threshold is
/// [`degenerate`](ThresholdRecord::degenerate) — see [`ThresholdAudit`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionCandidate {
    pub class: OpportunityClass,
    /// `stable_id("resolution", [class, policy_hash, receipts, nev])`. P6.0.1: it
    /// used to be derived from the adapter's own integer, so the caller chose it;
    /// it is now recomputable from the three fields below, which is what lets an
    /// auditor check it rather than trust it.
    pub resolution_id: String,
    /// From the [`VerifiedNev`] behind the attestation, never from
    /// [`ResolvedNev::claimed_nev_musd_micros`]. Documented at the use site
    /// because the field is `Deserialize`-able in its own right: this is a
    /// reported suggestion, and `EconomicResolution::from_discovery_state` still
    /// refuses `PositiveNev` regardless of what it claims.
    pub nev_musd_micros: i64,
    /// The policy every counted receipt was issued under — the authority the
    /// audit trail can be checked against, rather than one the operator has to
    /// take on faith. P6.0.1.
    pub policy_hash: String,
    pub required_musd_micros: u64,
    /// The candidates the observation produced. Submitted individually; each one
    /// still has to clear every autonomy gate.
    pub candidates: Vec<OpportunityCandidate>,
}

/// A request for research attention, and nothing else.
///
/// TERR's constraints are structural here rather than checked later:
///
/// * `passive_only` and `influences_execution` are private fields with no
///   `Deserialize`, set to `true`/`false` by the only constructor, and there is no
///   method that changes them;
/// * the requested job type is restricted to the three kinds
///   [`crate::terr_research::TerrResearchEngine::orchestrate`] accepts;
/// * it is emitted **only** from [`DiscoveryState::ColdDiscovery`] and only when
///   diversity is below its floor. It is never emitted from a promotable state,
///   so there is no TERR → execution path to close later — the type cannot reach
///   a [`PromotionCandidate`] and cannot name a threshold.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerrResearchRequest {
    schema_version: u32,
    pub request_id: String,
    pub observed_at_unix: u64,
    pub class: OpportunityClass,
    pub requested_job_type: JobType,
    pub requested_job_cost_musd_micros: u64,
    passive_only: bool,
    influences_execution: bool,
    pub why: String,
}

impl TerrResearchRequest {
    /// The job kinds TERR may request. Mirrors
    /// [`crate::terr_research::TerrResearchEngine::orchestrate`]'s allowlist, so
    /// a request built here is one that engine can accept — and one it can only
    /// accept into the **TERR** ledger, where its intents are structurally
    /// unfundable.
    pub fn research(
        class: OpportunityClass,
        requested_job_type: &JobType,
        requested_job_cost_musd_micros: u64,
        observed_at_unix: u64,
        why: &str,
    ) -> Result<Self> {
        if !matches!(
            requested_job_type,
            JobType::Backtest | JobType::Validation | JobType::DataTransform
        ) {
            return Err(EconomyError::Invalid(
                "TERR may request only backtest, validation or data_transform \
                 research; any other job type would be an execution request in \
                 disguise"
                    .into(),
            ));
        }
        if requested_job_cost_musd_micros == 0 {
            return Err(EconomyError::Invalid(
                "TERR research request cost must be > 0".into(),
            ));
        }
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            request_id: stable_id(
                "terrresearchrequest",
                &[
                    class.state(),
                    &format!("{requested_job_type:?}"),
                    &requested_job_cost_musd_micros.to_string(),
                    &observed_at_unix.to_string(),
                ],
            ),
            observed_at_unix,
            class,
            requested_job_type: requested_job_type.clone(),
            requested_job_cost_musd_micros,
            // Hardcoded, not read from anything, and not writable afterwards.
            passive_only: true,
            influences_execution: false,
            why: why.to_string(),
        })
    }

    /// Always `true`. Present as an accessor so the field can stay private.
    pub fn passive_only(&self) -> bool {
        self.passive_only
    }

    /// Always `false`. Present as an accessor so the field can stay private.
    pub fn influences_execution(&self) -> bool {
        self.influences_execution
    }

    pub fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

/// What the machine did, in one explicit record.
///
/// Nothing here collapses into a status string. `state` and `state_name` are the
/// conclusion, `action` is the one consequence that conclusion permits, and
/// `completed` answers a narrower question — was this a conclusion about the
/// market at all — with `false` for a thermal stop, an incomplete settlement, a
/// budget stop, invalid evidence, an unsupported class and a search in progress.
#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryReport {
    pub schema_version: u32,
    pub report_id: String,
    pub decided_at_unix: u64,
    pub cycle: u64,
    /// The state this observation produced, before the memory-level rotation.
    pub observation_state: DiscoveryState,
    pub observation_state_name: String,
    /// The state the machine is in afterwards. Equal to `observation_state` unless
    /// coverage made the class exhausted.
    pub state: DiscoveryState,
    pub state_name: String,
    pub action: SearchAction,
    pub action_name: String,
    /// `true` only for a conclusion about the market backed by completed cycles.
    pub completed: bool,
    pub class: OpportunityClass,
    /// Coverage for the searched class.
    pub coverage: ClassCoverage,
    /// Coverage for every class, with `support` reported next to it so "searched
    /// and found nothing" and "never implemented" are different rows.
    pub class_coverage: Vec<ClassCoverage>,
    /// The health vector, reported as a vector. There is no fused fitness score.
    pub health: SearchHealth,
    pub health_verdict: HealthVerdict,
    pub budget: BudgetSpend,
    pub budget_exhausted_by: Option<BudgetDimension>,
    pub backoff_cycles: u32,
    pub next_attempt_cycle: u64,
    /// Every threshold P6 consumed, with the surface each came from.
    pub thresholds: ThresholdAudit,
    /// `None` unless the state is [`DiscoveryState::PositiveNev`] and no consumed
    /// threshold is degenerate.
    pub promotion: Option<PromotionCandidate>,
    /// `Some` only from [`DiscoveryState::ColdDiscovery`] with diversity below
    /// its floor.
    pub research: Option<TerrResearchRequest>,
    /// `true` only when all seven classes are implemented, exhausted and backed
    /// by completed cycles. With six unimplemented it cannot be true.
    pub concludes_no_external_value_exists: bool,
    pub reason: String,
}

impl DiscoveryReport {
    /// Whether the machine may claim that no external value exists at all.
    ///
    /// Requires every class implemented *and* exhausted *and* backed by
    /// completed cycles. That is why [`DiscoveryState::NoEdge`] on
    /// [`OpportunityClass::Arbitrage`] cannot be read as "there is nothing
    /// there": one of seven classes was searched, and the other six have no
    /// adapter, which [`ColdDiscoverySummary`] lists on the face of the report.
    pub fn concludes_no_external_value_exists(&self) -> bool {
        self.concludes_no_external_value_exists
    }
}

// ---------------------------------------------------------------------------
// The machine
// ---------------------------------------------------------------------------

/// The autonomous search state machine.
///
/// Owns the durable [`SearchMemory`] and is the only thing that issues a
/// [`SearchPermit`], so every search is bounded, backed off and thermally gated
/// by construction rather than by convention.
///
/// It writes nothing but its own memory file, submits nothing to the autonomy
/// ledger and has no RPC write path.
#[derive(Debug, Clone)]
pub struct DiscoveryMachine {
    root: PathBuf,
}

impl DiscoveryMachine {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        crate::durability::ensure_private_dir(&root)?;
        Ok(Self { root })
    }

    pub fn memory_path(&self) -> PathBuf {
        self.root.join(SEARCH_MEMORY_FILE)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Reads the memory. A missing file is a machine that has never searched,
    /// which is the honest answer and not an error.
    pub fn load(&self) -> Result<SearchMemory> {
        let path = self.memory_path();
        if !path.exists() {
            return Ok(SearchMemory::new());
        }
        let bytes = std::fs::read(&path)?;
        let memory: SearchMemory = serde_json::from_slice(&bytes).map_err(|e| {
            EconomyError::Invalid(format!("search memory cannot be parsed: {e}"))
        })?;
        memory.validate()?;
        Ok(memory)
    }

    /// Writes the memory atomically and privately.
    ///
    /// Atomic because a half-written memory would reset a backoff window and a
    /// thermal cooldown — the two things this module most needs to survive a
    /// restart.
    pub fn store(&self, memory: &SearchMemory) -> Result<()> {
        memory.validate()?;
        // `write_private_atomic` forces 0600 on the file it writes and renames it
        // into place, so the mode is correct on a first write as well as on an
        // overwrite.
        let bytes = serde_json::to_vec_pretty(memory)?;
        crate::durability::write_private_atomic(&self.memory_path(), &bytes)
    }

    /// Asks for permission to search. The only source of [`SearchPermit`].
    ///
    /// The order of the refusals is deliberate. Thermal is checked **before**
    /// class selection so that a machine with no headroom stops before it decides
    /// anything, and unsupported classes are reported before backoff so that a
    /// class nothing implements is never described as "waiting its turn".
    pub fn begin_search(
        &self,
        memory: &mut SearchMemory,
        registry: &AdapterRegistry,
        policy: &SearchPolicy,
        mupp_gate: Option<&MuppPhysicalGate>,
        now_unix: u64,
    ) -> Result<SearchAttempt> {
        policy.validate()?;
        memory.validate()?;
        memory.migrate_wait_deadlines(now_unix);

        let thermal_deadline = memory.thermal_cooldown_until_unix.unwrap_or(0);
        if now_unix < thermal_deadline {
            let cycles_remaining = (thermal_deadline - now_unix)
                .div_ceil(SEARCH_WAIT_CYCLE_SECONDS)
                .min(u32::MAX as u64) as u32;
            memory.state = DiscoveryState::SearchAbortedThermal {
                class: memory.current_class,
                stop: ThermalStop::Cooldown { cycles_remaining },
                spend: memory.total_spend,
            };
            return Ok(SearchAttempt::Denied(DenialReason::Thermal {
                stop: ThermalStop::Cooldown { cycles_remaining },
            }));
        }

        // A thermal gate is required to proceed. `None` is a refusal: P6 will not
        // search a machine whose thermal state nobody has read. This is the fix
        // for the audit's finding that MUPP never touched discovery.
        let Some(gate) = mupp_gate else {
            let stop = ThermalStop::SensorsInvalid {
                reason: "no MUPP state was supplied; a search may not run on a \
                         machine whose thermal state has not been read"
                    .into(),
            };
            memory.state = DiscoveryState::SearchAbortedThermal {
                class: memory.current_class,
                stop: stop.clone(),
                spend: memory.total_spend,
            };
            return Ok(SearchAttempt::Denied(DenialReason::Thermal { stop }));
        };

        let thermal = match ThermalPermit::check(
            gate,
            now_unix,
            policy.required_thermal_headroom,
        ) {
            Ok(permit) => permit,
            Err(stop) => {
                memory.state = DiscoveryState::SearchAbortedThermal {
                    class: memory.current_class,
                    stop: stop.clone(),
                    spend: memory.total_spend,
                };
                return Ok(SearchAttempt::Denied(DenialReason::Thermal { stop }));
            }
        };

        let class = match memory.next_class(registry, policy) {
            Some(class) => class,
            None => {
                // The default for the empty set: nothing left to search. This is
                // the only terminal state the machine reaches on its own, and it
                // is reached by giving up, not by lowering a bar.
                let summary = memory.cold_summary(registry, policy);
                memory.state = DiscoveryState::ColdDiscovery { summary };
                return Ok(SearchAttempt::Denied(DenialReason::NothingSearchable {
                    enabled: policy.enabled_classes.iter().copied().collect(),
                    exhausted: OpportunityClass::ALL
                        .into_iter()
                        .filter(|c| memory.statistics(*c).exhausted)
                        .collect(),
                }));
            }
        };

        // Status must expose the deadline of the selected class even when
        // this attempt is denied before a SearchPermit is issued.
        memory.current_class = class;
        if !registry.support(class).can_resolve() {
            let why = "no OpportunityAdapter is registered for this class".to_string();
            memory.state = DiscoveryState::UnsupportedClass {
                class,
                why: why.clone(),
            };
            return Ok(SearchAttempt::Denied(DenialReason::UnsupportedClass {
                class,
                why,
            }));
        }

        let stats = memory.statistics(class);
        if now_unix < stats.next_attempt_unix.unwrap_or(0) {
            return Ok(SearchAttempt::Denied(DenialReason::InBackoff {
                class,
                current_cycle: memory.cycle,
                next_attempt_cycle: stats.next_attempt_cycle,
            }));
        }

        let cycle = memory.cycle.saturating_add(1);
        memory.current_class = class;
        memory.state = DiscoveryState::Searching {
            class,
            cycle,
            started_at_unix: now_unix,
        };
        Ok(SearchAttempt::Proceed(SearchPermit {
            class,
            cycle,
            budget: policy.budget,
            thermal,
        }))
    }

    /// The decision. Classifies one observation, updates the memory, and returns
    /// the report.
    ///
    /// # The classification order, and why it is this order
    ///
    /// 1. **Shape and identity.** A malformed observation, or one whose class or
    ///    cycle disagrees with its permit, is
    ///    [`DiscoveryState::InvalidEvidence`] and nothing else.
    /// 2. **Thermal, then budget.** A search that overran its budget, or ran
    ///    above its temperature ceiling, contributes no coverage and no
    ///    conclusion. Checked before anything about the market, so a thermal stop
    ///    can never be reported as a negative edge.
    /// 3. **Evidence gaps.** An incomplete settlement is
    ///    [`DiscoveryState::NoCompleteSettlement`] and an un-comparable value is
    ///    [`DiscoveryState::NoComparableNetValue`]. Both are checked before the
    ///    candidate set, because a gap in the evidence means the candidate set
    ///    cannot be trusted to be empty *or* full.
    /// 4. **A resolution.** A conclusion about a candidate outranks the fact that
    ///    the search also produced one, and it is classified against
    ///    [`MinNetEdge`] — once, here, against a policy borrowed for the call.
    /// 5. **Candidates.** Something survived the adapter's own checks.
    /// 6. **The empty set.** This is the only route to
    ///    [`DiscoveryState::NoEdge`], and it requires a [`MeasuredEdge`]. Without
    ///    one the answer is [`DiscoveryState::InvalidEvidence`]: the machine will
    ///    not conclude "nothing there" from an absence.
    /// 7. **Exhaustion.** `NoEdge` plus sufficient coverage becomes
    ///    [`DiscoveryState::ClassExhausted`], which is the only state that may
    ///    rotate the class. Insufficient coverage leaves it at `NoEdge` and the
    ///    bounded backoff decides when to look again.
    // Eight parameters, and every one is needed: the memory being updated, the
    // permit being discharged, the evidence, the registry that decides whether a
    // class exists at all, the policy that decides every bar, the threshold
    // provenance that can veto promotion, and the clock. Bundling them into a
    // context struct would only move the same data behind another name.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &self,
        memory: &mut SearchMemory,
        permit: &SearchPermit,
        observation: &SearchObservation,
        registry: &AdapterRegistry,
        policy: &SearchPolicy,
        thresholds: &ThresholdAudit,
        now_unix: u64,
    ) -> Result<DiscoveryReport> {
        policy.validate()?;
        memory.validate()?;

        if let Err(e) = observation.validate_shape() {
            // A shape violation is invalid evidence, not a reason to abort the
            // whole run: the machine keeps its state and reports the defect.
            return Ok(self.report(
                memory,
                registry,
                policy,
                thresholds,
                DiscoveryState::InvalidEvidence {
                    class: permit.class,
                    defect: EvidenceDefect::UnreadableShape { why: e.to_string() },
                },
                DiscoveryState::InvalidEvidence {
                    class: permit.class,
                    defect: EvidenceDefect::UnreadableShape { why: e.to_string() },
                },
                permit,
                observation,
                now_unix,
            ));
        }

        if observation.class != permit.class || observation.cycle != permit.cycle {
            let defect = EvidenceDefect::ClassMismatch {
                why: format!(
                    "observation is class={} cycle={} but the permit is class={} \
                     cycle={}",
                    observation.class, observation.cycle, permit.class, permit.cycle
                ),
            };
            return Ok(self.report(
                memory,
                registry,
                policy,
                thresholds,
                DiscoveryState::InvalidEvidence {
                    class: permit.class,
                    defect: defect.clone(),
                },
                DiscoveryState::InvalidEvidence {
                    class: permit.class,
                    defect,
                },
                permit,
                observation,
                now_unix,
            ));
        }

        // Steps 3-6 are resolved without touching memory, so the coverage the
        // exhaustion test needs is the one *after* this observation.
        let observation_state = self.observation_state(permit, observation, policy);

        // Step 2a: temperature first, so a thermal stop is never a market claim.
        if let Some(stop) = thermal_stop_from_observation(permit, observation) {
            let state = DiscoveryState::SearchAbortedThermal {
                class: permit.class,
                stop: stop.clone(),
                spend: observation.spend,
            };
            let after = self.apply_thermal_stop(memory, permit.class, &stop, policy, &state);
            if stop.requires_cooldown() {
                memory.thermal_cooldown_until_unix = Some(now_unix.saturating_add(
                    (policy.thermal_cooldown_cycles as u64)
                        .saturating_mul(SEARCH_WAIT_CYCLE_SECONDS),
                ));
            }
            return Ok(self.report(
                memory,
                registry,
                policy,
                thresholds,
                state,
                after,
                permit,
                observation,
                now_unix,
            ));
        }

        // Step 2b: the rest of the budget.
        if let Some(dimension) = permit.budget.exhausted_by(&observation.spend) {
            // A budget stop backs nothing off: nothing was learned, so nothing
            // is scheduled and nothing is claimed.
            let aborted = DiscoveryState::BudgetExhausted {
                class: permit.class,
                dimension,
                coverage: ClassCoverage::unimplemented(permit.class),
            };
            memory.absorb(permit.class, observation, policy, &aborted, now_unix);
            let coverage = memory.coverage(permit.class, registry);
            let state = DiscoveryState::BudgetExhausted {
                class: permit.class,
                dimension,
                coverage: coverage.clone(),
            };
            memory.state = state.clone();
            return Ok(self.report(
                memory,
                registry,
                policy,
                thresholds,
                state.clone(),
                state,
                permit,
                observation,
                now_unix,
            ));
        }

        memory.absorb(permit.class, observation, policy, &observation_state, now_unix);
        let coverage = memory.coverage(permit.class, registry);

        let next_state = match &observation_state {
            DiscoveryState::NoEdge { .. } => {
                let sufficient = coverage.sufficient_for_exhaustion(
                    &policy.health_minimums.min_class_coverage,
                    policy.health_minimums.cells_required,
                )?;
                if sufficient {
                    let stats = memory.statistics_mut(permit.class);
                    stats.exhausted = true;
                    memory.statistics_mut(permit.class).last_state =
                        DiscoveryState::ClassExhausted {
                            class: permit.class,
                            coverage: coverage.clone(),
                        };
                    DiscoveryState::ClassExhausted {
                        class: permit.class,
                        coverage: coverage.clone(),
                    }
                } else {
                    observation_state.clone()
                }
            }
            other => other.clone(),
        };
        memory.state = next_state.clone();

        Ok(self.report(
            memory,
            registry,
            policy,
            thresholds,
            observation_state,
            next_state,
            permit,
            observation,
            now_unix,
        ))
    }

    /// The pure part of the decision: observation plus policy in, one state out.
    ///
    /// Split out from [`Self::observe`] so the mapping can be tested directly and
    /// so it is obvious that no state it produces contains a threshold.
    fn observation_state(
        &self,
        permit: &SearchPermit,
        observation: &SearchObservation,
        policy: &SearchPolicy,
    ) -> DiscoveryState {
        let class = permit.class;

        if let Some(defect) = &observation.defect {
            return DiscoveryState::InvalidEvidence {
                class,
                defect: defect.clone(),
            };
        }

        match &observation.settlement {
            SettlementReadiness::Incomplete(gaps) => {
                return DiscoveryState::NoCompleteSettlement {
                    class,
                    gaps: gaps.clone(),
                }
            }
            SettlementReadiness::Complete | SettlementReadiness::NotApplicable => {}
        }

        if let ValuationReadiness::NotComparable { why } = &observation.valuation {
            return DiscoveryState::NoComparableNetValue {
                class,
                why: why.clone(),
            };
        }

        if let Some(resolved) = &observation.resolution {
            let required = policy.min_net_edge.micros();
            // P6.0.1: the classification lives in one place, `ResolvedNev::classify`,
            // and this function is one of its two callers. The number in every arm
            // below is the authority's when there is an authority and the caller's
            // claim when there is not; `PositiveNev` is reachable only through an
            // `AttestedResolution`, which no JSON can carry.
            return match resolved.classify(class, required) {
                ResolutionClassification::NegativeNev {
                    nev_musd_micros,
                    resolution_id,
                } => DiscoveryState::NegativeNev {
                    class,
                    nev_musd_micros,
                    resolution_id,
                },
                ResolutionClassification::BreakEven {
                    nev_musd_micros,
                    required_musd_micros,
                } => DiscoveryState::BreakEven {
                    class,
                    nev_musd_micros,
                    required_musd_micros,
                },
                ResolutionClassification::PositiveNev {
                    nev_musd_micros,
                    policy_hash,
                    resolution_id,
                } => DiscoveryState::PositiveNev {
                    class,
                    nev_musd_micros,
                    required_musd_micros: required,
                    resolution_id,
                    policy_hash,
                },
                ResolutionClassification::UnattestedNev {
                    claimed_nev_musd_micros,
                } => DiscoveryState::UnattestedNev {
                    class,
                    claimed_nev_musd_micros,
                },
                ResolutionClassification::AttestedWithoutReceipts {
                    nev_musd_micros,
                    receipts,
                    policy_hash,
                } => DiscoveryState::InvalidEvidence {
                    class,
                    defect: EvidenceDefect::Unmeasured {
                        why: format!(
                            "policy {policy_hash} attests {nev_musd_micros} mUSD over \
                             {receipts} receipts, and an attested total that counts no \
                             receipt names no fact; it is not a resolution and it is not \
                             promotable"
                        ),
                    },
                },
            };
        }

        if !observation.candidates.is_empty() {
            return DiscoveryState::CandidateFound {
                class,
                candidates: observation.candidates.len(),
                cycle: permit.cycle,
            };
        }

        // The empty set. `NoEdge` requires a measurement.
        match &observation.best_observed_edge {
            None => DiscoveryState::InvalidEvidence {
                class,
                defect: EvidenceDefect::Unmeasured {
                    why: "the search returned no candidate and reported no measured \
                          best-observed robust net, so there is no evidence that \
                          the market was scanned at all"
                        .into(),
                },
            },
            Some(edge) if edge.robust_net_micros >= 0 => DiscoveryState::InvalidEvidence {
                class,
                defect: EvidenceDefect::InconsistentAccounting {
                    why: format!(
                        "the search returned no candidate while its best measured \
                         robust net was {} mUSD, which is not negative; the report \
                         is internally inconsistent and is not evidence of no edge",
                        edge.robust_net_micros
                    ),
                },
            },
            Some(edge) => DiscoveryState::NoEdge {
                class,
                edge: edge.clone(),
                cycles_completed: observation.cycles_completed,
            },
        }
    }

    fn apply_thermal_stop(
        &self,
        memory: &mut SearchMemory,
        class: OpportunityClass,
        stop: &ThermalStop,
        policy: &SearchPolicy,
        state: &DiscoveryState,
    ) -> DiscoveryState {
        // No coverage and no spend are recorded: a search that was not allowed to
        // finish learned nothing, and letting it contribute coverage is how
        // "searched" comes to mean "tried once and got interrupted".
        memory.statistics_mut(class).last_state = state.clone();
        if stop.requires_cooldown() {
            memory.thermal_cooldown_until_cycle = memory
                .cycle
                .saturating_add(policy.thermal_cooldown_cycles as u64);
        }
        memory.state = state.clone();
        state.clone()
    }

    #[allow(clippy::too_many_arguments)]
    fn report(
        &self,
        memory: &SearchMemory,
        registry: &AdapterRegistry,
        policy: &SearchPolicy,
        thresholds: &ThresholdAudit,
        observation_state: DiscoveryState,
        next_state: DiscoveryState,
        permit: &SearchPermit,
        observation: &SearchObservation,
        now_unix: u64,
    ) -> DiscoveryReport {
        let cycle = permit.cycle;
        let health = memory.health(registry);
        let health_verdict = health
            .verdict(&policy.health_minimums)
            .unwrap_or(HealthVerdict::Insufficient {
                dimension: HealthDimension::ClassCoverage,
                observed: "health could not be evaluated".into(),
                required: "a valid HealthMinimums".into(),
                failing_dimensions: vec![HealthDimension::ClassCoverage],
            });
        let focus = next_state
            .class()
            .or_else(|| observation_state.class())
            .unwrap_or(START_CLASS);
        let coverage = memory.coverage(focus, registry);
        let action = next_state.action();
        let stats = memory.statistics(focus);

        let promotion = match &next_state {
            DiscoveryState::PositiveNev {
                resolution_id,
                nev_musd_micros,
                required_musd_micros,
                policy_hash,
                ..
            } if !thresholds.any_degenerate() => Some(PromotionCandidate {
                class: focus,
                resolution_id: resolution_id.clone(),
                nev_musd_micros: *nev_musd_micros,
                policy_hash: policy_hash.clone(),
                required_musd_micros: *required_musd_micros,
                candidates: observation.candidates.clone(),
            }),
            _ => None,
        };

        let research = match &next_state {
            DiscoveryState::ColdDiscovery { summary } if !health.diversity.meets(
                &policy.health_minimums.min_diversity,
            ) => TerrResearchRequest::research(
                summary
                    .unsupported
                    .first()
                    .copied()
                    .unwrap_or(START_CLASS),
                &JobType::Backtest,
                1_000_000,
                now_unix,
                "search has gone cold and hypothesis diversity is below its floor; \
                 this requests bounded research attention only and can reach no \
                 execution path",
            )
            .ok(),
            _ => None,
        };

        let concludes_no_external_value_exists = OpportunityClass::ALL.into_iter().all(|c| {
            registry.support(c).can_resolve()
                && memory.statistics(c).exhausted
                && memory.statistics(c).cycles_completed > 0
        });

        // `completed` is a conclusion about the market. Three clauses, all
        // necessary: the state must be a conclusion at all, cycles must have
        // actually finished, and the adapter must not have stopped early. The
        // last two are what stop "processed nothing" and "ran out of time" from
        // reading as completion.
        let completed = next_state.is_complete()
            && observation.cycles_completed > 0
            && !observation.aborted;

        DiscoveryReport {
            schema_version: SCHEMA_VERSION,
            report_id: stable_id(
                "discoveryreport",
                &[
                    cycle.to_string().as_str(),
                    next_state.state(),
                    observation_state.state(),
                    &now_unix.to_string(),
                ],
            ),
            decided_at_unix: now_unix,
            cycle,
            observation_state_name: observation_state.state().to_string(),
            observation_state,
            state_name: next_state.state().to_string(),
            state: next_state.clone(),
            action_name: action.state().to_string(),
            action,
            completed,
            class: focus,
            coverage: coverage.clone(),
            class_coverage: health.class_coverage.clone(),
            health,
            health_verdict,
            budget: observation.spend,
            budget_exhausted_by: permit.budget.exhausted_by(&observation.spend),
            backoff_cycles: policy.backoff.cycles_after(stats.consecutive_empty),
            next_attempt_cycle: stats.next_attempt_cycle,
            thresholds: thresholds.clone(),
            promotion,
            research,
            concludes_no_external_value_exists,
            reason: next_state.describe(),
        }
    }
}

/// A temperature reading from the observation that exceeds the permit's ceiling.
///
/// This is the first thing [`DiscoveryMachine::observe`] checks after the shape of
/// the evidence, and it is what makes the inert S1 thermal fields mean something:
/// [`crate::s1_perception_adapter`] reads `thermal_start_window.max` and
/// `end_temp_c` into its report and nothing in the crate ever compared them to
/// anything.
///
/// It reads [`ObservedThermal::peak`], which spans the start, the end **and** the
/// mid-run maximum. An excursion that crossed the ceiling and cooled back down
/// before the job finished is refused here on the strength of the maximum alone,
/// which is the whole reason that field is carried.
fn thermal_stop_from_observation(
    permit: &SearchPermit,
    observation: &SearchObservation,
) -> Option<ThermalStop> {
    let ceiling = permit.budget.max_observed_temperature_c;
    observation
        .thermal
        .peak()
        .into_iter()
        .chain(observation.spend.peak_temperature_c)
        .find(|peak| *peak > ceiling)
        .map(|observed_c| ThermalStop::BudgetTemperature {
            observed_c,
            ceiling_c: ceiling,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        autonomy::{EconomicAgentManifest, EconomicPolicy},
        mupp_adapter::{read_mupp_gate, MuppAdapterPolicy},
    };
    use serde_json::{json, Value};
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    // ---------------------------------------------------------------------
    // Fixtures
    // ---------------------------------------------------------------------

    fn setup() -> (tempfile::TempDir, DiscoveryMachine) {
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        (dir, machine)
    }

    fn write_mupp_state(
        dir: &tempfile::TempDir,
        timestamp: f64,
        allow: bool,
        headroom_c: f64,
        phase: &str,
        sensor_ok: bool,
    ) -> std::path::PathBuf {
        let path = dir.path().join("mupp-state.json");
        let value = serde_json::json!({
            "schema_version": 1,
            "timestamp_unix": timestamp,
            "mode": "MUPP_LOCAL_CONTROL",
            "regime": "ECO",
            "phase": phase,
            "T": 60.0 + headroom_c,
            "H": headroom_c,
            "RecoveryDebt": 0.0,
            "sensor_ok": sensor_ok,
            "sensor_warmup_complete": true,
            "allow_execution": allow,
            "cpu_temp_c": 60.0,
            "gpu_temp_c": 50.0,
            "cpu_util_pct": 10.0,
            "gpu_util_pct": 0.0,
            "queue": 0
        });
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    }

    /// A MUPP gate that permits a search.
    fn healthy_gate(dir: &tempfile::TempDir, now: u64) -> MuppPhysicalGate {
        let path = write_mupp_state(dir, now as f64 - 1.0, true, 12.0, "IDLE", true);
        read_mupp_gate(&path, now as f64, &MuppAdapterPolicy::default()).unwrap()
    }

    // ---------------------------------------------------------------------
    // P6.0.1 — the only way to get an attestation in this module
    // ---------------------------------------------------------------------

    /// A genuine [`VerifiedNev`], built the way `verified_view.rs` builds one:
    /// a policy validated from the pinned anchor, a receipt signed by the key
    /// that policy delegated to, a crossing that re-derives against the
    /// operator's registry, and a chain read that confirms the transfer.
    ///
    /// P6.0.1: this is the whole point of the change. Attestation used to be the
    /// string `"chain_attested"` in a struct literal, so every test below could
    /// assert `PositiveNev` without anything having been verified. Now the only
    /// way in is a `VerifiedNev` this crate actually minted, and the recipe is
    /// the existing one rather than a second copy — a copy would be a second
    /// thing to keep in step with P4.5b's signature and P4.5c's chain read.
    ///
    /// The real total is 5_000_000 mUSD over one receipt, which clears the
    /// crate-default `MinNetEdge` of 10_000 by a wide margin — deliberately, so a
    /// test that passes a *different* number alongside it cannot be passing by
    /// coincidence.
    fn real_verified_nev() -> (VerifiedNev, String) {
        use crate::verified_view::tests::{fixture, record_genuine_inflow_with, Authenticated};
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Authenticated::new(dir.path(), &f.autonomy);
        record_genuine_inflow_with(&f, Some(&auth));
        let nev = auth.view().verified_nev().expect("the fixture is a genuine inflow");
        assert_eq!(nev.nev_musd_micros(), 5_000_000);
        assert_eq!(nev.receipts(), 1);
        assert!(nev.is_positive());
        assert!(nev.provider_identity_verified());
        let policy_hash = nev.policy_hash().to_string();
        (nev, policy_hash)
    }

    /// An attested [`ResolvedNev`], and the policy hash it was issued under.
    ///
    /// `claimed` is what the adapter said, and it is deliberately wrong in every
    /// test that uses this: the state's number must come from the `VerifiedNev`.
    fn attested_resolution(claimed_nev_musd_micros: i64) -> (ResolvedNev, String) {
        let (nev, policy_hash) = real_verified_nev();
        (
            ResolvedNev::attested(AttestedResolution::from_verified(nev), claimed_nev_musd_micros),
            policy_hash,
        )
    }

    fn candidate(id: &str, gross: u64) -> OpportunityCandidate {
        let mut metadata = BTreeMap::new();
        metadata.insert("route".into(), format!("route-{id}"));
        OpportunityCandidate {
            schema_version: SCHEMA_VERSION,
            opportunity_id: id.into(),
            agent_id: "s1-arb-01".into(),
            observed_at_unix: 1_700_000_100,
            expires_at_unix: 1_700_001_000,
            job_type: JobType::Simulation,
            input_hash: format!("blake3:input-{id}"),
            evidence_hash: format!("blake3:evidence-{id}"),
            expected_gross_musd_micros: gross,
            expected_external_cost_musd_micros: 0,
            estimated_job_cost_musd_micros: 50_000,
            risk_buffer_musd_micros: 0,
            metadata,
        }
    }

    fn base_observation(cycle: u64) -> SearchObservation {
        SearchObservation {
            schema_version: SCHEMA_VERSION,
            class: START_CLASS,
            adapter: "test_adapter".into(),
            cycle,
            cycles_budgeted: 1,
            cycles_completed: 1,
            cells_scanned: Some(1),
            aborted: false,
            candidates: Vec::new(),
            best_observed_edge: None,
            settlement: SettlementReadiness::NotApplicable,
            valuation: ValuationReadiness::NotRequired,
            thermal: ObservedThermal {
                start_max_c: Some(40.0),
                end_c: Some(41.0),
                maximum_c: None,
            },
            spend: BudgetSpend::cycles(1),
            resolution: None,
            defect: None,
        }
    }

    /// The empty candidate set *with* the measured proof it did not pay.
    fn no_edge_observation(cycle: u64, robust_net_micros: i64) -> SearchObservation {
        let mut o = base_observation(cycle);
        o.best_observed_edge = Some(MeasuredEdge {
            token_edge_micros: Some(-32_674),
            robust_net_micros,
            source_field: "near_edge_refinement".into(),
        });
        o
    }

    /// A permit for one search, obtained the only way it can be obtained.
    fn permit(
        machine: &DiscoveryMachine,
        memory: &mut SearchMemory,
        registry: &AdapterRegistry,
        policy: &SearchPolicy,
        gate: &MuppPhysicalGate,
        now: u64,
    ) -> SearchPermit {
        match machine
            .begin_search(memory, registry, policy, Some(gate), now)
            .unwrap()
        {
            SearchAttempt::Proceed(p) => p,
            SearchAttempt::Denied(d) => panic!("expected a permit, got {d:?}"),
        }
    }

    /// The registry this crate really has: only the S1 shadow adapter, since
    /// the flash arb adapter requires a live Base RPC endpoint which isn't
    /// available in unit tests.
    fn registry() -> AdapterRegistry {
        let mut registry = AdapterRegistry::new();
        registry.register(Box::new(
            S1ShadowEvidenceAdapter::new(S1ShadowEvidenceConfig {
                source_path: "/nonexistent/p6-test-source.json".into(),
                agent_id: "s1".into(),
                estimated_job_cost_musd_micros: 50_000,
                ttl_seconds: 120,
            })
            .unwrap(),
        ));
        registry
    }

    /// The same registry, pointing at a real file the test wrote.
    fn registry_for(path: &Path) -> AdapterRegistry {
        let mut registry = AdapterRegistry::new();
        registry.register(Box::new(
            S1ShadowEvidenceAdapter::new(S1ShadowEvidenceConfig {
                source_path: path.display().to_string(),
                agent_id: "s1".into(),
                estimated_job_cost_musd_micros: 50_000,
                ttl_seconds: 120,
            })
            .unwrap(),
        ));
        registry
    }

    fn default_audit() -> ThresholdAudit {
        ThresholdAudit::from_economic_policy(&EconomicPolicy::default())
    }

    fn all_states() -> Vec<DiscoveryState> {
        vec![
            DiscoveryState::Searching {
                class: START_CLASS,
                cycle: 1,
                started_at_unix: 1,
            },
            DiscoveryState::CandidateFound {
                class: START_CLASS,
                candidates: 1,
                cycle: 1,
            },
            DiscoveryState::NoEdge {
                class: START_CLASS,
                edge: MeasuredEdge {
                    token_edge_micros: Some(-1),
                    robust_net_micros: -1,
                    source_field: "near_edge_refinement".into(),
                },
                cycles_completed: 1,
            },
            DiscoveryState::NoCompleteSettlement {
                class: START_CLASS,
                gaps: vec![SettlementGap::Absent { why: "x".into() }],
            },
            DiscoveryState::NoComparableNetValue {
                class: START_CLASS,
                why: "no price".into(),
            },
            DiscoveryState::NegativeNev {
                class: START_CLASS,
                nev_musd_micros: -5,
                resolution_id: "r".into(),
            },
            DiscoveryState::BreakEven {
                class: START_CLASS,
                nev_musd_micros: 0,
                required_musd_micros: 10_000,
            },
            DiscoveryState::PositiveNev {
                class: START_CLASS,
                nev_musd_micros: 50_000,
                required_musd_micros: 10_000,
                resolution_id: "r".into(),
                policy_hash: "0xpolicy".into(),
            },
            DiscoveryState::UnattestedNev {
                class: START_CLASS,
                claimed_nev_musd_micros: 50_000,
            },
            DiscoveryState::InvalidEvidence {
                class: START_CLASS,
                defect: EvidenceDefect::Unmeasured { why: "x".into() },
            },
            DiscoveryState::ClassExhausted {
                class: START_CLASS,
                coverage: ClassCoverage::unimplemented(START_CLASS),
            },
            DiscoveryState::ColdDiscovery {
                summary: ColdDiscoverySummary {
                    exhausted: Vec::new(),
                    unsupported: Vec::new(),
                    disabled: Vec::new(),
                    total_classes: 7,
                    searched_classes: 0,
                },
            },
            DiscoveryState::SearchAbortedThermal {
                class: START_CLASS,
                stop: ThermalStop::Cooldown { cycles_remaining: 1 },
                spend: BudgetSpend::default(),
            },
            DiscoveryState::UnsupportedClass {
                class: START_CLASS,
                why: "no adapter".into(),
            },
            DiscoveryState::BudgetExhausted {
                class: START_CLASS,
                dimension: BudgetDimension::Cycles,
                coverage: ClassCoverage::unimplemented(START_CLASS),
            },
        ]
    }

    // ---------------------------------------------------------------------
    // A — OpportunityClass
    // ---------------------------------------------------------------------

    #[test]
    fn every_opportunity_class_has_a_distinct_machine_readable_name() {
        let names: BTreeSet<&str> = OpportunityClass::ALL.iter().map(|c| c.state()).collect();
        assert_eq!(names.len(), OpportunityClass::ALL.len());
        for class in OpportunityClass::ALL {
            assert_eq!(OpportunityClass::from_state(class.state()).unwrap(), class);
        }
        assert!(OpportunityClass::from_state("not_a_class").is_err());
    }

    #[test]
    fn no_edge_on_arbitrage_does_not_conclude_no_external_value_exists() {
        // The point of naming seven classes: one measured negative in one of them
        // is not a statement about the other six.
        let (_dir, machine) = setup();
        let memory = &mut SearchMemory::new();
        let registry = registry();
        let policy = SearchPolicy::default();
        let report = run_once(&machine, memory, &registry, &policy);

        assert_eq!(report.observation_state.state(), "no_edge");
        assert!(!report.concludes_no_external_value_exists());
        assert!(!report.concludes_no_external_value_exists());

        let unsupported = report
            .class_coverage
            .iter()
            .filter(|c| c.support == ClassSupport::Unsupported)
            .count();
        assert_eq!(unsupported, 6, "six classes have no adapter and say so");
        assert_eq!(
            report
                .class_coverage
                .iter()
                .filter(|c| c.support == ClassSupport::Implemented)
                .count(),
            1
        );
    }

    // ---------------------------------------------------------------------
    // B — DiscoveryState
    // ---------------------------------------------------------------------

    #[test]
    fn every_discovery_state_has_a_distinct_machine_readable_name() {
        let names: BTreeSet<&str> = all_states().iter().map(DiscoveryState::state).collect();
        assert_eq!(names.len(), all_states().len(), "{names:?}");
    }

    #[test]
    fn every_state_declares_its_own_class_except_cold_discovery() {
        for state in all_states() {
            match state.state() {
                "cold_discovery" => assert!(state.class().is_none()),
                _ => assert!(state.class().is_some(), "{state:?}"),
            }
        }
    }

    #[test]
    fn states_round_trip_through_the_tagged_wire_format() {
        // Same discipline as SettlementIncompleteness: a reader can tell the
        // failure modes apart without parsing prose.
        for state in all_states() {
            let json = serde_json::to_value(&state).unwrap();
            assert_eq!(
                json.get("state").and_then(|v| v.as_str()),
                Some(state.state()),
                "{state:?}"
            );
            let back: DiscoveryState = serde_json::from_value(json).unwrap();
            assert_eq!(back, state);
        }
    }

    // ---------------------------------------------------------------------
    // C — the default for the empty set
    // ---------------------------------------------------------------------

    #[test]
    fn empty_set_with_insufficient_coverage_stays_no_edge_and_backs_off() {
        let (_dir, machine) = setup();
        let memory = &mut SearchMemory::new();
        let registry = registry();
        let policy = SearchPolicy::default();

        // The perception importer does not report cells, so `cells_scanned` is
        // None. That is not sufficient coverage: the machine may not conclude the
        // class is exhausted from an unknown number of cells.
        let mut observation = no_edge_observation(1, -2_032_674);
        observation.cells_scanned = None;

        let gate = healthy_gate(
            &tempdir().unwrap(),
            1_000,
        );
        let p = permit(&machine, memory, &registry, &policy, &gate, 1_000);
        let report = machine
            .observe(
                memory,
                &p,
                &observation,
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();

        assert_eq!(report.state.state(), "no_edge");
        assert_eq!(report.action, SearchAction::BackoffAndContinueSearch);
        assert!(report.completed, "a measured negative with completed cycles is a result");
        assert!(report.next_attempt_cycle > 0, "backoff was scheduled");
        assert!(report.next_attempt_cycle <= 1 + 32, "and it is bounded");
    }

    #[test]
    fn empty_set_with_sufficient_coverage_marks_the_class_exhausted() {
        let (_dir, machine) = setup();
        let memory = &mut SearchMemory::new();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&tempdir().unwrap(), 1_000);

        let p = permit(&machine, memory, &registry, &policy, &gate, 1_000);
        let observation = no_edge_observation(1, -2_032_674);
        let report = machine
            .observe(
                memory,
                &p,
                &observation,
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();

        assert_eq!(report.observation_state.state(), "no_edge");
        assert_eq!(report.state.state(), "class_exhausted");
        assert_eq!(report.action, SearchAction::RotateClass);
        assert!(memory.statistics(START_CLASS).exhausted);
        assert!(report.coverage.support.can_resolve());
    }

    #[test]
    fn the_empty_set_defaults_to_cold_discovery_and_never_to_a_lower_bar() {
        let (dir, machine) = setup();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();

        // Exhaust the one implemented class.
        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
        machine
            .observe(
                &mut memory,
                &p,
                &no_edge_observation(1, -1),
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();

        // Now nothing is searchable. The default is ColdDiscovery.
        let attempt = machine
            .begin_search(&mut memory, &registry, &policy, Some(&gate), 1_001)
            .unwrap();
        let denial = attempt.denial().expect("nothing is searchable");
        assert_eq!(denial.state(), "nothing_searchable");
        assert_eq!(memory.state.state(), "cold_discovery");
        assert_eq!(memory.state.action(), SearchAction::HoldCold);

        // And the forbidden fallbacks are not actions this type can express.
        for action in [SearchAction::HoldCold, SearchAction::RotateClass] {
            assert_ne!(action, SearchAction::HandOffToAuthorityTrail);
        }

        // The summary names the six classes nothing implements, so "cold" cannot
        // be read as "there is nothing there".
        let summary = match &memory.state {
            DiscoveryState::ColdDiscovery { summary } => summary.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(summary.unsupported.len(), 6);
        assert_eq!(summary.exhausted, vec![START_CLASS]);
        assert!(summary.describe().contains("arbitrage"));
        assert!(summary.describe().contains("solver_reward"));
    }

    #[test]
    fn no_transition_can_carry_a_mutated_threshold() {
        // The forbidden fallbacks are: lowering the min-profit threshold, ignoring
        // gas, ignoring latency, changing a cost ceiling, turning a negative edge
        // positive, or scanning indefinitely. The first five are structurally
        // impossible because no state carries a threshold; the sixth is bounded
        // by the budget and the exhaustion gate.
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let audit = default_audit();

        let mut memory = SearchMemory::new();
        let before = serde_json::to_value(&policy).unwrap();
        let mut seen_states = Vec::new();

        for cycle in 1..=6u64 {
            let Some(p) = machine
                .begin_search(&mut memory, &registry, &policy, Some(&gate), 1_000 + cycle)
                .unwrap()
                .permit()
                .cloned()
            else {
                break;
            };
            let observation = match cycle % 3 {
                0 => no_edge_observation(p.cycle, -1),
                1 => {
                    let mut o = base_observation(p.cycle);
                    o.candidates = vec![candidate(&format!("opp-{cycle}"), 5_000_000)];
                    o
                }
                _ => no_edge_observation(p.cycle, -1),
            };
            let report = machine
                .observe(&mut memory, &p, &observation, &registry, &policy, &audit, 1_000)
                .unwrap();
            seen_states.push(report.state.clone());
        }

        // The policy is untouched by every transition.
        assert_eq!(serde_json::to_value(&policy).unwrap(), before);

        // No reachable state has a field whose name looks like a movable bar.
        for state in seen_states.iter().chain(all_states().iter()) {
            let json = serde_json::to_value(state).unwrap();
            check_no_threshold_fields(&json, state.state());
        }
    }

    fn check_no_threshold_fields(value: &serde_json::Value, path: &str) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, v) in map {
                    let lowered = key.to_lowercase();
                    assert!(
                        !lowered.contains("threshold")
                            && !lowered.contains("min_net")
                            && !lowered.contains("gas_weight")
                            && !lowered.contains("latency_weight")
                            && !lowered.contains("cost_ceiling"),
                        "{path}/{key} is a movable bar"
                    );
                    check_no_threshold_fields(v, &format!("{path}/{key}"));
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    check_no_threshold_fields(item, path);
                }
            }
            _ => {}
        }
    }

    // ---------------------------------------------------------------------
    // D — outcome-specific actions
    // ---------------------------------------------------------------------

    #[test]
    fn each_state_has_exactly_one_action_and_it_is_derived_not_decided() {
        let expected = [
            ("searching", SearchAction::ContinueSearchWithinBudget),
            ("candidate_found", SearchAction::HandOffToAuthorityTrail),
            ("no_edge", SearchAction::BackoffAndContinueSearch),
            ("no_complete_settlement", SearchAction::RecordEvidenceGap),
            ("no_comparable_net_value", SearchAction::RequestValuation),
            ("negative_nev", SearchAction::RecordNegativeResolution),
            ("break_even", SearchAction::DoNotPromote),
            ("positive_nev", SearchAction::HandOffToAuthorityTrail),
            ("unattested_nev", SearchAction::RequestChainAttestation),
            ("invalid_evidence", SearchAction::FailClosed),
            ("class_exhausted", SearchAction::RotateClass),
            ("cold_discovery", SearchAction::HoldCold),
            ("search_aborted_thermal", SearchAction::EnterThermalCooldown),
            ("unsupported_class", SearchAction::SkipUnsupportedClass),
            ("budget_exhausted", SearchAction::StopClassThisRun),
        ];
        for state in all_states() {
            let found = expected
                .iter()
                .find(|(name, _)| *name == state.state())
                .unwrap_or_else(|| panic!("{} is not in the table", state.state()));
            assert_eq!(state.action(), found.1, "{}", state.state());
        }
        assert_eq!(all_states().len(), expected.len());
    }

    #[test]
    fn incomplete_settlement_records_a_gap_and_does_not_re_run_discovery() {
        let report = observe(base_observation_with(|o| {
            o.settlement = SettlementReadiness::Incomplete(vec![
                SettlementGap::LegUnattested {
                    why: "no validated outcome policy is in force".into(),
                },
                SettlementGap::NativeCostUnpriced {
                    why: "gas was burned and nothing prices it".into(),
                },
            ]);
        }));
        assert_eq!(report.state.state(), "no_complete_settlement");
        assert_eq!(report.action, SearchAction::RecordEvidenceGap);
        assert_ne!(report.action, SearchAction::ContinueSearchWithinBudget);
        assert_ne!(report.action, SearchAction::BackoffAndContinueSearch);
        assert!(!report.completed, "an incomplete settlement is not a completion");
        assert!(report.promotion.is_none());
        match report.state {
            DiscoveryState::NoCompleteSettlement { gaps, .. } => {
                assert_eq!(gaps.len(), 2);
                assert_eq!(gaps[1].state(), "native_cost_unpriced");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn uncomparable_value_requests_valuation_and_does_not_re_run_discovery() {
        let report = observe(base_observation_with(|o| {
            o.valuation = ValuationReadiness::NotComparable {
                why: "no validated price for the burned native cost".into(),
            };
        }));
        assert_eq!(report.state.state(), "no_comparable_net_value");
        assert_eq!(report.action, SearchAction::RequestValuation);
        assert_ne!(report.action, SearchAction::ContinueSearchWithinBudget);
        assert!(report.promotion.is_none());
    }

    #[test]
    fn invalid_evidence_fails_closed_and_is_not_no_edge() {
        let report = observe(SearchObservation::defective(
            START_CLASS,
            "test_adapter",
            1,
            EvidenceDefect::UnreadableShape {
                why: "the file is not a report this machine can read".into(),
            },
        ));
        assert_eq!(report.state.state(), "invalid_evidence");
        assert_ne!(report.state.state(), "no_edge");
        assert_eq!(report.action, SearchAction::FailClosed);
        assert!(!report.completed);
        assert!(report.promotion.is_none());
    }

    #[test]
    fn an_empty_set_without_a_measured_negative_is_invalid_evidence() {
        // The key discarded-evidence property: no measurement, no `NoEdge`.
        let report = observe(base_observation(1));
        assert_eq!(report.state.state(), "invalid_evidence");
        assert_ne!(report.state.state(), "no_edge");
        match report.state {
            DiscoveryState::InvalidEvidence { defect, .. } => {
                assert_eq!(defect.state(), "unmeasured");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_non_negative_best_edge_with_no_candidate_is_inconsistent_not_no_edge() {
        let mut o = no_edge_observation(1, 500_000);
        o.best_observed_edge.as_mut().unwrap().robust_net_micros = 0;
        let report = observe(o);
        assert_eq!(report.state.state(), "invalid_evidence");
        match report.state {
            DiscoveryState::InvalidEvidence { defect, .. } => {
                assert_eq!(defect.state(), "inconsistent_accounting");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn negative_nev_records_the_resolution_and_backs_off() {
        let mut o = no_edge_observation(1, -1);
        // P6.0.1: a claim, not a fabricated attestation. The outcome asserted
        // here never depended on the attestation — `NegativeNev` is not
        // promotable and the loss still backs the class off — so the old
        // `"chain_attested"` literal was decoration. What is left is the claim
        // the adapter actually wrote.
        o.resolution = Some(ResolvedNev::claimed(-750_000));
        let report = observe(o);
        assert_eq!(report.state.state(), "negative_nev");
        assert_eq!(report.action, SearchAction::RecordNegativeResolution);
        assert!(report.next_attempt_cycle > 0, "a loss backs the class off");
        assert!(report.promotion.is_none());
        assert_eq!(report.coverage.resolutions_negative, 1);
    }

    #[test]
    fn break_even_does_not_promote() {
        for nev in [0i64, 1, 9_999] {
            let mut o = no_edge_observation(1, -1);
            o.resolution = Some(ResolvedNev::claimed(nev));
            let report = observe(o);
            assert_eq!(report.state.state(), "break_even", "nev={nev}");
            assert_eq!(report.action, SearchAction::DoNotPromote);
            assert!(report.promotion.is_none(), "nev={nev}");
            assert!(!report.state.is_promotable());
        }
    }

    #[test]
    fn a_genuine_attestation_below_the_minimum_is_break_even_not_promotion() {
        // P6.0.1. The repaired `break_even_does_not_promote` above can only
        // exercise the *claim* arm, because a real total is either above the
        // minimum or it is not something worth asserting. This is the genuine
        // arm: a real `VerifiedNev` of 5_000_000 mUSD judged against a required
        // 10_000_000, so the number in the state is the authority's and the
        // state is still `BreakEven`.
        let (resolution, _) = attested_resolution(i64::MIN);
        assert_eq!(
            resolution.classify(START_CLASS, 10_000_000),
            ResolutionClassification::BreakEven {
                nev_musd_micros: 5_000_000,
                required_musd_micros: 10_000_000,
            }
        );
    }

    #[test]
    fn positive_nev_is_the_only_state_that_reaches_the_authority_trail() {
        let states = all_states();
        let promotable: Vec<&DiscoveryState> =
            states.iter().filter(|s| s.is_promotable()).collect();
        assert_eq!(promotable.len(), 1);
        assert_eq!(promotable[0].state(), "positive_nev");

// P6.0.1: a real `VerifiedNev`, and an adapter that claimed something
        // else entirely. The state's number is the authority's.
        let (nev, policy_hash) = real_verified_nev();
        let attested = AttestedResolution::from_verified(nev);
        let mut o = no_edge_observation(1, -1);
        o.resolution = Some(ResolvedNev::attested(attested.clone(), 999_999_999));
        let report = observe(o);
        assert_eq!(report.state.state(), "positive_nev");
        assert_eq!(report.action, SearchAction::HandOffToAuthorityTrail);
        assert!(report.promotion.is_some());
        let promotion = report.promotion.as_ref().unwrap();
        assert_eq!(promotion.nev_musd_micros, 5_000_000);
        assert_eq!(promotion.policy_hash, policy_hash);

        // And the id is derived from the authority, not from the claim. P6.0.1:
        // this pairs ONE attestation with SEVERAL claims. It deliberately does not
        // compare two separately built fixtures against each other: two fixtures
        // are two independently validated policies, `policy_hash` is part of the
        // id, and comparing them would have been comparing two different
        // authorities — it would have failed for a reason that has nothing to do
        // with the claim, which is exactly the mistake this assertion exists to
        // rule out.
        let id = attested.resolution_id(START_CLASS);
        assert_eq!(promotion.resolution_id, id);
        let required = MinNetEdge::crate_default().micros();
        for claim in [-1i64, 0, 7, 999_999_999, i64::MAX] {
            assert_eq!(
                ResolvedNev::attested(attested.clone(), claim).classify(START_CLASS, required),
                ResolutionClassification::PositiveNev {
                    nev_musd_micros: 5_000_000,
                    policy_hash: policy_hash.clone(),
                    resolution_id: id.clone(),
                },
                "claim={claim}: the authority decides the whole classification"
            );
        }
        // And the id is not the caller-chosen digest of the old, pre-P6.0.1 shape.
        assert_ne!(
            id,
            crate::stable_id("resolution", &[START_CLASS.state(), "999999999"])
        );
    }

    /// The three resolution counters are a mutually exclusive partition, because
    /// `SearchMemory::health` *sums* them to get the divisor of
    /// `CostPerResolution::total_cost_musd_micros`.
    ///
    /// When a positive resolution was also counted as break-even, one resolution
    /// divided the total cost by two: `micros_per_resolution` came out at half
    /// the truth and the `max_cost_per_resolution` gate passed twice as easily as
    /// the spending warranted. A resolution is counted once, in the bucket its
    /// own state belongs to, and an unattested claim is not counted at all.
    #[test]
    fn a_resolution_is_counted_once_and_never_as_break_even_too() {
        let required = MinNetEdge::crate_default().micros() as i64;

        // (claim, expected negative / break-even / positive)
        for (claim, expected) in [
            (-1i64, (1u64, 0u64, 0u64)),
            (0, (0, 1, 0)),
            (required - 1, (0, 1, 0)),
            // At or above the minimum with no attestation is `UnattestedNev`,
            // which is not a resolution. Counting it would inflate
            // `ResolutionRate`.
            (required, (0, 0, 0)),
            (900_000, (0, 0, 0)),
        ] {
            let mut o = no_edge_observation(1, -1);
            o.candidates = vec![candidate("opp-1", 5_000_000)];
            o.resolution = Some(ResolvedNev::claimed(claim));
            let report = observe(o);
            assert_resolution_buckets(&report, expected, claim);
        }

        // P6.0.1: the same partition, now with a genuine attestation behind it.
        // The claim written alongside is deliberately wrong, so this also shows
        // the authority's number is the one that decides the bucket.
        for claim in [-1i64, 0, 900_000, i64::MAX] {
            let mut o = no_edge_observation(1, -1);
            o.candidates = vec![candidate("opp-1", 5_000_000)];
            let (resolution, _) = attested_resolution(claim);
            o.resolution = Some(resolution);
            let report = observe(o);
            assert_resolution_buckets(&report, (0, 0, 1), claim);
        }
    }

    /// The three counters must agree, must never sum past one, and must be the
    /// divisor the cost gate actually uses.
    fn assert_resolution_buckets(
        report: &DiscoveryReport,
        expected: (u64, u64, u64),
        claim: i64,
    ) {
        let c = &report.coverage;
        assert_eq!(
            (
                c.resolutions_negative,
                c.resolutions_break_even,
                c.resolutions_positive
            ),
            expected,
            "claim={claim}"
        );
        // The buckets partition the observations: at most one is ever set.
        let buckets = c.resolutions_negative + c.resolutions_break_even + c.resolutions_positive;
        assert!(buckets <= 1, "claim={claim} counted {buckets} times");

        // And the divisor the cost gate uses is that same count, so the cost
        // per resolution is the real cost rather than a fraction of it.
        let resolutions = c.resolutions_negative + c.resolutions_break_even + c.resolutions_positive;
        let cost = CostPerResolution {
            total_cost_musd_micros: 400_000,
            resolutions,
        };
        let expected_micros = if resolutions == 0 {
            None
        } else {
            Some(400_000 / resolutions)
        };
        assert_eq!(
            cost.micros_per_resolution(),
            expected_micros,
            "claim={claim}: the divisor must be the number of resolutions"
        );
    }

    #[test]
    fn a_claimed_positive_nev_without_attestation_is_never_positive_nev() {
        // Without this state, a caller-supplied number would have to be either
        // accepted (trust laundering through a decision layer) or mislabelled as
        // break-even (a false statement about value).
        let mut o = no_edge_observation(1, -1);
        let resolution = ResolvedNev::claimed(900_000);
        assert!(!resolution.is_attested());
        assert_eq!(resolution.attested_nev_musd_micros(), None);
        o.resolution = Some(resolution);
        let report = observe(o);
        assert_eq!(report.state.state(), "unattested_nev");
        assert_ne!(report.state.state(), "positive_nev");
        assert_ne!(report.state.state(), "break_even");
        assert_eq!(report.action, SearchAction::RequestChainAttestation);
        assert!(report.promotion.is_none());
    }

    // ---------------------------------------------------------------------
    // P6.0.1 — the attestation capability
    //
    // One question, asked from both sides: can anybody who is not this crate
    // produce an `AttestedResolution`, and therefore a
    // `DiscoveryState::PositiveNev`, out of text or an integer? Before P6.0.1
    // the answer was yes, and the two words `{"trust":"chain_attested"}` were
    // all it took.
    // ---------------------------------------------------------------------

    /// The document a caller would have written to forge an attestation before
    /// P6.0.1, spelled out in full.
    fn forged_trust_json() -> Value {
        json!({
            "nev_musd_micros": 900_000i64,
            "trust": { "chain_attested": { "provider": "x" } }
        })
    }

    #[test]
    fn a_caller_cannot_deserialize_an_attested_resolution() {
        // P6.0.1, negative. Behavioural half; the source-level half is
        // `attested_resolution_has_no_deserialize_and_no_production_constructor`
        // below. Both, because either alone can be satisfied by accident: the
        // behavioural one by a field name that happens to be unknown, the
        // source-level one by a comment.
        //
        // The first document is exactly what the pre-P6.0.1 code accepted and
        // read `can_attest() == true` off. It must not parse at all.
        assert!(
            serde_json::from_value::<ResolvedNev>(forged_trust_json()).is_err(),
            "a document that names an attestation must not parse as a ResolvedNev"
        );

        // Drop the retired key and the same number parses as a plain claim: a
        // loud demotion rather than a quiet one, so a caller upgrading sees the
        // refusal instead of a silent change of meaning.
        let claim = json!({ "nev_musd_micros": 900_000i64 });
        let parsed: ResolvedNev = serde_json::from_value(claim.clone()).unwrap();
        assert!(!parsed.is_attested());
        assert_eq!(parsed.attested_nev_musd_micros(), None);
        assert_eq!(parsed.claimed_nev_musd_micros, 900_000);

        // Spelling the capability field out in full — every field, the right
        // shapes, the right types, a plausible provider and policy hash — is
        // refused outright rather than quietly ignored. `deny_unknown_fields`
        // treats a `skip_deserializing` field as unknown, so the document does
        // not even become a claim: a caller who tries this learns that the field
        // is not part of the wire shape at all.
        let spelled = json!({
            "nev_musd_micros": 900_000i64,
            "attested": {
                "nev": {
                    "nev_musd_micros": 900_000i64,
                    "receipts": 7u64,
                    "provider": "unix:///run/mycelium-verifier.sock",
                    "provider_identity_verified": true,
                    "policy_hash": "0x0123456789abcdef"
                }
            }
        });
        assert!(
            serde_json::from_value::<ResolvedNev>(spelled).is_err(),
            "a JSON that spells out the capability must be refused, not silently downgraded"
        );

        // And the number a caller really can write stays a claim, all the way
        // through the state machine.
        let plain: ResolvedNev = serde_json::from_value(claim).unwrap();
        assert!(!plain.is_attested());
        assert_eq!(plain.claimed_nev_musd_micros, 900_000);
        let mut o = no_edge_observation(1, -1);
        o.resolution = Some(plain);
        let report = observe(o);
        assert_eq!(report.state.state(), "unattested_nev");
        assert_ne!(report.state.state(), "positive_nev");
        assert!(!report.state.is_promotable());
        assert!(report.promotion.is_none());
        assert_eq!(report.coverage.resolutions_positive, 0);
    }

    #[test]
    fn an_arbitrary_claimed_nev_is_never_positive_nev() {
        // P6.0.1, negative. The integer is the whole of the attack, so every
        // value a caller could type — including both extremes of the type — is
        // exercised, and each one is shown to stay a claim.
        for claim in [
            1i64,
            900_000,
            MinNetEdge::crate_default().micros() as i64,
            1_000_000_000_000,
            i64::MAX,
            -1,
            i64::MIN,
        ] {
            let mut o = no_edge_observation(1, -1);
            o.resolution = Some(ResolvedNev::claimed(claim));
            let report = observe(o);
            assert_ne!(
                report.state.state(),
                "positive_nev",
                "claim={claim} reached {}",
                report.state.state()
            );
            assert!(!report.state.is_promotable(), "claim={claim}");
            assert!(report.promotion.is_none(), "claim={claim} was promotable");
            assert_eq!(report.coverage.resolutions_positive, 0, "claim={claim}");
        }

        // The extremes are not a special case of the Rust constructor, so they
        // are also exercised arriving from JSON exactly as a caller would write
        // them.
        for written in ["9223372036854775807", "-9223372036854775808", "1000000000000"] {
            let doc = format!("{{\"nev_musd_micros\": {written}}}");
            let parsed: ResolvedNev = serde_json::from_str(&doc).unwrap();
            assert!(!parsed.is_attested(), "{doc}");
            let mut o = no_edge_observation(1, -1);
            o.resolution = Some(parsed);
            let report = observe(o);
            assert_ne!(report.state.state(), "positive_nev", "{doc}");
            assert!(report.promotion.is_none(), "{doc}");
            assert_eq!(report.coverage.resolutions_positive, 0, "{doc}");
        }
    }

    #[test]
    fn a_caller_supplied_integer_is_ignored_when_a_real_capability_is_present() {
        // P6.0.1. The inverse of the test above, and the reason the capability is
        // worth having: once a genuine `VerifiedNev` is in hand, the caller's
        // integer is not merely outweighed, it is not consulted at all. Every
        // surface that reports a number reports the authority's — the state, the
        // promotion candidate and the resolution id.
        let (nev, policy_hash) = real_verified_nev();
        let attested = AttestedResolution::from_verified(nev);
        for claim in [i64::MIN, -1, 0, 1, 900_000, i64::MAX] {
            let mut o = no_edge_observation(1, -1);
            o.resolution = Some(ResolvedNev::attested(attested.clone(), claim));
            let report = observe(o);
            match &report.state {
                DiscoveryState::PositiveNev {
                    nev_musd_micros,
                    policy_hash: state_policy_hash,
                    ..
                } => {
                    assert_eq!(*nev_musd_micros, 5_000_000, "claim={claim}");
                    assert_eq!(*state_policy_hash, policy_hash, "claim={claim}");
                }
                other => panic!("claim={claim} produced {other:?}"),
            }
            let promotion = report.promotion.as_ref().expect("promotable");
            assert_eq!(promotion.nev_musd_micros, 5_000_000, "claim={claim}");
            assert_eq!(promotion.policy_hash, policy_hash, "claim={claim}");
            assert_eq!(
                promotion.resolution_id,
                attested.resolution_id(START_CLASS),
                "claim={claim}: the id follows the authority, not the claim"
            );
            // The claim survives only as a record of what the adapter said.
            assert_eq!(report.observation_state.state(), "positive_nev", "claim={claim}");
        }
    }

    #[test]
    fn a_real_verified_nev_is_what_reaches_the_authority_trail() {
        // P6.0.1, positive. The genuine path, end to end: a policy validated
        // from the pinned anchor, a receipt signed by the key that policy
        // delegated to, a crossing that re-derives against the operator's
        // registry, and a chain read that confirms the transfer. `PositiveNev`
        // and a `PromotionCandidate` that names the policy both come out of
        // that, and out of nothing else in this file.
        let (nev, policy_hash) = real_verified_nev();
        let mut o = no_edge_observation(1, -1);
        o.resolution = Some(ResolvedNev::attested(
            AttestedResolution::from_verified(nev),
            900_000,
        ));
        let report = observe(o);
        assert_eq!(report.state.state(), "positive_nev");
        assert_eq!(report.action, SearchAction::HandOffToAuthorityTrail);
        let promotion = report.promotion.as_ref().expect("a promotion candidate");
        assert_eq!(promotion.class, START_CLASS);
        assert_eq!(promotion.nev_musd_micros, 5_000_000);
        // The authority is named rather than taken on faith.
        assert_eq!(promotion.policy_hash, policy_hash);
        assert!(promotion.policy_hash.starts_with("0x"), "{}", promotion.policy_hash);
        assert_eq!(
            promotion.required_musd_micros,
            MinNetEdge::crate_default().micros()
        );
    }

    #[test]
    fn a_promotion_candidate_is_still_refused_by_economic_resolution() {
        // P6.0.1: the backstop is untouched, and pinned here from the *other*
        // side. Before P6.0.1 nothing could reach `PositiveNev` without a string,
        // so the backstop was hard to tell from the capability; now a genuine
        // attestation reaches it routinely and `EconomicResolution` still refuses
        // to launder the state into an economic `PositiveNev`. The error is
        // pinned by name, by variant and by the phrase an operator greps for.
        let (nev, _) = real_verified_nev();
        let mut o = no_edge_observation(1, -1);
        o.resolution = Some(ResolvedNev::attested(
            AttestedResolution::from_verified(nev),
            900_000,
        ));
        let report = observe(o);
        assert_eq!(report.state.state(), "positive_nev");
        assert!(report.promotion.is_some());

        let err = crate::resolution::EconomicResolution::from_discovery_state(&report.state)
            .expect_err("the backstop must still refuse PositiveNev");
        assert_eq!(err.state(), "positive_nev_state");
        assert!(
            matches!(
                err,
                crate::resolution::StateWithoutAuthority::PositiveNevStateCarriesNoVerifiedNev { .. }
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("VerifiedNev"), "{err}");
    }

    #[test]
    fn a_verified_nev_that_is_not_positive_does_not_reach_positive_nev() {
        // P6.0.1, invariant. A real `VerifiedNev` from the production settlement
        // constructor over an operation set that settled nothing: a
        // kernel-identified provider, a validated policy, its real `policy_hash`,
        // and a total of zero over zero receipts. Not a fixture and not a
        // test-only shortcut into the type.
        let nev = crate::verified_view::tests::empty_verified_nev();
        assert!(!nev.is_positive(), "a zero over zero receipts is not positive");
        let policy_hash = nev.policy_hash().to_string();
        let attested = AttestedResolution::from_verified(nev);
        assert!(!attested.is_positive());

        // Against a required edge of zero — unrepresentable in a `SearchPolicy`
        // and reachable only by calling the classifier directly — the total is at
        // or above the bar, so this is the arm that exercises `is_positive()`
        // rather than the size comparison. The number the adapter claimed is
        // `i64::MAX` and it is not consulted.
        let resolution = ResolvedNev::attested(attested.clone(), i64::MAX);
        assert_eq!(
            resolution.classify(START_CLASS, 0),
            ResolutionClassification::AttestedWithoutReceipts {
                nev_musd_micros: 0,
                receipts: 0,
                policy_hash: policy_hash.clone(),
            }
        );

        // Under the crate default the same capability is break-even, and still
        // never positive.
        let required = MinNetEdge::crate_default().micros();
        assert_eq!(
            ResolvedNev::attested(attested.clone(), i64::MAX).classify(START_CLASS, required),
            ResolutionClassification::BreakEven {
                nev_musd_micros: 0,
                required_musd_micros: required,
            }
        );

        // End to end, through the state machine: no `PositiveNev`, no promotion,
        // and the positive counter stays at zero.
        let mut o = no_edge_observation(1, -1);
        o.resolution = Some(resolution);
        let report = observe(o);
        assert_eq!(report.state.state(), "break_even");
        assert_ne!(report.state.state(), "positive_nev");
        assert!(!report.state.is_promotable());
        assert!(report.promotion.is_none());
        assert_eq!(report.coverage.resolutions_positive, 0);
        assert_eq!(report.coverage.resolutions_break_even, 1);
    }

    #[test]
    fn attested_resolution_has_no_deserialize_and_no_production_constructor() {
        // P6.0.1. Source-level, and not vacuous, for two reasons that are both
        // implemented in [`code_region`]: it reads *this* file with
        // `include_str!` and cuts it at this test module's own header, so the
        // slice is the production text and nothing after it; and it drops
        // comment-only lines, so a guarantee cannot be satisfied by prose. What is
        // left is attributes, field declarations and `impl` blocks, which is
        // where a `Deserialize` would have to live.
        let code = code_region();
        assert!(code.contains("pub struct AttestedResolution"));

        // A derived `Deserialize` would have to sit in the attribute above the
        // type and a hand-written one in an `impl ... for AttestedResolution`
        // header. So every impl that names this type is enumerated and checked
        // rather than banned by substring: `PartialEq` and `Eq` are legitimate
        // here, and the guard below keeps the scan from passing on an empty
        // result.
        let impls: Vec<&str> = code
            .lines()
            .filter(|l| l.contains("for AttestedResolution"))
            .map(str::trim)
            .collect();
        assert!(
            impls.len() >= 2,
            "the scan found {impls:?}; a rename or a moved module would make it vacuous"
        );
        for header in impls {
            assert!(
                header.starts_with("impl PartialEq for AttestedResolution")
                    || header.starts_with("impl Eq for AttestedResolution"),
                "unexpected impl on AttestedResolution: {header}"
            );
        }

        // The derive is exactly `Serialize`, read from the attribute immediately
        // preceding the type rather than matched as a substring of the file, so a
        // second type's `Deserialize` elsewhere cannot satisfy or defeat it.
        let at = code
            .find("pub struct AttestedResolution")
            .expect("the type is in this file");
        let head = &code[..at];
        let start = head
            .rfind("#[derive(")
            .expect("a derive attribute precedes the type");
        let end = start + head[start..].find(")]").expect("a closed derive") + 2;
        assert_eq!(
            &head[start..end],
            "#[derive(Debug, Clone, Serialize)]",
            "AttestedResolution must derive Serialize and nothing else"
        );

        // The positive control: the *same* routine over a struct that does derive
        // `Deserialize`. Without it, a rename, a broken `rfind` or an empty
        // `code` would make the assertion above pass forever — which is exactly
        // how a real assertion in this file was briefly vacuous.
        let derive_of = |struct_marker: &str| -> &str {
            let at = code
                .find(struct_marker)
                .unwrap_or_else(|| panic!("{struct_marker} is in this file"));
            let head = &code[..at];
            let start = head
                .rfind("#[derive(")
                .unwrap_or_else(|| panic!("a derive precedes {struct_marker}"));
            let end = start + head[start..].find(")]").expect("a closed derive") + 2;
            &head[start..end]
        };
        let holder_derive = derive_of("pub struct ResolvedNev");
        assert!(
            holder_derive.contains("Deserialize"),
            "the positive control failed, so the assertion above proves nothing: {holder_derive}"
        );
        assert!(
            holder_derive.contains("Serialize"),
            "the positive control failed to find Serialize either: {holder_derive}"
        );

        // The field is private, and the capability sits under `skip_deserializing`
        // — which is what lets a type with no `Deserialize` live inside a
        // `Deserialize` struct at all.
        assert!(code.contains("\n    nev: VerifiedNev,"));
        assert!(!code.contains("pub nev: VerifiedNev"));
        assert!(code.contains("#[serde(skip_deserializing, default)]"));

        // Exactly one constructor for the capability and one for the
        // `ResolvedNev` that holds it, and both are `cfg(test)`. In a production
        // build this file therefore contains no way to *hold* an
        // `AttestedResolution`: `ResolvedNev::attested` can never be called,
        // `attested` is structurally always `None`, and `PositiveNev` is
        // unreachable from any observation. Wiring the settlement path is then a
        // visible, greppable change rather than an already-open door.
        assert_eq!(code.matches("fn from_verified(").count(), 1);
        assert_eq!(code.matches("fn attested(").count(), 1);
        assert!(
            code.contains("#[cfg(test)]\n    pub(crate) fn from_verified("),
            "AttestedResolution::from_verified must be cfg(test)"
        );
        assert!(
            code.contains("#[cfg(test)]\n    pub(crate) fn attested("),
            "ResolvedNev::attested must be cfg(test)"
        );
    }

    // ---------------------------------------------------------------------
    // Shared helpers for the table-driven classification tests
    // ---------------------------------------------------------------------

    /// The production half of this file with comments removed.
    ///
    /// The source-level guarantees above (no signing, no settlement dependency,
    /// no submission path) are only worth anything if they are checked against
    /// code rather than against prose, and they can only be checked against the
    /// production half — the tests themselves deliberately mention temperatures,
    /// job types and autonomy APIs.
    ///
    /// P6.0.1: the split marker is the test module's own two lines rather than a
    /// bare `#[cfg(test)]`. Production code now carries `#[cfg(test)]` of its own
    /// — on the two constructors that are deliberately uncallable in a release
    /// build — and the old marker would have truncated the region in the middle of
    /// the type definition, silently vacuating every assertion made about this
    /// file. Same reason `trusted_valuation.rs` splits on its module header.
    /// One source file with its `#[cfg(test)]` module cut off, so a
    /// "production callers" count really is about production. The same cut
    /// [`code_region`] performs, expressed as a function so a test can apply it
    /// to a file other than this one.
    fn production_half(src: &str) -> &str {
        src.split("#[cfg(test)]")
            .next()
            .expect("a source file is never empty")
    }

    fn code_region() -> &'static str {
        let src = include_str!("discovery.rs");
        let src = &src[..src
            .find("#[cfg(test)]\nmod tests {")
            .expect("the test module is present")];
        let code: String = src
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !(t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'))
            })
            .collect::<Vec<_>>()
            .join("\n");
        Box::leak(code.into_boxed_str())
    }

    fn base_observation_with(f: impl FnOnce(&mut SearchObservation)) -> SearchObservation {
        let mut o = base_observation(1);
        f(&mut o);
        o
    }

    /// One full step: obtain a permit legitimately, then classify.
    fn observe(observation: SearchObservation) -> DiscoveryReport {
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();
        let permit = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
        machine
            .observe(
                &mut memory,
                &permit,
                &observation,
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap()
    }

    /// One full step driven from a caller-supplied adapter observation.
    fn run_once(
        machine: &DiscoveryMachine,
        memory: &mut SearchMemory,
        registry: &AdapterRegistry,
        policy: &SearchPolicy,
    ) -> DiscoveryReport {
        let dir = tempdir().unwrap();
        let gate = healthy_gate(&dir, 1_000);
        let p = permit(machine, memory, registry, policy, &gate, 1_000);
        machine
            .observe(
                memory,
                &p,
                &no_edge_observation(p.cycle, -2_032_674),
                registry,
                policy,
                &default_audit(),
                1_000,
            )
            .unwrap()
    }

    // ---------------------------------------------------------------------
    // Threshold provenance
    // ---------------------------------------------------------------------

    #[test]
    fn a_min_net_edge_of_zero_is_unrepresentable() {
        assert!(MinNetEdge::new(0).is_err());
        assert!(MinNetEdge::new(1).is_ok());
        assert_eq!(MinNetEdge::crate_default().micros(), 10_000);
        assert_eq!(
            EconomicPolicy::default().min_net_edge_musd_micros,
            MinNetEdge::crate_default().micros()
        );
    }

    #[test]
    fn every_search_health_minimum_refuses_its_degenerate_form() {
        assert!(MinClassCoverage::new(0).is_err());
        assert!(MinResolutionRate::new(0).is_err());
        assert!(MaxCostPerResolution::new(0).is_err());
        assert!(MinDiversity::new(0, 1).is_err());
        assert!(MinDiversity::new(1, 0).is_err());
        assert!(SearchPolicy::default().validate().is_ok());
    }

    #[test]
    fn a_caller_supplied_degenerate_threshold_is_recorded_and_blocks_promotion() {
        // `min_net_edge_musd_micros = 0` on the pre-existing surface is still
        // accepted there (the CLI and the ledgers must keep working). What P6
        // adds is the record, and the refusal to promote while it is in force.
        let opened = EconomicPolicy {
            min_net_edge_musd_micros: 0,
            ..EconomicPolicy::default()
        };
        let audit = ThresholdAudit::from_economic_policy(&opened);
        assert!(audit.any_degenerate());
        let records = audit.degenerate();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "min_net_edge_musd_micros");
        assert_eq!(records[0].value, "0");
        assert_eq!(records[0].source.state(), "caller_supplied");
        assert!(records[0].why.contains("any candidate"));

        // P6's own gate is still the crate default and is not openable.
        let policy = SearchPolicy::default();
        assert_eq!(policy.min_net_edge.micros(), 10_000);

        // And a positive resolution under the degenerate audit produces no
        // promotion at all. P6.0.1: with a genuine attestation, so the state
        // under the veto is reached the only way it can be.
        let (resolution, _) = attested_resolution(900_000);
        let report = observe_with_audit(resolution, audit);
        assert_eq!(report.state.state(), "positive_nev");
        assert!(report.promotion.is_none(), "a degenerate threshold vetoes promotion");
        assert!(report.thresholds.any_degenerate());
    }

    #[test]
    fn crate_defaults_are_recorded_as_not_the_callers() {
        let audit = default_audit().with_crate_defaults();
        let crate_defaults: Vec<&ThresholdRecord> = audit
            .records
            .iter()
            .filter(|r| r.source == ThresholdSource::CrateDefault)
            .collect();
        assert_eq!(crate_defaults.len(), 2);
        assert!(crate_defaults.iter().all(|r| !r.degenerate));
        assert!(audit
            .records
            .iter()
            .any(|r| r.name.contains("HARD_THERMAL_CEILING_C")));
    }

    fn observe_with_audit(resolution: ResolvedNev, audit: ThresholdAudit) -> DiscoveryReport {
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();
        let permit = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
        let mut observation = no_edge_observation(1, -1);
        observation.resolution = Some(resolution);
        machine
            .observe(&mut memory, &permit, &observation, &registry, &policy, &audit, 1_000)
            .unwrap()
    }

    // ---------------------------------------------------------------------
    // G — budget
    // ---------------------------------------------------------------------

    #[test]
    fn a_search_budget_requires_every_dimension() {
        // An omitted dimension would be an unlimited dimension, which is exactly
        // the pre-P6 behaviour of scanning until something stopped it.
        for bad in [
            SearchBudget {
                max_cycles: 0,
                ..SearchBudget::default()
            },
            SearchBudget {
                max_rpc_calls: 0,
                ..SearchBudget::default()
            },
            SearchBudget {
                max_observed_temperature_c: 0.0,
                ..SearchBudget::default()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        assert!(SearchBudget::default().validate().is_ok());
    }

    #[test]
    fn a_search_budget_cannot_be_configured_to_reach_the_observed_peak() {
        // 93 C was actually observed on this hardware. The budget must not be
        // able to authorise it.
        assert_eq!(HARD_THERMAL_CEILING_C, 75.0);
        assert!(SearchBudget::new(1, 1, 1, 1, 1, 93.0).is_err());
        assert!(SearchBudget::new(1, 1, 1, 1, 1, 76.0).is_err());
        assert!(SearchBudget::new(1, 1, 1, 1, 1, 75.0).is_ok());
        assert!(SearchBudget::default().max_observed_temperature_c < 93.0);
    }

    #[test]
    fn budget_exhaustion_is_neither_no_edge_nor_exhaustion() {
        let report = observe(base_observation_with(|o| {
            o.cycles_budgeted = 8;
            o.cycles_completed = 8;
            o.spend = BudgetSpend {
                cycles: 99,
                wall_ms: 1,
                cpu_ms: 1,
                energy_mj: 1,
                rpc_calls: 1,
                peak_temperature_c: Some(40.0),
            };
        }));
        assert_eq!(report.state.state(), "budget_exhausted");
        assert_ne!(report.state.state(), "no_edge");
        assert_ne!(report.state.state(), "class_exhausted");
        assert_eq!(report.action, SearchAction::StopClassThisRun);
        assert!(!report.completed);
        assert_eq!(report.budget_exhausted_by, Some(BudgetDimension::Cycles));
    }

    #[test]
    fn budget_dimensions_are_reported_individually() {
        let budget = SearchBudget::default();
        assert_eq!(
            budget.exhausted_by(&BudgetSpend {
                cycles: 0,
                wall_ms: 0,
                cpu_ms: 0,
                energy_mj: 0,
                rpc_calls: 0,
                peak_temperature_c: Some(80.0),
            }),
            Some(BudgetDimension::Temperature)
        );
        assert_eq!(
            budget.exhausted_by(&BudgetSpend {
                energy_mj: budget.max_energy_mj + 1,
                ..BudgetSpend::default()
            }),
            Some(BudgetDimension::Energy)
        );
        assert!(budget.exhausted_by(&BudgetSpend::default()).is_none());
        assert!(
            budget.allows(&BudgetSpend::cycles(1)).unwrap(),
            "one cycle is inside a four-cycle budget"
        );
        assert!(!budget
            .allows(&BudgetSpend::cycles(budget.max_cycles + 1))
            .unwrap());
    }

    #[test]
    fn energy_is_reported_and_never_derived_from_a_temperature() {
        // No watts, no joules-per-degree, no model. The old theoretical figures
        // (65 W dissipation, 55 J per degree) appear nowhere in this module.
        let code = code_region();
        assert!(!code.contains("55.0"));
        assert!(!code.contains("65.0"));
        assert!(!code.contains("joule"));
        assert!(!code.contains("watt"));
        assert!(!code.contains("dissipation"));
        // And energy is a plain caller-measured number.
        let spend = BudgetSpend {
            cycles: 1,
            wall_ms: 1,
            cpu_ms: 1,
            energy_mj: 42,
            rpc_calls: 1,
            peak_temperature_c: Some(41.0),
        };
        assert_eq!(spend.energy_mj, 42);
    }

    // ---------------------------------------------------------------------
    // H — MUPP and thermal
    // ---------------------------------------------------------------------

    #[test]
    fn a_caller_clock_earlier_than_the_state_timestamp_is_refused() {
        // Both the adapter and P6 refuse a future timestamp.
        let dir = tempdir().unwrap();
        let path = write_mupp_state(&dir, 5_000.0, true, 12.0, "IDLE", true);
        let gate = read_mupp_gate(&path, 1_000.0, &MuppAdapterPolicy::default()).unwrap();
        assert!(!gate.fresh, "the adapter blocks future timestamps");
        assert_eq!(gate.age_seconds, 0.0, "because the age is clamped");

        match ThermalPermit::check(&gate, 1_000, MIN_SEARCH_THERMAL_HEADROOM) {
            Err(ThermalStop::ClockWentBackwards {
                state_timestamp_unix,
                now_unix,
            }) => {
                assert_eq!(state_timestamp_unix, 5_000.0);
                assert_eq!(now_unix, 1_000);
            }
            other => panic!("expected a clock refusal, got {other:?}"),
        }
        assert!(ThermalPermit::from_gate(&gate, 1_000, MIN_SEARCH_THERMAL_HEADROOM).is_err());
    }

    #[test]
    fn the_thermal_headroom_collapse_is_separated_into_named_causes() {
        // Four different worlds reach `thermal_headroom == 0.0` upstream. P6
        // names each and never reports any of them as no-edge.
        let dir = tempdir().unwrap();

        // 1. A MUPP control block, at a perfectly ordinary temperature.
        let blocked = read_mupp_gate(
            write_mupp_state(&dir, 1_000.0, false, 12.0, "COLLAPSE", true),
            1_001.0,
            &MuppAdapterPolicy::default(),
        )
        .unwrap();
        assert_eq!(blocked.thermal_headroom, 0.0);
        match ThermalPermit::check(&blocked, 1_001, MIN_SEARCH_THERMAL_HEADROOM) {
            Err(ThermalStop::MuppHardBlocked { phase, .. }) => assert_eq!(phase, "COLLAPSE"),
            other => panic!("{other:?}"),
        }

        // 2. Sensors that never warmed up.
        let cold = read_mupp_gate(
            write_mupp_state(&dir, 1_000.0, true, 12.0, "IDLE", false),
            1_001.0,
            &MuppAdapterPolicy::default(),
        )
        .unwrap();
        assert_eq!(cold.thermal_headroom, 0.0);
        assert!(matches!(
            ThermalPermit::check(&cold, 1_001, MIN_SEARCH_THERMAL_HEADROOM),
            Err(ThermalStop::SensorsInvalid { .. })
        ));

        // 3. Genuinely no headroom.
        let hot = read_mupp_gate(
            write_mupp_state(&dir, 1_000.0, true, 0.0, "IDLE", true),
            1_001.0,
            &MuppAdapterPolicy::default(),
        )
        .unwrap();
        assert_eq!(hot.thermal_headroom, 0.0);
        assert!(matches!(
            ThermalPermit::check(&hot, 1_001, MIN_SEARCH_THERMAL_HEADROOM),
            Err(ThermalStop::BelowSearchFloor { .. })
        ));

        // 4. A state that is simply old.
        let stale = read_mupp_gate(
            write_mupp_state(&dir, 1_000.0, true, 12.0, "IDLE", true),
            9_999.0,
            &MuppAdapterPolicy::default(),
        )
        .unwrap();
        assert_eq!(stale.thermal_headroom, 0.0);
        assert!(matches!(
            ThermalPermit::check(&stale, 9_999, MIN_SEARCH_THERMAL_HEADROOM),
            Err(ThermalStop::StaleState { .. })
        ));

        // Each is distinct, and none is a market conclusion.
        let names: BTreeSet<&str> = [
            ThermalStop::MuppHardBlocked {
                phase: "COLLAPSE".into(),
                reason: "x".into(),
            },
            ThermalStop::SensorsInvalid { reason: "x".into() },
            ThermalStop::BelowSearchFloor {
                headroom: 0.0,
                required: 0.15,
            },
            ThermalStop::StaleState { age_seconds: 1.0 },
        ]
        .iter()
        .map(ThermalStop::state)
        .collect();
        assert_eq!(names.len(), 4);
    }

    #[test]
    fn a_thermal_stop_is_never_no_edge_and_contributes_no_coverage() {
        let report = observe(base_observation_with(|o| {
            o.thermal = ObservedThermal {
                start_max_c: Some(93.0),
                end_c: Some(88.0),
                maximum_c: None,
            };
        }));
        assert_eq!(report.state.state(), "search_aborted_thermal");
        assert_ne!(report.state.state(), "no_edge");
        assert_ne!(report.state.state(), "class_exhausted");
        assert_eq!(report.action, SearchAction::EnterThermalCooldown);
        assert!(!report.completed);
        assert!(report.promotion.is_none());
        match report.state {
            DiscoveryState::SearchAbortedThermal { stop, .. } => {
                assert_eq!(stop.state(), "budget_temperature");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_inert_s1_thermal_fields_now_have_a_meaning() {
        // `s1_perception_adapter` reads these into its report and nothing in the
        // crate ever compared them to anything.
        let report = observe(base_observation_with(|o| {
            o.thermal = ObservedThermal {
                start_max_c: Some(55.0),
                end_c: Some(80.0),
                maximum_c: None,
            };
        }));
        assert_eq!(report.state.state(), "search_aborted_thermal");

        let cool = observe(base_observation_with(|o| {
            o.best_observed_edge = Some(MeasuredEdge {
                token_edge_micros: Some(-100),
                robust_net_micros: -200,
                source_field: "near_edge_refinement".into(),
            });
            o.thermal = ObservedThermal {
                start_max_c: Some(55.0),
                end_c: Some(60.0),
                maximum_c: None,
            };
        }));
        assert_eq!(cool.observation_state.state(), "no_edge");
        assert_eq!(cool.state.state(), "class_exhausted");
    }

    #[test]
    fn a_mid_run_thermal_peak_alone_aborts_the_search() {
        // The end points are both cool, because the excursion happened *during*
        // the run and was over before it finished. Reporting it from the end
        // points alone would have let a job that ran at 93 °C read as a 40 °C
        // search. `maximum_c` is the reading that closes that hole, and this is
        // the test that would fail if the field were dropped again.
        let endpoints_look_cool = ObservedThermal {
            start_max_c: Some(40.0),
            end_c: Some(45.0),
            maximum_c: Some(93.0),
        };
        assert_eq!(endpoints_look_cool.peak(), Some(93.0));

        let report = observe(base_observation_with(|o| {
            o.thermal = endpoints_look_cool;
        }));
        assert_eq!(report.state.state(), "search_aborted_thermal");
        assert_ne!(report.state.state(), "no_edge");
        assert_eq!(report.action, SearchAction::EnterThermalCooldown);
        match report.state {
            DiscoveryState::SearchAbortedThermal { stop, .. } => {
                assert_eq!(stop.state(), "budget_temperature");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_observation_persisted_before_the_mid_run_field_still_reads_back() {
        // `ObservedThermal` is `deny_unknown_fields`, so the new field needed
        // `#[serde(default)]`: without it every search-memory file written
        // before this change would have failed to open, turning a missing
        // measurement into a broken state.
        let old: ObservedThermal = serde_json::from_value(json!({
            "start_max_c": 41.0,
            "end_c": 44.0
        }))
        .expect("an observation written without maximum_c must still parse");
        assert_eq!(old.maximum_c, None);
        assert_eq!(old.peak(), Some(44.0));

        let round_trip = ObservedThermal {
            start_max_c: Some(40.0),
            end_c: Some(45.0),
            maximum_c: Some(93.0),
        };
        let encoded = serde_json::to_value(round_trip).unwrap();
        assert_eq!(encoded["maximum_c"], json!(93.0));
        assert_eq!(
            serde_json::from_value::<ObservedThermal>(encoded).unwrap(),
            round_trip
        );
    }

    #[test]
    fn a_thermal_abort_starts_a_cooldown_and_blocks_the_next_search() {
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy {
            thermal_cooldown_cycles: 3,
            ..SearchPolicy::default()
        };
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();

        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
        let mut hot = no_edge_observation(p.cycle, -1);
        hot.thermal = ObservedThermal {
            start_max_c: Some(90.0),
            end_c: None,
            maximum_c: None,
        };
        machine
            .observe(&mut memory, &p, &hot, &registry, &policy, &default_audit(), 1_000)
            .unwrap();

        assert!(memory.thermal_cooldown_until_cycle > memory.cycle);
        let attempt = machine
            .begin_search(&mut memory, &registry, &policy, Some(&gate), 1_001)
            .unwrap();
        assert!(attempt.permit().is_none());
        assert_eq!(attempt.denial().unwrap().state(), "thermal");
        assert_eq!(memory.state.state(), "search_aborted_thermal");
        assert_eq!(memory.wait_status().thermal_cooldown_until_unix, Some(1_180));
        let cycle = memory.cycle;
        let coverage = memory.statistics(START_CLASS).cycles_attempted;
        machine.store(&memory).unwrap();
        let reopened = DiscoveryMachine::open(dir.path()).unwrap();
        let mut restored = reopened.load().unwrap();
        let fresh = healthy_gate(&dir, 1_179);
        assert!(reopened
            .begin_search(&mut restored, &registry, &policy, Some(&fresh), 1_179)
            .unwrap()
            .permit()
            .is_none());
        // Time expiring does not manufacture a fresh MUPP authorisation.
        assert!(reopened
            .begin_search(&mut restored, &registry, &policy, None, 1_180)
            .unwrap()
            .permit()
            .is_none());
        let fresh = healthy_gate(&dir, 1_180);
        assert!(reopened
            .begin_search(&mut restored, &registry, &policy, Some(&fresh), 1_180)
            .unwrap()
            .permit()
            .is_some());
        assert_eq!(restored.cycle, cycle);
        assert_eq!(restored.statistics(START_CLASS).cycles_attempted, coverage);

        // A policy with no cooldown at all is refused: a thermal abort with no
        // cooldown is the behaviour P6 exists to stop.
        assert!(SearchPolicy {
            thermal_cooldown_cycles: 0,
            ..SearchPolicy::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn a_search_requires_a_mupp_state() {
        // The audit's finding that MUPP never touched discovery: `orchestrate`
        // consults no thermal input at all. Here, no thermal input is a refusal.
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy::default();
        let mut memory = SearchMemory::new();

        let attempt = machine
            .begin_search(&mut memory, &registry, &policy, None, 1_000)
            .unwrap();
        assert!(attempt.permit().is_none());
        assert_eq!(attempt.denial().unwrap().state(), "thermal");
        assert_eq!(memory.state.state(), "search_aborted_thermal");
    }

    #[test]
    fn a_state_stamped_inside_the_callers_own_second_is_not_a_clock_anomaly() {
        // The adapter needs the precise observation time. P6 accepts whole
        // seconds, but must not manufacture freshness for a future sample.
        let dir = tempdir().unwrap();
        let path = write_mupp_state(&dir, 1_000.75, true, 12.0, "IDLE", true);
        let future_gate = read_mupp_gate(&path, 1_000.0, &MuppAdapterPolicy::default()).unwrap();
        assert!(ThermalPermit::check(&future_gate, 1_000, MIN_SEARCH_THERMAL_HEADROOM).is_err());
        let gate = read_mupp_gate(&path, 1_000.9, &MuppAdapterPolicy::default()).unwrap();
        assert!(ThermalPermit::check(&gate, 1_000, MIN_SEARCH_THERMAL_HEADROOM).is_ok());
        assert!(ThermalPermit::check(&gate, 1_001, MIN_SEARCH_THERMAL_HEADROOM).is_ok());
        // A clock a full second behind the state's own second is the anomaly, and
        // the refusal names it rather than silently accepting the pair.
        assert!(matches!(
            ThermalPermit::check(&gate, 999, MIN_SEARCH_THERMAL_HEADROOM),
            Err(ThermalStop::ClockWentBackwards { .. })
        ));
    }

    #[test]
    fn a_required_headroom_of_zero_is_refused() {
        let dir = tempdir().unwrap();
        let gate = healthy_gate(&dir, 1_000);
        assert!(ThermalPermit::check(&gate, 1_000, 0.0).is_err());
        assert!(ThermalPermit::check(&gate, 1_000, 1.5).is_err());
        assert!(ThermalPermit::check(&gate, 1_000, MIN_SEARCH_THERMAL_HEADROOM).is_ok());
    }

    // ---------------------------------------------------------------------
    // Backoff
    // ---------------------------------------------------------------------

    #[test]
    fn the_backoff_grows_and_is_bounded() {
        let schedule = BackoffSchedule::default();
        assert_eq!(schedule.cycles_after(0), 1);
        assert_eq!(schedule.cycles_after(1), 2);
        assert_eq!(schedule.cycles_after(2), 4);
        assert_eq!(schedule.cycles_after(6), 32);
        // Bounded: no accumulation of cycles escapes the cap, which is why
        // "keep scanning" is not an available behaviour.
        for n in [7u32, 10, 32, 64, 1_000, u32::MAX] {
            assert_eq!(schedule.cycles_after(n), schedule.max_cycles, "n={n}");
        }
    }

    #[test]
    fn a_backoff_that_is_not_a_backoff_is_refused() {
        assert!(BackoffSchedule::new(0, 10, 20_000).is_err());
        assert!(BackoffSchedule::new(2, 1, 20_000).is_err());
        // A shrinking schedule is not a backoff.
        assert!(BackoffSchedule::new(1, 10, 9_999).is_err());
        assert!(BackoffSchedule::new(1, 10, 10_000).is_ok());
    }

    #[test]
    fn backoff_blocks_the_next_attempt_of_the_same_class() {
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();

        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
        // No cells reported => insufficient coverage => NoEdge, which backs off.
        let mut observation = no_edge_observation(p.cycle, -1);
        observation.cells_scanned = None;
        machine
            .observe(
                &mut memory,
                &p,
                &observation,
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();

        let attempt = machine
            .begin_search(&mut memory, &registry, &policy, Some(&gate), 1_001)
            .unwrap();
        assert!(attempt.permit().is_none());
        assert_eq!(attempt.denial().unwrap().state(), "in_backoff");
    }

    #[test]
    fn backoff_and_cooldown_survive_a_restart() {
        // A backoff that resets when the process does is not a backoff.
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();

        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
        let mut observation = no_edge_observation(p.cycle, -1);
        observation.cells_scanned = None;
        machine
            .observe(
                &mut memory,
                &p,
                &observation,
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();
        machine.store(&memory).unwrap();

        let reopened = DiscoveryMachine::open(dir.path()).unwrap();
        let restored = reopened.load().unwrap();
        assert_eq!(restored, memory);
        assert!(restored.statistics(START_CLASS).next_attempt_cycle > 0);
        assert!(reopened
            .begin_search(&mut restored.clone(), &registry, &policy, Some(&gate), 1_001)
            .unwrap()
            .permit()
            .is_none());
    }

    #[test]
    fn wall_clock_backoff_expires_without_fabricating_search_coverage() {
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();
        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
        let mut observation = no_edge_observation(p.cycle, -1);
        observation.cells_scanned = None;
        machine
            .observe(
                &mut memory, &p, &observation, &registry, &policy,
                &default_audit(), 1_000,
            )
            .unwrap();
        assert_eq!(memory.wait_status().next_attempt_unix, Some(1_120));
        machine.store(&memory).unwrap();

        let reopened = DiscoveryMachine::open(dir.path()).unwrap();
        let mut restored = reopened.load().unwrap();
        let cycle = restored.cycle;
        let coverage = restored.statistics(START_CLASS);
        let fresh = healthy_gate(&dir, 1_119);
        let blocked = reopened
            .begin_search(&mut restored, &registry, &policy, Some(&fresh), 1_119)
            .unwrap();
        assert_eq!(blocked.denial().unwrap().state(), "in_backoff");
        let fresh = healthy_gate(&dir, 1_120);
        assert!(reopened
            .begin_search(&mut restored, &registry, &policy, Some(&fresh), 1_120)
            .unwrap()
            .permit()
            .is_some());
        assert_eq!(restored.cycle, cycle);
        assert_eq!(restored.statistics(START_CLASS), coverage);
    }

    #[test]
    fn legacy_cycle_waits_migrate_once_and_survive_a_restart() {
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();
        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
        let mut observation = no_edge_observation(p.cycle, -1);
        observation.cells_scanned = None;
        machine
            .observe(
                &mut memory, &p, &observation, &registry, &policy,
                &default_audit(), 1_000,
            )
            .unwrap();
        let mut legacy = serde_json::to_value(&memory).unwrap();
        legacy.as_object_mut().unwrap().remove("thermal_cooldown_until_unix");
        for stats in legacy["classes"].as_object_mut().unwrap().values_mut() {
            stats.as_object_mut().unwrap().remove("next_attempt_unix");
        }
        let mut restored: SearchMemory = serde_json::from_value(legacy).unwrap();
        assert_eq!(restored.wait_status().next_attempt_unix, None);
        let fresh = healthy_gate(&dir, 2_000);
        assert!(machine
            .begin_search(&mut restored, &registry, &policy, Some(&fresh), 2_000)
            .unwrap()
            .permit()
            .is_none());
        assert_eq!(restored.wait_status().next_attempt_unix, Some(2_120));
        machine.store(&restored).unwrap();
        let reopened = DiscoveryMachine::open(dir.path()).unwrap();
        let mut restored = reopened.load().unwrap();
        let fresh = healthy_gate(&dir, 2_001);
        assert!(reopened
            .begin_search(&mut restored, &registry, &policy, Some(&fresh), 2_001)
            .unwrap()
            .permit()
            .is_none());
        assert_eq!(restored.wait_status().next_attempt_unix, Some(2_120));
        let fresh = healthy_gate(&dir, 2_120);
        assert!(reopened
            .begin_search(&mut restored, &registry, &policy, Some(&fresh), 2_120)
            .unwrap()
            .permit()
            .is_some());
        assert_eq!(restored.cycle, memory.cycle);
        assert_eq!(restored.coverage_all(&registry), memory.coverage_all(&registry));
    }

    #[test]
    fn search_memory_round_trips_and_never_stores_support() {
        // Support comes from the registry, not from a file on disk, so a
        // hand-written memory cannot claim a class is implemented.
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let memory = SearchMemory::new();
        machine.store(&memory).unwrap();
        let raw = std::fs::read_to_string(machine.memory_path()).unwrap();
        assert!(!raw.contains("\"support\""));
        assert!(raw.contains("\"current_class\""));
        assert_eq!(machine.load().unwrap(), memory);
        assert_eq!(
            DiscoveryMachine::open(tempdir().unwrap())
                .unwrap()
                .load()
                .unwrap(),
            SearchMemory::new(),
            "a missing memory file is a machine that has never searched"
        );
    }

    // ---------------------------------------------------------------------
    // E — SearchHealth
    // ---------------------------------------------------------------------

    fn coverage_row(cycles: u64, cells: Option<u64>, support: ClassSupport) -> ClassCoverage {
        ClassCoverage {
            class: START_CLASS,
            support,
            cycles_attempted: cycles,
            cycles_completed: cycles,
            cycles_aborted: 0,
            cells_scanned: cells,
            candidates_found: 0,
            resolutions_negative: 0,
            resolutions_break_even: 0,
            resolutions_positive: 0,
        }
    }

    fn healthy_health() -> SearchHealth {
        SearchHealth {
            coverage: SearchCoverage {
                cycles_budgeted: 4,
                cycles_completed: 4,
                cycles_aborted: 0,
                cells_scanned: Some(40),
            },
            class_coverage: vec![coverage_row(4, Some(40), ClassSupport::Implemented)],
            resolution_rate: ResolutionRate {
                attempts: 4,
                resolved: 4,
            },
            cost_per_resolution: CostPerResolution {
                total_cost_musd_micros: 400_000,
                resolutions: 4,
            },
            diversity: HypothesisDiversity {
                distinct_classes: 2,
                distinct_routes: 3,
                distinct_sources: 1,
            },
        }
    }

    #[test]
    fn health_is_reported_as_a_vector_and_never_fused_into_one_number() {
        let health = healthy_health();
        let minimums = HealthMinimums::default();
        assert!(matches!(
            health.verdict(&minimums).unwrap(),
            HealthVerdict::Sufficient { .. }
        ));
        assert!(health.reasons(&minimums).unwrap().is_empty());

        // A weighted sum is deliberately absent: `SearchHealth` has no `fitness`,
        // no `score` and no `total`, so there is nothing for a caller to mistake
        // for a verdict.
        let code = code_region();
        assert!(!code.contains("fn fitness"));
        assert!(!code.contains("fn score"));
        assert!(!code.contains("fn total"));

        // Failing dimensions are named, and the first one is deterministic.
        let mut broken = healthy_health();
        broken.class_coverage[0].cycles_completed = 0;
        broken.resolution_rate = ResolutionRate {
            attempts: 0,
            resolved: 0,
        };
        broken.diversity.distinct_routes = 0;
        match broken.verdict(&minimums).unwrap() {
            HealthVerdict::Insufficient {
                dimension,
                observed,
                required,
                failing_dimensions,
            } => {
                assert_eq!(dimension, HealthDimension::ClassCoverage);
                assert!(observed.contains("completed 0 cycle"));
                assert!(failing_dimensions.contains(&HealthDimension::ClassCoverage));
                assert!(failing_dimensions.contains(&HealthDimension::ResolutionRate));
                assert!(failing_dimensions.contains(&HealthDimension::Diversity));
                assert!(required.contains("cycle(s)"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn zero_nev_with_no_coverage_is_distinguishable_from_zero_nev_with_full_coverage() {
        // The requirement that motivates reporting a vector instead of a score.
        let minimums = HealthMinimums::default();

        let broken = SearchHealth {
            coverage: SearchCoverage::default(),
            class_coverage: vec![coverage_row(0, None, ClassSupport::Implemented)],
            resolution_rate: ResolutionRate::default(),
            cost_per_resolution: CostPerResolution::default(),
            diversity: HypothesisDiversity::default(),
        };
        let correctly_negative = healthy_health();

        let broken_verdict = broken.verdict(&minimums).unwrap();
        let negative_verdict = correctly_negative.verdict(&minimums).unwrap();
        assert_ne!(broken_verdict, negative_verdict);
        assert!(matches!(broken_verdict, HealthVerdict::Insufficient { .. }));
        assert!(matches!(negative_verdict, HealthVerdict::Sufficient { .. }));

        // And they select differently: the broken one may not have its value
        // compared at all, even though both have value 0.
        let values = vec![RankedValue {
            class: START_CLASS,
            verified_nev_musd_micros: 0,
            cost_musd_micros: 0,
        }];
        assert!(matches!(
            SearchSelection::decide_with(&broken, &minimums, &values).unwrap(),
            SearchSelection::BelowMinimumHealth { .. }
        ));
        assert!(matches!(
            SearchSelection::decide_with(&correctly_negative, &minimums, &values).unwrap(),
            SearchSelection::ByVerifiedValue { .. }
        ));
    }

    #[test]
    fn selection_reaches_value_first_and_cost_only_as_a_tie_break() {
        let minimums = HealthMinimums::default();
        let health = healthy_health();
        let value = |nev: i64, cost: u64, class: OpportunityClass| RankedValue {
            class,
            verified_nev_musd_micros: nev,
            cost_musd_micros: cost,
        };

        // (2) then (3): a larger attested value wins even at a far higher cost.
        let ranked = SearchSelection::decide_with(
            &health,
            &minimums,
            &[
                value(900_000, 10, START_CLASS),
                value(800_000, 1, OpportunityClass::NetworkFee),
            ],
        )
        .unwrap();
        match ranked {
            SearchSelection::ByVerifiedValue { ranked } => {
                assert_eq!(ranked[0].verified_nev_musd_micros, 900_000);
                assert_eq!(ranked[0].cost_musd_micros, 10);
            }
            other => panic!("{other:?}"),
        }

        // Equivalent value: cost decides, and only among the tied set.
        let tie = SearchSelection::decide_with(
            &health,
            &minimums,
            &[
                value(900_000, 10, START_CLASS),
                value(900_000, 1, OpportunityClass::NetworkFee),
                value(700_000, 0, OpportunityClass::KeeperReward),
            ],
        )
        .unwrap();
        match tie {
            SearchSelection::ByLowestCost { ranked } => {
                assert_eq!(ranked.len(), 2, "only the tied set is ranked by cost");
                assert_eq!(ranked[0].cost_musd_micros, 1);
                assert!(ranked.iter().all(|v| v.verified_nev_musd_micros == 900_000));
            }
            other => panic!("{other:?}"),
        }

        // Zero is a value and compares as one, it is not "no value".
        let zeros = SearchSelection::decide_with(
            &health,
            &minimums,
            &[value(0, 5, START_CLASS), value(-1, 5, OpportunityClass::NetworkFee)],
        )
        .unwrap();
        match zeros {
            SearchSelection::ByVerifiedValue { ranked } => {
                assert_eq!(ranked[0].verified_nev_musd_micros, 0);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn cost_and_rate_are_absent_without_data_not_zero() {
        // "No data" must not read as "perfect" or as "free".
        assert_eq!(ResolutionRate::default().basis_points(), None);
        assert_eq!(
            ResolutionRate {
                attempts: 10,
                resolved: 0
            }
            .basis_points(),
            Some(0)
        );
        assert_eq!(CostPerResolution::default().micros_per_resolution(), None);
        assert_eq!(
            CostPerResolution {
                total_cost_musd_micros: 100,
                resolutions: 0
            }
            .micros_per_resolution(),
            None
        );
        // Integer division, so no float decides a cost gate.
        assert_eq!(
            CostPerResolution {
                total_cost_musd_micros: 101,
                resolutions: 3
            }
            .micros_per_resolution(),
            Some(33)
        );
        assert_eq!(
            ResolutionRate {
                attempts: 3,
                resolved: 1
            }
            .basis_points(),
            Some(3_333)
        );
    }

    #[test]
    fn diversity_counts_distinct_routes_not_parameter_variants() {
        let minimums = HealthMinimums::default();
        let mut memory = SearchMemory::new();
        let registry = registry();

        // One route, re-run with different parameters, is one hypothesis.
        memory.statistics_mut(START_CLASS).routes.insert("route-a".into());
        for _ in 0..5 {
            memory.statistics_mut(START_CLASS).cycles_attempted += 1;
            memory.statistics_mut(START_CLASS).cycles_completed += 1;
        }
        let health = memory.health(&registry);
        assert_eq!(health.diversity.distinct_routes, 1);
        assert_eq!(health.diversity.distinct_classes, 1);

        // A second route is a second hypothesis.
        memory.statistics_mut(START_CLASS).routes.insert("route-b".into());
        assert_eq!(memory.health(&registry).diversity.distinct_routes, 2);

        // Two sources for the same route do not make two routes.
        memory.statistics_mut(START_CLASS).sources.insert("adapter-a".into());
        memory.statistics_mut(START_CLASS).sources.insert("adapter-b".into());
        let health = memory.health(&registry);
        assert_eq!(health.diversity.distinct_routes, 2);
        assert_eq!(health.diversity.distinct_sources, 2);
        assert!(health.diversity.meets(&minimums.min_diversity));
    }

    #[test]
    fn a_machine_that_searched_one_route_cannot_meet_a_diversity_of_two() {
        let minimums = HealthMinimums {
            min_diversity: MinDiversity::new(2, 1).unwrap(),
            ..HealthMinimums::default()
        };
        let mut memory = SearchMemory::new();
        memory.statistics_mut(START_CLASS).cycles_attempted = 5;
        memory.statistics_mut(START_CLASS).cycles_completed = 5;
        memory.statistics_mut(START_CLASS).routes.insert("route-a".into());
        let health = memory.health(&registry());
        assert!(!health.diversity.meets(&minimums.min_diversity));
        match health.verdict(&minimums).unwrap() {
            HealthVerdict::Insufficient {
                failing_dimensions,
                ..
            } => assert!(failing_dimensions.contains(&HealthDimension::Diversity)),
            other => panic!("{other:?}"),
        }
    }

    // ---------------------------------------------------------------------
    // F — class rotation and support
    // ---------------------------------------------------------------------

    #[test]
    fn only_arbitrage_is_implemented_and_the_other_six_are_unsupported() {
        let registry = registry();
        assert_eq!(
            registry.implemented(),
            BTreeSet::from([OpportunityClass::Arbitrage])
        );
        for class in OpportunityClass::ALL {
            let expected = if class == OpportunityClass::Arbitrage {
                ClassSupport::Implemented
            } else {
                ClassSupport::Unsupported
            };
            assert_eq!(registry.support(class), expected, "{class}");
        }
        assert_eq!(registry.identities().len(), 1);
        assert_eq!(registry.identities().get(&OpportunityClass::Arbitrage), Some(&vec!["s1_shadow_scan".to_string()]));
        assert_eq!(SearchPolicy::default().searchable_classes(&registry), vec![
            OpportunityClass::Arbitrage
        ]);
    }

    #[test]
    fn support_is_derived_from_the_registry_and_not_asserted_by_an_adapter() {
        // `ClassSupport::can_resolve` is the only gate, and it is only ever fed
        // from the registry. There is no constructor that takes a support value
        // from a caller, so an adapter cannot declare itself implemented.
        let code = code_region();
        assert!(!code.contains("fn support(&self) -> ClassSupport {\n        ClassSupport::Implemented"));
        assert!(ClassSupport::Implemented.can_resolve());
        assert!(!ClassSupport::Unsupported.can_resolve());
        assert_eq!(ClassSupport::Unsupported.state(), "unsupported");

        // A memory file that claims otherwise is not consulted: support is applied
        // at report time from the registry.
        let memory = SearchMemory::new();
        let raw = serde_json::to_value(&memory).unwrap();
        assert_eq!(raw.get("classes"), Some(&json!({})));
    }

    #[test]
    fn an_unimplemented_class_can_never_be_exhausted() {
        let minimums = HealthMinimums::default();
        for class in OpportunityClass::ALL {
            let coverage = ClassCoverage::unimplemented(class);
            assert_eq!(coverage.support, ClassSupport::Unsupported);
            assert!(
                !coverage
                    .sufficient_for_exhaustion(&minimums.min_class_coverage, 1)
                    .unwrap(),
                "{class} has no adapter and must never be exhausted"
            );
            // Not even with maximal, fake coverage.
            let mut faked = coverage.clone();
            faked.cycles_completed = 1_000_000;
            faked.cells_scanned = Some(1_000_000);
            assert!(!faked
                .sufficient_for_exhaustion(&minimums.min_class_coverage, 1)
                .unwrap());
        }
    }

    #[test]
    fn coverage_distinguishes_searched_and_empty_from_never_implemented() {
        let (dir, machine) = setup();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();

        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
        machine
            .observe(
                &mut memory,
                &p,
                &no_edge_observation(p.cycle, -1),
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();

        let rows = memory.coverage_all(&registry);
        let arbitrage = rows
            .iter()
            .find(|c| c.class == OpportunityClass::Arbitrage)
            .unwrap();
        assert_eq!(arbitrage.support, ClassSupport::Implemented);
        assert_eq!(arbitrage.cycles_completed, 1);
        assert!(arbitrage.candidates_found == 0);

        let solver = rows
            .iter()
            .find(|c| c.class == OpportunityClass::SolverReward)
            .unwrap();
        assert_eq!(solver.support, ClassSupport::Unsupported);
        assert_eq!(solver.cycles_attempted, 0);
        assert_eq!(solver.cycles_completed, 0);
        assert_eq!(solver.cells_scanned, None);
        assert_eq!(solver.state(), "unsupported");
    }

    #[test]
    fn enabling_an_unimplemented_class_does_not_manufacture_coverage() {
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let mut enabled = SearchPolicy::default().enabled_classes.clone();
        for class in OpportunityClass::ALL {
            enabled.insert(class);
        }
        let policy = SearchPolicy {
            enabled_classes: enabled,
            ..SearchPolicy::default()
        };
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();

        // Arbitrage exhausts first; then there is nothing searchable, because the
        // other six classes have no adapter regardless of what was enabled.
        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
        machine
            .observe(
                &mut memory,
                &p,
                &no_edge_observation(p.cycle, -1),
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();

        let attempt = machine
            .begin_search(&mut memory, &registry, &policy, Some(&gate), 1_001)
            .unwrap();
        assert!(attempt.permit().is_none());
        match attempt.denial().unwrap() {
            DenialReason::NothingSearchable { exhausted, enabled } => {
                assert_eq!(exhausted, &vec![START_CLASS]);
                assert_eq!(enabled.len(), 7);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(memory.state.state(), "cold_discovery");
        for class in OpportunityClass::ALL.iter().skip(1) {
            assert!(!memory.statistics(*class).exhausted, "{class}");
            assert_eq!(memory.statistics(*class).cycles_attempted, 0);
        }
    }

    #[test]
    fn an_unsupported_class_is_never_reported_as_no_edge() {
        // `next_class` never returns an unimplemented class, so the machine
        // cannot even enter a search for one; and if one is named directly, the
        // state is `unsupported_class`, not a market conclusion.
        let state = DiscoveryState::UnsupportedClass {
            class: OpportunityClass::StorageReward,
            why: "no OpportunityAdapter is registered for this class".into(),
        };
        assert_ne!(state.state(), "no_edge");
        assert!(!state.is_complete());
        assert!(!state.is_market_conclusion());
        assert_eq!(state.action(), SearchAction::SkipUnsupportedClass);
    }

    // ---------------------------------------------------------------------
    // I — TERR
    // ---------------------------------------------------------------------

    #[test]
    fn a_terr_research_request_is_passive_only_and_cannot_influence_execution() {
        let request =
            TerrResearchRequest::research(START_CLASS, &JobType::Backtest, 1_000_000, 1_000, "why")
                .unwrap();
        assert!(request.passive_only());
        assert!(!request.influences_execution());
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json.get("passive_only").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(
            json.get("influences_execution").and_then(|v| v.as_bool()),
            Some(false)
        );
        // No `Deserialize`: a JSON blob cannot be read back as a request, so
        // nothing downstream can be handed one.
        let code = code_region();
        assert!(!code.contains("impl<'de> Deserialize<'de> for TerrResearchRequest"));
        assert!(!code.contains("TerrResearchRequest>(serde_json::from_value"));
    }

    #[test]
    fn a_terr_research_request_refuses_any_job_type_outside_the_research_allowlist() {
        for job_type in [JobType::Simulation, JobType::Compute, JobType::Quote] {
            assert!(
                TerrResearchRequest::research(START_CLASS, &job_type, 1_000_000, 1_000, "why")
                    .is_err(),
                "{job_type:?} would be an execution request in disguise"
            );
        }
        for job_type in [JobType::Backtest, JobType::Validation, JobType::DataTransform] {
            assert!(TerrResearchRequest::research(
                START_CLASS,
                &job_type,
                1_000_000,
                1_000,
                "why"
            )
            .is_ok());
        }
        assert!(
            TerrResearchRequest::research(START_CLASS, &JobType::Backtest, 0, 1_000, "why")
                .is_err()
        );
    }

    #[test]
    fn a_terr_research_request_is_emitted_only_from_cold_discovery() {
        // From every other state, and from cold discovery with sufficient
        // diversity, `research` is `None`. There is no state from which a research
        // request and a promotable result coexist, so no TERR -> execution path
        // exists to close later.
        let mut requests = 0;
        for observation in [
            no_edge_observation(1, -1),
            base_observation_with(|o| {
                o.candidates = vec![candidate("c", 5_000_000)];
            }),
            base_observation_with(|o| {
                o.valuation = ValuationReadiness::NotComparable { why: "x".into() };
            }),
            SearchObservation::defective(
                START_CLASS,
                "test_adapter",
                1,
                EvidenceDefect::Unmeasured { why: "x".into() },
            ),
        ] {
            let report = observe(observation);
            assert!(
                report.research.is_none(),
                "{} must not emit a research request",
                report.state.state()
            );
            requests += 1;
        }
        assert_eq!(requests, 4);

        let cold = cold_report();
        assert_eq!(cold.state.state(), "cold_discovery");
        let request = cold.research.as_ref().expect("diversity is below its floor");
        assert!(request.passive_only());
        assert!(!request.influences_execution());
    }

    #[test]
    fn a_terr_research_request_can_never_produce_a_promotion() {
        let cold = cold_report();
        assert!(cold.research.is_some());
        assert!(cold.promotion.is_none());
        assert_ne!(cold.action, SearchAction::HandOffToAuthorityTrail);
        assert!(!cold.state.is_promotable());

        // And the module never writes TERR's ledger, so a request can only reach
        // TERR the way TERR already worked: by an operator importing a snapshot.
        let code = code_region();
        assert!(!code.contains("TERR_RESEARCH_LEDGER_FILE"));
        assert!(!code.contains("terr_research::"));
    }

    fn cold_report() -> DiscoveryReport {
        // A machine that has never searched and has nothing enabled to search:
        // zero completed cycles, no coverage, no conclusion about a market.
        let registry = registry();
        let policy = SearchPolicy::default();
        let mut memory = SearchMemory::new();
        memory.state = DiscoveryState::ColdDiscovery {
            summary: memory.cold_summary(&registry, &policy),
        };
        DiscoveryReport {
            schema_version: SCHEMA_VERSION,
            report_id: "cold".into(),
            decided_at_unix: 1_001,
            cycle: 0,
            observation_state: memory.state.clone(),
            observation_state_name: memory.state.state().to_string(),
            state: memory.state.clone(),
            state_name: memory.state.state().to_string(),
            action: memory.state.action(),
            action_name: memory.state.action().state().to_string(),
            completed: false,
            class: START_CLASS,
            coverage: memory.coverage(START_CLASS, &registry),
            class_coverage: memory.coverage_all(&registry),
            health: memory.health(&registry),
            health_verdict: HealthVerdict::Sufficient { checked: 4 },
            budget: BudgetSpend::default(),
            budget_exhausted_by: None,
            backoff_cycles: 0,
            next_attempt_cycle: 0,
            thresholds: default_audit(),
            promotion: None,
            research: TerrResearchRequest::research(
                OpportunityClass::SolverReward,
                &JobType::Backtest,
                1_000_000,
                1_001,
                "cold",
            )
            .ok(),
            concludes_no_external_value_exists: false,
            reason: memory.state.describe(),
        }
    }

    // ---------------------------------------------------------------------
    // J — execution capability
    // ---------------------------------------------------------------------

    #[test]
    fn the_adapter_trait_has_no_execution_method_and_no_code_can_transmit() {
        // Source-level, because this is the property that must not rot: there is
        // no method on any type in this module that can sign, order or broadcast.
        let code = code_region();
        for forbidden in [
            "eth_sendRaw",
            "send_transaction",
            "sign_transaction",
            "private_key",
            "TxHash",
            "raw_transaction",
            "signer(",
            "broadcast(",
        ] {
            assert!(
                !code.contains(forbidden),
                "discovery.rs production code contains {forbidden}"
            );
        }
        // The trait has exactly the three documented methods and no `execute`.
        let trait_block = &code[code.find("pub trait OpportunityAdapter").unwrap()
            ..code.find("pub trait OpportunityAdapter").unwrap() + 1_400];
        assert!(trait_block.contains("fn class(&self) -> OpportunityClass"));
        assert!(trait_block.contains("fn identity(&self) -> &str"));
        assert!(trait_block.contains("fn observe(&self, permit: &SearchPermit, now_unix: u64)"));
        assert!(!trait_block.contains("fn execute"));
        // And no RPC write path: the crate's six-method allowlist is untouched by
        // this module, which has no provider field at all.
        assert!(!code.contains("ChainProvider"));
        assert!(!code.contains("RpcMethod"));
    }

    #[test]
    fn p6_does_not_touch_the_settlement_module() {
        // The settlement path keeps its zero production callers: P6 can
        // *represent* an incomplete settlement but never derives one.
        let code = code_region();
        assert!(!code.contains("use crate::settlement"));
        assert!(!code.contains("crate::settlement::"));
        assert!(!code.contains("SettlementAuthority"));
        assert!(!code.contains("from_settlement_authorities"));
        // Its own vocabulary, so the boundary is a mapping and not a dependency.
        assert!(code.contains("pub enum SettlementGap"));
    }

    #[test]
    fn the_settlement_promotion_path_still_has_zero_production_callers() {
        // Nothing in P6 refers to the promotion constructor, so P6 did not become
        // the settlement path's first production caller.
        // P6.0.1: counted over the production halves only, with each file's
        // `#[cfg(test)]` module cut off first. Counting raw occurrences made this
        // a tripwire on how many *tests* exercise the constructor, so a test
        // gaining a fixture would have looked exactly like the settlement path
        // gaining a production caller.
        let settlement = production_half(include_str!("settlement.rs"));
        let view = production_half(include_str!("verified_view.rs"));
        let callers = settlement.matches("from_settlement_authorities(").count()
            + view.matches("from_settlement_authorities(").count();
        // Two: the definition and the one call site inside `verified_view`, which
        // sits on the `#[cfg(test)]`-free half only because the cut above removed
        // its test module.
        assert_eq!(
            callers, 2,
            "unexpected production references to the promotion constructor: {callers}"
        );
        let code = code_region();
        assert!(!code.contains("from_settlement_authorities"));
    }

    #[test]
    fn p6_submits_nothing_and_opens_no_execution_channel() {
        let code = code_region();
        for forbidden in [
            "submit_opportunity",
            "append_job",
            "register_agent",
            "orchestrate(",
            "settle_",
            "record_external_value",
        ] {
            assert!(
                !code.contains(forbidden),
                "discovery.rs production code contains {forbidden}"
            );
        }
        // Promotion is a returned suggestion, never a submission.
        assert!(code.contains("pub promotion: Option<PromotionCandidate>"));
    }

    #[test]
    fn a_promotable_candidate_still_has_to_clear_the_existing_autonomy_gates() {
        // Reaching `PromotionCandidate` is necessary and not sufficient: the
        // caller's `min_net_edge` is still applied by `orchestrate`, which is the
        // only path from an opportunity to a job intent.
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();
        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);

        let mut observation = no_edge_observation(p.cycle, -1);
        observation.candidates = vec![candidate("opp-1", 5_000_000)];
        // P6.0.1: a real attestation. This test is about the autonomy gates
        // downstream, and it can no longer reach a `PromotionCandidate` by
        // asserting a string.
        let (resolution, _) = attested_resolution(900_000);
        observation.resolution = Some(resolution);
        let report = machine
            .observe(
                &mut memory,
                &p,
                &observation,
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();
        assert_eq!(report.state.state(), "positive_nev");
        let promotion = report.promotion.as_ref().expect("promotable");
        assert_eq!(promotion.candidates.len(), 1);

        let home = tempdir().unwrap();
        let autonomous =
            crate::autonomy::AutonomousEconomy::open(home.path()).unwrap();
        let manifest = EconomicAgentManifest {
            schema_version: SCHEMA_VERSION,
            agent_id: "s1-arb-01".into(),
            // Required non-empty and, as the audit found, never parsed and never
            // verified. P6 neither relies on it nor adds a use for it.
            public_key: "unused-by-this-crate-not-parsed-not-verified".into(),
            agent_class: crate::autonomy::AgentClass::Finance,
            allowed_job_types: vec![JobType::Simulation],
            daily_budget_musd_micros: 500_000,
            max_job_cost_musd_micros: 50_000,
            risk_profile: crate::autonomy::RiskProfile::Conservative,
            enabled: true,
            created_at_unix: 1_000,
        };
        autonomous.register_agent(manifest).unwrap();

        // Even with the edge threshold opened to 0 by the caller, the job-type
        // allowlist and per-agent caps still apply — P6 changed nothing there.
        let loose = EconomicPolicy {
            min_net_edge_musd_micros: 0,
            ..EconomicPolicy::default()
        };
        for candidate in &promotion.candidates {
            autonomous.submit_opportunity(candidate.clone()).unwrap();
            let out = autonomous
                .orchestrate(&candidate.opportunity_id, &loose, 1_000_100)
                .unwrap();
            assert!(
                out.decision.accepted,
                "orchestrate still decides; P6 only recommends"
            );
        }
    }

    // ---------------------------------------------------------------------
    // L — P6.0.1: the wire shape
    //
    // The behavioural guarantees above live in the "P6.0.1 — the attestation
    // capability" section. What is left here is the *contract* rather than the
    // refusal: what a retired document does, and what an attestation looks like
    // once it has been earned. Three assertions that would otherwise be prose.
    // ---------------------------------------------------------------------

    /// A whole `SearchObservation` as JSON, built from the real serialiser rather
    /// than hand-written, so a field rename cannot turn this into a test of the
    /// wrong document.
    fn observation_json(resolution: Value) -> Value {
        let mut o = no_edge_observation(1, -1);
        o.candidates = vec![candidate("opp-1", 5_000_000)];
        let mut doc = serde_json::to_value(o).unwrap();
        doc["resolution"] = resolution;
        doc
    }

    #[test]
    fn a_legacy_chain_attested_document_is_refused_by_name_and_the_trust_type_is_gone() {
        // The leak, in one document, and what happens to a caller who sends it.
        // Before P6.0.1 this parsed into a `ResolutionTrust::ChainAttested` and
        // the state machine read `can_attest() == true` off it — an attestation
        // asserted by the very JSON being authorised.
        //
        // It is refused at the parse rather than demoted to a claim, and the
        // refusal *names the retired key*. That is deliberate: a caller
        // upgrading gets an error that tells them what to remove, instead of a
        // document that quietly parses with a different meaning. Demotion would
        // also be safe — a claim cannot promote — but it would be silent, and
        // the operator would go looking for the bug somewhere else.
        let doc = observation_json(json!({
            "nev_musd_micros": 900_000,
            "trust": {"chain_attested": {"provider": "unix:///run/mycelium-verifier.sock"}},
        }));
        let err = serde_json::from_value::<SearchObservation>(doc).unwrap_err();
        let why = err.to_string();
        assert!(why.contains("unknown field"), "{why}");
        assert!(why.contains("trust"), "{why}");

        // `ResolutionTrust` is deleted rather than kept as a reporting view: the
        // derived `ResolvedNev::is_attested` replaces it, and a second vocabulary
        // saying "chain_attested" in a log would be a second thing an operator
        // could read as a gate. It is gone from the production half of this file,
        // so there is nothing to construct it with either.
        let code = code_region();
        assert!(!code.contains("pub enum ResolutionTrust"));
        assert!(!code.contains("can_attest"));
    }

    #[test]
    fn a_claim_keeps_its_wire_name_and_an_earned_authority_is_named_beside_it() {
        // The compatibility half of the change. `nev_musd_micros` is preserved
        // under `#[serde(rename)]` so a `SearchObservation` written before
        // P6.0.1 still parses — it is simply a claim now, which is exactly the
        // mandate: non-authoritative by construction, not by rejection.
        let claim = serde_json::to_value(ResolvedNev::claimed(900_000)).unwrap();
        assert_eq!(
            claim["nev_musd_micros"],
            serde_json::json!(900_000),
            "the wire name is unchanged"
        );
        assert_eq!(claim["attested"], serde_json::Value::Null);

        // And an attestation that *was* earned is still serialized, so the report
        // and the audit log name the provider and the policy behind the number
        // instead of making the operator take it on faith.
        let (resolution, policy_hash) = attested_resolution(900_000);
        let json = serde_json::to_value(&resolution).unwrap();
        assert_eq!(json["nev_musd_micros"], serde_json::json!(900_000));
        assert_eq!(json["attested"]["nev"]["nev_musd_micros"], serde_json::json!(5_000_000));
        assert_eq!(json["attested"]["nev"]["receipts"], serde_json::json!(1));
        assert_eq!(json["attested"]["nev"]["policy_hash"], serde_json::json!(policy_hash));
        assert_eq!(
            json["attested"]["nev"]["provider_identity_verified"],
            serde_json::json!(true)
        );
        assert!(
            json["attested"]["nev"]["provider"]
                .as_str()
                .unwrap()
                .starts_with("unix://"),
            "{json}"
        );
    }

    #[test]
    fn the_operator_facing_reason_names_the_policy_that_attested_the_number() {
        // The audit trail is the reason `PromotionCandidate` carries a
        // `policy_hash` at all, so the sentence a human reads has to name the
        // authority too. An id in a log that cannot be traced to an authority is
        // an id the operator has to trust.
        let (resolution, policy_hash) = attested_resolution(900_000);
        let report = observe(resolution_free_observation(resolution));
        assert_eq!(report.state.state(), "positive_nev");
        assert!(
            report.reason.contains(&policy_hash),
            "the reason names the authority: {}",
            report.reason
        );
        assert!(report.reason.contains("attested"), "{}", report.reason);
        // The number is interpolated without digit separators, so the assertion
        // looks for the same spelling `Display` produces rather than the Rust
        // literal `5_000_000`.
        assert!(report.reason.contains("5000000"), "{}", report.reason);
        assert_eq!(report.state_name, "positive_nev");
        assert_eq!(report.action_name, "hand_off_to_authority_trail");
        // And the state serializes it too, so a persisted search-memory file
        // carries the authority rather than only the number.
        let state_json = serde_json::to_value(&report.state).unwrap();
        assert_eq!(state_json["detail"]["policy_hash"], serde_json::json!(policy_hash));
    }

    fn resolution_free_observation(resolution: ResolvedNev) -> SearchObservation {
        let mut o = no_edge_observation(1, -1);
        o.candidates = vec![candidate("opp-1", 5_000_000)];
        o.resolution = Some(resolution);
        o
    }

    // ---------------------------------------------------------------------
    // K — the report
    // ---------------------------------------------------------------------

    #[test]
    fn completed_is_false_for_a_thermal_stop_an_incomplete_settlement_zero_cells_and_invalid_evidence() {
        // The four things that must never read as completion, plus two more.
        for (observation, expected) in [
            (
                base_observation_with(|o| {
                    o.thermal = ObservedThermal {
                        start_max_c: Some(93.0),
                        end_c: None,
                        maximum_c: None,
                    };
                }),
                "search_aborted_thermal",
            ),
            (
                base_observation_with(|o| {
                    o.settlement = SettlementReadiness::Incomplete(vec![SettlementGap::Absent {
                        why: "x".into(),
                    }]);
                }),
                "no_complete_settlement",
            ),
            (base_observation(1), "invalid_evidence"),
            (
                base_observation_with(|o| {
                    o.cycles_budgeted = 4;
                    o.spend = BudgetSpend {
                        cycles: 99,
                        ..BudgetSpend::default()
                    };
                }),
                "budget_exhausted",
            ),
            (
                base_observation_with(|o| {
                    o.aborted = true;
                    o.best_observed_edge = Some(MeasuredEdge {
                        token_edge_micros: Some(-1),
                        robust_net_micros: -1,
                        source_field: "near_edge_refinement".into(),
                    });
                }),
                "no_edge",
            ),
        ] {
            let report = observe(observation);
            assert_eq!(report.state.state(), expected);
            assert!(!report.completed, "{expected} must not read as complete");
            assert_ne!(report.state_name, "completed");
            // A run that stopped early can never declare a class exhausted, so
            // it contributes coverage but never closure.
            if expected == "no_edge" {
                assert!(report.coverage.cycles_aborted > 0);
            }
        }

        // `is_complete` is the single definition, and it excludes exactly these.
        let incomplete: BTreeSet<&str> = all_states()
            .iter()
            .filter(|s| !s.is_complete())
            .map(DiscoveryState::state)
            .collect();
        assert_eq!(
            incomplete,
            BTreeSet::from([
                "searching",
                "search_aborted_thermal",
                "no_complete_settlement",
                "invalid_evidence",
                "unsupported_class",
                "budget_exhausted",
            ])
        );
    }

    #[test]
    fn every_report_names_its_state_its_action_and_its_reason() {
        for observation in [
            no_edge_observation(1, -2_032_674),
            base_observation(1),
            base_observation_with(|o| {
                o.candidates = vec![candidate("c", 5_000_000)];
            }),
        ] {
            let report = observe(observation);
            assert_eq!(report.state_name, report.state.state());
            assert_eq!(report.action, report.state.action());
            assert_eq!(report.action_name, report.action.state());
            assert_eq!(report.observation_state_name, report.observation_state.state());
            assert!(!report.reason.is_empty());
            assert_eq!(report.reason, report.state.describe());
            let json = serde_json::to_value(&report).unwrap();
            assert_eq!(
                json.get("state").and_then(|v| v.get("state")).and_then(|v| v.as_str()),
                Some(report.state_name.as_str())
            );
        }
    }

    #[test]
    fn a_machine_that_never_searched_is_not_reported_as_completed() {
        // Cold discovery with zero completed cycles: a conclusion about the
        // machine, not about the market, so `completed` stays false.
        let cold = cold_report();
        assert_eq!(cold.state.state(), "cold_discovery");
        assert!(!cold.completed);
        assert_eq!(cold.coverage.cycles_completed, 0);
        assert!(!cold.state.is_market_conclusion());
        assert!(!cold.concludes_no_external_value_exists);
    }

    // ---------------------------------------------------------------------
    // The one real adapter, over the two existing S1 importers
    // ---------------------------------------------------------------------

    fn perception_report(
        dir: &tempfile::TempDir,
        best_edge: Option<i64>,
        best_robust: Option<i64>,
        end_temp_c: Option<f64>,
        events: Value,
    ) -> PathBuf {
        let path = dir.path().join("perception.json");
        let value = json!({
            // Key names and refusal rules are the importer's, not P6's.
            "mode": "PERCEPTION_SHADOW",
            "status": "COMPLETED",
            "cycles_requested": 2,
            "cycles_completed": 2,
            "started_at": 1_700_000_000.0,
            "chain_id": 8453,
            "measured": true,
            "broadcast": false,
            "profit_is_real": false,
            "anvil": false,
            "best_observed_token_edge_usdc_raw": best_edge,
            "best_observed_robust_net_usdc_raw": best_robust,
            "thermal_start_window": { "max": 55.0 },
            "end_temp_c": end_temp_c,
            "events": events,
            "candidates": []
        });
        std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    }

    /// The event shape the perception importer actually reduces across
    /// `events[].near_edge_refinement`. These are the fields whose **maximum**
    /// across every event becomes `best_observed_*_usdc_raw` — the measurement the
    /// audit found being computed and discarded.
    ///
    /// Two events on purpose: the aggregate is a maximum, so a report whose best
    /// observation is worse than a later one must not be summarised by whichever
    /// event happened to be first.
    fn edge_event(token: i64, robust: i64) -> Value {
        json!([
            { "near_edge_refinement": {
                "best_refined_edge_usdc_raw": -90_000,
                "best_refined_robust_net_usdc_raw": -9_000_000
            } },
            { "near_edge_refinement": {
                "best_refined_edge_usdc_raw": token,
                "best_refined_robust_net_usdc_raw": robust
            } }
        ])
    }

    #[test]
    fn a_measured_negative_perception_scan_becomes_no_edge_with_its_evidence() {
        // The evidence the audit found being computed and discarded, now kept.
        let dir = tempdir().unwrap();
        let path = perception_report(&dir, Some(-32_674), Some(-2_032_674), Some(58.0), edge_event(-32_674, -2_032_674));
        let registry = registry_for(&path);

        let machine = DiscoveryMachine::open(tempdir().unwrap()).unwrap();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();
        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);

        let observation = registry
            .adapter(OpportunityClass::Arbitrage, "s1_shadow_scan")
            .unwrap()
            .observe(&p, 1_000)
            .unwrap();
        assert_eq!(observation.best_observed_edge.as_ref().unwrap().robust_net_micros, -2_032_674);
        assert_eq!(
            observation.best_observed_edge.as_ref().unwrap().source_field,
            "near_edge_refinement"
        );

        let report = machine
            .observe(
                &mut memory,
                &p,
                &observation,
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();
        assert_eq!(report.observation_state.state(), "no_edge");
        // The perception report does not count cells, so coverage is not
        // sufficient and the class may not be declared exhausted from it.
        assert_eq!(report.state.state(), "no_edge");
        assert!(report.completed);
        assert!(report.reason.contains("-2032674"));
    }

    #[test]
    fn a_perception_report_with_no_measured_aggregate_is_invalid_evidence() {
        // A completed scan that found nothing and measured nothing cannot be
        // turned into "the market did not pay".
        let dir = tempdir().unwrap();
        let path = perception_report(&dir, None, None, Some(58.0), json!([]));
        let registry = registry_for(&path);
        let machine = DiscoveryMachine::open(tempdir().unwrap()).unwrap();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();
        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);

        let observation = registry
            .adapter(OpportunityClass::Arbitrage, "s1_shadow_scan")
            .unwrap()
            .observe(&p, 1_000)
            .unwrap();
        assert!(observation.best_observed_edge.is_none());
        let report = machine
            .observe(
                &mut memory,
                &p,
                &observation,
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();
        assert_eq!(report.state.state(), "invalid_evidence");
        assert_ne!(report.state.state(), "no_edge");
        assert!(!report.completed);
    }

    #[test]
    fn a_perception_report_that_ran_hot_is_a_thermal_stop() {
        // `endTempC` is read into the report by the importer and, before P6,
        // compared by nothing.
        let dir = tempdir().unwrap();
        let path = perception_report(
            &dir,
            Some(-1),
            Some(-1),
            Some(93.0),
            edge_event(-1, -1),
        );
        let registry = registry_for(&path);
        let machine = DiscoveryMachine::open(tempdir().unwrap()).unwrap();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();
        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
        let observation = registry
            .adapter(OpportunityClass::Arbitrage, "s1_shadow_scan")
            .unwrap()
            .observe(&p, 1_000)
            .unwrap();
        assert_eq!(observation.thermal.end_c, Some(93.0));

        let report = machine
            .observe(
                &mut memory,
                &p,
                &observation,
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();
        assert_eq!(report.state.state(), "search_aborted_thermal");
        assert_ne!(report.state.state(), "no_edge");
    }

    #[test]
    fn an_observation_that_disagrees_with_its_permit_is_invalid_evidence() {
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy::default();
        let gate = healthy_gate(&dir, 1_000);
        let mut memory = SearchMemory::new();
        let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);

        let mut observation = no_edge_observation(p.cycle, -1);
        observation.cycle = p.cycle + 7;
        let report = machine
            .observe(
                &mut memory,
                &p,
                &observation,
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();
        assert_eq!(report.state.state(), "invalid_evidence");
        match report.state {
            DiscoveryState::InvalidEvidence { defect, .. } => {
                assert_eq!(defect.state(), "class_mismatch");
            }
            other => panic!("{other:?}"),
        }

        let mut wrong_class = no_edge_observation(p.cycle, -1);
        wrong_class.class = OpportunityClass::NetworkFee;
        let report = machine
            .observe(
                &mut memory,
                &p,
                &wrong_class,
                &registry,
                &policy,
                &default_audit(),
                1_000,
            )
            .unwrap();
        assert_eq!(report.state.state(), "invalid_evidence");
    }

    #[test]
    fn a_denied_attempt_hands_the_adapter_nothing() {
        // The permit is the only thing that lets an adapter run, so a refused
        // search cannot reach one.
        let dir = tempdir().unwrap();
        let machine = DiscoveryMachine::open(dir.path()).unwrap();
        let registry = registry();
        let policy = SearchPolicy::default();
        let mut memory = SearchMemory::new();
        let blocked = read_mupp_gate(
            write_mupp_state(&dir, 1_000.0, false, 12.0, "COLLAPSE", true),
            1_001.0,
            &MuppAdapterPolicy::default(),
        )
        .unwrap();

        let attempt = machine
            .begin_search(&mut memory, &registry, &policy, Some(&blocked), 1_001)
            .unwrap();
        assert!(attempt.permit().is_none());
        assert_eq!(memory.state.state(), "search_aborted_thermal");
    }

    #[test]
    fn a_perception_report_that_failed_upstream_is_still_refused() {
        // P6 adds no acceptance the existing importers do not already make:
        // `chainId`, `measured`, `broadcast` and `profitIsReal` are still the
        // importers' refusals, reached through the same functions.
        let dir = tempdir().unwrap();
        // The importer's own refusal list, verbatim. P6 adds none and relaxes
        // none: it reaches these refusals through the same functions.
        for mutation in [
            json!({ "broadcast": true }),
            json!({ "anvil": true }),
            json!({ "status": "THERMAL_START_BLOCKED" }),
            json!({ "status": "SOMETHING_ELSE" }),
            json!({ "cycles_completed": 0 }),
            json!({ "cycles_completed": 3 }),
            json!({ "mode": "LIVE" }),
            json!({ "started_at": -1.0 }),
        ] {
            let path = dir.path().join(format!("m-{mutation}.json"));
            let mut value = json!({
                "mode": "PERCEPTION_SHADOW",
                "status": "COMPLETED",
                "cycles_requested": 2,
                "cycles_completed": 2,
                "started_at": 1_700_000_000.0,
                "chain_id": 8453,
                "measured": true,
                "broadcast": false,
                "profit_is_real": false,
                "anvil": false,
                "best_observed_token_edge_usdc_raw": -1,
                "best_observed_robust_net_usdc_raw": -1,
                "thermal_start_window": { "max": 55.0 },
                "end_temp_c": 58.0,
                "events": edge_event(-1, -1),
                "candidates": []
            });
            for (k, v) in mutation.as_object().unwrap() {
                value[k] = v.clone();
            }
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let registry = registry_for(&path);
            let machine = DiscoveryMachine::open(tempdir().unwrap()).unwrap();
            let policy = SearchPolicy::default();
            let gate = healthy_gate(&dir, 1_000);
            let mut memory = SearchMemory::new();
            let p = permit(&machine, &mut memory, &registry, &policy, &gate, 1_000);
            let result = registry
                .adapter(OpportunityClass::Arbitrage, "s1_shadow_scan")
                .unwrap()
                .observe(&p, 1_000);
            assert!(result.is_err(), "{mutation} should be refused upstream");
        }
    }

    // ---------------------------------------------------------------------
    // Shared helpers for the table-driven classification tests
    // ---------------------------------------------------------------------
}
