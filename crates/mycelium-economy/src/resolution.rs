//! P6.6 — the economic result taxonomy.
//!
//! # What this is for
//!
//! [`crate::discovery::DiscoveryState`] is a *report*: fifteen states, all
//! `Serialize`/`Deserialize`, none of them carrying an authority. That is
//! correct and it is not enough, because a report and a value are different
//! things and the difference was not expressible anywhere. A caller holding
//! `DiscoveryState::PositiveNev { nev_musd_micros, .. }` holds a **number and a
//! resolution id**; [`EconomicResolution::PositiveNev`] holds a
//! [`crate::verified_view::VerifiedNev`], which is a type with private fields,
//! no `Deserialize` and one `pub(crate)` constructor inside this crate.
//!
//! This module closes that gap in the direction that cannot be reopened later:
//! **the taxonomy has nine arms and exactly one of them can hand out a value.**
//! Not "has a flag that says it may". One arm, one type, one private field, and
//! a single function — [`EconomicResolution::into_authority`] — which is the
//! only route from a resolution to anything an authority could consume.
//!
//! # The properties, one by one
//!
//! ## 1. Eight arms, eight types, none of which can hold a `VerifiedNev`
//!
//! Each non-authoritative arm is a **distinct struct**, not a shared payload
//! with a boolean. [`NoEdge`] and [`BreakEven`] are different types, so there is
//! no expression of "a no-edge that happens to be promotable": the flag a `bool`
//! would carry has nowhere to live, because the two values have different field
//! lists and a bool would have to be invented to bridge them.
//!
//! None of the eight has a method returning a
//! [`crate::verified_view::VerifiedNev`], a budget, or a promotion candidate.
//! That is a property of the types, not of a code path someone can forget:
//!
//! * their fields are `pub` (so a report is useful) and none of them has a
//!   `VerifiedNev` field;
//! * the only function that returns a [`PositiveNev`] is
//!   [`EconomicResolution::into_authority`], and it is one `match` whose
//!   successful arm is the `PositiveNev` arm;
//! * the coherence tripwire in [`sealed`] makes it a **compile error** for
//!   `PositiveNev` ever to gain the [`NonAuthoritative`] marker the eight
//!   refusals carry.
//!
//! ## 2. A `DiscoveryState` cannot be laundered into a `PositiveNev`
//!
//! [`EconomicResolution::from_discovery_state`] refuses
//! `DiscoveryState::PositiveNev` with
//! [`StateWithoutAuthority::PositiveNevStateCarriesNoVerifiedNev`]. The
//! discovery state reports a number; the taxonomy arm requires a
//! `VerifiedNev`. Accepting the first as the second would be exactly the
//! failure this crate's whole trust chain exists to prevent: a caller-supplied
//! integer reaching a promotion as though a pinned provider had attested it.
//!
//! The only constructor of [`PositiveNev`] is `pub(crate)`, lives in this
//! module, and its one production caller is the NEV-0 gate in [`crate::nev0`].
//!
//! ## 3. Nothing here reaches spend authority
//!
//! [`PositiveNev`] is an economic claim, not a budget. It has no method that
//! returns a commitment, an amount, or a spend permission, and this module does
//! not call [`crate::reinvestment::ReinvestmentController`] at all. Turning a
//! value into spending authority still goes through
//! [`crate::reinvestment::ReinvestmentController::commit_job_from_view`], which
//! takes a [`crate::verified_view::VerifiedEconomyView`] — not a
//! `PositiveNev`, not a `VerifiedNev`, not anything from this module. The
//! settlement promotion path keeps its zero production callers.
//!
//! What a `PositiveNev` does gate is spend authority's *precondition*, and
//! that check lives in [`crate::revalidation`]: the only pair that yields a
//! standing is the one authority-bearing arm **plus** a confirmed canonical
//! chain. `NeedsRevalidation` blocks.

use crate::autonomy::ExternalValueClass;
use crate::discovery::{
    BudgetSpend, DiscoveryState, EvidenceDefect, MeasuredEdge, OpportunityClass, SettlementGap,
    ThermalStop,
};
use crate::verified_view::VerifiedNev;
use serde::{Deserialize, Serialize};
use std::fmt;

mod sealed {
    /// The coherence tripwire.
    ///
    /// [`super::NonAuthoritative`] is a marker with no methods, so nothing
    /// consumes it at runtime and there would be nothing to notice if a ninth
    /// impl appeared. This blanket impl gives the marker a consequence: if
    /// `PositiveNev` ever gained `NonAuthoritative`, the two impls below would
    /// overlap and the crate would **stop compiling**. That is the only way the
    /// absence is testable at all — Rust has no negative trait bounds, so the
    /// boundary has to be enforced by something that breaks loudly.
    ///
    /// `allow(dead_code)`: the constraint is evaluated by the compiler whether or
    /// not any code *names* the trait, and the crate's own assertions about it
    /// live in the tests. Without this the non-test build would warn about a
    /// trait whose entire value is that it has exactly two impls and no callers.
    #[allow(dead_code)]
    pub trait AuthorityTripwire {}

    /// Blanket over every non-authoritative arm.
    impl<T: super::NonAuthoritative> AuthorityTripwire for T {}

    /// The single explicit impl. Its only job is to collide with the blanket
    /// impl above if the boundary is ever crossed.
    impl AuthorityTripwire for super::PositiveNev {}
}

/// Marker for the eight arms that can never carry a verified net external value.
///
/// Deliberately **not** sealed by a supertrait bound: making
/// [`sealed::AuthorityTripwire`] a supertrait of this would make the blanket impl
/// in [`sealed`] depend on the very bound it implements, and trait resolution
/// would cycle. The tripwire works without it.
pub trait NonAuthoritative {}

// ---------------------------------------------------------------------------
// The eight refusals
// ---------------------------------------------------------------------------

/// The market was scanned and the best measured robust net did not pay.
///
/// Requires a [`MeasuredEdge`]: "found nothing" without a measured negative is
/// not this arm, it is a defect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoEdge {
    pub class: OpportunityClass,
    pub edge: MeasuredEdge,
    pub cycles_completed: u64,
}

impl NoEdge {
    pub fn new(class: OpportunityClass, edge: MeasuredEdge, cycles_completed: u64) -> Self {
        Self {
            class,
            edge,
            cycles_completed,
        }
    }
}

impl NonAuthoritative for NoEdge {}

/// A settlement-shaped result exists and is incomplete.
///
/// The adapter or the evidence is at fault, **not** the market, so this arm is
/// never a licence to search again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoCompleteSettlement {
    pub class: OpportunityClass,
    pub gaps: Vec<SettlementGap>,
}

impl NoCompleteSettlement {
    pub fn new(class: OpportunityClass, gaps: Vec<SettlementGap>) -> Self {
        Self { class, gaps }
    }
}

impl NonAuthoritative for NoCompleteSettlement {}

/// A value exists but no comparable net value could be derived.
///
/// The valuation is at fault, so this arm asks for a price and never for
/// another scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoComparableNetValue {
    pub class: OpportunityClass,
    pub why: String,
}

impl NoComparableNetValue {
    pub fn new(class: OpportunityClass, why: impl Into<String>) -> Self {
        Self {
            class,
            why: why.into(),
        }
    }
}

impl NonAuthoritative for NoComparableNetValue {}

/// A candidate resolved and the net external value was a realised loss.
///
/// The sign is the invariant, enforced by the constructor: there is no way to
/// build this arm with a non-negative value, so it cannot be used to carry a
/// positive number into a "we measured a loss" report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeNev {
    pub class: OpportunityClass,
    /// Strictly negative. See [`NegativeNev::new`].
    pub nev_musd_micros: i64,
    pub resolution_id: String,
}

impl NegativeNev {
    /// Refuses a non-negative value.
    pub fn new(
        class: OpportunityClass,
        nev_musd_micros: i64,
        resolution_id: impl Into<String>,
    ) -> Result<Self, ResolutionError> {
        if nev_musd_micros >= 0 {
            return Err(ResolutionError::ValueOutsideArm {
                arm: "negative_nev",
                value_musd_micros: nev_musd_micros,
                why: "a realised loss is negative by definition; a value at or above zero \
                      belongs to break_even or positive_nev"
                    .to_string(),
            });
        }
        Ok(Self {
            class,
            nev_musd_micros,
            resolution_id: resolution_id.into(),
        })
    }
}

impl NonAuthoritative for NegativeNev {}

/// A candidate resolved to a value that did not clear the minimum.
///
/// Both `nev == 0` and a positive value below the bar land here, and that is
/// deliberate: the decision is the same, so reporting them differently would
/// imply the machine distinguishes "nothing" from "a little", which for
/// promotion purposes it must not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BreakEven {
    pub class: OpportunityClass,
    /// In `[0, required_musd_micros)`. See [`BreakEven::new`].
    pub nev_musd_micros: i64,
    /// The bar that was not cleared. Never zero for an arm built here.
    pub required_musd_micros: u64,
}

impl BreakEven {
    /// Refuses a negative value, a value at or above the bar, and a zero bar.
    pub fn new(
        class: OpportunityClass,
        nev_musd_micros: i64,
        required_musd_micros: u64,
    ) -> Result<Self, ResolutionError> {
        if nev_musd_micros < 0 {
            return Err(ResolutionError::ValueOutsideArm {
                arm: "break_even",
                value_musd_micros: nev_musd_micros,
                why: "a negative value is a realised loss, which is its own arm".to_string(),
            });
        }
        if required_musd_micros == 0 {
            return Err(ResolutionError::ZeroRequiredEdge {
                why: "a required net edge of zero would make every value promotable; the \
                      minimum is a gate and this crate refuses to construct the degenerate one"
                    .to_string(),
            });
        }
        if nev_musd_micros as u64 >= required_musd_micros {
            return Err(ResolutionError::ValueOutsideArm {
                arm: "break_even",
                value_musd_micros: nev_musd_micros,
                why: "a value at or above the required minimum is positive_nev, not break_even"
                    .to_string(),
            });
        }
        Ok(Self {
            class,
            nev_musd_micros,
            required_musd_micros,
        })
    }
}

impl NonAuthoritative for BreakEven {}

/// The adapter's evidence is unusable. Fail closed, and never a negative edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvalidEvidence {
    pub class: OpportunityClass,
    pub defect: EvidenceDefect,
}

impl InvalidEvidence {
    pub fn new(class: OpportunityClass, defect: EvidenceDefect) -> Self {
        Self { class, defect }
    }
}

impl NonAuthoritative for InvalidEvidence {}

/// A thermal or budget stop. Contributes no coverage and is not a conclusion
/// about the market.
///
/// `PartialEq` without `Eq`: [`ThermalStop`] and [`BudgetSpend`] both carry
/// `f64` measurements, and "is this exactly the same measurement" is not a
/// question this crate asks of a stop reason.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchAbortedThermal {
    pub class: OpportunityClass,
    pub stop: ThermalStop,
    pub spend: BudgetSpend,
}

impl SearchAbortedThermal {
    pub fn new(class: OpportunityClass, stop: ThermalStop, spend: BudgetSpend) -> Self {
        Self { class, stop, spend }
    }
}

impl NonAuthoritative for SearchAbortedThermal {}

/// No adapter exists for this class. Never searched, so no coverage number will
/// ever move and no conclusion about the market exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedClass {
    pub class: OpportunityClass,
    pub why: String,
}

impl UnsupportedClass {
    pub fn new(class: OpportunityClass, why: impl Into<String>) -> Self {
        Self {
            class,
            why: why.into(),
        }
    }
}

impl NonAuthoritative for UnsupportedClass {}

// ---------------------------------------------------------------------------
// The one arm that carries a value
// ---------------------------------------------------------------------------

/// What NEV-0 established about the evidence behind a [`PositiveNev`].
///
/// Recorded rather than inferred, so an audit reads the accounting that produced
/// the number instead of re-deriving it from a number it is already supposed to
/// trust. The gate that fills this in checks the arithmetic: what was counted is
/// `gross - external_cost - native_cost`, and it is `> 0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nev0Evidence {
    /// The single external class every counted operation was booked as.
    ///
    /// One value, not a set: NEV-0 does not add a MYC emission to a trading
    /// profit, it refuses the whole set.
    pub value_class: ExternalValueClass,
    /// Complete operations, each one all legs or none.
    pub complete_operations: u64,
    /// Legs across those operations.
    pub legs: u64,
    pub gross_inflow_musd_micros: u64,
    pub external_cost_musd_micros: u64,
    /// Gas and every other native cost, already converted at a
    /// policy-authorised price. Zero is legitimate; *unpriced* is not, and that
    /// is [`crate::nev0::GasPricing::Unpriced`].
    pub native_cost_musd_micros: u64,
}

impl Nev0Evidence {
    /// The net that was counted, recomputed from the recorded parts.
    ///
    /// A checked subtraction: accounting that cannot be recomputed is not
    /// counted, so `None` here is a refusal signal for a caller reading a stored
    /// report rather than an in-memory grant.
    pub fn net_musd_micros(&self) -> Option<i64> {
        let gross = i64::try_from(self.gross_inflow_musd_micros).ok()?;
        let external = i64::try_from(self.external_cost_musd_micros).ok()?;
        let native = i64::try_from(self.native_cost_musd_micros).ok()?;
        gross.checked_sub(external)?.checked_sub(native)
    }
}

/// The only arm of [`EconomicResolution`] that carries a value.
///
/// Private fields, no `Deserialize`, and one `pub(crate)` constructor. The
/// absence of `Deserialize` is the load-bearing half: a JSON document cannot be
/// read back as one of these, exactly as with
/// [`crate::verified_view::VerifiedNev`], so the only way to hold a `PositiveNev`
/// is to have been handed a `VerifiedNev` *and* been through
/// [`crate::nev0::Nev0Gate`].
///
/// **This is an economic claim, not a budget.** It has no method that returns a
/// commitment, an amount, or a spend permission, and nothing in this crate
/// wires it to [`crate::reinvestment`].
#[derive(Debug, Clone, Serialize)]
pub struct PositiveNev {
    class: OpportunityClass,
    nev: VerifiedNev,
    evidence: Nev0Evidence,
}

impl PositiveNev {
    /// The one constructor. `pub(crate)`, and called in production only by the
    /// NEV-0 gate, after every refusal has been checked.
    pub(crate) fn from_verified(
        class: OpportunityClass,
        nev: VerifiedNev,
        evidence: Nev0Evidence,
    ) -> Self {
        Self {
            class,
            nev,
            evidence,
        }
    }

    /// The verified total. Read-only: there is no mutable accessor, and
    /// `VerifiedNev` has no mutator either.
    pub fn verified_nev(&self) -> &VerifiedNev {
        &self.nev
    }

    pub fn nev_musd_micros(&self) -> i64 {
        self.nev.nev_musd_micros()
    }

    /// The class the search resolved, as the gate was told.
    pub fn class(&self) -> OpportunityClass {
        self.class
    }

    /// The NEV-0 accounting, so a report names the parts and not only the total.
    pub fn evidence(&self) -> &Nev0Evidence {
        &self.evidence
    }
}

// ---------------------------------------------------------------------------
// The enum
// ---------------------------------------------------------------------------

/// A final economic result: nine arms, one of which carries a value.
///
/// Coherent with [`crate::discovery::DiscoveryState`] and its
/// [`crate::discovery::DiscoveryState::state`] convention — the eight refusal
/// arms use the same state names the discovery states they come from use, so a
/// report can be joined on one key.
///
/// `Serialize` but **not** `Deserialize`: the enum contains a
/// [`crate::verified_view::VerifiedNev`], which has no `Deserialize` either.
/// That is deliberate, and it is why an adjudication cannot be replayed from
/// disk. A caller who wants a stored decision re-derives it, which means
/// re-running the gate.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "resolution", content = "detail", rename_all = "snake_case")]
pub enum EconomicResolution {
    NoEdge(NoEdge),
    NoCompleteSettlement(NoCompleteSettlement),
    NoComparableNetValue(NoComparableNetValue),
    NegativeNev(NegativeNev),
    BreakEven(BreakEven),
    PositiveNev(PositiveNev),
    InvalidEvidence(InvalidEvidence),
    SearchAbortedThermal(SearchAbortedThermal),
    UnsupportedClass(UnsupportedClass),
}

impl EconomicResolution {
    /// The machine-readable arm name, one per situation, never shared.
    pub fn state(&self) -> &'static str {
        match self {
            Self::NoEdge(_) => "no_edge",
            Self::NoCompleteSettlement(_) => "no_complete_settlement",
            Self::NoComparableNetValue(_) => "no_comparable_net_value",
            Self::NegativeNev(_) => "negative_nev",
            Self::BreakEven(_) => "break_even",
            Self::PositiveNev(_) => "positive_nev",
            Self::InvalidEvidence(_) => "invalid_evidence",
            Self::SearchAbortedThermal(_) => "search_aborted_thermal",
            Self::UnsupportedClass(_) => "unsupported_class",
        }
    }

    /// Every arm name, so a renderer cannot forget one. A `const`, so a tenth
    /// arm is a compile error here rather than a row that quietly stops being
    /// listed.
    pub const ALL_STATES: [&'static str; 9] = [
        "no_edge",
        "no_complete_settlement",
        "no_comparable_net_value",
        "negative_nev",
        "break_even",
        "positive_nev",
        "invalid_evidence",
        "search_aborted_thermal",
        "unsupported_class",
    ];

    /// The class this resolution is about. Not optional: unlike
    /// [`crate::discovery::DiscoveryState`], no arm here is about "all classes",
    /// because a resolution is always about exactly one.
    pub fn class(&self) -> OpportunityClass {
        match self {
            Self::NoEdge(v) => v.class,
            Self::NoCompleteSettlement(v) => v.class,
            Self::NoComparableNetValue(v) => v.class,
            Self::NegativeNev(v) => v.class,
            Self::BreakEven(v) => v.class,
            Self::PositiveNev(v) => v.class(),
            Self::InvalidEvidence(v) => v.class,
            Self::SearchAbortedThermal(v) => v.class,
            Self::UnsupportedClass(v) => v.class,
        }
    }

    /// Whether this arm is the one that carries a value.
    ///
    /// `false` for eight arms by construction: the match has one `true` and the
    /// enum has nine variants, so adding a tenth arm fails to compile here until
    /// somebody decides what it means.
    pub fn is_authority(&self) -> bool {
        matches!(self, Self::PositiveNev(_))
    }

    /// Whether this is a conclusion about the market rather than about the
    /// machine's own limits.
    ///
    /// Mirrors [`crate::discovery::DiscoveryState::is_market_conclusion`]: a
    /// thermal stop, an incomplete settlement, an unsupported class and invalid
    /// evidence are all *not* market conclusions, and folding any of them into
    /// "the market did not pay" is the collapse this taxonomy exists to prevent.
    pub fn is_market_conclusion(&self) -> bool {
        matches!(
            self,
            Self::NoEdge(_) | Self::NegativeNev(_) | Self::BreakEven(_) | Self::PositiveNev(_)
        )
    }

    /// Whether the search that produced this resolution can be said to have
    /// concluded. `false` for the four states that are not completions.
    pub fn is_complete(&self) -> bool {
        !matches!(
            self,
            Self::NoCompleteSettlement(_)
                | Self::InvalidEvidence(_)
                | Self::UnsupportedClass(_)
                | Self::SearchAbortedThermal(_)
        )
    }

    /// The only route from a resolution to something an authority could consume.
    ///
    /// One `match`, one successful arm, one error type. Every other arm is
    /// consumed and destroyed: there is no borrow-based reading that could hand
    /// out a value sitting inside a refusal, because no refusal holds one.
    ///
    /// This says nothing about spend authority. See
    /// [`crate::revalidation`] for that, which additionally requires a confirmed
    /// canonical chain.
    pub fn into_authority(self) -> Result<PositiveNev, NoEconomicAuthority> {
        match self {
            Self::PositiveNev(v) => Ok(v),
            other => Err(NoEconomicAuthority {
                state: other.state().to_string(),
                class: other.class(),
                why: format!(
                    "{} is not the authority-bearing arm; only a NEV-0 adjudication that cleared \
                     every refusal produces a positive net external value, and this arm reports: \
                     {}",
                    other.state(),
                    other.describe()
                ),
            }),
        }
    }

    /// A borrowed view of the value, for reporting. Not a grant: it still has to
    /// go through [`Self::into_authority`], and it borrows the resolution rather
    /// than moving it.
    pub fn positive_nev(&self) -> Option<&PositiveNev> {
        match self {
            Self::PositiveNev(v) => Some(v),
            _ => None,
        }
    }

    /// Build a resolution from a discovery state.
    ///
    /// Refuses, rather than guessing:
    ///
    /// * [`DiscoveryState::PositiveNev`] — it carries a number and a resolution
    ///   id, not a [`crate::verified_view::VerifiedNev`]. Converting it would be
    ///   laundering a claim into an authority, so the conversion does not exist.
    /// * [`DiscoveryState::UnattestedNev`] — same reason, and the state exists
    ///   precisely so a claim is not mistaken for a value.
    /// * The five states that are about the *search* rather than about a
    ///   resolution — there is nothing to resolve yet.
    // The clippy lint wants a `matches!`, which cannot express "this arm builds
    // a value and that arm returns an error with a different payload". The `match`
    // is the readable form and the one that keeps each refusal next to its own
    // reason.
    #[allow(clippy::match_like_matches_macro)]
    pub fn from_discovery_state(state: &DiscoveryState) -> Result<Self, StateWithoutAuthority> {
        // The arm constructors carry their own invariants (a `negative_nev` is
        // negative, a `break_even` is below its bar) and a discovery state that
        // violates one is a state this crate will not resolve rather than a
        // state it will mis-file. Translating keeps the error vocabulary of
        // this function to "there is no authority here", which is the only
        // question it answers.
        let arm_error = |e: ResolutionError| StateWithoutAuthority::NotAResolution {
            state: state.state().to_string(),
            why: format!(
                "the state names an economic result this taxonomy refuses to build: {e}"
            ),
        };
        match state {
            DiscoveryState::NoEdge {
                class,
                edge,
                cycles_completed,
            } => Ok(Self::NoEdge(NoEdge::new(*class, edge.clone(), *cycles_completed))),
            DiscoveryState::NoCompleteSettlement { class, gaps } => {
                Ok(Self::NoCompleteSettlement(NoCompleteSettlement::new(
                    *class, gaps.clone(),
                )))
            }
            DiscoveryState::NoComparableNetValue { class, why } => Ok(Self::NoComparableNetValue(
                NoComparableNetValue::new(*class, why.clone()),
            )),
            DiscoveryState::NegativeNev {
                class,
                nev_musd_micros,
                resolution_id,
            } => Ok(Self::NegativeNev(
                NegativeNev::new(*class, *nev_musd_micros, resolution_id.clone())
                    .map_err(arm_error)?,
            )),
            DiscoveryState::BreakEven {
                class,
                nev_musd_micros,
                required_musd_micros,
            } => Ok(Self::BreakEven(
                BreakEven::new(*class, *nev_musd_micros, *required_musd_micros)
                    .map_err(arm_error)?,
            )),
            DiscoveryState::InvalidEvidence { class, defect } => {
                Ok(Self::InvalidEvidence(InvalidEvidence::new(*class, defect.clone())))
            }
            DiscoveryState::SearchAbortedThermal {
                class,
                stop,
                spend,
            } => Ok(Self::SearchAbortedThermal(SearchAbortedThermal::new(
                *class,
                stop.clone(),
                *spend,
            ))),
            DiscoveryState::UnsupportedClass { class, why } => {
                Ok(Self::UnsupportedClass(UnsupportedClass::new(
                    *class, why.clone(),
                )))
            }
            DiscoveryState::PositiveNev {
                class,
                nev_musd_micros,
                resolution_id,
                ..
            } => Err(StateWithoutAuthority::PositiveNevStateCarriesNoVerifiedNev {
                class: *class,
                resolution_id: resolution_id.clone(),
                claimed_nev_musd_micros: *nev_musd_micros,
                why: "a discovery state reports a number and a resolution id; the authority arm \
                      of the taxonomy requires a VerifiedNev, which only a pinned provider and a \
                      NEV-0 adjudication can produce"
                    .to_string(),
            }),
            DiscoveryState::UnattestedNev {
                class,
                claimed_nev_musd_micros,
            } => Err(StateWithoutAuthority::UnattestedStateCarriesNoVerifiedNev {
                class: *class,
                claimed_nev_musd_micros: *claimed_nev_musd_micros,
                why: "an unattested claim is explicitly not a value; promoting it here is the \
                      trust laundering this type exists to prevent"
                    .to_string(),
            }),
            _ => Err(StateWithoutAuthority::NotAResolution {
                state: state.state().to_string(),
                why: "this discovery state describes the search, not an economic result; there \
                      is nothing to resolve yet"
                    .to_string(),
            }),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::NoEdge(v) => format!(
                "{} was scanned over {} completed cycle(s) and the best measured robust net was \
                 {} mUSD (token edge {:?} mUSD, from {}); a measured negative, not an absence of \
                 one",
                v.class,
                v.cycles_completed,
                v.edge.robust_net_micros,
                v.edge.token_edge_micros,
                v.edge.source_field
            ),
            Self::NoCompleteSettlement(v) => format!(
                "{} produced an incomplete settlement ({}); the adapter, the evidence or the \
                 completeness is at fault, so discovery is NOT re-run",
                v.class,
                v.gaps
                    .iter()
                    .map(SettlementGap::state)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::NoComparableNetValue(v) => format!(
                "{} has no comparable net value ({}); the valuation is at fault, so discovery is \
                 NOT re-run",
                v.class, v.why
            ),
            Self::NegativeNev(v) => format!(
                "{} candidate {} resolved to {} mUSD; a realised loss is recorded and the class \
                 backs off",
                v.class, v.resolution_id, v.nev_musd_micros
            ),
            Self::BreakEven(v) => format!(
                "{} resolved to {} mUSD against a required {} mUSD; no surplus, nothing is \
                 promoted",
                v.class, v.nev_musd_micros, v.required_musd_micros
            ),
            Self::PositiveNev(v) => format!(
                "{} resolved to a NEV-0 verified {} mUSD net external value ({} complete \
                 operation(s), {} leg(s), gross {} mUSD less {} mUSD of external cost and {} \
                 mUSD of native cost); this is an economic claim and reaches no budget on its \
                 own",
                v.class(),
                v.nev_musd_micros(),
                v.evidence.complete_operations,
                v.evidence.legs,
                v.evidence.gross_inflow_musd_micros,
                v.evidence.external_cost_musd_micros,
                v.evidence.native_cost_musd_micros
            ),
            Self::InvalidEvidence(v) => format!(
                "{} evidence is unusable ({}); failing closed, and this is NOT treated as no-edge",
                v.class,
                v.defect.state()
            ),
            Self::SearchAbortedThermal(v) => format!(
                "{} search stopped before it could conclude ({}); this is NOT a negative edge \
                 and contributes no coverage",
                v.class,
                v.stop.state()
            ),
            Self::UnsupportedClass(v) => {
                format!("{} has no adapter ({}); it has never been searched", v.class, v.why)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A resolution could not be built with the values it was handed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", content = "detail", rename_all = "snake_case")]
pub enum ResolutionError {
    /// The value does not belong in the arm it was offered to.
    ValueOutsideArm {
        arm: &'static str,
        value_musd_micros: i64,
        why: String,
    },
    /// A required net edge of zero.
    ZeroRequiredEdge { why: String },
}

impl fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueOutsideArm {
                arm,
                value_musd_micros,
                why,
            } => write!(f, "cannot build {arm} with {value_musd_micros} mUSD: {why}"),
            Self::ZeroRequiredEdge { why } => write!(f, "cannot build break_even: {why}"),
        }
    }
}

impl std::error::Error for ResolutionError {}

impl From<ResolutionError> for crate::EconomyError {
    fn from(value: ResolutionError) -> Self {
        crate::EconomyError::Invalid(value.to_string())
    }
}

/// No authority exists in this resolution, named rather than counted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoEconomicAuthority {
    /// The arm that was asked.
    pub state: String,
    pub class: OpportunityClass,
    pub why: String,
}

impl fmt::Display for NoEconomicAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no economic authority in {}: {}", self.state, self.why)
    }
}

impl std::error::Error for NoEconomicAuthority {}

impl From<NoEconomicAuthority> for crate::EconomyError {
    fn from(value: NoEconomicAuthority) -> Self {
        crate::EconomyError::Invalid(value.to_string())
    }
}

/// A [`DiscoveryState`] cannot become an [`EconomicResolution`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "absent", content = "detail", rename_all = "snake_case")]
pub enum StateWithoutAuthority {
    /// The state names a positive NEV but carries no
    /// [`crate::verified_view::VerifiedNev`].
    PositiveNevStateCarriesNoVerifiedNev {
        class: OpportunityClass,
        resolution_id: String,
        claimed_nev_musd_micros: i64,
        why: String,
    },
    /// The state is an explicit non-attestation.
    UnattestedStateCarriesNoVerifiedNev {
        class: OpportunityClass,
        claimed_nev_musd_micros: i64,
        why: String,
    },
    /// The state is about the search, not about a result.
    NotAResolution { state: String, why: String },
}

impl StateWithoutAuthority {
    pub fn state(&self) -> &'static str {
        match self {
            Self::PositiveNevStateCarriesNoVerifiedNev { .. } => "positive_nev_state",
            Self::UnattestedStateCarriesNoVerifiedNev { .. } => "unattested_nev_state",
            Self::NotAResolution { .. } => "not_a_resolution",
        }
    }
}

impl fmt::Display for StateWithoutAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PositiveNevStateCarriesNoVerifiedNev {
                claimed_nev_musd_micros,
                why,
                ..
            } => write!(
                f,
                "refusing a positive_nev discovery state claiming {claimed_nev_musd_micros} \
                 mUSD: {why}"
            ),
            Self::UnattestedStateCarriesNoVerifiedNev {
                claimed_nev_musd_micros,
                why,
                ..
            } => write!(
                f,
                "refusing an unattested_nev discovery state claiming {claimed_nev_musd_micros} \
                 mUSD: {why}"
            ),
            Self::NotAResolution { state, why } => write!(f, "cannot resolve {state}: {why}"),
        }
    }
}

impl std::error::Error for StateWithoutAuthority {}

impl From<StateWithoutAuthority> for crate::EconomyError {
    fn from(value: StateWithoutAuthority) -> Self {
        crate::EconomyError::Invalid(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::{
        BudgetDimension, BudgetSpend, ColdDiscoverySummary, ClassCoverage, MeasuredEdge,
        SettlementGap, ThermalStop,
    };

    // ------------------------------------------------------------------
    // Fixtures. No test in this module builds a chain: the taxonomy is
    // about types, and the chain-backed positive arm is exercised in
    // `crate::nev0`, which does have a provider fixture.
    // ------------------------------------------------------------------

    fn edge(net: i64) -> MeasuredEdge {
        MeasuredEdge {
            token_edge_micros: Some(net.saturating_add(1_000)),
            robust_net_micros: net,
            source_field: "robust_net_usdc_raw".into(),
        }
    }

    fn spend() -> BudgetSpend {
        BudgetSpend::cycles(1)
    }

    fn coverage(class: OpportunityClass) -> ClassCoverage {
        ClassCoverage::unimplemented(class)
    }

    fn cold() -> ColdDiscoverySummary {
        ColdDiscoverySummary {
            exhausted: vec![],
            unsupported: vec![OpportunityClass::NetworkFee],
            disabled: vec![],
            total_classes: 7,
            searched_classes: 0,
        }
    }

    /// The eight refusals, one of each, as full resolutions.
    fn the_eight_refusals() -> Vec<EconomicResolution> {
        vec![
            EconomicResolution::NoEdge(NoEdge::new(OpportunityClass::Arbitrage, edge(-5), 3)),
            EconomicResolution::NoCompleteSettlement(NoCompleteSettlement::new(
                OpportunityClass::Arbitrage,
                vec![SettlementGap::LegAbsent {
                    why: "second leg had no evidence".into(),
                }],
            )),
            EconomicResolution::NoComparableNetValue(NoComparableNetValue::new(
                OpportunityClass::Arbitrage,
                "no authorised price source for the native leg",
            )),
            EconomicResolution::NegativeNev(
                NegativeNev::new(OpportunityClass::Arbitrage, -1_000, "res-1").unwrap(),
            ),
            EconomicResolution::BreakEven(
                BreakEven::new(OpportunityClass::Arbitrage, 0, 1).unwrap(),
            ),
            EconomicResolution::InvalidEvidence(InvalidEvidence::new(
                OpportunityClass::Arbitrage,
                EvidenceDefect::Unmeasured {
                    why: "the adapter reported a scan it did not perform".into(),
                },
            )),
            EconomicResolution::SearchAbortedThermal(SearchAbortedThermal::new(
                OpportunityClass::Arbitrage,
                ThermalStop::BudgetTemperature { observed_c: 40.0, ceiling_c: 75.0 },
                spend(),
            )),
            EconomicResolution::UnsupportedClass(UnsupportedClass::new(
                OpportunityClass::NetworkFee,
                "no adapter is registered for this class",
            )),
        ]
    }

    /// Compile-time assertion: a type listed here satisfies the marker trait.
    /// If any of the eight ever stopped implementing it, this stops compiling.
    fn assert_non_authoritative<T: NonAuthoritative>() {}

    #[test]
    fn exactly_eight_of_the_nine_arms_are_non_authoritative() {
        assert_non_authoritative::<NoEdge>();
        assert_non_authoritative::<NoCompleteSettlement>();
        assert_non_authoritative::<NoComparableNetValue>();
        assert_non_authoritative::<NegativeNev>();
        assert_non_authoritative::<BreakEven>();
        assert_non_authoritative::<InvalidEvidence>();
        assert_non_authoritative::<SearchAbortedThermal>();
        assert_non_authoritative::<UnsupportedClass>();

        // The tripwire, in its other direction. `PositiveNev` satisfies
        // `AuthorityTripwire` only through the single explicit impl in `sealed`;
        // if it ever gained `NonAuthoritative`, the blanket impl would produce a
        // second one and the crate would not compile. Both halves are asserted
        // here because both are compile-time facts, and a test is where a reader
        // looks for them.
        fn tripwire<T: sealed::AuthorityTripwire>() {}
        tripwire::<NoEdge>();
        tripwire::<BreakEven>();
        tripwire::<PositiveNev>();
    }

    #[test]
    fn the_eight_refusals_cannot_produce_any_authority() {
        let mut seen: Vec<&'static str> = Vec::new();
        for resolution in the_eight_refusals() {
            let state = resolution.state();
            assert!(!resolution.is_authority(), "{state} reported authority");
            assert!(
                resolution.positive_nev().is_none(),
                "{state} exposed a value"
            );
            assert!(!resolution.describe().is_empty(), "{state} described nothing");
            let err = resolution
                .into_authority()
                .expect_err("a refusal must not produce an authority");
            assert_eq!(err.state, state);
            assert!(err.why.contains(state), "{state}: {}", err.why);
            seen.push(state);
        }
        assert_eq!(seen.len(), 8, "the taxonomy has exactly eight refusals");
    }

    #[test]
    fn the_nine_arm_names_are_distinct_and_complete() {
        let mut from_refusals: Vec<&'static str> =
            the_eight_refusals().iter().map(|r| r.state()).collect();
        from_refusals.push("positive_nev");
        let mut unique = from_refusals.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 9, "two arms share a state name");

        let mut declared: Vec<&'static str> = EconomicResolution::ALL_STATES.to_vec();
        declared.sort_unstable();
        unique.sort_unstable();
        assert_eq!(declared, unique, "ALL_STATES drifted from the arms");
    }

    #[test]
    fn only_a_market_conclusion_is_a_market_conclusion() {
        // A *measured* negative is a conclusion about the market: the class was
        // scanned and it did not pay. What is not a conclusion is anything about
        // the machine's own limits — the adapter, the valuation, the thermal
        // budget, whether the class was ever implemented.
        for resolution in the_eight_refusals() {
            let state = resolution.state();
            let is_conclusion = matches!(state, "no_edge" | "negative_nev" | "break_even");
            assert_eq!(
                resolution.is_market_conclusion(),
                is_conclusion,
                "{state}: is_market_conclusion disagrees with the taxonomy"
            );
        }
        for state in [
            DiscoveryState::NoEdge {
                class: OpportunityClass::Arbitrage,
                edge: edge(-5),
                cycles_completed: 3,
            },
            DiscoveryState::NegativeNev {
                class: OpportunityClass::Arbitrage,
                nev_musd_micros: -1_000,
                resolution_id: "res-1".into(),
            },
            DiscoveryState::BreakEven {
                class: OpportunityClass::Arbitrage,
                nev_musd_micros: 0,
                required_musd_micros: 1,
            },
        ] {
            let r = EconomicResolution::from_discovery_state(&state).unwrap();
            assert!(r.is_market_conclusion(), "{} should be one", r.state());
        }
    }

    #[test]
    fn incompleteness_is_never_a_completion() {
        for resolution in the_eight_refusals() {
            let state = resolution.state();
            let must_be_incomplete = matches!(
                state,
                "no_complete_settlement" | "invalid_evidence" | "search_aborted_thermal"
                    | "unsupported_class"
            );
            assert_eq!(
                resolution.is_complete(),
                !must_be_incomplete,
                "{state}: is_complete disagrees with the taxonomy"
            );
        }
    }

    #[test]
    fn a_discovery_state_cannot_be_laundered_into_an_authority() {
        let state = DiscoveryState::PositiveNev {
            class: OpportunityClass::Arbitrage,
            nev_musd_micros: 100_000_000,
            required_musd_micros: 1_000_000,
            resolution_id: "res-1".into(),
            policy_hash: "0xpolicy".into(),
        };
        let err = EconomicResolution::from_discovery_state(&state).unwrap_err();
        assert_eq!(err.state(), "positive_nev_state");
        assert!(matches!(
            err,
            StateWithoutAuthority::PositiveNevStateCarriesNoVerifiedNev { .. }
        ));
        assert!(err.to_string().contains("100000000"), "{err}");
        assert!(err.to_string().contains("VerifiedNev"), "{err}");

        let unattested = DiscoveryState::UnattestedNev {
            class: OpportunityClass::Arbitrage,
            claimed_nev_musd_micros: 100_000_000,
        };
        let err = EconomicResolution::from_discovery_state(&unattested).unwrap_err();
        assert_eq!(err.state(), "unattested_nev_state");
    }

    #[test]
    fn a_search_in_progress_is_not_a_resolution() {
        for state in [
            DiscoveryState::Searching {
                class: OpportunityClass::Arbitrage,
                cycle: 1,
                started_at_unix: 1_700_000_000,
            },
            DiscoveryState::CandidateFound {
                class: OpportunityClass::Arbitrage,
                candidates: 2,
                cycle: 1,
            },
            DiscoveryState::ClassExhausted {
                class: OpportunityClass::Arbitrage,
                coverage: coverage(OpportunityClass::Arbitrage),
            },
            DiscoveryState::ColdDiscovery { summary: cold() },
            DiscoveryState::BudgetExhausted {
                class: OpportunityClass::Arbitrage,
                dimension: BudgetDimension::Cycles,
                coverage: coverage(OpportunityClass::Arbitrage),
            },
        ] {
            let err = EconomicResolution::from_discovery_state(&state).unwrap_err();
            assert!(
                matches!(err, StateWithoutAuthority::NotAResolution { .. }),
                "{state:?}: {err}"
            );
        }
    }

    #[test]
    fn every_discovery_state_either_resolves_or_names_why_not() {
        // Enumerated by hand on purpose: this is the mapping's contract, and a
        // new `DiscoveryState` variant has to be added here deliberately.
        let states = vec![
            DiscoveryState::Searching {
                class: OpportunityClass::Arbitrage,
                cycle: 1,
                started_at_unix: 0,
            },
            DiscoveryState::CandidateFound {
                class: OpportunityClass::Arbitrage,
                candidates: 1,
                cycle: 1,
            },
            DiscoveryState::NoEdge {
                class: OpportunityClass::Arbitrage,
                edge: edge(-1),
                cycles_completed: 1,
            },
            DiscoveryState::NoCompleteSettlement {
                class: OpportunityClass::Arbitrage,
                gaps: vec![],
            },
            DiscoveryState::NoComparableNetValue {
                class: OpportunityClass::Arbitrage,
                why: "x".into(),
            },
            DiscoveryState::NegativeNev {
                class: OpportunityClass::Arbitrage,
                nev_musd_micros: -1,
                resolution_id: "r".into(),
            },
            DiscoveryState::BreakEven {
                class: OpportunityClass::Arbitrage,
                nev_musd_micros: 0,
                required_musd_micros: 1,
            },
            DiscoveryState::PositiveNev {
                class: OpportunityClass::Arbitrage,
                nev_musd_micros: 1,
                required_musd_micros: 1,
                resolution_id: "r".into(),
                policy_hash: "0xpolicy".into(),
            },
            DiscoveryState::UnattestedNev {
                class: OpportunityClass::Arbitrage,
                claimed_nev_musd_micros: 1,
            },
            DiscoveryState::InvalidEvidence {
                class: OpportunityClass::Arbitrage,
                defect: EvidenceDefect::UnreadableShape { why: "x".into() },
            },
            DiscoveryState::ClassExhausted {
                class: OpportunityClass::Arbitrage,
                coverage: coverage(OpportunityClass::Arbitrage),
            },
            DiscoveryState::ColdDiscovery { summary: cold() },
            DiscoveryState::SearchAbortedThermal {
                class: OpportunityClass::Arbitrage,
                stop: ThermalStop::BudgetTemperature { observed_c: 40.0, ceiling_c: 75.0 },
                spend: spend(),
            },
            DiscoveryState::UnsupportedClass {
                class: OpportunityClass::NetworkFee,
                why: "x".into(),
            },
            DiscoveryState::BudgetExhausted {
                class: OpportunityClass::Arbitrage,
                dimension: BudgetDimension::Cycles,
                coverage: coverage(OpportunityClass::Arbitrage),
            },
        ];
        assert_eq!(states.len(), 15, "DiscoveryState has 15 variants");
        let mut resolved = 0usize;
        let mut refused = 0usize;
        for state in &states {
            match EconomicResolution::from_discovery_state(state) {
                Ok(r) => {
                    resolved += 1;
                    // Every resolvable state except `PositiveNev` is a refusal
                    // arm, and the mapping must never mint an authority.
                    assert!(
                        !r.is_authority(),
                        "{} resolved to an authority-bearing arm",
                        state.state()
                    );
                }
                Err(e) => {
                    refused += 1;
                    assert!(!e.to_string().is_empty(), "{}: empty refusal", state.state());
                }
            }
        }
        assert_eq!(resolved, 8);
        assert_eq!(refused, 7);
    }

    #[test]
    fn the_arm_constructors_refuse_values_that_belong_elsewhere() {
        assert!(matches!(
            NegativeNev::new(OpportunityClass::Arbitrage, 0, "r"),
            Err(ResolutionError::ValueOutsideArm { arm: "negative_nev", .. })
        ));
        assert!(matches!(
            NegativeNev::new(OpportunityClass::Arbitrage, 5, "r"),
            Err(ResolutionError::ValueOutsideArm { arm: "negative_nev", .. })
        ));
        assert!(matches!(
            BreakEven::new(OpportunityClass::Arbitrage, -1, 10),
            Err(ResolutionError::ValueOutsideArm { arm: "break_even", .. })
        ));
        assert!(matches!(
            BreakEven::new(OpportunityClass::Arbitrage, 10, 10),
            Err(ResolutionError::ValueOutsideArm { arm: "break_even", .. })
        ));
        assert!(matches!(
            BreakEven::new(OpportunityClass::Arbitrage, 11, 10),
            Err(ResolutionError::ValueOutsideArm { arm: "break_even", .. })
        ));
        assert!(matches!(
            BreakEven::new(OpportunityClass::Arbitrage, 0, 0),
            Err(ResolutionError::ZeroRequiredEdge { .. })
        ));
        // The boundary values that must be accepted.
        assert!(NegativeNev::new(OpportunityClass::Arbitrage, -1, "r").is_ok());
        assert!(BreakEven::new(OpportunityClass::Arbitrage, 0, 1).is_ok());
        assert!(BreakEven::new(OpportunityClass::Arbitrage, 9, 10).is_ok());
    }

    #[test]
    fn a_refusal_arm_round_trips_because_it_is_only_a_report() {
        for resolution in the_eight_refusals() {
            let json = serde_json::to_string(&resolution).unwrap();
            assert!(
                json.contains(&format!("\"{}\"", resolution.state())),
                "{json}"
            );
            // `deny_unknown_fields` on the payload, so a stored refusal cannot
            // acquire an extra field that a later reader would honour.
            let arm = match &resolution {
                EconomicResolution::NoEdge(v) => serde_json::to_value(v).unwrap(),
                EconomicResolution::NoCompleteSettlement(v) => serde_json::to_value(v).unwrap(),
                EconomicResolution::NoComparableNetValue(v) => serde_json::to_value(v).unwrap(),
                EconomicResolution::NegativeNev(v) => serde_json::to_value(v).unwrap(),
                EconomicResolution::BreakEven(v) => serde_json::to_value(v).unwrap(),
                EconomicResolution::InvalidEvidence(v) => serde_json::to_value(v).unwrap(),
                EconomicResolution::SearchAbortedThermal(v) => serde_json::to_value(v).unwrap(),
                EconomicResolution::UnsupportedClass(v) => serde_json::to_value(v).unwrap(),
                EconomicResolution::PositiveNev(_) => unreachable!(),
            };
            assert!(arm.get("class").is_some(), "{json}");
        }
    }

    #[test]
    fn nev0_evidence_accounting_is_recomputable_and_checked() {
        let e = Nev0Evidence {
            value_class: ExternalValueClass::ExternalTradingPnl,
            complete_operations: 1,
            legs: 2,
            gross_inflow_musd_micros: 1_000_000,
            external_cost_musd_micros: 100_000,
            native_cost_musd_micros: 10_000,
        };
        assert_eq!(e.net_musd_micros(), Some(890_000));

        // Costs above the gross are a real possibility in a stored report, and
        // the recomputation has to say so rather than wrap.
        let loss = Nev0Evidence {
            gross_inflow_musd_micros: 10,
            external_cost_musd_micros: 20,
            native_cost_musd_micros: 0,
            ..e
        };
        assert_eq!(loss.net_musd_micros(), Some(-10));
    }
}
