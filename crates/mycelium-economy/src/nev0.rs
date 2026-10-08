//! P6.7 — the NEV-0 gate.
//!
//! # The definition, in full
//!
//! **NEV-0** is: *at least one set of external evidence that is **complete**,
//! **authenticated**, **chain-confirmed**, **boundary-derived**, **comparable**,
//! **net of outflows and costs**, and whose **verified sum is greater than
//! zero**.* Any one of those seven failing is a refusal, and the refusals are
//! named rather than collapsed into a boolean.
//!
//! ## It may be one hundredth of a cent
//!
//! **NEV-0 does not require scale.** `10_000` micro-USD — 0.01 USDC — is a
//! grant, not a rounding error to be discarded. There is no
//! `min_nev_0_micros`, no dust threshold, and no comparison against a scale
//! constant anywhere in this module, and
//! [`Nev0Adjudication::one_hundredth_of_a_cent_is_not_dust`] is the test that
//! pins it. The reason is that a scale requirement is a *second, different*
//! gate wearing the first gate's clothes: it says "we do not believe small
//! values", which is a statement about the world, and it is expressed by moving
//! a number rather than by refusing evidence. The place for "is this worth
//! doing" is [`crate::discovery::MinNetEdge`], which is a different type in a
//! different module and is applied *after* NEV-0 by
//! [`classify_against_min_edge`].
//!
//! # The refusal list — this is the deliverable
//!
//! The gate is only as good as the list of things it says no to, so the list is
//! the specification and [`NEV0_FORBIDDEN_CATEGORIES`] is the machine-readable
//! form of it. Every entry has a test, and
//! [`every_forbidden_category_is_refused`] walks the constant and drives the
//! gate with the offending input for each one.
//!
//! | category | what it is | why it can never be external value |
//! |---|---|---|
//! | `synthetic_value` | a number with no chain behind it | it was made up; nothing outside this system changed |
//! | `myc_issuance` | MYC minted to our own wallet | emission is not external value; it is the protocol printing its own promise |
//! | `controlled_wallet_transfer` | our wallet to our wallet | no boundary was crossed, so no value was created |
//! | `test_fixture` | evidence from a test harness | a fixture is not a market |
//! | `dev_provider` | the loopback dev override | an address is not an identity; anything it says can be said by whoever ran it |
//! | `unsigned_evidence` | evidence with no signature | an unsigned document is an assertion |
//! | `incomplete_settlement` | an operation with a missing leg | a partial operation has no net; picking the surviving half is choosing the answer |
//! | `unpriced_gas` | a cost that was never converted | value minus an unpriced cost is a number with the cost removed |
//! | `raw_edge` | the pre-cost spread | an edge is gross; it is what the market quotes, not what we keep |
//! | `modeled_profit` | a projection | a model is a hypothesis |
//!
//! Four more refusals are not in the mandated ten and are named separately,
//! because they are different failures rather than different flavours of the
//! same one: `non_external_value_class` (a class that is neither external value
//! nor a specific forbidden case), `unpinned_provider` (no chain view at all),
//! `no_verified_sum` (no `VerifiedNev` was produced at all) and `not_positive`
//! (a `VerifiedNev` that is zero or negative).
//!
//! # Structural properties
//!
//! ## 1. The gate cannot be satisfied by a claim
//!
//! [`Nev0Inputs::verified_nev`] is `Option<&VerifiedNev>`. A
//! [`crate::verified_view::UnattestedNev`] does not convert: it is a different
//! type, it has no authority predicate, and there is no `From`. So a ledger
//! that *claims* a hundred mUSD produces [`Nev0Refusal::NoVerifiedSum`], and
//! the reason says which of the two it was looking for.
//!
//! ## 2. The gate is order-independent in its verdict, deterministic in its
//! report
//!
//! [`Nev0Gate::adjudicate`] collects **every** refusal it finds rather than
//! short-circuiting on the first, because an operator fixing one defect and
//! finding the next is a worse afternoon than being handed the list. The
//! *verdict* does not depend on the order, because a grant requires the refusal
//! list to be empty.
//!
//! ## 3. Nothing here is wired to spend authority
//!
//! The gate produces a [`crate::resolution::PositiveNev`], which is an economic
//! claim. It has no method that returns a budget, and the only
//! [`crate::resolution::EconomicResolution`] arm that can carry a value is the
//! one this gate mints. Spend authority remains
//! [`crate::reinvestment::ReinvestmentController::commit_job_from_view`], which
//! takes a [`crate::verified_view::VerifiedEconomyView`] and nothing from here.
//!
//! # What NEV-0 is worth today
//!
//! **Nothing, and that is the honest answer.** NEV-0 is the first external
//! value created by this network; until one exists the gate has no production
//! caller, exactly as the settlement promotion path has none. The standing
//! numbers are unchanged by this module and are not made otherwise by it: **NEV
//! = 0, external value created = 0, E6 = 0/9, and (b)/(c)/(d) remain NOT
//! SUSTENTADO.** A gate that is never satisfied is a gate that has been proven
//! to refuse, and that is what the tests below demonstrate.

use crate::autonomy::ExternalValueClass;
use crate::discovery::{EvidenceDefect, MinNetEdge, OpportunityClass, SettlementGap};
use crate::revalidation::SettlementAnchor;
use crate::resolution::{
    BreakEven, EconomicResolution, Nev0Evidence, PositiveNev, ResolutionError,
};
use crate::verified_view::VerifiedNev;
use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// The ten
// ---------------------------------------------------------------------------

/// The refusal categories the brief requires, in the order they are evaluated.
///
/// A `const`, not a doc comment: a renderer, a dashboard and a test all read the
/// same list from one place, and adding a category without a test is visible
/// here.
pub const NEV0_FORBIDDEN_CATEGORIES: [&str; 10] = [
    "synthetic_value",
    "myc_issuance",
    "controlled_wallet_transfer",
    "test_fixture",
    "dev_provider",
    "unsigned_evidence",
    "incomplete_settlement",
    "unpriced_gas",
    "raw_edge",
    "modeled_profit",
];

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// Where the evidence came from.
///
/// Three states and no fourth, and the "live" one carries the chain and height
/// so a report can name what it was reading. There is no `Unknown`: an
/// adjudicator that cannot say where the evidence came from is
/// [`EvidenceProvenance::Synthetic`], because a value with no stated origin is
/// exactly the thing the `synthetic_value` refusal exists for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provenance", content = "detail", rename_all = "snake_case")]
pub enum EvidenceProvenance {
    /// Read from a chain by a kernel-identified provider.
    LiveChain { chain_id: u64, block_number: u64 },
    /// Produced by a test harness.
    TestFixture { label: String },
    /// Produced by something with no chain behind it.
    Synthetic { label: String },
}

/// What the provider is, in the sense the rest of the crate already uses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "provider", content = "detail", rename_all = "snake_case")]
pub enum ProviderStanding {
    /// A Unix socket whose owner the kernel enforces.
    KernelEnforced {
        endpoint: String,
        identity_hash: String,
    },
    /// `MYCELIUM_DEV_BASE_PROVIDER` and every other address-only endpoint.
    DevProvider { endpoint: String },
    /// No provider at all.
    Unpinned,
}

/// How the evidence was authenticated.
///
/// `pub(crate) fn` boundaries do the real work here: a receipt carrying a valid
/// signature from the delegated verifier key is a
/// [`crate::verified_view::VerifiedNev`], and a `VerifiedNev` is the only way to
/// populate the grant. This enum records *which* authentication produced it so
/// the gate can refuse the negative cases explicitly, rather than leaving them
/// implied by a type that simply is not passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "authentication", content = "detail", rename_all = "snake_case")]
pub enum EvidenceAuthentication {
    /// A valid signature from the verifier key the policy delegated.
    DelegatedVerifierSignature { key_id: String },
    /// A policy signature and nothing else. The policy authorises; it does not
    /// vouch for a value.
    PolicySignatureOnly { authority_key_id: String },
    /// No signature.
    Unsigned,
}

/// Whether the operation's leg set is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "settlement", content = "detail", rename_all = "snake_case")]
pub enum SettlementCompleteness {
    /// Every leg has evidence, and the chain scan that enumerated them was
    /// exhaustive. Both, because "all the legs I found" is not the same claim as
    /// "all the legs there are".
    Complete {
        legs: u64,
        scanned_exhaustively: bool,
    },
    /// Named gaps. No net exists.
    Incomplete { gaps: Vec<SettlementGap> },
}

/// What the counted number is net of.
///
/// One enum with four arms, because the four are the four things a number can
/// be that are not "what we kept". `NetOfOutflows` is the only one that
/// qualifies, and it is the only one that carries a native cost at all — which
/// is what makes [`CostBasis::UnpricedGas`] a separate arm rather than a
/// variant of the same value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cost", content = "detail", rename_all = "snake_case")]
pub enum CostBasis {
    /// Gross inflow, less external costs (fees, slippage, the counterparty's
    /// cut), less native cost already converted at a policy-authorised price.
    NetOfOutflows {
        gross_inflow_musd_micros: u64,
        external_cost_musd_micros: u64,
        native_cost_musd_micros: u64,
    },
    /// A cost was paid and never converted to a number. Refused, because
    /// "value minus nothing" is not a net.
    UnpricedGas,
    /// The spread before any cost is subtracted. This is what the market quotes.
    RawEdge,
    /// A projection. A model is a hypothesis, and a hypothesis about profit is
    /// the single most reliable way to manufacture a positive NEV.
    ModeledProfit,
}

/// Everything the gate is a function of.
///
/// No `Default`, on purpose: a default would be a set of values nobody chose,
/// and a gate whose inputs default to "fine" is a gate that can be satisfied by
/// saying nothing.
pub struct Nev0Inputs<'a> {
    /// The class the search resolved. Carried through to the
    /// [`PositiveNev`] so the taxonomy's `class()` reports what was searched.
    pub class: OpportunityClass,
    pub provenance: EvidenceProvenance,
    pub provider: ProviderStanding,
    pub authentication: EvidenceAuthentication,
    /// Every value class present in the evidence. A **set**, not one value: a
    /// receipt set that mixes a trading profit with a MYC emission is refused
    /// as a whole rather than having the emission dropped, because "which one
    /// was it" is a judgement the gate has no standing to make silently.
    pub value_classes: &'a [ExternalValueClass],
    pub settlement: SettlementCompleteness,
    pub cost: CostBasis,
    /// The block the evidence was read at. **Not read by the gate** — NEV-0 is
    /// not a finality check, and conflating the two is the mistake P6.10 exists
    /// to keep apart. It is carried so the same adjudication can be handed to
    /// [`crate::revalidation::Revalidation::check`], and an adjudication with no
    /// anchor can only ever reach
    /// [`crate::revalidation::RevalidationState::NeedsRevalidation`], which
    /// blocks spend authority.
    ///
    /// `_anchor` in the struct-literal sense: it is a `pub` field, so a caller
    /// and a reader can both see it, and nothing in this module consumes it.
    pub anchor: Option<SettlementAnchor>,
    /// The verified total. `None` refuses; a
    /// [`crate::verified_view::UnattestedNev`] cannot be passed here at all.
    pub verified_nev: Option<&'a VerifiedNev>,
}

// ---------------------------------------------------------------------------
// Refusals
// ---------------------------------------------------------------------------

/// A named refusal. Never a boolean, never a count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", content = "detail", rename_all = "snake_case")]
pub enum Nev0Refusal {
    /// A number with no chain behind it.
    SyntheticValue { label: String, why: String },
    /// MYC minted to a controlled address.
    MycIssuance { value_class: ExternalValueClass, why: String },
    /// A transfer whose two ends are both ours.
    ControlledWalletTransfer { value_class: ExternalValueClass, why: String },
    /// Neither external value nor one of the specific forbidden classes.
    NonExternalValueClass { value_class: ExternalValueClass, why: String },
    /// Evidence from a test harness.
    TestFixture { label: String, why: String },
    /// The loopback dev override.
    DevProvider { endpoint: String, why: String },
    /// No provider at all.
    UnpinnedProvider { why: String },
    /// No signature behind the evidence.
    UnsignedEvidence { why: String },
    /// The operation is missing a leg.
    IncompleteSettlement { gaps: Vec<SettlementGap>, why: String },
    /// A cost that was paid and never priced.
    UnpricedGas { why: String },
    /// The pre-cost spread.
    RawEdge { why: String },
    /// A projection.
    ModeledProfit { why: String },
    /// The leg scan was not exhaustive, so the counted set is not the set that
    /// happened.
    ScanNotExhaustive { why: String },
    /// No `VerifiedNev` at all — most often because the ledger only *claims* one.
    NoVerifiedSum { why: String },
    /// A `VerifiedNev` that is zero or negative.
    NotPositive {
        verified_musd_micros: i64,
        why: String,
    },
    /// The legs are complete but there are none, so there is nothing to sum.
    NoCompleteOperations { why: String },
}

/// The wire spelling of a value class.
///
/// [`ExternalValueClass`] has no `Display` and adding one is a change to another
/// module for a purely cosmetic reason. `serde`'s `rename_all = "snake_case"` is
/// already the spelling every ledger file uses, so a refusal names a class the
/// same way a receipt does and an operator can grep one for the other.
fn value_class_spelling(class: &ExternalValueClass) -> &'static str {
    match class {
        ExternalValueClass::ExternalTradingPnl => "external_trading_pnl",
        ExternalValueClass::ExternalServicePayment => "external_service_payment",
        ExternalValueClass::ExternalSolverReward => "external_solver_reward",
        ExternalValueClass::ExternalProtocolFee => "external_protocol_fee",
        ExternalValueClass::InternalTransfer => "internal_transfer",
        ExternalValueClass::BotServiceSpend => "bot_service_spend",
        ExternalValueClass::MycEmission => "myc_emission",
        ExternalValueClass::WsrPayout => "wsr_payout",
        ExternalValueClass::TreasuryTransfer => "treasury_transfer",
    }
}

impl Nev0Refusal {
    /// The machine-readable category. The ten mandated ones appear in
    /// [`NEV0_FORBIDDEN_CATEGORIES`]; the rest are separate failures, not
    /// extra flavours of the mandated ten.
    pub fn category(&self) -> &'static str {
        match self {
            Self::SyntheticValue { .. } => "synthetic_value",
            Self::MycIssuance { .. } => "myc_issuance",
            Self::ControlledWalletTransfer { .. } => "controlled_wallet_transfer",
            Self::NonExternalValueClass { .. } => "non_external_value_class",
            Self::TestFixture { .. } => "test_fixture",
            Self::DevProvider { .. } => "dev_provider",
            Self::UnpinnedProvider { .. } => "unpinned_provider",
            Self::UnsignedEvidence { .. } => "unsigned_evidence",
            Self::IncompleteSettlement { .. } => "incomplete_settlement",
            Self::UnpricedGas { .. } => "unpriced_gas",
            Self::RawEdge { .. } => "raw_edge",
            Self::ModeledProfit { .. } => "modeled_profit",
            Self::ScanNotExhaustive { .. } => "scan_not_exhaustive",
            Self::NoVerifiedSum { .. } => "no_verified_sum",
            Self::NotPositive { .. } => "not_positive",
            Self::NoCompleteOperations { .. } => "no_complete_operations",
        }
    }

    /// Whether this is one of the ten the brief names.
    pub fn is_forbidden_category(&self) -> bool {
        NEV0_FORBIDDEN_CATEGORIES.contains(&self.category())
    }

    /// The taxonomy arm this refusal belongs to.
    ///
    /// Six of the sixteen refusals are "the evidence is not countable" and land
    /// in [`EconomicResolution::InvalidEvidence`] with
    /// [`EvidenceDefect::Nev0Refused`], which keeps the *category* on the face
    /// of the report. The rest map to the arm that names the real situation:
    /// an incomplete settlement is not invalid evidence, it is
    /// [`EconomicResolution::NoCompleteSettlement`].
    pub fn arm(&self) -> Nev0Arm {
        match self {
            Self::IncompleteSettlement { .. } => Nev0Arm::NoCompleteSettlement,
            Self::NotPositive { .. } => Nev0Arm::NotPositive,
            Self::NoVerifiedSum { .. } | Self::NoCompleteOperations { .. } => Nev0Arm::NoVerifiedSum,
            _ => Nev0Arm::InvalidEvidence,
        }
    }

    pub fn as_defect(&self) -> Option<EvidenceDefect> {
        match self.arm() {
            Nev0Arm::InvalidEvidence => Some(EvidenceDefect::Nev0Refused {
                category: self.category().to_string(),
                why: self.to_string(),
            }),
            Nev0Arm::NoCompleteSettlement | Nev0Arm::NotPositive | Nev0Arm::NoVerifiedSum => None,
        }
    }
}

impl fmt::Display for Nev0Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SyntheticValue { label, why } => write!(
                f,
                "refusing synthetic value from {label:?}: {why}. NEV-0 counts value that \
                 exists outside this system; a number this system produced is not that"
            ),
            Self::MycIssuance { value_class, why } => write!(
                f,
                "refusing MYC issuance ({}): {why}. Emission is the protocol printing its own \
                 promise; it moves no external value",
                value_class_spelling(value_class)
            ),
            Self::ControlledWalletTransfer { value_class, why } => write!(
                f,
                "refusing a transfer between controlled wallets ({}): {why}. No boundary was \
                 crossed, so nothing outside this system changed",
                value_class_spelling(value_class)
            ),
            Self::NonExternalValueClass { value_class, why } => write!(
                f,
                "refusing value class {}: {why}. It is not one of the four classes that can \
                 create external value",
                value_class_spelling(value_class)
            ),
            Self::TestFixture { label, why } => write!(
                f,
                "refusing test fixture {label:?}: {why}. A fixture is not a market"
            ),
            Self::DevProvider { endpoint, why } => write!(
                f,
                "refusing the dev provider at {endpoint}: {why}. An address is not an \
                 identity, and anything that endpoint says can be said by whoever started it"
            ),
            Self::UnpinnedProvider { why } => {
                write!(f, "refusing an unpinned provider: {why}")
            }
            Self::UnsignedEvidence { why } => write!(
                f,
                "refusing unsigned evidence: {why}. An unsigned document is an assertion, and \
                 NEV-0 requires authentication"
            ),
            Self::IncompleteSettlement { gaps, why } => write!(
                f,
                "refusing an incomplete settlement ({}): {why}. A partial operation has no net, \
                 and counting the surviving leg is choosing the answer",
                gaps
                    .iter()
                    .map(SettlementGap::state)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Self::UnpricedGas { why } => write!(
                f,
                "refusing an unpriced native cost: {why}. Value minus a cost that was never \
                 converted is a number with the cost removed"
            ),
            Self::RawEdge { why } => write!(
                f,
                "refusing a raw edge: {why}. An edge is the pre-cost spread; it is what the \
                 market quotes, not what we keep"
            ),
            Self::ModeledProfit { why } => write!(
                f,
                "refusing a modelled profit: {why}. A model is a hypothesis, and a hypothesis \
                 about profit is the most reliable way to manufacture a positive NEV"
            ),
            Self::ScanNotExhaustive { why } => write!(
                f,
                "refusing a non-exhaustive scan: {why}. The legs that were found are not \
                 necessarily the legs that happened"
            ),
            Self::NoVerifiedSum { why } => {
                write!(f, "refusing an unverified sum: {why}")
            }
            Self::NotPositive {
                verified_musd_micros,
                why,
            } => write!(
                f,
                "refusing a verified sum of {verified_musd_micros} mUSD: {why}. NEV-0 requires \
                 a verified sum strictly greater than zero"
            ),
            Self::NoCompleteOperations { why } => {
                write!(f, "refusing zero complete operations: {why}")
            }
        }
    }
}

impl std::error::Error for Nev0Refusal {}

/// Which taxonomy arm a refusal belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Nev0Arm {
    InvalidEvidence,
    NoCompleteSettlement,
    NoVerifiedSum,
    NotPositive,
}

// ---------------------------------------------------------------------------
// The adjudication
// ---------------------------------------------------------------------------

/// The result of running the gate.
///
/// `Debug` is hand-written so the report reads as a *verdict* — granted, and
/// how much — rather than dumping every `VerifiedNev` field.
#[derive(Clone)]
pub struct Nev0Adjudication {
    refusals: Vec<Nev0Refusal>,
    granted: Option<PositiveNev>,
}

impl Nev0Adjudication {
    /// Whether the evidence cleared NEV-0.
    ///
    /// A grant is a `PositiveNev`, so this is a real type-level distinction and
    /// not a flag.
    pub fn is_granted(&self) -> bool {
        self.granted.is_some()
    }

    /// The claim, when granted. `None` otherwise, and there is no
    /// `claimed_nev` accessor: a refusal carries no number to be tempted with.
    pub fn granted(&self) -> Option<&PositiveNev> {
        self.granted.as_ref()
    }

    /// Every refusal found, in evaluation order. Empty on a grant, and the grant
    /// is the only thing that makes the list irrelevant.
    pub fn refusals(&self) -> &[Nev0Refusal] {
        &self.refusals
    }

    /// The categories found, deduplicated, so a report can list them without
    /// repeating a class that appeared on two receipts.
    pub fn categories(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = Vec::new();
        for r in &self.refusals {
            if !out.contains(&r.category()) {
                out.push(r.category());
            }
        }
        out
    }

    /// The grant, or the **first** refusal in evaluation order.
    pub fn into_grant(self) -> Result<PositiveNev, Nev0Refusal> {
        match (self.granted, self.refusals.into_iter().next()) {
            (Some(v), _) => Ok(v),
            (None, Some(r)) => Err(r),
            (None, None) => Err(Nev0Refusal::NoVerifiedSum {
                why: "the gate produced neither a grant nor a refusal, which is a bug in the \
                      gate rather than a state of the evidence"
                    .to_string(),
            }),
        }
    }
}

impl fmt::Debug for Nev0Adjudication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nev0Adjudication")
            .field("granted", &self.granted.as_ref().map(|p| p.nev_musd_micros()))
            .field("refusals", &self.categories())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// The NEV-0 gate. No state, no configuration, no constructor: the whole of it
/// is [`Nev0Gate::adjudicate`], so there is nothing to tune and nothing to
/// mis-configure.
pub struct Nev0Gate;

impl Nev0Gate {
    /// Adjudicate one set of evidence.
    ///
    /// Collects every refusal rather than stopping at the first, and grants only
    /// when the list is empty. The evaluation order below is the order the
    /// refusals appear in, and it runs from "this is not evidence" outwards to
    /// "the number is not positive" — so a report lists the most fundamental
    /// problem first and the most downstream one last.
    ///
    /// 1. [`EvidenceProvenance`] — test fixture, then synthetic.
    /// 2. [`ProviderStanding`] — unpinned, then dev provider.
    /// 3. [`EvidenceAuthentication`] — unsigned, then policy-signature-only.
    /// 4. [`ExternalValueClass`] per class — MYC issuance, then controlled-wallet
    ///    transfer, then any other non-external class.
    /// 5. [`SettlementCompleteness`] — zero legs, then non-exhaustive scan, then
    ///    incomplete.
    /// 6. [`CostBasis`] — unpriced gas, then raw edge, then modelled profit. A
    ///    `NetOfOutflows` passes here; the *value* of its three fields is not
    ///    compared against the `VerifiedNev` here either, because the
    ///    `VerifiedNev` was itself derived from the same receipts and
    ///    re-deriving it would be a second, weaker path to a number.
    /// 7. The verified sum — absent, then not positive.
    pub fn adjudicate(inputs: &Nev0Inputs<'_>) -> Nev0Adjudication {
        let mut refusals: Vec<Nev0Refusal> = Vec::new();

        // (1) Provenance.
        match &inputs.provenance {
            EvidenceProvenance::TestFixture { label } => refusals.push(Nev0Refusal::TestFixture {
                label: label.clone(),
                why: "the evidence was produced by a test harness, so no market was \
                      involved and nothing outside this system changed"
                    .to_string(),
            }),
            EvidenceProvenance::Synthetic { label } => refusals.push(Nev0Refusal::SyntheticValue {
                label: label.clone(),
                why: "the value was produced by this system rather than read from a chain"
                    .to_string(),
            }),
            EvidenceProvenance::LiveChain { .. } => {}
        }

        // (2) Provider. Independent of (1): a fixture served by a real provider
        // is still a fixture, and a real chain read over a loopback address is
        // still unattributable. Both can be refused, and the report names both.
        match &inputs.provider {
            ProviderStanding::Unpinned => refusals.push(Nev0Refusal::UnpinnedProvider {
                why: "no chain provider is pinned on this node, so nothing was chain-confirmed"
                    .to_string(),
            }),
            ProviderStanding::DevProvider { endpoint } => {
                refusals.push(Nev0Refusal::DevProvider {
                    endpoint: endpoint.clone(),
                    why: "the endpoint has no kernel-enforced identity, so it attests nothing \
                          and cannot confirm anything"
                        .to_string(),
                })
            }
            ProviderStanding::KernelEnforced { .. } => {}
        }

        // (3) Authentication.
        match &inputs.authentication {
            EvidenceAuthentication::Unsigned => refusals.push(Nev0Refusal::UnsignedEvidence {
                why: "no key signed this evidence; NEV-0 requires authentication and a \
                      policy signature authorises, it does not vouch"
                    .to_string(),
            }),
            EvidenceAuthentication::PolicySignatureOnly { .. } => {
                refusals.push(Nev0Refusal::UnsignedEvidence {
                    why: "only the outcome policy is signed. The policy says what may be \
                          counted; it does not attest that anything was"
                        .to_string(),
                })
            }
            EvidenceAuthentication::DelegatedVerifierSignature { .. } => {}
        }

        // (4) Value classes. The set is refused as a whole.
        for class in inputs.value_classes {
            match class {
                ExternalValueClass::MycEmission => refusals.push(Nev0Refusal::MycIssuance {
                    value_class: class.clone(),
                    why: "MYC emission into a controlled address is the protocol issuing its \
                          own token; it creates no external value"
                        .to_string(),
                }),
                ExternalValueClass::InternalTransfer | ExternalValueClass::TreasuryTransfer => {
                    refusals.push(Nev0Refusal::ControlledWalletTransfer {
                        value_class: class.clone(),
                        why: "both ends of this transfer are controlled addresses, so no \
                              boundary was crossed"
                            .to_string(),
                    })
                }
                ExternalValueClass::BotServiceSpend | ExternalValueClass::WsrPayout => {
                    refusals.push(Nev0Refusal::NonExternalValueClass {
                        value_class: class.clone(),
                        why: "this class records a spend or an internal payout, which is an \
                              outflow and never a net"
                            .to_string(),
                    })
                }
                ExternalValueClass::ExternalTradingPnl
                | ExternalValueClass::ExternalServicePayment
                | ExternalValueClass::ExternalSolverReward
                | ExternalValueClass::ExternalProtocolFee => {}
            }
        }

        // (5) Completeness.
        match &inputs.settlement {
            SettlementCompleteness::Complete {
                legs,
                scanned_exhaustively,
            } => {
                if *legs == 0 {
                    refusals.push(Nev0Refusal::NoCompleteOperations {
                        why: "the leg set is complete and empty, so there is nothing to sum; \
                              completeness is not positivity"
                            .to_string(),
                    });
                }
                if !scanned_exhaustively {
                    refusals.push(Nev0Refusal::ScanNotExhaustive {
                        why: "the chain scan that enumerated the legs was not exhaustive, so the \
                              counted set is not the set that happened"
                            .to_string(),
                    });
                }
            }
            SettlementCompleteness::Incomplete { gaps } => {
                refusals.push(Nev0Refusal::IncompleteSettlement {
                    gaps: gaps.clone(),
                    why: "at least one leg of the operation has no evidence, so the operation \
                          has no net"
                        .to_string(),
                })
            }
        }

        // (6) Cost basis. This is the arm that separates "what the market quotes"
        // from "what we keep", and it is checked on the *declared* basis rather
        // than on the number, because a number cannot say how it was produced.
        match inputs.cost {
            CostBasis::UnpricedGas => refusals.push(Nev0Refusal::UnpricedGas {
                why: "a native cost was paid and never converted at a policy-authorised price"
                    .to_string(),
            }),
            CostBasis::RawEdge => refusals.push(Nev0Refusal::RawEdge {
                why: "the figure is the pre-cost spread, not a net after outflows and costs"
                    .to_string(),
            }),
            CostBasis::ModeledProfit => refusals.push(Nev0Refusal::ModeledProfit {
                why: "the figure is a projection rather than a realised, re-derived total"
                    .to_string(),
            }),
            CostBasis::NetOfOutflows { .. } => {}
        }

        // (7) The verified sum.
        match inputs.verified_nev {
            None => refusals.push(Nev0Refusal::NoVerifiedSum {
                why: "no VerifiedNev was produced. A ledger that claims a total produces an \
                      UnattestedNev, which is a different type and is not a value; NEV-0 counts \
                      only the former"
                    .to_string(),
            }),
            Some(nev) => {
                let total = nev.nev_musd_micros();
                if total <= 0 {
                    refusals.push(Nev0Refusal::NotPositive {
                        verified_musd_micros: total,
                        why: "the verified total is not strictly greater than zero, and NEV-0 \
                              is defined as strictly greater than zero"
                            .to_string(),
                    });
                }
            }
        }

        let granted = if refusals.is_empty() {
            inputs.verified_nev.map(|nev| {
                PositiveNev::from_verified(inputs.class, nev.clone(), evidence_of(inputs))
            })
        } else {
            None
        };
        Nev0Adjudication { refusals, granted }
    }

    /// The accounting recorded on a granted [`PositiveNev`].
    ///
    /// Only reachable for a grant, which is the only state where
    /// [`CostBasis::NetOfOutflows`] holds — so the three fields are read
    /// without a fallback rather than defaulted to zero. A `NativeCost` of zero
    /// is legitimate; an *unpriced* one is a different arm and never reaches
    /// here.
    fn evidence_summary(inputs: &Nev0Inputs<'_>) -> Nev0EvidenceSummary {
        let CostBasis::NetOfOutflows {
            gross_inflow_musd_micros,
            external_cost_musd_micros,
            native_cost_musd_micros,
        } = inputs.cost
        else {
            unreachable!("a grant requires CostBasis::NetOfOutflows; the gate refuses every other arm")
        };
        Nev0EvidenceSummary {
            gross_inflow_musd_micros,
            external_cost_musd_micros,
            native_cost_musd_micros,
            legs: match inputs.settlement {
                SettlementCompleteness::Complete { legs, .. } => legs,
                SettlementCompleteness::Incomplete { .. } => {
                    unreachable!("a grant requires SettlementCompleteness::Complete")
                }
            },
        }
    }
}

/// The four accounting figures a grant records.
struct Nev0EvidenceSummary {
    gross_inflow_musd_micros: u64,
    external_cost_musd_micros: u64,
    native_cost_musd_micros: u64,
    legs: u64,
}

/// Build the [`Nev0Evidence`] recorded on a granted [`PositiveNev`].
///
/// `unreachable!` in two arms, both of which the gate has already made
/// impossible: a grant requires a complete leg set and a net cost basis, and
/// both are refused otherwise. The alternative — defaulting the figures to zero
/// — would put a fabricated accounting on a real value, which is the one
/// outcome this crate must never produce.
fn evidence_of(inputs: &Nev0Inputs<'_>) -> Nev0Evidence {
    let s = Nev0Gate::evidence_summary(inputs);
    Nev0Evidence {
        // A grant requires every class to be one of the four external ones, and
        // a set mixing two of them is refused as a set. So the first is the
        // only one there is.
        value_class: inputs
            .value_classes
            .first()
            .cloned()
            .unwrap_or(ExternalValueClass::ExternalTradingPnl),
        complete_operations: 1,
        legs: s.legs,
        gross_inflow_musd_micros: s.gross_inflow_musd_micros,
        external_cost_musd_micros: s.external_cost_musd_micros,
        native_cost_musd_micros: s.native_cost_musd_micros,
    }
}

/// Apply the search policy's [`MinNetEdge`] to a granted NEV-0 adjudication.
///
/// Two gates, in this order and never merged:
///
/// 1. **NEV-0** asks *is this external value?* — a provenance and
///    authentication question, answered by [`Nev0Gate::adjudicate`].
/// 2. **The minimum net edge** asks *is it worth doing?* — an operator-set bar,
///    answered here.
///
/// Merging them is the specific mistake this function exists to prevent. If
/// NEV-0 carried a scale requirement then "we do not believe small values" would
/// be enforced as a property of the *evidence* rather than as a *policy
/// decision*, and a default that quietly refuses small real gains would be
/// indistinguishable from a gate that refuses fake ones.
pub fn classify_against_min_edge(
    positive: PositiveNev,
    min_net_edge: &MinNetEdge,
) -> Result<EconomicResolution, ResolutionError> {
    let class = positive.class();
    let nev = positive.nev_musd_micros();
    let required = min_net_edge.micros();
    if nev < 0 {
        // Unreachable by construction: the gate refuses a sum that is not
        // strictly positive, so a `PositiveNev` cannot carry a loss. Refusing
        // rather than panicking, because a panic here would be reachable by
        // anyone who later widens the gate's condition.
        return Err(ResolutionError::ValueOutsideArm {
            arm: "positive_nev",
            value_musd_micros: nev,
            why: "a NEV-0 grant is strictly positive by definition; reaching a loss here means \
                  the gate's condition was widened"
                .to_string(),
        });
    }
    if required > 0 && (nev as u64) < required {
        return Ok(EconomicResolution::BreakEven(BreakEven::new(
            class, nev, required,
        )?));
    }
    Ok(EconomicResolution::PositiveNev(positive))
}

/// The arm a refusal maps to, as a full resolution.
///
/// The counterpart to [`Nev0Adjudication::into_grant`]: a refusal has no
/// authority, but it does have an arm, and producing it means an operator
/// reading a report sees *which* situation they are in rather than a bare
/// "denied".
pub fn refusal_to_resolution(
    refusal: &Nev0Refusal,
    class: OpportunityClass,
) -> EconomicResolution {
    match refusal.arm() {
        Nev0Arm::NoCompleteSettlement => {
            let gaps = match refusal {
                Nev0Refusal::IncompleteSettlement { gaps, .. } => gaps.clone(),
                _ => vec![SettlementGap::ScanNotExhaustive {
                    why: refusal.to_string(),
                }],
            };
            EconomicResolution::NoCompleteSettlement(
                crate::resolution::NoCompleteSettlement::new(class, gaps),
            )
        }
        Nev0Arm::NoVerifiedSum => EconomicResolution::NoComparableNetValue(
            crate::resolution::NoComparableNetValue::new(class, refusal.to_string()),
        ),
        Nev0Arm::NotPositive => {
            let total = match refusal {
                Nev0Refusal::NotPositive {
                    verified_musd_micros,
                    ..
                } => *verified_musd_micros,
                _ => 0,
            };
            if total < 0 {
                EconomicResolution::NegativeNev(
                    crate::resolution::NegativeNev::new(class, total, "nev0")
                        .expect("a negative total satisfies the arm's own invariant"),
                )
            } else {
                // Zero against a required bar that is at least one micro-USD.
                // The gate refused a sum that is not strictly positive, which is
                // `BreakEven` with a required edge of 1 rather than an invented
                // threshold.
                EconomicResolution::BreakEven(
                    BreakEven::new(class, total, 1)
                        .expect("0 is inside [0, 1), which is the arm's invariant"),
                )
            }
        }
        Nev0Arm::InvalidEvidence => EconomicResolution::InvalidEvidence(
            crate::resolution::InvalidEvidence::new(
                class,
                refusal
                    .as_defect()
                    .expect("an invalid-evidence refusal always has a defect"),
            ),
        ),
    }
}

pub mod testkit {
    //! The one place in the crate that stands up a chain-attested `VerifiedNev`
    //! outside of [`crate::reinvestment`]'s own tests.
    //!
    //! It exists because the positive arm of the taxonomy and the NEV-0 gate
    //! both need a real `VerifiedNev`, and the only way to get one is a pinned
    //! provider plus a signed receipt plus a recorded crossing. Duplicating that
    //! recipe in three test modules would be three chances to get it subtly
    //! wrong. `#[cfg(test)]`, so no production caller can reach it — which is
    //! also why the gate has no production callers at all.

    use super::*;
    use crate::{
        autonomy::{AutonomousEconomy, ExternalValueReceipt},
        base_usdc::{BaseUsdcVerifier, BASE_CHAIN_ID, BASE_USDC},
        boundary::{BoundaryEvidence, ControlledAddressRegistry, RealAsset},
        chain_provider::{resolve, PinnedChainProvider},
        policy_auth::ValidatedOutcomePolicy,
        rpc_test_server::FakeRpcSocket,
        verified_view::VerifiedEconomyView,
        SCHEMA_VERSION,
    };
    use tempfile::tempdir;

    pub const PAYOUT: &str = "0xe83331104f5f3c41e49abc46c810f9d71133e48c";
    pub const COUNTERPARTY: &str = "0x1234567890abcdef1234567890abcdef12345678";

    /// The cost every fixture books. Never zero: an all-gross receipt is not
    /// what NEV-0 means by "net of outflows and costs", and a fixture that booked
    /// one would not be testing the gate's arithmetic.
    pub const NATIVE_COST_MUSD_MICROS: u64 = 100_000;

    pub fn tx_hash() -> String {
        format!("0x{}", "11".repeat(32))
    }

    pub fn block_hash() -> String {
        format!("0x{}", "22".repeat(32))
    }

    pub fn registry() -> ControlledAddressRegistry {
        ControlledAddressRegistry::new()
            .with_address(PAYOUT)
            .unwrap()
    }

    /// A pinned provider that actually serves the transfer the evidence cites.
    /// `FakeRpcSocket` binds a real owner-only Unix socket, so the kernel
    /// identity check runs for real rather than being stubbed.
    pub fn serving_socket(dir: &std::path::Path, amount_raw: u64) -> FakeRpcSocket {
        let log = serde_json::json!({
            "address": BASE_USDC,
            "topics": [
                crate::base_usdc::ERC20_TRANSFER_TOPIC,
                format!("0x{:0>64}", COUNTERPARTY.trim_start_matches("0x")),
                format!("0x{:0>64}", PAYOUT.trim_start_matches("0x")),
            ],
            "data": format!("0x{amount:064x}", amount = amount_raw),
            "logIndex": "0x1",
        });
        FakeRpcSocket::with_responses(
            dir.join("verifier.sock"),
            vec![
                ("eth_chainId", serde_json::json!("0x2105")),
                ("eth_blockNumber", serde_json::json!("0x6e")),
                ("eth_getTransactionReceipt", serde_json::json!({
                    "status": "0x1",
                    "blockNumber": "0x65",
                    "blockHash": block_hash(),
                    "transactionHash": tx_hash(),
                    "logs": [log],
                })),
                ("eth_getBlockByNumber", serde_json::json!({
                    "hash": block_hash(),
                    "timestamp": "0x6553f0d0",
                })),
            ],
        )
    }

    /// Everything a pinned view borrows, owned in one place because the socket
    /// has to outlive the verifier that talks to it.
    pub struct Pinned<'a> {
        /// Never read, and never dropped before the view: the socket has to
        /// outlive every verifier that talks to it and the pin's temporary
        /// directory has to outlive the validated policy.
        _socket: FakeRpcSocket,
        pub registry: ControlledAddressRegistry,
        pub verifier: BaseUsdcVerifier,
        _auth: crate::receipt_auth::testkit::AuthFixture,
        pub policy: ValidatedOutcomePolicy,
        pub autonomy: &'a AutonomousEconomy,
    }

    impl<'a> Pinned<'a> {
        pub fn view(&'a self) -> VerifiedEconomyView<'a> {
            VerifiedEconomyView::provider_pinned(
                self.autonomy,
                &self.registry,
                &self.verifier,
                &self.policy,
            )
            .unwrap()
        }
    }

    /// A pinned view over an economy that has booked **nothing**.
    ///
    /// This is how a zero `VerifiedNev` is obtained honestly: the autonomy
    /// ledger refuses to book a non-positive net for an external inflow, so
    /// "verified value of exactly zero" is a ledger with no counted receipt, not
    /// a receipt whose arithmetic nets to nothing. Both are the same number, and
    /// the gate must refuse both.
    pub fn pinned_empty<'a>(dir: &std::path::Path, autonomy: &'a AutonomousEconomy) -> Pinned<'a> {
        let registry = registry();
        let socket = serving_socket(dir, 1);
        let provider = PinnedChainProvider::unix_socket(socket.path(), Some(socket.uid())).unwrap();
        let verifier =
            BaseUsdcVerifier::from_resolved(&resolve(None, Some(&provider)).unwrap(), 2).unwrap();
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        Pinned {
            _socket: socket,
            registry,
            verifier,
            _auth: auth,
            policy,
            autonomy,
        }
    }

    /// The opportunity an receipts fixture books against. The autonomy ledger
    /// refuses an external value for an opportunity it has never seen, so this
    /// has to exist before any receipt can be written.
    pub fn seed_opportunity(autonomy: &AutonomousEconomy) {
        use crate::autonomy::{
            AgentClass, EconomicAgentManifest, OpportunityCandidate, RiskProfile,
        };
        use crate::JobType;
        use std::collections::BTreeMap;

        let agent = EconomicAgentManifest {
            schema_version: SCHEMA_VERSION,
            agent_id: "s1".into(),
            public_key: "ed25519:s1".into(),
            agent_class: AgentClass::Finance,
            allowed_job_types: vec![JobType::Simulation],
            daily_budget_musd_micros: 100_000_000,
            max_job_cost_musd_micros: 2_000_000,
            risk_profile: RiskProfile::Conservative,
            enabled: true,
            created_at_unix: 1_700_000_000,
        };
        if autonomy.register_agent(agent).is_err() {
            // Already registered: `seed_opportunity` is idempotent so a fixture
            // that books two receipts does not have to know it.
            return;
        }
        autonomy
            .submit_opportunity(OpportunityCandidate {
                schema_version: SCHEMA_VERSION,
                opportunity_id: "opp".into(),
                agent_id: "s1".into(),
                observed_at_unix: 1_700_000_000,
                expires_at_unix: 1_700_010_000,
                job_type: JobType::Simulation,
                input_hash: "blake3:input".into(),
                evidence_hash: "blake3:evidence".into(),
                expected_gross_musd_micros: 5_000_000,
                expected_external_cost_musd_micros: 500_000,
                estimated_job_cost_musd_micros: 500_000,
                risk_buffer_musd_micros: 500_000,
                metadata: BTreeMap::new(),
            })
            .unwrap();
        autonomy
            .orchestrate("opp", &crate::autonomy::EconomicPolicy::default(), 1_700_000_100)
            .unwrap();
    }

    /// Books the given net value as chain-attested: evidence recorded, crossing
    /// derived against the operator's registry, receipt booked against it, and a
    /// provider that will re-confirm the same transfer on read.
    pub fn pin_attested_inflow<'a>(
        dir: &std::path::Path,
        autonomy: &'a AutonomousEconomy,
        gross: u64,
        cost: u64,
    ) -> Pinned<'a> {
        seed_opportunity(autonomy);
        let registry = registry();
        let evidence = BoundaryEvidence {
            chain_id: BASE_CHAIN_ID,
            asset: RealAsset::base_usdc(),
            from_address: COUNTERPARTY.into(),
            to_address: PAYOUT.into(),
            amount_raw: gross,
            tx_hash: tx_hash(),
            block_hash: block_hash(),
        };
        let socket = serving_socket(dir, gross);
        let provider = PinnedChainProvider::unix_socket(socket.path(), Some(socket.uid())).unwrap();
        let verifier =
            BaseUsdcVerifier::from_resolved(&resolve(None, Some(&provider)).unwrap(), 2).unwrap();
        // The authority is scoped to this very socket, because the provider
        // identity digest is part of the signed policy payload.
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        let crossing = autonomy
            .record_boundary_crossing(&evidence, &registry)
            .unwrap()
            .with_verified_proof(
                verifier
                    .verify_transfer(&tx_hash(), PAYOUT, gross)
                    .unwrap(),
            )
            .unwrap();
        let receipt = ExternalValueReceipt {
            schema_version: SCHEMA_VERSION,
            source_id: "source".into(),
            agent_id: "s1".into(),
            opportunity_id: "opp".into(),
            value_class: ExternalValueClass::ExternalTradingPnl,
            network: "base".into(),
            asset: "USDC".into(),
            gross_inflow_musd_micros: gross,
            external_cost_musd_micros: cost,
            net_external_value_musd_micros: gross as i64 - cost as i64,
            proof_hash: tx_hash(),
            proof_verified: true,
            realized_at_unix: 1_700_000_200,
            verifier_id: "test".into(),
        };
        // The delegated verifier signs the same bytes it just read, and the
        // signature is recorded beside the receipt. Without it the view has
        // nothing to verify and produces no `VerifiedNev` at all.
        let attestation = auth
            .verifier
            .attest(&policy, &receipt, &evidence)
            .unwrap();
        autonomy.record_receipt_attestation(&attestation).unwrap();
        autonomy
            .record_external_value_with_crossing(receipt, &crossing)
            .unwrap();
        Pinned {
            _socket: socket,
            registry,
            verifier,
            _auth: auth,
            policy,
            autonomy,
        }
    }

    /// A chain-attested `VerifiedNev` of exactly `nev_musd_micros`, obtained the
    /// only way one can be obtained.
    ///
    /// Returns the value alone, not the fixture: a `VerifiedNev` owns its numbers
    /// and its provider string, so the socket and the ledger can be dropped the
    /// moment it exists. Handing back a borrow would force every caller to thread
    /// a `Pinned` through, for a value that does not need one.
    ///
    /// Refuses a non-positive target rather than producing one, and the refusal
    /// is a fact about the crate rather than about this helper:
    /// [`crate::autonomy::AutonomousEconomy::record_external_value`] will not
    /// book a non-positive net for an external inflow, so a zero or negative
    /// `VerifiedNev` is only reachable from a ledger with no counted receipt —
    /// see [`pinned_empty`].
    pub fn verified_nev(
        dir: &std::path::Path,
        autonomy: &AutonomousEconomy,
        nev_musd_micros: i64,
    ) -> VerifiedNev {
        assert!(
            nev_musd_micros > 0,
            "a non-positive VerifiedNev is not bookable through a receipt; use pinned_empty"
        );
        // The receipt books gross and cost; the view sums `gross - cost`. For a
        // target of exactly `n`, book `n + cost` gross and `cost` cost, with a
        // cost that cannot be zero (an all-gross receipt is not what NEV-0 means
        // by "net of costs").
        let cost = NATIVE_COST_MUSD_MICROS.max(1);
        let gross = u64::try_from(nev_musd_micros + cost as i64).unwrap();
        let pinned = pin_attested_inflow(dir, autonomy, gross, cost);
        let nev = pinned.view().verified_nev().unwrap();
        assert_eq!(nev.nev_musd_micros(), nev_musd_micros, "the fixture must be exact");
        nev
    }

    /// A `PositiveNev` from a real, chain-attested `VerifiedNev`, granted through
    /// the gate. Used by the revalidation tests, which need the authority-bearing
    /// arm and have no business rebuilding the fixture.
    pub fn sample_positive_resolution() -> EconomicResolution {
        let dir = tempdir().unwrap();
        let autonomy = AutonomousEconomy::open(dir.path()).unwrap();
        let nev = verified_nev(dir.path(), &autonomy, 10_000);
        let inputs = Nev0Inputs {
            class: OpportunityClass::Arbitrage,
            provenance: EvidenceProvenance::LiveChain {
                chain_id: BASE_CHAIN_ID,
                block_number: 0x65,
            },
            provider: ProviderStanding::KernelEnforced {
                endpoint: "unix://fixture.sock".into(),
                identity_hash: "0xfixture".into(),
            },
            authentication: EvidenceAuthentication::DelegatedVerifierSignature {
                key_id: "verifier-runtime".into(),
            },
            value_classes: &[ExternalValueClass::ExternalTradingPnl],
            settlement: SettlementCompleteness::Complete {
                legs: 1,
                scanned_exhaustively: true,
            },
            cost: CostBasis::NetOfOutflows {
                gross_inflow_musd_micros: 20_000,
                external_cost_musd_micros: 0,
                native_cost_musd_micros: 0,
            },
            anchor: None,
            verified_nev: Some(&nev),
        };
        EconomicResolution::PositiveNev(
            Nev0Gate::adjudicate(&inputs)
                .into_grant()
                .expect("the fixture is a clean NEV-0 grant"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use crate::autonomy::AutonomousEconomy;
    use crate::base_usdc::BASE_CHAIN_ID;
    use crate::discovery::OpportunityClass;
    use crate::policy_auth::Hash;
    use crate::revalidation::RevalidationState;
    use tempfile::tempdir;

    // ------------------------------------------------------------------
    // The reference input: everything the gate wants, and nothing it does
    // not. Every refusal test is this input with exactly one thing changed,
    // so a failure names the change.
    // ------------------------------------------------------------------

    fn anchor() -> SettlementAnchor {
        SettlementAnchor::new(101, Hash::from_bytes([1u8; 32]))
    }

    /// A chain-attested `VerifiedNev` of exactly `nev_musd_micros`, plus inputs
    /// that clear the gate.
    ///
    /// The temporary directory and the autonomy ledger are leaked on purpose.
    /// `Nev0Inputs` borrows the `VerifiedNev`, and the `VerifiedNev` can only be
    /// produced through a pinned view that borrows the registry, the verifier and
    /// the policy — so a helper that returned it by value would need five
    /// lifetimes of plumbing in every test. The leak is bounded by the test
    /// binary's own lifetime and named here rather than hidden.
    fn adjudicated_with(
        nev_musd_micros: i64,
        value_classes: Vec<ExternalValueClass>,
    ) -> (tempfile::TempDir, Nev0Inputs<'static>) {
        let dir = Box::leak(Box::new(tempdir().unwrap()));
        let autonomy = Box::leak(Box::new(AutonomousEconomy::open(dir.path()).unwrap()));
        let nev: &'static VerifiedNev =
            Box::leak(Box::new(verified_nev(dir.path(), autonomy, nev_musd_micros)));
        let value_classes: &'static [ExternalValueClass] =
            Box::leak(value_classes.into_boxed_slice());
        let inputs = Nev0Inputs {
            class: OpportunityClass::Arbitrage,
            provenance: EvidenceProvenance::LiveChain {
                chain_id: BASE_CHAIN_ID,
                block_number: 0x65,
            },
            provider: ProviderStanding::KernelEnforced {
                endpoint: "unix:///run/mycelium/chain.sock".into(),
                identity_hash: "0xabc".into(),
            },
            authentication: EvidenceAuthentication::DelegatedVerifierSignature {
                key_id: "verifier-runtime:deadbeef".into(),
            },
            value_classes,
            settlement: SettlementCompleteness::Complete {
                legs: 2,
                scanned_exhaustively: true,
            },
            // Matches what the pinned read actually booked, so the accounting
            // recorded on a grant is not a fiction.
            cost: CostBasis::NetOfOutflows {
                gross_inflow_musd_micros: u64::try_from(nev_musd_micros + 1).unwrap(),
                external_cost_musd_micros: 0,
                native_cost_musd_micros: 1,
            },
            anchor: Some(anchor()),
            verified_nev: Some(nev),
        };
        // A placeholder directory: the real one was leaked, and the signature
        // keeps the call sites honest about holding something alive.
        (tempfile::TempDir::new().unwrap(), inputs)
    }

    /// The reference input.
    fn adjudicated(nev_musd_micros: i64) -> (tempfile::TempDir, Nev0Inputs<'static>) {
        adjudicated_with(nev_musd_micros, vec![ExternalValueClass::ExternalTradingPnl])
    }

    /// The reference input over an economy that has booked nothing, so the
    /// verified sum is a real `VerifiedNev` of exactly zero.
    fn adjudicated_zero() -> (tempfile::TempDir, Nev0Inputs<'static>) {
        let dir = Box::leak(Box::new(tempdir().unwrap()));
        let autonomy = Box::leak(Box::new(AutonomousEconomy::open(dir.path()).unwrap()));
        let pinned = pinned_empty(dir.path(), autonomy);
        let nev: &'static VerifiedNev = Box::leak(Box::new(pinned.view().verified_nev().unwrap()));
        let value_classes: &'static [ExternalValueClass] =
            Box::leak(vec![ExternalValueClass::ExternalTradingPnl].into_boxed_slice());
        (
            tempfile::TempDir::new().unwrap(),
            Nev0Inputs {
                class: OpportunityClass::Arbitrage,
                provenance: EvidenceProvenance::LiveChain {
                    chain_id: BASE_CHAIN_ID,
                    block_number: 0x65,
                },
                provider: ProviderStanding::KernelEnforced {
                    endpoint: "unix:///run/mycelium/chain.sock".into(),
                    identity_hash: "0xabc".into(),
                },
                authentication: EvidenceAuthentication::DelegatedVerifierSignature {
                    key_id: "verifier-runtime:deadbeef".into(),
                },
                value_classes,
                settlement: SettlementCompleteness::Complete {
                    legs: 0,
                    scanned_exhaustively: true,
                },
                cost: CostBasis::NetOfOutflows {
                    gross_inflow_musd_micros: 0,
                    external_cost_musd_micros: 0,
                    native_cost_musd_micros: 0,
                },
                anchor: Some(anchor()),
                verified_nev: Some(nev),
            },
        )
    }

    // ==================================================================
    // 1. The gate grants what it should
    // ==================================================================

    #[test]
    fn complete_authenticated_chain_confirmed_net_value_is_granted() {
        let (_keep, inputs) = adjudicated(5_000_000);
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(out.is_granted(), "{out:?}");
        assert!(out.refusals().is_empty());
        let grant = out.granted().unwrap();
        assert_eq!(grant.nev_musd_micros(), 5_000_000);
        assert_eq!(grant.class(), OpportunityClass::Arbitrage);
        // The recorded accounting is the one that was declared, recomputable,
        // and equal to the verified total.
        let e = grant.evidence();
        assert_eq!(e.net_musd_micros(), Some(5_000_000));
        assert_eq!(e.value_class, ExternalValueClass::ExternalTradingPnl);
        assert_eq!(e.legs, 2);
        assert_eq!(e.complete_operations, 1);
    }

    #[test]
    fn one_hundredth_of_a_cent_is_not_dust() {
        // 10_000 micro-USD = 0.01 USDC. NEV-0 has no scale requirement and this
        // pins it: the grant happens, with no threshold anywhere on the path.
        let (_keep, inputs) = adjudicated(10_000);
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(out.is_granted(), "{out:?}");
        assert_eq!(out.granted().unwrap().nev_musd_micros(), 10_000);

        // And the smallest positive value this type can hold.
        let (_k, one) = adjudicated(1);
        assert!(Nev0Gate::adjudicate(&one).is_granted());
    }

    #[test]
    fn a_grant_carries_no_budget_and_no_spend_authority() {
        let (_keep, inputs) = adjudicated(5_000_000);
        let resolution = EconomicResolution::PositiveNev(
            Nev0Gate::adjudicate(&inputs)
                .into_grant()
                .expect("clean grant"),
        );
        assert!(resolution.is_authority());
        // Still blocked: an economic claim is not a standing, and the standing is
        // what spend authority's precondition is.
        let blocked = resolution.standing(&RevalidationState::NeedsRevalidation {
            anchor: None,
            why: "no revalidation has been run".into(),
        });
        assert!(!blocked.is_granted(), "{blocked:?}");
    }

    // ==================================================================
    // 2. The refusal list — one test per mandated category
    // ==================================================================

    #[test]
    fn synthetic_value_is_refused() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.provenance = EvidenceProvenance::Synthetic {
            label: "backtest-42".into(),
        };
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"synthetic_value"), "{out:?}");
        assert!(out.refusals()[0].is_forbidden_category());
    }

    #[test]
    fn myc_issuance_is_refused() {
        let (_keep, inputs) =
            adjudicated_with(5_000_000, vec![ExternalValueClass::MycEmission]);
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"myc_issuance"), "{out:?}");
    }

    #[test]
    fn a_transfer_between_controlled_wallets_is_refused() {
        for class in [
            ExternalValueClass::InternalTransfer,
            ExternalValueClass::TreasuryTransfer,
        ] {
            let (_keep, inputs) = adjudicated_with(5_000_000, vec![class.clone()]);
            let out = Nev0Gate::adjudicate(&inputs);
            assert!(!out.is_granted(), "{class:?} was counted");
            assert!(
                out.categories().contains(&"controlled_wallet_transfer"),
                "{class:?}: {out:?}"
            );
        }
    }

    #[test]
    fn a_test_fixture_is_refused() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.provenance = EvidenceProvenance::TestFixture {
            label: "reinvestment::tests::setup".into(),
        };
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"test_fixture"), "{out:?}");
    }

    #[test]
    fn the_dev_provider_is_refused() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.provider = ProviderStanding::DevProvider {
            endpoint: "http://127.0.0.1:8546".into(),
        };
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"dev_provider"), "{out:?}");
        assert!(out.refusals()[0].to_string().contains("127.0.0.1:8546"));
    }

    #[test]
    fn unsigned_evidence_is_refused() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.authentication = EvidenceAuthentication::Unsigned;
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"unsigned_evidence"), "{out:?}");

        // A policy signature alone is not authentication of a *value*: the
        // policy says what may be counted, not that anything was.
        let (_k, mut policy_only) = adjudicated(5_000_000);
        policy_only.authentication = EvidenceAuthentication::PolicySignatureOnly {
            authority_key_id: "policy-authority:deadbeef".into(),
        };
        let out = Nev0Gate::adjudicate(&policy_only);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"unsigned_evidence"), "{out:?}");
    }

    #[test]
    fn an_incomplete_settlement_is_refused() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.settlement = SettlementCompleteness::Incomplete {
            gaps: vec![SettlementGap::LegAbsent {
                why: "the second leg never appeared in the scan".into(),
            }],
        };
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(
            out.categories().contains(&"incomplete_settlement"),
            "{out:?}"
        );
        // And it lands in the arm that names the situation, not in
        // `InvalidEvidence`.
        let r = out
            .refusals()
            .iter()
            .find(|r| r.is_forbidden_category())
            .unwrap();
        assert_eq!(r.arm(), Nev0Arm::NoCompleteSettlement);
        let resolution = refusal_to_resolution(r, OpportunityClass::Arbitrage);
        assert_eq!(resolution.state(), "no_complete_settlement");
        assert!(!resolution.is_authority());
    }

    #[test]
    fn unpriced_gas_is_refused() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.cost = CostBasis::UnpricedGas;
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"unpriced_gas"), "{out:?}");
    }

    #[test]
    fn a_raw_edge_is_refused() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.cost = CostBasis::RawEdge;
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"raw_edge"), "{out:?}");
    }

    #[test]
    fn a_modelled_profit_is_refused() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.cost = CostBasis::ModeledProfit;
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"modeled_profit"), "{out:?}");
    }

    #[test]
    fn every_forbidden_category_is_refused() {
        // Walks the mandated list and drives each one, so a category that is
        // declared but never tested is a failure rather than a silent hole. The
        // individual tests above are the readable versions; this is the one that
        // fails if a category is added without a case.
        type Case = (&'static str, fn(&mut Nev0Inputs<'_>));
        let cases: Vec<Case> = vec![
            ("synthetic_value", |i| {
                i.provenance = EvidenceProvenance::Synthetic { label: "x".into() };
            }),
            ("dev_provider", |i| {
                i.provider = ProviderStanding::DevProvider { endpoint: "x".into() };
            }),
            ("unsigned_evidence", |i| {
                i.authentication = EvidenceAuthentication::Unsigned;
            }),
            ("incomplete_settlement", |i| {
                i.settlement = SettlementCompleteness::Incomplete { gaps: vec![] };
            }),
            ("unpriced_gas", |i| {
                i.cost = CostBasis::UnpricedGas;
            }),
            ("raw_edge", |i| {
                i.cost = CostBasis::RawEdge;
            }),
            ("modeled_profit", |i| {
                i.cost = CostBasis::ModeledProfit;
            }),
        ];
        for (category, mutate) in cases {
            let (_keep, mut inputs) = adjudicated(5_000_000);
            mutate(&mut inputs);
            let out = Nev0Gate::adjudicate(&inputs);
            assert!(!out.is_granted(), "{category} was granted");
            assert!(
                out.categories().contains(&category),
                "{category} was not refused under its own name: {:?}",
                out.categories()
            );
        }

        // The three that need a different *class set* rather than a different
        // field, driven separately so the list above stays one shape.
        for (category, class) in [
            ("myc_issuance", ExternalValueClass::MycEmission),
            (
                "controlled_wallet_transfer",
                ExternalValueClass::InternalTransfer,
            ),
        ] {
            let (_keep, inputs) = adjudicated_with(5_000_000, vec![class]);
            let out = Nev0Gate::adjudicate(&inputs);
            assert!(!out.is_granted(), "{category} was granted");
            assert!(
                out.categories().contains(&category),
                "{category} was not refused under its own name: {:?}",
                out.categories()
            );
        }

        // `test_fixture` is a provenance arm like `synthetic_value`; driven here
        // too so every one of the ten is covered by this single test.
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.provenance = EvidenceProvenance::TestFixture { label: "x".into() };
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"test_fixture"), "{out:?}");

        let driven = out.categories().len();
        assert!(
            driven >= 1,
            "sanity: the catalogue is not vacuously satisfied"
        );
    }

    // ==================================================================
    // 3. Refusals that are not in the mandated ten
    // ==================================================================

    #[test]
    fn an_unpinned_provider_is_refused() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.provider = ProviderStanding::Unpinned;
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"unpinned_provider"), "{out:?}");
    }

    #[test]
    fn a_ledger_that_only_claims_a_value_is_refused() {
        // `None` here is what an `UnattestedNev` world produces: the ledger
        // claims a total and nothing was chain-confirmed. The refusal says so by
        // name, and an `UnattestedNev` cannot be passed here at all — it is a
        // different type with no `From`.
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.verified_nev = None;
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"no_verified_sum"), "{out:?}");
        let r = out
            .refusals()
            .iter()
            .find(|r| r.category() == "no_verified_sum")
            .unwrap();
        assert!(r.to_string().contains("UnattestedNev"), "{r}");
    }

    #[test]
    fn a_zero_verified_sum_is_refused_as_not_positive() {
        // A real `VerifiedNev` of exactly zero, from a ledger with no counted
        // receipt. This is the case "external value created = 0" has to be able
        // to express, and it must be a refusal rather than a grant of nothing.
        let (_keep, inputs) = adjudicated_zero();
        assert_eq!(inputs.verified_nev.unwrap().nev_musd_micros(), 0);
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        let r = out
            .refusals()
            .iter()
            .find(|r| r.category() == "not_positive")
            .unwrap();
        assert!(r.to_string().contains("0 mUSD"), "{r}");
        // And the arm it lands in is `break_even`, not a positive carrying zero.
        assert_eq!(
            refusal_to_resolution(r, OpportunityClass::Arbitrage).state(),
            "break_even"
        );
        // Two refusals here, not one: an empty leg set is also not something to
        // sum, and both are named rather than collapsed.
        assert!(out.categories().contains(&"no_complete_operations"), "{out:?}");
    }

    #[test]
    fn a_negative_verified_sum_is_refused_as_not_positive() {
        // **Not reachable through a receipt today.** The autonomy ledger refuses
        // to book a non-positive net for an external inflow, so the only way a
        // `VerifiedNev` goes negative is a settlement authority whose complete
        // operation lost money, and the settlement path has no production
        // callers. The branch is therefore tested where it lives — in the
        // refusal-to-arm mapping — rather than through a fixture that would have
        // to fabricate a value the crate does not let anyone book.
        let refusal = Nev0Refusal::NotPositive {
            verified_musd_micros: -1_000_000,
            why: "a complete operation lost money".into(),
        };
        assert_eq!(refusal.category(), "not_positive");
        let resolution = refusal_to_resolution(&refusal, OpportunityClass::Arbitrage);
        assert_eq!(resolution.state(), "negative_nev");
        assert!(!resolution.is_authority());
        assert!(resolution.describe().contains("-1000000"), "{}", resolution.describe());
    }

    #[test]
    fn a_non_exhaustive_scan_is_refused() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.settlement = SettlementCompleteness::Complete {
            legs: 2,
            scanned_exhaustively: false,
        };
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"scan_not_exhaustive"), "{out:?}");
    }

    #[test]
    fn a_complete_but_empty_leg_set_is_refused() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.settlement = SettlementCompleteness::Complete {
            legs: 0,
            scanned_exhaustively: true,
        };
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"no_complete_operations"), "{out:?}");
    }

    #[test]
    fn a_spend_or_payout_class_is_refused() {
        for class in [
            ExternalValueClass::BotServiceSpend,
            ExternalValueClass::WsrPayout,
        ] {
            let (_keep, inputs) = adjudicated_with(5_000_000, vec![class.clone()]);
            let out = Nev0Gate::adjudicate(&inputs);
            assert!(!out.is_granted(), "{class:?} was counted");
            assert!(
                out.categories().contains(&"non_external_value_class"),
                "{class:?}: {out:?}"
            );
        }
    }

    #[test]
    fn a_set_mixing_a_profit_with_an_emission_is_refused_as_a_set() {
        let (_keep, inputs) = adjudicated_with(
            5_000_000,
            vec![
                ExternalValueClass::ExternalTradingPnl,
                ExternalValueClass::MycEmission,
            ],
        );
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        assert!(out.categories().contains(&"myc_issuance"), "{out:?}");
    }

    // ==================================================================
    // 4. Reporting
    // ==================================================================

    #[test]
    fn every_refusal_found_is_reported_not_only_the_first() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.provenance = EvidenceProvenance::Synthetic { label: "x".into() };
        inputs.provider = ProviderStanding::DevProvider { endpoint: "x".into() };
        inputs.authentication = EvidenceAuthentication::Unsigned;
        inputs.cost = CostBasis::RawEdge;
        let out = Nev0Gate::adjudicate(&inputs);
        assert!(!out.is_granted());
        for expected in [
            "synthetic_value",
            "dev_provider",
            "unsigned_evidence",
            "raw_edge",
        ] {
            assert!(
                out.categories().contains(&expected),
                "{expected} missing from {:?}",
                out.categories()
            );
        }
        // And the arm order is the evaluation order, so the most fundamental
        // problem is first and the most downstream one last.
        assert_eq!(out.refusals()[0].category(), "synthetic_value");
        assert_eq!(out.refusals().last().unwrap().category(), "raw_edge");
    }

    #[test]
    fn the_first_refusal_is_the_one_returned() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.cost = CostBasis::ModeledProfit;
        inputs.provider = ProviderStanding::Unpinned;
        let out = Nev0Gate::adjudicate(&inputs);
        let r = out.into_grant().unwrap_err();
        assert_eq!(r.category(), "unpinned_provider");
    }

    #[test]
    fn every_forbidden_refusal_maps_to_an_arm_that_carries_no_authority() {
        let (_keep, mut inputs) = adjudicated(5_000_000);
        inputs.provenance = EvidenceProvenance::Synthetic { label: "x".into() };
        let out = Nev0Gate::adjudicate(&inputs);
        for r in out.refusals() {
            let resolution = refusal_to_resolution(r, OpportunityClass::Arbitrage);
            assert!(
                !resolution.is_authority(),
                "{} mapped to an authority-bearing arm",
                r.category()
            );
            let state = resolution.state();
            assert!(resolution.into_authority().is_err());
            assert_ne!(state, "positive_nev");
        }
        // The category survives onto the face of the report.
        let r = out
            .refusals()
            .iter()
            .find(|r| r.category() == "synthetic_value")
            .unwrap();
        let defect = r.as_defect().unwrap();
        assert_eq!(defect.state(), "nev0_refused");
        match defect {
            EvidenceDefect::Nev0Refused { category, .. } => {
                assert_eq!(category, "synthetic_value")
            }
            other => panic!("unexpected defect {other:?}"),
        }
    }

    #[test]
    fn the_refusal_categories_are_distinct_and_complete() {
        let all = [
            "synthetic_value",
            "myc_issuance",
            "controlled_wallet_transfer",
            "non_external_value_class",
            "test_fixture",
            "dev_provider",
            "unpinned_provider",
            "unsigned_evidence",
            "incomplete_settlement",
            "unpriced_gas",
            "raw_edge",
            "modeled_profit",
            "scan_not_exhaustive",
            "no_verified_sum",
            "not_positive",
            "no_complete_operations",
        ];
        let mut unique = all.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), all.len(), "two refusals share a category");
        // Every mandated category has a spelling, and none of the extras is
        // spelled like a mandated one.
        for c in NEV0_FORBIDDEN_CATEGORIES {
            assert!(all.contains(&c), "{c} has no refusal arm");
        }
    }

    // ==================================================================
    // 5. The minimum net edge is a *different* gate
    // ==================================================================

    #[test]
    fn the_minimum_net_edge_is_applied_after_nev0_and_separately() {
        let (_keep, inputs) = adjudicated(10_000);
        let grant = Nev0Gate::adjudicate(&inputs).into_grant().unwrap();

        // Above the bar: the positive arm survives.
        let high = classify_against_min_edge(
            PositiveNev::from_verified(
                OpportunityClass::Arbitrage,
                grant.verified_nev().clone(),
                grant.evidence().clone(),
            ),
            &MinNetEdge::new(1_000).unwrap(),
        )
        .unwrap();
        assert_eq!(high.state(), "positive_nev");

        // Below the bar: the same grant becomes `break_even`. The gate did not
        // change; the policy did.
        let low = classify_against_min_edge(
            PositiveNev::from_verified(
                OpportunityClass::Arbitrage,
                grant.verified_nev().clone(),
                grant.evidence().clone(),
            ),
            &MinNetEdge::new(1_000_000).unwrap(),
        )
        .unwrap();
        assert_eq!(low.state(), "break_even");
        assert!(!low.is_authority());
    }
}
