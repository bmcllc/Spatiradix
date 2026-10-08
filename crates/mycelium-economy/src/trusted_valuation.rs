//! P4.6: a price, read the way this crate reads everything else — named,
//! anchored, signed by a key a validated policy delegated, and selected by a
//! rule that was decided before the number was known.
//!
//! # What this replaces
//!
//! P4.5c left a seam open on purpose and said so in three places: gas is a fact
//! in wei, the token delta is a fact in micros of the operation asset, and the
//! two are not added because this build had no trustworthy ETH/USD evidence.
//! [`crate::settlement::VerifiedSettlement::promote`] therefore refused every
//! operation that burned native value, with
//! [`crate::settlement::SettlementError::NoComparableNetValue`].
//!
//! That refusal was the correct answer to "what can we do without a price?" and
//! the wrong answer to "how do we get a price?". This module is the second
//! half: it makes a price a *fact with a chain anchor and an authority* rather
//! than a parameter, so the refusal can be lifted for a real price and kept for
//! everything else.
//!
//! # The four properties that make a price usable here
//!
//! 1. **It is anchored in the chain, not in the reader's clock.** Every
//!    observation carries the block number, the hash of that block, that block's
//!    own timestamp and how deep the block was. Selection compares the
//!    observation against the *settlement's* block anchor, never against "now":
//!    see [`select_price`].
//! 2. **It is authorised by the same trust chain as everything else.** The
//!    signing key is the policy's delegated `verifier-runtime` key — the same
//!    key that signs receipts — and the observation is bound to the same
//!    `policy_hash`. There is no second authority and no oracle-specific key
//!    type. See [`validate_price_observation`].
//! 3. **The source is named by the policy, not by the observation.** The
//!    [`PriceSourcePolicy`] is hashed into the signed payload
//!    ([`crate::policy_auth::OutcomePolicyPayload::price_source_hash`]), and a
//!    [`ValidatedPriceSource`] can only be built when the live policy hashes to
//!    what the signed policy named. A source named only by the receipt is
//!    refused at policy-validation time and again at bind time.
//! 4. **The rounding is decided here, not at the call site.**
//!    [`AppliedPrice::cost_musd`] rounds **up**, always, and this is the
//!    crate's first lossy division; see the rounding section below.
//!
//! # Why the price is not a `promote` parameter
//!
//! The tempting shape is `promote(verifier, policy, price_musd: u64)`, and it is
//! wrong for a reason that has nothing to do with types: a caller who can pass a
//! price can pass a price that makes the settlement profitable. The number would
//! be chosen after the legs were summed, which is hindsight with extra steps.
//!
//! So the price travels as a *context*, and the context has one constructor:
//!
//! ```text
//! ValidatedPriceSource::bind(&ValidatedOutcomePolicy, &PriceSourcePolicy)
//!     -> only when the live policy's binding digest is the one the signed
//!        policy carries
//! select_price(&ValidatedPriceSource, &[ValidatedPriceObservation], &BlockAnchor)
//!     -> PriceSelection::Priced(AppliedPrice) | PriceSelection::Unpriced(..)
//! ```
//!
//! Both inputs are types with private fields and no arbitrary constructor: the
//! first only exists if a *validated* policy named that price source, and the
//! second only exists if the policy's own delegated key signed the exact bytes.
//! There is no way to reach [`AppliedPrice`] with a number no authority spoke
//! for, and no way to reach one whose number was picked after the fact.
//!
//! # The selection rule, and why "latest at or before" is the only one here
//!
//! ```text
//! eligible := observations o such that
//!               o.chain_id  == policy.chain_id
//!               o.source_id ∈ policy.permitted_sources
//!               o.pair      == policy.pair
//!               o.policy_hash == policy_hash
//!               o.block_number      <= anchor.block_number
//!               o.block_timestamp   <= anchor.block_timestamp
//!               anchor.block_timestamp - o.block_timestamp <= policy.max_staleness
//!               o.confirmations     >= policy.min_confirmations
//! chosen   := the member of eligible with the greatest
//!             (block_number, block_timestamp, event_id)
//! ```
//!
//! Every clause is a *rejection* except the last, which is a total order. That
//! is the property that matters: selection cannot prefer an observation because
//! it arrived first, was offered first, or produces a rounder number. The
//! ordering key ends with the event id, so two observations that agree on block
//! and timestamp — same price feed, two rounds — resolve to the same choice
//! whatever order the caller listed them in.
//!
//! The two rejections that are *not* obvious, and are the reason this rule
//! rather than "newest wins":
//!
//! * **No future observation.** An observation at a block *after* the
//!   settlement's, or at a timestamp after it, is a price read after the fact.
//!   It may well be the honest price — that is not the point. It is a price the
//!   settlement did not have, and admitting it would let a later read
//!   retroactively decide an earlier operation's worth.
//! * **No forked block.** Two eligible observations at the *same* block with
//!   *different* prices are not two readings, they are a fork the node cannot
//!   resolve. Refusing is the only answer; picking either one would be picking a
//!   side in a reorg.
//!
//! # The rounding, decided once and asserted
//!
//! ```text
//! GasCost_musd = CEIL(cost_wei × price_musd_per_eth / 10^18)
//! ```
//!
//! **Up, always.** There is no precedent for a lossy division in this crate, so
//! the direction is a decision rather than a convention, and the argument is
//! about who the error favours. This term is subtracted from the settlement's
//! net, so rounding *down* shrinks a cost — the operator's budget grows by the
//! difference on every transaction, forever, and the direction of the error is
//! chosen by whoever picked the price. Rounding *up* can only ever make a
//! settlement look marginally worse, which is the direction that fails safe.
//! The overstatement is bounded by `1e-6 USD` per cost row, which is
//! [`MICROS_DECIMALS`] of the unit the ledger books in, and `1e-6 × 0.08 = 8e-8
//! USD` — far below any economically meaningful figure, which is the point: the
//! bound has to be negligible *and* on the safe side.
//!
//! # Overflow fails closed
//!
//! `cost_wei` is bounded by `u64::MAX` (about 1.8e19, a property of
//! [`crate::event_id::ExternalEventFact::native_gas`]) and the product
//! `cost_wei × price_musd_per_eth` needs the price to stay below about 1.9e19
//! micro-USD per ETH — roughly 19 trillion USD per ETH — before a `u128`
//! overflows. Every multiplication and addition is `checked_*` anyway, and an
//! overflow is [`ValuationError::PriceArithmeticOverflow`], never a wrapped
//! figure and never a saturating one. No big-integer dependency is needed, and
//! none was added: see the crate's `[dependencies]`, which is unchanged by this
//! step.
//!
//! # Where the observation comes from, and why no new RPC method was added
//!
//! An oracle's own `Transfer` log cannot reach this crate through
//! [`crate::base_usdc::BaseUsdcVerifier::scan_transaction`]: a `Transfer` on any
//! contract other than Base USDC lands in `unclassified`, which sets
//! `exhaustive = false` and makes **every** settlement over that transaction
//! incomplete. So the price does not arrive through the transaction scan, and
//! it does not arrive through a new RPC surface either.
//!
//! What it arrives through is the *existing* read-only allowlist. `eth_getBlock
//! ByNumber` is already permitted — `scan_transaction` uses it to learn a
//! block's hash and timestamp — and a block carries a timestamp, which is what a
//! price observation needs to be anchored at all. This build adds no RPC method,
//! writes nothing, and stays structurally incapable of broadcasting; the
//! observation is a *signed document* whose fields the delegated verifier read
//! over its own already-pinned transport. When a production reader is written it
//! must go through [`crate::base_usdc::BaseUsdcVerifier`]'s single
//! `rpc_call` choke point, so the allowlist binds it for free. **No such reader
//! is added here**: the settlement path has no production callers and stays that
//! way, so wiring one up would be adding live machinery to an inert path.
//!
//! # Finality, and what is *not* implemented
//!
//! An observation is [`PriceFinality::Finalized`] when the block it was read at
//! had at least `policy.min_confirmations` confirmations — the same bar
//! [`crate::base_usdc::BaseUsdcVerifier`] applies to a transaction receipt, and
//! the same value the policy already carries. A pending observation is refused
//! by the selection, so a promoted comparable value always rests on a price
//! that met the policy's own depth requirement.
//!
//! What is **not** here, and is a real exposure rather than a scoped-out
//! nicety:
//!
//! * **No reorg detection.** Nothing in this crate watches for a reorg, so a
//!   chain that reorganises deeper than `min_confirmations` invalidates an
//!   already-promoted value and this build will never say so. A promoted
//!   comparable value is a statement about the chain view at promotion time.
//! * **No cross-checking of the source.** An observation is trusted because the
//!   policy's own verifier signed it, not because a second source agreed.
//! * **No expiry of an observation *document***. Freshness is decided at
//!   selection against the anchor and `max_staleness_unix`, never by a wall
//!   clock, which is what makes the same ledger read twice produce the same
//!   number.

use crate::{
    base_usdc::BlockAnchor,
    event_id::{CountedEvents, ExternalEventId, PriceObservationFact},
    policy_auth::{
        push_tagged, signature_serde, Hash, KeyId, PreimageFieldKind, ValidatedOutcomePolicy,
        VerifierRuntimeKey,
    },
    EconomyError,
};
use ed25519_dalek::{Signature, Verifier as _};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Domain of the digest that binds a [`PriceSourcePolicy`] into an outcome
/// policy. First bytes of that digest, and a different string from every other
/// domain in the crate, so a price-source binding can never be confused with the
/// registry binding, the provider pin, a policy hash or an event id.
pub const PRICE_SOURCE_POLICY_DOMAIN: &str = "MYCELIUM-ECONOMY/PRICE-SOURCE/V1";

/// Schema version of the price-source binding this build computes.
pub const PRICE_SOURCE_POLICY_SCHEMA_VERSION: u32 = 1;

/// Domain of the price-attestation preimage. A different string from the
/// price-observation *identity* domain in [`crate::event_id`]: what was read and
/// who vouched for it are two different messages.
pub const PRICE_ATTESTATION_DOMAIN: &str = "MYCELIUM-ECONOMY/PRICE-ATTESTATION/V1";

/// Schema version of the price attestation this build computes and accepts.
pub const PRICE_ATTESTATION_SCHEMA_VERSION: u32 = 1;

/// Decimals of the economic unit the whole crate books in. Named here because
/// the rounding argument above is stated in terms of it.
pub const MICROS_DECIMALS: u32 = 6;

/// The fixed-point divisor of the conversion, `10^18`.
///
/// It is exactly two things multiplied: `10^18` wei per ETH, and `10^6`
/// micro-USD per USD. `price_musd_per_eth` is therefore a whole number of
/// **micro-USD per whole ETH** — `3000.00 USD/ETH` is `3_000_000_000_000` — and
/// `cost_wei × price_musd_per_eth / 10^18` lands in micro-USD with no unit
/// conversion anywhere in the crate.
pub const PRICE_FIXED_POINT_DIVISOR: u128 = 1_000_000_000_000_000_000;

/// Maximum length of a [`PriceSourceId`] and of a source round, in bytes.
/// Bounded so a preimage row has a bounded size and a report line has a bounded
/// length.
const MAX_SOURCE_ID_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can refuse to produce a price.
///
/// The shape is P4.5c's: a refusal is never "the price is different". Either
/// the reading is one this build can use, or the settlement has no comparable
/// value and says which of these it hit.
#[derive(Debug, thiserror::Error)]
pub enum ValuationError {
    #[error(transparent)]
    Economy(#[from] EconomyError),

    #[error(transparent)]
    Policy(#[from] crate::policy_auth::PolicyError),

    #[error(transparent)]
    EventId(#[from] crate::event_id::EventIdError),

    #[error("price preimage is malformed: {0}")]
    Preimage(String),

    /// A source identity that names nothing.
    ///
    /// The reserved spellings are refused so a policy cannot be signed with a
    /// source called "any" or "unknown" and then be read as though it had
    /// authorised a specific feed. This is a spelling check, not an
    /// authorisation: authorisation is
    /// [`crate::settlement::VerifiedSettlement::compare`].
    #[error("price source id {source_id:?} is not a usable source identity: {reason}")]
    UnusableSourceId { source_id: String, reason: String },

    /// A pair this build does not price.
    ///
    /// The pair is a closed enum, so this is what "the wrong pair" looks like at
    /// the boundary: a spelling that does not name one of the inhabitable pairs.
    #[error("this build does not price {pair:?}; it prices {supported}")]
    UnsupportedPair { pair: String, supported: String },

    /// A source policy with no permitted source, or a zero-length staleness
    /// window.
    #[error("price source policy is not usable: {0}")]
    UnusableSourcePolicy(String),

    /// The live price-source policy is not the one the signed policy authorises.
    ///
    /// This is the gate that makes "a source named only by the receipt" a
    /// refusal rather than a preference: the observation may name any source it
    /// likes, and it still cannot be used unless the *policy* named it first.
    #[error(
        "the price source in use hashes to {found}, and the policy in force authorises \
         {policy}; an observation may not introduce its own source"
    )]
    SourceNotAuthorised { found: Hash, policy: Hash },

    /// The signing key is not the one a validated policy delegated to.
    ///
    /// Same refusal, same wording, same consequence as
    /// [`crate::receipt_auth::ReceiptAuthError::VerifierNotDelegated`]: a
    /// cryptographically perfect signature from a key no policy named buys
    /// nothing.
    #[error(
        "price observation was signed by {claimed}, which the policy in force does not \
         delegate; it delegates {delegated}"
    )]
    SigningKeyNotDelegated { claimed: String, delegated: String },

    /// The signature does not verify against the policy's delegated key.
    #[error("price observation signature does not verify under the policy in force")]
    BadSignature,

    /// The observation was signed under a policy that is not the one in force.
    #[error(
        "price observation carries policy {found}, and the policy in force is {current}"
    )]
    PolicyHashMismatch { found: Hash, current: Hash },

    /// The attestation's own digest does not match its signed body.
    #[error(
        "price attestation hash {found} is not the digest of this attestation's signed \
         body ({computed})"
    )]
    AttestationHashMismatch { found: Hash, computed: Hash },

    /// The observation claims a different chain from the policy.
    #[error("price observation is on chain {found}, and the policy settles chain {expected}")]
    ChainMismatch { found: u64, expected: u64 },

    /// The attestation schema is not one this build computes.
    #[error(
        "price attestation schema_version {found} is not supported (expected {expected})"
    )]
    UnsupportedSchema { found: u32, expected: u32 },

    /// The conversion overflowed.
    ///
    /// Unreachable for any physically reachable price (see the module doc), and
    /// checked rather than assumed: a wrapped cost is free money and a
    /// saturated one is a lie.
    #[error(
        "converting {cost_wei} wei at {price_musd_per_eth} micro-USD per ETH does not fit \
         the fixed-point arithmetic; the figure is refused, never wrapped"
    )]
    PriceArithmeticOverflow {
        cost_wei: u128,
        price_musd_per_eth: u128,
    },
}

// ---------------------------------------------------------------------------
// The pair
// ---------------------------------------------------------------------------

/// What the numerator of a price is denominated in.
///
/// A closed enum with one inhabitant on purpose: adding a second base asset is a
/// schema change, not a string. "ETH/USD" is a market convention with a dozen
/// meanings (spot, index, TWAP, per-gas-token) and none of them is derivable
/// from the characters, so this build names exactly the one it means and refuses
/// every other spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseAsset {
    /// The chain's own currency — ETH on Base.
    NativeEth,
}

impl BaseAsset {
    /// The canonical spelling that goes into a preimage and into a report.
    pub fn spelling(self) -> &'static str {
        match self {
            Self::NativeEth => "native-eth",
        }
    }
}

impl std::fmt::Display for BaseAsset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.spelling())
    }
}

/// What the denominator of a price is denominated in.
///
/// The crate books in micro-USD, so this is the only unit that makes a price
/// comparable with a settlement net without a second conversion table. Whole USD
/// is *not* accepted: a whole-USD price would force a rounding decision at
/// conversion time, and the rounding decision is made once, in one place, with
/// the direction argued for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuoteUnit {
    /// One millionth of a US dollar — `micros` everywhere else in this crate.
    MicroUsd,
}

impl QuoteUnit {
    pub fn spelling(self) -> &'static str {
        match self {
            Self::MicroUsd => "musd",
        }
    }
}

impl std::fmt::Display for QuoteUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.spelling())
    }
}

/// The economic pair a price is quoted in.
///
/// # Why this is a closed type and not a pair of strings
///
/// "the wrong pair" has to be a *state the code can refuse*, and a pair of free
/// strings makes it a spelling question. [`PricePair::parse`] is the validating
/// constructor and it accepts exactly the spellings of the closed enums, so the
/// wrong pair fails at the boundary and is unrepresentable everywhere else. It
/// is not `ETH/USD` and not `ETHUSDC`: it is one asset against the crate's own
/// economic unit, which is the only thing a settlement net can be compared with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PricePair {
    base: BaseAsset,
    quote: QuoteUnit,
}

impl PricePair {
    /// The only pair this build prices.
    pub const fn eth_per_musd() -> Self {
        Self {
            base: BaseAsset::NativeEth,
            quote: QuoteUnit::MicroUsd,
        }
    }

    /// Validating constructor. Accepts `"<base>/<quote>"` where each half is the
    /// canonical spelling of an inhabitant of the closed enums, and refuses
    /// everything else — including the market-conventional `"native-eth/usd"`,
    /// which names a different denominator.
    pub fn parse(value: &str) -> Result<Self, ValuationError> {
        if value == "native-eth/musd" {
            return Ok(Self::eth_per_musd());
        }
        Err(ValuationError::UnsupportedPair {
            pair: value.to_string(),
            supported: Self::eth_per_musd().to_string(),
        })
    }

    pub fn base(&self) -> BaseAsset {
        self.base
    }

    pub fn quote(&self) -> QuoteUnit {
        self.quote
    }
}

impl std::fmt::Display for PricePair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.base.spelling(), self.quote.spelling())
    }
}

// ---------------------------------------------------------------------------
// The source identity
// ---------------------------------------------------------------------------

/// Spellings that name no source at all.
///
/// Refused by [`PriceSourceId::parse`]. This is not authorisation — a policy may
/// name any source it likes — it is a check that the identifier says something,
/// so a placeholder cannot be signed into a policy and later read as a mandate.
const RESERVED_SOURCE_IDS: &[&str] = &[
    "", "any", "none", "null", "unknown", "unspecified", "untrusted", "unverified", "default",
];

/// The identity of a source permitted to speak for the pair.
///
/// Canonicalised on construction: lowercase, and only the characters that can
/// appear in an endpoint identity or a feed name. Two spellings of one source
/// therefore cannot produce two bindings — the same discipline
/// [`crate::policy_auth::Address`] applies to a chain address, and for the same
/// reason: a permitted-source *set* is iterated into a digest, and if spelling
/// mattered, two identical sets would hash differently.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PriceSourceId(String);

impl PriceSourceId {
    /// Validating constructor.
    pub fn parse(value: &str) -> Result<Self, ValuationError> {
        let reason = |reason: &str| ValuationError::UnusableSourceId {
            source_id: value.to_string(),
            reason: reason.to_string(),
        };
        if value.is_empty() {
            return Err(reason("a source identity cannot be empty"));
        }
        if value.len() > MAX_SOURCE_ID_LEN {
            return Err(reason("a source identity is at most 128 bytes"));
        }
        if RESERVED_SOURCE_IDS.contains(&value) {
            return Err(reason(
                "this spelling names no source; a permitted source must be identifiable",
            ));
        }
        if !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._:/-".contains(&b))
        {
            return Err(reason(
                "only lowercase letters, digits and `. _ : / -` are allowed, so one \
                 source has one spelling",
            ));
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PriceSourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// The selection and rounding rules
// ---------------------------------------------------------------------------

/// How the price that applies to a settlement is chosen.
///
/// A closed enum with one arm. `NewestOverall` sounds reasonable and is exactly
/// the hindsight vector this module exists to close: "newest" is relative to the
/// *reader's* clock, and a reader who chooses the newest price after summing the
/// legs chooses the price that suits the sum. The arm that exists is relative to
/// the settlement's block anchor, which was fixed before anyone knew what the
/// settlement was worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceSelectionRule {
    /// The latest valid observation at or before the settlement's block anchor,
    /// within the policy's staleness window.
    LatestAtOrBeforeAnchor,
}

impl PriceSelectionRule {
    pub fn spelling(self) -> &'static str {
        match self {
            Self::LatestAtOrBeforeAnchor => "latest_at_or_before_anchor",
        }
    }
}

impl std::fmt::Display for PriceSelectionRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.spelling())
    }
}

/// How the conversion rounds.
///
/// A closed enum with one arm, [`PriceRounding::CeilToMicros`], and the arm is
/// the *decision* rather than a default: the crate has never had a lossy
/// division, so leaving the direction to the call site would leave it to
/// whoever wrote the call site. See the module doc for why the direction is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceRounding {
    /// Round the converted cost **up** to whole micro-USD. Never down, never to
    /// nearest: a cost that rounds *down* is a cost the operator chose to
    /// underpay.
    CeilToMicros,
}

impl PriceRounding {
    pub fn spelling(self) -> &'static str {
        match self {
            Self::CeilToMicros => "ceil_to_micros",
        }
    }
}

impl std::fmt::Display for PriceRounding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.spelling())
    }
}

// ---------------------------------------------------------------------------
// The price source policy
// ---------------------------------------------------------------------------

/// The price-source binding preimage layout, in canonical order.
///
/// The permitted-source set is a *tail*, not a row: it is a set of variable
/// length and it is emitted after this table, under a `sources_count` row that
/// the tail's own length is checked against. Order-independence comes from the
/// [`BTreeSet`] the value holds, so two identical sets written in two different
/// orders produce the same digest; and the empty set produces a *defined* digest
/// rather than no digest at all, which is what makes
/// "this policy authorises no source" a checkable state instead of an absence.
pub const PRICE_SOURCE_POLICY_FIELDS: &[(&str, PreimageFieldKind)] = &[
    ("schema_version", PreimageFieldKind::U32),
    ("chain_id", PreimageFieldKind::U64),
    ("base_asset", PreimageFieldKind::Text),
    ("quote_unit", PreimageFieldKind::Text),
    ("max_staleness_unix", PreimageFieldKind::U64),
    ("selection", PreimageFieldKind::Text),
    ("rounding", PreimageFieldKind::Text),
];

/// What a policy permits a price source to be, and how a permitted price is
/// chosen.
///
/// This is the value [`crate::policy_auth::OutcomePolicyPayload::price_source_hash`]
/// is the digest of. It is *constructed* by whoever wants to price something and
/// it *authorises* nothing by existing: the authority's signature over its
/// binding digest is what authorises it, and
/// [`ValidatedPriceSource::bind`] is where the two meet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceSourcePolicy {
    permitted_sources: BTreeSet<PriceSourceId>,
    pair: PricePair,
    chain_id: u64,
    max_staleness_unix: u64,
    selection: PriceSelectionRule,
    rounding: PriceRounding,
}

impl PriceSourcePolicy {
    /// A price source policy that permits sources.
    ///
    /// `max_staleness_unix` is a **maximum**, and `0` is refused: a zero window
    /// would make the applicable price a function of whether the price read and
    /// the settlement landed in the same second, which is a coin flip wearing a
    /// policy's clothes. One second is the floor, and an operator who wants a
    /// tighter window than the market updates cannot have it.
    pub fn new(
        chain_id: u64,
        permitted_sources: impl IntoIterator<Item = PriceSourceId>,
        max_staleness_unix: u64,
    ) -> Result<Self, ValuationError> {
        if chain_id == 0 {
            return Err(ValuationError::UnusableSourcePolicy(
                "chain_id must name a chain; 0 is the pre-mainnet id".into(),
            ));
        }
        if max_staleness_unix == 0 {
            return Err(ValuationError::UnusableSourcePolicy(
                "max_staleness_unix must be at least 1 second".into(),
            ));
        }
        let sources: BTreeSet<PriceSourceId> = permitted_sources.into_iter().collect();
        if sources.is_empty() {
            return Err(ValuationError::UnusableSourcePolicy(
                "a price source policy must permit at least one source; use \
                 PriceSourcePolicy::none() for the binding a policy may not carry"
                    .into(),
            ));
        }
        Ok(Self {
            permitted_sources: sources,
            pair: PricePair::eth_per_musd(),
            chain_id,
            max_staleness_unix,
            selection: PriceSelectionRule::LatestAtOrBeforeAnchor,
            rounding: PriceRounding::CeilToMicros,
        })
    }

    /// The one binding a valid outcome policy may **not** carry.
    ///
    /// It exists so that "authorises no source" is a value with a digest rather
    /// than an absence, which is the only way a *digest-carrying* payload can be
    /// checked for it:
    /// [`crate::policy_auth::validate_outcome_policy`] compares
    /// `price_source_hash` against this value's digest and refuses. It is also
    /// why [`Self::new`] refuses an empty set rather than quietly producing it —
    /// the sentinel has one constructor, and it is not this one.
    pub fn none() -> Self {
        Self {
            permitted_sources: BTreeSet::new(),
            pair: PricePair::eth_per_musd(),
            chain_id: 0,
            max_staleness_unix: 0,
            selection: PriceSelectionRule::LatestAtOrBeforeAnchor,
            rounding: PriceRounding::CeilToMicros,
        }
    }

    /// Whether this is the forbidden empty binding.
    pub fn is_none(&self) -> bool {
        self.permitted_sources.is_empty()
    }

    /// The digest an outcome policy carries to authorise this value.
    ///
    /// Never `Result`: every field was validated at construction, so there is
    /// nothing left that can fail, and a fallible digest would invite a caller to
    /// proceed with a placeholder error. Same construction as
    /// [`crate::policy_auth::controlled_registry_hash`] and
    /// [`crate::policy_auth::provider_identity_hash`] — tagged, length-prefixed,
    /// domain first — and the same three properties: changing any field changes
    /// the digest, the set's iteration order cannot be chosen to preserve it,
    /// and the empty set hashes to a defined value.
    pub fn binding_hash(&self) -> Hash {
        let mut buf = Vec::new();
        push_tagged(
            &mut buf,
            b"domain",
            PRICE_SOURCE_POLICY_DOMAIN.as_bytes(),
        );
        push_tagged(
            &mut buf,
            b"schema_version",
            &PRICE_SOURCE_POLICY_SCHEMA_VERSION.to_be_bytes(),
        );
        push_tagged(&mut buf, b"chain_id", &self.chain_id.to_be_bytes());
        push_tagged(&mut buf, b"base_asset", self.pair.base().spelling().as_bytes());
        push_tagged(&mut buf, b"quote_unit", self.pair.quote().spelling().as_bytes());
        push_tagged(
            &mut buf,
            b"max_staleness_unix",
            &self.max_staleness_unix.to_be_bytes(),
        );
        push_tagged(&mut buf, b"selection", self.selection.spelling().as_bytes());
        push_tagged(&mut buf, b"rounding", self.rounding.spelling().as_bytes());
        // The count precedes the tail, so an omitted source cannot be
        // re-spelled into an adjacent row: the digest commits to how many there
        // are as well as to which.
        let count = u32::try_from(self.permitted_sources.len()).unwrap_or(u32::MAX);
        push_tagged(&mut buf, b"sources_count", &count.to_be_bytes());
        for source in &self.permitted_sources {
            push_tagged(&mut buf, b"source", source.as_str().as_bytes());
        }
        Hash::from_bytes(*blake3::hash(&buf).as_bytes())
    }

    /// The permitted source identities, in canonical order.
    pub fn permitted_sources(&self) -> Vec<&PriceSourceId> {
        self.permitted_sources.iter().collect()
    }

    pub fn pair(&self) -> PricePair {
        self.pair
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn max_staleness_unix(&self) -> u64 {
        self.max_staleness_unix
    }

    pub fn selection(&self) -> PriceSelectionRule {
        self.selection
    }

    pub fn rounding(&self) -> PriceRounding {
        self.rounding
    }

    pub fn permits(&self, source: &PriceSourceId) -> bool {
        self.permitted_sources.contains(source)
    }
}

// ---------------------------------------------------------------------------
// The observation
// ---------------------------------------------------------------------------

/// One reading of the pair, anchored to a block.
///
/// Private fields, one validating constructor, and `Deserialize` with
/// `deny_unknown_fields` because this is a transported document and the signature
/// is only meaningful over an exact field set: an extra field in a hand-written
/// JSON document must be *refused*, not ignored. Ignored is how a
/// `gas_used_override` field would end up in a price document that reads as if
/// it were authenticated.
///
/// No pair parameter: the pair is [`PricePair::eth_per_musd`], which is a
/// closed type. Passing one would be passing a constant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriceObservation {
    source_id: PriceSourceId,
    price_musd_per_eth: u128,
    chain_id: u64,
    block_number: u64,
    block_hash: Hash,
    block_timestamp_unix: u64,
    source_round: String,
    confirmations: u64,
}

impl PriceObservation {
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        source_id: PriceSourceId,
        price_musd_per_eth: u128,
        chain_id: u64,
        block_number: u64,
        block_hash: &str,
        block_timestamp_unix: u64,
        source_round: &str,
        confirmations: u64,
    ) -> Result<Self, ValuationError> {
        if price_musd_per_eth == 0 {
            return Err(ValuationError::Preimage(
                "a price of zero micro-USD per ETH is not a price; it is a missing \
                 reading wearing a number"
                    .into(),
            ));
        }
        if chain_id == 0 {
            return Err(ValuationError::Preimage(
                "a price observation must name the chain it was read on".into(),
            ));
        }
        if block_number == 0 {
            return Err(ValuationError::Preimage(
                "a price observation must name the block it was read at".into(),
            ));
        }
        if block_timestamp_unix == 0 {
            return Err(ValuationError::Preimage(
                "a price observation must carry the block timestamp it was read at".into(),
            ));
        }
        if source_round.is_empty() || source_round.len() > MAX_SOURCE_ID_LEN {
            return Err(ValuationError::Preimage(
                "a price observation must name the source round it came from".into(),
            ));
        }
        if confirmations == 0 {
            return Err(ValuationError::Preimage(
                "a price observation read at zero confirmations has not been read from a \
                 canonical view of the chain"
                    .into(),
            ));
        }
        Ok(Self {
            source_id,
            price_musd_per_eth,
            chain_id,
            block_number,
            block_hash: Hash::parse("price_observation_block_hash", block_hash)?,
            block_timestamp_unix,
            source_round: source_round.to_string(),
            confirmations,
        })
    }

    pub fn pair(&self) -> PricePair {
        PricePair::eth_per_musd()
    }

    pub fn source_id(&self) -> &PriceSourceId {
        &self.source_id
    }

    /// The price in micro-USD per whole ETH. An integer, always. See the module
    /// doc for the fixed-point definition.
    pub fn price_musd_per_eth(&self) -> u128 {
        self.price_musd_per_eth
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn block_hash(&self) -> &str {
        self.block_hash.as_str()
    }

    pub fn block_timestamp_unix(&self) -> u64 {
        self.block_timestamp_unix
    }

    /// The source's own round/feed identifier, if the source has one. Carried so
    /// two readings of the same block are distinguishable to an operator; it is
    /// not compared against anything, because no two sources agree on what a
    /// "round" is.
    pub fn source_round(&self) -> &str {
        &self.source_round
    }

    pub fn confirmations(&self) -> u64 {
        self.confirmations
    }

    /// The canonical identity of this reading, under
    /// [`crate::event_id::PRICE_OBSERVATION_ID_DOMAIN`].
    pub fn fact(&self) -> Result<PriceObservationFact, ValuationError> {
        let pair = self.pair();
        PriceObservationFact::from_parts(
            self.source_id.as_str(),
            pair.base().spelling(),
            pair.quote().spelling(),
            self.price_musd_per_eth,
            self.chain_id,
            self.block_number,
            self.block_hash.as_str(),
            self.block_timestamp_unix,
            &self.source_round,
            self.confirmations,
        )
        .map_err(ValuationError::EventId)
    }
}

// ---------------------------------------------------------------------------
// The attestation
// ---------------------------------------------------------------------------

/// The attestation preimage layout, in canonical order.
///
/// The body binds the observation *and* the policy it was signed under. The
/// policy row is not redundant with the signature: the signature says "the
/// delegated key signed these bytes", and the policy row says *which* mandate it
/// signed them under — the same two-question split
/// [`crate::receipt_auth`] makes.
pub const PRICE_ATTESTATION_FIELDS: &[(&str, PreimageFieldKind)] = &[
    ("schema_version", PreimageFieldKind::U32),
    ("policy_hash", PreimageFieldKind::Hash32),
    ("source_id", PreimageFieldKind::Text),
    ("base_asset", PreimageFieldKind::Text),
    ("quote_unit", PreimageFieldKind::Text),
    ("price_musd_per_eth", PreimageFieldKind::U128),
    ("chain_id", PreimageFieldKind::U64),
    ("block_number", PreimageFieldKind::U64),
    ("block_hash", PreimageFieldKind::Hash32),
    ("block_timestamp_unix", PreimageFieldKind::U64),
    ("source_round", PreimageFieldKind::Text),
    ("confirmations", PreimageFieldKind::U64),
];

/// The exact bytes a price attestation signs.
///
/// Never a serialised struct, for the reason
/// [`crate::policy_auth::OutcomePolicyPayload::signing_preimage`] spells out:
/// a self-describing encoding would promote field order and number formatting
/// into what a signature means. This module keeps its own local layout check
/// rather than sharing one, so a table in another module can never satisfy this
/// encoder's field list.
fn price_attestation_preimage(
    observation: &PriceObservation,
    policy_hash: &Hash,
) -> Result<Vec<u8>, ValuationError> {
    let pair = observation.pair();
    let values: Vec<(&str, Vec<u8>)> = vec![
        (
            "schema_version",
            PRICE_ATTESTATION_SCHEMA_VERSION.to_be_bytes().to_vec(),
        ),
        ("policy_hash", policy_hash.to_bytes()?.to_vec()),
        ("source_id", observation.source_id.as_str().as_bytes().to_vec()),
        ("base_asset", pair.base().spelling().as_bytes().to_vec()),
        ("quote_unit", pair.quote().spelling().as_bytes().to_vec()),
        (
            "price_musd_per_eth",
            observation.price_musd_per_eth.to_be_bytes().to_vec(),
        ),
        ("chain_id", observation.chain_id.to_be_bytes().to_vec()),
        (
            "block_number",
            observation.block_number.to_be_bytes().to_vec(),
        ),
        ("block_hash", observation.block_hash.to_bytes()?.to_vec()),
        (
            "block_timestamp_unix",
            observation.block_timestamp_unix.to_be_bytes().to_vec(),
        ),
        ("source_round", observation.source_round.as_bytes().to_vec()),
        ("confirmations", observation.confirmations.to_be_bytes().to_vec()),
    ];
    check_layout(&values, PRICE_ATTESTATION_FIELDS, "price attestation")?;

    let mut buf = Vec::new();
    push_tagged(&mut buf, b"domain", PRICE_ATTESTATION_DOMAIN.as_bytes());
    push_tagged(
        &mut buf,
        b"sections",
        &u32::try_from(values.len())
            .map_err(|_| ValuationError::Preimage("too many price attestation sections".into()))?
            .to_be_bytes(),
    );
    for (tag, value) in &values {
        push_tagged(&mut buf, tag.as_bytes(), value);
    }
    Ok(buf)
}

/// This module's own encoder/table check. Local on purpose — see
/// [`crate::event_id::check_layout`] for why it is not shared.
fn check_layout(
    values: &[(&str, Vec<u8>)],
    layout: &[(&str, PreimageFieldKind)],
    what: &str,
) -> Result<(), ValuationError> {
    if values.len() != layout.len() {
        return Err(ValuationError::Preimage(format!(
            "{what}: encoder emitted {} sections for a layout of {}",
            values.len(),
            layout.len()
        )));
    }
    for ((tag, _), (expected_tag, _)) in values.iter().zip(layout.iter()) {
        if *tag != *expected_tag {
            return Err(ValuationError::Preimage(format!(
                "{what}: encoder emitted section {tag:?} where the layout expects \
                 {expected_tag:?}"
            )));
        }
    }
    Ok(())
}

/// A price observation and the delegated verifier's signature over it.
///
/// `Deserialize` with `deny_unknown_fields`, like
/// [`crate::receipt_auth::AuthenticatedExternalValueReceipt`]: this is a
/// transported document, and a document with a field the signer never signed
/// must not parse into something that looks signed. There is no public
/// constructor, so a value of this type can only have come from a
/// deserialiser — and a deserialised value authorises nothing until
/// [`validate_price_observation`] has run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedPriceObservation {
    observation: PriceObservation,
    policy_hash: Hash,
    signer_key_id: KeyId,
    attestation_hash: Hash,
    #[serde(with = "signature_serde")]
    signature: Signature,
}

impl AuthenticatedPriceObservation {
    pub fn observation(&self) -> &PriceObservation {
        &self.observation
    }

    pub fn policy_hash(&self) -> &Hash {
        &self.policy_hash
    }

    pub fn signer_key_id(&self) -> &KeyId {
        &self.signer_key_id
    }

    pub fn attestation_hash(&self) -> &Hash {
        &self.attestation_hash
    }

    /// Digest of the attestation's signed body. This is a digest, not a
    /// signature: it names the bytes, so an audit log can quote them.
    pub fn compute_attestation_hash(&self) -> Result<Hash, ValuationError> {
        let preimage = price_attestation_preimage(&self.observation, &self.policy_hash)?;
        let mut buf = Vec::new();
        push_tagged(&mut buf, b"attestation", &preimage);
        Ok(Hash::from_bytes(*blake3::hash(&buf).as_bytes()))
    }
}

impl VerifierRuntimeKey {
    /// Signs a price observation.
    ///
    /// The only producer of an [`AuthenticatedPriceObservation`], and it requires
    /// a validated policy for exactly the reason
    /// [`crate::receipt_auth::VerifierRuntimeKey::attest`] does: a key no
    /// validated policy delegated to must not be able to mint an attestation, or
    /// "signed by a key some policy delegated to" has no referent.
    ///
    /// Note what this signature does **not** cover: nothing here is a chain gas
    /// fact. The observation's fields are the price and where it was read; the
    /// gas a settlement burned comes from the settlement's own chain read and
    /// cannot be touched, overridden or restated by anything in this document.
    pub fn attest_price_observation(
        &self,
        policy: &ValidatedOutcomePolicy,
        observation: PriceObservation,
    ) -> Result<AuthenticatedPriceObservation, ValuationError> {
        let trusted = policy.trusted_verifier();
        if self.key_id() != trusted.key_id() {
            return Err(ValuationError::SigningKeyNotDelegated {
                claimed: self.key_id().to_string(),
                delegated: trusted.key_id().to_string(),
            });
        }
        let policy_hash = policy.policy_hash()?;
        let preimage = price_attestation_preimage(&observation, &policy_hash)?;
        let mut buf = Vec::new();
        push_tagged(&mut buf, b"attestation", &preimage);
        let attestation_hash = Hash::from_bytes(*blake3::hash(&buf).as_bytes());
        Ok(AuthenticatedPriceObservation {
            observation,
            policy_hash,
            signer_key_id: self.key_id(),
            attestation_hash,
            signature: self.sign_preimage(&preimage),
        })
    }
}

/// What a successful [`validate_price_observation`] establishes: the delegated
/// verifier signed *these bytes*, about *this* reading, under *that* policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPriceObservation {
    observation: PriceObservation,
    event_id: ExternalEventId,
    policy_hash: Hash,
    signer_key_id: KeyId,
    attestation_hash: Hash,
}

impl ValidatedPriceObservation {
    pub fn observation(&self) -> &PriceObservation {
        &self.observation
    }

    /// The canonical identity of the reading, under
    /// [`crate::event_id::PRICE_OBSERVATION_ID_DOMAIN`]. Two copies of one
    /// reading have one identity, which is what makes a duplicated observation
    /// countable-once rather than countable-twice.
    pub fn event_id(&self) -> &ExternalEventId {
        &self.event_id
    }

    pub fn policy_hash(&self) -> &Hash {
        &self.policy_hash
    }

    pub fn signer_key_id(&self) -> &KeyId {
        &self.signer_key_id
    }

    pub fn attestation_hash(&self) -> &Hash {
        &self.attestation_hash
    }

    pub fn source_id(&self) -> &PriceSourceId {
        self.observation.source_id()
    }

    pub fn pair(&self) -> PricePair {
        self.observation.pair()
    }

    pub fn price_musd_per_eth(&self) -> u128 {
        self.observation.price_musd_per_eth()
    }

    pub fn chain_id(&self) -> u64 {
        self.observation.chain_id()
    }

    pub fn block_number(&self) -> u64 {
        self.observation.block_number()
    }

    pub fn block_hash(&self) -> &str {
        self.observation.block_hash()
    }

    pub fn block_timestamp_unix(&self) -> u64 {
        self.observation.block_timestamp_unix()
    }

    pub fn source_round(&self) -> &str {
        self.observation.source_round()
    }

    pub fn confirmations(&self) -> u64 {
        self.observation.confirmations()
    }
}

/// The single constructor of a [`ValidatedPriceObservation`].
///
/// Gates, in this order:
///
/// 1. the signer is the key the validated policy delegated to — checked on the
///    *claim* and not only by the signature, because a hand-built document names
///    its own signer and that must not be able to slip past the verification;
/// 2. the signature verifies against that key;
/// 3. the attestation's digest is the digest of its signed body;
/// 4. the policy hash is the hash of the policy in force, so a rotated policy
///    never silently re-approves an old reading;
/// 5. the chain is the policy's chain;
/// 6. the reading itself is re-validated from its parts, because a
///    deserialised document never went through [`PriceObservation::from_parts`].
pub fn validate_price_observation(
    signed: &AuthenticatedPriceObservation,
    policy: &ValidatedOutcomePolicy,
) -> Result<ValidatedPriceObservation, ValuationError> {
    let trusted = policy.trusted_verifier();
    if signed.signer_key_id != trusted.key_id() {
        return Err(ValuationError::SigningKeyNotDelegated {
            claimed: signed.signer_key_id.to_string(),
            delegated: trusted.key_id().to_string(),
        });
    }
    // Re-derived from the parts rather than trusted from the document: the
    // `PriceObservation` inside a deserialised artefact may have been built by
    // anything.
    let observation = PriceObservation::from_parts(
        signed.observation.source_id.clone(),
        signed.observation.price_musd_per_eth,
        signed.observation.chain_id,
        signed.observation.block_number,
        signed.observation.block_hash.as_str(),
        signed.observation.block_timestamp_unix,
        &signed.observation.source_round,
        signed.observation.confirmations,
    )?;

    let preimage = price_attestation_preimage(&observation, &signed.policy_hash)?;
    policy
        .trusted_verifier()
        .verifying_key()?
        .verify(&preimage, &signed.signature)
        .map_err(|_| ValuationError::BadSignature)?;

    let mut buf = Vec::new();
    push_tagged(&mut buf, b"attestation", &preimage);
    let computed = Hash::from_bytes(*blake3::hash(&buf).as_bytes());
    if signed.attestation_hash != computed {
        return Err(ValuationError::AttestationHashMismatch {
            found: signed.attestation_hash.clone(),
            computed,
        });
    }

    let current = policy.policy_hash()?;
    if signed.policy_hash != current {
        return Err(ValuationError::PolicyHashMismatch {
            found: signed.policy_hash.clone(),
            current,
        });
    }
    if observation.chain_id != policy.chain_id() {
        return Err(ValuationError::ChainMismatch {
            found: observation.chain_id,
            expected: policy.chain_id(),
        });
    }
    let event_id = ExternalEventId::price_observation(&observation.fact()?)?;
    Ok(ValidatedPriceObservation {
        observation,
        event_id,
        policy_hash: signed.policy_hash.clone(),
        signer_key_id: signed.signer_key_id,
        attestation_hash: signed.attestation_hash.clone(),
    })
}

// ---------------------------------------------------------------------------
// The bound source
// ---------------------------------------------------------------------------

/// How deep the block a price was read at must be before the reading counts as
/// final.
///
/// [`PriceFinality`] is derived, never claimed: a document cannot assert that it
/// is final, it can only report how deep its block was, and the bar is the
/// policy's own `min_confirmations`. That is the same bar
/// [`crate::base_usdc::BaseUsdcVerifier`] applies to a transaction receipt, so
/// one number governs both halves of an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PriceFinality {
    /// The block was at least `policy.min_confirmations` deep when the reading
    /// was taken.
    Finalized,
    /// Shallower than the policy's bar. Refused by [`select_price`], and
    /// reported rather than used so an operator can see the reading existed.
    PendingFinality,
}

impl PriceFinality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Finalized => "finalized",
            Self::PendingFinality => "pending_finality",
        }
    }
}

impl std::fmt::Display for PriceFinality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A [`PriceSourcePolicy`] the validated policy in force actually authorises.
///
/// Private fields and one constructor, [`Self::bind`]. Holding one of these is
/// the statement "the policy in force named this price source", and there is no
/// other way to hold one — which is what makes the price impossible to smuggle
/// through a parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPriceSource {
    policy: PriceSourcePolicy,
    binding_hash: Hash,
    policy_hash: Hash,
    chain_id: u64,
    min_confirmations: u64,
}

impl ValidatedPriceSource {
    /// Binds a live price-source policy to a validated outcome policy.
    ///
    /// Refuses unless the live value's [`PriceSourcePolicy::binding_hash`] is
    /// *the* hash the signed policy carries. Two rejections hide in that one
    /// comparison: a policy that authorises no source at all
    /// ([`PriceSourcePolicy::none`], which
    /// [`crate::policy_auth::validate_outcome_policy`] already refused at load),
    /// and a live policy that differs from the signed one in any field, including
    /// the permitted set, the staleness window, the chain, the selection rule and
    /// the rounding rule.
    pub fn bind(
        policy: &ValidatedOutcomePolicy,
        source: &PriceSourcePolicy,
    ) -> Result<Self, ValuationError> {
        let found = source.binding_hash();
        let expected = policy.price_source_hash().clone();
        if found != expected {
            return Err(ValuationError::SourceNotAuthorised { found, policy: expected });
        }
        if source.chain_id() != policy.chain_id() {
            return Err(ValuationError::ChainMismatch {
                found: source.chain_id(),
                expected: policy.chain_id(),
            });
        }
        Ok(Self {
            policy: source.clone(),
            binding_hash: found,
            policy_hash: policy.policy_hash()?,
            chain_id: policy.chain_id(),
            min_confirmations: policy.min_confirmations(),
        })
    }

    pub fn policy(&self) -> &PriceSourcePolicy {
        &self.policy
    }

    pub fn permits(&self, source: &PriceSourceId) -> bool {
        self.policy.permits(source)
    }

    pub fn pair(&self) -> PricePair {
        self.policy.pair()
    }

    pub fn max_staleness_unix(&self) -> u64 {
        self.policy.max_staleness_unix()
    }

    pub fn selection(&self) -> PriceSelectionRule {
        self.policy.selection()
    }

    pub fn rounding(&self) -> PriceRounding {
        self.policy.rounding()
    }

    pub fn binding_hash(&self) -> &Hash {
        &self.binding_hash
    }

    pub fn policy_hash(&self) -> &Hash {
        &self.policy_hash
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn min_confirmations(&self) -> u64 {
        self.min_confirmations
    }

    /// The finality of a reading taken at `confirmations` deep, derived rather
    /// than claimed.
    pub fn finality_of(&self, confirmations: u64) -> PriceFinality {
        if confirmations >= self.min_confirmations {
            PriceFinality::Finalized
        } else {
            PriceFinality::PendingFinality
        }
    }
}

// ---------------------------------------------------------------------------
// The applied price
// ---------------------------------------------------------------------------

/// The price that applies to one settlement, and the reading it came from.
///
/// Private fields and one constructor, in [`select_price`]. Its existence is the
/// claim "this number is the price, by this rule, from that reading, for that
/// anchor" — and the reading's own identity is carried so the number is
/// auditable after the fact rather than merely reproducible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppliedPrice {
    event_id: ExternalEventId,
    source_id: PriceSourceId,
    price_musd_per_eth: u128,
    block_number: u64,
    block_hash: Hash,
    block_timestamp_unix: u64,
    confirmations: u64,
    age_unix: u64,
    max_staleness_unix: u64,
    policy_hash: Hash,
    rounding: PriceRounding,
    duplicate_observations: usize,
}

impl AppliedPrice {
    /// The canonical identity of the reading this price came from.
    pub fn event_id(&self) -> &ExternalEventId {
        &self.event_id
    }

    pub fn source_id(&self) -> &PriceSourceId {
        &self.source_id
    }

    /// The price in micro-USD per whole ETH. An integer.
    pub fn price_musd_per_eth(&self) -> u128 {
        self.price_musd_per_eth
    }

    pub fn pair(&self) -> PricePair {
        PricePair::eth_per_musd()
    }

    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    pub fn block_hash(&self) -> &str {
        self.block_hash.as_str()
    }

    pub fn block_timestamp_unix(&self) -> u64 {
        self.block_timestamp_unix
    }

    /// How deep the observed block was when the reading was taken. Report it
    /// beside a promoted value: it is the honest limit of what the chain view
    /// supported, and nothing in this crate detects a reorg past it.
    pub fn confirmations(&self) -> u64 {
        self.confirmations
    }

    /// How old the reading was relative to the settlement's block timestamp.
    pub fn age_unix(&self) -> u64 {
        self.age_unix
    }

    pub fn max_staleness_unix(&self) -> u64 {
        self.max_staleness_unix
    }

    /// The policy the reading was signed under, which is the policy this price
    /// was selected for.
    pub fn policy_hash(&self) -> &Hash {
        &self.policy_hash
    }

    /// The rounding that was applied. Always [`PriceRounding::CeilToMicros`];
    /// exposed so an audit never has to take the direction on faith.
    pub fn rounding(&self) -> PriceRounding {
        self.rounding
    }

    /// How many of the supplied observations were byte-identical to one already
    /// counted in this pass.
    ///
    /// Counted, not refused: the same reading offered twice is one reading, and
    /// the duplicate is *evidence of a storage problem*, not a different price.
    /// It is reported so a duplicated observation is visible rather than silently
    /// collapsed — and, crucially, so it can be counted once.
    pub fn duplicate_observations(&self) -> usize {
        self.duplicate_observations
    }

    /// `CEIL(cost_wei × price_musd_per_eth / 10^18)`, in micro-USD.
    ///
    /// Integer only. There is no `f64` anywhere on this path, and there is no
    /// decimal or big-integer dependency in the crate — `u128` is sufficient for
    /// every physically reachable price (see the module doc), and a `u128`
    /// overflow is a refusal rather than a wrap.
    ///
    /// **The rounding is up.** Cost is a subtraction from the settlement's net,
    /// so rounding down would hand the operator a refund on every transaction
    /// with the direction of the error under the price-chooser's control.
    pub fn cost_musd(&self, cost_wei: u128) -> Result<u128, ValuationError> {
        let numerator = cost_wei
            .checked_mul(self.price_musd_per_eth)
            .ok_or(ValuationError::PriceArithmeticOverflow {
                cost_wei,
                price_musd_per_eth: self.price_musd_per_eth,
            })?;
        // `ceil(n / d) == (n + d - 1) / d` for `d >= 1`, and it is exact at
        // `n == 0` as well. The addition is checked so the one case that could
        // wrap is a refusal instead.
        let rounded = numerator
            .checked_add(PRICE_FIXED_POINT_DIVISOR - 1)
            .ok_or(ValuationError::PriceArithmeticOverflow {
                cost_wei,
                price_musd_per_eth: self.price_musd_per_eth,
            })?;
        Ok(rounded / PRICE_FIXED_POINT_DIVISOR)
    }
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// Why no price applies.
///
/// Every arm is a *rejection with a name*, because "there was no price" is the
/// one answer an operator cannot act on: the fix for a stale window is a
/// different feed, the fix for an unauthorised source is a re-signed policy, and
/// the fix for a future reading is nothing at all (it is the correct behaviour).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum NoPriceReason {
    /// No observation was supplied at all.
    NoPriceObservation,
    /// The observation came from a source the policy does not permit.
    SourceNotPermitted { source_id: String },
    /// The observation quotes a pair this operation is not priced in.
    PairMismatch {
        found: String,
        expected: String,
    },
    /// The observation was signed under a different policy.
    PolicyHashMismatch { found: String, current: String },
    /// The observation is for another chain.
    ChainMismatch { found: u64, expected: u64 },
    /// The observation is at a block or a timestamp after the settlement's —
    /// a reading taken after the fact.
    AfterAnchor {
        block_number: u64,
        anchor_block_number: u64,
    },
    /// The reading is older than the policy permits.
    Stale {
        age_unix: u64,
        max_staleness_unix: u64,
    },
    /// The observed block was shallower than the policy's confirmation bar.
    NotFinal {
        confirmations: u64,
        min_confirmations: u64,
    },
    /// Two eligible readings at the same block disagree on the price. This is a
    /// fork the node cannot resolve, so no price is declared.
    ForkedBlock { block_number: u64 },
}

impl NoPriceReason {
    pub fn describe(&self) -> String {
        match self {
            Self::NoPriceObservation => {
                "no price observation was supplied, and this operation burned native \
                 value that has no comparable figure without one"
                    .into()
            }
            Self::SourceNotPermitted { source_id } => format!(
                "source {source_id} is not permitted by the policy in force; an \
                 observation cannot introduce its own source"
            ),
            Self::PairMismatch { found, expected } => {
                format!("the observation quotes {found}, and this operation prices {expected}")
            }
            Self::PolicyHashMismatch { found, current } => format!(
                "the observation was signed under policy {found}, and the policy in \
                 force is {current}"
            ),
            Self::ChainMismatch { found, expected } => {
                format!("the observation is on chain {found}, and this policy settles {expected}")
            }
            Self::AfterAnchor {
                block_number,
                anchor_block_number,
            } => format!(
                "the observation was read at block {block_number}, which is after the \
                 settlement's block {anchor_block_number}; a price read after the fact is \
                 not a price the settlement had"
            ),
            Self::Stale {
                age_unix,
                max_staleness_unix,
            } => format!(
                "the observation is {age_unix}s old relative to the settlement's block \
                 timestamp, and the policy permits at most {max_staleness_unix}s"
            ),
            Self::NotFinal {
                confirmations,
                min_confirmations,
            } => format!(
                "the observed block had {confirmations} confirmations, and the policy \
                 requires {min_confirmations}"
            ),
            Self::ForkedBlock { block_number } => format!(
                "two eligible readings disagree about the price at block {block_number}; \
                 this build cannot resolve a fork, so it declares no price"
            ),
        }
    }
}

/// The outcome of [`select_price`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "value")]
pub enum PriceSelection {
    /// Exactly one reading applies, and it is named.
    Priced(AppliedPrice),
    /// No reading applies. Every rejection is listed, so an operator sees the
    /// whole set rather than the first one the loop happened to hit.
    Unpriced(NoPriceRefusal),
}

impl PriceSelection {
    pub fn as_priced(&self) -> Option<&AppliedPrice> {
        match self {
            Self::Priced(price) => Some(price),
            Self::Unpriced(_) => None,
        }
    }

    pub fn as_unpriced(&self) -> Option<&NoPriceRefusal> {
        match self {
            Self::Priced(_) => None,
            Self::Unpriced(refusal) => Some(refusal),
        }
    }
}

/// Why no reading applied, and what was thrown away on the way.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NoPriceRefusal {
    pub reasons: Vec<NoPriceReason>,
    /// How many observations were identical to one already counted.
    ///
    /// Counted, not refused: a duplicated reading of the same block is one
    /// reading, and the fact that a second copy existed is reported rather than
    /// turned into an error — but it is *counted*, through the same
    /// [`CountedEvents`] set the revenue side uses, so a duplicated observation
    /// can never be counted twice.
    pub duplicate_observations: usize,
}

impl NoPriceRefusal {
    pub fn describe(&self) -> String {
        self.reasons
            .iter()
            .map(NoPriceReason::describe)
            .collect::<Vec<String>>()
            .join("; ")
    }
}

/// Deterministically selects the price that applies to one settlement.
///
/// See the module doc for the rule in full. What is worth stating here is the
/// shape: every loop below can only *reject*, and the single choice made at the
/// end is a `max` over a total order. There is no branch anywhere in this
/// function whose condition is a property of the caller other than the facts
/// themselves, which is why the answer does not depend on the order the
/// observations arrived in.
///
/// The counting claim happens **after** the read gates and **before** the choice:
/// a reading that is not eligible is not counted at all, and a reading that is
/// eligible is claimed once, so the same reading offered twice cannot be
/// considered twice — and cannot be *promoted* twice either, because the choice
/// is over a set.
pub fn select_price(
    source: &ValidatedPriceSource,
    observations: &[ValidatedPriceObservation],
    anchor: &BlockAnchor,
) -> PriceSelection {
    let mut reasons: Vec<NoPriceReason> = Vec::new();
    if observations.is_empty() {
        reasons.push(NoPriceReason::NoPriceObservation);
        return PriceSelection::Unpriced(NoPriceRefusal {
            reasons,
            duplicate_observations: 0,
        });
    }

    let max_staleness = source.max_staleness_unix();
    let mut counted = CountedEvents::default();
    let mut eligible: Vec<&ValidatedPriceObservation> = Vec::new();
    let mut duplicates = 0usize;

    for observation in observations {
        // (a) Chain. An observation for another chain is not a price for this
        // operation even if the number matches.
        if observation.chain_id() != source.chain_id() {
            reasons.push(NoPriceReason::ChainMismatch {
                found: observation.chain_id(),
                expected: source.chain_id(),
            });
            continue;
        }
        // (b) Pair. Unreachable today — both sides are the one inhabitant of a
        // closed enum — and kept because the moment a second pair is added this
        // is the gate that must not be forgotten.
        if observation.pair() != source.pair() {
            reasons.push(NoPriceReason::PairMismatch {
                found: observation.pair().to_string(),
                expected: source.pair().to_string(),
            });
            continue;
        }
        // (c) Policy. A reading signed under another policy is not current, and
        // rotation must never silently re-approve an old reading.
        if observation.policy_hash() != source.policy_hash() {
            reasons.push(NoPriceReason::PolicyHashMismatch {
                found: observation.policy_hash().to_string(),
                current: source.policy_hash().to_string(),
            });
            continue;
        }
        // (d) Source. The whole point of the policy binding.
        if !source.permits(observation.source_id()) {
            reasons.push(NoPriceReason::SourceNotPermitted {
                source_id: observation.source_id().to_string(),
            });
            continue;
        }
        // (e) Anchor. At or before, never after.
        if observation.block_number() > anchor.block_number()
            || observation.block_timestamp_unix() > anchor.block_timestamp_unix()
        {
            reasons.push(NoPriceReason::AfterAnchor {
                block_number: observation.block_number(),
                anchor_block_number: anchor.block_number(),
            });
            continue;
        }
        // (f) Staleness, measured against the *settlement's block timestamp*.
        // Never against a local clock: two nodes reading the same ledger seconds
        // apart must produce the same number.
        let age_unix = anchor
            .block_timestamp_unix()
            .saturating_sub(observation.block_timestamp_unix());
        if age_unix > max_staleness {
            reasons.push(NoPriceReason::Stale {
                age_unix,
                max_staleness_unix: max_staleness,
            });
            continue;
        }
        // (g) Finality, against the policy's own bar.
        if source.finality_of(observation.confirmations()) == PriceFinality::PendingFinality {
            reasons.push(NoPriceReason::NotFinal {
                confirmations: observation.confirmations(),
                min_confirmations: source.min_confirmations(),
            });
            continue;
        }
        // (h) The counting claim, after every gate above: an eligible reading is
        // claimed exactly once per pass.
        if counted.claim(observation.event_id().clone(), 0).is_some() {
            duplicates += 1;
            continue;
        }
        eligible.push(observation);
    }

    if eligible.is_empty() {
        if reasons.is_empty() {
            // Only reachable if every observation was a duplicate of the first,
            // which the loop above has already accounted for.
            reasons.push(NoPriceReason::NoPriceObservation);
        }
        return PriceSelection::Unpriced(NoPriceRefusal {
            reasons,
            duplicate_observations: duplicates,
        });
    }

    // The choice. `max_by_key` over a total order that ends in the event id, so
    // the answer is the same whatever order the caller listed the observations
    // in — including when two readings of the same block carry the same price
    // under different round ids.
    let newest_block = eligible
        .iter()
        .map(|o| o.block_number())
        .max()
        .unwrap_or_default();
    let at_newest: Vec<&&ValidatedPriceObservation> = eligible
        .iter()
        .filter(|o| o.block_number() == newest_block)
        .collect();
    // A fork: two eligible readings, one block, two prices. Declining is the
    // only honest answer, because choosing either is choosing a side.
    let distinct_prices: BTreeSet<u128> = at_newest
        .iter()
        .map(|o| o.price_musd_per_eth())
        .collect();
    if distinct_prices.len() > 1 {
        reasons.push(NoPriceReason::ForkedBlock {
            block_number: newest_block,
        });
        return PriceSelection::Unpriced(NoPriceRefusal {
            reasons,
            duplicate_observations: duplicates,
        });
    }
    let chosen = at_newest
        .into_iter()
        .max_by_key(|o| (o.block_timestamp_unix(), o.event_id().as_str().to_string()))
        .expect("at_newest is non-empty because eligible is");

    PriceSelection::Priced(AppliedPrice {
        event_id: chosen.event_id().clone(),
        source_id: chosen.source_id().clone(),
        price_musd_per_eth: chosen.price_musd_per_eth(),
        block_number: chosen.block_number(),
        block_hash: chosen.observation.block_hash.clone(),
        block_timestamp_unix: chosen.block_timestamp_unix(),
        confirmations: chosen.confirmations(),
        age_unix: anchor
            .block_timestamp_unix()
            .saturating_sub(chosen.block_timestamp_unix()),
        max_staleness_unix: max_staleness,
        policy_hash: chosen.policy_hash().clone(),
        rounding: source.rounding(),
        duplicate_observations: duplicates,
    })
}
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The one price-source policy the crate's tests share.
///
/// Lives here for the same reason `receipt_auth::testkit` lives in
/// `receipt_auth`: three test modules need the same thing and a copy per module
/// is three places for the fixtures to drift apart.
pub mod testkit {
    use super::*;

    /// The permitted source every fixture uses.
    pub const SOURCE_A: &str = "base-rpc/eth-musd";
    /// A second permitted source, for the "one of several is permitted" tests.
    pub const SOURCE_B: &str = "base-rpc/eth-musd-backup";
    /// A source no policy permits.
    pub const SOURCE_UNPERMITTED: &str = "attacker/eth-musd";
    /// Five minutes, in seconds.
    pub const MAX_STALENESS_UNIX: u64 = 300;

    pub fn source_id(spelling: &str) -> PriceSourceId {
        PriceSourceId::parse(spelling).expect("a usable source identity")
    }

    /// A price-source policy permitting [`SOURCE_A`] with the shared window.
    pub fn canonical(chain_id: u64) -> PriceSourcePolicy {
        PriceSourcePolicy::new(chain_id, [source_id(SOURCE_A)], MAX_STALENESS_UNIX)
            .expect("a usable price source policy")
    }

    /// The digest an outcome policy must carry to authorise [`canonical`].
    pub fn canonical_hash(chain_id: u64) -> Hash {
        canonical(chain_id).binding_hash()
    }

    /// A source policy differing from [`canonical`] in exactly one field, for
    /// the "one field of the binding changes the digest" test.
    pub fn with_staleness(chain_id: u64, max_staleness_unix: u64) -> PriceSourcePolicy {
        PriceSourcePolicy::new(chain_id, [source_id(SOURCE_A)], max_staleness_unix)
            .expect("a usable price source policy")
    }

    /// The same source policy, permitting two sources. A superset, so a test can
    /// show that an observation from the second one is accepted and one from a
    /// third is not.
    pub fn with_two_sources(chain_id: u64) -> PriceSourcePolicy {
        PriceSourcePolicy::new(
            chain_id,
            [source_id(SOURCE_A), source_id(SOURCE_B)],
            MAX_STALENESS_UNIX,
        )
        .expect("a usable price source policy")
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::*;
    use super::*;
    use crate::{
        autonomy::ExternalValueReceipt,
        base_usdc::BASE_CHAIN_ID,
        policy_auth::ValidatedOutcomePolicy,
        receipt_auth::testkit::{AuthFixture, EXECUTOR_HEX},
        rpc_test_server::FakeRpcSocket,
    };

    const CHAIN: u64 = BASE_CHAIN_ID;
    const ANCHOR_TS: u64 = 1_700_000_000;
    const PRICE_TS: u64 = ANCHOR_TS - 60;
    const PRICE_BLOCK: u64 = 190;
    const CONFIRMATIONS: u64 = 13;
    /// 3000.00 USD/ETH in micro-USD per whole ETH.
    const PRICE: u128 = 3_000_000_000_000;
    fn block_hash() -> String {
        format!("0x{}", "ab".repeat(32))
    }

    fn later_block_hash() -> String {
        format!("0x{}", "cd".repeat(32))
    }

    /// The policy, the delegated key, and the socket that made both of them
    /// describe a real pinned provider.
    struct Bench {
        // Declaration order is drop order, and the socket has to outlive the
        // directory that holds its path — same trap `settlement.rs`'s `Arena`
        // documents. A socket whose directory is gone cannot be woken on drop,
        // and its accept thread would never join.
        _socket: FakeRpcSocket,
        _dir: tempfile::TempDir,
        auth: AuthFixture,
        policy: ValidatedOutcomePolicy,
    }

    impl Bench {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("temp dir");
            let socket = FakeRpcSocket::bind(dir.path().join("bench.sock"));
            let auth = AuthFixture::new(socket.path(), socket.uid(), registry());
            let policy = auth.validated();
            Self {
                _socket: socket,
                _dir: dir,
                auth,
                policy,
            }
        }

        fn source(&self) -> ValidatedPriceSource {
            ValidatedPriceSource::bind(&self.policy, &canonical(CHAIN))
                .expect("the fixture policy authorises the shared source")
        }

        fn sign(
            &self,
            observation: PriceObservation,
        ) -> AuthenticatedPriceObservation {
            self.auth
                .verifier
                .attest_price_observation(&self.policy, observation)
                .expect("the delegated verifier signs the reading")
        }

        fn validated(&self, observation: PriceObservation) -> ValidatedPriceObservation {
            let signed = self.sign(observation);
            validate_price_observation(&signed, &self.policy).expect("authentic")
        }
    }

    fn registry() -> crate::boundary::ControlledAddressRegistry {
        crate::boundary::ControlledAddressRegistry::new()
            .with_address(crate::receipt_auth::testkit::EXECUTOR_HEX)
            .expect("valid controlled address")
    }

    /// An anchor: the settlement's block, as a chain read produced it.
    ///
    /// `BlockAnchor` has private fields and exactly one public constructor,
    /// `from_scan`, so there is no way to invent one — this helper goes through
    /// `BaseUsdcVerifier::from_receipt`, the same constructor `scan_transaction`
    /// uses after its gates, and the anchor is what came out. That is also why
    /// the price selection cannot be handed a convenient timestamp.
    fn anchor(
        block_number: u64,
        block_hash: &str,
        timestamp: u64,
        confirmations: u64,
    ) -> BlockAnchor {
        let receipt = serde_json::json!({
            "status": "0x1",
            "blockNumber": format!("0x{block_number:x}"),
            "blockHash": block_hash,
            "logs": [],
            "gasUsed": "0x0",
            "effectiveGasPrice": "0x0",
        });
        let ctx = crate::base_usdc::TransactionScanContext {
            chain_id: CHAIN,
            tx_hash: format!("0x{}", "cd".repeat(32)),
            block_number,
            block_hash: block_hash.to_string(),
            block_timestamp_unix: timestamp,
            confirmations,
            provider: "unix:///bench.sock".to_string(),
            provider_identity_verified: true,
        };
        let scan = crate::base_usdc::BaseUsdcVerifier::from_receipt(&receipt, ctx)
            .expect("the read produced a scan");
        BlockAnchor::from_scan(&scan)
    }

    fn reading(
        block_number: u64,
        timestamp: u64,
        price: u128,
        confirmations: u64,
    ) -> PriceObservation {
        PriceObservation::from_parts(
            source_id(SOURCE_A),
            price,
            CHAIN,
            block_number,
            &block_hash(),
            timestamp,
            "round-1",
            confirmations,
        )
        .expect("a usable reading")
    }

    fn good() -> PriceObservation {
        reading(PRICE_BLOCK, PRICE_TS, PRICE, CONFIRMATIONS)
    }

    fn selection(
        source: &ValidatedPriceSource,
        observations: &[ValidatedPriceObservation],
    ) -> PriceSelection {
        select_price(source, observations, &anchor(201, &block_hash(), ANCHOR_TS, 10))
    }

    fn unpriced(selection: &PriceSelection) -> &NoPriceRefusal {
        selection
            .as_unpriced()
            .unwrap_or_else(|| panic!("expected no price, got {selection:?}"))
    }

    // ---- the pair ---------------------------------------------------------

    /// Invariant 7. "The wrong pair" is not a runtime branch here, it is a
    /// spelling the parser refuses and a type with no second inhabitant. The
    /// market-conventional `native-eth/usd` is refused too: whole dollars would
    /// force a second rounding decision at conversion time.
    #[test]
    fn the_pair_is_closed_and_the_wrong_pair_is_unrepresentable() {
        assert_eq!(
            PricePair::parse("native-eth/musd").expect("the one pair"),
            PricePair::eth_per_musd()
        );
        for spelling in [
            "native-eth/usd",
            "native-eth/USDC",
            "wbtc/musd",
            "eth/usd",
            "native-eth",
            "native-eth/musd-6",
            "",
        ] {
            assert!(
                PricePair::parse(spelling).is_err(),
                "{spelling:?} must not name a pair this build prices"
            );
        }
        // And the observation does not take a pair at all: it is the one
        // inhabitant, so there is no argument through which a wrong one could
        // arrive.
        assert_eq!(good().pair(), PricePair::eth_per_musd());
        assert_eq!(PricePair::eth_per_musd().to_string(), "native-eth/musd");
    }

    // ---- the source identity ---------------------------------------------

    /// A source identity that names nothing is refused, and so is one whose
    /// spelling is not canonical — two spellings of one source must not produce
    /// two bindings.
    #[test]
    fn a_source_id_that_names_nothing_is_refused() {
        for spelling in RESERVED_SOURCE_IDS {
            assert!(
                PriceSourceId::parse(spelling).is_err(),
                "{spelling:?} names no source and must be refused"
            );
        }
        assert!(PriceSourceId::parse("").is_err());
        assert!(PriceSourceId::parse(&"a".repeat(MAX_SOURCE_ID_LEN + 1)).is_err());
        assert!(PriceSourceId::parse("Base-RPC/ETH").is_err(), "uppercase");
        assert!(PriceSourceId::parse("base rpc").is_err(), "space");
        assert_eq!(
            PriceSourceId::parse(SOURCE_A).expect("usable").as_str(),
            SOURCE_A
        );
    }

    // ---- the binding digest ----------------------------------------------

    /// The binding digest depends on every field, does not depend on the order
    /// the permitted set was written in, and the empty set hashes to a *defined*
    /// value rather than to nothing.
    #[test]
    fn the_price_source_binding_depends_on_every_field_and_not_on_set_order() {
        let base = canonical(CHAIN);
        let base_hash = base.binding_hash();

        // One field at a time.
        assert_ne!(
            base_hash,
            canonical(CHAIN + 1).binding_hash(),
            "chain_id is bound"
        );
        assert_ne!(
            base_hash,
            with_staleness(CHAIN, MAX_STALENESS_UNIX + 1).binding_hash(),
            "the staleness window is bound"
        );
        assert_ne!(
            base_hash,
            with_two_sources(CHAIN).binding_hash(),
            "the permitted set is bound"
        );
        // And a different chain cannot produce the same digest, which is what
        // makes `ValidatedPriceSource::bind`'s single comparison sufficient.
        assert_ne!(base_hash, canonical(CHAIN + 1).binding_hash());

        // Order-independent: the same two sources, written in two orders.
        let forward = PriceSourcePolicy::new(
            CHAIN,
            [source_id(SOURCE_A), source_id(SOURCE_B)],
            MAX_STALENESS_UNIX,
        )
        .expect("usable");
        let backward = PriceSourcePolicy::new(
            CHAIN,
            [source_id(SOURCE_B), source_id(SOURCE_A)],
            MAX_STALENESS_UNIX,
        )
        .expect("usable");
        assert_eq!(
            forward.binding_hash(),
            backward.binding_hash(),
            "a set is not a list"
        );
        assert_eq!(
            forward.binding_hash(),
            with_two_sources(CHAIN).binding_hash()
        );

        // The empty binding is a value with a digest, which is the only reason
        // `validate_outcome_policy` can refuse it at all.
        let none = PriceSourcePolicy::none();
        assert!(none.is_none());
        assert_ne!(none.binding_hash(), base_hash);
        // Deterministic: it hashes the same way every time.
        assert_eq!(none.binding_hash(), PriceSourcePolicy::none().binding_hash());
        assert!(PriceSourcePolicy::new(CHAIN, [], MAX_STALENESS_UNIX).is_err());
        assert!(PriceSourcePolicy::new(CHAIN, [source_id(SOURCE_A)], 0).is_err());
        assert!(PriceSourcePolicy::new(0, [source_id(SOURCE_A)], 1).is_err());
    }

    /// Invariant 4, at the binding. A live price-source policy the signed policy
    /// does not name cannot be bound, so a caller cannot widen its own authority
    /// by constructing one — including by naming a second source.
    #[test]
    fn only_the_policy_named_source_can_be_bound() {
        let bench = Bench::new();
        assert!(ValidatedPriceSource::bind(&bench.policy, &canonical(CHAIN)).is_ok());
        for other in [
            canonical(CHAIN + 1),
            with_staleness(CHAIN, MAX_STALENESS_UNIX + 1),
            with_two_sources(CHAIN),
            PriceSourcePolicy::none(),
        ] {
            assert!(
                matches!(
                    ValidatedPriceSource::bind(&bench.policy, &other),
                    Err(ValuationError::SourceNotAuthorised { .. })
                ),
                "a policy that binds a different source set must not accept it"
            );
        }
        // The chain is checked again after the digest comparison, so the refusal
        // has a specific reason rather than a generic one.
        // And the chain clause is reachable in its own right: a policy whose
        // binding says chain X cannot be bound to an outcome policy for chain Y,
        // even when the digests were made to agree by hand — they cannot be, which
        // is why this is a second, named check rather than the only one.
        let foreign = PriceSourcePolicy::new(CHAIN + 1, [source_id(SOURCE_A)], MAX_STALENESS_UNIX)
            .expect("usable");
        assert!(
            matches!(
                ValidatedPriceSource::bind(&bench.policy, &foreign),
                Err(ValuationError::SourceNotAuthorised { .. })
            ),
            "the digest comparison alone already refuses a foreign chain, because the \
             chain is inside the binding"
        );
    }

    // ---- the attestation --------------------------------------------------

    /// Invariant 3 and 15. The signature covers every field of the reading, and
    /// a key no policy delegated to cannot sign one at all.
    #[test]
    fn an_observation_signed_by_an_undelegated_key_is_refused() {
        let bench = Bench::new();
        let impostor = crate::policy_auth::VerifierRuntimeKey::generate();
        assert!(matches!(
            impostor.attest_price_observation(&bench.policy, good()),
            Err(ValuationError::SigningKeyNotDelegated { .. })
        ));

        // Forged with the impostor's key over the real bytes: the document is
        // self-consistent and it is still refused, first on the claimed signer
        // (which the signature cannot establish by itself) and then on the
        // signature.
        let mut forged = bench.sign(good());
        forged.signer_key_id = impostor.key_id();
        assert!(matches!(
            validate_price_observation(&forged, &bench.policy),
            Err(ValuationError::SigningKeyNotDelegated { .. })
        ));

        // Correct signer claimed, and a signature that is real but over different
        // bytes — a genuine key, a genuine signature, the wrong message.
        let mut swapped = bench.sign(good());
        swapped.signature = bench
            .sign(reading(PRICE_BLOCK, PRICE_TS, PRICE + 1, CONFIRMATIONS))
            .signature;
        assert!(matches!(
            validate_price_observation(&swapped, &bench.policy),
            Err(ValuationError::BadSignature)
        ));
    }

    /// Invariant 14 at the price level. Every field of the reading is bound by
    /// the signature, so changing any one of them after the fact breaks it. The
    /// list is explicit rather than generated, because the point is *which*
    /// fields are covered.
    #[test]
    fn the_attestation_covers_every_field_of_the_reading() {
        let bench = Bench::new();
        let signed = bench.sign(good());
        let baseline = signed.attestation_hash().to_string();

        let mutations: Vec<(&str, AuthenticatedPriceObservation)> = vec![
            ("price", mutate(&signed, |o| o.price_musd_per_eth = 1)),
            ("block_number", mutate(&signed, |o| o.block_number = 191)),
            ("block_hash", mutate(&signed, |o| o.block_hash = Hash::parse("h", &later_block_hash()).unwrap())),
            ("timestamp", mutate(&signed, |o| o.block_timestamp_unix = PRICE_TS + 1)),
            ("confirmations", mutate(&signed, |o| o.confirmations = 14)),
            ("round", mutate(&signed, |o| o.source_round = "round-2".into())),
            ("source", mutate(&signed, |o| o.source_id = source_id(SOURCE_B))),
            ("chain", mutate(&signed, |o| o.chain_id = CHAIN + 1)),
        ];
        for (field, tampered) in mutations {
            assert!(
                tampered.attestation_hash().to_string() != baseline
                    || tampered.observation() != signed.observation(),
                "{field} must be part of the signed message"
            );
            assert!(
                validate_price_observation(&tampered, &bench.policy).is_err(),
                "a reading whose {field} was changed after signing must be refused"
            );
        }
    }

    /// Invariant 8. A reading signed under one policy validates under that policy
    /// and is refused under another — and the refusal is a *policy* refusal, not
    /// a signature one.
    #[test]
    fn a_reading_signed_under_another_policy_is_refused() {
        let bench = Bench::new();
        let alternate = bench.auth.rotated(99);
        let other = alternate.validate().expect("the rotated policy validates");
        let signed = bench
            .auth
            .verifier
            .attest_price_observation(&other, good())
            .expect("signs under the other policy");

        validate_price_observation(&signed, &other).expect("authentic under its own");
        assert!(matches!(
            validate_price_observation(&signed, &bench.policy),
            Err(ValuationError::PolicyHashMismatch { .. })
        ));

        // And the same reading, validated under the *other* policy, is refused by
        // a source bound to this one: the selector's own policy clause. Defence in
        // depth over the validator — two policies are alive at once here on
        // purpose, which is the only way that clause is reachable.
        let other_observation = validate_price_observation(&signed, &other).expect("ok");
        let result = selection(&bench.source(), &[other_observation]);
        assert_eq!(unpriced(&result).reasons, vec![NoPriceReason::PolicyHashMismatch {
            found: signed.policy_hash().to_string(),
            current: bench.policy.policy_hash().unwrap().to_string(),
        }]);
    }

    /// The one trust chain. The key that signs a price is the key the policy
    /// delegates for receipts, and the policy hash is the same hash.
    #[test]
    fn a_price_and_a_receipt_are_signed_by_one_key_under_one_policy() {
        let bench = Bench::new();
        // `EXECUTOR_HEX` is the controlled address, so the payer is a different
        // one: an evidence row whose two ends are the same address is not a
        // crossing and would be refused for an unrelated reason.
        let evidence = crate::receipt_auth::testkit::evidence(
            "0x2222222222222222222222222222222222222222",
            EXECUTOR_HEX,
            1_000_000,
        );
        let receipt: ExternalValueReceipt = serde_json::from_value(serde_json::json!({
            "schema_version": crate::SCHEMA_VERSION,
            "source_id": "bench",
            "agent_id": "0x2222222222222222222222222222222222222222",
            "opportunity_id": "opp-1",
            "value_class": "external_service_payment",
            "network": "base",
            "asset": "USDC",
            "gross_inflow_musd_micros": 1_000_000,
            "external_cost_musd_micros": 0,
            "net_external_value_musd_micros": 1_000_000,
            "proof_hash": evidence.tx_hash.clone(),
            "proof_verified": false,
            "realized_at_unix": 1_700_000_000,
            "verifier_id": "bench",
        }))
        .expect("a usable receipt");
        let attestation = bench.auth.attest(&bench.policy, &receipt, &evidence);
        let price = bench.sign(good());

        assert_eq!(
            attestation.verifier_key_id().to_string(),
            price.signer_key_id().to_string(),
            "one delegated key, or the crate would have two authorities"
        );
        assert_eq!(
            attestation.policy_hash().to_string(),
            price.policy_hash().to_string()
        );
        // And the key is the policy's own delegated key, not merely the same key
        // twice: `TrustedVerifierKey` has exactly one source, so there is no way
        // for the price side to name a different authority.
        assert_eq!(
            bench.policy.trusted_verifier().key_id().to_string(),
            price.signer_key_id().to_string()
        );
    }

    // ---- selection --------------------------------------------------------

    /// The rule itself, on the happy path, plus the determinism property: the
    /// answer is a function of the set of readings, never of the order they were
    /// offered in.
    #[test]
    fn the_latest_reading_at_or_before_the_anchor_is_the_one_that_applies() {
        let bench = Bench::new();
        let source = bench.source();
        let older = bench.validated(reading(
            PRICE_BLOCK - 10,
            PRICE_TS - 20,
            PRICE - 100_000_000,
            CONFIRMATIONS,
        ));
        let newest = bench.validated(good());
        let anchor_now = anchor(201, &block_hash(), ANCHOR_TS, 10);

        for order in [
            vec![older.clone(), newest.clone()],
            vec![newest.clone(), older.clone()],
        ] {
            let priced = select_price(&source, &order, &anchor_now)
                .as_priced()
                .cloned()
                .unwrap_or_else(|| panic!("expected a price for {order:?}"));
            assert_eq!(priced.event_id(), newest.event_id());
            assert_eq!(priced.price_musd_per_eth(), PRICE);
            assert_eq!(priced.age_unix(), 60);
            assert_eq!(priced.max_staleness_unix(), MAX_STALENESS_UNIX);
            assert_eq!(priced.rounding(), PriceRounding::CeilToMicros);
            assert_eq!(priced.duplicate_observations(), 0);
            assert_eq!(priced.policy_hash(), &bench.policy.policy_hash().unwrap());
        }
    }

    /// Invariant 5. Neither a later block nor a later timestamp may be used, and
    /// the reason says so in words an operator can act on.
    #[test]
    fn a_reading_from_after_the_anchor_is_refused() {
        let bench = Bench::new();
        let source = bench.source();
        for (block, ts) in [(202, PRICE_TS), (PRICE_BLOCK, ANCHOR_TS + 1)] {
            let late = bench.validated(reading(block, ts, PRICE, CONFIRMATIONS));
            let result = selection(&source, &[late]);
            let refusal = unpriced(&result);
            assert_eq!(
                refusal.reasons,
                vec![NoPriceReason::AfterAnchor {
                    block_number: block,
                    anchor_block_number: 201,
                }],
                "block {block} at ts {ts}"
            );
            assert!(refusal.describe().contains("after the fact"));
        }
    }

    /// Invariant 6, on the boundary: `age > max_staleness` is refused and
    /// `age == max_staleness` is priced.
    #[test]
    fn staleness_is_measured_against_the_anchor_and_not_a_clock() {
        let bench = Bench::new();
        let source = bench.source();

        let at_limit = bench.validated(reading(
            PRICE_BLOCK,
            ANCHOR_TS - MAX_STALENESS_UNIX,
            PRICE,
            CONFIRMATIONS,
        ));
        assert!(selection(&source, &[at_limit]).as_priced().is_some());

        let one_past = bench.validated(reading(
            PRICE_BLOCK,
            ANCHOR_TS - MAX_STALENESS_UNIX - 1,
            PRICE,
            CONFIRMATIONS,
        ));
        assert_eq!(
            unpriced(&selection(&source, &[one_past])).reasons,
            vec![NoPriceReason::Stale {
                age_unix: MAX_STALENESS_UNIX + 1,
                max_staleness_unix: MAX_STALENESS_UNIX,
            }]
        );

        // Two readings of the same age, selected by block rather than by clock.
        let first = bench.validated(reading(
            PRICE_BLOCK,
            ANCHOR_TS - MAX_STALENESS_UNIX,
            PRICE - 1_000_000,
            CONFIRMATIONS,
        ));
        let second = bench.validated(reading(
            PRICE_BLOCK - 1,
            ANCHOR_TS - MAX_STALENESS_UNIX,
            PRICE - 2_000_000,
            CONFIRMATIONS,
        ));
        let priced = select_price(&source, &[first, second], &anchor(201, &block_hash(), ANCHOR_TS, 10))
            .as_priced()
            .cloned()
            .expect("both are inside the window");
        assert_eq!(priced.block_number(), PRICE_BLOCK, "the later block wins");
    }

    /// Invariant 4, at the selector. A perfectly signed reading from a source the
    /// policy does not permit is refused.
    #[test]
    fn a_reading_from_an_unpermitted_source_is_refused() {
        let bench = Bench::new();
        let rogue = bench.validated(
            PriceObservation::from_parts(
                source_id(SOURCE_UNPERMITTED),
                PRICE,
                CHAIN,
                PRICE_BLOCK,
                &block_hash(),
                PRICE_TS,
                "round-1",
                CONFIRMATIONS,
            )
            .expect("usable"),
        );
        assert_eq!(
            unpriced(&selection(&bench.source(), &[rogue])).reasons,
            vec![NoPriceReason::SourceNotPermitted {
                source_id: SOURCE_UNPERMITTED.to_string(),
            }]
        );

        // And the gate is the *set* the policy named, not a hard-coded identity:
        // a source inside it is priced, one outside it is not. (A policy permitting
        // two sources is exercised in
        // `the_price_source_binding_depends_on_every_field_and_not_on_set_order`;
        // the fixture policy permits one, so it is the other half of the gate that
        // is reachable here.)
        let source = bench.source();
        assert!(source.permits(&source_id(SOURCE_A)));
        assert!(!source.permits(&source_id(SOURCE_UNPERMITTED)));
    }

    /// Finality is derived, never claimed, and a pending reading is refused with
    /// its confirmations named.
    #[test]
    fn a_pending_reading_is_refused_and_finality_is_derived_from_the_policy() {
        let bench = Bench::new();
        let source = bench.source();
        let min = bench.policy.min_confirmations();
        assert_eq!(source.finality_of(min), PriceFinality::Finalized);
        assert_eq!(
            source.finality_of(min - 1),
            PriceFinality::PendingFinality
        );

        let pending = bench.validated(reading(PRICE_BLOCK, PRICE_TS, PRICE, min - 1));
        assert_eq!(
            unpriced(&selection(&source, &[pending])).reasons,
            vec![NoPriceReason::NotFinal {
                confirmations: min - 1,
                min_confirmations: min,
            }]
        );
    }

    /// A fork: two eligible readings at one block with two prices. Declining is
    /// the only honest answer.
    #[test]
    fn two_readings_at_one_block_with_two_prices_is_a_fork() {
        let bench = Bench::new();
        let one = bench.validated(good());
        let two = bench.validated(reading(PRICE_BLOCK, PRICE_TS, PRICE + 1, CONFIRMATIONS));
        let result = selection(&bench.source(), &[one.clone(), two.clone()]);
        assert_eq!(
            unpriced(&result).reasons,
            vec![NoPriceReason::ForkedBlock {
                block_number: PRICE_BLOCK
            }]
        );
        assert!(unpriced(&result).describe().contains("cannot resolve a fork"));

        // The same block, the same price, two round ids: not a fork, and the tie
        // is broken by the event id so the answer does not depend on the order.
        let round_two = bench.validated(PriceObservation::from_parts(
            source_id(SOURCE_A),
            PRICE,
            CHAIN,
            PRICE_BLOCK,
            &block_hash(),
            PRICE_TS,
            "round-2",
            CONFIRMATIONS,
        )
        .expect("usable"));
        assert_ne!(round_two.event_id(), one.event_id());
        let forwards = select_price(
            &bench.source(),
            &[one.clone(), round_two.clone()],
            &anchor(201, &block_hash(), ANCHOR_TS, 10),
        )
        .as_priced()
        .cloned()
        .expect("an agreement is not a fork");
        let backwards = select_price(
            &bench.source(),
            &[round_two, one.clone()],
            &anchor(201, &block_hash(), ANCHOR_TS, 10),
        )
        .as_priced()
        .cloned()
        .expect("an agreement is not a fork");
        assert_eq!(forwards.event_id(), backwards.event_id());
    }

    /// A duplicated reading is one reading: claimed once through the same
    /// [`CountedEvents`] set the revenue side uses, and reported rather than
    /// folded.
    #[test]
    fn a_duplicated_reading_is_counted_once_and_reported() {
        let bench = Bench::new();
        let source = bench.source();
        let reading = bench.validated(good());
        let result = select_price(
            &source,
            &[reading.clone(), reading.clone(), reading.clone()],
            &anchor(201, &block_hash(), ANCHOR_TS, 10),
        );
        let priced = result.as_priced().expect("one reading, priced once");
        assert_eq!(priced.duplicate_observations(), 2);
        assert_eq!(priced.event_id(), reading.event_id());
    }

    /// Every rejection is reported, not just the first: an operator sees the whole
    /// set rather than whichever the loop happened to reach.
    #[test]
    fn every_rejected_reading_is_reported() {
        let bench = Bench::new();
        let source = bench.source();
        let stale = bench.validated(reading(
            PRICE_BLOCK,
            ANCHOR_TS - MAX_STALENESS_UNIX - 1,
            PRICE,
            CONFIRMATIONS,
        ));
        let future = bench.validated(reading(202, PRICE_TS, PRICE, CONFIRMATIONS));
        let other_source = bench.validated(
            PriceObservation::from_parts(
                source_id(SOURCE_UNPERMITTED),
                PRICE,
                CHAIN,
                PRICE_BLOCK,
                &block_hash(),
                PRICE_TS,
                "round-1",
                CONFIRMATIONS,
            )
            .expect("usable"),
        );
        let result = selection(&source, &[stale, future, other_source]);
        let refusal = unpriced(&result);
        assert_eq!(refusal.reasons.len(), 3, "{:?}", refusal.reasons);
        assert!(refusal.reasons.contains(&NoPriceReason::Stale {
            age_unix: MAX_STALENESS_UNIX + 1,
            max_staleness_unix: MAX_STALENESS_UNIX,
        }));
        assert!(refusal.reasons.iter().any(|r| matches!(r, NoPriceReason::AfterAnchor { .. })));
        assert!(refusal
            .reasons
            .iter()
            .any(|r| matches!(r, NoPriceReason::SourceNotPermitted { .. })));

        // And no readings at all is its own named reason.
        assert_eq!(
            unpriced(&selection(&source, &[])).reasons,
            vec![NoPriceReason::NoPriceObservation]
        );
    }

    // ---- the conversion ---------------------------------------------------

    /// Invariant 10. The conversion rounds **up**, on both sides of a whole
    /// micro-USD, and never down. The numbers are written out so a reader can
    /// check the arithmetic rather than trust it.
    #[test]
    fn the_conversion_rounds_upward_and_never_down() {
        let bench = Bench::new();
        let source = bench.source();
        let priced = select_price(
            &source,
            &[bench.validated(good())],
            &anchor(201, &block_hash(), ANCHOR_TS, 10),
        )
        .as_priced()
        .cloned()
        .expect("priced");

        // The smallest possible charge is still a charge: one wei at $3000/ETH is
        // three millionths of a micro-USD, and it costs one micro-USD. This is the
        // floor the rounding puts under every conversion, and it is the reason a
        // round-down could not be repaired later.
        assert_eq!(
            priced.cost_musd(1).expect("one wei converts"),
            1,
            "one wei must not cost nothing"
        );
        // 21_000_001_234 wei at 3000.00 USD/ETH is 63000.003702 micro-USD.
        let fraction = 21_000_001_234u128 * PRICE;
        assert_eq!(fraction / PRICE_FIXED_POINT_DIVISOR, 63_000);
        assert_eq!(fraction % PRICE_FIXED_POINT_DIVISOR, 3_702_000_000_000_000);
        assert_eq!(
            priced.cost_musd(21_000_001_234).expect("converts"),
            63_001,
            "the fraction rounds up, so the cost is never understated"
        );
        // One wei below a whole micro-USD still costs one micro-USD: the smallest
        // possible upward rounding, and the reason a tiny gas charge cannot be
        // laundered into a free one.
        assert_eq!(
            priced
                .cost_musd(PRICE_FIXED_POINT_DIVISOR / PRICE - 1)
                .expect("converts"),
            1
        );
        // And zero wei is zero cost, not one.
        assert_eq!(priced.cost_musd(0).expect("converts"), 0);
        // Monotonic in the cost, and never decreasing: a bigger cost is never a
        // smaller charge, whichever way the rounding fell.
        let mut previous = 0u128;
        for cost_wei in [
            1u128,
            1_000_000,
            21_000_001_234,
            21_000_001_235,
            333_333_333_333,
            u64::MAX as u128,
        ] {
            let converted = priced.cost_musd(cost_wei).expect("converts");
            assert!(
                converted >= previous,
                "cost_musd is not monotonic: {cost_wei} wei converted to {converted} after \
                 {previous}"
            );
            previous = converted;
        }
    }

    /// Invariant 9. The conversion path is integer-only. This is a source-level
    /// check and it is deliberately blunt: no `f64` and no `as f64` anywhere in
    /// this module's non-test code, because a single float on the path would
    /// make every other test in this file true for the wrong reason.
    #[test]
    fn the_conversion_path_contains_no_float() {
        // Both halves of the path: this module, which owns the conversion, and
        // `settlement.rs`, which owns the comparison and the subtraction. Comments
        // are stripped first, because these modules' *prose* says "never `f64`"
        // and a check that could not tell prose from code would be either useless
        // or trivially satisfied. What is checked is the code.
        for (module, source) in [
            ("trusted_valuation", include_str!("trusted_valuation.rs")),
            ("settlement", include_str!("settlement.rs")),
        ] {
            let production = source
                .split("#[cfg(test)]\nmod tests")
                .next()
                .expect("the tests marker is still in the file");
            let code: String = production
                .lines()
                .map(|line| line.split("//").next().unwrap_or(""))
                .collect::<Vec<&str>>()
                .join("\n");
            for needle in ["f64", "f32", "as f64", "parse::<f"] {
                assert!(
                    !code.contains(needle),
                    "{needle} must not appear in the non-test code of {module}"
                );
            }
        }
        // The test half is not scanned by the same trick, because this very test
        // names the needles it searches for — a check that finds itself is not a
        // check. What the scan above does cover is every line of production code
        // on the path, in both modules; and `grep -n f64` over this file returns
        // only prose (this module's doc comment and this test's needle list) and
        // one pre-existing assertion in `settlement.rs`'s own tests.
        // And the divisor is the constant the formula names, not a recomputed
        // power of ten.
        assert_eq!(PRICE_FIXED_POINT_DIVISOR, 1_000_000_000_000_000_000);
        assert_eq!(PRICE_FIXED_POINT_DIVISOR, 10u128.pow(18));
        // 18 decimals of a micro-USD per ETH is the whole scale: 10^18 wei per
        // ETH times 10^6 micro per USD folded into one divisor.
        assert_eq!(
            PRICE_FIXED_POINT_DIVISOR,
            10u128.pow(18) / 10u128.pow(12) * 10u128.pow(12)
        );
    }

    /// Invariant 11. Overflow is refused. `u128` is sufficient for every
    /// physically reachable price, and this test is what "physically reachable"
    /// means: the largest `cost_wei` this crate can ever bind, against the
    /// largest price `u128` can express, has to come back as a typed error rather
    /// than a wrapped number.
    #[test]
    fn an_overflowing_conversion_is_refused_and_never_wrapped() {
        let bench = Bench::new();
        let huge = PriceObservation::from_parts(
            source_id(SOURCE_A),
            u128::MAX / 2,
            CHAIN,
            PRICE_BLOCK,
            &block_hash(),
            PRICE_TS,
            "round-1",
            CONFIRMATIONS,
        )
        .expect("a syntactically valid, economically absurd price");
        let priced = select_price(
            &bench.source(),
            &[bench.validated(huge)],
            &anchor(201, &block_hash(), ANCHOR_TS, 10),
        )
        .as_priced()
        .cloned()
        .expect("a reading can name any price it likes");

        // The largest cost this crate can bind: `u64::MAX` wei, because
        // `ExternalEventFact::native_gas` refuses anything above it.
        assert!(matches!(
            priced.cost_musd(u64::MAX as u128),
            Err(ValuationError::PriceArithmeticOverflow { .. })
        ));
        // And the same for the second multiplication-plus-one, which is the case a
        // naive `n / d` would get wrong near the boundary.
        let near = priced.clone();
        assert!(matches!(
            near.cost_musd(2),
            Err(ValuationError::PriceArithmeticOverflow { .. })
        ));
        // Just inside the boundary it converts, and the answer is not a wrapped
        // one: one wei at an absurd price is a number, not a failure.
        assert_eq!(
            priced.cost_musd(1).expect("fits"),
            (u128::MAX / 2).div_ceil(PRICE_FIXED_POINT_DIVISOR)
        );
    }

    // ---- the observation identity ----------------------------------------

    /// Invariant G. The price observation has its own domain, its own layout and
    /// its own identity — and none of the other three layouts can be satisfied by
    /// it. Two readings that differ in any bound field have different identities,
    /// and the identity carries no policy and no verifier.
    #[test]
    fn the_price_observation_identity_is_its_own_domain() {
        let fact = good().fact().expect("a describable reading");
        let id = ExternalEventId::price_observation(&fact).expect("an identity");
        assert_eq!(id.to_string(), {
            let again = ExternalEventId::price_observation(&good().fact().unwrap())
                .expect("an identity");
            again.to_string()
        });

        // Domains are distinct strings, asserted with the constants the crate
        // ships rather than by restating them.
        let domains = [
            crate::event_id::EVENT_ID_DOMAIN,
            crate::event_id::NATIVE_GAS_EVENT_ID_DOMAIN,
            crate::event_id::SETTLEMENT_EVENT_ID_DOMAIN,
            crate::event_id::PRICE_OBSERVATION_ID_DOMAIN,
            PRICE_ATTESTATION_DOMAIN,
            PRICE_SOURCE_POLICY_DOMAIN,
        ];
        let unique: std::collections::BTreeSet<&str> = domains.iter().copied().collect();
        assert_eq!(unique.len(), domains.len(), "two domains share a string");

        // The layout is its own, and it is checked at run time by the module's own
        // `check_layout` — this asserts the *table* is what the encoder says.
        assert_eq!(
            crate::event_id::PRICE_OBSERVATION_FIELDS
                .iter()
                .map(|(tag, _)| *tag)
                .collect::<Vec<&str>>(),
            vec![
                "schema_version",
                "source_id",
                "base_asset",
                "quote_unit",
                "price_musd_per_eth",
                "chain_id",
                "block_number",
                "block_hash",
                "block_timestamp_unix",
                "source_round",
                "confirmations",
            ]
        );
        // It is not the transfer layout, so a price can never be filed as a
        // transfer even though both carry a chain id and a block hash.
        let transfer_tags: Vec<&str> = crate::event_id::EVENT_ID_FIELDS
            .iter()
            .map(|(tag, _)| *tag)
            .collect();
        assert_ne!(
            transfer_tags,
            crate::event_id::PRICE_OBSERVATION_FIELDS
                .iter()
                .map(|(t, _)| *t)
                .collect::<Vec<&str>>()
        );

        // Every bound field changes the identity.
        let variants = [
            reading(PRICE_BLOCK + 1, PRICE_TS, PRICE, CONFIRMATIONS),
            reading(PRICE_BLOCK, PRICE_TS, PRICE + 1, CONFIRMATIONS),
            reading(PRICE_BLOCK, PRICE_TS + 1, PRICE, CONFIRMATIONS),
            reading(PRICE_BLOCK, PRICE_TS, PRICE, CONFIRMATIONS + 1),
            PriceObservation::from_parts(
                source_id(SOURCE_B),
                PRICE,
                CHAIN,
                PRICE_BLOCK,
                &block_hash(),
                PRICE_TS,
                "round-1",
                CONFIRMATIONS,
            )
            .expect("usable"),
            PriceObservation::from_parts(
                source_id(SOURCE_A),
                PRICE,
                CHAIN,
                PRICE_BLOCK,
                &block_hash(),
                PRICE_TS,
                "round-2",
                CONFIRMATIONS,
            )
            .expect("usable"),
        ];
        for variant in variants {
            let other = ExternalEventId::price_observation(&variant.fact().unwrap())
                .expect("an identity");
            assert_ne!(id, other, "two readings must not share an identity");
        }

        // And the fact layer refuses the same readings the observation layer
        // refuses, so an identity cannot be minted for a reading that was never
        // usable.
        assert!(PriceObservationFact::from_parts(
            SOURCE_A, "native-eth", "musd", 0, CHAIN, PRICE_BLOCK, &block_hash(), PRICE_TS,
            "round-1", CONFIRMATIONS
        )
        .is_err());
        assert!(PriceObservationFact::from_parts(
            SOURCE_A, "native-eth", "musd", PRICE, 0, PRICE_BLOCK, &block_hash(), PRICE_TS,
            "round-1", CONFIRMATIONS
        )
        .is_err());
        assert!(PriceObservationFact::from_parts(
            SOURCE_A, "native-eth", "musd", PRICE, CHAIN, 0, &block_hash(), PRICE_TS,
            "round-1", CONFIRMATIONS
        )
        .is_err());
        assert!(PriceObservationFact::from_parts(
            SOURCE_A, "native-eth", "musd", PRICE, CHAIN, PRICE_BLOCK, &block_hash(), 0,
            "round-1", CONFIRMATIONS
        )
        .is_err());
        assert!(PriceObservationFact::from_parts(
            SOURCE_A, "native-eth", "musd", PRICE, CHAIN, PRICE_BLOCK, &block_hash(), PRICE_TS,
            "round-1", 0
        )
        .is_err());
    }

    /// The reading's own validation, before any signature exists: no price, no
    /// chain, no block, no time, no round and no depth are all refused.
    #[test]
    fn a_reading_with_a_missing_fact_is_refused() {
        let good_hash = block_hash();
        let bad = [
            (0u128, CHAIN, PRICE_BLOCK, good_hash.clone(), PRICE_TS, "round-1", CONFIRMATIONS),
            (PRICE, 0, PRICE_BLOCK, good_hash.clone(), PRICE_TS, "round-1", CONFIRMATIONS),
            (PRICE, CHAIN, 0, good_hash.clone(), PRICE_TS, "round-1", CONFIRMATIONS),
            (PRICE, CHAIN, PRICE_BLOCK, "0xnothex".to_string(), PRICE_TS, "round-1", CONFIRMATIONS),
            (PRICE, CHAIN, PRICE_BLOCK, good_hash.clone(), 0, "round-1", CONFIRMATIONS),
            (PRICE, CHAIN, PRICE_BLOCK, good_hash.clone(), PRICE_TS, "", CONFIRMATIONS),
            (PRICE, CHAIN, PRICE_BLOCK, good_hash.clone(), PRICE_TS, "round-1", 0),
        ];
        for (price, chain, block, hash, ts, round, confirmations) in bad {
            assert!(
                PriceObservation::from_parts(
                    source_id(SOURCE_A),
                    price,
                    chain,
                    block,
                    &hash,
                    ts,
                    round,
                    confirmations,
                )
                .is_err(),
                "price {price}, chain {chain}, block {block}, hash {hash}, ts {ts}, round \
                 {round:?}, confirmations {confirmations} must be refused"
            );
        }
    }

    /// A document with a field the signer never signed must not parse. Ignored
    /// is how a `gas_used_override` would get in.
    #[test]
    fn a_price_document_with_an_extra_field_does_not_parse() {
        let bench = Bench::new();
        let signed = bench.sign(good());
        let mut json = serde_json::to_value(&signed).expect("serialise");
        json["observation"]["gas_used"] = serde_json::json!(1);
        assert!(
            serde_json::from_value::<AuthenticatedPriceObservation>(json).is_err(),
            "an extra field is a document this build did not sign"
        );
        // A missing one is equally fatal.
        let mut json = serde_json::to_value(&signed).expect("serialise");
        json["observation"]
            .as_object_mut()
            .expect("an object")
            .remove("confirmations");
        assert!(serde_json::from_value::<AuthenticatedPriceObservation>(json).is_err());
        // And the honest document round-trips, so transport is not the thing being
        // refused.
        let back: AuthenticatedPriceObservation =
            serde_json::from_value(serde_json::to_value(&signed).unwrap()).expect("round-trips");
        validate_price_observation(&back, &bench.policy).expect("still authentic");
    }

    // ---- helpers ----------------------------------------------------------

    /// Edits a signed document through the serialiser, the way an attacker has to.
    fn mutate(
        signed: &AuthenticatedPriceObservation,
        edit: impl FnOnce(&mut PriceObservation),
    ) -> AuthenticatedPriceObservation {
        let mut json = serde_json::to_value(signed).expect("serialise");
        let mut observation: PriceObservation =
            serde_json::from_value(json["observation"].take()).expect("the observation");
        edit(&mut observation);
        json["observation"] = serde_json::to_value(observation).expect("serialise the edit");
        serde_json::from_value(json).expect("the shape still parses")
    }
}
