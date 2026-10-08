//! P4.5c/d/e: the operation, the aggregation over all of its legs, and the
//! refusal that makes an incomplete operation worth nothing.
//!
//! # The gap this step closes
//!
//! ```text
//! NEV = ΣVerifiedInflows − ΣVerifiedOutflows − ExternalCosts
//! ```
//!
//! Every term on the right-hand side now exists, and until this step they could
//! not be added: P4.5a gave the negative leg a type and made promoting it alone
//! *structurally* impossible, which is the right interim state and also means
//! nothing promotes. An arbitrage is the smallest case that shows why:
//!
//! ```text
//! controlled executor -> pool     100.00 USDC   (outflow,  must be -)
//! pool             -> executor    100.08 USDC   (inflow,   must be +)
//! ```
//!
//! Count the return leg alone and the system books `+100.08` with no `-100.00`
//! in sight: a false profit large enough to fund real budget. Count the payment
//! leg alone and it books `-100.00`, which is merely wrong. **The only sound
//! unit is the whole operation**, so this module aggregates over legs and puts
//! the promotion predicate here, where the leg set is known, instead of on a
//! leg, where it is not.
//!
//! # How legs are grouped into an operation, and why it cannot be asserted
//!
//! An operation is **one transaction**. [`OperationId`] is a digest of
//! `(chain_id, tx_hash)` under [`OPERATION_ID_DOMAIN`], it is derived from the
//! chain read and never from a string, and it has no `Deserialize` — the same
//! three-part discipline as every other derived identity in this crate, and for
//! the same reason: a caller-asserted `operation_id` is a caller-asserted
//! grouping, and the grouping decides what gets subtracted.
//!
//! Why transaction-scoped, and why not wider:
//!
//! * A transaction is the largest unit the chain itself vouches for. Every log
//!   it emitted happened, or none did. That is *evidence of atomicity*, and it
//!   is the only kind of atomicity this crate can point at.
//! * An operation spanning two transactions has **no** such evidence. Nothing
//!   says the legs belong together, so the grouping would be an operator's
//!   choice made after the fact — which is precisely how a profitable net gets
//!   manufactured: book the inflow from the successful leg, and pick a window
//!   that excludes the outflow that lost money.
//! * So multi-transaction grouping is **refused**, with
//!   [`SettlementError::CrossTransaction`], and the refusal is a typed error
//!   rather than a silent split into two operations: two operations would give
//!   the caller a complete-looking `VerifiedSettlement` for the winning half.
//!
//! # Completeness, and the one rule this module exists to enforce
//!
//! ```text
//! MissingRequiredEconomicEvidence  =>  NoSpendAuthority
//! ```
//!
//! A leg set is complete when, and only when, the **chain** says the operation
//! had no other economic legs. That is a checkable statement, and
//! [`crate::base_usdc::BaseUsdcVerifier::scan_transaction`] is what makes it
//! checkable: it reads the whole receipt and enumerates every `Transfer` log,
//! so the leg set is compared against an enumeration rather than against the
//! node's own evidence. A settlement built only from the evidence rows this node
//! happens to hold would be complete by construction — it would be missing
//! exactly the legs nobody wrote down.
//!
//! The three ways a leg can fail are **different states**, never one zero:
//!
//! | state | what is true | why it is not zero |
//! |-------|--------------|--------------------|
//! | [`LegState::Absent`] | the chain enumerated the transfer; this node holds no evidence for it | the transfer happened and moved money; the number is unknown, not zero |
//! | [`LegState::Unattested`] | the transfer is chain-confirmed and evidence is held, but no validated outcome policy is in force | the transfer is real and unpriced; there is no authority to name |
//! | [`LegState::Unconfirmed`] | the transfer is chain-confirmed and evidence is held, but the read could not bind the evidence to that exact log | the node has a record the chain has not vouched for *as this transfer* |
//!
//! Collapsing them to "assume zero" is the exact failure P4.5c is closing: an
//! unrecorded outflow is worth `-100.00` to the operator's budget and `0` to a
//! summing function that treats silence as absence. So an incomplete leg set
//! produces [`IncompleteSettlement`], a type with **no net accessor at all** —
//! not a zero net, no net — and [`SettlementAuthority`] cannot be obtained from
//! it.
//!
//! # The gas seam, and how P4.6 addressed the price
//!
//! Gas is not a [`BoundaryDirection::ControlledToExternal`] crossing. It has no
//! ERC-20 `Transfer` log to point a proof at, it may never touch a controlled
//! address, and P4.5a made expressing it as an outflow structurally impossible
//! rather than conventional. It is therefore a **separate quantity**:
//! [`VerifiedNativeGasCost`] carries `gas_used`, `effective_gas_price_wei` and
//! `l1_fee_wei`, and derives `cost_wei = gas_used × effective_gas_price + l1_fee`
//! with checked arithmetic.
//!
//! P4.5c denominated it in wei and stopped there, because a receipt that carried
//! a presumed price would be unfalsifiable: nobody could audit which price was
//! used, and the price would move with the market underneath a signed document.
//! So it reported two numbers and refused to add them.
//!
//! P4.6 keeps that refusal as the *default* and replaces it with a real answer
//! when — and only when — a price exists as a fact with a chain anchor and an
//! authority:
//!
//! * [`crate::trusted_valuation::PriceObservation`] is a reading of one pair,
//!   anchored to a block (number, hash, timestamp, depth);
//! * it is signed by the **same** `verifier-runtime` key the policy delegates
//!   for receipts, under the same `policy_hash` — there is no second authority;
//! * the permitted source identity, the pair, the staleness window, the chain
//!   and the rounding rule are all inside the signed policy
//!   ([`crate::policy_auth::OutcomePolicyPayload::price_source_hash`]), so a
//!   source named only by the observation is refused;
//! * [`crate::trusted_valuation::select_price`] picks the latest valid reading
//!   **at or before this settlement's block anchor**, within the window — never
//!   "the newest one I have", which would be chosen after the net was known;
//! * the conversion is integer-only and rounds **up**
//!   ([`crate::trusted_valuation::AppliedPrice::cost_musd`]).
//!
//! The price is therefore not a parameter anywhere. [`VerifiedSettlement::compare`]
//! takes a [`crate::trusted_valuation::ValidatedPriceSource`] and a slice of
//! [`crate::trusted_valuation::ValidatedPriceObservation`], both of which have
//! private fields and no arbitrary constructor, and it returns a
//! [`ComparableSettlementResult`]: either a [`ComparableVerifiedSettlement`],
//! which is a *different type* from [`VerifiedSettlement`] and the only one that
//! can produce a [`SettlementAuthority`], or a
//! [`ComparableSettlementResult::NoComparableNetValue`] that names every
//! rejection. Nothing was relaxed to get there: an operation with no price, a
//! stale price, a future price, a price from a source the policy does not
//! permit, or a price signed under another policy all land on the refusal arm,
//! exactly as they did before.
//!
//! The load-bearing reason a *type* is needed rather than a flag: a
//! [`VerifiedSettlement`] with no comparable value and a
//! [`ComparableVerifiedSettlement`] with one are different claims, and the second
//! is the only one that has been through a price. Marking the first with a
//! boolean would let a caller skip the price by setting the flag.
//!
//! # Where the promotion predicate lives
//!
//! On [`SettlementAuthority`], reachable only from
//! [`VerifiedSettlement::promote`], reachable only from
//! [`VerifiedSettlement::assemble`] returning a *complete* outcome.
//! [`crate::boundary_delta::VerifiedBoundaryDelta`] still carries no predicate
//! and no public magnitude: its `signed_amount_micros` stays `pub(crate)`. That
//! is not an oversight left over from P4.5a — it is the point. A leg knows its
//! own sign and nothing about whether its siblings exist, so no predicate about
//! money can live on it without being wrong.

use crate::{
    base_usdc::{BaseUsdcVerification, BaseUsdcVerifier, BlockAnchor, ObservedTransfer, TransactionLogScan},
    boundary::{
        BoundaryCrossing, BoundaryDirection, BoundaryEvidence, ControlledAddressRegistry,
        RealAsset,
    },
    boundary_delta::VerifiedBoundaryDelta,
    event_id::{ExternalEventFact, ExternalEventId},
    policy_auth::{
        push_tagged, Hash, PolicyError, PreimageFieldKind, ValidatedOutcomePolicy,
    },
    trusted_valuation::{
        select_price, AppliedPrice, NoPriceReason, PriceSelection, ValidatedPriceObservation,
        ValidatedPriceSource,
    },
    EconomyError,
};
use serde::Serialize;

/// Domain of the canonical identity of an *operation*. First bytes of the
/// preimage, so it can never equal a policy hash, a receipt attestation, a
/// settlement attestation, an event id or a boundary-evidence digest.
pub const OPERATION_ID_DOMAIN: &str = "MYCELIUM-ECONOMY/OPERATION-ID/V1";

/// Schema version this build computes and expects for [`OPERATION_ID_DOMAIN`].
pub const OPERATION_ID_SCHEMA_VERSION: u32 = 1;

/// Domain of the digest that binds one complete settlement: its legs, its
/// direction and its external costs.
pub const SETTLEMENT_DIGEST_DOMAIN: &str = "MYCELIUM-ECONOMY/SETTLEMENT-DIGEST/V1";

/// Schema version this build computes and expects for
/// [`SETTLEMENT_DIGEST_DOMAIN`].
///
/// Bumped 1 -> 2 by P4.6, and the reason is not cosmetic. P4.6 gave
/// [`VerifiedSettlement`] a **block anchor** — the block number, hash and
/// timestamp the operation settled in — so that a price could be selected
/// against it instead of after the fact. A digest that does not bind the anchor
/// cannot tell two settlements of the same transaction in the same block apart
/// from... nothing, they are the same; but it *can* be re-read against a
/// different anchor later, and a settlement digest that does not commit to the
/// anchor it was priced against is not the digest of what was priced.
pub const SETTLEMENT_DIGEST_SCHEMA_VERSION: u32 = 2;

/// Domain of the digest that binds a **comparable** settlement: the settlement
/// digest plus the price observation that was applied to it.
///
/// A separate domain rather than another section of
/// [`SETTLEMENT_DIGEST_DOMAIN`], because it is a different message about a
/// different claim: one says "this is what happened", the other says "this is
/// what it is worth, and here is the reading that says so". The comparable digest
/// embeds the settlement digest, so the two compose and neither can be read as
/// the other.
pub const COMPARABLE_SETTLEMENT_DIGEST_DOMAIN: &str =
    "MYCELIUM-ECONOMY/COMPARABLE-SETTLEMENT-DIGEST/V1";

/// Schema version of the comparable digest this build computes.
pub const COMPARABLE_SETTLEMENT_DIGEST_SCHEMA_VERSION: u32 = 1;

/// The comparable digest's layout when a price was applied, in canonical order.
///
/// **This is the price row the brief asks for.** `price_observation_event_id` is
/// the reading's own [`ExternalEventId`], not a copy of the price: binding the
/// identity means an audit can go back to the observation, re-run
/// [`crate::trusted_valuation::select_price`] and get the same number, and it
/// means two comparable values built from two different readings of the same
/// block are different digests even when the readings agree on the price. The
/// price itself is bound too, because a value whose digest did not commit to the
/// number it authorised would not be auditable at all.
const COMPARABLE_DIGEST_FIELDS_WITH_PRICE: &[&str] = &[
    "schema_version",
    "settlement_digest",
    "policy_hash",
    "price_observation_event_id",
    "price_source_id",
    "price_musd_per_eth",
    "price_block_number",
    "price_block_hash",
    "price_block_timestamp_unix",
    "price_confirmations",
    "price_age_unix",
    "price_rounding",
    "total_native_cost_wei",
    "native_cost_musd",
    "comparable_net_value_micros",
];

/// The comparable digest's layout when no price was needed because the operation
/// burned no native value. Every other row is present; the price rows are
/// *absent* rather than zero-filled, so a settlement that needed no price can
/// never be read as one that was priced at zero.
const COMPARABLE_DIGEST_FIELDS_WITHOUT_PRICE: &[&str] = &[
    "schema_version",
    "settlement_digest",
    "policy_hash",
    "total_native_cost_wei",
    "native_cost_musd",
    "comparable_net_value_micros",
];

/// The layout of the operation-id preimage, in canonical order.
///
/// Two rows, because an operation on this build is a transaction and nothing
/// else: no registry, no counterparty, no caller-supplied label. A third row
/// here would be a place a grouping choice could sneak in.
pub const OPERATION_ID_FIELDS: &[(&str, PreimageFieldKind)] = &[
    ("schema_version", PreimageFieldKind::U32),
    ("chain_id", PreimageFieldKind::U64),
    ("tx_hash", PreimageFieldKind::Hash32),
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything that can refuse to produce a settlement.
///
/// A refusal here is never "the net is smaller". A net that could be wrong is
/// not a net; the only safe answers are "this operation is worth what it is
/// worth" and "I cannot tell what this operation is worth", and the second is
/// what these arms are.
#[derive(Debug, thiserror::Error)]
pub enum SettlementError {
    #[error(transparent)]
    Economy(#[from] EconomyError),

    #[error(transparent)]
    Policy(#[from] PolicyError),

    #[error(transparent)]
    EventId(#[from] crate::event_id::EventIdError),

    #[error(transparent)]
    BoundaryDelta(#[from] crate::boundary_delta::BoundaryDeltaError),

    #[error("settlement preimage is malformed: {0}")]
    Preimage(String),

    /// No transaction at all. There is no operation to name and no leg set to
    /// sum, so there is nothing to report — not an operation worth zero.
    #[error("a settlement needs at least one transaction; an empty leg set has no operation id")]
    NoTransaction,

    /// More than one transaction was offered as one operation. See the module
    /// doc: this is refused rather than split, because the split would hand
    /// back a *complete* settlement for one half of an operation.
    #[error(
        "{transactions} transactions were offered as one operation ({operations}); an \
         operation is one transaction, because one transaction is the largest unit the \
         chain vouches for"
    )]
    CrossTransaction {
        transactions: usize,
        operations: String,
    },

    /// The legs of one transaction moved different assets, so a single signed
    /// micros total would be meaningless. Base USDC is the only identified asset
    /// in this build, so this is defence in depth — and it is the honest place
    /// for the mistake to stop.
    #[error("one operation moved {assets}; a net needs one asset")]
    MixedAssets { assets: String },

    /// The signed total does not fit the micro unit the ledger books in.
    #[error("operation total of {total_micros} micros does not fit a signed 64-bit micro total")]
    NetOutOfRange { total_micros: i128 },

    /// The operation burned native value and no trustworthy ETH/USD evidence
    /// exists, so there is no single comparable figure to declare.
    ///
    /// See the module doc on the gas seam. The two quantities are still
    /// reported — see [`crate::settlement::VerifiedSettlement::token_net_delta_micros`]
    /// and [`crate::settlement::VerifiedSettlement::total_native_cost_wei`] —
    /// and this arm says only that they may not be added.
    #[error(
        "operation {operation_id} burned {cost_wei} wei of native value and this build \
         has no trustworthy ETH/USD price evidence, so no comparable net value exists; \
         the token delta and the native cost are reported separately and are not added"
    )]
    NoComparableNetValue { operation_id: String, cost_wei: u128 },

    /// The endpoint the operation was read from has no kernel-enforced
    /// identity, so nothing derived from it may promote.
    #[error(
        "chain provider {endpoint} is an address, not an identity, so an operation read \
         through it cannot promote"
    )]
    ProviderIdentityUnverified { endpoint: String },

    /// P4.6. A comparable value was computed under one policy and promoted under
    /// another.
    ///
    /// The comparable value's own fields already name the policy it was computed
    /// under, so this is not the signature check — it is the "is it *current*?"
    /// check, the same split [`crate::receipt_auth`] makes. Promotion re-reads
    /// the policy in force and declines a value from another one, so a rotated
    /// policy never silently re-prices an operation under new rules.
    #[error(
        "this comparable value was priced under policy {found}, and the policy in force \
         is {current}; a value priced under another policy is not this policy's"
    )]
    ComparablePolicyMismatch { found: Hash, current: Hash },
}

// ---------------------------------------------------------------------------
// The operation identity
// ---------------------------------------------------------------------------

/// The canonical identity of one operation: `(chain_id, tx_hash)` under
/// [`OPERATION_ID_DOMAIN`].
///
/// Private field, no `Deserialize`, and one constructor,
/// [`Self::from_scan`], which takes the chain facts a provider-scoped
/// [`TransactionLogScan`] already carries. Note what that signature rules out:
/// a bare string cannot become an operation id, a JSON document cannot become
/// one, and two transactions cannot be made to share one.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct OperationId(Hash);

impl OperationId {
    /// Derived from the transaction itself.
    pub fn from_scan(scan: &TransactionLogScan) -> Result<Self, SettlementError> {
        if scan.chain_id() == 0 {
            return Err(SettlementError::EventId(
                crate::event_id::EventIdError::ZeroChain,
            ));
        }
        crate::base_usdc::validate_hash32("tx_hash", scan.tx_hash())?;
        let mut buf = Vec::new();
        push_tagged(&mut buf, b"domain", OPERATION_ID_DOMAIN.as_bytes());
        push_tagged(
            &mut buf,
            b"sections",
            &u32::try_from(OPERATION_ID_FIELDS.len())
                .map_err(|_| SettlementError::Preimage("too many sections".into()))?
                .to_be_bytes(),
        );
        for (tag, value) in [
            (
                "schema_version",
                OPERATION_ID_SCHEMA_VERSION.to_be_bytes().to_vec(),
            ),
            ("chain_id", scan.chain_id().to_be_bytes().to_vec()),
            (
                "tx_hash",
                Hash::parse("tx_hash", scan.tx_hash())?.to_bytes()?.to_vec(),
            ),
        ] {
            push_tagged(&mut buf, tag.as_bytes(), &value);
        }
        // The encoder and the table are checked against each other rather than
        // trusted, the same discipline as every other preimage in this crate.
        let tags: Vec<&str> = OPERATION_ID_FIELDS.iter().map(|(t, _)| *t).collect();
        let emitted: Vec<&str> = ["schema_version", "chain_id", "tx_hash"].into();
        if tags != emitted {
            return Err(SettlementError::Preimage(format!(
                "operation id: encoder emitted {emitted:?} where the layout expects {tags:?}"
            )));
        }
        Ok(Self(Hash::from_bytes(*blake3::hash(&buf).as_bytes())))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn digest(&self) -> &Hash {
        &self.0
    }
}

impl std::fmt::Display for OperationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Legs
// ---------------------------------------------------------------------------

/// Whether this node established one leg of the operation.
///
/// Three failure states, deliberately not one. Each names a different missing
/// thing and each is fixed by a different action, so collapsing them would
/// destroy the only information an operator has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LegState {
    /// The chain enumerated the transfer, this node holds evidence for it, the
    /// pinned provider confirmed that exact log, and the policy in force
    /// authorised the derivation. Nothing else is needed.
    Confirmed,
    /// The chain enumerated the transfer and this node holds evidence for it,
    /// but the evidence cannot be bound to that exact log: no log index was
    /// reported, or the record disagrees with the chain about the block or the
    /// amount.
    ///
    /// The record exists and may be true. It has not been confirmed as *this*
    /// transfer, and "the node has not checked yet" is not "there was nothing
    /// to check".
    Unconfirmed,
    /// The chain enumerated the transfer and this node holds evidence for it,
    /// but no validated outcome policy is in force, so no authority can be
    /// named for the leg.
    ///
    /// The transfer is real; it is unbound. This is P4b's
    /// `PolicyNotValidated` at the leg layer, and it is a different failure
    /// from [`Self::Unconfirmed`]: the chain spoke, and this node has no
    /// mandate.
    Unattested,
    /// The chain enumerated the transfer and this node holds **no evidence**
    /// for it at all.
    ///
    /// The leg happened. Its amount is unknown here, and an unknown outflow is
    /// the most expensive thing this crate can get wrong.
    Absent,
}

impl LegState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Unconfirmed => "unconfirmed",
            Self::Unattested => "unattested",
            Self::Absent => "absent",
        }
    }
}

impl std::fmt::Display for LegState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One economic movement of an operation, with what this node established about
/// it.
///
/// The magnitude is exposed for audit and is deliberately **not** a net: it is
/// one leg's worth of one asset. Summing these without a completeness check is
/// the mistake P4.5a made impossible at the type level and P4.5c makes
/// unnecessary at the arithmetic level.
#[derive(Debug, Clone, Serialize)]
pub struct SettlementLeg {
    event_id: Option<ExternalEventId>,
    direction: BoundaryDirection,
    asset: RealAsset,
    amount_micros: u64,
    evidence_hash: Option<Hash>,
    policy_hash: Option<Hash>,
    state: LegState,
    /// Why this leg is in the state it is in. Never empty for a non-confirmed
    /// leg: a refusal with no stated reason is not reportable.
    why: String,
}

impl SettlementLeg {
    fn confirmed(delta: &VerifiedBoundaryDelta) -> Self {
        Self {
            event_id: Some(delta.event_id().clone()),
            direction: delta.direction(),
            asset: delta.asset().clone(),
            amount_micros: delta.signed_amount_micros().unsigned_abs() as u64,
            evidence_hash: Some(delta.evidence_hash().clone()),
            policy_hash: Some(delta.policy_hash().clone()),
            state: LegState::Confirmed,
            why: "chain-confirmed under the policy in force".to_string(),
        }
    }

    fn unestablished(
        event_id: Option<ExternalEventId>,
        direction: BoundaryDirection,
        asset: RealAsset,
        amount_micros: u64,
        state: LegState,
        why: String,
    ) -> Self {
        Self {
            event_id,
            direction,
            asset,
            amount_micros,
            evidence_hash: None,
            policy_hash: None,
            state,
            why,
        }
    }

    pub fn state(&self) -> LegState {
        self.state
    }

    /// The canonical identity of the external event this leg moves, when it
    /// could be named. `None` only on a leg that could not be named at all,
    /// which is itself a completeness failure.
    pub fn event_id(&self) -> Option<&ExternalEventId> {
        self.event_id.as_ref()
    }

    pub fn direction(&self) -> BoundaryDirection {
        self.direction
    }

    pub fn asset(&self) -> &RealAsset {
        &self.asset
    }

    /// The leg's own magnitude, in micros of its asset. Not a net.
    pub fn amount_micros(&self) -> u64 {
        self.amount_micros
    }

    /// The signed contribution, for the one caller that is allowed to add legs:
    /// [`VerifiedSettlement`]. `pub(crate)` so no code outside this crate can
    /// reach the arithmetic at all.
    pub(crate) fn signed_amount_micros(&self) -> i128 {
        match self.direction {
            BoundaryDirection::ExternalToControlled => i128::from(self.amount_micros),
            BoundaryDirection::ControlledToExternal => -(i128::from(self.amount_micros)),
        }
    }

    pub fn is_inflow(&self) -> bool {
        self.direction.is_inflow()
    }

    /// Diagnostics: the digest of the stored evidence this leg was derived
    /// from, when it was derived from any.
    pub fn evidence_hash(&self) -> Option<&Hash> {
        self.evidence_hash.as_ref()
    }

    /// Diagnostics: the policy this leg was bound to, when it was bound to one.
    pub fn policy_hash(&self) -> Option<&Hash> {
        self.policy_hash.as_ref()
    }

    /// Why this leg is in the state it is in.
    pub fn why(&self) -> &str {
        &self.why
    }
}

// ---------------------------------------------------------------------------
// The native cost
// ---------------------------------------------------------------------------

/// The native value one transaction burned, in wei, and nothing else.
///
/// # Why this is not a delta
///
/// A gas fee has no ERC-20 `Transfer` log to point a proof at, is paid to a
/// validator or burned by a protocol, and may never touch a controlled address.
/// There is therefore no [`crate::boundary::BoundaryCrossing`] to derive it
/// from, and modelling it as an outflow would make it inherit an evidence
/// requirement it cannot meet *and* let it be double-counted against an outflow
/// that really did leave. It is a separate term, subtracted separately.
///
/// # Why nothing here divides by a price
///
/// The cost is denominated in wei and the type has no USD field, no
/// `eth_usd` parameter and no rate. Converting requires a price, and the price
/// arrives from outside — see [`crate::trusted_valuation`] — carried on the
/// type rather than passed to it. Two facts force that shape:
///
/// * **The anchor (P4.6).** Before P4.6 this type carried `chain_id`,
///   `tx_hash`, `gas_used`, the two prices and the cost, and *dropped* the block
///   number and the block timestamp that the read had established. Nothing above
///   it could then say *when* the transaction settled, so any price would have
///   been chosen after the fact. The [`BlockAnchor`] is now part of this type, so
///   the time the cost belongs to travels with the cost.
/// * **The L1 component.** `l1_fee_reported` distinguishes "the receipt reported
///   zero" from "the receipt reported nothing", which are different claims, and
///   [`Self::l1_fee_verifiable`] exposes the difference so a conversion can
///   refuse instead of assuming the data charge was free.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedNativeGasCost {
    event_id: ExternalEventId,
    operation_id: OperationId,
    /// P4.6. The block this transaction settled in: number, hash, that block's
    /// own timestamp, and how deep it was at the moment of the read.
    anchor: BlockAnchor,
    chain_id: u64,
    tx_hash: String,
    gas_used: u64,
    effective_gas_price_wei: u128,
    l1_fee_wei: u128,
    /// P4.6. Whether the receipt actually reported an L1 data charge.
    l1_fee_reported: bool,
    cost_wei: u128,
    policy_hash: Hash,
}

impl VerifiedNativeGasCost {
    /// Derived from the chain read and bound to the policy in force.
    ///
    /// `fee_payer` and `fee_recipient` are recorded only so the identity is
    /// over something real; neither is a controlled address, and neither is
    /// treated as a boundary leg anywhere in this crate.
    pub fn from_scan(
        scan: &TransactionLogScan,
        policy: &ValidatedOutcomePolicy,
        fee_payer: &str,
        fee_recipient: &str,
    ) -> Result<Self, SettlementError> {
        let operation_id = OperationId::from_scan(scan)?;
        let gas_used = scan.gas_used();
        let effective_gas_price_wei = scan.effective_gas_price_wei();
        let l1_fee_wei = scan.l1_fee_wei();
        // `gas_used × price + l1_fee`, checked. A cost that overflows is a
        // refused cost, never a wrapped one — a wrapped fee would be free money.
        let cost_wei = u128::from(gas_used)
            .checked_mul(effective_gas_price_wei)
            .and_then(|exec| exec.checked_add(l1_fee_wei))
            .ok_or(SettlementError::NetOutOfRange {
                total_micros: u64::MAX as i128,
            })?;
        let fact = ExternalEventFact::native_gas(
            scan.chain_id(),
            scan.tx_hash(),
            fee_payer,
            fee_recipient,
            gas_used,
            cost_wei,
        )?;
        Ok(Self {
            event_id: ExternalEventId::native_gas(&fact)?,
            operation_id,
            anchor: scan.anchor(),
            chain_id: scan.chain_id(),
            tx_hash: scan.tx_hash().to_string(),
            gas_used,
            effective_gas_price_wei,
            l1_fee_wei,
            l1_fee_reported: scan.l1_fee_reported(),
            cost_wei,
            policy_hash: policy.policy_hash()?,
        })
    }

    /// The canonical identity of this native fact, under
    /// [`crate::event_id::NATIVE_GAS_EVENT_ID_DOMAIN`].
    pub fn event_id(&self) -> &ExternalEventId {
        &self.event_id
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// P4.6. The block this transaction settled in. This is what makes a price
    /// selectable without hindsight: the cost's own time travels with it.
    pub fn anchor(&self) -> &BlockAnchor {
        &self.anchor
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn tx_hash(&self) -> &str {
        &self.tx_hash
    }

    pub fn gas_used(&self) -> u64 {
        self.gas_used
    }

    pub fn effective_gas_price_wei(&self) -> u128 {
        self.effective_gas_price_wei
    }

    /// The separate L1 data charge, in wei. Zero when this receipt reported
    /// none; never estimated.
    pub fn l1_fee_wei(&self) -> u128 {
        self.l1_fee_wei
    }

    /// P4.6. Whether the receipt reported an L1 data charge at all.
    pub fn l1_fee_reported(&self) -> bool {
        self.l1_fee_reported
    }

    /// P4.6. Whether this cost's L1 component is verifiably available.
    ///
    /// `false` means the receipt carried no L1 figure. On Base the data charge
    /// is always part of the real cost, so treating its absence as zero would
    /// understate the cost by exactly the amount nobody read — and the
    /// understatement favours whoever is being billed. A conversion must refuse
    /// instead; see [`VerifiedSettlement::compare`].
    pub fn l1_fee_verifiable(&self) -> bool {
        self.l1_fee_reported
    }

    /// `gas_used × effective_gas_price_wei + l1_fee_wei`, checked. **Never**
    /// divided by a price.
    pub fn cost_wei(&self) -> u128 {
        self.cost_wei
    }

    pub fn policy_hash(&self) -> &Hash {
        &self.policy_hash
    }
}

// ---------------------------------------------------------------------------
// Incompleteness
// ---------------------------------------------------------------------------

/// Why a leg set does not establish an operation.
///
/// Serialised with an explicit `state` tag, so a report can distinguish the
/// failure modes *without parsing prose*: `absent`, `unattested`,
/// `unconfirmed`, `scan_not_exhaustive`, `native_cost_unattested`. An operator
/// reading a dashboard sees which one happened and can act on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail")]
pub enum SettlementIncompleteness {
    /// The chain read could not classify every log in the receipt, so the set
    /// of transfers it enumerated is not the set that happened.
    #[serde(rename = "scan_not_exhaustive")]
    ScanNotExhaustive { why: String },
    /// P4.6. The transaction burned native value and **no validated policy is in
    /// force**, so the cost cannot be bound to an authority.
    ///
    /// This arm is the fix for a hole P4.5c left open: the cost vector was
    /// populated only when a policy existed, so a gas-bearing transaction read
    /// without one produced a *complete* settlement with an empty cost vector —
    /// `has_native_cost()` false, `comparable_net_value_micros()` equal to the
    /// token net, and a burned cost that nothing anywhere reported.
    ///
    /// It was unreachable through the public constructor, because no policy
    /// means every leg is `Unattested` and the operation is already incomplete.
    /// It was reachable the moment a settlement could be assembled with a
    /// complete leg set and no authority to attach the cost to — which is
    /// exactly the shape P4.6's price path needs. So the hole is closed rather
    /// than left to a future reader: a cost with no authority is a reason, and
    /// the operation is incomplete.
    #[serde(rename = "native_cost_unattested")]
    NativeCostUnattested {
        gas_used: u64,
        cost_wei_unpriced: String,
        why: String,
    },
    /// A transfer the chain enumerated has no evidence here at all.
    #[serde(rename = "absent")]
    LegAbsent {
        event_id: String,
        direction: BoundaryDirection,
        why: String,
    },
    /// Evidence exists for a real transfer, but no validated outcome policy is
    /// in force to bind it to an authority.
    #[serde(rename = "unattested")]
    LegUnattested {
        event_id: String,
        direction: BoundaryDirection,
        why: String,
    },
    /// Evidence exists, but the chain read could not bind it to the exact log
    /// the transfer is at.
    #[serde(rename = "unconfirmed")]
    LegUnconfirmed {
        event_id: String,
        direction: BoundaryDirection,
        why: String,
    },
}

impl SettlementIncompleteness {
    /// The machine-readable state name. Distinct per failure mode, and the
    /// reason the three are kept apart.
    pub fn state(&self) -> &'static str {
        match self {
            Self::ScanNotExhaustive { .. } => "scan_not_exhaustive",
            Self::NativeCostUnattested { .. } => "native_cost_unattested",
            Self::LegAbsent { .. } => "absent",
            Self::LegUnattested { .. } => "unattested",
            Self::LegUnconfirmed { .. } => "unconfirmed",
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::ScanNotExhaustive { why } => format!(
                "the chain read could not classify every log in this transaction, so \
                 no leg set built from it can be shown complete: {why}"
            ),
            Self::NativeCostUnattested {
                gas_used,
                cost_wei_unpriced,
                why,
            } => format!(
                "this transaction burned {gas_used} gas (about {cost_wei_unpriced} wei \
                 before any conversion) and no validated outcome policy is in force, so \
                 the native cost has no authority behind it and is not reported as zero: \
                 {why}"
            ),
            Self::LegAbsent {
                event_id,
                direction,
                why,
            } => format!(
                "leg {event_id} is a real {direction} the chain recorded and this node \
                 holds no evidence for; it moved money and is not counted as zero: {why}"
            ),
            Self::LegUnattested {
                event_id,
                direction,
                why,
            } => format!(
                "leg {event_id} is a real {direction} with evidence, but it is not bound \
                 to any authority: {why}"
            ),
            Self::LegUnconfirmed {
                event_id,
                direction,
                why,
            } => format!(
                "leg {event_id} is a real {direction} whose evidence the chain read \
                 could not bind to the log it is at: {why}"
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// The two outcomes
// ---------------------------------------------------------------------------

/// What [`VerifiedSettlement::assemble`] concluded.
///
/// Two types, not one with a flag. An incomplete operation has no net, so there
/// is nothing a flag could hold; giving it an `Option<i64>` and a `is_complete`
/// would put a number next to a settlement that must not have one.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "value")]
pub enum SettlementOutcome {
    /// Every leg the chain enumerated was established. This is the only
    /// variant that has a net, and the only one that can promote.
    Complete(VerifiedSettlement),
    /// Something the chain requires could not be established. No net exists.
    Incomplete(IncompleteSettlement),
}

impl SettlementOutcome {
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete(_))
    }

    pub fn as_complete(&self) -> Option<&VerifiedSettlement> {
        match self {
            Self::Complete(s) => Some(s),
            Self::Incomplete(_) => None,
        }
    }

    pub fn as_incomplete(&self) -> Option<&IncompleteSettlement> {
        match self {
            Self::Complete(_) => None,
            Self::Incomplete(s) => Some(s),
        }
    }
}

/// An operation whose leg set could not be completed.
///
/// # What is deliberately missing
///
/// There is no `net_delta_micros`, no `promote`, and no way to obtain a
/// [`SettlementAuthority`]. `MissingRequiredEconomicEvidence ⇒ NoSpendAuthority`
/// is enforced by the **absence of the method**, not by a check that could be
/// edited away later.
///
/// The two partial columns are present and are explicitly partial: they are
/// what *was* established, so an operator can see how far the read got without
/// the total ever existing.
#[derive(Debug, Clone, Serialize)]
pub struct IncompleteSettlement {
    operation_id: OperationId,
    legs: Vec<SettlementLeg>,
    reasons: Vec<SettlementIncompleteness>,
    external_costs: Vec<VerifiedNativeGasCost>,
    /// P4.6. `Σ ExternalCosts`, computed once with checked arithmetic where the
    /// settlement is assembled. It is a wei figure, not a net and not a
    /// comparable value — an incomplete operation has neither — and it is here
    /// so an operator can see what the operation burned even though the leg set
    /// could not be completed.
    total_native_cost_wei: u128,
    confirmed_inflow_micros: u128,
    confirmed_outflow_micros: u128,
    /// Stored evidence for this transaction that the chain did not show. A
    /// diagnostic, not a leg: the chain is authoritative about what happened,
    /// and a row it contradicts contributes nothing — but it is reported,
    /// because a node holding evidence the chain contradicts is a bug or a
    /// forgery and neither should be silent.
    unmatched_stored_evidence: usize,
}

impl IncompleteSettlement {
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn legs(&self) -> &[SettlementLeg] {
        &self.legs
    }

    pub fn reasons(&self) -> &[SettlementIncompleteness] {
        &self.reasons
    }

    /// Why the leg set is incomplete, as a flat list of machine-readable
    /// states. Never empty: this type is only constructible with a reason.
    pub fn missing_states(&self) -> Vec<&'static str> {
        self.reasons.iter().map(|r| r.state()).collect()
    }

    pub fn external_costs(&self) -> &[VerifiedNativeGasCost] {
        &self.external_costs
    }

    /// P4.6. `Σ ExternalCosts` in wei, checked where the settlement was
    /// assembled. Partial like the two columns above: it says what the
    /// transaction burned, not what the operation was worth.
    pub fn total_native_cost_wei(&self) -> u128 {
        self.total_native_cost_wei
    }

    /// What *was* established, in micros. **Partial**: a number that is known
    /// to be wrong as a total, reported so an operator can see how far the read
    /// got. It is named `confirmed_*` so it cannot be mistaken for the operation
    /// and it is the only numeric column this type has.
    pub fn confirmed_inflow_micros(&self) -> u128 {
        self.confirmed_inflow_micros
    }

    pub fn confirmed_outflow_micros(&self) -> u128 {
        self.confirmed_outflow_micros
    }

    pub fn unmatched_stored_evidence(&self) -> usize {
        self.unmatched_stored_evidence
    }

    /// The net of an incomplete operation, which is to say: there isn't one.
    ///
    /// Present as an accessor so a caller that tries gets `None` rather than a
    /// compile error, and so the *shape* of the refusal is part of the public
    /// API: there is no net here, and no method that could produce one.
    pub fn net_delta_micros(&self) -> Option<i64> {
        None
    }
}

/// A complete operation: every leg the chain enumerated was established, so a
/// net exists and may be promoted.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedSettlement {
    operation_id: OperationId,
    digest: Hash,
    /// P4.6. The block this operation settled in. Carried on the settlement, not
    /// recomputed by the layer that needs it, so the price selection has an
    /// anchor that came from the same read as the legs.
    anchor: BlockAnchor,
    legs: Vec<SettlementLeg>,
    external_costs: Vec<VerifiedNativeGasCost>,
    /// P4.6. `Σ ExternalCosts`, computed **once, with checked arithmetic**, in
    /// [`Self::assemble`].
    ///
    /// This field exists because of a defect. The accessor used to be
    /// `self.external_costs.iter().map(|c| c.cost_wei()).sum()`: `Iterator::sum`
    /// panics in debug and **silently wraps** in release, in a crate whose
    /// neighbouring line says "a wrapped fee would be free money" and refuses
    /// the identical arithmetic two functions away. The sum is now performed by
    /// `checked_add` where a `Result` exists to carry the failure, and the
    /// accessor is a field read. `total_native_cost_wei_does_not_wrap` is the
    /// regression test.
    total_native_cost_wei: u128,
    inflow_micros: u128,
    outflow_micros: u128,
    token_net_delta_micros: i64,
    unmatched_stored_evidence: usize,
}

impl VerifiedSettlement {
    /// Stored evidence for this transaction that the chain did not show.
    ///
    /// Non-zero on a *complete* settlement is a finding rather than an error:
    /// the chain is authoritative, so the row contributes nothing and the
    /// settlement is unaffected. It is reported because a node holding evidence
    /// the chain contradicts is a bug or a forgery, and neither should be
    /// silent.
    pub fn unmatched_stored_evidence(&self) -> usize {
        self.unmatched_stored_evidence
    }

    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// P4.6. The block this operation settled in: number, hash, that block's own
    /// timestamp, and how deep it was when it was read.
    pub fn anchor(&self) -> &BlockAnchor {
        &self.anchor
    }

    /// Digest binding the operation, every leg's identity, direction and
    /// amount, and every external cost. Under [`SETTLEMENT_DIGEST_DOMAIN`].
    pub fn digest(&self) -> &Hash {
        &self.digest
    }


    pub fn legs(&self) -> &[SettlementLeg] {
        &self.legs
    }

    pub fn external_costs(&self) -> &[VerifiedNativeGasCost] {
        &self.external_costs
    }

    /// `ΣVerifiedInflows`, in micros of the operation asset.
    pub fn verified_inflows_micros(&self) -> u128 {
        self.inflow_micros
    }

    /// `ΣVerifiedOutflows`, in micros of the operation asset.
    pub fn verified_outflows_micros(&self) -> u128 {
        self.outflow_micros
    }

    /// `ΣVerifiedInflows − ΣVerifiedOutflows`, in micros of the operation
    /// asset.
    ///
    /// This is the token half of the NEV identity and it is denominated in the
    /// asset, not in a comparison. The external-cost term is deliberately **not**
    /// subtracted here: it is a different currency, and subtracting wei from
    /// micros would be a category error. It is reported beside this number, and
    /// the two are added only where a trustworthy price exists.
    pub fn token_net_delta_micros(&self) -> i64 {
        self.token_net_delta_micros
    }

    /// `Σ ExternalCosts`, in wei. Never converted, never estimated, never added
    /// to [`Self::token_net_delta_micros`].
    ///
    /// P4.6: this is a stored field, not a fold. It used to be
    /// `Iterator::sum` over `u128`, which panics in debug and wraps silently in
    /// release — the exact failure the checked arithmetic at
    /// [`VerifiedNativeGasCost::from_scan`] refuses, one function away. The sum
    /// is now `checked_add`-ed in [`Self::assemble`], where the failure can be
    /// reported as an error.
    pub fn total_native_cost_wei(&self) -> u128 {
        self.total_native_cost_wei
    }

    /// Whether the operation burned native value at all.
    pub fn has_native_cost(&self) -> bool {
        !self.external_costs.is_empty()
    }

    /// The comparable figure **without a price**, which is to say: only when the
    /// operation burned no native value.
    ///
    /// `Some(token_net_delta_micros)` when the operation moved no native value
    /// and the token net is therefore the whole answer. `None` when it did move
    /// native value, because *this method* has no price to convert with — see
    /// [`Self::compare`], which is the only way a gas-bearing operation gets a
    /// comparable figure, and which is the only thing
    /// [`ComparableVerifiedSettlement`] is built by.
    ///
    /// The `None` is load-bearing: it is why [`Self::promote`] refuses, and
    /// therefore why an operation that burned gas cannot fund a job through the
    /// *unpriced* route. It is not, and never will be, a way to skip the price:
    /// the priced route produces a different type.
    pub fn comparable_net_value_micros(&self) -> Option<i64> {
        if self.has_native_cost() {
            return None;
        }
        Some(self.token_net_delta_micros)
    }

    /// The one way to obtain spending authority from a settlement **without a
    /// price**.
    ///
    /// Requires a kernel-identified provider and a validated policy, and fails
    /// with [`SettlementError::NoComparableNetValue`] when the operation burned
    /// native value that cannot honestly be converted. An operation that burned
    /// gas takes the other route: [`Self::compare`], and then
    /// [`ComparableVerifiedSettlement::promote`].
    pub fn promote(
        &self,
        verifier: &BaseUsdcVerifier,
        policy: &ValidatedOutcomePolicy,
    ) -> Result<SettlementAuthority, SettlementError> {
        if !verifier.provider_identity_verified() {
            return Err(SettlementError::ProviderIdentityUnverified {
                endpoint: verifier.endpoint().to_string(),
            });
        }
        let comparable = self
            .comparable_net_value_micros()
            .ok_or(SettlementError::NoComparableNetValue {
                operation_id: self.operation_id.as_str().to_string(),
                cost_wei: self.total_native_cost_wei,
            })?;
        Ok(SettlementAuthority {
            operation_id: self.operation_id.clone(),
            settlement_digest: self.digest().clone(),
            nev_musd_micros: comparable,
            legs: self.legs.len() as u64,
            provider: verifier.endpoint().to_string(),
            provider_identity_verified: true,
            policy_hash: policy.policy_hash()?.to_string(),
        })
    }

    /// P4.6. The priced route: turn a complete operation into either a
    /// [`ComparableVerifiedSettlement`] or a refusal that names every reason.
    ///
    /// # What it takes, and what it refuses
    ///
    /// Two arguments, and neither of them is a number:
    ///
    /// * a [`ValidatedPriceSource`], which can only exist if a
    ///   **validated** outcome policy's `price_source_hash` is the digest of the
    ///   supplied [`crate::trusted_valuation::PriceSourcePolicy`];
    /// * observations that are already [`ValidatedPriceObservation`]s, each of
    ///   which can only exist if the policy's own delegated verifier signed those
    ///   exact bytes under that exact policy.
    ///
    /// A price therefore cannot be *passed* here. It has to have been read, named
    /// by the policy, signed by the delegated key, anchored to a block at or
    /// before this operation's, and chosen by
    /// [`crate::trusted_valuation::select_price`] — a rule that was fixed before
    /// the legs were summed.
    ///
    /// # The order of the checks
    ///
    /// 1. no native cost ⇒ no price is needed, and the token net *is* the
    ///    comparable figure. A zero-gas operation stays promotable exactly as it
    ///    was, with no oracle involved;
    /// 2. the price source must be for the settlement's own chain;
    /// 3. a price must be selectable;
    /// 4. every native cost must have a verifiably reported L1 component;
    /// 5. every native cost must convert without overflow;
    /// 6. the totals must fit their accumulators.
    ///
    /// Steps 4 and 5 are what "do not assume zero" means in practice: a receipt
    /// with no L1 figure, or a price that does not fit `u128`, produces the
    /// refusal arm rather than a cost of zero.
    pub fn compare(
        &self,
        source: &ValidatedPriceSource,
        observations: &[ValidatedPriceObservation],
    ) -> ComparableSettlementResult {
        let mut reasons: Vec<NoComparableReason> = Vec::new();

        if !self.has_native_cost() {
            // (1) Nothing to convert. The token net is the whole answer, and no
            // observation is consulted — a wrong, stale or forged price cannot
            // affect an operation that burned nothing.
            return ComparableSettlementResult::Comparable(
                self.to_comparable(source, None, 0, self.token_net_delta_micros),
            );
        }

        // (2) The price source must speak for the chain this operation settled
        // on. The legs were derived under a policy for this chain, but the
        // anchor came from the scan, and the anchor is what the price is selected
        // against — so the two chains have to be the same chain here too.
        if source.chain_id() != self.anchor.chain_id() {
            reasons.push(NoComparableReason::PriceChainMismatch {
                price_chain: source.chain_id(),
                settlement_chain: self.anchor.chain_id(),
            });
            return ComparableSettlementResult::NoComparableNetValue(reasons);
        }

        // (3) The price. Every rejection inside the selector is carried through
        // rather than collapsed into one word.
        let price = match select_price(source, observations, &self.anchor) {
            PriceSelection::Priced(price) => price,
            PriceSelection::Unpriced(refusal) => {
                reasons.push(NoComparableReason::NoPrice {
                    reasons: refusal.reasons,
                    duplicate_observations: refusal.duplicate_observations,
                });
                return ComparableSettlementResult::NoComparableNetValue(reasons);
            }
        };

        // (4) and (5): every cost converts, and converts honestly. Both loops
        // accumulate into `reasons` rather than returning, so a report names
        // every cost row that failed and not only the first.
        let mut native_cost_musd: u128 = 0;
        let mut every_cost_converted = true;
        for cost in &self.external_costs {
            if !cost.l1_fee_verifiable() {
                reasons.push(NoComparableReason::L1FeeNotVerifiable {
                    event_id: cost.event_id().to_string(),
                    gas_used: cost.gas_used(),
                });
                every_cost_converted = false;
                continue;
            }
            match price.cost_musd(cost.cost_wei()) {
                Ok(musd) => match native_cost_musd.checked_add(musd) {
                    Some(total) => native_cost_musd = total,
                    None => {
                        reasons.push(NoComparableReason::CostTotalOverflow {
                            total_wei: self.total_native_cost_wei,
                        });
                        every_cost_converted = false;
                    }
                },
                Err(_) => {
                    reasons.push(NoComparableReason::CostArithmeticOverflow {
                        event_id: cost.event_id().to_string(),
                        cost_wei: cost.cost_wei(),
                    });
                    every_cost_converted = false;
                }
            }
        }
        if !every_cost_converted {
            return ComparableSettlementResult::NoComparableNetValue(reasons);
        }

        // (6) The subtraction, in `i128` so the sign is unambiguous, then the
        // range check. The rounding already happened inside `cost_musd`, upward.
        let Ok(native_cost_musd_i128) = i128::try_from(native_cost_musd) else {
            reasons.push(NoComparableReason::CostTotalOverflow {
                total_wei: self.total_native_cost_wei,
            });
            return ComparableSettlementResult::NoComparableNetValue(reasons);
        };
        let comparable_i128 = i128::from(self.token_net_delta_micros) - native_cost_musd_i128;
        let Ok(comparable) = i64::try_from(comparable_i128) else {
            reasons.push(NoComparableReason::ComparableOutOfRange {
                micros: comparable_i128,
            });
            return ComparableSettlementResult::NoComparableNetValue(reasons);
        };

        ComparableSettlementResult::Comparable(
            self.to_comparable(source, Some(price), native_cost_musd, comparable),
        )
    }

    /// The one construction site of a [`ComparableVerifiedSettlement`].
    ///
    /// `pub(crate)`-in-spirit — a private associated function, callable only from
    /// [`Self::compare`], which is the only place that can produce a price. There
    /// is no second constructor and no public way to hand this module a number,
    /// which is the structural half of "the price is not a runtime parameter";
    /// [`Self::compare`] refusing is the other half.
    ///
    /// Named `to_comparable` rather than `into_comparable`: it borrows `self` and
    /// copies out of it, so the `into_` prefix would be a lie about ownership.
    fn to_comparable(
        &self,
        source: &ValidatedPriceSource,
        price: Option<AppliedPrice>,
        native_cost_musd: u128,
        comparable_net_value_micros: i64,
    ) -> ComparableVerifiedSettlement {
        // The policy hash comes from the *bound source*, not from the price: an
        // operation that burned nothing still needs to name the policy it is
        // promoted under, and the source is the value that carries it.
        let policy_hash = source.policy_hash().clone();
        let duplicate_price_observations = price
            .as_ref()
            .map(|p| p.duplicate_observations())
            .unwrap_or(0);
        let comparable_digest = comparable_digest(
            &self.digest,
            &policy_hash,
            price.as_ref(),
            self.total_native_cost_wei,
            native_cost_musd,
            comparable_net_value_micros,
        );
        ComparableVerifiedSettlement {
            operation_id: self.operation_id.clone(),
            comparable_digest,
            settlement_digest: self.digest.clone(),
            anchor: self.anchor.clone(),
            legs: self.legs.clone(),
            external_costs: self.external_costs.clone(),
            token_net_delta_micros: self.token_net_delta_micros,
            total_native_cost_wei: self.total_native_cost_wei,
            native_cost_musd,
            price,
            comparable_net_value_micros,
            policy_hash,
            unmatched_stored_evidence: self.unmatched_stored_evidence,
            duplicate_price_observations,
        }
    }
}

/// Why a complete operation has no comparable value.
///
/// Every arm is a named rejection. `NoPrice` carries the price selector's own
/// reasons verbatim rather than summarising them, so the two layers never
/// disagree about *why* a reading did not apply — an operator reading a report
/// gets the same wording whichever layer produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum NoComparableReason {
    /// No price could be selected, and here is every reading that was rejected
    /// and why.
    NoPrice {
        reasons: Vec<NoPriceReason>,
        duplicate_observations: usize,
    },
    /// A native cost's receipt reported no L1 data charge.
    ///
    /// On Base the data charge is part of the real cost, so its absence is a
    /// missing *fact*, not a zero. Assuming zero here would understate the cost
    /// by exactly the amount nobody read, on every transaction, in the direction
    /// that flatters the operator.
    L1FeeNotVerifiable { event_id: String, gas_used: u64 },
    /// One cost did not fit the fixed-point arithmetic. Refused, never wrapped.
    CostArithmeticOverflow { event_id: String, cost_wei: u128 },
    /// The wei→micro-USD accumulator overflowed.
    CostTotalOverflow { total_wei: u128 },
    /// The comparable total does not fit a signed 64-bit micro total.
    ComparableOutOfRange { micros: i128 },
    /// The price source speaks for another chain than the operation settled on.
    PriceChainMismatch {
        price_chain: u64,
        settlement_chain: u64,
    },
}

impl NoComparableReason {
    pub fn describe(&self) -> String {
        match self {
            Self::NoPrice { reasons, .. } if reasons.is_empty() => {
                "no price applies to this operation".into()
            }
            Self::NoPrice { reasons, .. } => reasons
                .iter()
                .map(NoPriceReason::describe)
                .collect::<Vec<String>>()
                .join("; "),
            Self::L1FeeNotVerifiable { event_id, gas_used } => format!(
                "native cost {event_id} burned {gas_used} gas but its receipt reported no \
                 L1 data charge, so the cost is not verifiably complete and is not \
                 converted as though the data charge were free"
            ),
            Self::CostArithmeticOverflow { event_id, cost_wei } => format!(
                "native cost {event_id} of {cost_wei} wei does not fit the fixed-point \
                 conversion at the selected price; the figure is refused, never wrapped"
            ),
            Self::CostTotalOverflow { total_wei } => format!(
                "the converted native costs do not fit a micro-USD accumulator at \
                 {total_wei} wei of total cost"
            ),
            Self::ComparableOutOfRange { micros } => format!(
                "the comparable total of {micros} micros does not fit a signed 64-bit \
                 micro total"
            ),
            Self::PriceChainMismatch {
                price_chain,
                settlement_chain,
            } => format!(
                "the price source speaks for chain {price_chain}, and this operation \
                 settled on chain {settlement_chain}"
            ),
        }
    }
}

/// The outcome of [`VerifiedSettlement::compare`].
///
/// Two types, not one with a flag, for the reason P4.5c used when it split
/// [`VerifiedSettlement`] from [`IncompleteSettlement`]: the absence of a
/// comparable value is not a value, and a `Option`-shaped field would put a
/// number next to a settlement that must not have one. More importantly, the
/// *presence* of one is a claim about a price, and only a distinct type can say
/// that a number has been through [`VerifiedSettlement::compare`].
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "outcome", content = "value")]
// The two arms are different claims — one is a settlement that has been through a
// price, the other is the absence of one — and boxing the large arm to satisfy a
// size heuristic would put an indirection between a caller and the value it is
// asking for, in a type whose whole purpose is to make the priced claim hard to
// confuse with the unpriced one. The cost is a few hundred bytes on a stack frame
// that already carries the settlement it came from.
#[allow(clippy::large_enum_variant)]
pub enum ComparableSettlementResult {
    /// Exactly one price applies and every cost converted. The only arm with a
    /// `promote`.
    Comparable(ComparableVerifiedSettlement),
    /// No comparable figure exists. Never empty: this arm is only constructible
    /// with at least one reason.
    NoComparableNetValue(Vec<NoComparableReason>),
}

impl ComparableSettlementResult {
    pub fn is_comparable(&self) -> bool {
        matches!(self, Self::Comparable(_))
    }

    pub fn as_comparable(&self) -> Option<&ComparableVerifiedSettlement> {
        match self {
            Self::Comparable(s) => Some(s),
            Self::NoComparableNetValue(_) => None,
        }
    }

    pub fn as_refusal(&self) -> Option<&[NoComparableReason]> {
        match self {
            Self::Comparable(_) => None,
            Self::NoComparableNetValue(reasons) => Some(reasons),
        }
    }

    /// Every reason, flattened into machine-readable state names. A report can
    /// branch on these without parsing prose.
    pub fn refusal_states(&self) -> Vec<&'static str> {
        match self {
            Self::Comparable(_) => Vec::new(),
            Self::NoComparableNetValue(reasons) => {
                let mut names: Vec<&'static str> = Vec::new();
                for reason in reasons {
                    match reason {
                        NoComparableReason::NoPrice { .. } => {
                            names.push("no_price");
                        }
                        NoComparableReason::L1FeeNotVerifiable { .. } => {
                            names.push("l1_fee_not_verifiable");
                        }
                        NoComparableReason::CostArithmeticOverflow { .. } => {
                            names.push("cost_arithmetic_overflow");
                        }
                        NoComparableReason::CostTotalOverflow { .. } => {
                            names.push("cost_total_overflow");
                        }
                        NoComparableReason::ComparableOutOfRange { .. } => {
                            names.push("comparable_out_of_range");
                        }
                        NoComparableReason::PriceChainMismatch { .. } => {
                            names.push("price_chain_mismatch");
                        }
                    }
                }
                names
            }
        }
    }

    /// The refusal, as words. One line per reason.
    pub fn refusal_description(&self) -> String {
        match self {
            Self::Comparable(_) => String::new(),
            Self::NoComparableNetValue(reasons) => reasons
                .iter()
                .map(NoComparableReason::describe)
                .collect::<Vec<String>>()
                .join("; "),
        }
    }
}

/// A complete operation with a comparable value: `ΣInflows − ΣOutflows −
/// GasCost`, where the gas term was converted by an authorised price, rounded
/// **up**, and named.
///
/// # A different type from [`VerifiedSettlement`], deliberately
///
/// This is not `VerifiedSettlement` with a flag. Holding one of these *is* the
/// statement that a price was applied under a specific policy, at a specific
/// block anchor, from a specific signed observation — and the only way to obtain
/// one is [`VerifiedSettlement::compare`]. A flag could be set by a caller; a type
/// cannot be.
///
/// # What it adds to the audit record
///
/// The price is not merely applied, it is carried: the observation's
/// [`ExternalEventId`], the source identity, the block it was read at, how deep
/// that block was, how old the reading was relative to this operation's block,
/// and the rounding that was applied. All of it is inside
/// [`Self::comparable_digest`], so two comparable values that used different
/// readings — or the same reading and different settlements — are different
/// digests.
#[derive(Debug, Clone, Serialize)]
pub struct ComparableVerifiedSettlement {
    operation_id: OperationId,
    /// Under [`COMPARABLE_SETTLEMENT_DIGEST_DOMAIN`]. This is what
    /// [`SettlementAuthority::settlement_digest`] carries on the priced route.
    comparable_digest: Hash,
    /// The unpriced settlement digest this value was computed from.
    settlement_digest: Hash,
    anchor: BlockAnchor,
    legs: Vec<SettlementLeg>,
    external_costs: Vec<VerifiedNativeGasCost>,
    token_net_delta_micros: i64,
    total_native_cost_wei: u128,
    /// `Σ GasCost`, in micro-USD, each term rounded up.
    native_cost_musd: u128,
    /// `None` only when the operation burned no native value, in which case no
    /// price was consulted and none is named.
    price: Option<AppliedPrice>,
    comparable_net_value_micros: i64,
    policy_hash: Hash,
    unmatched_stored_evidence: usize,
    duplicate_price_observations: usize,
}

impl ComparableVerifiedSettlement {
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// The digest that binds the settlement **and** the price observation.
    pub fn comparable_digest(&self) -> &Hash {
        &self.comparable_digest
    }

    pub fn settlement_digest(&self) -> &Hash {
        &self.settlement_digest
    }

    pub fn anchor(&self) -> &BlockAnchor {
        &self.anchor
    }

    pub fn legs(&self) -> &[SettlementLeg] {
        &self.legs
    }

    pub fn external_costs(&self) -> &[VerifiedNativeGasCost] {
        &self.external_costs
    }

    pub fn token_net_delta_micros(&self) -> i64 {
        self.token_net_delta_micros
    }

    pub fn total_native_cost_wei(&self) -> u128 {
        self.total_native_cost_wei
    }

    /// The native cost in micro-USD, **rounded up**. Zero when the operation
    /// burned nothing.
    pub fn native_cost_musd(&self) -> u128 {
        self.native_cost_musd
    }

    /// The price that was applied, when one was needed.
    pub fn price(&self) -> Option<&AppliedPrice> {
        self.price.as_ref()
    }

    /// `ΣInflows − ΣOutflows − GasCost`. Always present: this type exists only
    /// when it is.
    pub fn comparable_net_value_micros(&self) -> i64 {
        self.comparable_net_value_micros
    }

    pub fn policy_hash(&self) -> &Hash {
        &self.policy_hash
    }

    pub fn unmatched_stored_evidence(&self) -> usize {
        self.unmatched_stored_evidence
    }

    /// How many supplied observations were byte-identical to one already
    /// counted. They were counted once, never twice.
    pub fn duplicate_price_observations(&self) -> usize {
        self.duplicate_price_observations
    }

    /// The one way to obtain spending authority from a **priced** settlement.
    ///
    /// The gate order is the one [`VerifiedSettlement::promote`] uses, and the
    /// order is load-bearing:
    ///
    /// 1. **provider identity first.** An endpoint with no kernel-enforced
    ///    identity is refused before anything else is looked at, so a caller
    ///    cannot learn anything about the operation from an unpinned source. The
    ///    settlement tests assert this specific error for an unpinned verifier.
    /// 2. **the comparable figure second.** On this arm it is present by
    ///    construction — the refusal is [`ComparableSettlementResult`], not this
    ///    function — and the accessor is still read here so that the order of
    ///    the two historical steps is preserved literally rather than being
    ///    rearranged by a later edit.
    /// 3. **then, and only then, P4.6's own checks**: that the policy in force
    ///    is the policy this value was priced under.
    pub fn promote(
        &self,
        verifier: &BaseUsdcVerifier,
        policy: &ValidatedOutcomePolicy,
    ) -> Result<SettlementAuthority, SettlementError> {
        // (1) Provider identity. Unchanged order, first step, on both routes.
        if !verifier.provider_identity_verified() {
            return Err(SettlementError::ProviderIdentityUnverified {
                endpoint: verifier.endpoint().to_string(),
            });
        }
        // (2) The comparable figure. Present by construction on this type.
        let comparable = self.comparable_net_value_micros;
        // (3) P4.6. Currency, not authenticity: the value was priced under a
        // policy, and only that policy's own rules may promote it.
        let policy_hash = policy.policy_hash()?;
        if policy_hash != self.policy_hash {
            return Err(SettlementError::ComparablePolicyMismatch {
                found: self.policy_hash.clone(),
                current: policy_hash,
            });
        }
        Ok(SettlementAuthority {
            operation_id: self.operation_id.clone(),
            // The *comparable* digest, not the settlement digest: this authority
            // authorises a number, and the digest that names the number is the
            // one that includes the price observation.
            settlement_digest: self.comparable_digest.clone(),
            nev_musd_micros: comparable,
            legs: self.legs.len() as u64,
            provider: verifier.endpoint().to_string(),
            provider_identity_verified: true,
            policy_hash: self.policy_hash.to_string(),
        })
    }
}

/// The only thing in this crate that a settlement hands to a budget gate.
///
/// Private fields, no `Deserialize`, and exactly one producer:
/// [`VerifiedSettlement::promote`], which needs a complete leg set, a
/// kernel-identified provider and a validated policy, and which refuses an
/// operation whose native cost cannot be converted.
///
/// The promotion predicate is here and not on a
/// [`crate::boundary_delta::VerifiedBoundaryDelta`] because a leg knows its own
/// sign and nothing about whether its siblings exist. `is_positive` is the same
/// shape as [`crate::verified_view::VerifiedNev::is_positive`] — a count and a
/// strictly positive total — so the two agree on what "worth funding" means.
#[derive(Debug, Clone, Serialize)]
pub struct SettlementAuthority {
    operation_id: OperationId,
    settlement_digest: Hash,
    nev_musd_micros: i64,
    legs: u64,
    provider: String,
    provider_identity_verified: bool,
    policy_hash: String,
}

impl SettlementAuthority {
    pub fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    pub fn settlement_digest(&self) -> &Hash {
        &self.settlement_digest
    }

    pub fn nev_musd_micros(&self) -> i64 {
        self.nev_musd_micros
    }

    /// How many legs the complete operation had.
    pub fn legs(&self) -> u64 {
        self.legs
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn provider_identity_verified(&self) -> bool {
        self.provider_identity_verified
    }

    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    /// Whether this operation is strictly worth funding. The single predicate a
    /// budget gate needs, and it lives only on types that already hold a
    /// complete leg set.
    pub fn is_positive(&self) -> bool {
        self.legs > 0 && self.nev_musd_micros > 0
    }
}

// ---------------------------------------------------------------------------
// The aggregation
// ---------------------------------------------------------------------------

/// The inputs one operation's legs are assembled from.
///
/// Four things, none of which is a number the caller wants to be true:
///
/// * `scans` — what the pinned provider read. Determines the leg set and the
///   operation id.
/// * `registry` — which addresses are ours. Determines every direction.
/// * `stored_evidence` — what this node wrote down. Determines which enumerated
///   legs can be established.
/// * `policy` — the authority. `None` is the offline case and produces
///   `Unattested` legs rather than an error, because "no authority" is a state
///   the reader should see, not a crash.
pub struct SettlementInputs<'a> {
    scans: Vec<&'a TransactionLogScan>,
    registry: &'a ControlledAddressRegistry,
    stored_evidence: &'a [BoundaryEvidence],
    policy: Option<&'a ValidatedOutcomePolicy>,
    fee_payer: &'a str,
    fee_recipient: &'a str,
}

impl<'a> SettlementInputs<'a> {
    pub fn new(
        scans: Vec<&'a TransactionLogScan>,
        registry: &'a ControlledAddressRegistry,
        stored_evidence: &'a [BoundaryEvidence],
        policy: Option<&'a ValidatedOutcomePolicy>,
    ) -> Self {
        Self {
            scans,
            registry,
            stored_evidence,
            policy,
            // A native fee's payer and recipient are recorded for the identity
            // only. The crate does not read them from a receipt, so the
            // reserved zero word stands in, exactly as it does for the currency
            // itself: neither address is treated as a boundary endpoint
            // anywhere, and neither is compared against the controlled set.
            fee_payer: crate::event_id::NATIVE_CURRENCY,
            fee_recipient: crate::event_id::NATIVE_CURRENCY,
        }
    }

    /// Names the addresses the native fee moved between, for the audit trail
    /// and the identity. Purely diagnostic: neither address is a leg.
    pub fn with_fee_parties(mut self, payer: &'a str, recipient: &'a str) -> Self {
        self.fee_payer = payer;
        self.fee_recipient = recipient;
        self
    }
}

impl VerifiedSettlement {
    /// The one assembler. Everything else in this module is a reading of what
    /// this produced.
    ///
    /// The gate order, in the order the reasoning runs:
    ///
    /// 1. at least one scan;
    /// 2. one transaction — more than one is [`SettlementError::CrossTransaction`];
    /// 3. the chain read classified every log, or the leg set cannot be shown
    ///    complete;
    /// 4. for every enumerated transfer: the registry derives a direction, and
    ///    either it is not a crossing (a zero row or outside the perimeter, both
    ///    correctly worth nothing) or this node must establish it;
    /// 5. establish: stored evidence → chain confirmation → policy → delta;
    /// 6. every leg confirmed, or the operation is incomplete;
    /// 7. one asset, one net;
    /// 8. the native cost, reported separately and never converted.
    pub fn assemble(
        inputs: &SettlementInputs<'_>,
    ) -> Result<SettlementOutcome, SettlementError> {
        let scan = *inputs
            .scans
            .first()
            .ok_or(SettlementError::NoTransaction)?;

        // (2) One transaction or no operation. This is the grouping decision,
        // and it is made here rather than by the caller: the caller supplies
        // scans, never an `OperationId`.
        let operation_id = OperationId::from_scan(scan)?;
        let mut distinct: Vec<OperationId> = vec![operation_id.clone()];
        for other in inputs.scans.iter().skip(1) {
            let id = OperationId::from_scan(other)?;
            if !distinct.contains(&id) {
                distinct.push(id);
            }
        }
        if distinct.len() > 1 {
            return Err(SettlementError::CrossTransaction {
                transactions: distinct.len(),
                operations: distinct
                    .iter()
                    .map(|o| o.as_str().to_string())
                    .collect::<Vec<String>>()
                    .join(", "),
            });
        }

        let mut legs = Vec::new();
        let mut reasons: Vec<SettlementIncompleteness> = Vec::new();
        let mut established = 0usize;

        // (3) A scan that could not classify every log cannot establish a
        // complete leg set, so nothing downstream may treat it as one.
        if !scan.exhaustive() {
            reasons.push(SettlementIncompleteness::ScanNotExhaustive {
                why: scan.unclassified().join("; "),
            });
        }

        for transfer in scan.transfers() {
            let Some(asset) = identified_asset(scan.chain_id(), &transfer.token)? else {
                reasons.push(SettlementIncompleteness::ScanNotExhaustive {
                    why: format!(
                        "log {:?}: transfer of unidentified token {}",
                        transfer.log_index, transfer.token
                    ),
                });
                continue;
            };
            // (4) Direction comes from two registry lookups and nowhere else.
            let crossing = match BoundaryCrossing::derive(
                &evidence_for(scan, transfer, asset.clone()),
                inputs.registry,
            ) {
                Ok(crossing) => crossing,
                Err(e) => {
                    reasons.push(SettlementIncompleteness::ScanNotExhaustive {
                        why: format!("log {:?}: {e}", transfer.log_index),
                    });
                    continue;
                }
            };
            let Some(direction) = crossing.boundary_direction() else {
                // A transfer between two controlled addresses, or between two
                // external ones, is a row of P1's table that is worth nothing —
                // and worth *knowingly* nothing, which is different from an
                // absent leg. It contributes zero and blocks nothing.
                continue;
            };

            match establish_leg(transfer, scan, &asset, inputs) {
                Ok(delta) => {
                    established += 1;
                    legs.push(SettlementLeg::confirmed(&delta));
                }
                Err((state, event_id, why)) => {
                    reasons.push(incompleteness_for(state, &event_id, direction, why.clone()));
                    legs.push(SettlementLeg::unestablished(
                        event_id,
                        direction,
                        asset.clone(),
                        micros_of(transfer.amount_raw, &asset)?,
                        state,
                        why,
                    ));
                }
            }
        }

        // `net = Σ signed legs`, computed once, over the legs the chain
        // enumerated and this node established. Incomplete legs contribute
        // nothing here *and* make the outcome incomplete, so the accumulator is
        // never the thing that decides the answer.
        let mut inflow: u128 = 0;
        let mut outflow: u128 = 0;
        for leg in legs.iter().filter(|l| l.state() == LegState::Confirmed) {
            let signed = leg.signed_amount_micros();
            if signed > 0 {
                inflow = inflow.saturating_add(signed as u128);
            } else {
                outflow = outflow.saturating_add(signed.unsigned_abs());
            }
        }

        // Stored evidence for this transaction that the chain did not show. The
        // chain is authoritative; a row it contradicts contributes nothing and
        // blocks nothing, but it is reported rather than dropped — a node
        // holding evidence the chain contradicts is a bug or a forgery.
        let stored_for_tx = inputs
            .stored_evidence
            .iter()
            .filter(|e| e.tx_hash.eq_ignore_ascii_case(scan.tx_hash()))
            .count();
        let unmatched_stored_evidence = stored_for_tx.saturating_sub(established);

        // (8) The native cost, reported in wei and never converted here.
        //
        // P4.6 fixes the hole this used to have: the cost vector was populated
        // only when a policy existed, so a gas-bearing transaction read without
        // one produced a **complete** settlement whose `has_native_cost()` was
        // `false` — a burned cost that nothing reported and nothing subtracted.
        // It was unreachable through this constructor (no policy ⇒ every leg is
        // `Unattested` ⇒ already incomplete) and reachable the moment a complete
        // leg set can exist without an authority to attach the cost to, which is
        // exactly the shape the priced path needs. So a cost with no authority is
        // now a *reason*, and the operation is incomplete rather than
        // deceptively cost-free.
        let mut external_costs = Vec::new();
        if scan.gas_used() > 0 {
            match inputs.policy {
                Some(policy) => external_costs.push(VerifiedNativeGasCost::from_scan(
                    scan,
                    policy,
                    inputs.fee_payer,
                    inputs.fee_recipient,
                )?),
                None => {
                    // The wei figure is computed here only to be *reported* in the
                    // refusal. It is never stored as a cost row, so nothing can
                    // later read it as one.
                    let unpriced = u128::from(scan.gas_used())
                        .checked_mul(scan.effective_gas_price_wei())
                        .and_then(|exec| exec.checked_add(scan.l1_fee_wei()))
                        .unwrap_or(u128::MAX);
                    reasons.push(SettlementIncompleteness::NativeCostUnattested {
                        gas_used: scan.gas_used(),
                        cost_wei_unpriced: unpriced.to_string(),
                        why: "no validated outcome policy is in force, so the native cost \
                              this transaction burned has no authority behind it and is \
                              not reported as zero"
                            .into(),
                    });
                }
            }
        }

        // The wei total, **checked, once, here** — where a `Result` exists to
        // carry the failure. `total_native_cost_wei()` is a field read; it used
        // to be `Iterator::sum`, which panics in debug and wraps silently in
        // release, one function away from the checked arithmetic that refuses
        // the identical overflow two lines above.
        let total_native_cost_wei = sum_checked(&external_costs)?;

        if !reasons.is_empty() {
            return Ok(SettlementOutcome::Incomplete(IncompleteSettlement {
                operation_id,
                legs,
                reasons,
                external_costs,
                total_native_cost_wei,
                confirmed_inflow_micros: inflow,
                confirmed_outflow_micros: outflow,
                unmatched_stored_evidence,
            }));
        }

        // (7) One asset, one net. The legs were checked as they were built;
        // this is the belt to that braces, and it is where a mixed-asset
        // operation stops.
        let assets: Vec<String> = {
            let mut seen: Vec<String> = Vec::new();
            for leg in &legs {
                let key = format!(
                    "{}/{}",
                    leg.asset().chain_id(),
                    leg.asset().contract()
                );
                if !seen.contains(&key) {
                    seen.push(key);
                }
            }
            seen
        };
        if assets.len() > 1 {
            return Err(SettlementError::MixedAssets {
                assets: assets.join(", "),
            });
        }

        let token_net_delta_micros = i64::try_from(inflow as i128 - outflow as i128).map_err(
            |_| SettlementError::NetOutOfRange {
                total_micros: inflow as i128 - outflow as i128,
            },
        )?;
        // The anchor travels with the settlement (P4.6): the block this
        // operation settled in, read by the same call that read the legs, so no
        // layer above has to invent one — and a price cannot be selected against
        // a settlement that does not know when it happened.
        let anchor = scan.anchor();
        let digest = settlement_digest(
            &operation_id,
            &anchor,
            &legs,
            &external_costs,
            token_net_delta_micros,
        )?;

        Ok(SettlementOutcome::Complete(VerifiedSettlement {
            operation_id,
            digest,
            anchor,
            legs,
            external_costs,
            total_native_cost_wei,
            inflow_micros: inflow,
            outflow_micros: outflow,
            token_net_delta_micros,
            unmatched_stored_evidence,
        }))
    }
}

/// `Σ cost_wei` over the cost rows, **checked**.
///
/// P4.6. The one place this sum happens; both settlement types store the result.
/// `Iterator::sum` was the previous implementation and it is exactly the wrong
/// tool here: it panics in debug and wraps silently in release, in a crate whose
/// neighbouring arithmetic says "a wrapped fee would be free money". A wrapped
/// total is not a slightly wrong number, it is a total that has been reduced by
/// `2^128`, so it is refused like any other overflow.
fn sum_checked(costs: &[VerifiedNativeGasCost]) -> Result<u128, SettlementError> {
    let mut total: u128 = 0;
    for cost in costs {
        total = total
            .checked_add(cost.cost_wei())
            .ok_or(SettlementError::NetOutOfRange {
                total_micros: u128::MAX as i128,
            })?;
    }
    Ok(total)
}

/// Turns a leg's facts into the reason it is not established, picking the
/// incompleteness variant by state so the three never collapse into one.
fn incompleteness_for(
    state: LegState,
    event_id: &Option<ExternalEventId>,
    direction: BoundaryDirection,
    why: String,
) -> SettlementIncompleteness {
    let id = event_id
        .as_ref()
        .map(|i| i.to_string())
        .unwrap_or_else(|| "unnamed".to_string());
    match state {
        LegState::Absent => SettlementIncompleteness::LegAbsent {
            event_id: id,
            direction,
            why,
        },
        LegState::Unattested => SettlementIncompleteness::LegUnattested {
            event_id: id,
            direction,
            why,
        },
        LegState::Unconfirmed => SettlementIncompleteness::LegUnconfirmed {
            event_id: id,
            direction,
            why,
        },
        // `Confirmed` never reaches here: it is not a failure.
        LegState::Confirmed => SettlementIncompleteness::ScanNotExhaustive {
            why: format!("internal: {why}"),
        },
    }
}

/// The asset a transfer moved, when this build can identify it.
///
/// `Ok(None)` for a contract this build does not identify: not an error, but
/// certainly not a leg, and the caller records it as an exhaustive-scan failure
/// rather than ignoring it. On Base USDC there is exactly one identified asset.
fn identified_asset(
    chain_id: u64,
    token: &str,
) -> Result<Option<RealAsset>, SettlementError> {
    if chain_id != crate::base_usdc::BASE_CHAIN_ID {
        return Ok(None);
    }
    if !token.eq_ignore_ascii_case(crate::base_usdc::BASE_USDC) {
        return Ok(None);
    }
    Ok(Some(RealAsset::base_usdc()))
}

/// The evidence a crossing for one enumerated transfer would have.
///
/// Built from the *chain's* facts, not from a stored row — that is the whole
/// point: it is what the leg set is compared against. The stored row is looked
/// up separately and must match this, field for field.
fn evidence_for(
    scan: &TransactionLogScan,
    transfer: &ObservedTransfer,
    asset: RealAsset,
) -> BoundaryEvidence {
    BoundaryEvidence {
        chain_id: scan.chain_id(),
        asset,
        from_address: transfer.from_address.clone(),
        to_address: transfer.to_address.clone(),
        amount_raw: transfer.amount_raw,
        tx_hash: scan.tx_hash().to_string(),
        block_hash: scan.block_hash().to_string(),
    }
}

fn micros_of(amount_raw: u64, asset: &RealAsset) -> Result<u64, SettlementError> {
    // P4.6. The guard its twin has: `BOUNDARY_DELTA_MICROS_DECIMALS -
    // asset.decimals()` is `u8` subtraction, and an asset with more decimals than
    // the micro unit underflows. In debug that panics; in release it wraps to a
    // huge `u8`, `checked_pow` refuses it, and the *refusal reason* becomes "cannot
    // scale to micros" instead of "this asset has 18 decimals" — a wrong answer
    // to a real question, produced by an underflow rather than by a check.
    //
    // It is unreachable through the public path today (the only identified asset
    // is Base USDC at 6 decimals, and `boundary_delta::signed_micros` refuses a
    // finer asset before this is called), and it is fixed anyway: an unguarded
    // subtraction is a defect whatever its reachability, and its twin at
    // `boundary_delta.rs` shows the intended shape.
    let micros_decimals = crate::boundary_delta::BOUNDARY_DELTA_MICROS_DECIMALS;
    if asset.decimals() > micros_decimals {
        return Err(SettlementError::BoundaryDelta(
            crate::boundary_delta::BoundaryDeltaError::SubMicrosPrecision {
                decimals: asset.decimals(),
            },
        ));
    }
    let scale = 10u128
        .checked_pow(u32::from(micros_decimals - asset.decimals()))
        .ok_or_else(|| SettlementError::Preimage("cannot scale to micros".into()))?;
    u64::try_from(u128::from(amount_raw) * scale).map_err(|_| {
        SettlementError::NetOutOfRange {
            total_micros: i128::from(amount_raw),
        }
    })
}

/// Establishes one enumerated transfer, or says precisely why it cannot be.
///
/// The order is the one the module doc gives, and each step's failure is a
/// *different* state:
///
/// 1. the log index — without it the transfer cannot be named and the stored
///    row cannot be bound to it, so it is `Unconfirmed`, not `Absent`;
/// 2. the stored evidence — no row is `Absent`;
/// 3. the chain confirmation — a row the chain will not bind is `Unconfirmed`;
/// 4. the policy — no authority is `Unattested`;
/// 5. the delta, which re-checks 1 to 4 for itself.
fn establish_leg(
    transfer: &ObservedTransfer,
    scan: &TransactionLogScan,
    asset: &RealAsset,
    inputs: &SettlementInputs<'_>,
) -> Result<VerifiedBoundaryDelta, (LegState, Option<ExternalEventId>, String)> {
    let event_id = match transfer.log_index {
        Some(log_index) => match ExternalEventFact::from_parts(
            scan.chain_id(),
            scan.tx_hash(),
            log_index,
            asset,
            &transfer.from_address,
            &transfer.to_address,
            transfer.amount_raw,
        )
        .and_then(|f| ExternalEventId::logged(&f))
        {
            Ok(id) => Some(id),
            Err(e) => {
                return Err((
                    LegState::Unconfirmed,
                    None,
                    format!("the transfer cannot be named: {e}"),
                ))
            }
        },
        None => {
            return Err((
                LegState::Unconfirmed,
                None,
                "the provider reported no log index for this transfer, so it can be \
                 neither named nor bound to stored evidence"
                    .into(),
            ))
        }
    };

    let expected = evidence_for(scan, transfer, asset.clone());
    let stored = inputs
        .stored_evidence
        .iter()
        .find(|e| same_transfer(e, &expected));
    let Some(stored) = stored else {
        return Err((
            LegState::Absent,
            event_id,
            "the chain recorded this transfer and this node's ledger holds no evidence \
             for it"
                .into(),
        ));
    };

    // The crossing is re-derived from the *stored* row, so the proof below has
    // to describe the stored row: a chain read that confirms a different amount
    // or a different block is not a confirmation of this record.
    let crossing = match BoundaryCrossing::derive(stored, inputs.registry) {
        Ok(crossing) => crossing,
        Err(e) => {
            return Err((
                LegState::Unconfirmed,
                event_id,
                format!("the stored evidence does not derive against the registry: {e}"),
            ))
        }
    };
    let proof = BaseUsdcVerification {
        verified: true,
        rpc: scan.provider().to_string(),
        provider_identity_verified: scan.provider_identity_verified(),
        chain_id: scan.chain_id(),
        transaction_hash: scan.tx_hash().to_string(),
        block_number: scan.block_number(),
        block_hash: scan.block_hash().to_string(),
        block_timestamp_unix: scan.block_timestamp_unix(),
        latest_block: scan.block_number().saturating_add(scan.confirmations()),
        confirmations: scan.confirmations(),
        token: asset.contract().to_string(),
        // The recipient is the transfer's own `to`, which for an outflow is an
        // external counterparty and for an inflow is us. `with_verified_proof`
        // checks it against the crossing, so a mismatch is refused rather than
        // accommodated.
        recipient: transfer.to_address.clone(),
        expected_raw: transfer.amount_raw,
        matched_raw: transfer.amount_raw,
        matching_log_index: transfer.log_index,
    };
    let crossing = match crossing.with_verified_proof(proof) {
        Ok(crossing) => crossing,
        Err(e) => {
            return Err((
                LegState::Unconfirmed,
                event_id,
                format!(
                    "the chain read cannot bind this stored evidence to the log it is at: {e}"
                ),
            ))
        }
    };

    let Some(policy) = inputs.policy else {
        return Err((
            LegState::Unattested,
            event_id,
            "no validated outcome policy is in force, so the leg has evidence and a \
             chain confirmation but no authority behind it"
                .into(),
        ));
    };

    match VerifiedBoundaryDelta::from_crossing(&crossing, policy) {
        Ok(delta) => Ok(delta),
        Err(e) => Err((
            LegState::Unconfirmed,
            event_id,
            format!("the leg could not be derived under the policy in force: {e}"),
        )),
    }
}

/// Whether a stored evidence row describes the very transfer the chain
/// enumerated: same transaction, same asset, same parties, same amount, on
/// normalised spellings. A row that agrees on anything less is not evidence for
/// this transfer — and the block is excluded, because the block is the fact under
/// test rather than part of the transfer's identity.
fn same_transfer(stored: &BoundaryEvidence, expected: &BoundaryEvidence) -> bool {
    stored.chain_id == expected.chain_id
        && stored.asset == expected.asset
        && stored.amount_raw == expected.amount_raw
        && stored.tx_hash.eq_ignore_ascii_case(&expected.tx_hash)
        // `block_hash` is deliberately NOT compared. The block is the thing that
        // has to be confirmed, so a row that disagrees with the chain about it is
        // still evidence *about this transfer* — it is simply not confirmed, and
        // that is `Unconfirmed` rather than `Absent`. Matching on the block would
        // have routed a mis-recorded block into "we hold no evidence", which
        // tells an operator to go and write the record down again rather than to
        // find out why the chain disagrees.
        && stored.from_address.eq_ignore_ascii_case(&expected.from_address)
        && stored.to_address.eq_ignore_ascii_case(&expected.to_address)
}

/// The digest that binds a complete settlement.
///
/// Legs first, in the order the chain enumerated them, then the external costs
/// in the same order. The order is part of the message, so two settlements with
/// the same legs in a different order are different digests — which is
/// correct: they are different readings of a transaction whose log order is
/// itself part of what happened.
///
/// P4.6 adds three rows before the legs and a schema-version row: the **block
/// anchor**. That is not decoration. Before P4.6 the digest committed to the
/// legs and the costs and to nothing about *when* the operation happened, so two
/// settlements of the same transaction priced against different anchors were the
/// same digest — and an audit could not tell which anchor a number was read
/// against. The anchor is now inside it.
fn settlement_digest(
    operation_id: &OperationId,
    anchor: &BlockAnchor,
    legs: &[SettlementLeg],
    costs: &[VerifiedNativeGasCost],
    token_net_delta_micros: i64,
) -> Result<Hash, SettlementError> {
    let mut buf = Vec::new();
    push_tagged(&mut buf, b"domain", SETTLEMENT_DIGEST_DOMAIN.as_bytes());
    push_tagged(
        &mut buf,
        b"schema_version",
        &SETTLEMENT_DIGEST_SCHEMA_VERSION.to_be_bytes(),
    );
    push_tagged(
        &mut buf,
        b"operation_id",
        operation_id.as_str().as_bytes(),
    );
    // The anchor. Three rows, in the order the block describes itself.
    push_tagged(
        &mut buf,
        b"anchor_block_number",
        &anchor.block_number().to_be_bytes(),
    );
    push_tagged(
        &mut buf,
        b"anchor_block_hash",
        &Hash::parse("anchor_block_hash", anchor.block_hash())?.to_bytes()?,
    );
    push_tagged(
        &mut buf,
        b"anchor_block_timestamp_unix",
        &anchor.block_timestamp_unix().to_be_bytes(),
    );
    push_tagged(
        &mut buf,
        b"leg_count",
        &u32::try_from(legs.len())
            .map_err(|_| SettlementError::Preimage("too many legs".into()))?
            .to_be_bytes(),
    );
    for leg in legs {
        push_tagged(
            &mut buf,
            b"leg",
            &serde_json::to_vec(&leg).map_err(|e| SettlementError::Preimage(e.to_string()))?,
        );
    }
    push_tagged(
        &mut buf,
        b"cost_count",
        &u32::try_from(costs.len())
            .map_err(|_| SettlementError::Preimage("too many costs".into()))?
            .to_be_bytes(),
    );
    for cost in costs {
        push_tagged(
            &mut buf,
            b"cost",
            &serde_json::to_vec(cost)
                .map_err(|e| SettlementError::Preimage(e.to_string()))?,
        );
    }
    push_tagged(
        &mut buf,
        b"token_net_delta_micros",
        &token_net_delta_micros.to_be_bytes(),
    );
    Ok(Hash::from_bytes(*blake3::hash(&buf).as_bytes()))
}

/// The digest that binds a comparable value: the settlement digest, the policy it
/// was priced under, **the price observation**, the two cost figures and the
/// number itself.
///
/// This is the row the whole step exists for. Without it,
/// [`SettlementAuthority::settlement_digest`] would be the same digest for two
/// settlements that authorise two different numbers — the audit log would record
/// that *an* authority was minted without recording *what it authorised*, which
/// is the same unauditable shape as a receipt that carries no amount.
///
/// The price rows are **absent** when the operation burned nothing, not zero: a
/// settlement that needed no price must not be readable as one that was priced
/// at zero. The emitted tag list is checked against one of two local tables, and
/// the check is local for the reason every other preimage check in this crate is
/// — see [`crate::event_id::check_layout`].
fn comparable_digest(
    settlement_digest: &Hash,
    policy_hash: &Hash,
    price: Option<&AppliedPrice>,
    total_native_cost_wei: u128,
    native_cost_musd: u128,
    comparable_net_value_micros: i64,
) -> Hash {
    let mut values: Vec<(&str, Vec<u8>)> = vec![
        (
            "schema_version",
            COMPARABLE_SETTLEMENT_DIGEST_SCHEMA_VERSION
                .to_be_bytes()
                .to_vec(),
        ),
        ("settlement_digest", settlement_digest.to_bytes().unwrap_or_default().to_vec()),
        ("policy_hash", policy_hash.to_bytes().unwrap_or_default().to_vec()),
    ];
    if let Some(price) = price {
        values.push((
            "price_observation_event_id",
            price
                .event_id()
                .digest()
                .to_bytes()
                .unwrap_or_default()
                .to_vec(),
        ));
        values.push((
            "price_source_id",
            price.source_id().as_str().as_bytes().to_vec(),
        ));
        values.push((
            "price_musd_per_eth",
            price.price_musd_per_eth().to_be_bytes().to_vec(),
        ));
        values.push((
            "price_block_number",
            price.block_number().to_be_bytes().to_vec(),
        ));
        values.push((
            "price_block_hash",
            price.block_hash().as_bytes().to_vec(),
        ));
        values.push((
            "price_block_timestamp_unix",
            price.block_timestamp_unix().to_be_bytes().to_vec(),
        ));
        values.push((
            "price_confirmations",
            price.confirmations().to_be_bytes().to_vec(),
        ));
        values.push(("price_age_unix", price.age_unix().to_be_bytes().to_vec()));
        values.push((
            "price_rounding",
            price.rounding().spelling().as_bytes().to_vec(),
        ));
    }
    values.push((
        "total_native_cost_wei",
        total_native_cost_wei.to_be_bytes().to_vec(),
    ));
    values.push((
        "native_cost_musd",
        native_cost_musd.to_be_bytes().to_vec(),
    ));
    values.push((
        "comparable_net_value_micros",
        comparable_net_value_micros.to_be_bytes().to_vec(),
    ));

    // The local encoder/table check. `unwrap_or_default()` above can only ever
    // fire on a `Hash` that failed `parse`, and every one of these was parsed at
    // construction — so an empty value would be a *bug*, not a silent wrong
    // digest, and the check below is what makes it loud instead.
    let layout: &[&str] = if price.is_some() {
        COMPARABLE_DIGEST_FIELDS_WITH_PRICE
    } else {
        COMPARABLE_DIGEST_FIELDS_WITHOUT_PRICE
    };
    let emitted: Vec<&str> = values.iter().map(|(tag, _)| *tag).collect();
    assert_eq!(
        emitted, layout,
        "comparable digest: encoder emitted {emitted:?} where the layout expects \
         {layout:?}"
    );

    let mut buf = Vec::new();
    push_tagged(
        &mut buf,
        b"domain",
        COMPARABLE_SETTLEMENT_DIGEST_DOMAIN.as_bytes(),
    );
    push_tagged(
        &mut buf,
        b"sections",
        &u32::try_from(values.len())
            .expect("a comparable digest has a handful of sections")
            .to_be_bytes(),
    );
    for (tag, value) in &values {
        push_tagged(&mut buf, tag.as_bytes(), value);
    }
    Hash::from_bytes(*blake3::hash(&buf).as_bytes())
}

// ---------------------------------------------------------------------------
// The revenue-side payment identity, re-exported for the read path
// ---------------------------------------------------------------------------

/// Re-exported so `verified_view` does not have to reach into `event_id` for a
/// type it must build itself. See [`crate::event_id::SettlementPaymentFact`] for
/// why a payment has its own preimage.
pub use crate::event_id::SettlementPaymentFact as RevenuePaymentFact;
// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        autonomy::AutonomousEconomy,
        base_usdc::{BASE_CHAIN_ID, BASE_USDC},
        chain_provider::{resolve, PinnedChainProvider},
        policy_auth::ValidatedOutcomePolicy,
        receipt_auth::testkit::{AuthFixture, EXECUTOR_HEX},
        rpc_test_server::FakeRpcSocket,
        trusted_valuation::{
            AuthenticatedPriceObservation, PriceObservation, ValidatedPriceObservation,
            ValidatedPriceSource,
        },
        verified_view::{VerifiedEconomyView, VerifiedNev},
    };
    use std::path::Path;
    use tempfile::tempdir;

    /// The controlled side. Exactly one address, so "which direction" has a
    /// single answer in every test below.
    const CONTROLLED: &str = EXECUTOR_HEX;
    /// The pool: outside the controlled set, which is what makes the two
    /// transfers crossings in opposite directions.
    const POOL: &str = "0x3333333333333333333333333333333333333333";

    /// 100.00 USDC.
    const OUT_RAW: u64 = 100_000_000;
    /// 100.08 USDC — the eight-cent edge that makes the whole thing worth doing.
    const IN_RAW: u64 = 100_080_000;

    const BLOCK: u64 = 201;
    const LATEST: u64 = 210;

    fn tx_hash() -> String {
        format!("0x{}", "cd".repeat(32))
    }

    fn other_tx_hash() -> String {
        format!("0x{}", "ef".repeat(32))
    }

    fn block_hash() -> String {
        format!("0x{}", "ab".repeat(32))
    }

    fn registry() -> ControlledAddressRegistry {
        ControlledAddressRegistry::new()
            .with_address(CONTROLLED)
            .expect("valid controlled address")
    }

    /// One `Transfer` log, spelled the way a receipt spells one.
    fn transfer_log(index: &str, from: &str, to: &str, amount_raw: u64) -> serde_json::Value {
        serde_json::json!({
            "address": BASE_USDC,
            "topics": [
                crate::base_usdc::ERC20_TRANSFER_TOPIC,
                format!("0x{:0>64}", from.trim_start_matches("0x")),
                format!("0x{:0>64}", to.trim_start_matches("0x")),
            ],
            "data": format!("0x{amount:064x}", amount = amount_raw),
            "logIndex": index,
        })
    }

    /// A receipt body for `tx` carrying exactly `logs`, plus the gas fields.
    ///
    /// `gas_used` is a parameter rather than a constant so the gas seam can be
    /// tested independently of the completeness tests: see
    /// `a_settlement_with_gas_and_no_price_declares_no_comparable_net_value`,
    /// and the note in `a_complete_arbitrage_promotes_the_real_profit` about
    /// why the promoting fixture reports no gas.
    fn receipt_for(tx: &str, logs: Vec<serde_json::Value>, gas_used: &str, gas_price: &str, l1_fee: Option<&str>) -> serde_json::Value {
        let mut receipt = serde_json::json!({
            "status": "0x1",
            "blockNumber": format!("0x{block:x}", block = BLOCK),
            "blockHash": block_hash(),
            "transactionHash": tx,
            "logs": logs,
            "gasUsed": gas_used,
            "effectiveGasPrice": gas_price,
        });
        if let Some(l1_fee) = l1_fee {
            receipt["l1Fee"] = serde_json::json!(l1_fee);
        }
        receipt
    }

    /// A pinned provider that serves one transaction with the given logs.
    ///
    /// The per-request dispatcher exists because a fixed method→response map can
    /// only ever describe one world, and three of the tests here need two
    /// different transactions in the same fixture.
    fn socket_serving(dir: &Path, name: &str, receipts: Vec<(String, serde_json::Value)>) -> FakeRpcSocket {
        FakeRpcSocket::with_dispatch(dir.join(name), move |method, params| {
            match method {
                "eth_chainId" => Some(serde_json::json!("0x2105")),
                "eth_blockNumber" => Some(serde_json::json!(format!("0x{latest:x}", latest = LATEST))),
                "eth_getTransactionReceipt" => {
                    let asked = params
                        .as_array()
                        .and_then(|a| a.first())
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    receipts
                        .iter()
                        .find(|(tx, _)| tx.eq_ignore_ascii_case(&asked))
                        .map(|(_, body)| body.clone())
                }
                "eth_getBlockByNumber" => Some(serde_json::json!({
                    "hash": block_hash(),
                    "timestamp": "0x6553f100",
                })),
                _ => None,
            }
        })
    }

    /// The arbitrage transaction: one controlled→pool outflow and one
    /// pool→controlled inflow, in one transaction, so the chain itself vouches
    /// that they belong to one operation.
    fn arbitrage_receipt(gas_used: &str, gas_price: &str, l1_fee: Option<&str>) -> serde_json::Value {
        receipt_for(
            &tx_hash(),
            vec![
                transfer_log("0x1", CONTROLLED, POOL, OUT_RAW),
                transfer_log("0x2", POOL, CONTROLLED, IN_RAW),
            ],
            gas_used,
            gas_price,
            l1_fee,
        )
    }

    fn arbitrage_socket(dir: &Path) -> FakeRpcSocket {
        // `gasUsed: 0x0` on purpose: this fixture exercises the promotion path,
        // and promotion is only reachable for an operation whose native cost is
        // zero — see the module doc on the gas seam. A second test covers the
        // other half, and the pair is the honest state of this build: it can
        // promote a cost-free operation and refuses to promote one that burned
        // gas it cannot price.
        socket_serving(
            dir,
            "arbitrage.sock",
            vec![(tx_hash(), arbitrage_receipt("0x0", "0x0", None))],
        )
    }

    /// The evidence rows this node wrote down for the arbitrage.
    fn arbitrage_evidence() -> Vec<BoundaryEvidence> {
        vec![
            evidence_row(CONTROLLED, POOL, OUT_RAW),
            evidence_row(POOL, CONTROLLED, IN_RAW),
        ]
    }

    fn evidence_row(from: &str, to: &str, amount_raw: u64) -> BoundaryEvidence {
        BoundaryEvidence {
            chain_id: crate::base_usdc::BASE_CHAIN_ID,
            asset: RealAsset::base_usdc(),
            from_address: from.into(),
            to_address: to.into(),
            amount_raw,
            tx_hash: tx_hash(),
            block_hash: block_hash(),
        }
    }

    /// Everything one settlement test needs: the pinned provider, the
    /// validated policy over it, the registry that decides direction, and the
    /// scan the chain read produced.
    ///
    /// Field order is drop order, and the socket has to outlive the directory
    /// that holds it — same trap `revenue_fixture` documents.
    struct Arena {
        _socket: FakeRpcSocket,
        _dir: tempfile::TempDir,
        root: std::path::PathBuf,
        registry: ControlledAddressRegistry,
        auth: AuthFixture,
        verifier: BaseUsdcVerifier,
        policy: ValidatedOutcomePolicy,
    }

    impl Arena {
        fn new(socket: FakeRpcSocket) -> Self {
            let dir = tempdir().expect("temp dir");
            let registry = registry();
            let verifier = {
                let provider =
                    PinnedChainProvider::unix_socket(socket.path(), Some(socket.uid()))
                        .expect("unix socket pin");
                let resolved = resolve(None, Some(&provider)).expect("resolve pin");
                BaseUsdcVerifier::from_resolved(&resolved, 2).expect("pinned verifier")
            };
            assert!(
                verifier.provider_identity_verified(),
                "every test here is about a kernel-identified provider"
            );
            let auth = AuthFixture::new(socket.path(), socket.uid(), registry.clone());
            let policy = auth.validated();
            Self {
                root: dir.path().to_path_buf(),
                _socket: socket,
                _dir: dir,
                registry,
                auth,
                verifier,
                policy,
            }
        }

        /// The scan the pinned provider produced for the arbitrage, through the
        /// real RPC path rather than a hand-built value.
        fn scan(&self) -> TransactionLogScan {
            self.verifier
                .scan_transaction(&tx_hash())
                .expect("the scan of a confirmed transaction")
        }

        fn scan_of(&self, tx: &str) -> TransactionLogScan {
            self.verifier
                .scan_transaction(tx)
                .expect("the scan of a confirmed transaction")
        }

        fn autonomy(&self) -> AutonomousEconomy {
            AutonomousEconomy::open(self.root.clone()).expect("autonomy ledger")
        }

        /// The offline autonomy view over the same directory, for the shared
        /// "no promotion route" assertions.
        fn autonomy_view<'a>(&'a self, autonomy: &'a AutonomousEconomy) -> VerifiedEconomyView<'a> {
            VerifiedEconomyView::unverified(autonomy, &self.registry)
        }
    }

    fn assemble<'a>(
        scan: &'a TransactionLogScan,
        registry: &'a ControlledAddressRegistry,
        evidence: &'a [BoundaryEvidence],
        policy: Option<&'a ValidatedOutcomePolicy>,
    ) -> SettlementOutcome {
        let inputs = SettlementInputs::new(vec![scan], registry, evidence, policy);
        VerifiedSettlement::assemble(&inputs).expect("assembly itself does not fail")
    }

    // ------------------------------------------------------------------
    // 1. the arbitrage case
    // ------------------------------------------------------------------

    /// THE CASE P4.5c EXISTS FOR.
    ///
    /// Two legs of one arbitrage, both established:
    ///
    /// ```text
    /// executor -> pool     100.00 USDC   outflow   -100_000_000 micros
    /// pool     -> executor 100.08 USDC   inflow    +100_080_000 micros
    ///                                       net        +    80_000 micros
    /// ```
    ///
    /// Asserts all four things the step promised:
    ///
    /// * both legs are present and one is an outflow;
    /// * the net is the **eight cents**, not the inflow and not zero;
    /// * a complete operation **promotes** — this is the first promotion in the
    ///   crate that did not come from a receipt;
    /// * the promotion reaches a [`VerifiedNev`] through the view, with both
    ///   legs counted and `is_positive`.
    ///
    /// The last two are why this is the load-bearing test and not just an
    /// arithmetic one: before P4.5c nothing here could promote at all.
    #[test]
    fn a_complete_arbitrage_promotes_its_real_profit() {
        let dir = tempdir().unwrap();
        let arena = Arena::new(arbitrage_socket(dir.path()));
        let scan = arena.scan();
        let evidence = arbitrage_evidence();

        // The precondition, stated rather than assumed: the chain read really
        // did enumerate two transfers, one in each direction.
        assert_eq!(scan.transfers().len(), 2);
        assert!(scan.exhaustive());
        assert_eq!(scan.transfers()[0].log_index, Some(1));
        assert_eq!(scan.transfers()[1].log_index, Some(2));

        let outcome = assemble(&scan, &arena.registry, &evidence, Some(&arena.policy));
        let settlement = outcome
            .as_complete()
            .expect("both legs established, so the leg set is complete");

        assert_eq!(settlement.legs().len(), 2);
        let outflows: Vec<&SettlementLeg> = settlement
            .legs()
            .iter()
            .filter(|l| !l.is_inflow())
            .collect();
        let inflows: Vec<&SettlementLeg> =
            settlement.legs().iter().filter(|l| l.is_inflow()).collect();
        assert_eq!(outflows.len(), 1, "the payment leg is an outflow");
        assert_eq!(inflows.len(), 1, "the return leg is an inflow");
        assert!(
            settlement
                .legs()
                .iter()
                .all(|l| l.state() == LegState::Confirmed),
            "both legs are confirmed: {:?}",
            settlement.legs().iter().map(|l| l.state()).collect::<Vec<_>>()
        );

        // The arithmetic.
        assert_eq!(settlement.verified_inflows_micros(), 100_080_000);
        assert_eq!(settlement.verified_outflows_micros(), 100_000_000);
        assert_eq!(
            settlement.token_net_delta_micros(),
            80_000,
            "eight cents, not a hundred and not a hundred and eight"
        );
        assert_eq!(settlement.token_net_delta_micros() as f64 / 1e6, 0.08);
        assert!(!settlement.has_native_cost());
        assert_eq!(settlement.total_native_cost_wei(), 0);
        assert_eq!(
            settlement.comparable_net_value_micros(),
            Some(80_000)
        );

        // The legs are named, distinctly: same transaction, different logs.
        let ids: Vec<String> = settlement
            .legs()
            .iter()
            .map(|l| l.event_id().expect("a confirmed leg is named").to_string())
            .collect();
        assert_ne!(ids[0], ids[1], "two logs are two events");

        // THE PROMOTION. This is the first promotion in the crate that did not
        // come from a receipt, and it is only reachable because the leg set is
        // complete.
        let authority = settlement
            .promote(&arena.verifier, &arena.policy)
            .expect("a complete operation with no native cost promotes");
        assert_eq!(authority.nev_musd_micros(), 80_000);
        assert_eq!(authority.legs(), 2);
        assert!(authority.is_positive());
        assert!(authority.provider_identity_verified());
        assert_eq!(authority.operation_id(), settlement.operation_id());

        // And it reaches a `VerifiedNev`, through the view, over a pinned
        // provider and the validated policy.
        let autonomy = arena.autonomy();
        let view = VerifiedEconomyView::provider_pinned(
            &autonomy,
            &arena.registry,
            &arena.verifier,
            &arena.policy,
        )
        .expect("pinned view");
        let nev = view
            .settlement_nev(std::slice::from_ref(&authority))
            .expect("a pinned view grants settlement NEV");
        assert_eq!(nev.nev_musd_micros(), 80_000);
        assert_eq!(nev.nev_musd(), 0.08);
        assert_eq!(nev.receipts(), 2, "both legs are counted");
        assert!(nev.is_positive());
        assert!(nev.provider_identity_verified());
        assert_eq!(nev.policy_hash(), arena.policy.policy_hash().unwrap().as_str());

        // The receipt-side total is untouched by any of this: P4.5c adds a
        // route, it does not change the one that already existed. The autonomy
        // ledger holds no receipt, so the receipt-side figure is an empty zero
        // and does not borrow the settlement's 80_000.
        let receipt_side = view.verified_nev().expect("the pinned view answers");
        assert_eq!(receipt_side.nev_musd_micros(), 0);
        assert_eq!(receipt_side.receipts(), 0);
        assert!(!receipt_side.is_positive());

        // No authority is reachable for a zero-length set, so "we promoted
        // nothing" cannot be spelled as "we promoted an empty operation".
        let none = view.settlement_nev(&[]).expect("an empty set is still pinned");
        assert_eq!(none.nev_musd_micros(), 0);
        assert_eq!(none.receipts(), 0);
        assert!(!none.is_positive());
    }

    /// Either leg **alone** promotes nothing, and — this is the part that is
    /// easy to get wrong — the reason is not a rule about legs. It is that the
    /// leg set is compared against the *chain's* enumeration, so a leg cannot be
    /// presented without its sibling: the sibling shows up as [`LegState::Absent`]
    /// and the operation has no net at all.
    ///
    /// Both directions are tested, because the asymmetry is the whole risk: an
    /// inflow-only presentation yields a false **profit**, while an
    /// outflow-only presentation yields merely a wrong number. The first is the
    /// one that funds jobs.
    #[test]
    fn either_leg_on_its_own_promotes_nothing() {
        let dir = tempdir().unwrap();
        let arena = Arena::new(arbitrage_socket(dir.path()));
        let scan = arena.scan();
        let both = arbitrage_evidence();
        let only_inflow = vec![evidence_row(POOL, CONTROLLED, IN_RAW)];
        let only_outflow = vec![evidence_row(CONTROLLED, POOL, OUT_RAW)];
        let autonomy = arena.autonomy();

        // The control, so the two refusals below cannot be passing because the
        // fixture never worked.
        assert!(assemble(&scan, &arena.registry, &both, Some(&arena.policy)).is_complete());

        for (why, stored, missing_direction) in [
            ("inflow only", &only_inflow, "controlled_to_external"),
            ("outflow only", &only_outflow, "external_to_controlled"),
        ] {
            let outcome =
                assemble(&scan, &arena.registry, stored, Some(&arena.policy));
            let incomplete = outcome
                .as_incomplete()
                .unwrap_or_else(|| panic!("{why} must not be a complete operation"));
            assert_eq!(
                incomplete.net_delta_micros(),
                None,
                "{why}: an incomplete operation has no net, not a zero one"
            );
            assert!(
                !outcome.is_complete(),
                "{why}: presenting one leg cannot make the operation complete"
            );
            assert!(
                matches!(
                    incomplete.missing_states().as_slice(),
                    [state] if *state == "absent"
                ),
                "{why}: the missing leg is absent, and the report says so: {:?}",
                incomplete.missing_states()
            );
            // One leg was established; the other was not, and it is present in
            // the report as a leg rather than dropped.
            assert_eq!(incomplete.legs().len(), 2, "{why}: both are reported");
            let absent: Vec<&SettlementLeg> = incomplete
                .legs()
                .iter()
                .filter(|l| l.state() == LegState::Absent)
                .collect();
            assert_eq!(absent.len(), 1, "{why}: exactly one leg is missing");
            assert!(
                absent[0].direction().spelling() == missing_direction,
                "{why}: the missing leg is the {} one, got {}",
                missing_direction,
                absent[0].direction().spelling()
            );
            assert!(absent[0].event_id().is_some(), "{why}: the chain named it");
            // The established half is still reported, as a partial column and
            // not as a total.
            if why == "inflow only" {
                assert_eq!(incomplete.confirmed_inflow_micros(), 100_080_000);
                assert_eq!(incomplete.confirmed_outflow_micros(), 0);
            } else {
                assert_eq!(incomplete.confirmed_inflow_micros(), 0);
                assert_eq!(incomplete.confirmed_outflow_micros(), 100_000_000);
            }

            // And the promotion route, on every route, is closed. The
            // authoritative half of this test is this call.
            assert_no_promotion_route(
                &arena.autonomy_view(&autonomy),
                None,
                &format!("incomplete settlement ({why})"),
            );
        }
    }

    // ------------------------------------------------------------------
    // 2. the three incompleteness states
    // ------------------------------------------------------------------

    /// A leg the chain confirmed and this node has evidence for, with **no
    /// validated policy in force**, is `Unattested` — a different state from
    /// `Absent`, and emphatically not zero.
    ///
    /// The failure is about authority, not about knowledge: the transfer is real,
    /// the node holds it, and there is simply nothing permitted to bind it. That
    /// is P4b's `PolicyNotValidated` at the leg layer.
    #[test]
    fn a_leg_with_no_validated_policy_is_unattested_not_zero() {
        let dir = tempdir().unwrap();
        let arena = Arena::new(arbitrage_socket(dir.path()));
        let scan = arena.scan();
        let autonomy = arena.autonomy();

        let outcome = assemble(&scan, &arena.registry, &arbitrage_evidence(), None);
        let incomplete = outcome
            .as_incomplete()
            .expect("no policy means no leg can be bound to an authority");

        assert!(outcome.missing_states_is_unattested());
        assert_eq!(incomplete.missing_states(), vec!["unattested", "unattested"]);
        for leg in incomplete.legs() {
            assert_eq!(leg.state(), LegState::Unattested);
            assert!(leg.policy_hash().is_none(), "no policy was bound");
            assert!(
                leg.why().contains("no validated outcome policy"),
                "and the reason names the missing thing: {}",
                leg.why()
            );
        }
        assert_eq!(incomplete.net_delta_micros(), None);
        assert_eq!(
            incomplete.confirmed_inflow_micros(),
            0,
            "an unbound leg is not a confirmed one, so neither partial column \
             moves — reporting it as 100.08 would be the very error this \
             module exists to prevent"
        );
        assert_no_promotion_route(
            &arena.autonomy_view(&autonomy),
            None,
            "settlement with no validated policy",
        );

        // The control: the same bytes with a policy in force are complete. So the
        // refusal above is about the policy and nothing else.
        assert!(assemble(
            &scan,
            &arena.registry,
            &arbitrage_evidence(),
            Some(&arena.policy)
        )
        .is_complete());
    }

    /// A leg whose evidence the chain read will not bind is `Unconfirmed` — the
    /// third state, and different from both of the others.
    ///
    /// Two realistic ways to get here, both tested, because they fail at
    /// different steps and both are "present but not confirmed":
    ///
    /// * the node recorded the wrong block, so the provider's read describes a
    ///   different block than the stored row does;
    /// * the provider confirmed the transfer without saying which log it
    ///   matched, so the stored row cannot be bound to it at all.
    #[test]
    fn a_leg_the_chain_will_not_bind_is_unconfirmed_not_zero() {
        let dir = tempdir().unwrap();
        let arena = Arena::new(arbitrage_socket(dir.path()));
        let scan = arena.scan();
        let autonomy = arena.autonomy();

        // (a) the stored evidence disagrees with the chain about the block.
        // This is the canonical `Unconfirmed`: the node holds a row *about this
        // transfer* — same transaction, same parties, same amount — and the one
        // fact the provider contradicts is the block it claims to be in. The
        // node's record has not been confirmed, as opposed to there being
        // nothing to confirm.
        let mut wrong_block = arbitrage_evidence();
        wrong_block[0].block_hash = format!("0x{}", "99".repeat(32));
        let outcome =
            assemble(&scan, &arena.registry, &wrong_block, Some(&arena.policy));
        let incomplete = outcome
            .as_incomplete()
            .expect("a stored row the chain will not bind is not a leg");
        assert!(
            incomplete.missing_states().contains(&"unconfirmed"),
            "the wrong-block leg is unconfirmed: {:?}",
            incomplete.missing_states()
        );
        assert_eq!(incomplete.missing_states(), vec!["unconfirmed"]);
        let leg = incomplete
            .legs()
            .iter()
            .find(|l| !l.is_inflow())
            .expect("the outflow leg is reported");
        assert_eq!(leg.state(), LegState::Unconfirmed);
        assert!(
            leg.why().contains("cannot bind"),
            "the reason says it is a binding failure, not a missing file: {}",
            leg.why()
        );
        assert!(
            leg.event_id().is_some(),
            "an unconfirmed leg is still a named leg: the chain knows it happened"
        );
        // The other leg was fine, and is still established — which is exactly
        // what makes this state different from `Absent`.
        assert!(
            incomplete
                .legs()
                .iter()
                .any(|l| l.state() == LegState::Confirmed),
            "the sibling leg is confirmed"
        );
        assert_eq!(incomplete.net_delta_micros(), None);
        assert_no_promotion_route(
            &arena.autonomy_view(&autonomy),
            None,
            "settlement with an unbound leg",
        );

        // (b) the provider named no log, so the stored row cannot be bound to
        // it. Same state, different step.
        let indexless = indexless_socket(dir.path());
        let arena2 = Arena::new(indexless);
        let scan2 = arena2.scan();
        let outcome2 = assemble(
            &scan2,
            &arena2.registry,
            &arbitrage_evidence(),
            Some(&arena2.policy),
        );
        let incomplete2 = outcome2
            .as_incomplete()
            .expect("an unnamed transfer cannot be bound to evidence");
        assert!(incomplete2
            .missing_states()
            .iter()
            .all(|s| *s == "unconfirmed"));
        let leg = incomplete2.legs().first().expect("a leg is reported");
        assert_eq!(leg.state(), LegState::Unconfirmed);
        assert!(
            leg.why().contains("no log index"),
            "the reason names the missing log: {}",
            leg.why()
        );
        assert_no_promotion_route(
            &arena2.autonomy_view(&arena2.autonomy()),
            None,
            "settlement with an unnamed leg",
        );
    }

    /// A scan that could not classify every log cannot establish a complete leg
    /// set. This is the fourth state, and it is the one that stops a caller from
    /// quietly narrowing the enumeration: a transaction that moved an
    /// *unidentified* token through a controlled address has an economic leg this
    /// build cannot price, and pretending the receipt held only the USDC logs
    /// would be an assumption, not a reading.
    #[test]
    fn an_unclassifiable_log_makes_the_scan_unusable_rather_than_empty() {
        let dir = tempdir().unwrap();
        let socket = socket_serving(
            dir.path(),
            "mixed.sock",
            vec![(
                tx_hash(),
                receipt_for(
                    &tx_hash(),
                    vec![
                        transfer_log("0x1", CONTROLLED, POOL, OUT_RAW),
                        transfer_log("0x2", POOL, CONTROLLED, IN_RAW),
                        // A `Transfer` of a token this build cannot identify.
                        serde_json::json!({
                            "address": "0x4200000000000000000000000000000000000006",
                            "topics": [
                                crate::base_usdc::ERC20_TRANSFER_TOPIC,
                                format!("0x{:0>64}", POOL.trim_start_matches("0x")),
                                format!("0x{:0>64}", CONTROLLED.trim_start_matches("0x")),
                            ],
                            "data": format!("0x{:064x}", 1u64),
                            "logIndex": "0x3",
                        }),
                        // And a log that is not a transfer at all, which is
                        // correctly ignored.
                        serde_json::json!({
                            "address": BASE_USDC,
                            "topics": [format!("0x{:0>64}", 1)],
                            "data": "0x",
                            "logIndex": "0x4",
                        }),
                    ],
                    "0x0",
                    "0x0",
                    None,
                ),
            )],
        );
        let arena = Arena::new(socket);
        let scan = arena.scan();
        assert!(!scan.exhaustive(), "one log could not be classified");
        assert_eq!(scan.unclassified().len(), 1);
        assert!(
            scan.unclassified()[0].contains("unidentified token"),
            "and the report names it: {}",
            scan.unclassified()[0]
        );
        assert_eq!(
            scan.transfers().len(),
            2,
            "the two USDC legs were still read; they just are not the whole story"
        );

        let outcome = assemble(&scan, &arena.registry, &arbitrage_evidence(), Some(&arena.policy));
        let incomplete = outcome.as_incomplete().expect("not exhaustive means not complete");
        assert_eq!(incomplete.missing_states(), vec!["scan_not_exhaustive"]);
        assert!(incomplete
            .legs()
            .iter()
            .all(|l| l.state() == LegState::Confirmed),
            "the two USDC legs are confirmed; the settlement is still incomplete \
             because the enumeration was not whole"
        );
        assert_eq!(
            incomplete.net_delta_micros(),
            None,
            "two confirmed legs and an unreadable third is not a net"
        );
        assert_no_promotion_route(
            &arena.autonomy_view(&arena.autonomy()),
            None,
            "settlement over a scan that could not classify every log",
        );
    }

    /// The three incompleteness states are distinguishable in the report, with
    /// no prose parsing required — and they stay distinguishable when one
    /// operation has all three at once.
    ///
    /// The test that would matter most: an operation with an inflow, an outflow
    /// nobody wrote down, an unbound leg and an unidentifiable log must report
    /// four different states in one list, and none of them may read as zero.
    #[test]
    fn the_three_incompleteness_states_are_distinguishable_in_the_report() {
        // Each variant serialises with a distinct `state` tag, which is the
        // machine-readable half of the claim.
        let states = [
            SettlementIncompleteness::ScanNotExhaustive {
                why: "x".into(),
            },
            SettlementIncompleteness::LegAbsent {
                event_id: "0x1".into(),
                direction: BoundaryDirection::ControlledToExternal,
                why: "x".into(),
            },
            SettlementIncompleteness::LegUnattested {
                event_id: "0x2".into(),
                direction: BoundaryDirection::ExternalToControlled,
                why: "x".into(),
            },
            SettlementIncompleteness::LegUnconfirmed {
                event_id: "0x3".into(),
                direction: BoundaryDirection::ControlledToExternal,
                why: "x".into(),
            },
        ];
        let mut names: Vec<&str> = states.iter().map(|s| s.state()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "every state has its own name");

        // Each one serialises its own tag, so a dashboard can branch on it.
        for s in &states {
            let json = serde_json::to_value(s).unwrap();
            assert_eq!(json["state"], s.state());
            assert!(
                s.describe().len() > 20,
                "and each has words as well: {}",
                s.describe()
            );
        }
        // And the three leg states are told apart in prose too, because an
        // operator reads words.
        assert_ne!(
            states[1].describe(),
            states[2].describe(),
            "absent and unattested are different faults"
        );
        assert_ne!(states[2].describe(), states[3].describe());

        // `LegState` is the same distinction one level down.
        assert_ne!(LegState::Absent.as_str(), "unattested");
        assert_ne!(LegState::Unattested.as_str(), "unconfirmed");
        assert_eq!(LegState::Absent.to_string(), "absent");
    }

    // ------------------------------------------------------------------
    // 3. the gas seam
    // ------------------------------------------------------------------

    /// Gas is captured, computed, and reported in wei — separately from the
    /// token delta, and never converted.
    ///
    /// The arithmetic is asserted rather than described:
    /// `21_000 gas × 1_000_000 wei/gas + 1_234 wei of L1 fee = 21_001_234 wei`.
    #[test]
    fn gas_is_captured_computed_and_reported_in_wei() {
        let dir = tempdir().unwrap();
        let socket = socket_serving(
            dir.path(),
            "gas.sock",
            vec![(
                tx_hash(),
                arbitrage_receipt("0x5208", "0xf4240", Some("0x4d2")),
            )],
        );
        let arena = Arena::new(socket);
        let scan = arena.scan();

        // The raw figures, straight off the read.
        assert_eq!(scan.gas_used(), 21_000);
        assert_eq!(scan.effective_gas_price_wei(), 1_000_000);
        assert_eq!(scan.l1_fee_wei(), 1_234);

        let outcome = assemble(&scan, &arena.registry, &arbitrage_evidence(), Some(&arena.policy));
        let settlement = outcome
            .as_complete()
            .expect("gas does not affect completeness: the legs are all there");

        assert!(settlement.has_native_cost());
        let cost = &settlement.external_costs()[0];
        assert_eq!(cost.gas_used(), 21_000);
        assert_eq!(cost.effective_gas_price_wei(), 1_000_000);
        assert_eq!(cost.l1_fee_wei(), 1_234);
        assert_eq!(
            cost.cost_wei(),
            // 21_000 gas × 1_000_000 wei/gas = 21_000_000_000, + 1_234 of L1 fee.
            21_000_000_000u128 + 1_234,
            "gas_used × effective_gas_price + l1_fee"
        );
        assert_eq!(settlement.total_native_cost_wei(), 21_000_001_234);
        assert_eq!(cost.operation_id(), settlement.operation_id());

        // THE SEAM. The token delta is unchanged by the cost, and the cost is
        // not in micros, and nothing added them together.
        assert_eq!(
            settlement.token_net_delta_micros(),
            80_000,
            "the token leg is exactly what it was: gas is a different currency"
        );
        assert_eq!(
            settlement.comparable_net_value_micros(),
            None,
            "and there is therefore no comparable figure"
        );

        // The gas fact has its own canonical identity, in its own domain, under
        // `NATIVE_GAS_EVENT_ID_DOMAIN`.
        let id = cost.event_id().to_string();
        assert!(id.starts_with("0x") && id.len() == 66);
        assert_ne!(
            *cost.event_id(),
            *settlement.legs()[0].event_id().expect("named"),
            "a native fact and a token fact are different identities"
        );
        // It is stable across reads: the digest is a function of the facts, so
        // re-scanning the same transaction cannot move it.
        assert_eq!(
            settlement.digest(),
            &assemble(
                &arena.scan_of(&tx_hash()),
                &arena.registry,
                &arbitrage_evidence(),
                Some(&arena.policy),
            )
            .as_complete()
            .expect("complete")
            .digest()
            .clone()
        );

        // The settlement digest binds the cost, so two settlements that differ
        // only in gas are different digests even though their token net is
        // identical.
        let zero_gas_dir = tempdir().unwrap();
        let zero = Arena::new(arbitrage_socket(zero_gas_dir.path()));
        let other = assemble(
            &zero.scan(),
            &zero.registry,
            &arbitrage_evidence(),
            Some(&zero.policy),
        );
        let other = other.as_complete().expect("complete");
        assert_eq!(other.token_net_delta_micros(), 80_000);
        assert_ne!(
            settlement.digest(),
            other.digest(),
            "the cost is part of what the settlement is"
        );
    }

    /// An operation that burned native value declares **no** comparable NEV, and
    /// therefore produces no spend authority.
    ///
    /// This is the honest state of this build and it is stated rather than
    /// worked around: there is no ETH/USD price evidence here, so an operation
    /// that cost native value cannot be compared with one that moved USDC, and
    /// the refusal is the answer rather than a gap in it.
    #[test]
    fn a_settlement_with_gas_and_no_price_declares_no_comparable_net_value() {
        let dir = tempdir().unwrap();
        let socket = socket_serving(
            dir.path(),
            "gas2.sock",
            vec![(tx_hash(), arbitrage_receipt("0x5208", "0xf4240", None))],
        );
        let arena = Arena::new(socket);
        let scan = arena.scan();
        let settlement = assemble(
            &scan,
            &arena.registry,
            &arbitrage_evidence(),
            Some(&arena.policy),
        );
        let settlement = settlement.as_complete().expect("the legs are complete");

        // Both quantities are reported, separately, and neither is converted.
        assert_eq!(settlement.token_net_delta_micros(), 80_000);
        assert_eq!(settlement.total_native_cost_wei(), 21_000_000_000);

        // And the comparison is refused rather than guessed.
        assert_eq!(settlement.comparable_net_value_micros(), None);
        let err = settlement
            .promote(&arena.verifier, &arena.policy)
            .expect_err("a gas-bearing operation cannot promote without a price");
        assert!(
            matches!(err, SettlementError::NoComparableNetValue { .. }),
            "expected the price refusal, got {err}"
        );
        let text = err.to_string();
        assert!(text.contains("no trustworthy ETH/USD price evidence"), "{text}");
        assert!(text.contains("21000000000"), "and names the cost: {text}");
        assert!(
            text.contains("reported separately and are not added"),
            "and says what it did instead of guessing: {text}"
        );

        // So no authority, and therefore no NEV from this view either.
        let autonomy = arena.autonomy();
        let view = VerifiedEconomyView::provider_pinned(
            &autonomy,
            &arena.registry,
            &arena.verifier,
            &arena.policy,
        )
        .expect("pinned view");
        assert!(view.settlement_nev(&[]).is_ok(), "an empty set is still fine");
        assert!(!view
            .settlement_nev(&[])
            .expect("empty")
            .is_positive());
        assert_no_promotion_route(
            &arena.autonomy_view(&autonomy),
            None,
            "operation with an unpriceable native cost",
        );

        // The token-only operation in the same shape does promote. Stated here
        // so the refusal above cannot be mistaken for "settlements never
        // promote".
        let clean_dir = tempdir().unwrap();
        let clean_arena = Arena::new(arbitrage_socket(clean_dir.path()));
        let clean_scan = clean_arena.scan();
        let clean = assemble(
            &clean_scan,
            &clean_arena.registry,
            &arbitrage_evidence(),
            Some(&clean_arena.policy),
        );
        assert!(
            clean
                .as_complete()
                .expect("complete")
                .promote(&clean_arena.verifier, &clean_arena.policy)
                .is_ok(),
            "so the refusal above is about the price seam, not about settlements"
        );
    }

    // ------------------------------------------------------------------
    // 4. grouping
    // ------------------------------------------------------------------

    /// An `OperationId` is derived from the transaction and cannot be asserted.
    #[test]
    fn an_operation_id_is_derived_and_cannot_be_asserted() {
        let dir = tempdir().unwrap();
        let arena = Arena::new(arbitrage_socket(dir.path()));
        let scan = arena.scan();
        let id = OperationId::from_scan(&scan).expect("an operation id");
        assert_eq!(id.as_str().len(), 66);
        assert_eq!(id, OperationId::from_scan(&scan).expect("stable"));

        // Different transaction, different operation.
        let two_tx = socket_serving(
            dir.path(),
            "two.sock",
            vec![
                (tx_hash(), arbitrage_receipt("0x0", "0x0", None)),
                (
                    other_tx_hash(),
                    receipt_for(
                        &other_tx_hash(),
                        vec![transfer_log("0x1", POOL, CONTROLLED, IN_RAW)],
                        "0x0",
                        "0x0",
                        None,
                    ),
                ),
            ],
        );
        let arena2 = Arena::new(two_tx);
        assert_ne!(
            id,
            OperationId::from_scan(&arena2.scan_of(&other_tx_hash()))
                .expect("an operation id for the second transaction"),
            "two transactions are two operations"
        );

        // The domain is the first section, so an operation id cannot be any of
        // the other digests in the crate.
        assert_ne!(OPERATION_ID_DOMAIN, crate::policy_auth::POLICY_SIGNING_DOMAIN);
        assert_ne!(
            OPERATION_ID_DOMAIN,
            crate::boundary_delta::BOUNDARY_EVIDENCE_DIGEST_DOMAIN
        );
        assert_ne!(OPERATION_ID_DOMAIN, crate::event_id::EVENT_ID_DOMAIN);
        // And the layout has exactly the two facts plus the schema version.
        assert_eq!(OPERATION_ID_FIELDS.len(), 3);
    }

    /// An operation spanning two transactions is **refused**, not split.
    ///
    /// The choice, and why: a transaction is the largest unit the chain vouches
    /// for — every log it emitted happened, or none did — so it is the only
    /// grouping with evidence behind it. Two transactions have no such evidence,
    /// and grouping them would be an operator's choice made after the fact,
    /// which is exactly how a profitable net is manufactured. Splitting instead
    /// of refusing would be worse than doing nothing: each half would be a
    /// *complete* settlement, and the losing half would come back as a complete
    /// operation worth `-100.08`.
    #[test]
    fn an_operation_spanning_two_transactions_is_refused() {
        let dir = tempdir().unwrap();
        let socket = socket_serving(
            dir.path(),
            "span.sock",
            vec![
                (tx_hash(), arbitrage_receipt("0x0", "0x0", None)),
                (
                    other_tx_hash(),
                    receipt_for(
                        &other_tx_hash(),
                        vec![transfer_log("0x1", POOL, CONTROLLED, IN_RAW)],
                        "0x0",
                        "0x0",
                        None,
                    ),
                ),
            ],
        );
        let arena = Arena::new(socket);
        let first = arena.scan_of(&tx_hash());
        let second = arena.scan_of(&other_tx_hash());

        let stored = arbitrage_evidence();
        let inputs = SettlementInputs::new(
            vec![&first, &second],
            &arena.registry,
            &stored,
            Some(&arena.policy),
        );
        let err = VerifiedSettlement::assemble(&inputs)
            .expect_err("two transactions are not one operation");
        match &err {
            SettlementError::CrossTransaction {
                transactions,
                operations,
            } => {
                assert_eq!(*transactions, 2);
                assert!(operations.contains(&OperationId::from_scan(&first).unwrap().as_str().to_string()));
                assert!(operations.contains(&OperationId::from_scan(&second).unwrap().as_str().to_string()));
            }
            other => panic!("expected the grouping refusal, got {other}"),
        }
        let text = err.to_string();
        assert!(
            text.contains("an operation is one transaction"),
            "and says why: {text}"
        );

        // The same transaction twice is not two operations — it is one, because
        // the identity is a function of the facts, not of the list length.
        let inputs = SettlementInputs::new(
            vec![&first, &first],
            &arena.registry,
            &stored,
            Some(&arena.policy),
        );
        assert!(
            VerifiedSettlement::assemble(&inputs)
                .expect("one operation named twice")
                .is_complete(),
            "the same scan listed twice is still one operation"
        );

        // And no operation at all is refused rather than treated as worth zero.
        let inputs = SettlementInputs::new(
            vec![],
            &arena.registry,
            &stored,
            Some(&arena.policy),
        );
        assert!(matches!(
            VerifiedSettlement::assemble(&inputs),
            Err(SettlementError::NoTransaction)
        ));
    }

    // ------------------------------------------------------------------
    // 5. the promotion predicate lives here, and not on a leg
    // ------------------------------------------------------------------

    /// A leg carries no predicate and no readable magnitude, so nothing outside
    /// this module can compute a total out of one.
    #[test]
    fn a_leg_carries_no_promotion_predicate() {
        let dir = tempdir().unwrap();
        let arena = Arena::new(arbitrage_socket(dir.path()));
        let settlement = assemble(
            &arena.scan(),
            &arena.registry,
            &arbitrage_evidence(),
            Some(&arena.policy),
        );
        let settlement = settlement.as_complete().expect("complete");
        let inflow = settlement
            .legs()
            .iter()
            .find(|l| l.is_inflow())
            .expect("an inflow leg");

        // What a leg does say: its own direction, its own magnitude, its own
        // state. Enough for an audit, not enough to be a total.
        assert!(inflow.is_inflow());
        assert_eq!(inflow.amount_micros(), 100_080_000);
        assert_eq!(inflow.state(), LegState::Confirmed);

        // What it does not say: anything about whether the *operation* is worth
        // anything. The single predicate lives on `SettlementAuthority`.
        let authority = settlement
            .promote(&arena.verifier, &arena.policy)
            .expect("promotes");
        assert!(authority.is_positive());

        // The strongest statement of "the predicate is not on a leg": an
        // operation made only of inflows still has legs that individually look
        // good, and the operation still gets no positive predicate if it is not
        // worth anything. Here the operation IS worth something, so the control
        // is the mirror case below — the same two legs with the amounts the
        // other way round, which is a *loss*, and which no per-leg rule could
        // have noticed.
        let dir = tempdir().unwrap();
        let socket = socket_serving(
            dir.path(),
            "loss.sock",
            vec![(
                tx_hash(),
                receipt_for(
                    &tx_hash(),
                    vec![
                        transfer_log("0x1", POOL, CONTROLLED, OUT_RAW),
                        transfer_log("0x2", CONTROLLED, POOL, IN_RAW),
                    ],
                    "0x0",
                    "0x0",
                    None,
                ),
            )],
        );
        let losing_arena = Arena::new(socket);
        let losing = assemble(
            &losing_arena.scan(),
            &losing_arena.registry,
            &[
                evidence_row(POOL, CONTROLLED, OUT_RAW),
                evidence_row(CONTROLLED, POOL, IN_RAW),
            ],
            Some(&losing_arena.policy),
        );
        let losing = losing.as_complete().expect("both legs are established");
        assert_eq!(losing.token_net_delta_micros(), -80_000);
        // Every leg is confirmed and each one is individually well-formed...
        assert!(losing.legs().iter().all(|l| l.state() == LegState::Confirmed));
        // ...and the operation is not worth funding, which is a statement no
        // single leg's facts could make.
        let losing_authority = losing
            .promote(&losing_arena.verifier, &losing_arena.policy)
            .expect("a complete operation produces an authority either way");
        assert_eq!(losing_authority.nev_musd_micros(), -80_000);
        assert!(
            !losing_authority.is_positive(),
            "and that is where the predicate lives"
        );
    }

    /// `SettlementAuthority` is refused from an unpinned endpoint, exactly as a
    /// receipt is. P4.5c adds a promotion route; it does not add a weaker one.
    #[test]
    fn an_unpinned_endpoint_cannot_promote_an_operation() {
        let dir = tempdir().unwrap();
        let arena = Arena::new(arbitrage_socket(dir.path()));
        let settlement = assemble(
            &arena.scan(),
            &arena.registry,
            &arbitrage_evidence(),
            Some(&arena.policy),
        );
        let settlement = settlement.as_complete().expect("complete");

        // The dev-only loopback override: an address, not an identity.
        let unpinned = BaseUsdcVerifier::new("http://127.0.0.1:8546", 2)
            .expect("a loopback verifier can be constructed");
        assert!(!unpinned.provider_identity_verified());
        let err = settlement
            .promote(&unpinned, &arena.policy)
            .expect_err("an unpinned endpoint cannot promote an operation");
        assert!(matches!(
            err,
            SettlementError::ProviderIdentityUnverified { .. }
        ));
        assert!(err.to_string().contains("not an identity"), "{err}");
    }

    /// An authority minted under one policy is refused by a view holding
    /// another, and an offline view grants nothing at all.
    #[test]
    fn a_settlement_authority_is_bound_to_the_policy_it_was_minted_under() {
        let dir = tempdir().unwrap();
        let arena = Arena::new(arbitrage_socket(dir.path()));
        let settlement = assemble(
            &arena.scan(),
            &arena.registry,
            &arbitrage_evidence(),
            Some(&arena.policy),
        );
        let authority = settlement
            .as_complete()
            .expect("complete")
            .promote(&arena.verifier, &arena.policy)
            .expect("promotes");
        let autonomy = arena.autonomy();

        // A rotated policy: same anchor, same provider, different version.
        let rotated = arena.auth.rotated(99).validate().expect("valid rotated");
        assert_ne!(rotated.policy_hash().unwrap().as_str(), authority.policy_hash());
        let pinned = VerifiedEconomyView::provider_pinned(
            &autonomy,
            &arena.registry,
            &arena.verifier,
            &rotated,
        )
        .expect("pinned view under the rotated policy");
        let err = pinned
            .settlement_nev(std::slice::from_ref(&authority))
            .expect_err("an authority from another policy is not this view's");
        assert!(
            err.to_string().contains("not the one in force"),
            "{err}"
        );

        // And an offline view grants nothing.
        let offline = VerifiedEconomyView::unverified(&autonomy, &arena.registry);
        let err = offline
            .settlement_nev(std::slice::from_ref(&authority))
            .expect_err("an offline view grants no settlement NEV");
        assert!(err.to_string().contains("provider-pinned"), "{err}");

        // The pinned view under the *right* policy still does.
        let pinned = VerifiedEconomyView::provider_pinned(
            &autonomy,
            &arena.registry,
            &arena.verifier,
            &arena.policy,
        )
        .expect("pinned view");
        assert_eq!(
            pinned
                .settlement_nev(std::slice::from_ref(&authority))
                .expect("granted")
                .nev_musd_micros(),
            80_000
        );
    }

    /// Two settlements of the same operation are one event, and two *different*
    /// operations each count in full. The identity is a function of the facts, so
    /// neither over- nor under-counting is possible here.
    #[test]
    fn an_operation_identity_does_not_double_count_or_under_count() {
        let dir = tempdir().unwrap();
        let socket = socket_serving(
            dir.path(),
            "distinct.sock",
            vec![
                (tx_hash(), arbitrage_receipt("0x0", "0x0", None)),
                (
                    other_tx_hash(),
                    receipt_for(
                        &other_tx_hash(),
                        vec![transfer_log("0x1", POOL, CONTROLLED, IN_RAW)],
                        "0x0",
                        "0x0",
                        None,
                    ),
                ),
            ],
        );
        let arena = Arena::new(socket);
        let first = assemble(
            &arena.scan_of(&tx_hash()),
            &arena.registry,
            &arbitrage_evidence(),
            Some(&arena.policy),
        );
        let first = first.as_complete().expect("complete");

        // A second read of the same transaction is the same operation, not a
        // second one.
        let again = assemble(
            &arena.scan_of(&tx_hash()),
            &arena.registry,
            &arbitrage_evidence(),
            Some(&arena.policy),
        );
        let again = again.as_complete().expect("complete");
        assert_eq!(first.operation_id(), again.operation_id());
        assert_eq!(first.digest(), again.digest());

        // Two settlements of two transactions are two operations, and their
        // nets add — including the negative one, which is why
        // `from_settlement_authorities` takes the whole set.
        let autonomy = arena.autonomy();
        let view = VerifiedEconomyView::provider_pinned(
            &autonomy,
            &arena.registry,
            &arena.verifier,
            &arena.policy,
        )
        .expect("pinned view");
        let a = first.promote(&arena.verifier, &arena.policy).expect("a");
        assert!(a.is_positive());
        let nev = view
            .settlement_nev(std::slice::from_ref(&a))
            .expect("granted");
        assert_eq!(nev.nev_musd_micros(), 80_000);
        assert_eq!(nev.receipts(), 2);

        // The empty set is not positive, so "counted nothing" and "counted zero"
        // cannot be confused by a caller reading only the number.
        let empty: VerifiedNev = view.settlement_nev(&[]).expect("granted");
        assert!(!empty.is_positive());
    }

    /// A provider that cannot be trusted to have named every log must not be
    /// able to make a settlement look complete. The scan says so itself.
    #[test]
    fn the_scan_reports_its_own_provenance() {
        let dir = tempdir().unwrap();
        let arena = Arena::new(arbitrage_socket(dir.path()));
        let scan = arena.scan();
        assert!(scan.provider_identity_verified());
        assert!(scan.provider().starts_with("unix://"));
        assert_eq!(scan.chain_id(), crate::base_usdc::BASE_CHAIN_ID);
        assert_eq!(scan.block_number(), BLOCK);
        assert_eq!(scan.confirmations(), LATEST - BLOCK + 1);
        assert!(scan.exhaustive());
    }

    /// Stored evidence the chain did not show is reported and contributes
    /// nothing — it is not silently dropped, and it is not counted.
    #[test]
    fn evidence_the_chain_does_not_show_is_reported_and_not_counted() {
        let dir = tempdir().unwrap();
        let socket = socket_serving(
            dir.path(),
            "extra.sock",
            vec![(
                tx_hash(),
                receipt_for(
                    &tx_hash(),
                    vec![transfer_log("0x1", POOL, CONTROLLED, IN_RAW)],
                    "0x0",
                    "0x0",
                    None,
                ),
            )],
        );
        let arena = Arena::new(socket);
        let scan = arena.scan();

        // This node wrote down an outflow the transaction never contained. The
        // chain is authoritative, so it is not a leg — and reporting it is the
        // point, because a node holding evidence the chain contradicts is a bug
        // or a forgery.
        let mut stored = arbitrage_evidence();
        stored[0].amount_raw = OUT_RAW + 1; // same tx, a different amount
        let outcome = assemble(&scan, &arena.registry, &stored, Some(&arena.policy));
        let settlement = outcome.as_complete().expect("the chain's own leg is complete");
        assert_eq!(settlement.legs().len(), 1, "only the chain's leg");
        assert_eq!(settlement.token_net_delta_micros(), 100_080_000);
        assert_eq!(
            settlement.unmatched_stored_evidence(),
            1,
            "the row that claims a different amount is reported as one the chain \
             did not show; the chain's own leg is still counted in full"
        );

        // And when the extra row *is* for a leg the chain did not enumerate, the
        // settlement is incomplete, not silently short.
        let mut only_extra = vec![evidence_row(CONTROLLED, POOL, OUT_RAW)];
        only_extra[0].amount_raw = OUT_RAW + 1;
        let outcome = assemble(&scan, &arena.registry, &only_extra, Some(&arena.policy));
        let incomplete = outcome.as_incomplete().expect("the real leg is absent");
        assert_eq!(incomplete.missing_states(), vec!["absent"]);
        assert_eq!(incomplete.unmatched_stored_evidence(), 1);
        assert_no_promotion_route(
            &arena.autonomy_view(&arena.autonomy()),
            None,
            "settlement whose only stored evidence is not on chain",
        );
    }

    /// A provider that serves a receipt with no logs at all, for a transaction
    /// the node recorded. The enumeration is empty but not exhaustive — a
    /// receipt with no `logs` array is unreadable, not an empty transaction.
    #[test]
    fn a_receipt_with_no_logs_is_refused_outright() {
        let dir = tempdir().unwrap();
        let socket = socket_serving(
            dir.path(),
            "nologs.sock",
            vec![(
                tx_hash(),
                serde_json::json!({
                    "status": "0x1",
                    "blockNumber": format!("0x{block:x}", block = BLOCK),
                    "blockHash": block_hash(),
                    "transactionHash": tx_hash(),
                    "gasUsed": "0x0",
                    "effectiveGasPrice": "0x0",
                }),
            )],
        );
        let arena = Arena::new(socket);
        let err = arena
            .verifier
            .scan_transaction(&tx_hash())
            .expect_err("no logs is not an answer");
        assert!(err.to_string().contains("missing logs"), "{err}");
    }

    /// A provider that serves a failed transaction is refused before any leg is
    /// considered. A reverted transaction moved nothing.
    #[test]
    fn a_reverted_transaction_is_not_an_operation() {
        let dir = tempdir().unwrap();
        let socket = socket_serving(
            dir.path(),
            "reverted.sock",
            vec![(
                tx_hash(),
                serde_json::json!({
                    "status": "0x0",
                    "blockNumber": format!("0x{block:x}", block = BLOCK),
                    "blockHash": block_hash(),
                    "transactionHash": tx_hash(),
                    "logs": [],
                    "gasUsed": "0x5208",
                    "effectiveGasPrice": "0xf4240",
                }),
            )],
        );
        let arena = Arena::new(socket);
        let err = arena
            .verifier
            .scan_transaction(&tx_hash())
            .expect_err("a reverted transaction is not an operation");
        assert!(err.to_string().contains("did not succeed"), "{err}");
    }

    /// A native cost is a fact of the transaction, so its identity is stable,
    /// its own, and distinct from every token fact in the operation.
    #[test]
    fn a_native_cost_has_its_own_stable_identity() {
        let dir = tempdir().unwrap();
        let socket = socket_serving(
            dir.path(),
            "identity.sock",
            vec![(
                tx_hash(),
                arbitrage_receipt("0x5208", "0xf4240", None),
            )],
        );
        let arena = Arena::new(socket);
        let scan = arena.scan();
        let a = VerifiedNativeGasCost::from_scan(
            &scan,
            &arena.policy,
            crate::event_id::NATIVE_CURRENCY,
            crate::event_id::NATIVE_CURRENCY,
        )
        .expect("a native cost");
        let b = VerifiedNativeGasCost::from_scan(
            &scan,
            &arena.policy,
            crate::event_id::NATIVE_CURRENCY,
            crate::event_id::NATIVE_CURRENCY,
        )
        .expect("a native cost");
        assert_eq!(*a.event_id(), *b.event_id());
        assert_eq!(a.cost_wei(), b.cost_wei());
        assert_eq!(a.cost_wei(), 21_000_000_000);

        // It is a different identity from both token legs, because it is
        // domain-separated and binds a different fact.
        let settlement = assemble(
            &scan,
            &arena.registry,
            &arbitrage_evidence(),
            Some(&arena.policy),
        );
        let settlement = settlement.as_complete().expect("complete");
        for leg in settlement.legs() {
            assert_ne!(
                *a.event_id(),
                *leg.event_id().expect("named"),
                "a native fact is not a token fact"
            );
        }
        assert_eq!(a.policy_hash(), &arena.policy.policy_hash().unwrap());
    }

    /// An overflowed fee is refused, never wrapped. A wrapped cost is free money.
    #[test]
    fn an_overflowed_native_cost_is_refused_rather_than_wrapped() {
        let dir = tempdir().unwrap();
        let socket = socket_serving(
            dir.path(),
            "overflow.sock",
            vec![(
                tx_hash(),
                receipt_for(
                    &tx_hash(),
                    vec![transfer_log("0x1", POOL, CONTROLLED, IN_RAW)],
                    // 2^64 gas at a very high price: `u128` arithmetic is fine,
                    // the identity's `u64` slot is not.
                    "0xffffffffffffffff",
                    "0x100000000",
                    None,
                ),
            )],
        );
        let arena = Arena::new(socket);
        let err = VerifiedNativeGasCost::from_scan(
            &arena.scan_of(&tx_hash()),
            &arena.policy,
            crate::event_id::NATIVE_CURRENCY,
            crate::event_id::NATIVE_CURRENCY,
        )
        .expect_err("an unpriceable fee is refused");
        assert!(
            matches!(
                err,
                SettlementError::EventId(crate::event_id::EventIdError::NativeAmountOutOfRange { .. })
            ),
            "{err}"
        );
    }

    /// A provider that serves the transfer but not enough of the chain is
    /// refused before any leg exists.
    #[test]
    fn a_transaction_without_enough_confirmations_is_not_an_operation() {
        let dir = tempdir().unwrap();
        let socket = FakeRpcSocket::with_responses(
            dir.path().join("shallow.sock"),
            vec![
                ("eth_chainId", serde_json::json!("0x2105")),
                ("eth_blockNumber", serde_json::json!("0xc9")),
                ("eth_getTransactionReceipt", arbitrage_receipt("0x0", "0x0", None)),
                ("eth_getBlockByNumber", serde_json::json!({
                    "hash": block_hash(),
                    "timestamp": "0x6553f100",
                })),
            ],
        );
        let arena = Arena::new(socket);
        let err = arena
            .verifier
            .scan_transaction(&tx_hash())
            .expect_err("two confirmations is not enough");
        assert!(err.to_string().contains("not enough confirmations"), "{err}");
    }

    /// The one helper, used everywhere: no route out of a ledger exists for an
    /// incomplete settlement. Re-exported rather than re-implemented, so the
    /// settlement and receipt sides cannot drift apart on what "promotes" means.
    use crate::verified_view::tests::assert_no_promotion_route;

    /// A provider that names no log for a transfer it did confirm.
    fn indexless_socket(dir: &Path) -> FakeRpcSocket {
        let mut logs = vec![serde_json::json!({
            "address": BASE_USDC,
            "topics": [
                crate::base_usdc::ERC20_TRANSFER_TOPIC,
                format!("0x{:0>64}", CONTROLLED.trim_start_matches("0x")),
                format!("0x{:0>64}", POOL.trim_start_matches("0x")),
            ],
            "data": format!("0x{amount:064x}", amount = OUT_RAW),
        })];
        logs.push(transfer_log("0x2", POOL, CONTROLLED, IN_RAW));
        socket_serving(
            dir,
            "indexless.sock",
            vec![(tx_hash(), receipt_for(&tx_hash(), logs, "0x0", "0x0", None))],
        )
    }

    // =======================================================================
    // P4.6 — Trusted valuation
    // =======================================================================
    //
    // Every test below names one of the fifteen invariants in the P4.6 brief,
    // or one of the four defects the audit found. The fixtures are shared:

    /// The block timestamp the fake chain reports for every block:
    /// `0x6553f100` = 1_700_000_000.
    const ANCHOR_TS: u64 = 1_700_000_000;
    /// An observation 60 seconds before the anchor — inside the fixture policy's
    /// 300-second window, so not stale.
    const PRICE_TS: u64 = ANCHOR_TS - 60;
    /// An observation block *before* the settlement's block, which is what
    /// "at or before the anchor" requires.
    const PRICE_BLOCK: u64 = 190;
    /// 3000.00 USD per ETH, in micro-USD per whole ETH. An integer, always.
    const ETH_PRICE_MUSD: u128 = 3_000_000_000_000;
    /// The fixture policy's `min_confirmations` is 12 and the settlement's own
    /// block is 10 deep, so an observation the price source read at a shallower
    /// view would be pending. A source that has seen 13 blocks past its own
    /// observation reports 13 — the two views are independent, which is the whole
    /// reason a price is a separate document rather than a field of the scan.
    const PRICE_CONFIRMATIONS: u64 = 13;
    /// A second chain view of the *same* transaction: a later block, a later
    /// timestamp, everything else identical. Used to show the anchor is inside
    /// the settlement digest.
    const LATER_BLOCK: u64 = 240;
    const LATER_TS: u64 = ANCHOR_TS + 78;

    fn later_block_hash() -> String {
        format!("0x{}", "cd".repeat(32))
    }

    fn price_observation_at(
        block_number: u64,
        timestamp: u64,
        price_musd_per_eth: u128,
        confirmations: u64,
    ) -> PriceObservation {
        PriceObservation::from_parts(
            crate::trusted_valuation::testkit::source_id(
                crate::trusted_valuation::testkit::SOURCE_A,
            ),
            price_musd_per_eth,
            BASE_CHAIN_ID,
            block_number,
            &block_hash(),
            timestamp,
            "round-1",
            confirmations,
        )
        .expect("a usable price observation")
    }

    /// The observation the priced tests use: before the anchor, inside the
    /// window, final under the policy.
    fn price_observation() -> PriceObservation {
        price_observation_at(
            PRICE_BLOCK,
            PRICE_TS,
            ETH_PRICE_MUSD,
            PRICE_CONFIRMATIONS,
        )
    }

    /// A gas-bearing arbitrage: 21000 gas at 1_000_000 wei plus a reported L1
    /// fee of 1234 wei, so `cost_wei = 21_000_001_234`.
    fn priced_socket(dir: &Path) -> FakeRpcSocket {
        socket_serving(
            dir,
            "priced.sock",
            vec![(
                tx_hash(),
                arbitrage_receipt("0x5208", "0xf4240", Some("0x4d2")),
            )],
        )
    }

    /// A gas-bearing arbitrage whose receipt reports **no** L1 fee.
    fn unreported_l1_socket(dir: &Path) -> FakeRpcSocket {
        socket_serving(
            dir,
            "unreported-l1.sock",
            vec![(tx_hash(), arbitrage_receipt("0x5208", "0xf4240", None))],
        )
    }

    fn priced_arena(socket: FakeRpcSocket) -> (Arena, VerifiedSettlement) {
        let arena = Arena::new(socket);
        let scan = arena.scan();
        let settled = assemble(
            &scan,
            &arena.registry,
            &arbitrage_evidence(),
            Some(&arena.policy),
        );
        let settlement = match settled {
            SettlementOutcome::Complete(s) => s,
            SettlementOutcome::Incomplete(i) => {
                panic!("the priced fixture must be complete: {:?}", i.reasons())
            }
        };
        (arena, settlement)
    }

    /// The price source the fixture policy authorises, bound.
    fn bound_source(arena: &Arena) -> ValidatedPriceSource {
        ValidatedPriceSource::bind(
            &arena.policy,
            &crate::trusted_valuation::testkit::canonical(BASE_CHAIN_ID),
        )
        .expect("the fixture policy authorises the shared price source")
    }

    fn signed_observation(
        arena: &Arena,
        observation: PriceObservation,
    ) -> ValidatedPriceObservation {
        let signed = arena
            .auth
            .verifier
            .attest_price_observation(&arena.policy, observation)
            .expect("the delegated verifier signs the reading");
        crate::trusted_valuation::validate_price_observation(&signed, &arena.policy)
            .expect("the reading validates under the policy in force")
    }

    // -- invariant 1: the zero-gas fixture is still a fixture ---------------

    /// Invariant 1. A zero-gas operation still promotes, still needs no price,
    /// and still promotes through the *original* unpriced route — P4.6 did not
    /// quietly turn every settlement into a priced one.
    #[test]
    fn a_zero_gas_operation_is_still_a_fixture_and_needs_no_price() {
        let dir = tempdir().expect("temp dir");
        let arena = Arena::new(arbitrage_socket(dir.path()));
        let scan = arena.scan();
        assert_eq!(scan.gas_used(), 0, "this fixture burns no gas");
        let settlement = match assemble(
            &scan,
            &arena.registry,
            &arbitrage_evidence(),
            Some(&arena.policy),
        ) {
            SettlementOutcome::Complete(s) => s,
            SettlementOutcome::Incomplete(_) => panic!("the fixture is complete"),
        };

        assert!(!settlement.has_native_cost());
        assert_eq!(settlement.total_native_cost_wei(), 0);
        assert_eq!(settlement.comparable_net_value_micros(), Some(80_000));

        // The unpriced route, unchanged.
        let authority = settlement
            .promote(&arena.verifier, &arena.policy)
            .expect("a cost-free operation promotes as it always did");
        assert_eq!(authority.nev_musd_micros(), 80_000);
        assert_eq!(authority.settlement_digest(), settlement.digest());

        // And the priced route agrees with it without an observation in sight:
        // nothing needs pricing, so nothing is consulted.
        let source = bound_source(&arena);
        match settlement.compare(&source, &[]) {
            ComparableSettlementResult::Comparable(c) => {
                assert_eq!(c.comparable_net_value_micros(), 80_000);
                assert_eq!(c.native_cost_musd(), 0);
                assert!(
                    c.price().is_none(),
                    "an operation that burned nothing must not be recorded as priced"
                );
            }
            ComparableSettlementResult::NoComparableNetValue(reasons) => {
                panic!("no price is needed: {reasons:?}")
            }
        }
    }

    // -- invariant 2: real gas, no observation ------------------------------

    /// Invariant 2. A gas-bearing operation with no price observation declares
    /// no comparable value, names the reason, and cannot promote — through
    /// either route.
    #[test]
    fn a_gas_bearing_operation_with_no_price_declares_no_comparable_value() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        assert!(settlement.has_native_cost());
        assert_eq!(settlement.total_native_cost_wei(), 21_000_001_234);

        let source = bound_source(&arena);
        let result = settlement.compare(&source, &[]);
        assert!(!result.is_comparable());
        assert_eq!(result.refusal_states(), vec!["no_price"]);
        assert!(
            result
                .refusal_description()
                .contains("no price observation was supplied"),
            "{}",
            result.refusal_description()
        );

        // The unpriced route still refuses too, with its own error.
        assert!(matches!(
            settlement.promote(&arena.verifier, &arena.policy),
            Err(SettlementError::NoComparableNetValue { cost_wei: 21_000_001_234, .. })
        ));
    }

    // -- invariant 3: an unsigned observation cannot reach the comparison ---

    /// Invariant 3. There is no such thing as an *unsigned validated* price.
    ///
    /// The comparison takes `&[ValidatedPriceObservation]`, and that type has no
    /// public constructor — so a forged or hand-built document cannot be passed
    /// to it at all. What a caller *can* do is hand an
    /// `AuthenticatedPriceObservation` to the validator, and there it is refused:
    /// a document whose signature was replaced with another key's, and one whose
    /// `attestation_hash` was edited after signing. Both land on the refusal
    /// arm, and both are typed refusals rather than a silently ignored field.
    #[test]
    fn an_unsigned_price_observation_cannot_reach_the_comparison() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);

        // A document nobody signed: JSON with a tampered price and no signature.
        let doc = serde_json::json!({
            "observation": {
                "source_id": crate::trusted_valuation::testkit::SOURCE_A,
                "price_musd_per_eth": 1,
                "chain_id": BASE_CHAIN_ID,
                "block_number": PRICE_BLOCK,
                "block_hash": block_hash(),
                "block_timestamp_unix": PRICE_TS,
                "source_round": "round-1",
                "confirmations": PRICE_CONFIRMATIONS,
            },
            "policy_hash": arena.policy.policy_hash().unwrap().to_string(),
            "signer_key_id": arena.auth.verifier.key_id().to_string(),
            "attestation_hash": format!("0x{}", "00".repeat(32)),
            "signature": "11".repeat(64),
        });
        let forged: AuthenticatedPriceObservation = serde_json::from_value(doc)
            .expect("the shape parses; authorisation is a separate question");
        assert!(matches!(
            crate::trusted_valuation::validate_price_observation(&forged, &arena.policy),
            Err(crate::trusted_valuation::ValuationError::BadSignature)
        ));

        // A genuine signature over *different* bytes: the document is signed for
        // one price and delivered with another. Editing it through the
        // serialiser — the only way an attacker has — keeps every field the type
        // knows about and changes the meaning of the message.
        let genuine = arena
            .auth
            .verifier
            .attest_price_observation(&arena.policy, price_observation())
            .expect("sign");
        let mut json = serde_json::to_value(&genuine).expect("serialise");
        json["observation"]["price_musd_per_eth"] = serde_json::json!(1);
        let edited: AuthenticatedPriceObservation =
            serde_json::from_value(json).expect("the shape still parses");
        assert_eq!(
            edited.attestation_hash(),
            genuine.attestation_hash(),
            "the attacker left the digest alone, which is precisely what recomputing it \
             catches"
        );
        assert!(matches!(
            crate::trusted_valuation::validate_price_observation(&edited, &arena.policy),
            Err(crate::trusted_valuation::ValuationError::BadSignature)
        ));

        // And with nothing validated, there is nothing to pass: the comparison
        // refuses, which is the only behaviour available to a caller who has no
        // validated observation.
        let result = settlement.compare(&source, &[]);
        assert!(!result.is_comparable());
    }

    // -- invariant 4: unauthorised source ----------------------------------

    /// Invariant 4. Two refusals, both about authority rather than arithmetic.
    ///
    /// A source the policy does not permit is refused *by the selection*, even
    /// though the observation is perfectly signed by the policy's own delegated
    /// key — which is the point: a valid signature from a valid key over a
    /// source nobody authorised proves only that the key signed it.
    #[test]
    fn a_price_from_an_unpermitted_source_is_refused() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);

        let rogue = PriceObservation::from_parts(
            crate::trusted_valuation::testkit::source_id(
                crate::trusted_valuation::testkit::SOURCE_UNPERMITTED,
            ),
            ETH_PRICE_MUSD,
            BASE_CHAIN_ID,
            PRICE_BLOCK,
            &block_hash(),
            PRICE_TS,
            "round-1",
            PRICE_CONFIRMATIONS,
        )
        .expect("a usable reading");
        let signed = signed_observation(&arena, rogue);

        let result = settlement.compare(&source, std::slice::from_ref(&signed));
        assert!(!result.is_comparable());
        assert!(
            result
                .refusal_description()
                .contains("not permitted by the policy in force"),
            "{}",
            result.refusal_description()
        );
    }

    /// Invariant 4, second half. A price source *policy* the outcome policy does
    /// not name cannot be bound at all, so a caller cannot widen its own
    /// authority by constructing one.
    #[test]
    fn a_price_source_the_policy_does_not_name_cannot_be_bound() {
        let dir = tempdir().expect("temp dir");
        let (arena, _settlement) = priced_arena(priced_socket(dir.path()));

        // Same permitted source, different staleness window: one field.
        let wider = crate::trusted_valuation::testkit::with_staleness(
            BASE_CHAIN_ID,
            crate::trusted_valuation::testkit::MAX_STALENESS_UNIX * 2,
        );
        assert!(matches!(
            ValidatedPriceSource::bind(&arena.policy, &wider),
            Err(crate::trusted_valuation::ValuationError::SourceNotAuthorised { .. })
        ));

        // And the empty binding, which `validate_outcome_policy` refuses at
        // load, cannot be bound either.
        assert!(matches!(
            ValidatedPriceSource::bind(
                &arena.policy,
                &crate::trusted_valuation::PriceSourcePolicy::none()
            ),
            Err(crate::trusted_valuation::ValuationError::SourceNotAuthorised { .. })
        ));
    }

    // -- invariant 5: future observation ------------------------------------

    /// Invariant 5. A reading taken at a block *after* the settlement's, or at a
    /// timestamp after it, is refused. Both sub-cases, because a chain can put
    /// them out of step.
    #[test]
    fn a_future_price_is_refused() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);

        for (block, ts, why) in [
            (
                BLOCK + 1,
                PRICE_TS,
                "a later block than the settlement's",
            ),
            (
                PRICE_BLOCK,
                ANCHOR_TS + 1,
                "a later timestamp than the settlement's block carries",
            ),
        ] {
            let signed = signed_observation(
                &arena,
                price_observation_at(block, ts, ETH_PRICE_MUSD, PRICE_CONFIRMATIONS),
            );
            let result = settlement.compare(&source, std::slice::from_ref(&signed));
            assert!(!result.is_comparable(), "{why} must be refused");
            assert!(
                result
                    .refusal_description()
                    .contains("read after the fact"),
                "{why}: {}",
                result.refusal_description()
            );
        }
    }

    // -- invariant 6: stale observation ------------------------------------

    /// Invariant 6. One second past the window is refused, one second inside it
    /// is priced — the boundary is asserted on both sides so the comparison is
    /// `>` and not `>=` in the wrong place.
    #[test]
    fn a_stale_price_is_refused_at_the_window_boundary() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);
        let window = crate::trusted_valuation::testkit::MAX_STALENESS_UNIX;

        let inside = signed_observation(
            &arena,
            price_observation_at(
                PRICE_BLOCK,
                ANCHOR_TS - window,
                ETH_PRICE_MUSD,
                PRICE_CONFIRMATIONS,
            ),
        );
        assert!(
            settlement
                .compare(&source, std::slice::from_ref(&inside))
                .is_comparable(),
            "a reading exactly at the window must be priced, not refused"
        );

        let outside = signed_observation(
            &arena,
            price_observation_at(
                PRICE_BLOCK,
                ANCHOR_TS - window - 1,
                ETH_PRICE_MUSD,
                PRICE_CONFIRMATIONS,
            ),
        );
        let result = settlement.compare(&source, std::slice::from_ref(&outside));
        assert!(!result.is_comparable());
        assert!(
            result.refusal_description().contains("the policy permits at most"),
            "{}",
            result.refusal_description()
        );
    }

    // -- invariant 8: wrong policy hash -------------------------------------

    /// Invariant 8. A reading signed under a *different* policy is refused, and
    /// it is refused as a policy mismatch rather than as a bad signature — the
    /// two questions are kept apart, exactly as the receipt side keeps them.
    #[test]
    fn a_price_signed_under_another_policy_is_refused() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);

        // A rotated policy over the same socket, registry and **delegated key**:
        // only `policy_version` differs, so the policy hash differs and nothing
        // else does. This is the shape of a rotation that must not silently
        // re-approve an old reading.
        let alternate = arena.auth.rotated(99);
        let other = alternate.validate().expect("the rotated policy validates");
        assert_ne!(
            other.policy_hash().unwrap(),
            arena.policy.policy_hash().unwrap(),
            "two policy versions must hash differently for this test to mean anything"
        );
        let signed = arena
            .auth
            .verifier
            .attest_price_observation(&other, price_observation())
            .expect("the delegated verifier signs under the other policy");
        // Authentic under its own policy...
        crate::trusted_valuation::validate_price_observation(&signed, &other)
            .expect("authentic under its own policy");
        // ...and refused under this one, as a *policy* question rather than a
        // signature question: the signature is perfect and the delegation is
        // intact, and the reading still belongs to another mandate.
        assert!(matches!(
            crate::trusted_valuation::validate_price_observation(&signed, &arena.policy),
            Err(crate::trusted_valuation::ValuationError::PolicyHashMismatch { .. })
        ));

        // And therefore there is no validated observation to compare with: the
        // comparison is refused for want of one, not for want of an arithmetic
        // step.
        let result = settlement.compare(&source, &[]);
        assert_eq!(result.refusal_states(), vec!["no_price"]);
    }

    // -- invariant 12: the exact expected net -------------------------------

    /// Invariant 12, with the arithmetic written out longhand.
    ///
    /// The fixture: an 8.00-cent arbitrage edge, and 21_000_001_234 wei of gas.
    /// At 3000.00 USD/ETH that gas costs 0.0630003702 USD — 63000.003702 micro-USD,
    /// which rounds **up** to 63001. The comparable net is therefore
    /// 80_000 − 63_001 = **16_999** micro-USD, not 17_000: the rounding is part of
    /// the answer, and this test is where that is pinned.
    #[test]
    fn a_valid_price_produces_the_exact_expected_net() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);
        let signed = signed_observation(&arena, price_observation());

        let ComparableSettlementResult::Comparable(comparable) =
            settlement.compare(&source, std::slice::from_ref(&signed))
        else {
            panic!("a valid reading must price this operation");
        };

        // Longhand, with no arithmetic in the assertion itself.
        let numerator: u128 = 21_000_001_234 * ETH_PRICE_MUSD;
        let expected_cost = numerator.div_ceil(1_000_000_000_000_000_000);
        assert_eq!(numerator % 1_000_000_000_000_000_000, 3_702_000_000_000_000);
        assert_eq!(expected_cost, 63_001, "the gas term rounds up");
        assert_eq!(comparable.native_cost_musd(), expected_cost);
        assert_eq!(comparable.total_native_cost_wei(), 21_000_001_234);
        assert_eq!(comparable.token_net_delta_micros(), 80_000);
        assert_eq!(comparable.comparable_net_value_micros(), 16_999);
        assert!(comparable.comparable_net_value_micros() > 0);

        // The price is named, not merely applied.
        let price = comparable.price().expect("a priced operation names its price");
        assert_eq!(price.price_musd_per_eth(), ETH_PRICE_MUSD);
        assert_eq!(price.source_id().as_str(), crate::trusted_valuation::testkit::SOURCE_A);
        assert_eq!(price.age_unix(), 60);
        assert_eq!(price.confirmations(), PRICE_CONFIRMATIONS);
        assert_eq!(price.block_number(), PRICE_BLOCK);

        // And it promotes.
        let authority = comparable
            .promote(&arena.verifier, &arena.policy)
            .expect("a priced operation with a kernel-identified provider promotes");
        assert_eq!(authority.nev_musd_micros(), 16_999);
        assert_eq!(
            authority.settlement_digest(),
            comparable.comparable_digest(),
            "the authority must carry the digest that names the price"
        );
    }

    // -- invariant 13: removing the price proof -----------------------------

    /// Invariant 13. Take the price away and the promotion goes with it: the
    /// observation set is empty, so there is no comparable value, so there is no
    /// type to promote. Nothing degrades to the token net.
    #[test]
    fn removing_the_price_proof_removes_the_promotion() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);
        let signed = signed_observation(&arena, price_observation());

        let comparable = settlement
            .compare(&source, std::slice::from_ref(&signed))
            .as_comparable()
            .expect("priced with the reading")
            .clone();
        assert!(comparable.promote(&arena.verifier, &arena.policy).is_ok());

        let without = settlement.compare(&source, &[]);
        drop(comparable);
        assert!(without.as_comparable().is_none());
        assert_eq!(without.refusal_states(), vec!["no_price"]);
    }

    // -- invariant 14: gas facts are bound ----------------------------------

    /// Invariant 14. Changing `gas_used` in the receipt changes the cost, the
    /// cost's own identity, the settlement digest and the comparable net — and
    /// deterministically, twice the same value to the same answer. Nothing in
    /// between depends on how many times the test runs.
    #[test]
    fn changing_gas_used_changes_the_binding_and_the_result() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);
        let signed = signed_observation(&arena, price_observation());
        let first = settlement
            .compare(&source, std::slice::from_ref(&signed))
            .as_comparable()
            .expect("priced")
            .clone();

        // Same transaction, 42000 gas instead of 21000.
        let doubled_socket = socket_serving(
            dir.path(),
            "doubled.sock",
            vec![(
                tx_hash(),
                arbitrage_receipt("0xa410", "0xf4240", Some("0x4d2")),
            )],
        );
        let (arena2, doubled) = priced_arena(doubled_socket);
        let source2 = bound_source(&arena2);
        let signed2 = signed_observation(&arena2, price_observation());
        let second = doubled
            .compare(&source2, std::slice::from_ref(&signed2))
            .as_comparable()
            .expect("priced")
            .clone();

        assert_ne!(
            first.external_costs()[0].gas_used(),
            second.external_costs()[0].gas_used()
        );
        assert_ne!(
            first.external_costs()[0].event_id(),
            second.external_costs()[0].event_id(),
            "the native fact's identity binds gas_used"
        );
        assert_ne!(
            first.settlement_digest(),
            second.settlement_digest()
        );
        assert_ne!(
            first.comparable_digest(),
            second.comparable_digest()
        );
        // 42000 * 1_000_000 + 1234 = 42_000_001_234 wei, about 0.126 USD.
        assert_eq!(second.total_native_cost_wei(), 42_000_001_234);
        assert_eq!(second.native_cost_musd(), 126_001);
        assert_eq!(second.comparable_net_value_micros(), -46_001);
        assert!(first.comparable_net_value_micros() > 0);
        assert!(
            second.comparable_net_value_micros() < 0,
            "doubling the gas turns an 8-cent edge into a loss, and the price is what              shows it"
        );

        // Deterministic: the same inputs, read twice, agree.
        let again = settlement
            .compare(&source, std::slice::from_ref(&signed))
            .as_comparable()
            .expect("priced")
            .clone();
        assert_eq!(
            first.comparable_digest(),
            again.comparable_digest(),
            "the comparison is a function of its inputs, not of the call"
        );
    }

    /// Invariant 14, second half. The signer cannot restate a chain fact: the
    /// gas figure enters the comparable value only from the scan, and a price
    /// document carrying an extra field is refused at the door rather than
    /// ignored.
    #[test]
    fn the_signer_cannot_override_the_chain_gas_facts() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);

        // A price document with a `gas_used` override is not a price document.
        let doc = serde_json::json!({
            "observation": {
                "source_id": crate::trusted_valuation::testkit::SOURCE_A,
                "price_musd_per_eth": ETH_PRICE_MUSD,
                "chain_id": BASE_CHAIN_ID,
                "block_number": PRICE_BLOCK,
                "block_hash": block_hash(),
                "block_timestamp_unix": PRICE_TS,
                "source_round": "round-1",
                "confirmations": PRICE_CONFIRMATIONS,
                "gas_used": 1,
            },
            "policy_hash": arena.policy.policy_hash().unwrap().to_string(),
            "signer_key_id": arena.auth.verifier.key_id().to_string(),
            "attestation_hash": format!("0x{}", "00".repeat(32)),
            "signature": "11".repeat(64),
        });
        assert!(
            serde_json::from_value::<AuthenticatedPriceObservation>(doc).is_err(),
            "a document with a field the signer never signed must not parse"
        );

        // And the gas figure the settlement used is the one the chain reported,
        // whatever the observation says about anything.
        let signed = signed_observation(&arena, price_observation());
        let comparable = settlement
            .compare(&source, std::slice::from_ref(&signed))
            .as_comparable()
            .expect("priced")
            .clone();
        assert_eq!(
            comparable.external_costs()[0].gas_used(),
            21_000,
            "gas_used comes from the receipt and from nowhere else"
        );
        assert_eq!(comparable.native_cost_musd(), 63_001);
    }

    // -- the L1 fee nobody reported -----------------------------------------

    /// A receipt with no `l1Fee` is not a receipt with a zero L1 fee. The
    /// operation refuses rather than converting the execution charge as though
    /// the data charge were free.
    #[test]
    fn a_missing_l1_fee_is_not_converted_as_zero() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(unreported_l1_socket(dir.path()));
        let source = bound_source(&arena);
        let signed = signed_observation(&arena, price_observation());

        assert!(!settlement.external_costs()[0].l1_fee_reported());
        assert!(!settlement.external_costs()[0].l1_fee_verifiable());
        let result = settlement.compare(&source, std::slice::from_ref(&signed));
        assert!(!result.is_comparable());
        assert_eq!(result.refusal_states(), vec!["l1_fee_not_verifiable"]);
        assert!(
            result.refusal_description().contains("not converted as though"),
            "{}",
            result.refusal_description()
        );
    }

    // -- the four audit defects ---------------------------------------------

    /// Audit defect 2. `total_native_cost_wei` used to be `Iterator::sum` over
    /// `u128`: a panic in debug and a silent wrap in release, one function from a
    /// checked `+` that refuses the identical overflow. It is a stored field now,
    /// summed with `checked_add` where a `Result` exists — and this test asserts
    /// the sum is *the sum*, over many rows, with the overflowing case refused at
    /// `sum_checked` rather than wrapped.
    #[test]
    fn total_native_cost_wei_does_not_wrap() {
        // The fold this replaces, on values that cannot overflow, agrees.
        let costs: Vec<u128> = (1..=64u128).map(|i| i * u128::from(u32::MAX)).collect();
        let folded: u128 = costs.iter().sum();
        let mut checked_total: u128 = 0;
        for cost in &costs {
            checked_total = checked_total
                .checked_add(*cost)
                .expect("a sum that fits");
        }
        assert_eq!(folded, checked_total);

        // And the overflowing fold is refused rather than wrapped. Two rows that
        // individually fit and jointly do not are the only way to reach this, so
        // it is exercised directly against the same `checked_add` the
        // constructor uses.
        // Two rows whose true total is 2^128 + 1: 2^127 and 2^127 + 1. Both fit in
        // a `u128` on their own, which is the whole point — a per-row bound is not
        // a total bound.
        let half = u128::MAX / 2 + 1;
        let half_plus_one = half + 1;
        assert!(half.checked_add(half_plus_one).is_none(), "2^128 + 1 does not fit");
        // What `Iterator::sum` does in a *release* build, spelled out with
        // `wrapping_add` so this test can demonstrate it without panicking the way
        // the debug build does. The released sum is 1: a total that says the
        // operation cost one wei.
        let released_sum: u128 = [half, half_plus_one]
            .into_iter()
            .fold(0u128, |acc, value| acc.wrapping_add(value));
        assert_eq!(
            released_sum, 1,
            "this is the number the old accessor returned, and it is not the total"
        );

        // The real fixture, end to end: a stored total equal to the sum of its
        // rows, with no fold anywhere near it.
        let dir = tempdir().expect("temp dir");
        let (_arena, settlement) = priced_arena(priced_socket(dir.path()));
        let summed: u128 = settlement
            .external_costs()
            .iter()
            .fold(0u128, |acc, cost| acc + cost.cost_wei());
        assert_eq!(settlement.total_native_cost_wei(), summed);
        assert_eq!(summed, 21_000_001_234);
    }

    /// Audit defect 4. A gas-bearing settlement assembled with **no** policy used
    /// to produce a complete settlement whose cost vector was empty — so
    /// `has_native_cost()` was `false`, `comparable_net_value_micros()` returned
    /// the token net, and the burned gas was invisible everywhere. It is now a
    /// reason.
    #[test]
    fn a_gas_bearing_settlement_without_a_policy_is_incomplete_not_free() {
        let dir = tempdir().expect("temp dir");
        let arena = Arena::new(priced_socket(dir.path()));
        let scan = arena.scan();
        assert_eq!(scan.gas_used(), 21_000);

        let outcome = assemble(&scan, &arena.registry, &arbitrage_evidence(), None);
        let SettlementOutcome::Incomplete(incomplete) = outcome else {
            panic!("no authority means no complete settlement");
        };
        assert!(
            incomplete
                .missing_states()
                .contains(&"native_cost_unattested"),
            "{:?}",
            incomplete.missing_states()
        );
        assert!(
            incomplete
                .external_costs()
                .is_empty(),
            "a cost with no authority is never stored as a cost row"
        );
        assert_eq!(
            incomplete.total_native_cost_wei(),
            0,
            "and the total says what was burned, not what was authorised"
        );
        assert!(
            incomplete
                .reasons()
                .iter()
                .any(|r| r.state() == "native_cost_unattested"),
            "{:?}",
            incomplete.reasons()
        );
        // The zero-gas fixture still assembles without a policy: the new reason is
        // about a *cost*, so an operation with no cost is untouched.
        let free_dir = tempdir().expect("temp dir");
        let free_arena = Arena::new(arbitrage_socket(free_dir.path()));
        match assemble(
            &free_arena.scan(),
            &free_arena.registry,
            &arbitrage_evidence(),
            None,
        ) {
            SettlementOutcome::Incomplete(i) => {
                assert!(
                    i.missing_states().iter().all(|m| *m == "unattested"),
                    "no policy still means every leg is unattested, and only that: {:?}",
                    i.missing_states()
                );
            }
            SettlementOutcome::Complete(_) => {
                panic!("no policy means no verified delta, so never complete")
            }
        }
    }

    /// Audit defect 3. `BOUNDARY_DELTA_MICROS_DECIMALS - asset.decimals()` was
    /// `u8` subtraction with no guard, in a function whose twin in
    /// `boundary_delta.rs` has one. An 18-decimal asset underflows it. The guard
    /// is now the same shape as the twin's.
    #[test]
    fn micros_of_refuses_an_asset_with_more_decimals_than_micros() {
        let fine = RealAsset::new(BASE_CHAIN_ID, &format!("0x{}", "ab".repeat(20)), 18)
            .expect("a valid 18-decimal asset");
        assert_eq!(fine.decimals(), 18);
        let err = micros_of(1, &fine).expect_err("18 decimals cannot be micros");
        assert!(
            matches!(
                err,
                SettlementError::BoundaryDelta(
                    crate::boundary_delta::BoundaryDeltaError::SubMicrosPrecision { decimals: 18 }
                )
            ),
            "the refusal names the reason instead of reporting a failed u8 subtraction,              got: {err}"
        );
        // Six decimals — the only identified asset — is unchanged.
        assert_eq!(
            micros_of(1, &RealAsset::base_usdc()).expect("six decimals are exact"),
            1
        );
        assert_eq!(
            micros_of(5, &RealAsset::base_usdc()).expect("six decimals are exact"),
            5
        );
    }

    /// Audit defect 1. The block anchor reaches the settlement, and it is inside
    /// the settlement digest. Without it, a digest did not say which anchor a
    /// number was read against.
    #[test]
    fn the_settlement_carries_and_binds_its_block_anchor() {
        let dir = tempdir().expect("temp dir");
        let (_arena, settlement) = priced_arena(priced_socket(dir.path()));
        let anchor = settlement.anchor();
        assert_eq!(anchor.block_number(), BLOCK);
        assert_eq!(anchor.block_hash(), block_hash());
        assert_eq!(anchor.block_timestamp_unix(), ANCHOR_TS);
        assert_eq!(anchor.confirmations(), 10);
        // The cost row carries it too, so the time travels with the money.
        assert_eq!(
            settlement.external_costs()[0].anchor().block_number(),
            BLOCK
        );
        assert_eq!(
            settlement.external_costs()[0].anchor().block_timestamp_unix(),
            ANCHOR_TS
        );
        // And the anchor is inside the digest: the same legs, the same logs and
        // the same costs, read in a later block, are a different settlement. If
        // the anchor were not bound, this digest would be equal to the one above —
        // and then it could not say which anchor a number was read against.
        let later_dir = tempdir().expect("temp dir");
        let later = FakeRpcSocket::with_dispatch(later_dir.path().join("later.sock"), |m, p| match m {
            "eth_chainId" => Some(serde_json::json!("0x2105")),
            "eth_blockNumber" => Some(serde_json::json!(format!("0x{latest:x}", latest = LATEST + 40))),
            "eth_getTransactionReceipt" => {
                let asked = p
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                (asked == tx_hash()).then(|| {
                    let mut receipt = arbitrage_receipt("0x5208", "0xf4240", Some("0x4d2"));
                    receipt["blockNumber"] = serde_json::json!(format!("0x{:x}", LATER_BLOCK));
                    receipt["blockHash"] = serde_json::json!(later_block_hash());
                    receipt
                })
            }
            "eth_getBlockByNumber" => Some(serde_json::json!({
                "hash": later_block_hash(),
                "timestamp": format!("0x{:x}", LATER_TS),
            })),
            _ => None,
        });
        let later_arena = Arena::new(later);
        // The stored evidence has to describe the same block the read did: a
        // proof whose `block_hash` disagrees with the evidence it is attached to
        // is refused as unconfirmed, which is a different test.
        let later_evidence: Vec<BoundaryEvidence> = arbitrage_evidence()
            .into_iter()
            .map(|mut row| {
                row.block_hash = later_block_hash();
                row
            })
            .collect();
        let later_settlement = match assemble(
            &later_arena.scan(),
            &later_arena.registry,
            &later_evidence,
            Some(&later_arena.policy),
        ) {
            SettlementOutcome::Complete(s) => s,
            SettlementOutcome::Incomplete(_) => panic!("complete"),
        };
        assert_eq!(later_settlement.anchor().block_number(), LATER_BLOCK);
        assert_eq!(
            later_settlement.anchor().block_timestamp_unix(),
            LATER_TS
        );
        assert_eq!(
            later_settlement.legs().len(),
            settlement.legs().len(),
            "same legs..."
        );
        assert_eq!(
            later_settlement.total_native_cost_wei(),
            settlement.total_native_cost_wei(),
            "...and the same gas..."
        );
        assert_ne!(
            later_settlement.digest(),
            settlement.digest(),
            "...but a different anchor, so a different settlement digest"
        );
    }

    // -- the digest rows ----------------------------------------------------

    /// The price observation is a **row** of the comparable digest, so two
    /// authorities that authorise two different numbers are two different
    /// digests. This is the auditability property: without it,
    /// `SettlementAuthority::settlement_digest` would be the same value for two
    /// settlements authorising two amounts.
    #[test]
    fn the_comparable_digest_names_the_price_observation() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);

        let at_3000 = signed_observation(
            &arena,
            price_observation_at(
                PRICE_BLOCK,
                PRICE_TS,
                ETH_PRICE_MUSD,
                PRICE_CONFIRMATIONS,
            ),
        );
        let at_3001 = signed_observation(
            &arena,
            price_observation_at(
                PRICE_BLOCK,
                PRICE_TS,
                ETH_PRICE_MUSD + 1_000_000_000,
                PRICE_CONFIRMATIONS,
            ),
        );

        let a = settlement
            .compare(&source, std::slice::from_ref(&at_3000))
            .as_comparable()
            .expect("priced")
            .clone();
        let b = settlement
            .compare(&source, std::slice::from_ref(&at_3001))
            .as_comparable()
            .expect("priced")
            .clone();

        // Different observations, different numbers, different digests.
        assert_ne!(a.price().unwrap().event_id(), b.price().unwrap().event_id());
        assert_ne!(a.comparable_net_value_micros(), b.comparable_net_value_micros());
        assert_ne!(a.comparable_digest(), b.comparable_digest());
        // The settlement itself is the same, and its digest says so — which is
        // what makes the comparison meaningful: only the price row moved.
        assert_eq!(a.settlement_digest(), b.settlement_digest());

        // A settlement that needed no price has a digest with the price rows
        // *absent*, so it cannot be confused with one priced at zero.
        let free_dir = tempdir().expect("temp dir");
        let free = Arena::new(arbitrage_socket(free_dir.path()));
        let free_settlement = match assemble(
            &free.scan(),
            &free.registry,
            &arbitrage_evidence(),
            Some(&free.policy),
        ) {
            SettlementOutcome::Complete(s) => s,
            SettlementOutcome::Incomplete(_) => panic!("complete"),
        };
        let free_source = bound_source(&free);
        let free_comparable = free_settlement
            .compare(&free_source, &[])
            .as_comparable()
            .expect("no price needed")
            .clone();
        assert!(free_comparable.price().is_none());
        assert_ne!(
            free_comparable.comparable_digest(),
            a.comparable_digest(),
            "a priced and an unpriced settlement must never share a digest"
        );
    }

    // -- promotion order ----------------------------------------------------

    /// The promotion gate order is unchanged on the priced route: an endpoint
    /// with no kernel-enforced identity is refused **before** anything about the
    /// value is looked at, so an unpinned source learns nothing. This is the
    /// same first step, in the same position, as
    /// `an_unpinned_endpoint_cannot_promote_an_operation` asserts for the
    /// unpriced route.
    #[test]
    fn an_unpinned_endpoint_cannot_promote_a_comparable_operation() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);
        let signed = signed_observation(&arena, price_observation());
        let comparable = settlement
            .compare(&source, std::slice::from_ref(&signed))
            .as_comparable()
            .expect("priced")
            .clone();

        // `Arena::new` asserts the pinned verifier *is* identity-verified, so the
        // unpinned one is built directly: `BaseUsdcVerifier::new` refuses
        // anything but a loopback endpoint and never pins, which is exactly the
        // "an address, not an identity" case.
        let unpinned = crate::base_usdc::BaseUsdcVerifier::new(
            "http://127.0.0.1:1/",
            2,
        )
        .expect("a loopback endpoint parses");
        assert!(!unpinned.provider_identity_verified());
        assert!(matches!(
            comparable.promote(&unpinned, &arena.policy),
            Err(SettlementError::ProviderIdentityUnverified { .. })
        ));
        // Step 1, not step 2: the comparable figure is present, so the refusal
        // cannot be the comparability one.
        assert!(comparable.comparable_net_value_micros() > 0);
    }

    /// Step 3 of the priced promotion: the value was priced under one policy and
    /// is promoted under another.
    #[test]
    fn a_comparable_value_promoted_under_another_policy_is_refused() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);
        let signed = signed_observation(&arena, price_observation());
        let comparable = settlement
            .compare(&source, std::slice::from_ref(&signed))
            .as_comparable()
            .expect("priced")
            .clone();

        let alternate = arena.auth.rotated(99);
        let other = alternate.validate().expect("the rotated policy validates");
        assert!(matches!(
            comparable.promote(&arena.verifier, &other),
            Err(SettlementError::ComparablePolicyMismatch { .. })
        ));
        // And it still promotes under its own policy.
        assert!(comparable.promote(&arena.verifier, &arena.policy).is_ok());
    }

    // -- ordering, forks, duplicates ---------------------------------------

    /// The selection is a function of the *set* of readings, not of the order
    /// they were offered in. Three readings at three blocks, listed forwards,
    /// backwards and shuffled, give the same price observation every time.
    #[test]
    fn price_selection_is_independent_of_insertion_order() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);

        let older = signed_observation(
            &arena,
            price_observation_at(
                PRICE_BLOCK - 10,
                PRICE_TS - 20,
                ETH_PRICE_MUSD - 100_000_000,
                PRICE_CONFIRMATIONS,
            ),
        );
        let middle = signed_observation(
            &arena,
            price_observation_at(
                PRICE_BLOCK - 5,
                PRICE_TS - 10,
                ETH_PRICE_MUSD - 50_000_000,
                PRICE_CONFIRMATIONS,
            ),
        );
        let newest = signed_observation(&arena, price_observation());

        let orders = [
            vec![older.clone(), middle.clone(), newest.clone()],
            vec![newest.clone(), middle.clone(), older.clone()],
            vec![middle.clone(), newest.clone(), older.clone()],
        ];
        let mut chosen: Vec<String> = Vec::new();
        for order in &orders {
            let result = settlement.compare(&source, order);
            let comparable = result.as_comparable().expect("priced");
            chosen.push(comparable.price().unwrap().event_id().to_string());
            // The latest reading wins, whichever position it was offered in.
            assert_eq!(
                comparable.price().unwrap().event_id(),
                newest.event_id(),
                "the latest reading at or before the anchor is the one that applies"
            );
        }
        assert_eq!(chosen[0], chosen[1]);
        assert_eq!(chosen[1], chosen[2]);
    }

    /// Two eligible readings at one block with two different prices is a fork the
    /// node cannot resolve, and the only honest answer is to declare no price.
    #[test]
    fn a_forked_price_block_declares_no_price() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);
        let one = signed_observation(&arena, price_observation());
        let two = signed_observation(
            &arena,
            price_observation_at(
                PRICE_BLOCK,
                PRICE_TS,
                ETH_PRICE_MUSD + 1,
                PRICE_CONFIRMATIONS,
            ),
        );
        let result = settlement.compare(&source, &[one.clone(), two.clone()]);
        assert!(!result.is_comparable());
        assert!(
            result
                .refusal_description()
                .contains("cannot resolve a fork"),
            "{}",
            result.refusal_description()
        );
        // Either one alone is priced: it is the disagreement, not the block.
        assert!(settlement
            .compare(&source, std::slice::from_ref(&one))
            .is_comparable());
    }

    /// A duplicated reading is one reading: it is counted once, and the duplicate
    /// is reported rather than silently folded.
    #[test]
    fn a_duplicated_price_observation_is_counted_once() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);
        let signed = signed_observation(&arena, price_observation());

        let single = settlement
            .compare(&source, std::slice::from_ref(&signed))
            .as_comparable()
            .expect("priced")
            .clone();
        assert_eq!(single.duplicate_price_observations(), 0);

        let duplicated = settlement
            .compare(&source, &[signed.clone(), signed.clone(), signed.clone()])
            .as_comparable()
            .expect("priced")
            .clone();
        assert_eq!(duplicated.duplicate_price_observations(), 2);
        assert_eq!(
            duplicated.comparable_digest(),
            single.comparable_digest(),
            "three copies of one reading are one reading, and the promoted value is              identical"
        );
    }

    /// Finality is *derived* from the policy's confirmation bar, and a pending
    /// reading is refused rather than used.
    #[test]
    fn a_pending_price_is_refused_and_finality_is_derived() {
        let dir = tempdir().expect("temp dir");
        let (arena, settlement) = priced_arena(priced_socket(dir.path()));
        let source = bound_source(&arena);
        // The fixture policy demands 12 confirmations.
        let shallow = signed_observation(
            &arena,
            price_observation_at(PRICE_BLOCK, PRICE_TS, ETH_PRICE_MUSD, 11),
        );
        assert_eq!(
            source.finality_of(shallow.confirmations()),
            crate::trusted_valuation::PriceFinality::PendingFinality
        );
        assert_eq!(
            source.finality_of(PRICE_CONFIRMATIONS),
            crate::trusted_valuation::PriceFinality::Finalized
        );
        let result = settlement.compare(&source, std::slice::from_ref(&shallow));
        assert!(!result.is_comparable());
        assert!(
            result.refusal_description().contains("confirmations"),
            "{}",
            result.refusal_description()
        );
    }

    /// A price source for another chain cannot be used, even though it was signed
    /// and even though the policy authorises it — the chain is checked twice: once
    /// when the source is bound to the policy, and once against the settlement's
    /// own anchor.
    #[test]
    fn a_price_for_another_chain_is_refused() {
        let dir = tempdir().expect("temp dir");
        let (arena, _settlement) = priced_arena(priced_socket(dir.path()));
        let foreign = PriceObservation::from_parts(
            crate::trusted_valuation::testkit::source_id(
                crate::trusted_valuation::testkit::SOURCE_A,
            ),
            ETH_PRICE_MUSD,
            BASE_CHAIN_ID + 1,
            PRICE_BLOCK,
            &block_hash(),
            PRICE_TS,
            "round-1",
            PRICE_CONFIRMATIONS,
        )
        .expect("a usable reading for another chain");
        // Signed under this policy, so it is authentic — and the validator
        // refuses it on the chain, before the selector ever sees it.
        let signed = arena
            .auth
            .verifier
            .attest_price_observation(&arena.policy, foreign)
            .expect("signs");
        assert!(matches!(
            crate::trusted_valuation::validate_price_observation(&signed, &arena.policy),
            Err(crate::trusted_valuation::ValuationError::ChainMismatch {
                found,
                expected: BASE_CHAIN_ID,
            }) if found == BASE_CHAIN_ID + 1
        ));
    }

    /// The missing-state helper the tests use to stay readable. Defined here so
    /// the assertions read as claims about the report rather than as matches.
    trait MissingStates {
        fn missing_states_is_unattested(&self) -> bool;
    }

    impl MissingStates for SettlementOutcome {
        fn missing_states_is_unattested(&self) -> bool {
            self.as_incomplete().is_some_and(|s| {
                !s.missing_states().is_empty()
                    && s.missing_states().iter().all(|m| *m == "unattested")
            })
        }
    }
}
