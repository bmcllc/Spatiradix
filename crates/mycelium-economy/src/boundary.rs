//! Typed settlement boundary (P1).
//!
//! What this module buys, stated without overclaiming:
//!
//! 1. It removes a *semantic ambiguity*, not a write permission. A process
//!    that can append to the on-disk ledger can still fabricate every struct
//!    here, because nothing here is signed yet. What it can no longer do is
//!    write `asset: "smUSD"` and have that validate silently in the same slot
//!    as a real on-chain token.
//! 2. It defines the types that a later verified view consumes to *re-derive*
//!    trust from evidence instead of reading claims off a record.
//!
//! `ControlDomain` is therefore **derived**, never asserted: a
//! `BoundaryCrossing` has no public fields, no `Deserialize`, and exactly one
//! constructor, which takes a `ControlledAddressRegistry`. There is no code
//! path that turns a caller-supplied `from_domain: External` into a stored
//! fact. The registry is a local address set; `PaymentPolicy.payout_address`
//! is its seed, not its ceiling.

use crate::{
    autonomy::ExternalValueClass,
    base_usdc::{
        normalize_address, validate_hash32, BaseUsdcVerification,
        BASE_CHAIN_ID, BASE_USDC, BASE_USDC_DECIMALS,
    },
    EconomyError, PaymentPolicy, Result,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeSet;

/// Lowercased form of `BASE_USDC`, so an identified asset can be built without
/// a fallible normalisation in the middle. `base_usdc_is_normalised` pins the
/// two together.
const BASE_USDC_NORMALIZED: &str =
    "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

/// Highest decimals accepted for an identified real asset. Every mainstream
/// ERC-20 sits far below this (USDC and USDT use 6); a higher-precision token
/// needs an explicit entry rather than passing unnoticed.
const MAX_ASSET_DECIMALS: u8 = 36;

/// A ledger-internal unit. No chain, no contract, no redemption path, so it
/// can never carry external value across the boundary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticAsset {
    SmUsd,
    SyntheticMyc,
    SyntheticCredit,
}

impl SyntheticAsset {
    /// The symbols an older ledger may already carry for this asset. Used by
    /// the legacy classification table and nowhere else.
    pub fn legacy_symbols(self) -> &'static [&'static str] {
        match self {
            Self::SmUsd => &["smUSD", "sm_usd", "sm-usd"],
            Self::SyntheticMyc => &["sMYC", "syntheticMYC", "synthetic_myc"],
            Self::SyntheticCredit => &["sCREDIT", "synthetic_credit"],
        }
    }
}

/// A real, on-chain, *identified* asset. Deliberately not a name: an asset is
/// the triple (chain, contract, decimals), so "USDC" on two chains is two
/// assets, and neither is this crate's USDC unless the contract matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RealAsset {
    chain_id: u64,
    contract: String,
    decimals: u8,
}

impl RealAsset {
    /// The only real asset this crate can currently identify.
    pub fn base_usdc() -> Self {
        Self {
            chain_id: BASE_CHAIN_ID,
            contract: BASE_USDC_NORMALIZED.to_string(),
            decimals: BASE_USDC_DECIMALS,
        }
    }

    /// Validating constructor. Every `RealAsset` in existence passed through
    /// here, including the ones built by `Deserialize`, so neither a caller
    /// nor a hand-written ledger line can present a malformed contract.
    pub fn new(chain_id: u64, contract: &str, decimals: u8) -> Result<Self> {
        if chain_id == 0 {
            return Err(EconomyError::Invalid(
                "real asset chain_id must be > 0".into(),
            ));
        }
        if decimals > MAX_ASSET_DECIMALS {
            return Err(EconomyError::Invalid(format!(
                "real asset decimals must be <= {MAX_ASSET_DECIMALS}"
            )));
        }
        Ok(Self {
            chain_id,
            contract: normalize_address(contract)?,
            decimals,
        })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn contract(&self) -> &str {
        &self.contract
    }

    pub fn decimals(&self) -> u8 {
        self.decimals
    }

    /// Whether this asset is on the compiled-in allowlist. An unrecognised
    /// triple is well-formed but not *identified*, and an unidentified asset
    /// is refused at the boundary instead of being carried into NEV.
    pub fn is_known(&self) -> bool {
        self == &Self::base_usdc()
    }
}

impl<'de> Deserialize<'de> for RealAsset {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        // Hand-written rather than derived, so a hand-written ledger line
        // cannot present a RealAsset that `new` would have rejected.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Repr {
            chain_id: u64,
            contract: String,
            decimals: u8,
        }
        let repr = Repr::deserialize(deserializer)?;
        RealAsset::new(repr.chain_id, &repr.contract, repr.decimals)
            .map_err(serde::de::Error::custom)
    }
}

/// Which side of the controlled set an address sits on.
///
/// Derived, never asserted. This type intentionally has no `Deserialize`: a
/// domain that can be read back from a file is a domain a writer can assert,
/// and asserting `External` is precisely the forgery this design removes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlDomain {
    Controlled,
    External,
}

/// The local set of addresses this node controls. The payment policy payout
/// address is the seed; the set is deliberately allowed to hold several
/// addresses, so a second controlled hot wallet needs no new type.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ControlledAddressRegistry {
    addresses: BTreeSet<String>,
}

impl ControlledAddressRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seeds the registry from the create-once payment policy. The policy
    /// still owns the chain and the token; this only adopts its payout
    /// address as controlled.
    pub fn from_policy(policy: &PaymentPolicy) -> Result<Self> {
        let mut registry = Self::new();
        registry.insert(&policy.payout_address)?;
        Ok(registry)
    }

    pub fn insert(&mut self, address: &str) -> Result<()> {
        self.addresses.insert(normalize_address(address)?);
        Ok(())
    }

    pub fn with_address(mut self, address: &str) -> Result<Self> {
        self.insert(address)?;
        Ok(self)
    }

    pub fn contains(&self, address: &str) -> Result<bool> {
        let address = normalize_address(address)?;
        Ok(self.addresses.contains(&address))
    }

    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    pub fn addresses(&self) -> impl Iterator<Item = &str> {
        self.addresses.iter().map(String::as_str)
    }

    /// The whole derivation, in one place:
    ///
    /// ```text
    /// Domain(address) = Controlled if address in the controlled registry
    ///                   External   otherwise
    /// ```
    ///
    /// The registry is a parameter, so there is no registry-free variant that
    /// could hand out a domain on trust.
    pub fn domain_of(&self, address: &str) -> Result<ControlDomain> {
        if self.contains(address)? {
            Ok(ControlDomain::Controlled)
        } else {
            Ok(ControlDomain::External)
        }
    }
}

/// Addresses and chain evidence, with no domain field anywhere.
///
/// This is the only shape that gets persisted. Storing evidence and deriving
/// the domain on every read means the ledger holds no domain anyone can edit.
///
/// It does NOT mean the evidence is verified. A process that can write the
/// ledger can still invent an address, a transaction hash and a block hash;
/// all this removes is the ability to *assert* the conclusion. Checking the
/// evidence against chain state is the job of a later verified view.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundaryEvidence {
    pub chain_id: u64,
    pub asset: RealAsset,
    pub from_address: String,
    pub to_address: String,
    /// Raw on-chain units. `u64`, not `u128`: this struct is persisted as a
    /// variant of the internally tagged `AutonomyPayload`, and serde buffers a
    /// tagged enum's content in a deserializer with no `u128` support, so a
    /// `u128` here could be written but never read back. The bound is not
    /// invented either -- `BaseUsdcVerifier` already refuses a USDC transfer
    /// above `u64::MAX` with "USDC transfer exceeds u64".
    pub amount_raw: u64,
    pub tx_hash: String,
    pub block_hash: String,
}

impl BoundaryEvidence {
    /// Rejects everything the chain read and the constructors cannot vouch
    /// for. Callers must run this before deriving; `derive` runs it too.
    pub fn validate(&self) -> Result<()> {
        if self.chain_id != self.asset.chain_id() {
            return Err(EconomyError::Invalid(
                "boundary evidence chain_id does not match its asset".into(),
            ));
        }
        if !self.asset.is_known() {
            return Err(EconomyError::Invalid(format!(
                "boundary asset {}/{} is not an identified real asset",
                self.asset.chain_id(),
                self.asset.contract()
            )));
        }
        let from = normalize_address(&self.from_address)?;
        let to = normalize_address(&self.to_address)?;
        if from == to {
            return Err(EconomyError::Invalid(
                "boundary evidence from_address and to_address are the same"
                    .into(),
            ));
        }
        if self.amount_raw == 0 {
            return Err(EconomyError::Invalid(
                "boundary amount_raw must be > 0".into(),
            ));
        }
        validate_hash32("tx_hash", &self.tx_hash)?;
        validate_hash32("block_hash", &self.block_hash)?;
        Ok(())
    }
}

/// The four rows of the crossing invariant table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossingKind {
    ControlledToControlled,
    ExternalToExternal,
    ExternalToControlled,
    ControlledToExternal,
}

/// Sign of a crossing's contribution to Net External Value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NevSign {
    Zero,
    Positive,
    Negative,
}

/// Whether a value class may claim to have created external value. A coarser
/// question than the class itself: four different inflow classes are all
/// `Creating`, and the crossing decides which bucket a receipt must fall in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueClassDomain {
    Creating,
    NonCreating,
}

/// Which way a real asset crossed the controlled perimeter (P4.5a).
///
/// **Derived, never asserted, and deliberately without `Deserialize`** — the
/// same discipline, and for the same reason, as [`ControlDomain`]. The sign of
/// a crossing's contribution to Net External Value is a function of this
/// variant, and the variant is a function of two registry lookups, so the sign
/// cannot be supplied by a caller, cannot be read back from a file, and cannot
/// be edited without editing the addresses it was derived from.
///
/// There is exactly one construction path in the whole crate:
///
/// ```text
/// BoundaryCrossing::derive(&evidence, &registry)  // P1: registry lookup only
///   -> BoundaryCrossing::boundary_leg()           // reads derived (from, to)
///     -> BoundaryLeg::Crossing(BoundaryDirection)
/// ```
///
/// `BoundaryLeg::of` is private to this module, so no other module in the
/// crate can build a direction out of two domains it made up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryDirection {
    /// Money arrived from outside the controlled set: `+N`.
    ExternalToControlled,
    /// Money left the controlled set for the outside: `-N`.
    ControlledToExternal,
}

impl BoundaryDirection {
    /// The sign table for a real crossing, in one place and nowhere else. It
    /// takes no amount and returns no number, so nothing downstream can read a
    /// magnitude out of it without also going through a crossing.
    pub fn nev_sign(self) -> NevSign {
        match self {
            Self::ExternalToControlled => NevSign::Positive,
            Self::ControlledToExternal => NevSign::Negative,
        }
    }

    /// The multiplier that turns an absolute size into a signed contribution:
    /// `+1` in, `-1` out. This is the *only* place a sign is applied, so a
    /// caller cannot supply one and cannot override one.
    pub fn sign(self) -> i128 {
        match self {
            Self::ExternalToControlled => 1,
            Self::ControlledToExternal => -1,
        }
    }

    pub fn is_inflow(self) -> bool {
        matches!(self, Self::ExternalToControlled)
    }

    pub fn is_outflow(self) -> bool {
        matches!(self, Self::ControlledToExternal)
    }

    /// Canonical wire spelling. Total over the two variants, so a diagnostic
    /// rendering of a direction is never a `Debug` name that could change.
    pub fn spelling(self) -> &'static str {
        match self {
            Self::ExternalToControlled => "external_to_controlled",
            Self::ControlledToExternal => "controlled_to_external",
        }
    }
}

impl std::fmt::Display for BoundaryDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.spelling())
    }
}

/// The four rows, re-cut by the question P4.5a actually has to answer: is this
/// transfer a boundary crossing at all?
///
/// [`CrossingKind`] answers "which of the four pairs is this", and it answers it
/// for all four, including the two that are not crossings. That is the right
/// shape for a diagnostic table and the wrong shape for a decision: a caller
/// that pattern-matches `CrossingKind` and takes the `NevSign::Zero` branch
/// cannot tell an internal transfer (a real transfer of a real asset that moved
/// value between two addresses this node controls, and so moved nothing across
/// the perimeter) from a transfer between two addresses this node does not
/// control at all (which is not this node's business, is not evidence of
/// anything this node did, and has no entry in the NEV table whatsoever).
///
/// Both non-crossing answers are therefore spelled out as their own variants,
/// and neither of them can be a zero. That is what makes a zero-profit crossing
/// and a non-crossing distinguishable rather than merely numerically equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryLeg {
    /// A real crossing, in one of the two directions that move the perimeter.
    /// Only this variant can carry a value at all.
    Crossing(BoundaryDirection),
    /// `Controlled -> Controlled`. A real transfer of a real asset whose
    /// contribution to NEV is exactly zero, because both endpoints are inside
    /// the perimeter and the value never left it. It is a *row of the table*,
    /// and the row says zero.
    InternalTransfer,
    /// `External -> External`. Outside the perimeter entirely: not one endpoint
    /// is a controlled address, so nothing this node controls is involved. It is
    /// not a zero-profit crossing and cannot be represented as one — see
    /// [`Self::nev_sign`], which returns `None` rather than `Some(Zero)` for
    /// exactly this row.
    OutsidePerimeter,
}

impl BoundaryLeg {
    /// The classification, and the only construction path in the crate. Private
    /// so that the two domains it reads are the two a [`BoundaryCrossing`]
    /// derived from a [`ControlledAddressRegistry`], and cannot be supplied by
    /// a caller who holds two `ControlDomain` values of their own making.
    fn of(from: ControlDomain, to: ControlDomain) -> Self {
        match (from, to) {
            (ControlDomain::External, ControlDomain::Controlled) => {
                Self::Crossing(BoundaryDirection::ExternalToControlled)
            }
            (ControlDomain::Controlled, ControlDomain::External) => {
                Self::Crossing(BoundaryDirection::ControlledToExternal)
            }
            (ControlDomain::Controlled, ControlDomain::Controlled) => {
                Self::InternalTransfer
            }
            (ControlDomain::External, ControlDomain::External) => {
                Self::OutsidePerimeter
            }
        }
    }

    /// The direction, or `None` when this transfer is not a boundary crossing.
    ///
    /// `Option` rather than a three-way enum because the two non-crossing
    /// answers must not be interchangeable with a direction: this is the
    /// function P4.5a's delta constructor gates on, and its `None` arm is why a
    /// non-crossing cannot become a signed delta.
    pub fn direction(self) -> Option<BoundaryDirection> {
        match self {
            Self::Crossing(direction) => Some(direction),
            Self::InternalTransfer | Self::OutsidePerimeter => None,
        }
    }

    pub fn is_crossing(self) -> bool {
        self.direction().is_some()
    }

    /// The leg's contribution to NEV, or `None` when it has none.
    ///
    /// The `None` arm is the point of this method. `Some(NevSign::Zero)` is
    /// reserved for a crossing whose *magnitude* happens to be zero — which the
    /// P4.5a delta constructor refuses to build — and `OutsidePerimeter` gets
    /// `None` because a transfer with no controlled endpoint is not a row of the
    /// NEV table, it is outside the table. Returning `Zero` for both would let
    /// a caller sum a non-crossing into a total and read the result as
    /// "this transfer happened and was worth nothing", which is a claim nobody
    /// in this crate can support.
    pub fn nev_sign(self) -> Option<NevSign> {
        match self {
            Self::Crossing(direction) => Some(direction.nev_sign()),
            Self::InternalTransfer => Some(NevSign::Zero),
            Self::OutsidePerimeter => None,
        }
    }

    pub fn spelling(self) -> &'static str {
        match self {
            Self::Crossing(direction) => direction.spelling(),
            Self::InternalTransfer => "internal_transfer",
            Self::OutsidePerimeter => "outside_perimeter",
        }
    }
}

impl std::fmt::Display for BoundaryLeg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Crossing(direction) => write!(f, "{direction}"),
            Self::InternalTransfer => f.write_str("internal_transfer"),
            Self::OutsidePerimeter => f.write_str("outside_perimeter"),
        }
    }
}

impl CrossingKind {
    /// The invariant table, encoded:
    ///
    /// ```text
    /// Controlled -> Controlled = InternalTransfer  (NEV = 0)
    /// External   -> External   = irrelevant         (NEV = 0)
    /// External   -> Controlled = ExternalInflow     (NEV = +)
    /// Controlled -> External   = ExternalOutflow    (NEV = -)
    /// ```
    pub fn nev_sign(self) -> NevSign {
        match self {
            Self::ControlledToControlled | Self::ExternalToExternal => {
                NevSign::Zero
            }
            Self::ExternalToControlled => NevSign::Positive,
            Self::ControlledToExternal => NevSign::Negative,
        }
    }

    /// Only an inflow can justify a class that creates external value.
    pub fn value_class_domain(self) -> ValueClassDomain {
        match self {
            Self::ExternalToControlled => ValueClassDomain::Creating,
            Self::ControlledToExternal
            | Self::ControlledToControlled
            | Self::ExternalToExternal => ValueClassDomain::NonCreating,
        }
    }

    pub fn produces_external_value(self) -> bool {
        self.nev_sign() == NevSign::Positive
    }

    fn of(from: ControlDomain, to: ControlDomain) -> Self {
        match (from, to) {
            (ControlDomain::Controlled, ControlDomain::Controlled) => {
                Self::ControlledToControlled
            }
            (ControlDomain::External, ControlDomain::External) => {
                Self::ExternalToExternal
            }
            (ControlDomain::External, ControlDomain::Controlled) => {
                Self::ExternalToControlled
            }
            (ControlDomain::Controlled, ControlDomain::External) => {
                Self::ControlledToExternal
            }
        }
    }
}

impl ExternalValueClass {
    /// The crossing-derived counterpart of `can_create_external_value`.
    pub fn value_class_domain(&self) -> ValueClassDomain {
        if self.can_create_external_value() {
            ValueClassDomain::Creating
        } else {
            ValueClassDomain::NonCreating
        }
    }
}

/// A real asset crossing the controlled set, with both sides already derived.
///
/// No public fields, no `Deserialize`, and one way to obtain a value:
/// `derive` takes a `BoundaryEvidence` and a `ControlledAddressRegistry`, and
/// every other method takes `self`. The `asset` field is a `RealAsset` and no
/// constructor anywhere in this module accepts a `SyntheticAsset`, so placing
/// a synthetic asset in a crossing is a compile error rather than a runtime
/// check.
#[derive(Debug, Clone, Serialize)]
pub struct BoundaryCrossing {
    asset: RealAsset,
    from_address: String,
    to_address: String,
    from: ControlDomain,
    to: ControlDomain,
    amount_raw: u64,
    tx_hash: String,
    block_hash: String,
    proof: Option<BaseUsdcVerification>,
}

impl BoundaryCrossing {
    /// The single entry point. There is no variant that takes a domain, so
    /// `from` and `to` can only come out of a registry lookup. This is the
    /// only way to obtain a `BoundaryCrossing`; every other method takes one
    /// by value.
    pub fn derive(
        evidence: &BoundaryEvidence,
        registry: &ControlledAddressRegistry,
    ) -> Result<Self> {
        evidence.validate()?;
        Ok(Self {
            asset: evidence.asset.clone(),
            from_address: normalize_address(&evidence.from_address)?,
            to_address: normalize_address(&evidence.to_address)?,
            from: registry.domain_of(&evidence.from_address)?,
            to: registry.domain_of(&evidence.to_address)?,
            amount_raw: evidence.amount_raw,
            tx_hash: evidence.tx_hash.to_ascii_lowercase(),
            block_hash: evidence.block_hash.to_ascii_lowercase(),
            proof: None,
        })
    }

    /// Attaches the chain verification and checks that it actually describes
    /// this crossing: same chain, same token, same amount, same recipient,
    /// same transaction, and verified. A proof for a different transfer
    /// cannot be borrowed.
    pub fn with_verified_proof(
        mut self,
        proof: BaseUsdcVerification,
    ) -> Result<Self> {
        if !proof.verified {
            return Err(EconomyError::Invalid(
                "boundary crossing requires a verified payment proof".into(),
            ));
        }
        if proof.chain_id != self.asset.chain_id() {
            return Err(EconomyError::Invalid(
                "boundary proof chain_id does not match the crossing asset"
                    .into(),
            ));
        }
        if !proof.token.eq_ignore_ascii_case(self.asset.contract()) {
            return Err(EconomyError::Invalid(
                "boundary proof token does not match the crossing asset".into(),
            ));
        }
        if proof.matched_raw != self.amount_raw {
            return Err(EconomyError::Invalid(
                "boundary proof amount does not match the crossing amount"
                    .into(),
            ));
        }
        if normalize_address(&proof.recipient)? != self.to_address {
            return Err(EconomyError::Invalid(
                "boundary proof recipient is not the crossing recipient".into(),
            ));
        }
        if proof.transaction_hash.to_ascii_lowercase() != self.tx_hash {
            return Err(EconomyError::Invalid(
                "boundary proof transaction is not the crossing transaction"
                    .into(),
            ));
        }
        if proof.block_hash.to_ascii_lowercase() != self.block_hash {
            return Err(EconomyError::Invalid(
                "boundary proof block is not the crossing block".into(),
            ));
        }
        validate_hash32("proof transaction_hash", &proof.transaction_hash)?;
        validate_hash32("proof block_hash", &proof.block_hash)?;
        self.proof = Some(proof);
        Ok(self)
    }

    pub fn asset(&self) -> &RealAsset {
        &self.asset
    }

    pub fn from_address(&self) -> &str {
        &self.from_address
    }

    pub fn to_address(&self) -> &str {
        &self.to_address
    }

    pub fn from_domain(&self) -> ControlDomain {
        self.from
    }

    pub fn to_domain(&self) -> ControlDomain {
        self.to
    }

    pub fn amount_raw(&self) -> u64 {
        self.amount_raw
    }

    pub fn tx_hash(&self) -> &str {
        &self.tx_hash
    }

    pub fn block_hash(&self) -> &str {
        &self.block_hash
    }

    pub fn proof(&self) -> Option<&BaseUsdcVerification> {
        self.proof.as_ref()
    }

    pub fn kind(&self) -> CrossingKind {
        CrossingKind::of(self.from, self.to)
    }

    pub fn nev_sign(&self) -> NevSign {
        self.kind().nev_sign()
    }

    pub fn value_class_domain(&self) -> ValueClassDomain {
        self.kind().value_class_domain()
    }

    /// The P4.5a classification: is this transfer a boundary crossing, and in
    /// which direction?
    ///
    /// The only place in the crate a [`BoundaryLeg`] is built. It reads the two
    /// `from`/`to` fields that `derive` filled from the registry, so the answer
    /// changes if and only if the operator's controlled set changes — which is
    /// the same rule P1 established, applied to the direction rather than to the
    /// pair.
    pub fn boundary_leg(&self) -> BoundaryLeg {
        BoundaryLeg::of(self.from, self.to)
    }

    /// The direction when this is a real crossing, `None` when it is not.
    ///
    /// `None` is the whole answer for the two non-crossing rows: an internal
    /// transfer and a transfer outside the perimeter are both "no direction",
    /// and the caller that needs to tell them apart asks
    /// [`Self::boundary_leg`] instead of being handed a zero.
    pub fn boundary_direction(&self) -> Option<BoundaryDirection> {
        self.boundary_leg().direction()
    }
}

/// The typed replacement for a bare `settlement_asset: String`.
///
/// The wire format is deliberately unchanged: it still serializes as a plain
/// symbol string, so records already on disk keep the exact bytes their
/// `record_hash` was computed over. What changed is that the string is no
/// longer untyped -- it is classified on the way in, and a symbol that is
/// neither a known real asset nor a known synthetic asset is refused instead
/// of travelling forward as a silent "whatever this is".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementAsset {
    Real {
        asset: RealAsset,
        symbol: String,
    },
    Synthetic {
        asset: SyntheticAsset,
        symbol: String,
    },
}

impl SettlementAsset {
    /// Canonical spelling for new records.
    pub fn base_usdc() -> Self {
        Self::Real {
            asset: RealAsset::base_usdc(),
            symbol: "USDC".into(),
        }
    }

    pub fn synthetic(asset: SyntheticAsset) -> Self {
        Self::Synthetic {
            asset,
            symbol: asset.legacy_symbols()[0].to_string(),
        }
    }

    /// The classification table for symbols already on disk.
    ///
    /// An unrecognised symbol is an error, not a guess. The honest options
    /// were a typed error or a fallback to synthetic; the typed error was
    /// chosen because "not in the table" is a statement about *this build's*
    /// knowledge, and quietly filing an unknown symbol under a synthetic
    /// asset would rewrite the meaning of a historical record without anyone
    /// deciding to. It fails closed and it names the offending symbol.
    pub fn classify_symbol(symbol: &str) -> Result<Self> {
        let symbol = symbol.trim();
        if symbol.is_empty() {
            return Err(EconomyError::Invalid(
                "settlement asset symbol cannot be empty".into(),
            ));
        }
        let lowered = symbol.to_ascii_lowercase();
        let base_usdc = RealAsset::base_usdc();
        if lowered == BASE_USDC_NORMALIZED
            || lowered == BASE_USDC.to_ascii_lowercase()
            || lowered == BASE_USDC.trim_start_matches("0x").to_ascii_lowercase()
            || lowered == "usdc"
            || lowered == "usdc_base"
            || lowered == "usdc-base"
            || lowered == "usdc.base"
        {
            return Ok(Self::Real {
                asset: base_usdc,
                symbol: symbol.to_string(),
            });
        }
        for synthetic in [
            SyntheticAsset::SmUsd,
            SyntheticAsset::SyntheticMyc,
            SyntheticAsset::SyntheticCredit,
        ] {
            if synthetic
                .legacy_symbols()
                .iter()
                .any(|s| s.eq_ignore_ascii_case(symbol))
            {
                return Ok(Self::Synthetic {
                    asset: synthetic,
                    symbol: symbol.to_string(),
                });
            }
        }
        Err(EconomyError::Invalid(format!(
            "settlement asset symbol {symbol:?} is neither a known real asset \
             nor a known synthetic asset; refusing to guess"
        )))
    }

    /// The exact stored string, so a record keeps the bytes its hash was
    /// computed over.
    pub fn symbol(&self) -> &str {
        match self {
            Self::Real { symbol, .. } | Self::Synthetic { symbol, .. } => symbol,
        }
    }

    pub fn real_asset(&self) -> Option<&RealAsset> {
        match self {
            Self::Real { asset, .. } => Some(asset),
            Self::Synthetic { .. } => None,
        }
    }

    pub fn synthetic_asset(&self) -> Option<SyntheticAsset> {
        match self {
            Self::Synthetic { asset, .. } => Some(*asset),
            Self::Real { .. } => None,
        }
    }

    pub fn is_real(&self) -> bool {
        matches!(self, Self::Real { .. })
    }

    pub fn is_synthetic(&self) -> bool {
        matches!(self, Self::Synthetic { .. })
    }
}

impl Serialize for SettlementAsset {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        // Same shape as the old String: a bare JSON string.
        serializer.serialize_str(self.symbol())
    }
}

impl<'de> Deserialize<'de> for SettlementAsset {
    fn deserialize<D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let symbol = String::deserialize(deserializer)?;
        SettlementAsset::classify_symbol(&symbol)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        autonomy::{
            AgentClass, AutonomousEconomy, EconomicAgentManifest,
            ExternalValueReceipt, OpportunityCandidate, RiskProfile,
        },
        JobType, SCHEMA_VERSION,
    };
    use std::collections::BTreeMap;
    use tempfile::tempdir;

    const PAYOUT: &str = "0xe83331104f5f3c41e49abc46c810f9d71133e48c";
    const SECOND_CONTROLLED: &str = "0x9999999999999999999999999999999999999999";
    const COUNTERPARTY: &str = "0x1234567890abcdef1234567890abcdef12345678";
    const THIRD_PARTY: &str = "0x2222222222222222222222222222222222222222";
    const AMOUNT: u64 = 5_000_000;

    fn tx_hash() -> String {
        format!("0x{}", "11".repeat(32))
    }

    fn block_hash() -> String {
        format!("0x{}", "22".repeat(32))
    }

    fn registry() -> ControlledAddressRegistry {
        ControlledAddressRegistry::new()
            .with_address(PAYOUT)
            .unwrap()
            .with_address(SECOND_CONTROLLED)
            .unwrap()
    }

    fn evidence(from: &str, to: &str) -> BoundaryEvidence {
        BoundaryEvidence {
            chain_id: BASE_CHAIN_ID,
            asset: RealAsset::base_usdc(),
            from_address: from.into(),
            to_address: to.into(),
            amount_raw: AMOUNT,
            tx_hash: tx_hash(),
            block_hash: block_hash(),
        }
    }

    fn proof(to: &str, amount_raw: u64) -> BaseUsdcVerification {
        BaseUsdcVerification {
            verified: true,
            rpc: "http://127.0.0.1:8546".into(),
            provider_identity_verified: true,
            chain_id: BASE_CHAIN_ID,
            transaction_hash: tx_hash(),
            block_number: 101,
            block_hash: block_hash(),
            block_timestamp_unix: 1_700_000_400,
            latest_block: 110,
            confirmations: 10,
            token: BASE_USDC_NORMALIZED.to_string(),
            recipient: normalize_address(to).unwrap(),
            expected_raw: amount_raw,
            matched_raw: amount_raw,
            matching_log_index: Some(3),
        }
    }

    fn crossing(
        from: &str,
        to: &str,
        registry: &ControlledAddressRegistry,
    ) -> BoundaryCrossing {
        BoundaryCrossing::derive(&evidence(from, to), registry).unwrap()
    }

    fn agent() -> EconomicAgentManifest {
        EconomicAgentManifest {
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
        }
    }

    fn opportunity() -> OpportunityCandidate {
        OpportunityCandidate {
            schema_version: SCHEMA_VERSION,
            opportunity_id: "opp-1".into(),
            agent_id: "s1-arb-01".into(),
            observed_at_unix: 1_700_000_100,
            expires_at_unix: 1_700_001_000,
            job_type: JobType::Simulation,
            input_hash: "blake3:input".into(),
            evidence_hash: "blake3:evidence".into(),
            expected_gross_musd_micros: 8_000_000,
            expected_external_cost_musd_micros: 1_000_000,
            estimated_job_cost_musd_micros: 500_000,
            risk_buffer_musd_micros: 1_000_000,
            metadata: BTreeMap::new(),
        }
    }

    fn autonomy() -> (tempfile::TempDir, AutonomousEconomy) {
        let dir = tempdir().unwrap();
        let econ = AutonomousEconomy::open(dir.path()).unwrap();
        econ.register_agent(agent()).unwrap();
        econ.submit_opportunity(opportunity()).unwrap();
        (dir, econ)
    }

    fn external_receipt(gross: u64, cost: u64) -> ExternalValueReceipt {
        ExternalValueReceipt {
            schema_version: SCHEMA_VERSION,
            source_id: "source-1".into(),
            agent_id: "s1-arb-01".into(),
            opportunity_id: "opp-1".into(),
            value_class: ExternalValueClass::ExternalTradingPnl,
            network: "base".into(),
            asset: "USDC".into(),
            gross_inflow_musd_micros: gross,
            external_cost_musd_micros: cost,
            net_external_value_musd_micros: gross as i64 - cost as i64,
            proof_hash: tx_hash(),
            proof_verified: true,
            realized_at_unix: 1_700_000_400,
            verifier_id: "base-reconcile".into(),
        }
    }

    // ---- the invariant table, one row at a time ----

    #[test]
    fn controlled_to_controlled_is_internal_transfer_with_zero_nev() {
        let c = crossing(PAYOUT, SECOND_CONTROLLED, &registry());
        assert_eq!(c.from_domain(), ControlDomain::Controlled);
        assert_eq!(c.to_domain(), ControlDomain::Controlled);
        assert_eq!(c.kind(), CrossingKind::ControlledToControlled);
        assert_eq!(c.nev_sign(), NevSign::Zero);
        assert_eq!(c.value_class_domain(), ValueClassDomain::NonCreating);
        assert!(!c.kind().produces_external_value());
    }

    #[test]
    fn external_to_external_is_irrelevant_with_zero_nev() {
        let c = crossing(COUNTERPARTY, THIRD_PARTY, &registry());
        assert_eq!(c.from_domain(), ControlDomain::External);
        assert_eq!(c.to_domain(), ControlDomain::External);
        assert_eq!(c.kind(), CrossingKind::ExternalToExternal);
        assert_eq!(c.nev_sign(), NevSign::Zero);
        assert_eq!(c.value_class_domain(), ValueClassDomain::NonCreating);
        assert!(!c.kind().produces_external_value());
    }

    #[test]
    fn external_to_controlled_is_external_inflow_with_positive_nev() {
        let c = crossing(COUNTERPARTY, PAYOUT, &registry());
        assert_eq!(c.kind(), CrossingKind::ExternalToControlled);
        assert_eq!(c.nev_sign(), NevSign::Positive);
        assert_eq!(c.value_class_domain(), ValueClassDomain::Creating);
        assert!(c.kind().produces_external_value());
    }

    #[test]
    fn controlled_to_external_is_external_outflow_with_negative_nev() {
        let c = crossing(PAYOUT, COUNTERPARTY, &registry());
        assert_eq!(c.kind(), CrossingKind::ControlledToExternal);
        assert_eq!(c.nev_sign(), NevSign::Negative);
        assert_eq!(c.value_class_domain(), ValueClassDomain::NonCreating);
        assert!(!c.kind().produces_external_value());
    }

    #[test]
    fn every_domain_pair_maps_to_exactly_one_row() {
        // Guards the table against a variant being added without a row.
        let mut seen = Vec::new();
        for from in [ControlDomain::Controlled, ControlDomain::External] {
            for to in [ControlDomain::Controlled, ControlDomain::External] {
                let kind = CrossingKind::of(from, to);
                assert!(!seen.contains(&kind), "{kind:?} has two sources");
                seen.push(kind);
            }
        }
        assert_eq!(seen.len(), 4);
    }

    // ---- synthetic assets cannot reach a crossing ----

    #[test]
    fn synthetic_asset_cannot_be_placed_in_a_crossing() {
        // TYPE-level guarantee, not a runtime assertion: the asset field is a
        // RealAsset, `derive` takes only a BoundaryEvidence, and no
        // constructor in this module accepts a SyntheticAsset. This crate has
        // no compile-fail harness, so the test pins the type identity at
        // runtime instead of proving that no compiling program exists.
        fn only_real_assets(_: &RealAsset) {}
        let c = crossing(COUNTERPARTY, PAYOUT, &registry());
        only_real_assets(c.asset());
        assert!(c.asset().is_known());
        assert_eq!(
            std::any::type_name::<RealAsset>(),
            std::any::type_name_of_val(c.asset())
        );
        // And a synthetic asset never turns into a real one on the way in.
        for synthetic in [
            SyntheticAsset::SmUsd,
            SyntheticAsset::SyntheticMyc,
            SyntheticAsset::SyntheticCredit,
        ] {
            let classified = SettlementAsset::synthetic(synthetic);
            assert!(classified.is_synthetic());
            assert!(classified.real_asset().is_none());
            assert!(SettlementAsset::classify_symbol(
                classified.symbol()
            )
            .unwrap()
            .real_asset()
            .is_none());
        }
    }

    #[test]
    fn unidentified_real_asset_is_refused_at_the_boundary() {
        let mut e = evidence(COUNTERPARTY, PAYOUT);
        e.asset = RealAsset::new(BASE_CHAIN_ID, COUNTERPARTY, 6).unwrap();
        assert!(!e.asset.is_known());
        let err = BoundaryCrossing::derive(&e, &registry()).unwrap_err();
        assert!(err.to_string().contains("not an identified real asset"));
    }

    #[test]
    fn malformed_real_asset_is_refused_by_construction() {
        assert!(RealAsset::new(0, BASE_USDC, 6).is_err());
        assert!(RealAsset::new(BASE_CHAIN_ID, "not-an-address", 6).is_err());
        assert!(RealAsset::new(BASE_CHAIN_ID, BASE_USDC, 200).is_err());
        // A hand-written ledger line goes through the same check.
        let forged = serde_json::json!({
            "chain_id": BASE_CHAIN_ID,
            "contract": "0xdeadbeef",
            "decimals": 6,
        });
        assert!(serde_json::from_value::<RealAsset>(forged).is_err());
        // And an extra key on an otherwise valid asset is refused too.
        let extra = serde_json::json!({
            "chain_id": BASE_CHAIN_ID,
            "contract": BASE_USDC_NORMALIZED,
            "decimals": 6,
            "backdoor": true,
        });
        assert!(serde_json::from_value::<RealAsset>(extra).is_err());
    }

    #[test]
    fn base_usdc_constant_matches_the_normalizer() {
        // Keeps BASE_USDC_NORMALIZED honest without a fallible build step.
        assert_eq!(
            normalize_address(BASE_USDC).unwrap(),
            BASE_USDC_NORMALIZED
        );
        assert_eq!(BASE_USDC_DECIMALS, 6);
    }

    // ---- the domain is derived, not asserted ----

    #[test]
    fn domain_is_derived_from_the_registry_not_from_the_caller() {
        let registry = registry();
        assert_eq!(registry.len(), 2);

        assert_eq!(
            registry.domain_of(PAYOUT).unwrap(),
            ControlDomain::Controlled
        );
        assert_eq!(
            registry.domain_of(SECOND_CONTROLLED).unwrap(),
            ControlDomain::Controlled
        );
        assert_eq!(
            registry.domain_of(COUNTERPARTY).unwrap(),
            ControlDomain::External
        );
        // The same address in an empty registry is external, so the answer
        // comes from the registry and from nothing else.
        let empty = ControlledAddressRegistry::new();
        assert!(empty.is_empty());
        assert_eq!(
            empty.domain_of(PAYOUT).unwrap(),
            ControlDomain::External
        );
        assert_eq!(
            empty.domain_of(COUNTERPARTY).unwrap(),
            ControlDomain::External
        );
    }

    #[test]
    fn registry_matching_is_case_and_prefix_normalised() {
        let registry = ControlledAddressRegistry::new()
            .with_address("0xE83331104F5F3C41E49ABC46C810F9D71133E48C")
            .unwrap();
        assert!(registry.contains(PAYOUT).unwrap());
        assert_eq!(
            registry.domain_of(PAYOUT).unwrap(),
            ControlDomain::Controlled
        );
        assert_eq!(
            registry
                .domain_of("e83331104f5f3c41e49abc46c810f9d71133e48c")
                .unwrap(),
            ControlDomain::Controlled
        );
        // A malformed address is an error, not a silent "external".
        assert!(registry.domain_of("0xnothex").is_err());
    }

    #[test]
    fn payment_policy_payout_address_seeds_the_registry() {
        let policy = PaymentPolicy {
            schema_version: SCHEMA_VERSION,
            chain_id: BASE_CHAIN_ID,
            token: BASE_USDC_NORMALIZED.to_string(),
            payout_address: PAYOUT.into(),
            min_confirmations: 2,
            created_at_unix: 1_700_000_000,
            chain_provider: None,
        };
        let registry = ControlledAddressRegistry::from_policy(&policy).unwrap();
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.addresses().next(), Some(PAYOUT));
        assert_eq!(
            registry.domain_of(PAYOUT).unwrap(),
            ControlDomain::Controlled
        );
        assert_eq!(
            registry.domain_of(COUNTERPARTY).unwrap(),
            ControlDomain::External
        );
        // Seeded, not fixed: the set holds more than the one seed address.
        let grown = registry.with_address(SECOND_CONTROLLED).unwrap();
        assert_eq!(grown.len(), 2);
    }

    #[test]
    fn evidence_never_carries_a_domain_field() {
        // An extra "from_domain" key is refused rather than ignored, so there
        // is no way to smuggle an asserted domain through the ledger.
        let mut value =
            serde_json::to_value(evidence(COUNTERPARTY, PAYOUT)).unwrap();
        value["from_domain"] = serde_json::json!("external");
        assert!(serde_json::from_value::<BoundaryEvidence>(value).is_err());
    }

    // ---- the proof must describe this crossing ----

    #[test]
    fn proof_must_match_the_crossing_it_is_attached_to() {
        let registry = registry();
        let ok = crossing(COUNTERPARTY, PAYOUT, &registry)
            .with_verified_proof(proof(PAYOUT, AMOUNT))
            .unwrap();
        assert!(ok.proof().is_some());
        assert_eq!(ok.proof().unwrap().matched_raw, ok.amount_raw());

        // Wrong recipient.
        assert!(crossing(COUNTERPARTY, PAYOUT, &registry)
            .with_verified_proof(proof(COUNTERPARTY, AMOUNT))
            .is_err());
        // Wrong amount.
        assert!(crossing(COUNTERPARTY, PAYOUT, &registry)
            .with_verified_proof(proof(PAYOUT, AMOUNT - 1))
            .is_err());
        // Not verified.
        let mut unverified = proof(PAYOUT, AMOUNT);
        unverified.verified = false;
        assert!(crossing(COUNTERPARTY, PAYOUT, &registry)
            .with_verified_proof(unverified)
            .is_err());
        // Another transaction's proof.
        let mut other_tx = proof(PAYOUT, AMOUNT);
        other_tx.transaction_hash = format!("0x{}", "99".repeat(32));
        assert!(crossing(COUNTERPARTY, PAYOUT, &registry)
            .with_verified_proof(other_tx)
            .is_err());
        // Another chain's proof.
        let mut other_chain = proof(PAYOUT, AMOUNT);
        other_chain.chain_id = 1;
        assert!(crossing(COUNTERPARTY, PAYOUT, &registry)
            .with_verified_proof(other_chain)
            .is_err());
    }

    #[test]
    fn evidence_shape_is_validated() {
        let registry = registry();

        let mut e = evidence(COUNTERPARTY, PAYOUT);
        e.amount_raw = 0;
        assert!(BoundaryCrossing::derive(&e, &registry).is_err());

        let mut e = evidence(COUNTERPARTY, PAYOUT);
        e.tx_hash = "0xdead".into();
        assert!(BoundaryCrossing::derive(&e, &registry).is_err());

        let mut e = evidence(COUNTERPARTY, PAYOUT);
        e.block_hash = String::new();
        assert!(BoundaryCrossing::derive(&e, &registry).is_err());

        let mut e = evidence(COUNTERPARTY, PAYOUT);
        e.from_address = "nope".into();
        assert!(BoundaryCrossing::derive(&e, &registry).is_err());

        let mut e = evidence(COUNTERPARTY, PAYOUT);
        e.chain_id = 1;
        assert!(BoundaryCrossing::derive(&e, &registry).is_err());

        let mut e = evidence(COUNTERPARTY, PAYOUT);
        e.to_address = COUNTERPARTY.into();
        assert!(BoundaryCrossing::derive(&e, &registry).is_err());
    }

    // ---- legacy settlement_asset compatibility ----

    #[test]
    fn legacy_real_asset_symbol_still_deserializes() {
        for legacy in ["USDC", "usdc", "USDC_BASE", "usdc-base", BASE_USDC] {
            let classified = SettlementAsset::classify_symbol(legacy).unwrap();
            assert!(classified.is_real(), "{legacy} must stay real");
            assert_eq!(classified.symbol(), legacy);
            assert_eq!(
                classified.real_asset().unwrap(),
                &RealAsset::base_usdc()
            );
        }
    }

    #[test]
    fn legacy_ambiguous_symbol_is_a_typed_error_and_never_a_real_asset() {
        for ambiguous in ["USD", "USDC_BASE_XYZ", "stablecoin", "tokens"] {
            let err = SettlementAsset::classify_symbol(ambiguous).unwrap_err();
            assert!(
                matches!(err, EconomyError::Invalid(_)),
                "{ambiguous} must be a typed error"
            );
            assert!(err.to_string().contains("refusing to guess"));
        }
        // The deserialization path: no panic, no silent upgrade.
        assert!(serde_json::from_value::<SettlementAsset>(
            serde_json::json!("USD")
        )
        .is_err());
        assert!(SettlementAsset::classify_symbol("").is_err());
    }

    #[test]
    fn legacy_synthetic_symbol_is_classified_synthetic_not_real() {
        let classified = SettlementAsset::classify_symbol("smUSD").unwrap();
        assert_eq!(classified.synthetic_asset(), Some(SyntheticAsset::SmUsd));
        assert!(!classified.is_real());
        assert!(classified.real_asset().is_none());
        assert_eq!(classified.symbol(), "smUSD");
    }

    #[test]
    fn settlement_asset_still_serializes_as_a_plain_string() {
        // The wire shape is unchanged on purpose: an existing record's
        // record_hash was computed over `"settlement_asset":"USDC"`, and a map
        // here would invalidate every hash already on disk.
        assert_eq!(
            serde_json::to_value(SettlementAsset::base_usdc()).unwrap(),
            serde_json::json!("USDC")
        );
        assert_eq!(
            serde_json::to_value(SettlementAsset::synthetic(
                SyntheticAsset::SmUsd
            ))
            .unwrap(),
            serde_json::json!("smUSD")
        );
    }

    #[test]
    fn a_legacy_settlement_line_still_parses_and_still_hashes() {
        // A record in the exact shape older versions wrote, with the extra
        // top-level ledger envelope the revenue ledger adds.
        let settlement = crate::SettlementReceipt {
            schema_version: SCHEMA_VERSION,
            settlement_id: "settle-legacy".into(),
            job_id: "job-1".into(),
            work_receipt_id: "work-1".into(),
            settled_at_unix: 1_700_000_012,
            mode: crate::SettlementMode::Simulated,
            settlement_asset: SettlementAsset::classify_symbol("USDC").unwrap(),
            settled_amount_micros: 2_000_000,
            usd_equivalent_micros: 2_000_000,
            payment_intent_id: None,
            payment_block_number: None,
            payment_proof_hash: None,
            payment_proof_verified: false,
            external_paid: false,
            internal_work: false,
        };
        let bytes = serde_json::to_vec(&settlement).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains("\"settlement_asset\":\"USDC\""));
        let parsed: crate::SettlementReceipt = serde_json::from_slice(&bytes)
            .unwrap();
        assert_eq!(parsed.settlement_asset.symbol(), "USDC");
        assert!(parsed.settlement_asset.is_real());
        // Byte-for-byte stable, so the hash chain is untouched.
        assert_eq!(serde_json::to_vec(&parsed).unwrap(), bytes);
    }

    // ---- integration with the autonomy ledger ----

    #[test]
    fn inflow_crossing_justifies_the_classification_and_net_survives() {
        let (_dir, econ) = autonomy();
        let registry = registry();
        let crossing = econ
            .record_boundary_crossing(&evidence(COUNTERPARTY, PAYOUT), &registry)
            .unwrap()
            .with_verified_proof(proof(PAYOUT, AMOUNT))
            .unwrap();

        let receipt = econ
            .record_external_value_with_crossing(
                external_receipt(6_000_000, 1_000_000),
                &crossing,
            )
            .unwrap();
        // net = gross - cost still holds, and the crossing sign agrees.
        assert_eq!(receipt.net_external_value_musd_micros, 5_000_000);
        assert_eq!(
            receipt.net_external_value_musd_micros,
            receipt.gross_inflow_musd_micros as i64
                - receipt.external_cost_musd_micros as i64
        );
        assert_eq!(crossing.nev_sign(), NevSign::Positive);
        // P3: the write-time proof is not the authority. A reader re-derives the
        // crossing and, offline, stops before the chain read — so this ledger
        // reports a claim, not a level. The promotion path is exercised with a
        // provider that actually serves the transfer, in
        // `verified_view::tests::pinned_mode_promotes_when_the_chain_confirms`.
        let offline = econ.view(&registry).arv_status(1_700_000_500).unwrap();
        assert_eq!(offline.level, "PRE-ARV0");
        assert!(!offline.arv0_pass);
        assert_eq!(offline.net_external_value_musd_total, 0.0);
        // The receipt re-derives completely — chain, rules, class, asset and a
        // boundary crossing — and is still only a claim, because the transaction
        // behind it has not been looked at.
        assert_eq!(offline.unattested_external_events, 1);
        assert_eq!(offline.unattested_net_external_value_musd, 5.0);
        assert!(receipt.counts_as_external_value());

        // Stored as evidence, re-derived on read.
        let reread = econ.crossings(&registry).unwrap();
        assert_eq!(reread.len(), 1);
        assert_eq!(reread[0].from_domain(), ControlDomain::External);
        assert_eq!(reread[0].to_domain(), ControlDomain::Controlled);
        assert!(reread[0].proof().is_none());
        assert_eq!(reread[0].kind(), CrossingKind::ExternalToControlled);

        // The receipt is justified by the crossing, not by its own flag: the view
        // finds the evidence, derives it against the same registry, and agrees on
        // the class and the asset.
        let evidence = econ.view(&registry).receipt_evidence().unwrap();
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].revalidated);
        assert!(evidence[0].offline_ok);
        assert!(!evidence[0].counted, "no chain read happened yet");
        assert!(matches!(
            evidence[0].gap,
            Some(crate::verified_view::AttestationGap::ChainNotConfirmed(_))
        ));
    }

    #[test]
    fn a_derived_crossing_changes_with_the_registry() {
        // The ledger stores no domain: re-deriving against a registry that no
        // longer contains the payout address flips the classification.
        let (_dir, econ) = autonomy();
        econ.record_boundary_crossing(
            &evidence(COUNTERPARTY, PAYOUT),
            &registry(),
        )
        .unwrap();
        let empty = ControlledAddressRegistry::new();
        let reread = econ.crossings(&empty).unwrap();
        assert_eq!(reread.len(), 1);
        assert_eq!(reread[0].kind(), CrossingKind::ExternalToExternal);
        assert_eq!(reread[0].nev_sign(), NevSign::Zero);
    }

    #[test]
    fn gross_minus_cost_is_still_enforced_through_the_crossing() {
        let (_dir, econ) = autonomy();
        let registry = registry();
        let crossing = econ
            .record_boundary_crossing(&evidence(COUNTERPARTY, PAYOUT), &registry)
            .unwrap()
            .with_verified_proof(proof(PAYOUT, AMOUNT))
            .unwrap();

        let mut tampered = external_receipt(6_000_000, 1_000_000);
        tampered.gross_inflow_musd_micros = 9_000_000;
        let err = econ
            .record_external_value_with_crossing(tampered, &crossing)
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("gross inflow minus external cost"));
        assert_eq!(econ.external_values().unwrap().len(), 0);
        assert_eq!(
            econ.arv_status(1_700_000_500).unwrap().level,
            "PRE-ARV0"
        );
    }

    #[test]
    fn crossing_rejects_a_class_it_does_not_justify() {
        let (_dir, econ) = autonomy();
        let registry = registry();

        // An internal transfer cannot carry a class that creates value.
        let internal = econ
            .record_boundary_crossing(&evidence(PAYOUT, SECOND_CONTROLLED), &registry)
            .unwrap();
        assert_eq!(internal.nev_sign(), NevSign::Zero);
        let err = econ
            .record_external_value_with_crossing(
                external_receipt(6_000_000, 1_000_000),
                &internal,
            )
            .unwrap_err();
        assert!(err.to_string().contains("value class"));

        // An outflow with a positive net contradicts the crossing sign. The
        // class has to be a non-creating one, otherwise the class check above
        // rejects it first and the sign rule is never reached.
        let outflow = econ
            .record_boundary_crossing(&evidence(PAYOUT, COUNTERPARTY), &registry)
            .unwrap()
            .with_verified_proof(proof(COUNTERPARTY, AMOUNT))
            .unwrap();
        assert_eq!(outflow.nev_sign(), NevSign::Negative);
        let mut receipt = external_receipt(6_000_000, 1_000_000);
        receipt.value_class = ExternalValueClass::TreasuryTransfer;
        let err = econ
            .record_external_value_with_crossing(receipt, &outflow)
            .unwrap_err();
        assert!(err.to_string().contains("external outflow"), "{err}");

        // An outflow cannot book a receipt at all, in either direction: the
        // crossing demands a non-creating class, and the pre-existing rule in
        // validate_external_value refuses to mark a non-creating class as
        // verified. The two together mean the crossing path admits external
        // inflows only, which is the intended direction for a value boundary.
        let mut loss = external_receipt(1_000_000, 9_000_000);
        loss.source_id = "source-loss".into();
        loss.value_class = ExternalValueClass::TreasuryTransfer;
        let err = econ
            .record_external_value_with_crossing(loss, &outflow)
            .unwrap_err();
        assert!(
            err.to_string().contains("internal value class"),
            "{err}"
        );
        assert!(econ.external_values().unwrap().is_empty());
    }

    #[test]
    fn crossing_rejects_a_mismatched_asset_or_proof() {
        let (_dir, econ) = autonomy();
        let registry = registry();
        let crossing = econ
            .record_boundary_crossing(&evidence(COUNTERPARTY, PAYOUT), &registry)
            .unwrap()
            .with_verified_proof(proof(PAYOUT, AMOUNT))
            .unwrap();

        // Denominated in something other than the crossing asset.
        let mut receipt = external_receipt(6_000_000, 1_000_000);
        receipt.asset = "smUSD".into();
        let err = econ
            .record_external_value_with_crossing(receipt, &crossing)
            .unwrap_err();
        assert!(err.to_string().contains("settlement asset"));

        // Citing a transaction that is not the crossing transaction.
        let mut receipt = external_receipt(6_000_000, 1_000_000);
        receipt.proof_hash = format!("0x{}", "99".repeat(32));
        assert!(econ
            .record_external_value_with_crossing(receipt, &crossing)
            .is_err());
    }

    #[test]
    fn boundary_evidence_is_refused_before_it_is_stored() {
        let (_dir, econ) = autonomy();
        let mut bad = evidence(COUNTERPARTY, PAYOUT);
        bad.amount_raw = 0;
        assert!(econ
            .record_boundary_crossing(&bad, &registry())
            .is_err());
        assert!(econ.crossings(&registry()).unwrap().is_empty());
    }

    // ---- deny_unknown_fields regression (audit finding 5) ----

    #[test]
    fn autonomy_record_rejects_an_extra_unknown_key() {
        let (_dir, econ) = autonomy();
        econ.record_external_value(external_receipt(6_000_000, 1_000_000))
            .unwrap();
        let path = econ.ledger_path();
        let raw = std::fs::read_to_string(&path).unwrap();
        let line = raw.lines().last().unwrap();
        let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
        value["not_a_real_field"] = serde_json::json!({"free": "payload"});
        std::fs::write(&path, format!("{raw}{}\n", value)).unwrap();
        let err = econ.records().unwrap_err();
        assert!(err.to_string().contains("cannot be parsed"));
    }

    #[test]
    fn autonomy_payload_rejects_an_extra_unknown_key_inside_the_payload() {
        let (_dir, econ) = autonomy();
        let path = econ.ledger_path();
        let raw = std::fs::read_to_string(&path).unwrap();
        let line = raw.lines().last().unwrap();
        let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
        value["payload"]["agent"]["allow_any_job"] = serde_json::json!(true);
        std::fs::write(&path, format!("{}\n", value)).unwrap();
        assert!(econ.records().is_err());
    }

    #[test]
    fn settlement_receipt_rejects_an_extra_unknown_key() {
        let json = serde_json::json!({
            "schema_version": 1,
            "settlement_id": "settle-1",
            "job_id": "job-1",
            "work_receipt_id": "work-1",
            "settled_at_unix": 1,
            "mode": "simulated",
            "settlement_asset": "USDC",
            "settled_amount_micros": 1,
            "usd_equivalent_micros": 1,
            "payment_intent_id": null,
            "payment_block_number": null,
            "payment_proof_hash": null,
            "payment_proof_verified": false,
            "external_paid": false,
            "internal_work": false,
            "smuggled": true,
        });
        assert!(serde_json::from_value::<crate::SettlementReceipt>(json)
            .is_err());
    }

    #[test]
    fn a_closed_envelope_still_audits_clean() {
        // The counterpart of the three tests above: closing the envelope must
        // not break the records that never carried an extra key.
        let (_dir, econ) = autonomy();
        econ.record_external_value(external_receipt(6_000_000, 1_000_000))
            .unwrap();
        let records = econ.records().unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[2].record_hash.len(), 64);
        // P3: the summary's *verified* column is now the view's, and this receipt
        // cites no transaction, so it is counted as a receipt and reported as a
        // claim rather than as verified value.
        let summary = econ.summary().unwrap();
        assert_eq!(summary.external_value_receipts, 1);
        assert_eq!(summary.verified_external_value_receipts, 0);
        assert_eq!(summary.net_external_value_musd, 0.0);
    }

    #[test]
    fn evidence_round_trips_through_the_tagged_payload() {
        // The whole reason amount_raw is a u64: a large amount must survive
        // the internally tagged enum's buffering byte-exactly, or the record
        // could be written and never read back.
        let (_dir, econ) = autonomy();
        let mut big = evidence(COUNTERPARTY, PAYOUT);
        big.amount_raw = u64::MAX;
        econ.record_boundary_crossing(&big, &registry()).unwrap();
        let stored = econ.boundary_evidence().unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].amount_raw, u64::MAX);
        assert_eq!(stored[0], big);
    }
}
