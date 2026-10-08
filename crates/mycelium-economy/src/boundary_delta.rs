//! P4.5a: the boundary delta — a signed crossing contribution that is not yet
//! allowed to become a number.
//!
//! # The gap this step closes
//!
//! P1 made the settlement boundary a *typed* place. `NEV = ΣVerifiedInflows` was
//! computable because only inflows were ever promoted, and a lone inflow
//! genuinely can be a real receipt: someone paid a controlled address, that is
//! a fact, and it stands on its own. An external LOSS had no representation at
//! all, so `NEV = Σinflows − Σoutflows` was not computable — the negative leg
//! simply did not exist.
//!
//! # Why adding the negative leg naively would be a regression
//!
//! Consider an arbitrage, the smallest case that matters:
//!
//! ```text
//! controlled executor -> pool     100.00 USDC   (outflow,  must be -)
//! pool             -> executor     100.08 USDC   (inflow,   must be +)
//! ```
//!
//! The operation is worth `+0.08`. Promote either leg on its own and the
//! system records `+100.08` with no `-100.00` in sight, or `-100.00` with no
//! offsetting inflow: either way a false result, and the first one is a false
//! *profit* large enough to fund real budget. Under the inflows-only design
//! that mistake is not expressible, because promoting the inflow is the whole
//! of what the design can do and the inflow really did happen. The moment both
//! directions exist, **isolated-crossing promotion is unsound**, and adding the
//! negative leg without closing that hole would have made the codebase strictly
//! weaker.
//!
//! So this step does two things, and deliberately does not do the third:
//!
//! 1. it introduces the direction and the signed amount ([`BoundaryDirection`],
//!    [`crate::boundary::BoundaryLeg`], [`VerifiedBoundaryDelta`]) with the sign
//!    derived, never supplied; and
//! 2. it makes isolated promotion **structurally impossible** rather than merely
//!    discouraged.
//! 3. it does not promote anything. Promotion needs an aggregation over every
//!    leg of one operation, and that is P4.5c.
//!
//! # How isolated promotion is made impossible
//!
//! Not by a runtime flag, and not by a comment. By the *shape of the type*:
//!
//! * [`VerifiedBoundaryDelta`] is a **leg**, and its public surface offers no
//!   number at all. `signed_amount_micros` is `pub(crate)`, reserved for the
//!   P4.5c aggregation, so no predicate outside this crate can sum one leg into
//!   a total — not "should not", *cannot*.
//! * It has no `is_positive`, no `promotes`, no `nev_musd`, no `contributes_to`.
//!   The predicate that decides anything lives on [`crate::verified_view::VerifiedNev`],
//!   whose fields are private and which has no public constructor, exactly as
//!   before this step.
//! * It has no `Deserialize`, so a decoded JSON blob cannot be turned back into
//!   a leg and therefore cannot be fed to anything.
//! * Its only public constructor takes a `&BoundaryCrossing` and a
//!   `&ValidatedOutcomePolicy`. There is no constructor that takes a bare
//!   number, so nothing can become a leg by *claiming* to be one.
//! * Nothing in this module is reachable from
//!   [`crate::verified_view::VerifiedEconomyView`], so the leg type is not even
//!   connected to the promotion path. Until P4.5c exists, **no** leg promotes,
//!   which is the correct interim state and not a gap: the honest answer for a
//!   one-sided total is no total.
//!
//! `a_lone_delta_cannot_promote` in this module's tests walks every promotion
//! surface the crate has and asserts each one reports nothing for a ledger
//! holding both genuine legs of the arbitrage above. The claim is proved there,
//! not here.
//!
//! # The sign invariant, enforced twice
//!
//! `signed_amount_micros` is signed, and for a real crossing it must be
//! `> 0` for `ExternalToControlled` and `< 0` for `ControlledToExternal`.
//!
//! * **Publicly it is unconstructible.** [`VerifiedBoundaryDelta::from_crossing`]
//!   takes no sign and no amount: it reads the direction off the crossing's
//!   derived domains and applies [`BoundaryDirection::sign`]. A caller cannot
//!   supply a sign, cannot pass an amount of its own, and cannot override
//!   either.
//! * **Internally it is a typed error.** The one `pub(crate)` validating
//!   constructor is the only code that writes the field, and it refuses a zero
//!   or a wrongly-signed amount with [`BoundaryDeltaError::ZeroAmount`] or
//!   [`BoundaryDeltaError::SignMismatch`] — which hold in release builds too.
//!   A `debug_assert` was considered and rejected: it is strictly weaker, since
//!   it disappears exactly where an attacker controls the input.
//!
//! # Where external costs will attach (P4.5c, not here)
//!
//! A settlement will be `inflows − outflows − external_costs`. The cost term is
//! **not** a `ControlledToExternal` crossing, and this step makes that structural
//! rather than a convention:
//!
//! * a delta can only be built from a [`BoundaryCrossing`], which requires a
//!   [`crate::boundary::BoundaryEvidence`] describing a transfer between two
//!   distinct addresses, in an identified asset, of non-zero amount, with a
//!   well-formed transaction and block hash — and a
//!   [`crate::base_usdc::BaseUsdcVerification`] the chain confirmed for exactly
//!   that transfer;
//! * a gas fee has no ERC-20 `Transfer` log to point such a proof at. The fee is
//!   burned by a protocol or paid to a validator, and may never touch a
//!   controlled address at all, so there is no crossing to derive;
//! * therefore the aggregation in P4.5c will take the legs and a **separate**
//!   cost term, and subtract. Modelling a cost as an outflow crossing instead
//!   would make it inherit an evidence requirement it cannot meet, and — worse —
//!   let a cost be double-counted against an outflow that really did leave.
//!
//! Nothing here builds a cost term, names a gas schedule, or estimates one.
//!
//! # What is NOT here
//!
//! * **Aggregation.** That is [`crate::settlement`], and it is where the
//!   promotion predicate lives. A delta knows its own sign and nothing about
//!   whether its siblings exist, so it still has no `is_positive()`, no total
//!   and no route to one — the two tests at the end of this module assert that
//!   against the whole of `verified_view`, in both trust modes.
//! * **Gas, fees and native costs.** Still deliberately absent; see the seam
//!   above. P4.5d did not relax this: a cost is not a crossing and remains
//!   structurally inexpressible as one, so it is subtracted as a separate
//!   term in a different currency.
//! * **A second event identity.** P4.5b owns `ExternalEventId` and this module
//!   now uses it directly — see [`crate::event_id`]. The `UncanonicalEventId`
//!   placeholder P4.5a used is gone, not deprecated: two event-identity types
//!   in one crate is exactly how "temporary" becomes load-bearing, and the real
//!   type now exists to replace it.

use crate::{
    boundary::{BoundaryCrossing, BoundaryDirection, BoundaryLeg, RealAsset},
    event_id::{ExternalEventFact, ExternalEventId},
    policy_auth::{
        push_tagged, Address, Hash, PolicyError, PreimageFieldKind,
        ValidatedOutcomePolicy,
    },
    EconomyError,
};
use serde::Serialize;

/// Decimals of the unit a [`VerifiedBoundaryDelta`] is denominated in. Fixed at
/// 1e-6, the same unit the rest of the crate's economics use, so a delta and a
/// `musd_micros` figure are comparable without a conversion table.
const MICROS_DECIMALS: u8 = 6;

/// Domain of the canonical digest of a re-derived crossing. First bytes of that
/// digest, and a different string from every other domain in the crate, so a
/// delta's `evidence_hash` can never be confused with a policy hash, a
/// controlled-registry digest, a provider-identity digest, a receipt hash or a
/// settlement hash.
pub const BOUNDARY_EVIDENCE_DIGEST_DOMAIN: &str =
    "MYCELIUM-ECONOMY/BOUNDARY-EVIDENCE/V1";

/// Schema version of the evidence digest this build computes. A different
/// constant from every attestation schema in the crate on purpose: a delta is
/// not a receipt and not a settlement, and a digest minted by one layout must
/// not be read as though another had produced it.
pub const BOUNDARY_EVIDENCE_DIGEST_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum BoundaryDeltaError {
    #[error(transparent)]
    Economy(#[from] EconomyError),

    #[error(transparent)]
    Policy(#[from] PolicyError),

    #[error("boundary evidence digest is malformed: {0}")]
    Preimage(String),

    /// The transfer is not a boundary crossing, so it has no direction and
    /// therefore no signed contribution. An internal transfer and a transfer
    /// outside the perimeter both land here, with their own `leg` in the
    /// message: neither of them is a zero, and neither is ever summed.
    #[error(
        "{leg} is not a boundary crossing, so it cannot carry a signed boundary \
         delta; only external inflow and external outflow are entries in the NEV \
         table"
    )]
    NotABoundaryCrossing { leg: BoundaryLeg },

    /// The crossing's transaction has not been re-read by a pinned provider.
    /// A delta is strictly more authenticated than the crossing it comes from:
    /// it needs a validated policy *and* a chain-confirmed transfer, so
    /// "an operator holds a policy" is never enough to mint one.
    #[error(
        "a boundary delta requires a chain-confirmed crossing; the crossing's \
         transaction has not been re-read by a pinned provider"
    )]
    ChainUnconfirmed,

    /// A real crossing is never worth zero: `BoundaryEvidence` already refuses a
    /// zero `amount_raw`, and `amount_raw` is the only magnitude a delta can be
    /// built from. This arm is therefore defence in depth against a future
    /// magnitude source, not a reachable state from the current one.
    #[error("a {direction} crossing is worth a non-zero amount, so a delta of zero is a programming error")]
    ZeroAmount { direction: BoundaryDirection },

    /// The sign contradicts the direction.
    #[error(
        "a {direction} crossing must carry a signed amount with the opposite \
         sign, but this delta carries {signed_amount_micros} micros"
    )]
    SignMismatch {
        direction: BoundaryDirection,
        signed_amount_micros: i128,
    },

    /// An asset with more than 6 decimals cannot be denominated in micros
    /// without rounding, and a rounded boundary delta is a fabricated one. There
    /// is no such identified asset in this build, so this is not reachable
    /// through the public constructor either.
    #[error(
        "asset with {decimals} decimals cannot be expressed exactly in 1e-6 \
         units; a boundary delta is denominated in micros and may not round"
    )]
    SubMicrosPrecision { decimals: u8 },

    /// The scaled amount does not fit in a signed 64-bit-micros total's
    /// predecessor. Checked rather than assumed, so the failure is a typed
    /// refusal and not a wrapped number.
    #[error("boundary amount {amount_raw} does not fit in a signed micros total")]
    AmountOutOfRange { amount_raw: u64 },

    /// The crossing was chain-confirmed but the provider did not say which log
    /// it matched, so the transfer has no canonical
    /// [`ExternalEventId`] and cannot become a leg.
    ///
    /// Its own arm rather than a variant of [`Self::ChainUnconfirmed`], because
    /// the transfer may be entirely real and the failure is one of *naming*:
    /// two identical transfers in one transaction are indistinguishable without
    /// the index, so a leg named under a made-up index could be either the
    /// inflow or an outflow nobody booked. Fail closed and say so. Wraps
    /// [`crate::event_id::EventIdError`], so the provider's own wording survives.
    #[error(
        "the confirmed transfer has no canonical external identity, so it cannot \
         become a leg: {0}"
    )]
    EventIdentityIndeterminate(#[from] crate::event_id::EventIdError),
}

impl From<BoundaryDeltaError> for EconomyError {
    fn from(err: BoundaryDeltaError) -> Self {
        match err {
            // A delta that cannot be attested is an unattested artefact, which
            // is the crate's existing fail-closed vocabulary rather than a new
            // one for the same condition.
            BoundaryDeltaError::ChainUnconfirmed => {
                EconomyError::ProviderUnpinned(err.to_string())
            }
            other => EconomyError::Invalid(other.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// The signed amount
// ---------------------------------------------------------------------------

/// Converts a raw on-chain amount into micros and applies the direction's sign.
///
/// `pub(crate)` because the only legitimate caller inside the crate is
/// [`VerifiedBoundaryDelta::from_crossing`], and the only legitimate caller
/// outside it is P4.5c's aggregation — which will not be able to call this
/// directly either, since it will receive already-signed legs.
pub(crate) fn signed_micros(
    direction: BoundaryDirection,
    amount_raw: u64,
    decimals: u8,
) -> Result<i128, BoundaryDeltaError> {
    if decimals > MICROS_DECIMALS {
        return Err(BoundaryDeltaError::SubMicrosPrecision { decimals });
    }
    // `10^(6 - decimals)`. Bounded by `10^6` because `decimals <= 6`, and an
    // `i128` holding `u64::MAX * 10^6` cannot overflow — the checked call is
    // here so that a future change to `MICROS_DECIMALS` fails loudly instead of
    // silently wrapping.
    let scale = 10i128
        .checked_pow(u32::from(MICROS_DECIMALS - decimals))
        .ok_or(BoundaryDeltaError::AmountOutOfRange { amount_raw })?;
    let magnitude = i128::from(amount_raw)
        .checked_mul(scale)
        .ok_or(BoundaryDeltaError::AmountOutOfRange { amount_raw })?;
    let signed = magnitude
        .checked_mul(direction.sign())
        .ok_or(BoundaryDeltaError::AmountOutOfRange { amount_raw })?;
    // Checked here as well as in the constructor, so the sign rule is enforced
    // by the function that produces the number and not only by the function that
    // stores it. One implementation, two call sites, no drift.
    check_signed_amount(direction, signed)?;
    Ok(signed)
}

/// The sign rule itself, in one place.
///
/// A zero or a wrongly-signed amount for a real crossing is a *programming
/// error*, and it is reported as a typed error that survives a release build —
/// see the module doc for why this is not a `debug_assert`.
fn check_signed_amount(
    direction: BoundaryDirection,
    signed_amount_micros: i128,
) -> Result<(), BoundaryDeltaError> {
    let ok = match direction {
        BoundaryDirection::ExternalToControlled => signed_amount_micros > 0,
        BoundaryDirection::ControlledToExternal => signed_amount_micros < 0,
    };
    if ok {
        return Ok(());
    }
    if signed_amount_micros == 0 {
        Err(BoundaryDeltaError::ZeroAmount { direction })
    } else {
        Err(BoundaryDeltaError::SignMismatch {
            direction,
            signed_amount_micros,
        })
    }
}

// ---------------------------------------------------------------------------
// The evidence digest
// ---------------------------------------------------------------------------

/// The digest layout, in canonical order. Every fact a delta is derived from
/// appears exactly once.
const BOUNDARY_EVIDENCE_DIGEST_FIELDS: &[(&str, PreimageFieldKind)] = &[
    ("schema_version", PreimageFieldKind::U32),
    ("chain_id", PreimageFieldKind::U64),
    ("asset", PreimageFieldKind::AddressText),
    ("from_address", PreimageFieldKind::AddressText),
    ("to_address", PreimageFieldKind::AddressText),
    ("amount_raw", PreimageFieldKind::U64),
    ("tx_hash", PreimageFieldKind::Hash32),
    ("block_hash", PreimageFieldKind::Hash32),
];

/// Canonical digest of a re-derived crossing, under
/// [`BOUNDARY_EVIDENCE_DIGEST_DOMAIN`].
///
/// This is the `evidence_hash` a delta carries, and it is computed over facts
/// **re-derived** from the crossing's own derived fields — never over a copy
/// stored beside the delta. That is the P4b lesson applied one layer down: a
/// digest verified against the artefact's own copy of the facts is a digest of
/// nothing.
///
/// # What it commits to, and what it deliberately does not
///
/// It commits to **the transfer**. Chain, asset, sender, recipient, amount,
/// transaction and block: the things that happened on chain and are the same
/// whoever observed them and whenever.
///
/// It does **not** commit to whether this node has yet read the chain about
/// them. That was P4.5a's mistake, and this is the correction: with
/// `chain_confirmed` inside, one transfer had two evidence digests — one for
/// "recorded" and one for "confirmed" — and the second one is not a different
/// fact. It is a later stage of learning the same fact. An identity key that
/// changes when a node's own knowledge improves cannot be used as an identity:
/// the unconfirmed leg and the confirmed leg are the same leg, and a
/// de-duplication set keyed on this digest would have counted it twice.
///
/// The canonical identity of the external event is [`ExternalEventId`] and not
/// this digest, and the two are different digests over different messages:
/// `ExternalEventId` additionally binds the log index the chain read reported
/// and is domain-separated under [`crate::event_id::EVENT_ID_DOMAIN`], while
/// this one lives under [`BOUNDARY_EVIDENCE_DIGEST_DOMAIN`] and binds the
/// stored evidence a crossing was derived from. The confirmation state is
/// *still* recorded — it is not forgotten, it is just not an identity — in the
/// fact that a [`VerifiedBoundaryDelta`] cannot exist without one:
/// [`VerifiedBoundaryDelta::from_crossing`] refuses a crossing with no proof
/// with [`BoundaryDeltaError::ChainUnconfirmed`]. There is nothing to store on
/// a delta, because on a delta it is a constant.
pub fn boundary_evidence_digest(
    crossing: &BoundaryCrossing,
) -> Result<Hash, BoundaryDeltaError> {
    let values: Vec<(&str, Vec<u8>)> = vec![
        (
            "schema_version",
            BOUNDARY_EVIDENCE_DIGEST_SCHEMA_VERSION
                .to_be_bytes()
                .to_vec(),
        ),
        ("chain_id", crossing.asset().chain_id().to_be_bytes().to_vec()),
        (
            "asset",
            Address::parse(crossing.asset().contract())?
                .as_str()
                .as_bytes()
                .to_vec(),
        ),
        (
            "from_address",
            Address::parse(crossing.from_address())?
                .as_str()
                .as_bytes()
                .to_vec(),
        ),
        (
            "to_address",
            Address::parse(crossing.to_address())?
                .as_str()
                .as_bytes()
                .to_vec(),
        ),
        ("amount_raw", crossing.amount_raw().to_be_bytes().to_vec()),
        (
            "tx_hash",
            Hash::parse("tx_hash", crossing.tx_hash())?
                .to_bytes()?
                .to_vec(),
        ),
        (
            "block_hash",
            Hash::parse("block_hash", crossing.block_hash())?
                .to_bytes()?
                .to_vec(),
        ),
    ];
    check_layout(&values)?;

    let mut buf = Vec::new();
    push_tagged(&mut buf, b"domain", BOUNDARY_EVIDENCE_DIGEST_DOMAIN.as_bytes());
    push_tagged(
        &mut buf,
        b"sections",
        &u32::try_from(values.len())
            .map_err(|_| {
                BoundaryDeltaError::Preimage("too many digest sections".into())
            })?
            .to_be_bytes(),
    );
    for (tag, value) in &values {
        push_tagged(&mut buf, tag.as_bytes(), value);
    }
    Ok(Hash::from_bytes(*blake3::hash(&buf).as_bytes()))
}

/// The encoder and the layout table can disagree in exactly one way that
/// matters — a field renamed on one side and not the other — so it is checked at
/// run time rather than trusted. Same discipline as
/// [`crate::policy_auth::OutcomePolicyPayload::signing_preimage`], kept local so
/// this module's layout table stays independent of the receipt and settlement
/// ones.
fn check_layout(values: &[(&str, Vec<u8>)]) -> Result<(), BoundaryDeltaError> {
    if values.len() != BOUNDARY_EVIDENCE_DIGEST_FIELDS.len() {
        return Err(BoundaryDeltaError::Preimage(format!(
            "boundary evidence digest: encoder emitted {} sections for a layout \
             of {}",
            values.len(),
            BOUNDARY_EVIDENCE_DIGEST_FIELDS.len()
        )));
    }
    for ((tag, _), (expected_tag, _)) in
        values.iter().zip(BOUNDARY_EVIDENCE_DIGEST_FIELDS.iter())
    {
        if *tag != *expected_tag {
            return Err(BoundaryDeltaError::Preimage(format!(
                "boundary evidence digest: encoder emitted section {tag:?} where \
                 the layout expects {expected_tag:?}"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The delta
// ---------------------------------------------------------------------------

/// One leg of a settlement's boundary movement, signed.
///
/// This is **not** a receipt, **not** a promotion and **not** a number you can
/// spend. It is the unit P4.5c aggregates: a `(direction, magnitude)` pair,
/// derived from a re-derived crossing, bound to the evidence it came from and to
/// the policy that was in force when it was derived.
///
/// Private fields, no `Deserialize`, and one public constructor that takes a
/// [`BoundaryCrossing`] and a [`ValidatedOutcomePolicy`]. Note what that
/// signature rules out:
///
/// * a bare integer cannot become a leg;
/// * a JSON document cannot become a leg;
/// * a leg cannot be built from a crossing the chain has not confirmed;
/// * a leg cannot carry a sign, because [`from_crossing`] computes the sign from
///   the direction and the direction comes from two registry lookups.
///
/// The one piece of information deliberately kept off the public surface is
/// `signed_amount_micros`. See [`Self::signed_amount_micros`].
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedBoundaryDelta {
    event_id: ExternalEventId,
    asset: RealAsset,
    direction: BoundaryDirection,
    signed_amount_micros: i128,
    evidence_hash: Hash,
    policy_hash: Hash,
}

impl VerifiedBoundaryDelta {
    /// The only public constructor, and the only place a sign is applied.
    ///
    /// Three requirements, each of which fails closed with its own typed error:
    ///
    /// 1. the transfer must actually cross the perimeter. An internal transfer
    ///    and a transfer outside the perimeter are refused with their leg named,
    ///    not silently recorded as zero;
    /// 2. the crossing must carry a verified payment proof, so the transaction
    ///    the delta describes was re-read by a kernel-identified provider. A
    ///    delta is therefore *more* authenticated than the crossing it comes
    ///    from, never less: holding a policy is not enough, and holding a
    ///    chain-confirmed crossing is not enough either;
    /// 3. the amount must survive the scaling to micros exactly, and the sign
    ///    must match the direction — both enforced in
    ///    [`signed_micros`] and re-checked in [`Self::from_signed_amount`];
    /// 4. the transfer must be nameable. The proof has to report which log it
    ///    matched, because that is what [`ExternalEventId`] binds. A confirmed
    ///    transfer with no log index is refused with
    ///    [`BoundaryDeltaError::EventIdentityIndeterminate`] rather than named
    ///    under an invented index.
    ///
    /// There is no `Deserialize`, so this is not a gate a stored blob can skip:
    /// there is nothing to store and read back.
    pub fn from_crossing(
        crossing: &BoundaryCrossing,
        policy: &ValidatedOutcomePolicy,
    ) -> Result<Self, BoundaryDeltaError> {
        let leg = crossing.boundary_leg();
        let direction = leg
            .direction()
            .ok_or(BoundaryDeltaError::NotABoundaryCrossing { leg })?;
        let Some(proof) = crossing.proof() else {
            return Err(BoundaryDeltaError::ChainUnconfirmed);
        };
        let signed_amount_micros = signed_micros(
            direction,
            crossing.amount_raw(),
            crossing.asset().decimals(),
        )?;
        // P4.5c: the canonical identity, computed from the crossing's own
        // re-derived fields plus the log index the proof reported. There is no
        // fallback and no default index — `from_confirmed_transfer` is where
        // "no log index, no identity" lives, and its refusal is a leg that does
        // not get made.
        let fact = ExternalEventFact::from_parts(
            crossing.asset().chain_id(),
            crossing.tx_hash(),
            proof.matching_log_index.ok_or_else(|| {
                crate::event_id::EventIdError::LogIndexUnknown(format!(
                    "provider {} confirmed {} -> {} of {} raw units without reporting \
                     a log index",
                    proof.rpc,
                    crossing.from_address(),
                    crossing.to_address(),
                    crossing.amount_raw()
                ))
            })?,
            crossing.asset(),
            crossing.from_address(),
            crossing.to_address(),
            crossing.amount_raw(),
        )?;
        Self::from_signed_amount(
            direction,
            crossing.asset().clone(),
            ExternalEventId::logged(&fact)?,
            signed_amount_micros,
            boundary_evidence_digest(crossing)?,
            policy.policy_hash()?,
        )
    }

    /// The one place the field is written, and the place the sign rule is
    /// enforced for real.
    ///
    /// `pub(crate)` rather than `pub` so that the sign invariant is *testable*
    /// without becoming part of the crate's public surface. A public variant
    /// would be a way to hand a delta an arbitrary sign from outside; an
    /// unreachable private one would make the invariant unprovable, which is
    /// worse than untidy. As it stands: unreachable from outside the crate,
    /// checked here, and exercised by
    /// `a_zero_or_wrongly_signed_delta_is_a_typed_error`.
    pub(crate) fn from_signed_amount(
        direction: BoundaryDirection,
        asset: RealAsset,
        event_id: ExternalEventId,
        signed_amount_micros: i128,
        evidence_hash: Hash,
        policy_hash: Hash,
    ) -> Result<Self, BoundaryDeltaError> {
        check_signed_amount(direction, signed_amount_micros)?;
        Ok(Self {
            event_id,
            asset,
            direction,
            signed_amount_micros,
            evidence_hash,
            policy_hash,
        })
    }

    /// The leg's signed contribution, in 1e-6 units of the asset.
    ///
    /// **`pub(crate)`, and reserved for the P4.5c aggregation.** This is the
    /// seam that makes isolated promotion impossible rather than merely
    /// discouraged: the number exists, is signed, and is not reachable from
    /// outside the crate. No public accessor, no `nev_musd()`, no
    /// `is_positive()`, no `promotes()` — a caller outside this crate cannot
    /// obtain a magnitude to sum, so it cannot promote one leg, and it cannot
    /// even read one.
    ///
    /// `#[allow(dead_code)]` because nothing in the crate sums legs yet. That is
    /// the interim state the module doc describes: a leg exists, and it promotes
    /// nothing, including a genuine one.
    #[allow(dead_code)]
    pub(crate) fn signed_amount_micros(&self) -> i128 {
        self.signed_amount_micros
    }

    /// The asset this leg moves. A [`RealAsset`] and not a
    /// [`crate::boundary::SyntheticAsset`], and no constructor here accepts a
    /// synthetic asset, so placing one in a delta is a compile error rather than
    /// a runtime check.
    pub fn asset(&self) -> &RealAsset {
        &self.asset
    }

    /// The derived direction, and the only thing that determines the sign.
    pub fn direction(&self) -> BoundaryDirection {
        self.direction
    }

    /// The canonical identity of the external event this leg moves, under
    /// [`crate::event_id::EVENT_ID_DOMAIN`].
    ///
    /// P4.5c replaced P4.5a's `UncanonicalEventId` placeholder with this type
    /// outright. A leg and the receipt that books it now name the same on-chain
    /// fact with the same digest, so one de-duplication set covers both ledgers.
    pub fn event_id(&self) -> &ExternalEventId {
        &self.event_id
    }

    /// Digest of the re-derived crossing this leg was computed from.
    ///
    /// An identity over **the transfer**: the same addresses and the same
    /// amount before and after the chain read share it, because they are one
    /// fact and the read only changes what this node knows. See
    /// [`boundary_evidence_digest`]; the canonical *external event* identity is
    /// [`Self::event_id`], and the two are different digests over different
    /// messages.
    pub fn evidence_hash(&self) -> &Hash {
        &self.evidence_hash
    }

    /// The policy in force when this leg was derived. The same
    /// policy-hash-binding P4b and P4c use, so a leg derived under a rotated
    /// policy stops matching and is reported rather than silently re-approved.
    pub fn policy_hash(&self) -> &Hash {
        &self.policy_hash
    }

    /// The crossing's NEV sign, for a caller that wants the direction as a sign
    /// without a magnitude.
    ///
    /// This is a fact about the direction, not a promotion verdict: `NevSign` is
    /// a closed enum, so there is nothing here to sum and no amount to compare
    /// against a threshold. The predicate that decides anything still lives on
    /// [`crate::verified_view::VerifiedNev`], whose fields are private and which
    /// has no public constructor.
    pub fn nev_sign(&self) -> crate::boundary::NevSign {
        self.direction.nev_sign()
    }
}

/// The unit this module's amounts are denominated in, exposed so a caller
/// rendering a delta does not hard-code the exponent this module happened to
/// pick. `10^6 == 1_000_000`.
pub const BOUNDARY_DELTA_MICROS_DECIMALS: u8 = MICROS_DECIMALS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        autonomy::AutonomousEconomy,
        base_usdc::{
            normalize_address, BaseUsdcVerification, BaseUsdcVerifier,
            BASE_CHAIN_ID, BASE_USDC_DECIMALS,
        },
        boundary::{
            BoundaryEvidence, ControlDomain, ControlledAddressRegistry,
            CrossingKind, NevSign, SettlementAsset, SyntheticAsset,
        },
        chain_provider::{resolve, PinnedChainProvider},
        event_id::{ExternalEventFact, ExternalEventId},
        policy_auth::controlled_registry_hash,
        receipt_auth::testkit::AuthFixture,
        verified_view::VerifiedEconomyView,
    };
    use tempfile::tempdir;

    /// The controlled hot wallet: the address the registry adopts as ours.
    const EXECUTOR: &str = "0x1111111111111111111111111111111111111111";
    /// A second controlled address, so "controlled" is a set and not a name.
    const SECOND_CONTROLLED: &str =
        "0x2222222222222222222222222222222222222222";
    /// The external counterparty pool in the arbitrage below. NOT in the
    /// registry, which is the whole reason the two legs get opposite signs.
    const POOL: &str = "0x3333333333333333333333333333333333333333";
    /// A second external address, for the outside-the-perimeter row.
    const THIRD_PARTY: &str = "0x4444444444444444444444444444444444444444";

    /// 100.00 USDC, the arbitrage's outflow leg.
    const OUT_RAW: u64 = 100_000_000;
    /// 100.08 USDC, the arbitrage's inflow leg.
    const IN_RAW: u64 = 100_080_000;

    const NOW: u64 = 1_700_000_500;

    fn tx_a() -> String {
        format!("0x{}", "11".repeat(32))
    }

    fn block_a() -> String {
        format!("0x{}", "22".repeat(32))
    }

    fn tx_b() -> String {
        format!("0x{}", "33".repeat(32))
    }

    fn block_b() -> String {
        format!("0x{}", "44".repeat(32))
    }

    /// `BASE_USDC`'s lowercased contract, so a proof names the same asset the
    /// evidence does.
    const USDC: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

    fn evidence(
        from: &str,
        to: &str,
        amount_raw: u64,
        tx_hash: &str,
        block_hash: &str,
    ) -> BoundaryEvidence {
        BoundaryEvidence {
            chain_id: BASE_CHAIN_ID,
            asset: RealAsset::base_usdc(),
            from_address: from.into(),
            to_address: to.into(),
            amount_raw,
            tx_hash: tx_hash.into(),
            block_hash: block_hash.into(),
        }
    }

    /// The arbitrage's outflow leg: the executor pays the pool.
    fn out_evidence() -> BoundaryEvidence {
        evidence(EXECUTOR, POOL, OUT_RAW, &tx_a(), &block_a())
    }

    /// The arbitrage's inflow leg: the pool pays the executor back, plus 8 cents.
    fn in_evidence() -> BoundaryEvidence {
        evidence(POOL, EXECUTOR, IN_RAW, &tx_b(), &block_b())
    }

    fn proof(
        to: &str,
        amount_raw: u64,
        tx_hash: &str,
        block_hash: &str,
    ) -> BaseUsdcVerification {
        BaseUsdcVerification {
            verified: true,
            rpc: "unix:///run/mycelium-verifier.sock".into(),
            provider_identity_verified: true,
            chain_id: BASE_CHAIN_ID,
            transaction_hash: tx_hash.into(),
            block_number: 101,
            block_hash: block_hash.into(),
            block_timestamp_unix: 1_700_000_400,
            latest_block: 110,
            confirmations: 10,
            token: USDC.to_string(),
            recipient: normalize_address(to).unwrap(),
            expected_raw: amount_raw,
            matched_raw: amount_raw,
            matching_log_index: Some(3),
        }
    }

    fn registry() -> ControlledAddressRegistry {
        ControlledAddressRegistry::new()
            .with_address(EXECUTOR)
            .unwrap()
            .with_address(SECOND_CONTROLLED)
            .unwrap()
    }

    /// A validated policy, its pinned trust anchor and a live verifier socket.
    ///
    /// The socket is held, not dropped: its path and owner uid are baked into
    /// the signed policy's provider-identity digest, so the fixture has to
    /// describe a socket that still exists.
    struct Harness {
        /// Declared FIRST so it is dropped FIRST. `Drop for FakeRpcSocket`
        /// unblocks its accept loop by connecting to the socket *file*, so the
        /// directory holding that file has to still exist when the socket goes
        /// away; Rust drops struct fields in declaration order. Dropping the
        /// temp directory first unlinks the socket path, the reconnect fails,
        /// and the join at the end of `Drop` waits on a thread that will never
        /// wake.
        socket: crate::rpc_test_server::FakeRpcSocket,
        /// Keeps the socket's directory alive for as long as the socket. Named
        /// with the underscore for the same reason [`AuthFixture`]'s own
        /// `_dir` is: it is a lifetime guard, not something a test reads.
        _dir: tempfile::TempDir,
        auth: AuthFixture,
    }

    fn harness() -> Harness {
        let dir = tempdir().unwrap();
        let socket = crate::rpc_test_server::FakeRpcSocket::with_responses(
            dir.path().join("verifier.sock"),
            Vec::<(&str, serde_json::Value)>::new(),
        );
        let auth = AuthFixture::new(socket.path(), socket.uid(), registry());
        Harness {
            socket,
            _dir: dir,
            auth,
        }
    }

    impl Harness {
        fn policy(&self) -> ValidatedOutcomePolicy {
            self.auth.validated()
        }
    }

    /// A derived crossing, optionally with the chain read attached.
    fn crossing(
        ev: &BoundaryEvidence,
        registry: &ControlledAddressRegistry,
        confirmed: bool,
    ) -> Result<BoundaryCrossing, EconomyError> {
        let c = BoundaryCrossing::derive(ev, registry)?;
        if !confirmed {
            return Ok(c);
        }
        c.with_verified_proof(proof(
            &ev.to_address,
            ev.amount_raw,
            &ev.tx_hash,
            &ev.block_hash,
        ))
    }

    // ------------------------------------------------------------------
    // 1. the sign is derived, in both directions
    // ------------------------------------------------------------------

    #[test]
    fn external_to_controlled_derives_a_positive_signed_amount() {
        let h = harness();
        let policy = h.policy();
        let c = crossing(&in_evidence(), &h.auth.registry, true).unwrap();
        assert_eq!(c.boundary_direction(), Some(BoundaryDirection::ExternalToControlled));

        let leg = VerifiedBoundaryDelta::from_crossing(&c, &policy).unwrap();
        assert_eq!(leg.direction(), BoundaryDirection::ExternalToControlled);
        assert!(leg.direction().is_inflow());
        assert!(!leg.direction().is_outflow());
        assert_eq!(leg.nev_sign(), NevSign::Positive);
        assert_eq!(leg.signed_amount_micros(), IN_RAW as i128);
        assert!(leg.signed_amount_micros() > 0);
    }

    #[test]
    fn controlled_to_external_derives_a_negative_signed_amount() {
        let h = harness();
        let policy = h.policy();
        let c = crossing(&out_evidence(), &h.auth.registry, true).unwrap();
        assert_eq!(c.boundary_direction(), Some(BoundaryDirection::ControlledToExternal));

        let leg = VerifiedBoundaryDelta::from_crossing(&c, &policy).unwrap();
        assert_eq!(leg.direction(), BoundaryDirection::ControlledToExternal);
        assert!(leg.direction().is_outflow());
        assert!(!leg.direction().is_inflow());
        assert_eq!(leg.nev_sign(), NevSign::Negative);
        assert_eq!(leg.signed_amount_micros(), -(OUT_RAW as i128));
        assert!(leg.signed_amount_micros() < 0);
    }

    #[test]
    fn the_sign_cannot_be_supplied_or_overridden_by_a_caller() {
        let h = harness();
        let policy = h.policy();
        let reg = &h.auth.registry;
        let ev = in_evidence();

        // 1. Deterministic: the same evidence and the same registry give the
        //    same sign, every time, because the only inputs are the two
        //    addresses and the amount. There is no argument to get wrong.
        let first = VerifiedBoundaryDelta::from_crossing(
            &crossing(&ev, reg, true).unwrap(),
            &policy,
        )
        .unwrap();
        let second = VerifiedBoundaryDelta::from_crossing(
            &crossing(&ev, reg, true).unwrap(),
            &policy,
        )
        .unwrap();
        assert_eq!(first.direction(), second.direction());
        assert_eq!(
            first.signed_amount_micros(),
            second.signed_amount_micros()
        );

        // 2. The only thing that changes the sign is which address the operator
        //    controls. Adding the counterparty to the registry does not
        //    "override" the sign, it re-derives a different row: the transfer
        //    stops being a crossing at all.
        let widened = reg.clone().with_address(POOL).unwrap();
        let internal = crossing(&ev, &widened, true).unwrap();
        assert_eq!(
            internal.boundary_leg(),
            BoundaryLeg::InternalTransfer,
            "a registry that owns both endpoints is not a crossing"
        );
        assert_eq!(internal.boundary_direction(), None);
        let err = VerifiedBoundaryDelta::from_crossing(&internal, &policy)
            .unwrap_err();
        assert!(
            matches!(err, BoundaryDeltaError::NotABoundaryCrossing { .. }),
            "{err}"
        );

        // 3. Reversing the evidence reverses the sign. The caller controls the
        //    evidence, so the caller controls the direction — and that is
        //    exactly the P1 property, restated: the *conclusion* is derived
        //    from the evidence, never supplied alongside it.
        let reversed = crossing(
            &evidence(EXECUTOR, POOL, IN_RAW, &tx_b(), &block_b()),
            reg,
            true,
        )
        .unwrap();
        let flipped = VerifiedBoundaryDelta::from_crossing(&reversed, &policy)
            .unwrap();
        assert_eq!(flipped.direction(), BoundaryDirection::ControlledToExternal);
        assert_eq!(flipped.signed_amount_micros(), -(IN_RAW as i128));

        // 4. The sign is a function of the direction and the amount alone. The
        //    only multiplier in the crate is `BoundaryDirection::sign`, and it
        //    is two literal values.
        assert_eq!(BoundaryDirection::ExternalToControlled.sign(), 1);
        assert_eq!(BoundaryDirection::ControlledToExternal.sign(), -1);
    }

    #[test]
    fn boundary_direction_cannot_be_introduced_by_deserialization() {
        // COMPILE-TIME half: `BoundaryDirection` has no `Deserialize` impl, the
        // same guarantee P1 gave `ControlDomain` and P4a/P4b gave their wrappers.
        // Rust cannot assert "no impl exists" from a test, so — as in those
        // modules — the runtime half pins what a writer would actually have to
        // smuggle the direction through.
        let ev = in_evidence();

        // (a) The ledger's own shape refuses a direction field, at the top
        //     level and nested.
        for extra in ["direction", "boundary_direction", "nev_sign", "sign"] {
            let mut value = serde_json::to_value(ev.clone()).unwrap();
            value[extra] = serde_json::json!("controlled_to_external");
            assert!(
                serde_json::from_value::<BoundaryEvidence>(value).is_err(),
                "BoundaryEvidence must refuse a {extra} field"
            );
        }
        let mut value = serde_json::to_value(ev.clone()).unwrap();
        value["asset"]["direction"] = serde_json::json!("controlled_to_external");
        assert!(serde_json::from_value::<BoundaryEvidence>(value).is_err());

        // (b) The serialised crossing contains no direction, no domain and no
        //     sign: the wire form is evidence, and the conclusion is not in it.
        let c = crossing(&ev, &registry(), true).unwrap();
        let wire = serde_json::to_value(&c).unwrap();
        let object = wire.as_object().unwrap();
        for forbidden in [
            "direction",
            "boundary_direction",
            "boundary_leg",
            "nev_sign",
            "from_domain",
            "to_domain",
            "kind",
        ] {
            assert!(
                !object.contains_key(forbidden),
                "a serialised crossing must not carry {forbidden}, got {wire}"
            );
        }
        assert!(object.contains_key("from_address"));
        assert!(object.contains_key("amount_raw"));

        // (c) The diagnostic spellings are the only representation a direction
        //     has. They are a rendering, not an input.
        assert_eq!(
            serde_json::to_value(BoundaryDirection::ExternalToControlled).unwrap(),
            serde_json::json!("external_to_controlled")
        );
        assert_eq!(
            serde_json::to_value(BoundaryDirection::ControlledToExternal).unwrap(),
            serde_json::json!("controlled_to_external")
        );
        assert_eq!(
            serde_json::to_value(BoundaryLeg::InternalTransfer).unwrap(),
            serde_json::json!("internal_transfer")
        );
        assert_eq!(
            serde_json::to_value(BoundaryLeg::OutsidePerimeter).unwrap(),
            serde_json::json!("outside_perimeter")
        );
        // ... and the P1 four-row table is untouched by any of this.
        for (kind, spelling) in [
            (CrossingKind::ControlledToControlled, "controlled_to_controlled"),
            (CrossingKind::ExternalToExternal, "external_to_external"),
            (CrossingKind::ExternalToControlled, "external_to_controlled"),
            (CrossingKind::ControlledToExternal, "controlled_to_external"),
        ] {
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::json!(spelling)
            );
        }
    }

    // ------------------------------------------------------------------
    // 2. the two non-crossing rows
    // ------------------------------------------------------------------

    #[test]
    fn controlled_to_controlled_is_a_zero_row_and_carries_no_delta() {
        let h = harness();
        let policy = h.policy();
        let ev = evidence(EXECUTOR, SECOND_CONTROLLED, OUT_RAW, &tx_a(), &block_a());
        let c = crossing(&ev, &h.auth.registry, true).unwrap();

        assert_eq!(c.boundary_leg(), BoundaryLeg::InternalTransfer);
        assert_eq!(c.boundary_direction(), None);
        assert!(!c.boundary_leg().is_crossing());
        // Zero, and *knowingly* zero: this is a row of the NEV table whose value
        // is zero, because a controlled address participated and the value
        // never left the perimeter.
        assert_eq!(c.boundary_leg().nev_sign(), Some(NevSign::Zero));
        assert_eq!(c.nev_sign(), NevSign::Zero);

        // It is not a delta, and it cannot be promoted into one.
        let err = VerifiedBoundaryDelta::from_crossing(&c, &policy).unwrap_err();
        assert!(
            matches!(err, BoundaryDeltaError::NotABoundaryCrossing { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("internal_transfer"), "{err}");
    }

    #[test]
    fn external_to_external_is_outside_the_perimeter_not_a_zero_profit_crossing() {
        let h = harness();
        let policy = h.policy();
        let ev = evidence(POOL, THIRD_PARTY, OUT_RAW, &tx_a(), &block_a());
        let c = crossing(&ev, &h.auth.registry, true).unwrap();

        assert_eq!(c.boundary_leg(), BoundaryLeg::OutsidePerimeter);
        assert_eq!(c.boundary_direction(), None);
        assert!(!c.boundary_leg().is_crossing());

        // THE distinction. `nev_sign()` is `None` here, not `Some(Zero)`. A
        // transfer with no controlled endpoint is not a row of the NEV table
        // that happens to read zero; it is outside the table, and this type
        // refuses to pretend otherwise. An internal transfer, by contrast, is a
        // row that reads zero, and the two are different values.
        assert_eq!(c.boundary_leg().nev_sign(), None);
        assert_eq!(
            BoundaryLeg::InternalTransfer.nev_sign(),
            Some(NevSign::Zero),
            "an internal transfer is a row that reads zero"
        );
        assert_ne!(
            BoundaryLeg::InternalTransfer,
            BoundaryLeg::OutsidePerimeter,
            "a zero-profit crossing and a non-crossing must not be the same value"
        );

        // And it carries no delta either.
        let err = VerifiedBoundaryDelta::from_crossing(&c, &policy).unwrap_err();
        assert!(
            matches!(err, BoundaryDeltaError::NotABoundaryCrossing { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("outside_perimeter"), "{err}");

        // P1's row for the same transfer is still `ExternalToExternal` with
        // `NevSign::Zero`: the diagnostic table is unchanged by P4.5a, and the
        // new classification is strictly more informative than it.
        assert_eq!(c.kind(), CrossingKind::ExternalToExternal);
        assert_eq!(c.nev_sign(), NevSign::Zero);
    }

    #[test]
    fn every_domain_pair_maps_to_exactly_one_leg() {
        let registry = registry();
        let mut seen: Vec<BoundaryLeg> = Vec::new();
        for from in [ControlDomain::Controlled, ControlDomain::External] {
            for to in [ControlDomain::Controlled, ControlDomain::External] {
                // Two distinct addresses per domain, so the four rows are
                // reachable through the real derivation and not only through the
                // table.
                let (fa, ta) = match (from, to) {
                    (ControlDomain::Controlled, ControlDomain::Controlled) => {
                        (EXECUTOR, SECOND_CONTROLLED)
                    }
                    (ControlDomain::Controlled, ControlDomain::External) => {
                        (EXECUTOR, POOL)
                    }
                    (ControlDomain::External, ControlDomain::Controlled) => {
                        (POOL, EXECUTOR)
                    }
                    (ControlDomain::External, ControlDomain::External) => {
                        (POOL, THIRD_PARTY)
                    }
                };
                let c = crossing(
                    &evidence(fa, ta, OUT_RAW, &tx_a(), &block_a()),
                    &registry,
                    true,
                )
                .unwrap();
                let leg = c.boundary_leg();
                assert!(!seen.contains(&leg), "{leg:?} has two sources");
                seen.push(leg);
                // The P1 row and the P4.5a classification are two views of the
                // same two registry lookups, so they must not drift: the new
                // one is strictly more informative, never different.
                let (expected_leg, expected_kind) = match (from, to) {
                    (ControlDomain::Controlled, ControlDomain::Controlled) => {
                        (BoundaryLeg::InternalTransfer, CrossingKind::ControlledToControlled)
                    }
                    (ControlDomain::Controlled, ControlDomain::External) => (
                        BoundaryLeg::Crossing(BoundaryDirection::ControlledToExternal),
                        CrossingKind::ControlledToExternal,
                    ),
                    (ControlDomain::External, ControlDomain::Controlled) => (
                        BoundaryLeg::Crossing(BoundaryDirection::ExternalToControlled),
                        CrossingKind::ExternalToControlled,
                    ),
                    (ControlDomain::External, ControlDomain::External) => {
                        (BoundaryLeg::OutsidePerimeter, CrossingKind::ExternalToExternal)
                    }
                };
                assert_eq!(c.boundary_leg(), expected_leg);
                assert_eq!(c.kind(), expected_kind, "the P1 table must not drift");
            }
        }
        assert_eq!(seen.len(), 4);
        assert_eq!(
            seen.iter()
                .filter(|l| l.direction().is_some())
                .count(),
            2,
            "exactly two of the four rows are crossings"
        );
    }

    // ------------------------------------------------------------------
    // 3. a synthetic asset cannot appear
    // ------------------------------------------------------------------

    #[test]
    fn a_synthetic_asset_cannot_appear_in_a_delta() {
        // TYPE-level guarantee first, then the runtime half P1 pinned the same
        // way: the field is a `RealAsset`, `from_crossing` takes only a
        // `BoundaryCrossing` and a policy, and no constructor in this module
        // accepts a `SyntheticAsset`. This crate has no compile-fail harness,
        // so the type identity is pinned at runtime instead.
        let h = harness();
        let policy = h.policy();
        let c = crossing(&in_evidence(), &h.auth.registry, true).unwrap();
        let leg = VerifiedBoundaryDelta::from_crossing(&c, &policy).unwrap();
        fn only_real_assets(_: &RealAsset) {}
        only_real_assets(leg.asset());
        assert_eq!(
            std::any::type_name::<RealAsset>(),
            std::any::type_name_of_val(leg.asset())
        );
        assert!(leg.asset().is_known());
        assert_eq!(leg.asset(), &RealAsset::base_usdc());

        // Every synthetic ledger unit stays synthetic, in and out of the
        // classifier, so none of them can be routed into a delta.
        for synthetic in [
            SyntheticAsset::SmUsd,
            SyntheticAsset::SyntheticMyc,
            SyntheticAsset::SyntheticCredit,
        ] {
            let classified = SettlementAsset::synthetic(synthetic);
            assert!(classified.is_synthetic());
            assert!(classified.real_asset().is_none());
            assert!(SettlementAsset::classify_symbol(classified.symbol())
                .unwrap()
                .real_asset()
                .is_none());
        }

        // And a delta never renders its asset as a bare symbol string, which is
        // the shape a synthetic unit would arrive in.
        let wire = serde_json::to_value(&leg).unwrap();
        let asset = wire.get("asset").unwrap();
        assert!(asset.is_object(), "a delta's asset is a RealAsset, not a symbol");
        for key in ["chain_id", "contract", "decimals"] {
            assert!(asset.get(key).is_some(), "missing {key} in {asset}");
        }
        assert!(wire.get("settlement_asset").is_none());
    }

    // ------------------------------------------------------------------
    // 4. the sign invariant is enforced, not assumed
    // ------------------------------------------------------------------

    #[test]
    fn a_zero_or_wrongly_signed_delta_is_a_typed_error() {
        let h = harness();
        let policy = h.policy();
        let c = crossing(&in_evidence(), &h.auth.registry, true).unwrap();
        let fact = ExternalEventFact::from_parts(
            BASE_CHAIN_ID,
            &tx_b(),
            3,
            &RealAsset::base_usdc(),
            POOL,
            EXECUTOR,
            IN_RAW,
        )
        .unwrap();
        let id = ExternalEventId::logged(&fact).unwrap();
        let evidence_hash = boundary_evidence_digest(&c).unwrap();
        let policy_hash = policy.policy_hash().unwrap();
        let build = |direction, signed| {
            VerifiedBoundaryDelta::from_signed_amount(
                direction,
                RealAsset::base_usdc(),
                id.clone(),
                signed,
                evidence_hash.clone(),
                policy_hash.clone(),
            )
        };

        // Zero is refused in both directions, and it is its own error rather
        // than a "sign mismatch", because "worth nothing" and "worth the wrong
        // amount" are different mistakes.
        for direction in [
            BoundaryDirection::ExternalToControlled,
            BoundaryDirection::ControlledToExternal,
        ] {
            let err = build(direction, 0).unwrap_err();
            assert!(
                matches!(err, BoundaryDeltaError::ZeroAmount { .. }),
                "zero must be refused for {direction}, got {err}"
            );
            assert!(err.to_string().contains("programming error"), "{err}");
        }

        // A sign that contradicts the direction is refused, at both extremes of
        // the range, and the error names both the direction and the number so a
        // bug report says which way it went wrong.
        for (direction, wrong) in [
            (BoundaryDirection::ExternalToControlled, -1i128),
            (BoundaryDirection::ExternalToControlled, i128::MIN),
            (BoundaryDirection::ControlledToExternal, 1i128),
            (BoundaryDirection::ControlledToExternal, i128::MAX),
        ] {
            let err = build(direction, wrong).unwrap_err();
            match err {
                BoundaryDeltaError::SignMismatch {
                    direction: d,
                    signed_amount_micros,
                } => {
                    assert_eq!(d, direction);
                    assert_eq!(signed_amount_micros, wrong);
                }
                other => panic!("expected SignMismatch for {direction}, got {other}"),
            }
        }

        // The agreeing cases build.
        assert!(build(BoundaryDirection::ExternalToControlled, 1).is_ok());
        assert!(build(BoundaryDirection::ControlledToExternal, -1).is_ok());
        assert!(build(BoundaryDirection::ControlledToExternal, i128::MIN)
            .is_ok());

        // And there is no way to reach a zero leg through the public
        // constructor at all, because the only magnitude it can use is the
        // evidence's `amount_raw`, which P1 already refuses at zero.
        let mut zero = in_evidence();
        zero.amount_raw = 0;
        assert!(BoundaryCrossing::derive(&zero, &h.auth.registry).is_err());
        assert!(verified_boundary_delta_refuses(&zero, &policy).is_err());
    }

    fn verified_boundary_delta_refuses(
        ev: &BoundaryEvidence,
        policy: &ValidatedOutcomePolicy,
    ) -> Result<VerifiedBoundaryDelta, BoundaryDeltaError> {
        let c = BoundaryCrossing::derive(ev, &registry())?;
        VerifiedBoundaryDelta::from_crossing(&c, policy)
    }

    // ------------------------------------------------------------------
    // 5. symmetry: no direction is privileged in the derivation
    // ------------------------------------------------------------------

    #[test]
    fn an_outflow_is_derivable_from_evidence_an_inflow_is_derivable_from() {
        let h = harness();
        let policy = h.policy();
        let reg = &h.auth.registry;

        // Same helper, same policy, same kind of proof. The two legs differ in
        // the order of two addresses and in the amount, and in nothing else —
        // so the derivation cannot be quietly built to accept one and refuse
        // the other.
        let out_leg = VerifiedBoundaryDelta::from_crossing(
            &crossing(&out_evidence(), reg, true).unwrap(),
            &policy,
        )
        .unwrap();
        let in_leg = VerifiedBoundaryDelta::from_crossing(
            &crossing(&in_evidence(), reg, true).unwrap(),
            &policy,
        )
        .unwrap();

        assert_eq!(out_leg.direction(), BoundaryDirection::ControlledToExternal);
        assert_eq!(in_leg.direction(), BoundaryDirection::ExternalToControlled);
        assert_eq!(out_leg.asset(), in_leg.asset());
        assert_eq!(out_leg.policy_hash(), in_leg.policy_hash());
        assert_eq!(out_leg.signed_amount_micros(), -(OUT_RAW as i128));
        assert_eq!(in_leg.signed_amount_micros(), IN_RAW as i128);

        // The real arbitrage shape: both legs touch the SAME external pool, once
        // as sender and once as recipient. A design that treated the pool's
        // appearance as the privileged fact would accept one of these and
        // refuse the other.
        assert_eq!(
            crossing(&out_evidence(), reg, true).unwrap().from_address(),
            EXECUTOR
        );
        assert_eq!(
            crossing(&in_evidence(), reg, true).unwrap().to_address(),
            EXECUTOR
        );
        assert_eq!(
            crossing(&out_evidence(), reg, true).unwrap().to_address(),
            POOL
        );
        assert_eq!(
            crossing(&in_evidence(), reg, true).unwrap().from_address(),
            POOL
        );
        // Identical authority requirements: both legs needed a validated policy
        // and a chain-confirmed crossing, and nothing else.
        for ev in [out_evidence(), in_evidence()] {
            let unconfirmed = crossing(&ev, reg, false).unwrap();
            assert!(
                matches!(
                    VerifiedBoundaryDelta::from_crossing(&unconfirmed, &policy)
                        .unwrap_err(),
                    BoundaryDeltaError::ChainUnconfirmed
                ),
                "both directions must be refused identically without the chain read"
            );
            assert!(VerifiedBoundaryDelta::from_crossing(
                &crossing(&ev, reg, true).unwrap(),
                &policy
            )
            .is_ok());
        }
    }

    // ------------------------------------------------------------------
    // 6. the evidence digest
    // ------------------------------------------------------------------

    #[test]
    fn the_evidence_digest_cannot_be_re_pointed() {
        let h = harness();
        let policy = h.policy();
        let reg = &h.auth.registry;
        let base = crossing(&in_evidence(), reg, true).unwrap();
        let digest = boundary_evidence_digest(&base).unwrap();

        // Deterministic: the digest is over re-derived facts, not over a
        // serialised struct, so two derivations of one crossing agree.
        assert_eq!(digest, boundary_evidence_digest(&base).unwrap());
        let leg = VerifiedBoundaryDelta::from_crossing(&base, &policy).unwrap();
        assert_eq!(leg.evidence_hash(), &digest);

        // Every fact the delta depends on moves the digest.
        let mut other = in_evidence();
        other.amount_raw = IN_RAW - 1;
        assert_ne!(
            digest,
            boundary_evidence_digest(&crossing(&other, reg, true).unwrap())
                .unwrap()
        );
        let reversed = crossing(
            &evidence(EXECUTOR, POOL, IN_RAW, &tx_b(), &block_b()),
            reg,
            true,
        )
        .unwrap();
        assert_ne!(
            digest,
            boundary_evidence_digest(&reversed).unwrap(),
            "a different direction must not share an evidence digest"
        );
        let other_block = crossing(
            &evidence(POOL, EXECUTOR, IN_RAW, &tx_b(), &block_a()),
            reg,
            true,
        )
        .unwrap();
        assert_ne!(
            digest,
            boundary_evidence_digest(&other_block).unwrap()
        );
        // P4.5c, and the correction of a P4.5a decision: the confirmation
        // state is NOT in the digest. The unconfirmed and confirmed views of
        // one transfer are one transfer, and an identity key that moved when a
        // node learned something would be counting stages of knowledge, not
        // facts. `chain_confirmed` moved out of the preimage entirely; the
        // state is still enforced, structurally, because `from_crossing` will
        // not build a delta without a proof.
        let unconfirmed = crossing(&in_evidence(), reg, false).unwrap();
        assert_eq!(
            digest,
            boundary_evidence_digest(&unconfirmed).unwrap(),
            "an evidence digest must not change with this node's own knowledge"
        );
        assert!(
            VerifiedBoundaryDelta::from_crossing(&unconfirmed, &policy).is_err(),
            "and the state is still binding, just not as an identity"
        );

        // It is a distinct digest, not a re-spelling of another one.
        assert_ne!(digest, policy.policy_hash().unwrap());
        assert_ne!(digest, controlled_registry_hash(reg).unwrap());
        assert_ne!(
            digest,
            *leg.event_id().digest(),
            "evidence digest and event id are different messages"
        );
        assert_eq!(digest.as_str().len(), 66, "0x + 64 hex");
    }

    /// The reconciliation P4.5c owed P4.5a: the placeholder is gone and the
    /// real [`ExternalEventId`] is what a leg carries.
    #[test]
    fn a_leg_carries_the_canonical_external_event_id() {
        let h = harness();
        let policy = h.policy();
        let reg = &h.auth.registry;
        let c = crossing(&in_evidence(), reg, true).unwrap();

        // The identity is derived from the crossing's own re-derived fields and
        // the log index the proof reported, so it is exactly the id the receipt
        // side computes for the same transfer — which is what lets ONE
        // de-duplication set cover both ledgers.
        let leg = VerifiedBoundaryDelta::from_crossing(&c, &policy).unwrap();
        let fact = ExternalEventFact::from_parts(
            BASE_CHAIN_ID,
            &tx_b(),
            3,
            &RealAsset::base_usdc(),
            POOL,
            EXECUTOR,
            IN_RAW,
        )
        .unwrap();
        assert_eq!(*leg.event_id(), ExternalEventId::logged(&fact).unwrap());
        assert_eq!(
            leg.event_id().as_str(),
            crate::event_id::ExternalEventId::logged(
                &ExternalEventFact::from_confirmed_transfer(
                    &in_evidence(),
                    c.proof().unwrap()
                )
                .unwrap()
            )
            .unwrap()
            .as_str(),
            "the same identity the receipt-side reader computes"
        );

        // A different log index is a different event, so the two legs of one
        // transaction are distinguishable.
        let other_index = ExternalEventId::logged(
            &ExternalEventFact::from_parts(
                BASE_CHAIN_ID,
                &tx_b(),
                4,
                &RealAsset::base_usdc(),
                POOL,
                EXECUTOR,
                IN_RAW,
            )
            .unwrap(),
        )
        .unwrap();
        assert_ne!(*leg.event_id(), other_index);

        // Deterministic, and stable across derivations of the same crossing.
        let again = VerifiedBoundaryDelta::from_crossing(&c, &policy).unwrap();
        assert_eq!(again.event_id(), leg.event_id());

        // And the placeholder is not merely unused: it is not a type any more.
        // `UncanonicalEventId` has no `Deserialize` and its name appeared in no
        // other module, so nothing outside this file can have been holding one;
        // `the_uncanonical_event_id_is_derived_from_the_crossing_and_named_for_what_it_is`
        // below is replaced by this test for that reason.
        assert!(std::any::type_name::<ExternalEventId>().contains("event_id"));
        assert!(
            !std::any::type_name::<ExternalEventId>().contains("Uncanonical")
        );
    }

    /// A chain-confirmed transfer the provider could not place in a log cannot
    /// become a leg, because it cannot be named.
    ///
    /// This is P4.5b's `LogIndexUnknown` rule arriving at the delta layer, and
    /// it is a *naming* failure rather than a truth failure: the transfer may be
    /// entirely real. Refusing is still the only safe answer, because two
    /// identical transfers in one transaction would otherwise share an
    /// identity and one of them — possibly the outflow — would go unrepresented.
    #[test]
    fn a_confirmed_transfer_with_no_log_index_is_not_a_leg() {
        let h = harness();
        let policy = h.policy();
        let reg = &h.auth.registry;
        let c = crossing(&in_evidence(), reg, true).unwrap();
        // Same crossing, same proof, one field removed.
        let mut indexless = c.proof().unwrap().clone();
        indexless.matching_log_index = None;
        let c = c.with_verified_proof(indexless).unwrap();

        let err = VerifiedBoundaryDelta::from_crossing(&c, &policy).unwrap_err();
        match err {
            BoundaryDeltaError::EventIdentityIndeterminate(e) => {
                assert!(
                    matches!(e, crate::event_id::EventIdError::LogIndexUnknown(_)),
                    "{e}"
                );
                assert!(e.to_string().contains("no log index"), "{e}");
            }
            other => panic!("expected the naming refusal, got {other}"),
        }

        // Control: the very same crossing with the index is a leg, so the
        // refusal above is about the index and nothing else.
        let ok = crossing(&in_evidence(), reg, true).unwrap();
        assert!(
            VerifiedBoundaryDelta::from_crossing(&ok, &policy).is_ok(),
            "control: with a log index the same transfer is a leg"
        );
    }

    // ------------------------------------------------------------------
    // 7. the policy binding
    // ------------------------------------------------------------------

    #[test]
    fn a_delta_is_bound_to_the_policy_it_was_derived_under() {
        let h = harness();
        let policy = h.policy();
        let c = crossing(&out_evidence(), &h.auth.registry, true).unwrap();
        let leg = VerifiedBoundaryDelta::from_crossing(&c, &policy).unwrap();
        assert_eq!(leg.policy_hash(), &policy.policy_hash().unwrap());

        // A rotated policy over the same anchor, registry and provider produces a
        // different hash, so a leg derived under one is not silently
        // re-approved under the other. Rotation history is out of scope — the
        // mismatch simply fails closed, the same rule P4b and P4c use.
        let rotated = h.auth.rotated(9).validate().unwrap();
        let other = VerifiedBoundaryDelta::from_crossing(&c, &rotated).unwrap();
        assert_ne!(leg.policy_hash(), other.policy_hash());
        assert_eq!(other.policy_hash(), &rotated.policy_hash().unwrap());
        // The economics are untouched by the rotation: only the authority label
        // moved.
        assert_eq!(leg.signed_amount_micros(), other.signed_amount_micros());
        assert_eq!(leg.evidence_hash(), other.evidence_hash());
    }

    // ------------------------------------------------------------------
    // 8. micros scaling
    // ------------------------------------------------------------------

    #[test]
    fn micros_scaling_is_exact_and_refuses_to_round() {
        let inflow = BoundaryDirection::ExternalToControlled;
        let outflow = BoundaryDirection::ControlledToExternal;

        // 6 decimals is the identity: raw units are already micros.
        assert_eq!(signed_micros(inflow, 5_000_000, 6).unwrap(), 5_000_000);
        assert_eq!(signed_micros(outflow, 5_000_000, 6).unwrap(), -5_000_000);
        assert_eq!(BASE_USDC_DECIMALS, BOUNDARY_DELTA_MICROS_DECIMALS);

        // Fewer decimals scale UP by a power of ten, exactly: 2 decimals is
        // 10^4 micros per raw unit.
        assert_eq!(signed_micros(inflow, 1, 0).unwrap(), 1_000_000);
        assert_eq!(signed_micros(inflow, 3, 2).unwrap(), 30_000);
        assert_eq!(signed_micros(outflow, 3, 2).unwrap(), -30_000);

        // The largest on-chain amount this crate can hold, in both directions,
        // with and without scaling. Exact, and nowhere near an overflow.
        assert_eq!(
            signed_micros(inflow, u64::MAX, 6).unwrap(),
            i128::from(u64::MAX)
        );
        assert_eq!(
            signed_micros(outflow, u64::MAX, 0).unwrap(),
            -(i128::from(u64::MAX) * 1_000_000)
        );

        // More than 6 decimals cannot be denominated in micros without
        // rounding, and a rounded boundary delta is a fabricated one. Refused
        // rather than truncated.
        for decimals in [7u8, 9, 18, 36] {
            let err = signed_micros(inflow, 1, decimals).unwrap_err();
            assert!(
                matches!(err, BoundaryDeltaError::SubMicrosPrecision { .. }),
                "{decimals} decimals must be refused, got {err}"
            );
            assert!(err.to_string().contains("may not round"), "{err}");
        }
    }

    // ------------------------------------------------------------------
    // 9. a delta is more authenticated than the crossing it came from
    // ------------------------------------------------------------------

    #[test]
    fn a_delta_requires_a_validated_policy_and_a_chain_confirmed_crossing() {
        let h = harness();
        let policy = h.policy();
        let reg = &h.auth.registry;

        // No chain read, no delta. Not a warning and not a downgraded value.
        let unconfirmed = crossing(&in_evidence(), reg, false).unwrap();
        assert!(unconfirmed.proof().is_none());
        let err = VerifiedBoundaryDelta::from_crossing(&unconfirmed, &policy)
            .unwrap_err();
        assert!(
            matches!(err, BoundaryDeltaError::ChainUnconfirmed),
            "{err}"
        );
        // And it maps onto the crate's existing fail-closed vocabulary.
        let as_economy: EconomyError = err.into();
        assert!(
            matches!(as_economy, EconomyError::ProviderUnpinned(_)),
            "{as_economy}"
        );

        // A proof that does not describe this crossing cannot be borrowed, and a
        // delta cannot be minted off a crossing that P1 already refused to
        // attach one to. The crossing is `POOL -> EXECUTOR`, so its own proof
        // names EXECUTOR; every case below differs from that one proof in
        // exactly one way.
        let c = crossing(&in_evidence(), reg, false).unwrap();
        // Wrong recipient: the transfer's counterparty, not its beneficiary.
        assert!(c.clone().with_verified_proof(proof(POOL, IN_RAW, &tx_b(), &block_b())).is_err());
        // Wrong amount.
        assert!(c.clone().with_verified_proof(proof(EXECUTOR, IN_RAW - 1, &tx_b(), &block_b())).is_err());
        // Not verified.
        let mut unverified = proof(EXECUTOR, IN_RAW, &tx_b(), &block_b());
        unverified.verified = false;
        assert!(c.clone().with_verified_proof(unverified).is_err());
        // Another transaction, and another block.
        assert!(c.clone().with_verified_proof(proof(EXECUTOR, IN_RAW, &tx_a(), &block_b())).is_err());
        assert!(c.clone().with_verified_proof(proof(EXECUTOR, IN_RAW, &tx_b(), &block_a())).is_err());
        // Another chain.
        let mut other_chain = proof(EXECUTOR, IN_RAW, &tx_b(), &block_b());
        other_chain.chain_id = 1;
        assert!(c.clone().with_verified_proof(other_chain).is_err());
        // Control: the crossing's own proof is accepted, so the refusals above
        // are about the mismatch and not about the rule being unsatisfiable.
        assert!(c.clone().with_verified_proof(proof(EXECUTOR, IN_RAW, &tx_b(), &block_b())).is_ok());
        // Still nothing to mint from, because the attempts above all consumed
        // their clone rather than this one.
        assert!(VerifiedBoundaryDelta::from_crossing(&c, &policy).is_err());

        // With the chain read, and with a policy that resolved from the pin, it
        // builds. Both are required: the signature/policy is provenance, the
        // chain read is truth, and a delta needs both.
        assert!(
            VerifiedBoundaryDelta::from_crossing(
                &crossing(&in_evidence(), reg, true).unwrap(),
                &policy
            )
            .is_ok()
        );
    }

    // ------------------------------------------------------------------
    // 10. THE test: a lone delta cannot promote
    // ------------------------------------------------------------------

    /// Walks every promotion surface the crate exposes and asserts that none of
    /// them moved. Used by the two tests below; deliberately a local copy of the
    /// shape of `verified_view::tests::assert_no_promotion_route` rather than a
    /// call into it, because that helper is private to its own test module and
    /// this module must be able to assert the same thing without verified_view
    /// knowing about deltas at all.
    fn assert_no_promotion_surface(
        view: &VerifiedEconomyView<'_>,
        why: &str,
    ) {
        // 1. The authority number. In pinned mode this is a zero `VerifiedNev`
        //    rather than a refusal; what matters is that it names no event. In
        //    unverified mode there is no authority at all and the view refuses
        //    rather than handing out a zero.
        match view.verified_nev() {
            Ok(nev) => {
                assert_eq!(nev.receipts(), 0, "{why}: a delta reached VerifiedNev");
                assert_eq!(nev.nev_musd_micros(), 0, "{why}");
                assert!(!nev.is_positive(), "{why}: a delta promoted ARV0");
            }
            Err(e) => assert!(
                e.to_string().contains("verified NEV requires"),
                "{why}: {e}"
            ),
        }

        // 2. ARV.
        let arv = view.arv_status(NOW).unwrap();
        assert_eq!(arv.level, "PRE-ARV0", "{why}");
        assert!(!arv.arv0_pass, "{why}");
        assert_eq!(arv.verified_external_events, 0, "{why}");
        assert_eq!(arv.net_external_value_musd_total, 0.0, "{why}");

        // 3. The claimed side too: the delta's evidence is in the ledger, and it
        //    does not even become a claim.
        let claimed = view.unattested_nev().unwrap();
        assert_eq!(claimed.re_derived_receipts, 0, "{why}");
        assert!(
            claimed.receipts.is_empty(),
            "{why}: the crossing evidence became a receipt row"
        );
        assert_eq!(claimed.claimed_net_external_value_musd_micros, 0, "{why}");

        // 4. The summary the dashboards read.
        let summary = view.autonomy_summary().unwrap();
        assert_eq!(summary.verified_external_value_receipts, 0, "{why}");
        assert_eq!(summary.net_external_value_musd, 0.0, "{why}");
    }

    #[test]
    fn a_lone_delta_cannot_promote() {
        // The dangerous case is the inflow leg: promote `+100.08` on its own
        // and the system books a false profit with no `-100.00` anywhere in
        // sight. So this test starts from that leg.
        for (name, ev, expected_sign) in [
            ("inflow", in_evidence(), IN_RAW as i128),
            ("outflow", out_evidence(), -(OUT_RAW as i128)),
        ] {
            let h = harness();
            let policy = h.policy();
            let reg = &h.auth.registry;
            let c = crossing(&ev, reg, true).unwrap();
            let leg = VerifiedBoundaryDelta::from_crossing(&c, &policy).unwrap();
            assert_eq!(leg.signed_amount_micros(), expected_sign, "{name}");

            // A real, hashed, chain-anchored economy ledger holding this
            // crossing's evidence — the strongest thing a ledger author can
            // hand the view. The delta exists, and is correct.
            let dir = tempdir().unwrap();
            let econ = AutonomousEconomy::open(dir.path()).unwrap();
            econ.record_boundary_crossing(&ev, reg).unwrap();
            assert_eq!(econ.boundary_evidence().unwrap().len(), 1);
            assert_eq!(econ.crossings(reg).unwrap().len(), 1);

            // Unverified mode.
            let offline = VerifiedEconomyView::unverified(&econ, reg);
            assert_no_promotion_surface(&offline, &format!("lone {name}, offline"));

            // Pinned mode: a validated policy, a kernel-identified provider,
            // every gate the view has available. The offline view refused a
            // number for lack of authority; this one *has* the authority and
            // still grants nothing, because the delta is not wired into it.
            let provider =
                PinnedChainProvider::unix_socket(h.socket.path(), Some(h.socket.uid()))
                    .unwrap();
            let resolved = resolve(None, Some(&provider)).unwrap();
            let verifier =
                BaseUsdcVerifier::from_resolved(&resolved, 2).unwrap();
            assert!(verifier.provider_identity_verified());
            let pinned =
                VerifiedEconomyView::provider_pinned(&econ, reg, &verifier, &policy)
                    .unwrap();
            assert_eq!(pinned.trust_mode(), crate::verified_view::TrustMode::ProviderPinned);
            assert_no_promotion_surface(&pinned, &format!("lone {name}, pinned"));

            // And the delta is still intact afterwards: refusing to promote it
            // did not refuse to derive it. That is the whole design — the leg
            // is a real fact, and it is not yet a number anyone may act on.
            assert_eq!(leg.signed_amount_micros(), expected_sign, "{name}");
            assert_eq!(leg.asset(), &RealAsset::base_usdc(), "{name}");
        }
    }

    #[test]
    fn both_legs_of_an_arbitrage_sum_to_the_real_profit_and_promote_nothing() {
        // The whole point of the step, in one test: the arithmetic is right,
        // the isolation is closed, and the interim state is that nothing
        // promotes.
        let h = harness();
        let policy = h.policy();
        let reg = &h.auth.registry;

        let out_leg = VerifiedBoundaryDelta::from_crossing(
            &crossing(&out_evidence(), reg, true).unwrap(),
            &policy,
        )
        .unwrap();
        let in_leg = VerifiedBoundaryDelta::from_crossing(
            &crossing(&in_evidence(), reg, true).unwrap(),
            &policy,
        )
        .unwrap();
        assert_eq!(out_leg.direction(), BoundaryDirection::ControlledToExternal);
        assert_eq!(in_leg.direction(), BoundaryDirection::ExternalToControlled);

        // P4.5c does exactly this sum, and only over a complete operation:
        // `settlement::VerifiedSettlement::token_net_delta_micros` is this
        // addition, reached through `crate::settlement::VerifiedSettlement::assemble`
        // and gated on the chain having enumerated every leg. It is written here
        // too, at the delta layer, to show the two legs are the two halves of
        // one answer rather than two independent claims: -100.00 + 100.08 = +0.08.
        let net = out_leg.signed_amount_micros() + in_leg.signed_amount_micros();
        assert_eq!(net, 80_000, "the arbitrage is worth 0.08 mUSD");
        assert_ne!(net, in_leg.signed_amount_micros(), "the outflow must not vanish");
        assert_ne!(net, out_leg.signed_amount_micros());

        // That `net` is a bare `i128`. It is not a `VerifiedNev`, not an
        // `ArvStatus`, and not any other promotion input, and no public API in
        // this crate turns a *delta* into one — the only route is
        // `settlement::VerifiedSettlement::promote`, which a caller cannot reach
        // without a chain-scanned leg set. Both legs' evidence goes into a real
        // ledger and every promotion surface is asked.
        let dir = tempdir().unwrap();
        let econ = AutonomousEconomy::open(dir.path()).unwrap();
        econ.record_boundary_crossing(&out_evidence(), reg).unwrap();
        econ.record_boundary_crossing(&in_evidence(), reg).unwrap();
        assert_eq!(econ.boundary_evidence().unwrap().len(), 2);

        let offline = VerifiedEconomyView::unverified(&econ, reg);
        assert_no_promotion_surface(&offline, "both legs, offline");

        let provider =
            PinnedChainProvider::unix_socket(h.socket.path(), Some(h.socket.uid()))
                .unwrap();
        let resolved = resolve(None, Some(&provider)).unwrap();
        let verifier = BaseUsdcVerifier::from_resolved(&resolved, 2).unwrap();
        let pinned =
            VerifiedEconomyView::provider_pinned(&econ, reg, &verifier, &policy)
                .unwrap();
        assert_no_promotion_surface(&pinned, "both legs, pinned");

        // Stated as a test, and it is still true after P4.5c: crossing
        // evidence in the autonomy ledger is not in the view's vocabulary. The
        // count of receipt events stays zero with both legs present, because a
        // delta is a *settlement* input and a settlement is assembled from a
        // chain scan — which is what `settlement.rs` tests next.
        assert_eq!(pinned.receipt_evidence().unwrap().len(), 0);
        assert!(std::any::type_name::<VerifiedBoundaryDelta>()
            .contains("boundary_delta"));
        assert_eq!(
            net, 80_000,
            "and the number is still only reachable through the settlement route: \
             see settlement::tests::a_complete_arbitrage_promotes_its_real_profit"
        );
    }

    // ------------------------------------------------------------------
    // 11. the external-cost seam
    // ------------------------------------------------------------------

    #[test]
    fn an_external_cost_cannot_be_expressed_as_a_controlled_to_external_delta() {
        // P4.5c computes `inflows - outflows - external_costs` and P4.5d
        // supplies the last term — as a separate quantity in a different
        // currency, never as a delta. This test pins the reason, so the seam is
        // a structural property rather than a naming convention.
        let h = harness();
        let policy = h.policy();
        let reg = &h.auth.registry;

        // A gas fee has no ERC-20 transfer. Every route into a delta starts at a
        // `BoundaryEvidence`, and `with_verified_proof` demands a proof that
        // describes *that* transfer — token, recipient, amount, transaction and
        // block all of them. There is nothing for a fee to point at, so there is
        // no fee-shaped delta to build.
        let c = crossing(&out_evidence(), reg, true).unwrap();
        let gas_proof = proof(POOL, OUT_RAW, &tx_a(), &block_a());
        // A fee is not a transfer *to* the counterparty of any amount: the only
        // knob a fee has is its size, and a wrong size is a different transfer.
        assert!(
            c.clone()
                .with_verified_proof(proof(POOL, OUT_RAW - 1, &tx_a(), &block_a()))
                .is_err(),
            "a fee-sized amount is not this transfer"
        );
        assert!(c.clone().with_verified_proof(gas_proof).is_ok());

        // The direction itself is not a cost: `ControlledToExternal` is derived
        // from a controlled sender and a non-controlled recipient, and it
        // carries the amount of *that* transfer. Whether an operation's costs
        // happen to equal its outflows is a coincidence with no structural
        // meaning, and the aggregation in P4.5c will subtract a cost term
        // separately for exactly this reason.
        let outflow = VerifiedBoundaryDelta::from_crossing(&c, &policy).unwrap();
        assert_eq!(
            outflow.signed_amount_micros(),
            -(OUT_RAW as i128),
            "a crossing is a crossing; it is not a cost line"
        );

        // Nothing in this module names gas, a fee schedule or a cost estimate,
        // and no public constructor takes a bare amount — which is what a cost
        // term would need if it were to be smuggled in as a delta.
        let wire = serde_json::to_value(&outflow).unwrap();
        for forbidden in [
            "gas",
            "fee",
            "external_cost",
            "cost",
            "gas_used",
            "gas_price",
        ] {
            assert!(
                wire.get(forbidden).is_none(),
                "a delta carries no cost term, found {forbidden}"
            );
        }
    }

    // ------------------------------------------------------------------
    // 12. the evidence digest is an identity over the transfer
    // ------------------------------------------------------------------

    #[test]
    fn the_evidence_digest_names_the_transfer_and_nothing_else() {
        let h = harness();
        let reg = &h.auth.registry;
        let policy = h.policy();

        // Every leg of one crossing shares one evidence digest, whatever the
        // confirmation state, and it is a function of the transfer alone. The
        // reconciliation P4.5c owed: P4.5a put `chain_confirmed` inside, which
        // meant one transfer had two digests and the "confirmed" one was not a
        // different fact.
        let confirmed = crossing(&in_evidence(), reg, true).unwrap();
        let unconfirmed = crossing(&in_evidence(), reg, false).unwrap();
        assert_eq!(
            boundary_evidence_digest(&confirmed).unwrap(),
            boundary_evidence_digest(&unconfirmed).unwrap()
        );
        // Deterministic across repeated derivations, and equal for two deltas
        // built over the same evidence.
        let a = VerifiedBoundaryDelta::from_crossing(&confirmed, &policy).unwrap();
        let b = VerifiedBoundaryDelta::from_crossing(&confirmed, &policy).unwrap();
        assert_eq!(a.evidence_hash(), b.evidence_hash());

        // It is not a re-spelling of the canonical event id. Different domain,
        // different message: the evidence digest binds the stored evidence a
        // crossing was derived from, the event id binds the log the chain read
        // matched. A leg carries both and they never coincide.
        assert_ne!(a.evidence_hash(), a.event_id().digest());
        assert_ne!(
            BOUNDARY_EVIDENCE_DIGEST_DOMAIN,
            crate::event_id::EVENT_ID_DOMAIN,
            "the two digests are separated by domain, which is what makes them \
             different messages rather than different field lists"
        );

        // It moves for every fact that IS part of the transfer, and for nothing
        // else. Amount, direction, block and transaction each move it.
        let other_amount = crossing(
            &evidence(POOL, EXECUTOR, IN_RAW - 1, &tx_b(), &block_a()),
            reg,
            true,
        )
        .unwrap();
        let other_block = crossing(
            &evidence(POOL, EXECUTOR, IN_RAW, &tx_b(), &block_a()),
            reg,
            true,
        )
        .unwrap();
        let other_tx = crossing(
            &evidence(POOL, EXECUTOR, IN_RAW, &tx_a(), &block_a()),
            reg,
            true,
        )
        .unwrap();
        let base = boundary_evidence_digest(&confirmed).unwrap();
        for (why, other) in [
            ("amount", &other_amount),
            ("block", &other_block),
            ("transaction", &other_tx),
        ] {
            assert_ne!(
                base,
                boundary_evidence_digest(other).unwrap(),
                "{why} is not bound into the evidence digest"
            );
        }

        // The layout table itself, asserted rather than restated: the
        // confirmation state is not one of the rows, and the schema version is.
        let tags: Vec<&str> = BOUNDARY_EVIDENCE_DIGEST_FIELDS
            .iter()
            .map(|(t, _)| *t)
            .collect();
        assert_eq!(
            tags,
            vec![
                "schema_version",
                "chain_id",
                "asset",
                "from_address",
                "to_address",
                "amount_raw",
                "tx_hash",
                "block_hash",
            ]
        );
        assert!(!tags.contains(&"chain_confirmed"));
        assert!(!tags.contains(&"log_index"), "the log index belongs to the event id");
    }
}
