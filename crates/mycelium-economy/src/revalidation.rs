//! P6.10 — reorg detection and revalidation, and the state that blocks spend
//! authority when either cannot be established.
//!
//! # What was missing, stated as an exposure rather than a TODO
//!
//! [`crate::trusted_valuation::AppliedPrice::confirmations`] carries the honest
//! limit of what a chain view supported, and its own doc says the rest:
//!
//! > it is the honest limit of what the chain view supported, and nothing in
//! > this crate detects a reorg past it.
//!
//! [`crate::trusted_valuation`]'s module doc is blunter: *"No reorg detection.
//! Nothing in this crate watches for a reorg, so a chain that reorganises deeper
//! than `min_confirmations` invalidates an already-promoted value and this build
//! will never say so."*
//!
//! That exposure was about a **price**. It is at least as large for a
//! **settlement**: a settlement's legs are read from block logs, so a reorg that
//! removes the anchor block removes the evidence, and an economic result resting
//! on it stops being a fact about the world. Before this module, nothing in the
//! crate could say so.
//!
//! # What this module does, and what it deliberately does not fake
//!
//! It does three things:
//!
//! 1. **Revalidation on demand.** [`Revalidation::check`] takes the anchor an
//!    adjudication was taken at and asks the chain view what the canonical hash
//!    at that height is *now*. It is a caller-invoked check, not a watcher: this
//!    build has no background reorg subscription and does not pretend to.
//! 2. **A modelled finality bar.** Confirmation depth is the same arithmetic
//!    [`crate::base_usdc::BaseUsdcVerifier`] applies to a receipt —
//!    `head - anchor + 1` — compared against `policy.min_confirmations`, the
//!    same value, so one number governs prices and settlements alike.
//! 3. **A state that blocks.** [`RevalidationState::NeedsRevalidation`] exists
//!    precisely so "we did not check" is a first-class answer, and it blocks:
//!    [`EconomicResolution::standing`] yields
//!    [`AuthorityStanding::Blocked`] for it, and only
//!    [`RevalidationState::Confirmed`] combined with the one authority-bearing
//!    arm yields [`AuthorityStanding::Granted`].
//!
//! ## The one thing this module refuses to do
//!
//! **It does not fake finality.** There is no "assume 12 confirmations" fallback,
//! no cached-hash shortcut, and no path that treats a failed lookup as a pass. A
//! provider that cannot answer produces
//! [`RevalidationState::NeedsRevalidation`], and a reorg produces
//! [`RevalidationState::LeftCanonicalChain`]. Both block. The honest statement
//! is that a deep reorg *can* still defeat this, because confirmation depth is a
//! probability and not a proof — see the residual-exposure section at the bottom
//! of this file, which is not optional reading.
//!
//! # P6.N7.3 — the trusted revalidation authority
//!
//! ## The gap this closes, stated as an exposure rather than a TODO
//!
//! [`CanonicalChainView`] is a **`pub trait`**. Any caller can implement it, and
//! [`StaticChainView`] — caller-settable fields and all — was one such
//! implementation whose own doc comment admitted it "can only ever confirm what
//! the caller already asserted". [`RevalidationOutcome`] has private fields and
//! no `Deserialize`, and it was built specifically so that a durable ledger
//! record cannot carry a `confirmed` nobody checked. But its **only**
//! constructor took a `&dyn CanonicalChainView`, so the protection was one layer
//! out: a fabricated view still produced a fabricated [`RevalidationOutcome`],
//! and that outcome is what `nev_durable`'s append entry points accept.
//!
//! `Confirmed` has to mean **"a verified pinned provider said so"**, not "some
//! implementation of a trait said so". So:
//!
//! * [`TrustedCanonicalChainView`] is the only view
//!   [`RevalidationOutcome::check_trusted`] accepts. Its fields are private, it
//!   derives no `Deserialize`, it has no `From`/`Deref`/`TryFrom` out of
//!   anything, and its only production constructor takes an already-resolved
//!   [`ResolvedChainProvider`] and RE-VERIFIES it.
//! * [`RevalidationOutcome::check`], which still takes a `&dyn
//!   CanonicalChainView`, is no longer public. It is `pub(crate)`: in-crate and
//!   non-authority. The boundary is now the crate, not the trait.
//! * [`StaticChainView`] is `#[cfg(test)]`. It had no production caller anywhere
//!   in the crate, `tests/` or `src/bin/` (see its doc comment), so gating it
//!   costs nothing and removes it from every release build.
//!
//! ## What is still open, named rather than implied
//!
//! `pub(crate)` is a real boundary, not a proof. Any module inside this crate can
//! still call `RevalidationOutcome::check` with an arbitrary view and hand the
//! result to `nev_durable`'s `pub(crate)` append functions. Closing that means
//! making the append path itself take a token only `check_trusted` can mint, and
//! it is not attempted here. What *is* attempted here is that no **caller**
//! outside the crate can do it, and that inside the crate the pinned path is the
//! only documented way to reach `Confirmed`.

use crate::base_usdc::BaseUsdcVerifier;
use crate::chain_provider::{ProviderSource, ResolvedChainProvider};
use crate::discovery::OpportunityClass;
use crate::policy_auth::Hash;
use crate::resolution::EconomicResolution;
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
// `BTreeMap` reaches this file only through `StaticChainView`, which is a
// `#[cfg(test)]` test double. Ungated, the import is unused in every production
// build and the build warns.
#[cfg(test)]
use std::collections::BTreeMap;
use std::fmt;

/// The block a settlement's evidence was read at.
///
/// Constructible from values, deliberately: a revalidation check runs against a
/// *recorded* anchor, and refusing to name one would make the check
/// unreachable. The constructibility is not a trust grant — holding an anchor
/// asserts nothing, and [`Revalidation::check`] is what turns an assertion into
/// a [`RevalidationState`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementAnchor {
    pub block_number: u64,
    pub block_hash: Hash,
}

impl SettlementAnchor {
    pub fn new(block_number: u64, block_hash: Hash) -> Self {
        Self {
            block_number,
            block_hash,
        }
    }
}

impl fmt::Display for SettlementAnchor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "block {} ({})", self.block_number, self.block_hash)
    }
}

/// The chain's current head, as this build understands it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainHead {
    pub block_number: u64,
    pub block_hash: Hash,
}

/// The chain view a revalidation runs against.
///
/// A trait rather than a concrete reader for three reasons: the settlement path
/// has no production callers, so there is no live reader to wire to; the
/// allowlist in [`crate::base_usdc`] already constrains any future one; and a
/// trait makes the *discipline* testable without a network.
///
/// **An implementation must not cache a canonical hash and serve it later.** The
/// trait has one method per question and no "last known good", because a cached
/// answer is exactly the fake finality this module refuses. Implementations
/// return `Err` when they cannot answer, and `Err` is
/// [`RevalidationState::NeedsRevalidation`].
///
/// # This trait is not an authority (P6.N7.3)
///
/// It is `pub` because the *discipline* has to be testable without a network, and
/// that is the whole of what it grants. **Implementing it confers nothing.**
/// Because any caller can implement it, no production authority is reachable
/// through it: [`RevalidationOutcome::check_trusted`] takes a
/// [`TrustedCanonicalChainView`] instead, which cannot be produced by an impl of
/// this trait, and the [`RevalidationOutcome::check`] wrapper that does accept
/// `&dyn CanonicalChainView` is `pub(crate)` and is not an authority
/// constructor. See the P6.N7.3 section in the module doc.
pub trait CanonicalChainView {
    /// The current head.
    fn head(&self) -> Result<ChainHead>;

    /// The canonical block hash at `block_number`.
    ///
    /// `Ok(None)` means the provider no longer serves that height — pruned, or
    /// older than its retention. That is **not** a pass: it is
    /// [`RevalidationState::NeedsRevalidation`], because "I cannot tell" and "it
    /// is still there" are different answers and only one of them blocks.
    fn canonical_hash_at(&self, block_number: u64) -> Result<Option<Hash>>;
}

/// What a revalidation concluded.
///
/// Four states, and the split is the whole point: `Confirmed` is the only one
/// that grants a standing, and the two failure modes are kept apart because
/// they have opposite responses. `PendingFinality` is a "not yet" and resolves
/// on its own; `LeftCanonicalChain` is a "no" that no amount of waiting undoes;
/// `NeedsRevalidation` is an "unknown" that blocks precisely because it is
/// unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "revalidation", content = "detail", rename_all = "snake_case")]
pub enum RevalidationState {
    /// The anchor is still the canonical block at its height, and it is at or
    /// beyond the policy's confirmation bar. The only irrevocable state.
    Confirmed {
        anchor: SettlementAnchor,
        confirmations: u64,
        required_confirmations: u64,
    },
    /// The anchor is canonical but shallower than the bar. Not a failure: the
    /// same check a moment later may pass. Blocks in the meantime.
    PendingFinality {
        anchor: SettlementAnchor,
        confirmations: u64,
        required_confirmations: u64,
    },
    /// The block at that height is no longer the one the evidence came from.
    /// The evidence has left the canonical chain and spend authority is revoked
    /// with it — not deferred, revoked.
    LeftCanonicalChain {
        anchor: SettlementAnchor,
        canonical_block_hash: Hash,
        head_block_number: u64,
    },
    /// The revalidation could not be performed, or has not been. Deliberately a
    /// first-class state so that "we did not check" can never be represented as
    /// anything weaker.
    NeedsRevalidation {
        anchor: Option<SettlementAnchor>,
        why: String,
    },
}

impl RevalidationState {
    pub fn state(&self) -> &'static str {
        match self {
            Self::Confirmed { .. } => "confirmed",
            Self::PendingFinality { .. } => "pending_finality",
            Self::LeftCanonicalChain { .. } => "left_canonical_chain",
            Self::NeedsRevalidation { .. } => "needs_revalidation",
        }
    }

    /// Whether this state makes a historical NEV irrevocable *as far as this
    /// build can tell*.
    ///
    /// `true` for [`RevalidationState::Confirmed`] and nothing else. Note the
    /// wording: confirmation depth is a strong signal, not a proof of finality.
    /// See the residual-exposure section in the module doc.
    pub fn is_irrevocable(&self) -> bool {
        matches!(self, Self::Confirmed { .. })
    }

    /// Whether this state blocks. Everything that is not `Confirmed` blocks.
    pub fn blocks_spend_authority(&self) -> bool {
        !self.is_irrevocable()
    }

    /// The anchor this state was taken about, when it has one.
    pub fn anchor(&self) -> Option<&SettlementAnchor> {
        match self {
            Self::Confirmed { anchor, .. }
            | Self::PendingFinality { anchor, .. }
            | Self::LeftCanonicalChain { anchor, .. } => Some(anchor),
            Self::NeedsRevalidation { anchor, .. } => anchor.as_ref(),
        }
    }

    /// Confirmation depth, when it was computable.
    pub fn confirmations(&self) -> Option<u64> {
        match self {
            Self::Confirmed { confirmations, .. }
            | Self::PendingFinality { confirmations, .. } => Some(*confirmations),
            _ => None,
        }
    }

    /// Whether the evidence is known to have left the canonical chain. This is a
    /// *revocation*, not a deferral, and a caller that has already spent against
    /// a revoked value has an incident, not a retry.
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::LeftCanonicalChain { .. })
    }
}

impl fmt::Display for RevalidationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Confirmed {
                anchor,
                confirmations,
                required_confirmations,
            } => write!(
                f,
                "{anchor} is still canonical at {confirmations} confirmation(s), at or beyond \
                 the required {required_confirmations}"
            ),
            Self::PendingFinality {
                anchor,
                confirmations,
                required_confirmations,
            } => write!(
                f,
                "{anchor} is still canonical but only {confirmations} deep against a required \
                 {required_confirmations}; this resolves by waiting, and blocks until it does"
            ),
            Self::LeftCanonicalChain {
                anchor,
                canonical_block_hash,
                head_block_number,
            } => write!(
                f,
                "{} no longer names the canonical block at its height, which is now {canonical_block_hash} \
                 at head {head_block_number}; the evidence has left the canonical chain and any \
                 spend authority resting on it is revoked",
                anchor.block_number
            ),
            Self::NeedsRevalidation { anchor, why } => match anchor {
                Some(a) => write!(f, "{a} has not been revalidated: {why}"),
                None => write!(f, "no anchor to revalidate: {why}"),
            },
        }
    }
}

/// The chain-view limit a revalidation is measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevalidationPolicy {
    /// The same bar [`crate::base_usdc::BaseUsdcVerifier`] applies to a receipt
    /// and [`crate::trusted_valuation::ValidatedPriceSource::finality_of`]
    /// applies to a price. One number, three uses, deliberately.
    pub required_confirmations: u64,
}

impl RevalidationPolicy {
    /// Refuses zero, the same way `min_confirmations` is refused in
    /// [`crate::policy_auth::validate_outcome_policy`]: a bar of zero would make
    /// every anchor final the instant it is seen.
    pub fn new(required_confirmations: u64) -> Result<Self> {
        if required_confirmations < 1 {
            return Err(crate::EconomyError::Invalid(format!(
                "revalidation policy requires at least one confirmation; {required_confirmations} \
                 would make every anchor final the instant it is seen"
            )));
        }
        Ok(Self {
            required_confirmations,
        })
    }

    /// From a validated outcome policy, so the number cannot be set twice. The
    /// single source in production; the constructor exists so a test can pin a
    /// specific depth.
    pub fn from_policy(policy: &crate::policy_auth::ValidatedOutcomePolicy) -> Self {
        Self {
            required_confirmations: policy.min_confirmations(),
        }
    }

    pub fn required_confirmations(&self) -> u64 {
        self.required_confirmations
    }

    /// The depth verdict, derived rather than claimed.
    ///
    /// A pure depth comparison cannot decide whether an anchor is still
    /// canonical — that needs a chain read — so it returns this two-armed
    /// verdict and [`Revalidation::check`] combines it with the canonical-hash
    /// result. The shape matches
    /// [`crate::trusted_valuation::ValidatedPriceSource::finality_of`] so the
    /// two cannot drift into disagreeing about the same depth.
    pub fn finality_of(&self, confirmations: u64) -> DepthFinality {
        if confirmations >= self.required_confirmations {
            DepthFinality::DeepEnough
        } else {
            DepthFinality::TooShallow
        }
    }
}

/// Whether a depth clears the bar. Two states, and the shallow one is a "not
/// yet" rather than a failure — it resolves by waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepthFinality {
    DeepEnough,
    TooShallow,
}

impl fmt::Display for DepthFinality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DeepEnough => "deep_enough",
            Self::TooShallow => "too_shallow",
        })
    }
}

/// The revalidation check.
///
/// Order matters and is fixed, in the direction that refuses:
///
/// 1. **No anchor** → [`RevalidationState::NeedsRevalidation`]. There is nothing
///    to check, and an absent anchor must not read as an absent problem.
/// 2. **The head** is read first. A provider that cannot name its head cannot
///    answer anything, and a head that is *below* the anchor means the view is
///    behind the evidence, not that the evidence is fine.
/// 3. **The canonical hash at the anchor's height.** This is the reorg check.
///    A mismatch is [`RevalidationState::LeftCanonicalChain`] — a revocation, and
///    it short-circuits before the depth arithmetic, because an anchor that is no
///    longer canonical has no meaningful confirmation count.
/// 4. **Depth.** `head - anchor + 1`, the same expression
///    [`crate::base_usdc`] uses, compared against
///    [`RevalidationPolicy::required_confirmations`].
///
/// # This is not an authority constructor (P6.N7.3)
///
/// It returns a [`RevalidationState`], which is a public enum with public
/// variant fields and can be written by hand — so it grants nothing and is
/// deliberately left `pub`, because the discipline it implements has to be
/// testable. Authority lives one layer up, in
/// [`RevalidationOutcome::check_trusted`], which accepts only a
/// [`TrustedCanonicalChainView`].
pub struct Revalidation;

impl Revalidation {
    pub fn check(
        anchor: Option<&SettlementAnchor>,
        chain: &dyn CanonicalChainView,
        policy: &RevalidationPolicy,
    ) -> RevalidationState {
        let Some(anchor) = anchor else {
            return RevalidationState::NeedsRevalidation {
                anchor: None,
                why: "the adjudication carries no block anchor, so there is nothing to \
                      revalidate and nothing to confirm"
                    .to_string(),
            };
        };

        let head = match chain.head() {
            Ok(h) => h,
            Err(e) => {
                return RevalidationState::NeedsRevalidation {
                    anchor: Some(anchor.clone()),
                    why: format!("the chain view cannot name its head: {e}"),
                }
            }
        };

        if head.block_number < anchor.block_number {
            return RevalidationState::NeedsRevalidation {
                anchor: Some(anchor.clone()),
                why: format!(
                    "the chain view is at block {} but the evidence was read at block {}; a view \
                     behind the evidence cannot confirm it",
                    head.block_number, anchor.block_number
                ),
            };
        }

        let canonical = match chain.canonical_hash_at(anchor.block_number) {
            Ok(Some(h)) => h,
            Ok(None) => {
                return RevalidationState::NeedsRevalidation {
                    anchor: Some(anchor.clone()),
                    why: format!(
                        "the provider no longer serves block {}, so whether the evidence is still \
                         canonical is unknown; an unknown is not a pass",
                        anchor.block_number
                    ),
                }
            }
            Err(e) => {
                return RevalidationState::NeedsRevalidation {
                    anchor: Some(anchor.clone()),
                    why: format!(
                        "the chain view cannot report the canonical hash at block {}: {e}",
                        anchor.block_number
                    ),
                }
            }
        };

        if canonical != anchor.block_hash {
            return RevalidationState::LeftCanonicalChain {
                anchor: anchor.clone(),
                canonical_block_hash: canonical,
                head_block_number: head.block_number,
            };
        }

        let confirmations = head
            .block_number
            .saturating_sub(anchor.block_number)
            .saturating_add(1);
        match policy.finality_of(confirmations) {
            DepthFinality::TooShallow => RevalidationState::PendingFinality {
                anchor: anchor.clone(),
                confirmations,
                required_confirmations: policy.required_confirmations,
            },
            DepthFinality::DeepEnough => RevalidationState::Confirmed {
                anchor: anchor.clone(),
                confirmations,
                required_confirmations: policy.required_confirmations,
            },
        }
    }
}

/// Non-fabricable result of a real revalidation check.
///
/// # Why this wrapper exists
///
/// [`RevalidationState`] is a public enum whose variants carry public fields, so
/// `RevalidationState::Confirmed { .. }` can be written by hand with arbitrary
/// values. Storing that type as durable NEV authority would therefore let a caller
/// assert "confirmed" — which is precisely the property the NEV ledger must not
/// take on trust. A hash chain proves a record was not edited; it proves nothing
/// about whether the record was ever entitled to exist.
///
/// This type closes that. Its fields are private, it does not derive
/// `Deserialize`, and it has exactly two constructors:
///
/// | constructor | visibility | what it may say |
/// |---|---|---|
/// | [`RevalidationOutcome::check_trusted`] | `pub` — **the production authority path** | anything, but only against a [`TrustedCanonicalChainView`] |
/// | [`RevalidationOutcome::check`] | `pub(crate)` — in-crate, non-authority | anything, against any `&dyn CanonicalChainView` |
///
/// plus [`RevalidationOutcome::for_test`], which is `#[cfg(test)] pub(crate)` and
/// is compiled out of production builds entirely.
///
/// # Why `check` is no longer `pub` (P6.N7.3)
///
/// It used to be, and that was the whole gap: [`CanonicalChainView`] is a public
/// trait, so an arbitrary caller implementation could reach `check` and produce
/// `RevalidationOutcome::Confirmed`, which `nev_durable` then appends. Authority
/// now requires a [`TrustedCanonicalChainView`], which no arbitrary impl can
/// become. What remains is stated rather than implied: `pub(crate)` means a
/// module *inside this crate* can still do it, and closing that would mean making
/// the durable append path take a token only `check_trusted` can mint. See the
/// P6.N7.3 section in the module doc.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevalidationOutcome {
    state: RevalidationState,
}

impl RevalidationOutcome {
    /// The PRODUCTION authority path. Runs the real check against a
    /// [`TrustedCanonicalChainView`].
    ///
    /// This is the only public way to obtain an outcome, and the parameter type
    /// is the trust boundary: `TrustedCanonicalChainView` has private fields, no
    /// `Deserialize`, and no public constructor other than
    /// [`TrustedCanonicalChainView::from_resolved`], which re-verifies a pinned,
    /// kernel-identified provider and refuses a dev override, an unpinned
    /// endpoint, or the wrong chain id. A `Confirmed` reached through this
    /// function therefore means *a verified pinned provider said so*, and an
    /// untrusted view cannot produce a `Confirmed` here at all — it cannot be
    /// built, so it never reaches the depth arithmetic.
    pub fn check_trusted(
        anchor: Option<&SettlementAnchor>,
        view: &TrustedCanonicalChainView,
        policy: &RevalidationPolicy,
    ) -> Self {
        Self {
            state: Revalidation::check(anchor, view, policy),
        }
    }

    /// In-crate, **non-authority** constructor against any
    /// `&dyn CanonicalChainView`.
    ///
    /// It exists for the tests in this module and for non-authority internal use
    /// (there is none today, which is why the `dead_code` allowance below is
    /// `cfg(not(test))` rather than unconditional — a symbol that exists for a
    /// caller who has not arrived yet should say so rather than warn). It is
    /// deliberately **not** public: a public `&dyn CanonicalChainView` parameter
    /// is an arbitrary caller implementation away from a fabricated `Confirmed`,
    /// which is exactly the exposure [`RevalidationOutcome::check_trusted`] and
    /// [`TrustedCanonicalChainView`] exist to close. Production code must use
    /// [`RevalidationOutcome::check_trusted`].
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn check(
        anchor: Option<&SettlementAnchor>,
        chain: &dyn CanonicalChainView,
        policy: &RevalidationPolicy,
    ) -> Self {
        Self {
            state: Revalidation::check(anchor, chain, policy),
        }
    }

    pub fn state(&self) -> &RevalidationState {
        &self.state
    }

    /// The stable spelling, as written to the durable ledger.
    pub fn state_name(&self) -> &'static str {
        self.state.state()
    }

    /// Whether this outcome grants current NEV authority.
    pub fn is_confirmed(&self) -> bool {
        self.state.is_irrevocable()
    }

    /// Whether this outcome blocks current authority.
    pub fn blocks_authority(&self) -> bool {
        self.state.blocks_spend_authority()
    }

    /// The anchor this outcome was taken about, when it has one.
    pub fn anchor(&self) -> Option<&SettlementAnchor> {
        self.state.anchor()
    }

    pub fn confirmations(&self) -> Option<u64> {
        self.state.confirmations()
    }

    /// Test-only constructor, compiled out of production builds.
    ///
    /// It exists so in-crate tests can exercise ledger transitions without a live
    /// chain, and it is deliberately `#[cfg(test)]` rather than public: a public
    /// version would reopen exactly the hole this type closes. Ledger tests that
    /// must prove a *real* check produces `Confirmed` exercise
    /// [`RevalidationOutcome::check_trusted`] against a real pinned
    /// [`TrustedCanonicalChainView`] instead.
    #[cfg(test)]
    pub(crate) fn for_test(state: RevalidationState) -> Self {
        Self { state }
    }
}

// ---------------------------------------------------------------------------
// The trusted revalidation authority — P6.N7.3
// ---------------------------------------------------------------------------

/// The only chain view [`RevalidationOutcome::check_trusted`] will accept.
///
/// # What "trusted" means here
///
/// A revalidation is worth nothing unless the answer came from a source of truth
/// whose *identity* the kernel enforces, not merely one whose address a caller
/// supplied. This type is the place that requirement is enforced, once, at
/// construction — so `Confirmed` can mean **"a verified pinned provider said so"**
/// instead of **"some implementation of a trait said so"**.
///
/// # Why an arbitrary [`CanonicalChainView`] implementation cannot produce it
///
/// Four independent properties, and a caller cannot satisfy any of them by writing
/// an `impl`:
///
/// 1. **The fields are private and it derives no `Deserialize`.** A JSON document
///    cannot become one, and a caller cannot assemble one field by field. The
///    `From`/`TryFrom`/`Deref` surface between this type and
///    [`StaticChainView`] is deliberately empty.
/// 2. **It takes [`ResolvedChainProvider`], not an endpoint.** That type is
///    produced by [`crate::chain_provider::resolve`], whose only outcomes are a
///    validated policy pin, an explicit dev override, or a refusal — there is no
///    default endpoint to degrade to. A bare `&str` endpoint cannot even be
///    passed, so `BaseUsdcVerifier::new`'s legacy loopback path cannot reach it.
/// 3. **Every claim the value makes is RE-VERIFIED, none of it inferred from the
///    value's own label.** [`ResolvedChainProvider`] and
///    [`crate::chain_provider::PinnedChainProvider`] both have `pub` fields, so a
///    caller really can hand-assemble `source: PolicyPin` over a loopback HTTP
///    endpoint. [`Self::from_resolved`] therefore re-runs resolution, re-runs the
///    pin's own policy validation, and re-runs the kernel socket-identity check —
///    see the numbered checks on that constructor.
/// 4. **The reads go out through the crate's own pinned transport.**
///    [`BaseUsdcVerifier::rpc_call`] re-checks the socket's inode ownership and
///    permission bits on *every* call, refuses an unpinned endpoint outright, and
///    answers only from its read-only method allowlist. A caller cannot supply the
///    head or the canonical hash; only a socket the kernel agrees is owned by
///    somebody the pin named can.
///
/// # Trust modes — which of them may confirm
///
/// The distinction is [`ProviderSource`]'s, reused rather than re-invented:
///
/// | how the provider resolved | [`Self::trust_level`] | may reach `Confirmed` |
/// |---|---|---|
/// | [`ProviderSource::PolicyPin`] — written out-of-band into the payment policy file, kernel-enforced unix socket | `PolicyPin` | **yes** |
/// | [`ProviderSource::DevEnvOverride`] — [`crate::chain_provider::DEV_PROVIDER_ENV`], explicit opt-in for development and tests | *refused at construction* | no |
/// | no resolution at all | *refused at construction* | no |
///
/// There is no third state and no "warn but continue": an untrusted provider
/// cannot be wrapped, so it cannot produce a weakened verdict either. A dev
/// override that happens to name a unix socket — which *would* pass the
/// kernel-identity check — is still refused, because the SOURCE is development
/// and the source is what this table is keyed on.
///
/// # How the two of them are related
///
/// This type delegates [`CanonicalChainView`] to the provider read and adds
/// nothing to the arithmetic: [`Revalidation::check`] still decides, unchanged.
/// The trust is in the *answer's provenance*, not in a different answer.
#[derive(Debug, Clone)]
pub struct TrustedCanonicalChainView {
    inner: Inner,
    /// How the provider was resolved. Read-only, and necessarily
    /// [`ProviderSource::PolicyPin`] for anything a production build can hold.
    source: ProviderSource,
    /// The pinned endpoint, kept for the audit description.
    provider: String,
    /// The chain id this view was pinned to, re-checked on every read.
    chain_id: u64,
}

/// Where the answers come from. In a production build there is exactly one
/// variant, which is the point: there is no way to be here without a provider.
#[derive(Debug, Clone)]
enum Inner {
    /// A real pinned [`BaseUsdcVerifier`]. The only production variant.
    Provider(BaseUsdcVerifier),
    /// Test-only reader, compiled out of every production build and reachable
    /// only from [`TrustedCanonicalChainView::for_test`].
    #[cfg(test)]
    Static(StaticChainView),
}

impl TrustedCanonicalChainView {
    /// The only production constructor, and it re-verifies everything it is
    /// handed rather than trusting the type it is handed.
    ///
    /// The checks, in the order they run, each with its own refusal:
    ///
    /// 1. **(b) production source.** `resolved.source` must be
    ///    [`ProviderSource::PolicyPin`]. This runs first because a dev override
    ///    fails it *and* the re-derivation in step 2, and the dev message is the
    ///    one an operator can act on.
    /// 2. **(a) re-derivation through the real resolver.** The pin is fed back
    ///    through [`crate::chain_provider::resolve`] with no dev override and the
    ///    result must be *identical* to what was passed in. This is the
    ///    provenance check made mechanical: a `ResolvedChainProvider` that
    ///    `resolve` would not itself produce cannot become production authority,
    ///    no matter which label its `source` field carries.
    /// 3. **(e) the crate's own pinning path, reused verbatim.**
    ///    [`BaseUsdcVerifier::from_resolved`] re-runs `validate_shape`, runs
    ///    `validate_policy_pin`, and runs `verify_socket_identity` (symlink
    ///    refusal, `is_socket`, group/other-writable refusal, and owner-uid
    ///    match) before a single byte is written. Those checks are **not
    ///    reimplemented here** — this constructor calls the same function
    ///    production payment verification calls, and the socket identity is
    ///    re-checked again on every RPC by `rpc_call`.
    /// 4. **(c) provider identity enforced.**
    ///    [`BaseUsdcVerifier::provider_identity_verified`] must be `true`. This is
    ///    the belt to step 3's braces: it asks the built verifier rather than the
    ///    resolved value, so a verifier constructed by any other route cannot slip
    ///    in.
    /// 5. **(d) chain id.** The provider is asked for its chain id — over the
    ///    pinned transport — and it must equal `expected_chain_id`.
    pub fn from_resolved(
        resolved: &ResolvedChainProvider,
        expected_chain_id: u64,
        min_confirmations: u64,
    ) -> Result<Self> {
        // (b) PRODUCTION SOURCE. `resolve` labels a value `PolicyPin` only when
        // it came from the payment policy file written out-of-band at
        // `create_new` time. `DevEnvOverride` is the only other label it can
        // produce and it is, by its own documentation, development/test only.
        if resolved.source != ProviderSource::PolicyPin {
            return Err(crate::EconomyError::ProviderUnpinned(format!(
                "a production revalidation authority requires a provider resolved from the \
                 payment policy pin, but this one resolved from {:?} at {} — {}. That source \
                 authenticates nothing, so it is refused here instead of being allowed to \
                 produce a weakened verdict. There is no untrusted mode: a view that exists \
                 is a view whose reads a kernel-enforced socket answers",
                resolved.source,
                resolved.provider.endpoint(),
                crate::chain_provider::DEV_PROVIDER_ENV,
            )));
        }

        // (a) RE-DERIVATION. The parameter's type narrows provenance, but both it
        // and the pin it carries have `pub` fields, so the value in hand could be
        // hand-assembled. Re-resolving its pin through the crate's own resolver
        // and demanding an identical answer is what turns "it claims to be
        // pinned" into "the resolver agrees it is".
        let rederived = crate::chain_provider::resolve(None, Some(resolved.as_pinned()))?;
        if rederived != *resolved {
            return Err(crate::EconomyError::Invalid(format!(
                "this provider is not one `chain_provider::resolve` would produce: the value says \
                 {:?} at {} with socket owner {:?}, re-resolving its pin says {:?} at {} with \
                 socket owner {:?}",
                resolved.source,
                resolved.provider.endpoint(),
                resolved.provider.socket_owner_uid,
                rederived.source,
                rederived.provider.endpoint(),
                rederived.provider.socket_owner_uid,
            )));
        }

        // (e) THE PINNING PATH, REUSED. `from_resolved` is the single trust
        // boundary in `base_usdc`; calling it is what keeps the socket-identity,
        // ownership and mode checks identical to the ones a payment verification
        // performs, instead of a second and possibly weaker copy.
        let verifier = BaseUsdcVerifier::from_resolved(resolved, min_confirmations)?;

        // (c) PROVIDER IDENTITY ENFORCED. Asked of the verifier that will do the
        // reading, not of the value that was passed in.
        if !verifier.provider_identity_verified() {
            return Err(crate::EconomyError::ProviderUnpinned(format!(
                "provider {} has no kernel-enforced identity, so it cannot back a trusted \
                 revalidation view. A loopback TCP port is an address, not an identity: \
                 pin a unix socket owned by uid {} instead",
                verifier.endpoint(),
                crate::chain_provider::DEFAULT_PROVIDER_SOCKET_UID,
            )));
        }

        // (d) CHAIN ID. Read over the pinned transport, not taken on the label.
        let chain_id = read_chain_id(&verifier)?;
        if chain_id != expected_chain_id {
            return Err(crate::EconomyError::Invalid(format!(
                "wrong chain id: the pinned provider at {} reports {chain_id}, and this view \
                 was asked for chain {expected_chain_id}. A view pinned to one chain cannot \
                 revalidate evidence read on another, so the mismatch is refused rather than \
                 treated as a reorg or as a pass",
                verifier.endpoint(),
            )));
        }

        Ok(Self {
            inner: Inner::Provider(verifier),
            source: resolved.source,
            provider: resolved.provider.endpoint().to_string(),
            chain_id,
        })
    }

    /// The trust level this view was built with: a read-only copy of the
    /// [`ProviderSource`] the constructor verified.
    ///
    /// It is [`ProviderSource::PolicyPin`] for every view that exists in a
    /// production build. The accessor exists so an audit log can *print* the level
    /// rather than have it assumed by the reader — not because there is a choice
    /// left to make.
    pub fn trust_level(&self) -> ProviderSource {
        self.source
    }

    /// The chain id this view is pinned to. Re-checked against the provider on
    /// every read; see [`Self::assert_chain_id`].
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The pinned endpoint, for logs that need the address itself.
    pub fn endpoint(&self) -> &str {
        &self.provider
    }

    /// One line for an audit log: who answered, under what trust, on which chain.
    ///
    /// Reports the trust level rather than asserting it, so a record written
    /// after the fact carries the same evidence the constructor required.
    pub fn provider_description(&self) -> String {
        format!(
            "pinned Base provider at {} (source: {:?}, kernel-enforced socket identity, chain id {})",
            self.provider, self.source, self.chain_id,
        )
    }

    /// Re-reads the chain id on every read, for exactly the reason
    /// [`BaseUsdcVerifier::rpc_call`] re-checks socket identity on every call: the
    /// endpoint answered when the view was built, and it has to answer now. A view
    /// pinned to one chain refuses to answer for another rather than returning a
    /// `NeedsRevalidation` that reads like a provider outage.
    fn assert_chain_id(&self, verifier: &BaseUsdcVerifier) -> Result<()> {
        let observed = read_chain_id(verifier)?;
        if observed != self.chain_id {
            return Err(crate::EconomyError::Invalid(format!(
                "chain id changed under a trusted revalidation view: the view is pinned to {}, \
                 and the pinned provider at {} now reports {observed}",
                self.chain_id,
                verifier.endpoint(),
            )));
        }
        Ok(())
    }

    /// **TEST-ONLY SEAM.** `#[cfg(test)] pub(crate)`, so it is compiled out of
    /// every production build and is unreachable from an integration test — the
    /// same discipline as [`RevalidationOutcome::for_test`].
    ///
    /// It builds the view over a caller-supplied [`StaticChainView`] instead of a
    /// [`BaseUsdcVerifier`], which means it **bypasses checks (a)–(e) entirely**
    /// and takes the trust level and chain id on trust. That is the trade: it lets
    /// a unit test exercise the delegation from [`CanonicalChainView`] to the
    /// inner reader without standing up a socket.
    ///
    /// It is deliberately **not** how the can-confirm tests build their view.
    /// Those resolve a real [`crate::chain_provider::resolve`] pin against a
    /// [`crate::rpc_test_server::FakeRpcSocket`], so the pinning checks are
    /// themselves under test rather than assumed by this seam.
    #[cfg(test)]
    pub(crate) fn for_test(view: StaticChainView, provider: &str, chain_id: u64) -> Self {
        Self {
            inner: Inner::Static(view),
            source: ProviderSource::PolicyPin,
            provider: provider.to_string(),
            chain_id,
        }
    }
}

impl CanonicalChainView for TrustedCanonicalChainView {
    /// Delegates to the pinned provider: `eth_blockNumber` then
    /// `eth_getBlockByNumber` for the head block's hash, with the chain id
    /// re-read on the way. `Err` propagates, and `Err` is
    /// [`RevalidationState::NeedsRevalidation`].
    fn head(&self) -> Result<ChainHead> {
        match &self.inner {
            Inner::Provider(verifier) => {
                self.assert_chain_id(verifier)?;
                let block_number = hex_to_u64(
                    &verifier.rpc_call("eth_blockNumber", json!([]))?,
                    "eth_blockNumber",
                )?;
                let block = verifier.rpc_call(
                    "eth_getBlockByNumber",
                    json!([format!("0x{block_number:x}"), false]),
                )?;
                Ok(ChainHead {
                    block_number,
                    block_hash: block_hash_of(&block, "head block")?,
                })
            }
            #[cfg(test)]
            Inner::Static(view) => view.head(),
        }
    }

    /// Delegates to the pinned provider: `eth_getBlockByNumber` at that height.
    ///
    /// A `null` result — pruned, or older than the provider's retention — is
    /// `Ok(None)`, which [`Revalidation::check`] treats as
    /// [`RevalidationState::NeedsRevalidation`]. "I cannot tell" is not a pass.
    fn canonical_hash_at(&self, block_number: u64) -> Result<Option<Hash>> {
        match &self.inner {
            Inner::Provider(verifier) => {
                self.assert_chain_id(verifier)?;
                let block = verifier.rpc_call(
                    "eth_getBlockByNumber",
                    json!([format!("0x{block_number:x}"), false]),
                )?;
                match block {
                    Value::Null => Ok(None),
                    block => Ok(Some(block_hash_of(&block, "canonical block")?)),
                }
            }
            #[cfg(test)]
            Inner::Static(view) => view.canonical_hash_at(block_number),
        }
    }
}

/// `eth_chainId` over the pinned transport.
///
/// `base_usdc::hex_u64` is private to that module, so the parse is repeated here
/// rather than reimplemented elsewhere. It is a parse of a value the crate's own
/// verified transport produced — not a second transport and not a second pinning
/// stack.
fn read_chain_id(verifier: &BaseUsdcVerifier) -> Result<u64> {
    hex_to_u64(&verifier.rpc_call("eth_chainId", json!([]))?, "eth_chainId")
}

fn hex_to_u64(value: &Value, what: &str) -> Result<u64> {
    let s = value
        .as_str()
        .ok_or_else(|| crate::EconomyError::Invalid(format!("{what} was not a hex string")))?;
    let body = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(if body.is_empty() { "0" } else { body }, 16).map_err(|_| {
        crate::EconomyError::Invalid(format!("{what} is not a hex u64: {s}"))
    })
}

/// The block hash out of an `eth_getBlockByNumber` result.
///
/// Validated through [`crate::base_usdc::validate_hash32`] — the crate's single
/// 32-byte-hex rule — and normalised through [`Hash::parse`], so two spellings of
/// one digest cannot become two different anchors and a malformed provider
/// response is an `Err` rather than a silent `None`.
fn block_hash_of(block: &Value, what: &'static str) -> Result<Hash> {
    let raw = block
        .get("hash")
        .and_then(Value::as_str)
        .ok_or_else(|| crate::EconomyError::Invalid(format!("{what} is missing its hash")))?;
    crate::base_usdc::validate_hash32(what, raw)?;
    Hash::parse(what, raw).map_err(|e| crate::EconomyError::Invalid(e.to_string()))
}

/// Whether a revalidation happened, and against what.
///
/// A report, not a grant: the standing is derived by
/// [`EconomicResolution::standing`], which is the only place the two are
/// combined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevalidationVerdict {
    pub checked_at_unix: u64,
    /// The endpoint the canonical hash came from. Reported so a reader can tell
    /// which view decided, not so it can be trusted on its own.
    pub provider: String,
    pub state: RevalidationState,
}

impl RevalidationVerdict {
    /// A verdict that never ran. This is the value a caller gets when it has no
    /// chain view at all, and it is deliberately *not* representable as
    /// `Confirmed`.
    pub fn not_checked(provider: impl Into<String>, why: impl Into<String>) -> Self {
        Self {
            checked_at_unix: 0,
            provider: provider.into(),
            state: RevalidationState::NeedsRevalidation {
                anchor: None,
                why: why.into(),
            },
        }
    }

    pub fn state(&self) -> &RevalidationState {
        &self.state
    }

    pub fn is_irrevocable(&self) -> bool {
        self.state.is_irrevocable()
    }

    pub fn is_revoked(&self) -> bool {
        self.state.is_revoked()
    }

    pub fn describe(&self) -> String {
        format!(
            "revalidation against {} at {}: {}",
            self.provider, self.checked_at_unix, self.state
        )
    }
}

// ---------------------------------------------------------------------------
// Spend authority
// ---------------------------------------------------------------------------

/// Why spend authority is withheld.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "blocked", content = "detail", rename_all = "snake_case")]
pub enum BlockingReason {
    /// The resolution is not the one authority-bearing arm. Named, never counted.
    NotAnAuthority { state: String, why: String },
    /// The revalidation has not established the evidence as canonical. The
    /// state that P6.10 exists for.
    NeedsRevalidation { why: String },
    /// The evidence left the canonical chain. A revocation, not a deferral.
    EvidenceLeftCanonicalChain { why: String },
    /// The evidence is canonical but shallower than the policy's bar.
    PendingFinality { why: String },
}

impl fmt::Display for BlockingReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnAuthority { state, why } => {
                write!(f, "{state} carries no authority: {why}")
            }
            Self::NeedsRevalidation { why } => {
                write!(f, "spend authority withheld: the evidence has not been revalidated: {why}")
            }
            Self::EvidenceLeftCanonicalChain { why } => {
                write!(f, "spend authority REVOKED: {why}")
            }
            Self::PendingFinality { why } => {
                write!(f, "spend authority withheld: {why}")
            }
        }
    }
}

/// The only thing a resolution plus a chain view can say about spend authority.
///
/// Two variants, and the derivation is a `match` in one place
/// ([`EconomicResolution::standing`]) so the two conditions cannot be satisfied
/// independently by accident.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "standing", content = "detail", rename_all = "snake_case")]
pub enum AuthorityStanding {
    /// The authority-bearing arm, revalidated as canonical at or beyond the
    /// policy's depth. A **precondition**, not a budget: this is not wired to
    /// [`crate::reinvestment::ReinvestmentController::commit_job_from_view`],
    /// which still takes a [`crate::verified_view::VerifiedEconomyView`] and
    /// nothing from this module.
    Granted {
        class: OpportunityClass,
        nev_musd_micros: i64,
        state: RevalidationState,
    },
    /// Withheld, and the reason is named.
    Blocked(BlockingReason),
}

impl AuthorityStanding {
    /// Whether this standing puts the candidate into force.
    pub fn is_granted(&self) -> bool {
        matches!(self, Self::Granted { .. })
    }

    /// The refusal, when withheld. There is deliberately **no** counterpart that
    /// returns the value: `AuthorityStanding` has no `PositiveNev` field and no
    /// `VerifiedNev` field, so a standing is a report and there is nothing here
    /// a caller could hand to
    /// [`crate::reinvestment::ReinvestmentController::commit_job_from_view`]
    /// even by mistake.
    pub fn blocking_reason(&self) -> Option<&BlockingReason> {
        match self {
            Self::Blocked(r) => Some(r),
            Self::Granted { .. } => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Granted {
                class,
                nev_musd_micros,
                state,
            } => format!(
                "{class} holds {nev_musd_micros} mUSD of NEV-0 verified net external value with \
                 a revalidation that does not block ({state}); this is a precondition for a \
                 budget, not a budget, and no path in this crate turns it into one"
            ),
            Self::Blocked(r) => r.to_string(),
        }
    }
}

impl EconomicResolution {
    /// The single place a resolution and a chain view are combined.
    ///
    /// Two conditions, both necessary, checked in the order that refuses:
    ///
    /// 1. the arm is [`EconomicResolution::PositiveNev`]. The other eight are
    ///    reported as [`BlockingReason::NotAnAuthority`] without the revalidation
    ///    being consulted at all — there is nothing a chain read could add to a
    ///    measurement that found no edge.
    /// 2. the [`RevalidationState`] is [`RevalidationState::Confirmed`]. The
    ///    three blocking states each produce their own
    ///    [`BlockingReason`], so an operator is told whether the evidence needs
    ///    re-checking, is too shallow, or has been reorged out.
    pub fn standing(&self, revalidation: &RevalidationState) -> AuthorityStanding {
        let Self::PositiveNev(v) = self else {
            return AuthorityStanding::Blocked(BlockingReason::NotAnAuthority {
                state: self.state().to_string(),
                why: format!(
                    "only the positive_nev arm carries a verified net external value; this is \
                     {}, and a revalidation cannot create one",
                    self.state()
                ),
            });
        };
        match revalidation {
            RevalidationState::Confirmed { .. } => AuthorityStanding::Granted {
                class: v.class(),
                nev_musd_micros: v.nev_musd_micros(),
                state: revalidation.clone(),
            },
            RevalidationState::PendingFinality {
                confirmations,
                required_confirmations,
                ..
            } => AuthorityStanding::Blocked(BlockingReason::PendingFinality {
                why: format!(
                    "the evidence is canonical but {confirmations} deep against a required \
                     {required_confirmations}"
                ),
            }),
            RevalidationState::LeftCanonicalChain { .. } => {
                AuthorityStanding::Blocked(BlockingReason::EvidenceLeftCanonicalChain {
                    why: revalidation.to_string(),
                })
            }
            RevalidationState::NeedsRevalidation { why, .. } => {
                AuthorityStanding::Blocked(BlockingReason::NeedsRevalidation {
                    why: why.clone(),
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Residual exposure — required reading
// ---------------------------------------------------------------------------

// Confirmation depth is a probability and not a proof. A reorg deeper than
// `required_confirmations` between two revalidations defeats this module exactly
// as it defeats [`crate::base_usdc`] and [`crate::trusted_valuation`]: the
// canonical-hash check is only as good as the moment it ran. What this module
// changes is that the failure is now *expressible* and *blocking* rather than
// silent, and that a caller is given a state to be in when it has not checked.
//
// Not implemented, and not pretended to be:
//
//   * no background reorg watcher or subscription;
//   * no cross-provider agreement (a single kernel-identified view answers);
//   * no checkpoint/finality-committee notion — a chain whose finality is
//     stronger than confirmation depth gets only the depth this crate models;
//   * no automatic revocation propagation to an already-recorded reinvestment
//     commitment. `EvidenceLeftCanonicalChain` blocks *future* authority; a
//     commitment already appended to the reinvestment ledger is a historical
//     record and nothing here rewrites it. Closing that is a separate piece of
//     work and is named rather than glossed.

// ---------------------------------------------------------------------------
// A deterministic in-memory view — TEST ONLY, and incapable of authority
// ---------------------------------------------------------------------------

/// A chain view backed by a fixed map of height → canonical hash.
///
/// **This is a TEST DOUBLE. It can never produce production authority.** Three
/// independent reasons, each structural rather than a convention:
///
/// 1. **It is `#[cfg(test)]`**, so the type is not compiled into a release build
///    at all. It was gated on evidence, not on preference: a grep of this crate's
///    `src/`, `tests/` and `src/bin/` for `StaticChainView` returned matches only
///    inside this file — the definition, its two `impl`s, and thirteen uses in
///    this module's own test suite. There was no production caller to gate out.
/// 2. **It cannot become a [`TrustedCanonicalChainView`].** There is no `From`, no
///    `TryFrom`, no `Deref`, no accessor that hands one out, and the only
///    production constructor of that type takes an already-resolved pinned
///    provider. [`RevalidationOutcome::check_trusted`] takes the trusted type, so
///    a caller holding one of these has no argument it can pass.
/// 3. **Its answers are whatever the caller put in it**, so a `Confirmed` built
///    on it could only ever confirm what the caller already asserted.
///
/// What it *is* for: making the discipline in [`Revalidation::check`] testable
/// without a network — the head arithmetic, the reorg case, the provider-down
/// case, the pruned-height case and the view-behind-the-evidence case all need a
/// shaped answer, and there is no honest way to get one from a chain.
#[cfg(test)]
#[derive(Debug, Clone, Default)]
pub struct StaticChainView {
    head: Option<ChainHead>,
    canonical: BTreeMap<u64, Hash>,
    /// When set, `head()` fails with this message — the "provider is down" case.
    head_error: Option<String>,
    /// Heights the view has forgotten. Canonical lookups here return `Ok(None)`,
    /// which the check treats as unknown, not as a pass.
    pruned_below: Option<u64>,
}

#[cfg(test)]
impl StaticChainView {
    pub fn new() -> Self {
        Self::default()
    }

    /// A linear chain from `genesis_hash`, one hash per block, ending at `head`.
    ///
    /// Deterministic on purpose: a fixture whose block hashes depend on anything
    /// but its height cannot be reasoned about in a failing assertion.
    pub fn linear(head: u64, genesis: [u8; 32]) -> Self {
        let mut canonical = BTreeMap::new();
        for n in 0..=head {
            let mut b = genesis;
            b[0] ^= n as u8;
            b[1] ^= (n >> 8) as u8;
            b[2] ^= (n >> 16) as u8;
            b[3] ^= (n >> 24) as u8;
            canonical.insert(n, Hash::from_bytes(b));
        }
        Self {
            head: Some(ChainHead {
                block_number: head,
                block_hash: canonical[&head].clone(),
            }),
            canonical,
            head_error: None,
            pruned_below: None,
        }
    }

    /// The anchor this view reports at `number`, so a test cannot accidentally
    /// pair an anchor with a view whose canonical hash is something else — which
    /// would look exactly like a reorg.
    pub fn anchor_at(&self, number: u64) -> Option<SettlementAnchor> {
        self.canonical
            .get(&number)
            .map(|h| SettlementAnchor::new(number, h.clone()))
    }

    pub fn with_head(mut self, number: u64, hash: Hash) -> Self {
        self.head = Some(ChainHead {
            block_number: number,
            block_hash: hash,
        });
        self
    }

    /// Replace the canonical hash at `number`, which is how a reorg is
    /// expressed to the check.
    pub fn reorg_at(mut self, number: u64, new_hash: Hash) -> Self {
        self.canonical.insert(number, new_hash);
        self
    }

    pub fn with_head_error(mut self, why: impl Into<String>) -> Self {
        self.head_error = Some(why.into());
        self
    }

    pub fn pruned_below(mut self, height: u64) -> Self {
        self.pruned_below = Some(height);
        self
    }
}

#[cfg(test)]
impl CanonicalChainView for StaticChainView {
    fn head(&self) -> Result<ChainHead> {
        match &self.head_error {
            Some(why) => Err(crate::EconomyError::ProviderUnpinned(why.clone())),
            None => self.head.clone().ok_or_else(|| {
                crate::EconomyError::Invalid("static chain view has no head".into())
            }),
        }
    }

    fn canonical_hash_at(&self, block_number: u64) -> Result<Option<Hash>> {
        if self.pruned_below.is_some_and(|p| block_number < p) {
            return Ok(None);
        }
        Ok(self.canonical.get(&block_number).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base_usdc::BASE_CHAIN_ID;
    use crate::chain_provider::{resolve, PinnedChainProvider};
    use crate::discovery::{
        BudgetSpend, DiscoveryState, EvidenceDefect, MeasuredEdge, OpportunityClass,
        SettlementGap, ThermalStop,
    };
    use crate::resolution::{
        BreakEven, InvalidEvidence, NegativeNev, NoComparableNetValue, NoCompleteSettlement, NoEdge,
        SearchAbortedThermal, UnsupportedClass,
    };
    use crate::rpc_test_server::FakeRpcSocket;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tempfile::tempdir;

    fn hash(n: u8) -> Hash {
        let mut b = [0u8; 32];
        b[0] = n;
        Hash::from_bytes(b)
    }

    fn anchor(n: u64, h: u8) -> SettlementAnchor {
        SettlementAnchor::new(n, hash(h))
    }

    fn policy(depth: u64) -> RevalidationPolicy {
        RevalidationPolicy::new(depth).unwrap()
    }

    // ------------------------------------------------------------------
    // The revalidation check itself
    // ------------------------------------------------------------------

    #[test]
    fn a_canonical_anchor_at_the_required_depth_is_confirmed() {
        let view = StaticChainView::linear(100, [7u8; 32]);
        let at95 = view.anchor_at(95).unwrap();
        let state = Revalidation::check(Some(&at95), &view, &policy(6));
        assert_eq!(state.state(), "confirmed");
        assert_eq!(state.confirmations(), Some(6));
        assert!(state.is_irrevocable());
        assert!(!state.blocks_spend_authority());
    }

    #[test]
    fn a_shallow_anchor_is_pending_finality_and_blocks() {
        let view = StaticChainView::linear(100, [7u8; 32]);
        let at99 = view.anchor_at(99).unwrap();
        let state = Revalidation::check(Some(&at99), &view, &policy(6));
        assert_eq!(state.state(), "pending_finality");
        assert_eq!(state.confirmations(), Some(2));
        assert!(!state.is_irrevocable());
        assert!(state.blocks_spend_authority());
        assert!(!state.is_revoked());
    }

    #[test]
    fn a_reorg_revokes_rather_than_defers() {
        let view = StaticChainView::linear(100, [7u8; 32])
            .reorg_at(95, hash(0xAB))
            .with_head(100, hash(100));
        let state = Revalidation::check(Some(&anchor(95, 95u8)), &view, &policy(6));
        assert_eq!(state.state(), "left_canonical_chain");
        assert!(state.is_revoked(), "a reorg is a revocation, not a retry");
        assert!(!state.is_irrevocable());
        assert!(state.blocks_spend_authority());
        assert!(state.to_string().contains("revoked"), "{state}");

        // And it short-circuits before the depth arithmetic: an anchor that is
        // no longer canonical has no meaningful confirmation count.
        assert_eq!(state.confirmations(), None);
    }

    #[test]
    fn an_absent_anchor_is_unknown_not_a_pass() {
        let view = StaticChainView::linear(100, [7u8; 32]);
        let state = Revalidation::check(None, &view, &policy(6));
        assert_eq!(state.state(), "needs_revalidation");
        assert!(state.blocks_spend_authority());
        assert!(!state.is_irrevocable());
        assert_eq!(state.anchor(), None);
    }

    #[test]
    fn a_provider_that_cannot_name_its_head_is_unknown_not_a_pass() {
        let view = StaticChainView::linear(100, [7u8; 32])
            .with_head_error("connection refused");
        let at95 = view.anchor_at(95).unwrap();
        let state = Revalidation::check(Some(&at95), &view, &policy(6));
        assert_eq!(state.state(), "needs_revalidation");
        assert!(state.to_string().contains("connection refused"), "{state}");
    }

    #[test]
    fn a_pruned_height_is_unknown_not_a_pass() {
        let view = StaticChainView::linear(100, [7u8; 32]).pruned_below(98);
        let at95 = view.anchor_at(95).unwrap();
        let state = Revalidation::check(Some(&at95), &view, &policy(6));
        assert_eq!(state.state(), "needs_revalidation");
        assert!(
            state.to_string().contains("no longer serves block 95"),
            "{state}"
        );
    }

    #[test]
    fn a_view_behind_the_evidence_cannot_confirm_it() {
        let view = StaticChainView::linear(50, [7u8; 32]);
        let state = Revalidation::check(Some(&anchor(95, 95u8)), &view, &policy(1));
        assert_eq!(state.state(), "needs_revalidation");
        assert!(state.to_string().contains("behind the evidence"), "{state}");
    }

    #[test]
    fn the_depth_arithmetic_matches_the_receipt_rule() {
        // `head - anchor + 1`, the same expression `base_usdc` uses: the anchor
        // block itself counts as the first confirmation.
        let view = StaticChainView::linear(100, [7u8; 32]);
        for (anchor_n, expected) in [(100u64, 1u64), (99, 2), (50, 51)] {
            let at = view.anchor_at(anchor_n).unwrap();
            let state = Revalidation::check(Some(&at), &view, &policy(1));
            assert_eq!(state.confirmations(), Some(expected), "anchor {anchor_n}");
            assert_eq!(state.state(), "confirmed");
        }
    }

    #[test]
    fn a_zero_confirmation_bar_is_refused_like_a_policy_minimum() {
        assert!(RevalidationPolicy::new(0).is_err());
        let err = RevalidationPolicy::new(0).unwrap_err().to_string();
        assert!(err.contains("at least one confirmation"), "{err}");
        assert!(RevalidationPolicy::new(1).is_ok());
    }

    #[test]
    fn the_depth_verdict_is_derived_not_claimed() {
        let p = policy(6);
        assert_eq!(p.finality_of(5), DepthFinality::TooShallow);
        assert_eq!(p.finality_of(6), DepthFinality::DeepEnough);
        assert_eq!(p.finality_of(7), DepthFinality::DeepEnough);
        assert_eq!(p.required_confirmations(), 6);
    }

    #[test]
    fn a_verdict_that_never_ran_is_explicitly_not_confirmed() {
        let v = RevalidationVerdict::not_checked("none", "no pinned provider on this node");
        assert!(!v.is_irrevocable());
        assert!(!v.is_revoked());
        assert_eq!(v.state().state(), "needs_revalidation");
        assert!(v.describe().contains("no pinned provider"), "{}", v.describe());
    }

    // ------------------------------------------------------------------
    // The standing: a resolution plus a chain view
    // ------------------------------------------------------------------

    /// The eight refusal arms, as resolutions. No `VerifiedNev` is needed for
    /// any of them, which is the point: the standing computation reaches the
    /// blocking branch before it ever looks at the chain view.
    fn the_eight_refusals() -> Vec<EconomicResolution> {
        vec![
            EconomicResolution::NoEdge(NoEdge::new(
                OpportunityClass::Arbitrage,
                MeasuredEdge {
                    token_edge_micros: Some(-4_000),
                    robust_net_micros: -5_000,
                    source_field: "robust_net_usdc_raw".into(),
                },
                3,
            )),
            EconomicResolution::NoCompleteSettlement(NoCompleteSettlement::new(
                OpportunityClass::Arbitrage,
                vec![SettlementGap::LegAbsent { why: "x".into() }],
            )),
            EconomicResolution::NoComparableNetValue(NoComparableNetValue::new(
                OpportunityClass::Arbitrage,
                "no authorised price",
            )),
            EconomicResolution::NegativeNev(
                NegativeNev::new(OpportunityClass::Arbitrage, -1, "r").unwrap(),
            ),
            EconomicResolution::BreakEven(
                BreakEven::new(OpportunityClass::Arbitrage, 0, 1).unwrap(),
            ),
            EconomicResolution::InvalidEvidence(InvalidEvidence::new(
                OpportunityClass::Arbitrage,
                EvidenceDefect::Transmitted { why: "x".into() },
            )),
            EconomicResolution::SearchAbortedThermal(SearchAbortedThermal::new(
                OpportunityClass::Arbitrage,
                ThermalStop::BudgetTemperature { observed_c: 40.0, ceiling_c: 75.0 },
                BudgetSpend::cycles(1),
            )),
            EconomicResolution::UnsupportedClass(UnsupportedClass::new(
                OpportunityClass::NetworkFee,
                "no adapter",
            )),
        ]
    }

    fn confirmed_state() -> RevalidationState {
        RevalidationState::Confirmed {
            anchor: anchor(95, 95u8),
            confirmations: 6,
            required_confirmations: 6,
        }
    }

    #[test]
    fn no_refusal_arm_ever_gets_a_standing_however_good_the_chain_view() {
        for resolution in the_eight_refusals() {
            let state = resolution.state();
            // Deliberately the most permissive state that exists, including one
            // that was never produced by a check at all.
            let standing = resolution.standing(&confirmed_state());
            assert!(!standing.is_granted(), "{state} was granted a standing");
            match standing.blocking_reason().unwrap() {
                BlockingReason::NotAnAuthority { state: named, .. } => assert_eq!(named, state),
                other => panic!("{state}: expected NotAnAuthority, got {other}"),
            }
        }
    }

    #[test]
    fn needs_revalidation_blocks_spend_authority() {
        // The positive arm needs a `VerifiedNev`, which needs a provider, so the
        // "granted" case is exercised in `crate::nev0`. Here the state machine
        // is checked through a `PositiveNev`-shaped resolution built by the gate
        // test helper, and the three blocking branches are what matter.
        let res = crate::nev0::testkit::sample_positive_resolution();
        for (state, expected) in [
            (
                RevalidationState::NeedsRevalidation {
                    anchor: Some(anchor(95, 95u8)),
                    why: "the provider no longer serves block 95".into(),
                },
                "needs_revalidation",
            ),
            (
                RevalidationState::PendingFinality {
                    anchor: anchor(99, 99u8),
                    confirmations: 2,
                    required_confirmations: 6,
                },
                "pending_finality",
            ),
            (
                RevalidationState::LeftCanonicalChain {
                    anchor: anchor(95, 95u8),
                    canonical_block_hash: hash(0xAB),
                    head_block_number: 100,
                },
                "left_canonical_chain",
            ),
        ] {
            let standing = res.standing(&state);
            assert!(!standing.is_granted(), "{expected} must block");
            let reason = standing.blocking_reason().unwrap();
            match (&state, reason) {
                (
                    RevalidationState::NeedsRevalidation { .. },
                    BlockingReason::NeedsRevalidation { .. },
                ) => {}
                (
                    RevalidationState::PendingFinality { .. },
                    BlockingReason::PendingFinality { .. },
                ) => {}
                (
                    RevalidationState::LeftCanonicalChain { .. },
                    BlockingReason::EvidenceLeftCanonicalChain { .. },
                ) => {}
                _ => panic!("{expected} produced the wrong reason: {reason}"),
            }
            // The named reason has to say something the operator can act on, and
            // the two not-yet states must not be reported as a reorg.
            let text = reason.to_string();
            match reason {
                BlockingReason::NeedsRevalidation { .. } => {
                    assert!(text.contains("has not been revalidated"), "{text}");
                }
                BlockingReason::PendingFinality { .. } => {
                    assert!(text.contains("deep against a required"), "{text}");
                    assert!(!text.contains("REVOKED"), "{text}");
                }
                BlockingReason::EvidenceLeftCanonicalChain { .. } => {
                    assert!(text.contains("REVOKED"), "{text}");
                }
                other => panic!("{expected} produced the wrong reason: {other}"),
            }
        }
    }

    #[test]
    fn only_a_confirmed_positive_arm_gets_a_standing() {
        let res = crate::nev0::testkit::sample_positive_resolution();
        let standing = res.standing(&confirmed_state());
        assert!(standing.is_granted());
        assert!(standing.blocking_reason().is_none());
        let text = standing.describe();
        assert!(text.contains("precondition for a budget, not a budget"), "{text}");
        assert!(text.contains("NEV-0 verified"), "{text}");
    }

    #[test]
    fn a_standing_is_not_a_value() {
        // `AuthorityStanding` has no `PositiveNev` field and no `VerifiedNev`
        // field, and no method returning either. That is the structural half, and
        // it is why this module cannot be the last step into a budget even if a
        // caller wanted it to be.
        let standing = AuthorityStanding::Granted {
            class: OpportunityClass::Arbitrage,
            nev_musd_micros: 10_000,
            state: confirmed_state(),
        };
        assert!(standing.is_granted());
        assert!(standing.blocking_reason().is_none());
        let json = serde_json::to_value(&standing).unwrap();
        assert_eq!(json["standing"], serde_json::json!("granted"));
        assert_eq!(json["detail"]["nev_musd_micros"], serde_json::json!(10_000));
    }

    #[test]
    fn the_state_names_are_distinct() {
        let states = [
            confirmed_state(),
            RevalidationState::PendingFinality {
                anchor: anchor(99, 99u8),
                confirmations: 1,
                required_confirmations: 6,
            },
            RevalidationState::LeftCanonicalChain {
                anchor: anchor(95, 95u8),
                canonical_block_hash: hash(1),
                head_block_number: 100,
            },
            RevalidationState::NeedsRevalidation {
                anchor: None,
                why: "x".into(),
            },
        ];
        let mut names: Vec<&str> = states.iter().map(|s| s.state()).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before);
        assert_eq!(before, 4);
    }

    #[test]
    fn an_unsupported_class_is_a_refusal_arm_and_so_never_gets_a_standing() {
        // The revalidation check cannot rescue a class that was never searched:
        // `UnsupportedClass` is a refusal arm, so it takes the
        // `NotAnAuthority` branch without the chain view ever being consulted.
        let resolution = EconomicResolution::from_discovery_state(
            &DiscoveryState::UnsupportedClass {
                class: OpportunityClass::Arbitrage,
                why: "no adapter".into(),
            },
        )
        .unwrap();
        let view = StaticChainView::linear(100, [7u8; 32]);
        let at95 = view.anchor_at(95).unwrap();
        let state = Revalidation::check(Some(&at95), &view, &policy(6));
        assert!(state.is_irrevocable(), "the chain view here is clean");
        assert!(!resolution.standing(&state).is_granted());
    }

    // ------------------------------------------------------------------
    // P6.N7.3 — the trusted revalidation authority
    // ------------------------------------------------------------------

    /// A canonical block hash derived from the height alone. Deterministic on
    /// purpose: a fixture that depended on anything else could not be reasoned
    /// about in a failing assertion, and a reorg is expressed by naming a
    /// different height.
    fn chain_hash_hex(n: u64) -> String {
        let mut b = [0u8; 32];
        b[0] = n as u8;
        b[1] = (n >> 8) as u8;
        b[2] = (n >> 16) as u8;
        b[3] = (n >> 24) as u8;
        format!("0x{}", hex::encode(b))
    }

    fn chain_hash(n: u64) -> Hash {
        Hash::parse("test block hash", &chain_hash_hex(n)).expect("a 32-byte hex hash")
    }

    /// A fake Base provider on a **real unix socket inode**, resolved exactly the
    /// way production resolves one.
    ///
    /// `overrides` answers a height with a different canonical hash — that is how
    /// a reorg is expressed. `omit` names methods the server refuses, which is the
    /// provider-failure case; the fake answers an unknown method with JSON-RPC
    /// `-32601`, so "refused" is a refusal and not an empty success.
    fn fake_base_chain(
        dir: &Path,
        name: &str,
        head: u64,
        chain_id: u64,
        overrides: BTreeMap<u64, String>,
        omit: Vec<&'static str>,
    ) -> FakeRpcSocket {
        FakeRpcSocket::with_dispatch(dir.join(name), move |method, params| {
            if omit.contains(&method) {
                return None;
            }
            match method {
                "eth_chainId" => Some(json!(format!("0x{chain_id:x}"))),
                "eth_blockNumber" => Some(json!(format!("0x{head:x}"))),
                "eth_getBlockByNumber" => {
                    let requested = params.get(0).and_then(Value::as_str)?;
                    let n = u64::from_str_radix(requested.trim_start_matches("0x"), 16).ok()?;
                    let hash = overrides
                        .get(&n)
                        .cloned()
                        .unwrap_or_else(|| chain_hash_hex(n));
                    Some(json!({
                        "number": requested,
                        "hash": hash,
                        "timestamp": "0x1",
                    }))
                }
                _ => None,
            }
        })
    }

    /// A `ResolvedChainProvider` from the crate's own resolver, over a real
    /// pinned socket — with the preconditions asserted rather than assumed, so a
    /// fixture that stopped being a policy pin would fail here instead of quietly
    /// testing something else.
    fn resolve_pinned(server: &FakeRpcSocket) -> ResolvedChainProvider {
        let pin = PinnedChainProvider::unix_socket(server.path(), Some(server.uid()))
            .expect("a canonical unix socket pin");
        let resolved = resolve(None, Some(&pin)).expect("resolve a policy pin");
        assert_eq!(
            resolved.source,
            ProviderSource::PolicyPin,
            "precondition: a policy pin resolves to the production source"
        );
        assert!(
            resolved.identity_kernel_enforced(),
            "precondition: a policy pin is a unix socket"
        );
        assert_eq!(
            resolved.as_pinned().socket_path().ok().as_deref(),
            Some(server.path()),
            "precondition: the pin names this socket"
        );
        resolved
    }

    fn trusted_view(server: &FakeRpcSocket, expected_chain_id: u64) -> TrustedCanonicalChainView {
        let resolved = resolve_pinned(server);
        TrustedCanonicalChainView::from_resolved(&resolved, expected_chain_id, 1)
            .expect("a resolved policy pin yields a trusted view")
    }

    /// The attack [`TrustedCanonicalChainView`] exists to refuse, written the way
    /// an attacker would write it: a `pub` trait implemented outside any of the
    /// crate's trust machinery, with no socket, no pinning and no network.
    struct ArbitraryChainView {
        head: ChainHead,
        canonical: BTreeMap<u64, Hash>,
    }

    impl CanonicalChainView for ArbitraryChainView {
        fn head(&self) -> Result<ChainHead> {
            Ok(self.head.clone())
        }

        fn canonical_hash_at(&self, block_number: u64) -> Result<Option<Hash>> {
            Ok(self.canonical.get(&block_number).cloned())
        }
    }

    #[test]
    fn arbitrary_chain_view_cannot_produce_a_production_revalidation_outcome() {
        let view = ArbitraryChainView {
            head: ChainHead {
                block_number: 100,
                block_hash: chain_hash(100),
            },
            canonical: BTreeMap::from([(95, chain_hash(95))]),
        };
        let anchor = SettlementAnchor::new(95, chain_hash(95));

        // PRECONDITION, asserted rather than assumed: this implementation really is
        // powerful enough to make the *raw* check say confirmed. Without it the rest
        // of the test would pass vacuously, and the gap it documents would be a
        // claim instead of a measurement.
        let raw = Revalidation::check(Some(&anchor), &view, &policy(6));
        assert_eq!(raw.state(), "confirmed", "precondition: the gap was real");

        // And the in-crate, non-authority wrapper — which is what a module inside
        // this crate can still reach — produces the same thing. Named here rather
        // than hidden: `pub(crate)` is a real boundary, not a proof, and the module
        // doc says so.
        let untrusted = RevalidationOutcome::check(Some(&anchor), &view, &policy(6));
        assert_eq!(untrusted.state_name(), "confirmed");

        // `check_trusted`'s parameter is `&TrustedCanonicalChainView`, and there is
        // no way to turn a `&dyn CanonicalChainView` into one: no `From`, no
        // `TryFrom`, no `Deref`, no accessor, and the only production constructor
        // takes an already-resolved pinned provider. Writing
        // `check_trusted(&anchor, &view, &policy(6))` is a COMPILE ERROR, which is
        // why it is stated here rather than asserted. What is observable is that
        // none of the routes to a trusted view is available from an arbitrary impl,
        // and each one is checked:
        //
        // (1) Nothing to resolve: the resolver refuses rather than inventing an
        //     endpoint, so there is no default to fall back to.
        assert!(
            matches!(
                resolve(None, None).unwrap_err(),
                crate::EconomyError::ProviderUnpinned(_)
            ),
            "precondition: nothing resolves without a pin"
        );

        // (2) The dev override is the one source an arbitrary caller CAN name, and
        //     it is refused as a source.
        let dev = resolve(Some("http://127.0.0.1:8546"), None).expect("a dev override resolves");
        assert!(dev.is_dev_override(), "precondition: that is the dev source");
        let err = TrustedCanonicalChainView::from_resolved(&dev, BASE_CHAIN_ID, 1)
            .expect_err("a dev override cannot back a trusted view");
        assert!(
            err.to_string().contains("DevEnvOverride"),
            "the refusal must name the dev source, got {err}"
        );

        // (3) The `pub`-field forgery: hand-assemble a resolution that carries the
        //     production label over an endpoint with no kernel identity. It is
        //     re-verified and refused.
        let forged = ResolvedChainProvider {
            provider: dev.as_pinned().clone(),
            source: ProviderSource::PolicyPin,
        };
        assert_eq!(
            forged.source,
            ProviderSource::PolicyPin,
            "precondition: the forgery really does carry the production label"
        );
        let err = TrustedCanonicalChainView::from_resolved(&forged, BASE_CHAIN_ID, 1)
            .expect_err("a forged production label must be re-verified and refused");
        assert!(
            err.to_string().contains("no verifiable identity"),
            "the refusal must name the missing kernel identity, got {err}"
        );
    }

    #[test]
    fn static_chain_view_is_test_only_or_untrusted() {
        // PRECONDITION, and the first of the two claims: this whole test exists
        // only in a test build, because `StaticChainView` is `#[cfg(test)]` and is
        // therefore not compiled into a release build at all. Asserted so this file
        // cannot be read as describing a type production can name.
        assert!(cfg!(test), "precondition: StaticChainView is a test-only type");

        let view = StaticChainView::linear(100, [7u8; 32]);

        // PRECONDITION: the fixture is self-consistent, so a `confirmed` below is a
        // revalidation and not a tautology.
        let anchor = view
            .anchor_at(95)
            .expect("the linear view has a canonical block 95");
        assert_eq!(
            view.canonical_hash_at(95).ok().flatten(),
            Some(anchor.block_hash.clone()),
            "precondition: the fixture's anchor matches its own canonical hash"
        );

        // It IS powerful: through the raw check it confirms. That is exactly why it
        // has to be powerless where authority is concerned.
        let raw = Revalidation::check(Some(&anchor), &view, &policy(6));
        assert_eq!(raw.state(), "confirmed");

        // Second claim. The only wrapper that accepts a `&dyn CanonicalChainView`
        // is `pub(crate)` and non-authority; the only *public* wrapper accepts a
        // `TrustedCanonicalChainView`, and there is no `From<&StaticChainView>` for
        // it, so `check_trusted(.., &view, ..)` does not typecheck. That half is a
        // signature property and is stated, not asserted.
        //
        // The observable half: the ONE thing that grants a view its trust level is
        // its constructor. There is exactly one production constructor,
        // `from_resolved`, it demands an already-resolved pinned provider, and it
        // refuses everything that is not one. In a test build the only other
        // constructor is the seam below, and it is `#[cfg(test)] pub(crate)`.
        let seam = TrustedCanonicalChainView::for_test(view, "test double", BASE_CHAIN_ID);
        assert_eq!(
            seam.trust_level(),
            ProviderSource::PolicyPin,
            "the seam is the only way a StaticChainView acquires a trust level, and it exists \
             only in a test build"
        );
        assert!(seam.provider_description().contains("test double"));
    }

    #[test]
    fn unpinned_provider_cannot_confirm() {
        // PRECONDITION 1: there is no default endpoint. "Unpinned" is not a state a
        // provider can be in and still be handed to the constructor, because the
        // resolver refuses rather than inventing one.
        let err = resolve(None, None).unwrap_err();
        assert!(
            matches!(err, crate::EconomyError::ProviderUnpinned(_)),
            "precondition: resolve(None, None) refuses, got {err}"
        );

        // PRECONDITION 2: what "unpinned" looks like when a caller insists on one —
        // a loopback TCP endpoint, which is an address and not an identity.
        let loopback = PinnedChainProvider::parse("http://127.0.0.1:8546", None)
            .expect("a loopback spec parses");
        assert!(
            !loopback.identity_kernel_enforced(),
            "precondition: a loopback TCP endpoint has no verifiable identity"
        );

        // And the label does not help. Both `ResolvedChainProvider` and
        // `PinnedChainProvider` have `pub` fields, so a caller can assemble a
        // resolution that says `PolicyPin` over an endpoint `resolve` itself would
        // have refused.
        let forged = ResolvedChainProvider {
            provider: loopback.clone(),
            source: ProviderSource::PolicyPin,
        };
        assert_eq!(
            forged.source,
            ProviderSource::PolicyPin,
            "precondition: the forgery carries the production label"
        );

        let err = TrustedCanonicalChainView::from_resolved(&forged, BASE_CHAIN_ID, 1)
            .expect_err("a loopback endpoint cannot back a trusted view");
        assert!(
            err.to_string().contains("no verifiable identity"),
            "the refusal must name the missing kernel identity, got {err}"
        );
    }

    #[test]
    fn dev_provider_cannot_confirm() {
        let dir = tempdir().expect("tempdir");

        // The strongest form of this case, and the one that proves the source label
        // is what is checked: a dev override naming a REAL unix socket. It passes
        // every identity, ownership and mode check the pinning path performs, so
        // only the SOURCE distinguishes it from a production pin.
        let server = fake_base_chain(
            dir.path(),
            "dev.sock",
            100,
            BASE_CHAIN_ID,
            BTreeMap::new(),
            vec![],
        );
        let spec = format!("unix://{}", server.path().display());
        let dev = resolve(Some(spec.as_str()), None)
            .expect("a dev override naming a unix socket resolves");
        assert_eq!(
            dev.source,
            ProviderSource::DevEnvOverride,
            "precondition: it resolved from the dev override"
        );
        assert!(dev.is_dev_override(), "precondition");
        assert!(
            dev.identity_kernel_enforced(),
            "precondition: this dev override passes every kernel identity check, so only the \
             source label can refuse it"
        );

        let err = TrustedCanonicalChainView::from_resolved(&dev, BASE_CHAIN_ID, 1)
            .expect_err("a dev override cannot back a trusted view");
        assert!(
            err.to_string().contains("DevEnvOverride"),
            "the refusal must name the dev source, got {err}"
        );

        // And the ordinary dev case: a bare loopback HTTP endpoint, which fails for
        // two independent reasons and is refused for the first one that applies.
        let http = resolve(Some("http://127.0.0.1:8546"), None).expect("a dev override resolves");
        assert!(http.is_dev_override(), "precondition");
        assert!(
            TrustedCanonicalChainView::from_resolved(&http, BASE_CHAIN_ID, 1).is_err(),
            "a loopback HTTP dev override cannot back a trusted view either"
        );
    }

    #[test]
    fn wrong_chain_id_cannot_confirm() {
        let dir = tempdir().expect("tempdir");

        // (a) Construction. A properly pinned production provider answering on the
        //     wrong chain.
        let other = fake_base_chain(
            dir.path(),
            "other.sock",
            100,
            1,
            BTreeMap::new(),
            vec![],
        );
        let resolved = resolve_pinned(&other);
        let err = TrustedCanonicalChainView::from_resolved(&resolved, BASE_CHAIN_ID, 1)
            .expect_err("a provider on the wrong chain must be refused");
        assert!(
            err.to_string().contains("wrong chain id"),
            "the refusal must name the chain id, got {err}"
        );

        // (b) Call time. The chain id is re-read on every read, for the same reason
        //     `rpc_call` re-checks socket identity on every call: the endpoint
        //     answered when the view was built and it has to answer now.
        let drift = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&drift);
        let drifting = FakeRpcSocket::with_dispatch(
            dir.path().join("drift.sock"),
            move |method, params| {
                match method {
                    "eth_chainId" => Some(json!(format!(
                        "0x{:x}",
                        if flag.load(Ordering::SeqCst) {
                            BASE_CHAIN_ID
                        } else {
                            1
                        }
                    ))),
                    "eth_blockNumber" => Some(json!("0x64")),
                    "eth_getBlockByNumber" => {
                        let requested = params.get(0).and_then(Value::as_str)?;
                        let n =
                            u64::from_str_radix(requested.trim_start_matches("0x"), 16).ok()?;
                        Some(json!({
                            "number": requested,
                            "hash": chain_hash_hex(n),
                            "timestamp": "0x1",
                        }))
                    }
                    _ => None,
                }
            },
        );
        let view = trusted_view(&drifting, 1);
        let anchor = SettlementAnchor::new(95, chain_hash(95));

        // PRECONDITION: the fixture CAN confirm while the chain id is stable, so the
        // refusal below is the drift and nothing else.
        assert_eq!(
            RevalidationOutcome::check_trusted(Some(&anchor), &view, &policy(6)).state_name(),
            "confirmed",
            "precondition: a stable chain id confirms"
        );

        drift.store(true, Ordering::SeqCst);
        let outcome = RevalidationOutcome::check_trusted(Some(&anchor), &view, &policy(6));
        assert_eq!(
            outcome.state_name(),
            "needs_revalidation",
            "a chain id that changed under the view must not confirm"
        );
        assert!(!outcome.is_confirmed());
        assert!(
            outcome.state().to_string().contains("chain id changed"),
            "{}",
            outcome.state()
        );
    }

    #[test]
    fn pinned_provider_with_canonical_anchor_can_confirm() {
        let dir = tempdir().expect("tempdir");
        let server = fake_base_chain(
            dir.path(),
            "base.sock",
            100,
            BASE_CHAIN_ID,
            BTreeMap::new(),
            vec![],
        );
        let view = trusted_view(&server, BASE_CHAIN_ID);

        // PRECONDITIONS, on the reads themselves and not only on the outcome: this is
        // a pinned production view, on Base, reading a real chain.
        assert_eq!(view.trust_level(), ProviderSource::PolicyPin);
        assert_eq!(view.chain_id(), BASE_CHAIN_ID);
        let description = view.provider_description();
        assert!(
            description.contains("PolicyPin") && description.contains("kernel-enforced"),
            "the audit description must carry the trust level: {description}"
        );
        assert_eq!(
            view.head().expect("the head is readable").block_number,
            100,
            "precondition: the provider names its head"
        );

        // PRECONDITION: the anchor really is the canonical block at 95, so the
        // `confirmed` below is a revalidation and not a tautology.
        let anchor = SettlementAnchor::new(95, chain_hash(95));
        assert_eq!(
            view.canonical_hash_at(95).expect("a canonical read"),
            Some(anchor.block_hash.clone()),
            "precondition: the anchor is the canonical block at 95"
        );

        let outcome = RevalidationOutcome::check_trusted(Some(&anchor), &view, &policy(6));
        assert_eq!(outcome.state_name(), "confirmed");
        assert_eq!(outcome.confirmations(), Some(6));
        assert!(outcome.is_confirmed());
        assert!(!outcome.blocks_authority());
    }

    #[test]
    fn pinned_provider_reorg_produces_left_canonical_chain() {
        let dir = tempdir().expect("tempdir");
        let mut overrides = BTreeMap::new();
        overrides.insert(95u64, chain_hash_hex(0xDEAD));
        let server = fake_base_chain(
            dir.path(),
            "reorg.sock",
            100,
            BASE_CHAIN_ID,
            overrides,
            vec![],
        );
        let view = trusted_view(&server, BASE_CHAIN_ID);
        assert_eq!(
            view.trust_level(),
            ProviderSource::PolicyPin,
            "precondition: a pinned production view"
        );

        // PRECONDITION: the canonical hash at the anchor's height really is a
        // different block, so the state below is a reorg and not a depth verdict.
        let observed = view
            .canonical_hash_at(95)
            .expect("a canonical read")
            .expect("the provider serves block 95");
        assert_eq!(observed, chain_hash(0xDEAD));
        assert_ne!(observed, chain_hash(95), "precondition: the chain moved");

        let anchor = SettlementAnchor::new(95, chain_hash(95));
        let outcome = RevalidationOutcome::check_trusted(Some(&anchor), &view, &policy(6));
        assert_eq!(outcome.state_name(), "left_canonical_chain");
        assert!(
            outcome.state().is_revoked(),
            "a reorg is a revocation, not a retry"
        );
        assert!(!outcome.is_confirmed());
        assert!(outcome.blocks_authority());
        // It short-circuits before the depth arithmetic: an anchor that is no longer
        // canonical has no meaningful confirmation count.
        assert_eq!(outcome.confirmations(), None);
    }

    #[test]
    fn provider_failure_produces_needs_revalidation() {
        let dir = tempdir().expect("tempdir");

        // (a) A pinned provider that cannot answer the one question the constructor
        //     has to ask. PRECONDITION: it resolves and pins cleanly, so what fails
        //     below is the read and not the pinning.
        let silent = fake_base_chain(
            dir.path(),
            "silent.sock",
            100,
            BASE_CHAIN_ID,
            BTreeMap::new(),
            vec!["eth_chainId", "eth_blockNumber", "eth_getBlockByNumber"],
        );
        let resolved = resolve_pinned(&silent);
        let err = TrustedCanonicalChainView::from_resolved(&resolved, BASE_CHAIN_ID, 1)
            .expect_err("a provider that cannot name its chain id cannot back a view");
        assert!(
            err.to_string().contains("eth_chainId"),
            "the refusal must name the unanswered read, got {err}"
        );

        // (b) A pinned provider that answers at construction and then stops
        //     answering.
        let flaky = fake_base_chain(
            dir.path(),
            "flaky.sock",
            100,
            BASE_CHAIN_ID,
            BTreeMap::new(),
            vec!["eth_blockNumber"],
        );
        let view = trusted_view(&flaky, BASE_CHAIN_ID);
        assert_eq!(
            view.chain_id(),
            BASE_CHAIN_ID,
            "precondition: it answered at construction"
        );
        let anchor = SettlementAnchor::new(95, chain_hash(95));
        let outcome = RevalidationOutcome::check_trusted(Some(&anchor), &view, &policy(6));
        assert_eq!(outcome.state_name(), "needs_revalidation");
        assert!(!outcome.is_confirmed());
        assert!(outcome.blocks_authority());
        assert!(
            outcome.state().to_string().contains("cannot name its head"),
            "{}",
            outcome.state()
        );

        // (c) A pinned view whose head is BELOW the anchor. That is a failure to
        //     establish anything, so it must not confirm either.
        let behind = fake_base_chain(
            dir.path(),
            "behind.sock",
            50,
            BASE_CHAIN_ID,
            BTreeMap::new(),
            vec![],
        );
        let view = trusted_view(&behind, BASE_CHAIN_ID);
        let outcome = RevalidationOutcome::check_trusted(Some(&anchor), &view, &policy(1));
        assert_eq!(outcome.state_name(), "needs_revalidation");
        assert!(
            outcome.state().to_string().contains("behind the evidence"),
            "{}",
            outcome.state()
        );

        // (d) The same "provider is down" refusal through the `#[cfg(test)]` seam
        //     over a `StaticChainView`. The seam is the only way to reach this path
        //     and it does not exist in a production build.
        let healthy = StaticChainView::linear(100, [7u8; 32]);
        let healthy_anchor = healthy
            .anchor_at(95)
            .expect("the linear view has a canonical block 95");
        let up = TrustedCanonicalChainView::for_test(healthy, "test double", BASE_CHAIN_ID);
        assert_eq!(
            RevalidationOutcome::check_trusted(Some(&healthy_anchor), &up, &policy(6)).state_name(),
            "confirmed",
            "precondition: the seam CAN confirm, so the refusal below is the failure"
        );

        let down = StaticChainView::linear(100, [7u8; 32]).with_head_error("connection refused");
        let down = TrustedCanonicalChainView::for_test(down, "test double", BASE_CHAIN_ID);
        let outcome = RevalidationOutcome::check_trusted(Some(&healthy_anchor), &down, &policy(6));
        assert_eq!(outcome.state_name(), "needs_revalidation");
        assert!(!outcome.is_confirmed());
        assert!(
            outcome.state().to_string().contains("connection refused"),
            "{}",
            outcome.state()
        );
    }

    #[test]
    fn wrong_socket_identity_cannot_confirm() {
        // Feasible without a live node, and not faked: `FakeRpcSocket` binds a REAL
        // unix socket inode with real permissions and a real owner uid, so the
        // kernel identity checks in `chain_provider` apply here exactly as they
        // would to a production verifier socket. There is no simulated `stat`.
        let dir = tempdir().expect("tempdir");

        // (a) Construction: the pin names an owner the socket does not have.
        let server = fake_base_chain(
            dir.path(),
            "owned.sock",
            100,
            BASE_CHAIN_ID,
            BTreeMap::new(),
            vec![],
        );
        let wrong_uid = server.uid().wrapping_add(1);
        let pin =
            PinnedChainProvider::unix_socket(server.path(), Some(wrong_uid)).expect("a valid pin");
        let resolved = resolve(None, Some(&pin)).expect("a wrong-owner pin still resolves");
        assert_eq!(
            resolved.source,
            ProviderSource::PolicyPin,
            "precondition: the source label is correct, so only the socket identity is wrong"
        );

        let err = TrustedCanonicalChainView::from_resolved(&resolved, BASE_CHAIN_ID, 1)
            .expect_err("a socket owned by the wrong uid cannot back a trusted view");
        assert!(
            err.to_string().contains("expected uid"),
            "the refusal must name the owner mismatch, got {err}"
        );

        // (b) Call time: the view is built while the socket is correct, and the
        //     socket's permissions are widened afterwards. `rpc_call` re-checks on
        //     every call, so the identity check happens again at read time — which
        //     is what stops a "verified once at startup" swap from being trusted for
        //     the life of the process.
        let good = fake_base_chain(
            dir.path(),
            "good.sock",
            100,
            BASE_CHAIN_ID,
            BTreeMap::new(),
            vec![],
        );
        let view = trusted_view(&good, BASE_CHAIN_ID);
        let anchor = SettlementAnchor::new(95, chain_hash(95));

        // PRECONDITION: it confirms while the socket is intact, so the refusal below
        // is the permission change and nothing else.
        assert_eq!(
            RevalidationOutcome::check_trusted(Some(&anchor), &view, &policy(6)).state_name(),
            "confirmed",
            "precondition: an intact socket confirms"
        );

        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(good.path(), fs::Permissions::from_mode(0o777))
                .expect("widen the socket permissions");
        }

        let outcome = RevalidationOutcome::check_trusted(Some(&anchor), &view, &policy(6));
        assert_eq!(
            outcome.state_name(),
            "needs_revalidation",
            "a socket that stopped being owner-only must not confirm"
        );
        assert!(!outcome.is_confirmed());
        assert!(outcome.blocks_authority());
        assert!(
            outcome.state().to_string().contains("group/other-writable"),
            "{}",
            outcome.state()
        );
    }
}
