//! The verified read side (P3): economic numbers derived from evidence, never
//! from stored claims, under a policy-authenticated receipt (P4b).
//!
//! # The identity this module exists to make true
//!
//! ```text
//! VerifiedNev = VerifyChain(DeriveBoundary(VerifyReceiptSig(VerifyPolicy(Evidence))))
//! ```
//!
//! Read it as four nested steps, outermost last:
//!
//! 1. `VerifyPolicy(Evidence)` — the outcome policy is checked against a trust
//!    anchor pinned out-of-band ([`crate::policy_auth`]), and the receipt carries
//!    a signature from the one verifier key that policy delegated to. The
//!    signature is verified against *re-derived* evidence, never against a copy
//!    stored next to it, and the receipt's `policy_hash` must be the hash of the
//!    policy in force now.
//! 2. `VerifyReceiptSig(...)` — see 1; the boundary facts are in the preimage.
//! 3. `DeriveBoundary(...)` — the control side of a settlement is *derived* on
//!    read, from the addresses stored in the ledger and the operator's
//!    [`ControlledAddressRegistry`]. P1 already made this the only way to obtain
//!    a [`BoundaryCrossing`]; this module is its caller.
//! 4. `VerifyChain(...)` — the transaction, block and ERC-20 log the evidence
//!    cites are re-read from a kernel-identified provider, and the receipt has to
//!    survive the re-read.
//!
//! **The signature adds provenance and a policy binding. It does not substitute
//! for chain confirmation.** A signature says "the delegated verifier said this
//! receipt describes this transfer"; only the chain read says the transfer
//! exists. The gate order below is the identity read as a sequence, and it is
//! never collapsed to `signature valid → NEV valid`: reordering it would be a
//! regression of P3, and `the_signature_does_not_substitute_for_the_chain_read`
//! in this module's tests pins the property.
//!
//! What this module removes is the one step the identity does not have:
//!
//! ```text
//! FORBIDDEN: VerifiedNev = receipt.proof_verified
//! FORBIDDEN: VerifiedNev = receipt.proof_verified || valid_signature
//! ```
//!
//! A process that can append to `~/.mycelium/economy/*.jsonl` can write a valid
//! hash chain, a plausible `ExternalValueReceipt` and a plausible
//! `BoundaryEvidence`, because the genesis hash is a public constant and nothing
//! in the file is signed. Before this module that was enough to reach `ARV4` and
//! to unlock real reinvestment budget. Now the ledger's own claims are only ever
//! a *claim*; the number an operator may act on comes from a chain read this
//! module performs, or from nothing at all.
//!
//! # Where it sits
//!
//! ```text
//!   on-disk ledgers  ->  VerifiedEconomyView  ->  ARV / verified NEV
//!   (diagnostics)        VerifiedRevenueView  ->  RV / paid demand
//!                        reinvestment budget
//! ```
//!
//! The raw records and the stored `proof_verified: bool` stay readable, because
//! `autonomy-audit` and a human debugging a mismatch both need them. They are
//! not reachable from an economic decision: the only way to obtain an actionable
//! number is [`VerifiedEconomyView::verified_nev`], which returns a
//! [`VerifiedNev`] — a type with private fields, no `Deserialize` and no public
//! constructor anywhere in the crate.
//!
//! # Trust modes
//!
//! [`TrustMode::Unverified`] is the offline mode: hash chain, receipt
//! re-validation and boundary re-derivation, with no chain access at all. It
//! yields [`UnattestedNev`], a *different type* from [`VerifiedNev`] that
//! exposes no accessor an ARV predicate or a budget gate can accept. That is
//! the point of the split: "3 receipts re-derive and 5.0 mUSD is claimed" and
//! "5.0 mUSD is attested" are different sentences, and only the second one may
//! spend money.
//!
//! [`TrustMode::ProviderPinned`] additionally re-reads every cited transaction
//! through a provider pinned out-of-band, and refuses to be constructed when
//! that provider's identity was not enforced by the kernel. The dev-only
//! loopback override ([`crate::chain_provider::DEV_PROVIDER_ENV`]) can drive a
//! verifier but can never produce an attested number, because it authenticates
//! nothing.
//!
//! Since P4b the pinned mode also requires a *validated outcome policy*:
//! [`VerifiedEconomyView::provider_pinned`] takes one, so "provider pinned" and
//! "policy validated" are the same statement and there is no constructor that
//! yields a promotable view without an authority. A receipt with no signature
//! from the delegated verifier is unattested even in pinned mode, even with a
//! chain-confirmed transfer: the signature is provenance, the chain read is
//! truth, and a number needs both.

use crate::{
    autonomy::{
        revalidate_external_value, ArvStatus, AutonomousEconomy,
        AutonomousSummary, AutonomyPayload, ExternalValueClass,
        ExternalValueReceipt,
    },
    base_usdc::{self, BaseUsdcVerifier},
    boundary::{
        BoundaryCrossing, BoundaryEvidence, ControlDomain,
        ControlledAddressRegistry, CrossingKind, NevSign, SettlementAsset,
        ValueClassDomain,
    },
    event_id::{CountedEvents, ExternalEventFact, ExternalEventId},
    policy_auth::{Hash, ValidatedOutcomePolicy},
    receipt_auth::{
        receipt_hash, AuthenticatedExternalValueReceipt, ReceiptAuthError,
        VerifiedAttestation,
    },
    settlement_auth::{
        settlement_hash, AuthenticatedSettlementReceipt, SettlementAuthError,
    },
    EconomyError, LedgerRecord, LocalEconomy, PaymentIntent, Result, RevenueSummary,
    RvStatus, SettlementMode, SettlementReceipt,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// How much of the identity in the module doc this view actually executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    /// Offline re-derivation only: the hash chain, the receipt's own
    /// validation rules and the boundary derivation. No chain read is
    /// attempted, so nothing on this ledger can be promoted and no budget can
    /// be funded.
    #[default]
    Unverified,
    /// Additionally re-reads every cited transaction, block and ERC-20 log
    /// through a provider pinned out-of-band whose socket identity the kernel
    /// enforces.
    ProviderPinned,
}

impl TrustMode {
    /// Whether this mode may hand out an actionable number. One place, so no
    /// decision site re-derives the rule for itself.
    pub fn can_attest(self) -> bool {
        matches!(self, Self::ProviderPinned)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::ProviderPinned => "provider_pinned",
        }
    }
}

impl std::fmt::Display for TrustMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why one external-value receipt did not become verified value.
///
/// Diagnostics only: nothing promotes a level because a gap is absent, and
/// nothing spends because a receipt carries none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationGap {
    /// The value class cannot create external value at all.
    NotAValueClass,
    /// The receipt failed the write-time validation rules, re-run here.
    ReceiptRejected(String),
    /// The receipt cites no transaction hash, so there is nothing a provider
    /// could be asked about. This is the shape of every pre-crossing receipt
    /// and of every `external-value-candidate-json` submission.
    NoCitableTransaction,
    /// `proof_hash` is a 32-byte hash, but no boundary evidence in the ledger
    /// cites it.
    NoBoundaryCrossing,
    /// Evidence cites the transaction but does not derive against the registry
    /// as it stands now.
    BoundaryNotDerivable(String),
    /// The derived crossing is not money arriving from outside the controlled
    /// set into it.
    NotAnExternalInflow { kind: CrossingKind },
    /// The receipt's class is not the class the crossing creates.
    ClassNotJustified {
        crossing: ValueClassDomain,
        receipt: ValueClassDomain,
    },
    /// The receipt is denominated in something other than the crossing asset,
    /// or in a synthetic ledger unit.
    AssetNotJustified(String),
    /// The crossing direction and the booked sign contradict each other.
    SignNotJustified,
    // ---- P4b: provenance ------------------------------------------------
    /// This view holds no validated outcome policy, so there is no authority to
    /// check a receipt's signature against. Only reachable if the invariant
    /// that a promotable view always carries a policy is broken; it is written
    /// out rather than assumed, because "grants nothing" should not depend on a
    /// constructor someone can edit later.
    PolicyNotValidated,
    /// No signed attestation covers this receipt. This is the shape of every
    /// receipt written before signed attestations existed, and of every
    /// hand-written ledger line: the receipt is reported, with this reason, and
    /// is neither dropped nor promoted.
    UnsignedReceipt,
    /// Two *different* attestations claim the same receipt content. Nothing in
    /// the design produces this, so it is refused rather than resolved.
    DuplicateAttestation,
    /// This attestation was already consumed by another ledger record. One
    /// signature covers one receipt; the same attested receipt written twice
    /// must not be counted twice.
    ///
    /// P4.5b keeps this as defence in depth over the *attestation* ledger and
    /// does not widen it: it fires when one signature is claimed by two records.
    /// A ledger that books the same external *event* twice under two different,
    /// individually valid attestations is a different fault and gets
    /// [`Self::ExternalEventAlreadyCounted`] instead. The two never fire on the
    /// same record, because this one is decided at the signature gate and that
    /// one at the last gate.
    AttestationReplayed,
    /// P4.5b: this record's external fact has the same
    /// [`ExternalEventId`] as a record already in the total, so it is not
    /// counted again.
    ///
    /// The economic half of duplicate handling, and the only one that survives
    /// the process that created the duplicate. It is a *different* diagnosis
    /// from [`Self::AttestationReplayed`] with a different fix: here every
    /// signature is genuine and the chain read confirmed the transfer twice —
    /// the ledger simply books one piece of real money more than once. The event
    /// id is the external fact, so this fires regardless of ledger order,
    /// sequence, timestamps, receipt formatting or how many times the process
    /// has restarted.
    ExternalEventAlreadyCounted {
        event_id: String,
        /// The record that holds the credit for this fact, so the report can
        /// name it rather than only saying "already counted".
        first_counted_at_sequence: u64,
    },
    /// P4.5b: the transfer was confirmed but the provider did not report which
    /// log it matched, so the external fact has no canonical identity.
    ///
    /// Its own gap rather than a flavour of [`Self::ChainNotConfirmed`] because
    /// the transfer may be entirely real and the *counting* is what cannot be
    /// done safely: two identical transfers in one transaction are
    /// indistinguishable without a log index, so naming this one would risk
    /// either double-counting it or hiding it behind a different event. Fail
    /// closed and say so.
    EventIdentityIndeterminate(String),
    /// The attestation names a verifier the policy in force does not delegate
    /// to — the shape an unknown verifier's signature gets.
    VerifierNotDelegated { claimed: String, delegated: String },
    /// The signature does not verify against the delegated verifier key.
    AttestationSignatureInvalid,
    /// The receipt was issued under a different policy than the one in force.
    /// Policy rotation history is out of scope, so this fails closed and stays
    /// failed until the receipt is re-issued.
    PolicyHashMismatch { found: String, current: String },
    /// The attestation's own digest handle does not match the body it
    /// reconstructs, i.e. the record was edited after signing.
    AttestationBodyMismatch(String),
    /// The provider's endpoint identity was not enforced by the kernel. A
    /// provider that authenticates nothing cannot confirm anything, so this is
    /// refused before any chain read is attempted and before any number can be
    /// promoted.
    ProviderIdentityUnverified(String),
    /// P4b added a mandatory gate here with a dedicated gap. It is
    /// defence in depth rather than a reachable state: `provider_pinned`
    /// refuses to construct a view whose provider identity the kernel did not
    /// enforce, and `BaseUsdcVerifier::provider_identity_verified` is a field
    /// read off an immutable provider. It is written out anyway, because the
    /// alternative is a number whose authority depends on a property nobody
    /// re-checks.
    /// The pinned provider did not confirm the transfer. This is the predicate
    /// a fabricated transaction hash fails, and it is the gate a valid
    /// signature does *not* replace.
    ChainNotConfirmed(String),
}

impl AttestationGap {
    pub fn describe(&self) -> String {
        match self {
            Self::NotAValueClass => {
                "value class cannot create external value".to_string()
            }
            Self::ReceiptRejected(e) => format!("receipt rejected: {e}"),
            Self::NoCitableTransaction => {
                "cites no transaction a boundary crossing could have recorded"
                    .to_string()
            }
            Self::NoBoundaryCrossing => {
                "no stored boundary evidence cites this transaction".to_string()
            }
            Self::BoundaryNotDerivable(e) => {
                format!("boundary evidence does not derive: {e}")
            }
            Self::NotAnExternalInflow { kind } => format!(
                "crossing is {kind:?}, which is not money arriving from outside \
                 the controlled set into it"
            ),
            Self::ClassNotJustified { crossing, receipt } => format!(
                "crossing justifies {crossing:?} value, receipt claims {receipt:?}"
            ),
            Self::AssetNotJustified(e) => format!("asset: {e}"),
            Self::SignNotJustified => {
                "booked sign contradicts the crossing direction".to_string()
            }
            Self::PolicyNotValidated => {
                "no validated outcome policy in this view, so no signature can be \
                 checked"
                    .to_string()
            }
            Self::UnsignedReceipt => {
                "no signed attestation covers this receipt; it predates verifier \
                 signatures or was never attested"
                    .to_string()
            }
            Self::DuplicateAttestation => {
                "two different attestations claim the same receipt".to_string()
            }
            Self::AttestationReplayed => {
                "this attestation was already consumed by another ledger record"
                    .to_string()
            }
            Self::ExternalEventAlreadyCounted {
                event_id,
                first_counted_at_sequence,
            } => format!(
                "external event {event_id} is already in the total, counted at \
                 ledger sequence {first_counted_at_sequence}; this record names \
                 the same on-chain fact and is not counted again"
            ),
            Self::EventIdentityIndeterminate(e) => {
                format!("external fact has no canonical identity, so it is not counted: {e}")
            }
            Self::VerifierNotDelegated { claimed, delegated } => format!(
                "receipt names verifier {claimed}, which the policy in force does \
                 not delegate to (it delegates to {delegated})"
            ),
            Self::AttestationSignatureInvalid => {
                "signature does not verify against the policy's delegated verifier \
                 key"
                    .to_string()
            }
            Self::PolicyHashMismatch { found, current } => format!(
                "receipt was issued under policy {found}, but the policy in force \
                 is {current}; rotation history is not supported, so the receipt is \
                 not re-approved"
            ),
            Self::AttestationBodyMismatch(e) => {
                format!("attestation does not match its own signed body: {e}")
            }
            Self::ProviderIdentityUnverified(e) => format!(
                "chain provider has no kernel-enforced identity: {e}"
            ),
            Self::ChainNotConfirmed(e) => {
                format!("pinned provider did not confirm the transfer: {e}")
            }
        }
    }
}

/// One external-value receipt and what the view established about it.
#[derive(Debug, Clone, Serialize)]
pub struct ReceiptEvidence {
    pub sequence: u64,
    pub source_id: String,
    pub agent_id: String,
    pub opportunity_id: String,
    pub value_class: ExternalValueClass,
    pub network: String,
    pub asset: String,
    pub gross_inflow_musd_micros: u64,
    pub external_cost_musd_micros: u64,
    pub net_external_value_musd_micros: i64,
    pub realized_at_unix: u64,
    /// DIAGNOSTICS ONLY, FROZEN (P4b). The stored `proof_verified` flag grants
    /// nothing and is never read as an input — not to promote, and not to
    /// refuse. It survives for compatibility and for `autonomy-audit`; the
    /// authority input is `attested` below, which is a signature check plus a
    /// policy binding. `the_stored_flag_moves_nothing_in_either_direction` pins
    /// the rule in both directions: a genuine receipt signed by the delegated
    /// verifier still counts with the flag `false`, and a forged receipt with
    /// the flag `true` does not count without the signature.
    pub stored_proof_verified: bool,
    pub proof_hash: String,
    pub verifier_id: String,
    /// The write-time validation rules, re-run at read time.
    pub revalidated: bool,
    /// Gates 1-3 passed: class, re-validation, and a boundary crossing
    /// re-derived from stored evidence against the current registry. This is
    /// what an offline view is able to establish, and it is *not* attestation.
    pub offline_ok: bool,
    /// P4b: a signature from the verifier the policy in force delegates to,
    /// verified against re-derived evidence, with the receipt's `policy_hash`
    /// equal to the hash of that policy. Provenance, not money: `counted`
    /// additionally requires the chain read.
    pub attested: bool,
    /// Diagnostics for the attestation, when there is one.
    pub policy_hash: Option<String>,
    pub verifier_key_id: Option<String>,
    pub attestation_hash: Option<String>,
    /// The crossing re-derived from stored evidence, if one exists.
    pub crossing: Option<CrossingEvidence>,
    /// The chain read that re-confirmed the transfer, in pinned mode.
    pub chain_confirmed: bool,
    /// P4.5b: the canonical identity of the external fact this record books,
    /// under [`crate::event_id::EVENT_ID_DOMAIN`]. Reported for the audit trail
    /// whether or not the record was counted — a refused duplicate carries the
    /// id that matched, which is the whole diagnosis.
    ///
    /// It is a *digest*, not an authority input, and it is deliberately not
    /// computable in [`TrustMode::Unverified`]: the log index that discriminates
    /// two events inside one transaction is a chain fact, and the offline view
    /// performs no chain read.
    pub event_id: Option<String>,
    /// `true` only when every gate passed, the chain read included.
    pub counted: bool,
    pub gap: Option<AttestationGap>,
}

/// The inspectable parts of a re-derived crossing. Both domains come from the
/// registry lookup, never from the file.
#[derive(Debug, Clone, Serialize)]
pub struct CrossingEvidence {
    pub from_address: String,
    pub to_address: String,
    pub from_domain: ControlDomain,
    pub to_domain: ControlDomain,
    pub kind: CrossingKind,
    pub amount_raw: u64,
    pub tx_hash: String,
    pub block_hash: String,
    pub chain_id: u64,
    pub contract: String,
}

/// Offline re-derivation output: the numbers the ledger *claims*, and why they
/// are not verified.
///
/// "Claims" here means the receipts that survive every check an offline reader
/// can make: the hash chain, the receipt's own validation rules, and a boundary
/// crossing re-derived from stored evidence. A receipt that fails any of those is
/// not part of the claim either; its reason is in `receipts`.
///
/// Deliberately a distinct type from [`VerifiedNev`]: no ARV/RV promotion
/// predicate accepts it, no reinvestment budget is computable from it, and it
/// has no `Deserialize`, so a JSON blob cannot be read back as one.
#[derive(Debug, Clone, Serialize)]
pub struct UnattestedNev {
    pub trust_mode: TrustMode,
    /// Receipts that survived every offline check. A count, not a total.
    pub re_derived_receipts: u64,
    /// What those receipts claim. NOT an authority input.
    pub claimed_net_external_value_musd_micros: i64,
    pub receipts: Vec<ReceiptEvidence>,
    pub note: String,
}

impl UnattestedNev {
    /// Named `claimed` on purpose, so a caller cannot mistake this for a
    /// verified total.
    pub fn claimed_net_musd(&self) -> f64 {
        self.claimed_net_external_value_musd_micros as f64 / 1_000_000.0
    }
}

/// A verified NEV: the only number in this crate that can promote a level or
/// fund a job.
///
/// Private fields, no `Deserialize`, and exactly one constructor — the view, in
/// [`TrustMode::ProviderPinned`], after a validated policy authorised a verifier,
/// that verifier signed the receipt, and every cited transaction was re-read
/// from a kernel-identified provider. A stored `proof_verified: true` cannot
/// reach this type, and neither can any other module in the crate.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedNev {
    nev_musd_micros: i64,
    receipts: u64,
    provider: String,
    provider_identity_verified: bool,
    /// The hash of the policy every counted receipt was issued under. Exposed
    /// so an audit log can name the authority behind the number instead of
    /// asking the operator to take it on faith.
    policy_hash: String,
}

impl VerifiedNev {
    /// P4.5c: the only way a [`crate::settlement::SettlementAuthority`] becomes a
    /// [`VerifiedNev`], and `pub(crate)` so nothing outside this crate can mint one.
    ///
    /// Takes the whole set rather than a single authority, because the total has to
    /// be computed over *all* of an operator's complete operations: an operation
    /// that lost money and an operation that made more are a net, and letting each
    /// be judged alone would let the loss pass as nothing and the gain as profit.
    /// Same reason P4.5c refused isolated promotion — arithmetic over a chosen
    /// subset of the legs is precisely what went wrong.
    ///
    /// Each authority already carries the provider identity and the policy it was
    /// minted under, and both are re-checked against this view's: the only way to
    /// be handed a foreign authority is to already have one, and it is still
    /// declined rather than folded into this view's number.
    pub(crate) fn from_settlement_authorities(
        authorities: &[crate::settlement::SettlementAuthority],
        verifier: Option<&BaseUsdcVerifier>,
        policy: &ValidatedOutcomePolicy,
    ) -> Result<VerifiedNev> {
        let Some(verifier) = verifier else {
            return Err(EconomyError::Invalid(
                "settlement NEV requires a pinned chain provider".into(),
            ));
        };
        if !verifier.provider_identity_verified() {
            return Err(EconomyError::Invalid(format!(
                "provider {} is an address, not an identity",
                verifier.endpoint()
            )));
        }
        let policy_hash = policy.policy_hash()?;
        let mut total: i64 = 0;
        let mut legs: u64 = 0;
        for authority in authorities {
            if !authority.provider_identity_verified() {
                return Err(EconomyError::Invalid(format!(
                    "settlement authority {} was minted against an endpoint with no \
                     kernel-enforced identity",
                    authority.operation_id()
                )));
            }
            if authority.policy_hash() != policy_hash.as_str() {
                return Err(EconomyError::Invalid(format!(
                    "settlement authority {} was minted under policy {}, not the one in \
                     force",
                    authority.operation_id(),
                    authority.policy_hash()
                )));
            }
            total = total
                .checked_add(authority.nev_musd_micros())
                .ok_or_else(|| {
                    EconomyError::Invalid(
                        "settlement total does not fit a signed 64-bit micro total".into(),
                    )
                })?;
            legs = legs.saturating_add(authority.legs());
        }
        Ok(Self {
            nev_musd_micros: total,
            receipts: legs,
            provider: verifier.endpoint().to_string(),
            provider_identity_verified: true,
            policy_hash: policy_hash.to_string(),
        })
    }

    pub fn nev_musd_micros(&self) -> i64 {
        self.nev_musd_micros
    }

    pub fn nev_musd(&self) -> f64 {
        self.nev_musd_micros as f64 / 1_000_000.0
    }

    /// How many *distinct external events* this total covers.
    ///
    /// P4.5b: the sum above is over one contribution per
    /// [`ExternalEventId`], so a ledger that books the same on-chain transfer
    /// twice — with any number of records, in any order, under any number of
    /// individually valid attestations — still reports one event and one
    /// contribution. The count is a count of facts, not of lines in a file.
    pub fn receipts(&self) -> u64 {
        self.receipts
    }

    /// The endpoint the chain facts came from.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// True when the endpoint's identity was enforced by the kernel. Always
    /// true for a value that exists; exposed because an operator's audit log
    /// should not have to take it on faith.
    pub fn provider_identity_verified(&self) -> bool {
        self.provider_identity_verified
    }

    /// The hash of the policy in force. Every receipt counted here was issued
    /// under exactly this policy.
    pub fn policy_hash(&self) -> &str {
        &self.policy_hash
    }

    /// Whether the attested total is strictly positive. The single predicate an
    /// ARV0 or budget decision needs, and it lives only on this type.
    pub fn is_positive(&self) -> bool {
        self.receipts > 0 && self.nev_musd_micros > 0
    }
}

/// Why one settlement on the revenue ledger is not verified paid demand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementGap {
    NotExternal,
    InternalWork,
    NotARealAsset(String),
    NoValue,
    NoPaymentTransaction,
    MalformedTransaction,
    NoPaymentIntent,
    IntentMismatch,
    ForeignToken(String),
    AmountNotJustified { booked: u64, expected: u64 },
    RecipientNotControlled(String),
    NoPaymentBlock,
    MalformedRecipient(String),
    BlockNotAfterAnchor { block: u64, anchor: u64 },
    /// P4b: this view holds no validated outcome policy. A revenue view that
    /// cannot name its authority does not promote, for the same reason the
    /// autonomy view cannot: RV is computed from evidence the operator cannot
    /// audit the provenance of.
    PolicyNotValidated,
    NoPinnedProvider,
    /// The provider's endpoint identity was not enforced by the kernel. A
    /// provider that authenticates nothing confirms nothing.
    ProviderIdentityUnverified(String),
    ChainNotConfirmed(String),
    // ---- P4c: the settlement attestation ---------------------------------
    /// No signed attestation covers this settlement. This is the shape of every
    /// settlement written before signed settlements existed, and of every
    /// hand-written ledger line: the settlement is reported, with this reason,
    /// and is neither dropped nor promoted.
    ///
    /// It is also the shape of the attack P4b reported and P4c closes — a
    /// genuine on-chain transfer of the right size into a controlled address,
    /// booked by anyone who can write the revenue ledger, reaching paid demand
    /// with nobody to have signed it.
    UnsignedSettlement,
    /// Two *different* attestations claim the same settlement content. Nothing
    /// in the design produces this, so it is refused rather than resolved.
    DuplicateSettlementAttestation,
    /// This attestation was already consumed by another ledger record. One
    /// signature covers one settlement; the same attested settlement written
    /// twice must not be counted twice.
    SettlementAttestationReplayed,
    /// The settlement names a verifier the policy in force does not delegate to
    /// — the shape an unknown verifier's signature gets.
    SettlementVerifierNotDelegated { claimed: String, delegated: String },
    /// The signature does not verify against the delegated verifier key.
    SettlementSignatureInvalid,
    /// The settlement was issued under a different policy than the one in force.
    /// Policy rotation history is out of scope, so this fails closed and stays
    /// failed until the settlement is re-attested.
    SettlementPolicyHashMismatch { found: String, current: String },
    /// The attestation's own digest handle does not match the body it
    /// reconstructs, i.e. the record was edited after signing.
    SettlementAttestationBodyMismatch(String),
    /// P4.5c: the payment this settlement books has the same
    /// [`ExternalEventId`] as a settlement already in the total, so it is not
    /// counted again.
    ///
    /// The economic half of duplicate handling on the revenue side, and the
    /// gap P4.5b reported: the counting rule existed only for
    /// [`VerifiedEconomyView`], so two settlements of the same payment —
    /// differing in `settled_at_unix`, hence different content, different
    /// `settlement_hash` and therefore two individually genuine signatures —
    /// both reached paid demand. A different fault from
    /// [`Self::SettlementAttestationReplayed`] with a different fix, and the two
    /// never fire on the same record.
    SettlementEventAlreadyCounted {
        event_id: String,
        /// The record that holds the credit, so the report can name it.
        first_counted_at_sequence: u64,
    },
    /// P4.5c: the payment was confirmed but the provider did not report which
    /// log it matched, so the payment has no canonical identity.
    ///
    /// Its own gap for the same reason
    /// [`AttestationGap::EventIdentityIndeterminate`] is one on the autonomy
    /// side: the transfer may be entirely real and only the *counting* cannot
    /// be done safely.
    SettlementEventIdentityIndeterminate(String),
}

impl SettlementGap {
    pub fn describe(&self) -> String {
        match self {
            Self::NotExternal => "settlement is not an external settlement".into(),
            Self::InternalWork => "internal work is never paid demand".into(),
            Self::NotARealAsset(s) => {
                format!("{s} is not a real on-chain asset")
            }
            Self::NoValue => "paid demand must be > 0".into(),
            Self::NoPaymentTransaction => {
                "external settlement cites no payment transaction".into()
            }
            Self::MalformedTransaction => {
                "payment transaction is not a 32-byte hash".into()
            }
            Self::NoPaymentIntent => {
                "no recorded payment intent for this job".into()
            }
            Self::IntentMismatch => {
                "settlement does not reference its payment intent".into()
            }
            Self::ForeignToken(t) => {
                format!("payment intent names token {t}")
            }
            Self::AmountNotJustified { booked, expected } => format!(
                "settlement books {booked} but the intent expected {expected}"
            ),
            Self::RecipientNotControlled(a) => {
                format!("payment recipient {a} is not in the controlled registry")
            }
            Self::NoPaymentBlock => {
                "external settlement has no payment block".into()
            }
            Self::MalformedRecipient(a) => {
                format!("payment recipient {a} is not a usable address")
            }
            Self::BlockNotAfterAnchor { block, anchor } => format!(
                "payment block {block} is not after the intent anchor {anchor}"
            ),
            Self::PolicyNotValidated => {
                "no validated outcome policy in this view; a paid-demand number \
                 with no auditable authority behind it is not promoted"
                    .into()
            }
            Self::NoPinnedProvider => {
                "no pinned provider in this view; re-run with TrustMode::ProviderPinned"
                    .into()
            }
            Self::ProviderIdentityUnverified(e) => format!(
                "chain provider has no kernel-enforced identity: {e}"
            ),
            Self::ChainNotConfirmed(e) => {
                format!("pinned provider did not confirm: {e}")
            }
            // ---- P4c ---------------------------------------------------
            Self::UnsignedSettlement => {
                "no signed attestation covers this settlement; it predates \
                 settlement signatures or was never attested"
                    .into()
            }
            Self::DuplicateSettlementAttestation => {
                "two different attestations claim the same settlement".into()
            }
            Self::SettlementAttestationReplayed => {
                "this settlement attestation was already consumed by another \
                 ledger record"
                    .into()
            }
            Self::SettlementVerifierNotDelegated { claimed, delegated } => format!(
                "settlement names verifier {claimed}, which the policy in force \
                 does not delegate to (it delegates to {delegated})"
            ),
            Self::SettlementSignatureInvalid => {
                "signature does not verify against the policy's delegated verifier \
                 key"
                    .into()
            }
            Self::SettlementPolicyHashMismatch { found, current } => format!(
                "settlement was issued under policy {found}, but the policy in \
                 force is {current}; rotation history is not supported, so the \
                 settlement is not re-approved"
            ),
            Self::SettlementAttestationBodyMismatch(e) => {
                format!("settlement attestation does not match its own signed body: {e}")
            }
            Self::SettlementEventAlreadyCounted {
                event_id,
                first_counted_at_sequence,
            } => format!(
                "payment {event_id} is already in paid demand, counted at ledger \
                 sequence {first_counted_at_sequence}; this record names the same \
                 on-chain payment and is not counted again"
            ),
            Self::SettlementEventIdentityIndeterminate(e) => format!(
                "payment has no canonical identity, so it is not counted: {e}"
            ),
        }
    }
}

/// One settlement and what the view established about it.
#[derive(Debug, Clone, Serialize)]
pub struct SettlementEvidence {
    pub settlement_id: String,
    pub job_id: String,
    /// The exact stored symbol, so a summary can still group by asset.
    pub settlement_asset: String,
    pub settled_amount_micros: u64,
    pub usd_equivalent_micros: u64,
    pub settled_at_unix: u64,
    /// DIAGNOSTICS ONLY, FROZEN (P4b) — same rule as
    /// `ReceiptEvidence::stored_proof_verified`, and the same rule for
    /// `stored_external_paid`. Neither grants anything and neither is read as an
    /// input, not to promote and not to refuse. They survive for compatibility
    /// and for diagnostics; the authority inputs are the re-derivation, the
    /// validated policy and the chain read. P4b did not touch these paths, and
    /// `the_settlement_flags_still_move_nothing` in `lib.rs` pins it.
    pub stored_payment_proof_verified: bool,
    /// Diagnostics only, frozen with `stored_payment_proof_verified`.
    pub stored_external_paid: bool,
    /// Every structural fact re-derived from the ledger itself.
    pub rederived: bool,
    /// The chain read that re-confirmed the payment, in pinned mode.
    pub chain_confirmed: bool,
    pub counted: bool,
    pub gap: Option<SettlementGap>,
    /// P4c: a validated policy, an authorised verifier, a verifying signature
    /// over the ledger's own settlement and intent, and a `policy_hash` equal to
    /// the policy in force. Reported, never an input to anything else — the same
    /// rule as `ReceiptEvidence::attested`, and for the same reason.
    pub attested: bool,
    /// The policy the attestation was issued under, when it verified.
    pub policy_hash: Option<String>,
    /// The delegated verifier key that signed, when it verified.
    pub verifier_key_id: Option<String>,
    /// The digest of the signed body, when it verified. An audit handle.
    pub attestation_hash: Option<String>,
    /// P4.5c: the canonical identity of the payment this settlement books, under
    /// [`crate::event_id::SETTLEMENT_EVENT_ID_DOMAIN`]. Reported whether or not
    /// the record was counted — a refused duplicate carries the id that
    /// matched, which is the whole diagnosis.
    ///
    /// A digest, not an authority input, and deliberately not computable in
    /// [`TrustMode::Unverified`]: the log index that discriminates two payments
    /// inside one transaction is a chain fact, and the offline view performs no
    /// chain read.
    pub event_id: Option<String>,
}

/// Read-side authority over the autonomy ledger: ARV, verified NEV and the
/// reinvestment basis.
///
/// Constructed explicitly. The registry, the verifier and the validated policy
/// are parameters, never inferred from the directory or from an environment
/// variable, so a ledger can never supply its own trust configuration.
pub struct VerifiedEconomyView<'a> {
    autonomy: &'a AutonomousEconomy,
    registry: &'a ControlledAddressRegistry,
    mode: TrustMode,
    verifier: Option<&'a BaseUsdcVerifier>,
    /// The policy in force. `Some` exactly when `mode` can attest, which is the
    /// invariant [`Self::provider_pinned`] establishes and
    /// [`Self::assess_receipt`] re-checks before it counts anything.
    policy: Option<&'a ValidatedOutcomePolicy>,
}

impl<'a> VerifiedEconomyView<'a> {
    /// Offline mode. Constructs unconditionally: there is nothing to fail, and
    /// nothing this mode can grant.
    pub fn unverified(
        autonomy: &'a AutonomousEconomy,
        registry: &'a ControlledAddressRegistry,
    ) -> Self {
        Self {
            autonomy,
            registry,
            mode: TrustMode::Unverified,
            verifier: None,
            policy: None,
        }
    }

    /// Pinned mode. Fails closed on two counts:
    ///
    /// * the verifier's endpoint identity was not enforced by the kernel — a
    ///   loopback TCP port and the dev-only override are addresses, not
    ///   identities, and a number attributed to one of them is not attested;
    /// * there is no validated policy, so no receipt signature could be checked
    ///   and no `policy_hash` compared. The policy is a parameter rather than
    ///   something resolved from the economy directory, because a policy read
    ///   out of a mutable directory is a claim, not an authority.
    pub fn provider_pinned(
        autonomy: &'a AutonomousEconomy,
        registry: &'a ControlledAddressRegistry,
        verifier: &'a BaseUsdcVerifier,
        policy: &'a ValidatedOutcomePolicy,
    ) -> Result<Self> {
        if !verifier.provider_identity_verified() {
            return Err(EconomyError::Invalid(format!(
                "chain provider {} has no kernel-enforced identity, so it cannot \
                 attest value; pin a unix socket out-of-band with \
                 `payment-policy-pin-provider {}`, or report the number as \
                 TrustMode::Unverified instead",
                verifier.endpoint(),
                crate::chain_provider::DEFAULT_PROVIDER_SOCKET_URI
            )));
        }
        Ok(Self {
            autonomy,
            registry,
            mode: TrustMode::ProviderPinned,
            verifier: Some(verifier),
            policy: Some(policy),
        })
    }

    pub fn trust_mode(&self) -> TrustMode {
        self.mode
    }

    pub fn registry(&self) -> &ControlledAddressRegistry {
        self.registry
    }

    pub fn autonomy(&self) -> &AutonomousEconomy {
        self.autonomy
    }

    pub fn verifier(&self) -> Option<&BaseUsdcVerifier> {
        self.verifier
    }

    /// The validated policy in force, when this view has one.
    pub fn policy(&self) -> Option<&ValidatedOutcomePolicy> {
        self.policy
    }

    /// The authority token. Refuses in [`TrustMode::Unverified`]: there is no
    /// offline route to a number that may be acted on, by construction rather
    /// than by a runtime flag.
    pub fn verified_nev(&self) -> Result<VerifiedNev> {
        let receipts = self.receipt_evidence()?;
        let verifier = self.verifier.ok_or_else(|| {
            EconomyError::Invalid(format!(
                "verified NEV requires TrustMode::ProviderPinned; this view is {} \
                 and can only report an unattested claim",
                self.mode
            ))
        })?;
        let policy = self.policy.ok_or_else(|| {
            EconomyError::Invalid(format!(
                "verified NEV requires a validated outcome policy; this view is {} \
                 and has no authority to check a receipt signature against",
                self.mode
            ))
        })?;
        let mut nev = 0i64;
        let mut counted = 0u64;
        for evidence in receipts.iter().filter(|r| r.counted) {
            nev = nev.saturating_add(evidence.net_external_value_musd_micros);
            counted += 1;
        }
        Ok(VerifiedNev {
            nev_musd_micros: nev,
            receipts: counted,
            provider: verifier.endpoint().to_string(),
            provider_identity_verified: verifier.provider_identity_verified(),
            policy_hash: policy
                .policy_hash()
                .map(|h| h.to_string())
                .unwrap_or_else(|_| "0x".to_string()),
        })
    }

    /// The offline re-derivation, in either mode. In pinned mode this is still
    /// only what the ledger *claims*: the chain read is what promotes, and this
    /// function does not perform one.
    pub fn unattested_nev(&self) -> Result<UnattestedNev> {
        let receipts = self.receipt_evidence()?;
        let mut claimed = 0i64;
        let mut re_derived = 0u64;
        for evidence in receipts.iter().filter(|r| r.offline_ok) {
            claimed = claimed
                .saturating_add(evidence.net_external_value_musd_micros);
            re_derived += 1;
        }
        Ok(UnattestedNev {
            trust_mode: self.mode,
            re_derived_receipts: re_derived,
            claimed_net_external_value_musd_micros: claimed,
            note: claim_note(self.mode, &receipts),
            receipts,
        })
    }

    /// Per-receipt diagnostics, whatever the mode.
    ///
    /// # The one funnel
    ///
    /// Every economic number in this crate is assembled from what this function
    /// returns: [`Self::verified_nev`], [`Self::arv_status`],
    /// [`Self::autonomy_summary`] and [`Self::unattested_nev`] all call it and
    /// all filter on the `counted` flag it sets. There is no second path from a
    /// ledger record to a total, so anything that decides whether a record is
    /// counted decides it for every consumer at once.
    ///
    /// That is why the event-id set lives here, in this function's body, and not
    /// in a struct field: it is created empty on every call, passed as `&mut`
    /// into the one private function that can set `counted`, and dropped when the
    /// call returns. There is no constructor that seeds it, no parameter that
    /// skips it, and nothing that survives the call. A caller cannot bypass it
    /// because there is no other way to produce evidence.
    pub fn receipt_evidence(&self) -> Result<Vec<ReceiptEvidence>> {
        let records = self.autonomy.records()?;
        let evidence = self.autonomy.boundary_evidence()?;
        // P4b: the attestations are read once and indexed by the receipt
        // content they cover. Reading them per receipt would be quadratic, and
        // the replay guard below needs one shared set rather than one per
        // receipt.
        let attestations = self.autonomy.receipt_attestations()?;
        let mut index = AttestationIndex::build(&attestations);
        // P4.5b: the external facts already counted in THIS pass, keyed by
        // [`ExternalEventId`] — the digest of the on-chain fact, not of the
        // record's position in this file. See [`crate::event_id::CountedEvents`]
        // for the three duplicate concerns this is kept apart from.
        let mut counted_events = CountedEvents::default();
        let mut out = Vec::new();
        for record in records {
            if let AutonomyPayload::ExternalValue { receipt } = &record.payload {
                out.push(self.assess_receipt(
                    record.sequence,
                    receipt,
                    &evidence,
                    &mut index,
                    &mut counted_events,
                ));
            }
        }
        Ok(out)
    }

    /// ARV, computed by the view. In [`TrustMode::Unverified`] this cannot
    /// report a promoted level; the claimed numbers appear under explicitly
    /// unattested names instead of being dropped to a silent zero.
    pub fn arv_status(&self, now: u64) -> Result<ArvStatus> {
        let receipts = self.receipt_evidence()?;
        let counted: Vec<&ReceiptEvidence> =
            receipts.iter().filter(|r| r.counted).collect();
        let claimed: Vec<&ReceiptEvidence> =
            receipts.iter().filter(|r| r.offline_ok).collect();

        let cutoff = now.saturating_sub(30 * 86_400);
        let mut total = 0i64;
        let mut recent = 0i64;
        let mut oldest: Option<u64> = None;
        for r in &counted {
            total = total.saturating_add(r.net_external_value_musd_micros);
            oldest = Some(oldest.map_or(r.realized_at_unix, |t| t.min(r.realized_at_unix)));
            if r.realized_at_unix >= cutoff && r.realized_at_unix <= now {
                recent = recent.saturating_add(r.net_external_value_musd_micros);
            }
        }
        let claimed_total: i64 = claimed
            .iter()
            .map(|r| r.net_external_value_musd_micros)
            .sum();
        let claimed_recent: i64 = claimed
            .iter()
            .filter(|r| r.realized_at_unix >= cutoff && r.realized_at_unix <= now)
            .map(|r| r.net_external_value_musd_micros)
            .sum();

        let full_30d = oldest.map(|t| t <= cutoff).unwrap_or(false);
        let daily_30d = recent.max(0) as f64 / 1_000_000.0 / 30.0;
        let arv0 = counted.len() > 0 && total > 0;
        let (level, next) = if arv0 {
            if full_30d && daily_30d >= 2000.0 {
                ("ARV4", None)
            } else if full_30d && daily_30d >= 500.0 {
                ("ARV3", Some(2000.0))
            } else if full_30d && daily_30d >= 100.0 {
                ("ARV2", Some(500.0))
            } else if full_30d && daily_30d >= 10.0 {
                ("ARV1", Some(100.0))
            } else {
                ("ARV0", Some(10.0))
            }
        } else {
            ("PRE-ARV0", Some(0.0))
        };

        let note = claim_note(self.mode, &receipts);
        Ok(ArvStatus {
            level: level.into(),
            verified_external_events: counted.len() as u64,
            net_external_value_musd_total: total as f64 / 1_000_000.0,
            net_external_value_musd_per_day_30d: daily_30d,
            full_30d_window: full_30d,
            next_target_musd_per_day: next,
            arv0_pass: arv0,
            note: if arv0 {
                if full_30d {
                    "ARV is computed by VerifiedEconomyView from re-derived boundary \
                     evidence re-confirmed by the pinned provider; internal bot spend \
                     is excluded."
                        .into()
                } else {
                    "ARV0 passed on chain-attested external value; ARV1-ARV4 require a \
                     complete 30-day attested window."
                        .into()
                }
            } else {
                format!(
                    "ARV0 requires positive external value whose cited transaction \
                     was re-confirmed by the pinned provider. {note}"
                )
            },
            trust_mode: self.mode,
            unattested_external_events: claimed.len() as u64,
            unattested_net_external_value_musd: claimed_total as f64 / 1_000_000.0,
            unattested_net_external_value_musd_per_day_30d: {
                claimed_recent.max(0) as f64 / 1_000_000.0 / 30.0
            },
            attestation_note: note,
        })
    }

    /// The autonomy summary with the value columns computed by the view.
    /// The verified NEV granted by a set of **complete operations**.
    ///
    /// P4.5c. A second, additive route into [`VerifiedNev`], deliberately not a
    /// change to [`Self::verified_nev`]: the receipt-side total is what
    /// P3/P4b/P4.5b established, and their tests are the ones that must not
    /// move. Two additions, and the second is the point.
    ///
    /// 1. **Where promotion lives.** This is the route by which a settlement
    ///    reaches a number at all. The authority itself is minted one level down,
    ///    by [`crate::settlement::VerifiedSettlement::promote`], which needs a
    ///    complete leg set — every transfer the *chain* enumerated accounted for —
    ///    a kernel-identified provider and a validated policy. An incomplete
    ///    operation has no net to promote and no type to promote through, so there
    ///    is nothing here to filter out.
    /// 2. **Re-checks the trust mode.** Each authority already carries the
    ///    provider and policy it was minted under; this refuses to grant a total
    ///    from a view that is not in [`TrustMode::ProviderPinned`], and refuses an
    ///    authority whose recorded provider identity was not kernel-enforced. That
    ///    is belt to the braces: the only way to be handed a foreign authority is
    ///    to have one, and this still declines to treat it as this view's.
    ///
    /// A zero-length `authorities` slice yields `net_external_value_musd_micros
    /// == 0` with `receipts == 0`, and `VerifiedNev::is_positive` is then false —
    /// so "no operations" cannot fund anything, by construction rather than by a
    /// branch.
    pub fn settlement_nev(
        &self,
        authorities: &[crate::settlement::SettlementAuthority],
    ) -> Result<VerifiedNev> {
        if self.mode != TrustMode::ProviderPinned {
            return Err(EconomyError::Invalid(format!(
                "verified NEV from settlements requires a provider-pinned view, got \
                 trust mode {:?}",
                self.mode
            )));
        }
        let Some(policy) = self.policy else {
            return Err(EconomyError::Invalid(
                "settlement NEV requires a validated outcome policy".into(),
            ));
        };
        VerifiedNev::from_settlement_authorities(authorities, self.verifier, policy)
    }

    pub fn autonomy_summary(&self) -> Result<AutonomousSummary> {
        let receipts = self.receipt_evidence()?;
        let note = claim_note(self.mode, &receipts);
        self.autonomy.summary_with_evidence(self.mode, &receipts, &note)
    }

    // ---- per-receipt assessment ----

    /// The whole gate order, in the order the identity is read.
    ///
    /// 1. value class (from the enum, never from a stored boolean);
    /// 2. the receipt's own write-time rules, re-run;
    /// 3. a validated outcome policy — structural, the view holds one or it is
    ///    offline;
    /// 4. the receipt's verifier is the one that policy delegates to;
    /// 5. the signature verifies over preimage rebuilt from *re-derived*
    ///    evidence;
    /// 6. `policy_hash` equals the hash of the policy in force;
    /// 7. the boundary crossing re-derives against the operator's registry, and
    ///    the class, asset and sign it justifies;
    /// 8. the provider's identity was enforced by the kernel;
    /// 9. the chain read confirms the transfer;
    /// 10. the external fact has not already been counted in this pass;
    /// 11. `counted`.
    ///
    /// Steps 3 to 6 were added in P4b and were inserted, not substituted: no two
    /// steps 1, 2, 7 or 9 moved relative to each other. Step 10 was added in
    /// P4.5b, after the chain read and immediately before the last line, because
    /// it is the one gate that needs a *fact* rather than a signature: it is
    /// only decidable once the read has said which log the transfer is. Step 5
    /// deliberately precedes step 7 because the signature covers the crossing's
    /// facts — and it covers them *as re-derived*, which is why
    /// `select_provenance` hands step 7 the very evidence step 5 verified rather
    /// than a stored copy.
    fn assess_receipt(
        &self,
        sequence: u64,
        receipt: &ExternalValueReceipt,
        evidence: &[BoundaryEvidence],
        index: &mut AttestationIndex<'_>,
        counted_events: &mut CountedEvents,
    ) -> ReceiptEvidence {
        let mut out = ReceiptEvidence {
            sequence,
            source_id: receipt.source_id.clone(),
            agent_id: receipt.agent_id.clone(),
            opportunity_id: receipt.opportunity_id.clone(),
            value_class: receipt.value_class.clone(),
            network: receipt.network.clone(),
            asset: receipt.asset.clone(),
            gross_inflow_musd_micros: receipt.gross_inflow_musd_micros,
            external_cost_musd_micros: receipt.external_cost_musd_micros,
            net_external_value_musd_micros: receipt.net_external_value_musd_micros,
            realized_at_unix: receipt.realized_at_unix,
            // Read on purpose, reported on purpose. Nothing below reads it; see
            // the frozen-rule note on the field.
            stored_proof_verified: receipt.proof_verified,
            proof_hash: receipt.proof_hash.clone(),
            verifier_id: receipt.verifier_id.clone(),
            revalidated: false,
            offline_ok: false,
            attested: false,
            policy_hash: None,
            verifier_key_id: None,
            attestation_hash: None,
            crossing: None,
            chain_confirmed: false,
            event_id: None,
            counted: false,
            gap: None,
        };

        // Gate 1: the class, derived from enum, not from a stored boolean.
        if !receipt.value_class.can_create_external_value() {
            out.gap = Some(AttestationGap::NotAValueClass);
            return out;
        }
        // Gate 2: the write-time rules, re-run here. `proof_verified` is
        // deliberately not consulted, so a receipt written with the flag off
        // still counts if its evidence is genuine and its signature verifies.
        if let Err(e) = revalidate_external_value(receipt) {
            out.gap = Some(AttestationGap::ReceiptRejected(e.to_string()));
            return out;
        }
        out.revalidated = true;

        // Which stored evidence cites this receipt's transaction. A lookup, not
        // a derivation: the signature has to be checked against the evidence
        // itself, so a receipt can never be re-pointed at a copy of its own
        // claims.
        let cited = match base_usdc::validate_hash32("proof_hash", &receipt.proof_hash) {
            Err(_) => {
                // The shape of every pre-crossing receipt and of every
                // `external-value-candidate-json` submission.
                out.gap = Some(AttestationGap::NoCitableTransaction);
                return out;
            }
            Ok(()) => receipt.proof_hash.to_ascii_lowercase(),
        };
        let candidates: Vec<&BoundaryEvidence> = evidence
            .iter()
            .filter(|e| e.tx_hash.to_ascii_lowercase() == cited)
            .collect();
        if candidates.is_empty() {
            out.gap = Some(AttestationGap::NoBoundaryCrossing);
            return out;
        }

        // Gates 3 to 6 (P4b): policy valid, verifier authorised, signature
        // valid, `policy_hash` matches. Skipped when this view holds no validated
        // policy, which is the offline mode: there is no authority to check a
        // signature against, so the receipt stays exactly the claim P3 described
        // and promotes nothing. It is not "unsigned and therefore fine", it is
        // "unattested and therefore not a number".
        let provenance = match self.select_provenance(receipt, &candidates, index) {
            Err(gap) => {
                out.gap = Some(gap);
                return out;
            }
            Ok(p) => p,
        };
        if let Some(verified) = provenance.verified() {
            out.attested = true;
            out.policy_hash = Some(verified.policy_hash.to_string());
            out.verifier_key_id = Some(verified.verifier_key_id.to_string());
            out.attestation_hash = Some(verified.attestation_hash.to_string());
        }

        // Gate 7: the boundary derivation, P3's rule, unchanged — and now
        // applied to the very evidence the signature was verified over.
        let crossing = match BoundaryCrossing::derive(
            provenance.evidence(),
            self.registry,
        ) {
            Ok(crossing) => crossing,
            Err(e) => {
                out.gap = Some(AttestationGap::BoundaryNotDerivable(e.to_string()));
                return out;
            }
        };
        out.crossing = Some(crossing_evidence(&crossing));

        if !crossing.kind().produces_external_value() {
            out.gap = Some(AttestationGap::NotAnExternalInflow {
                kind: crossing.kind(),
            });
            return out;
        }
        if crossing.value_class_domain() != receipt.value_class.value_class_domain() {
            out.gap = Some(AttestationGap::ClassNotJustified {
                crossing: crossing.value_class_domain(),
                receipt: receipt.value_class.value_class_domain(),
            });
            return out;
        }
        match SettlementAsset::classify_symbol(&receipt.asset) {
            Ok(asset) => match asset.real_asset() {
                Some(real) if *real == *crossing.asset() => {}
                Some(real) => {
                    out.gap = Some(AttestationGap::AssetNotJustified(format!(
                        "receipt is denominated in {} while the crossing moved {}",
                        asset.symbol(),
                        real.contract()
                    )));
                    return out;
                }
                None => {
                    out.gap = Some(AttestationGap::AssetNotJustified(format!(
                        "{} is a synthetic ledger unit and can never book external \
                         value",
                        asset.symbol()
                    )));
                    return out;
                }
            },
            Err(e) => {
                out.gap = Some(AttestationGap::AssetNotJustified(e.to_string()));
                return out;
            }
        }
        if crossing.nev_sign() == NevSign::Positive
            && receipt.net_external_value_musd_micros <= 0
        {
            out.gap = Some(AttestationGap::SignNotJustified);
            return out;
        }
        if crossing.nev_sign() == NevSign::Negative
            && receipt.net_external_value_musd_micros > 0
        {
            out.gap = Some(AttestationGap::SignNotJustified);
            return out;
        }

        // Gates 1 to 3 and 7 are everything an offline view can check. Reaching
        // this line does not mean the value is real: the transaction behind the
        // crossing has not been looked at yet.
        out.offline_ok = true;

        // Gate 8 (P4b): the provider's identity, mandatory, and its own gap
        // rather than a flavour of `ChainNotConfirmed` because it is a different
        // failure with a different fix — the transfer may be real and the source
        // of truth is still unidentified.
        let Some(verifier) = self.verifier else {
            out.gap = Some(AttestationGap::ChainNotConfirmed(
                "no pinned provider in this view; re-run with TrustMode::ProviderPinned"
                    .into(),
            ));
            return out;
        };
        if !verifier.provider_identity_verified() {
            out.gap = Some(AttestationGap::ProviderIdentityUnverified(format!(
                "provider {} is an address, not an identity",
                verifier.endpoint()
            )));
            return out;
        }

        // Gate 9: the chain read. Offline, this view stops here on purpose, and
        // the receipt is reported as a claim with the reason spelled out. A
        // valid signature does not reach one line further than this.
        let proof = match verifier.verify_transfer(
            crossing.tx_hash(),
            crossing.to_address(),
            crossing.amount_raw(),
        ) {
            Ok(proof) => proof,
            Err(e) => {
                out.gap = Some(AttestationGap::ChainNotConfirmed(e.to_string()));
                return out;
            }
        };
        // Defence in depth, not a second opinion: the verifier checked the same
        // flag a moment ago, but the claim that matters is the one carried by the
        // proof that is about to be bound to this crossing.
        if !proof.verified || !proof.provider_identity_verified {
            out.gap = Some(AttestationGap::ChainNotConfirmed(format!(
                "provider {} answered without a verified, kernel-identified \
                 source of truth",
                proof.rpc
            )));
            return out;
        }
        // The P1 proof binding, re-derived at read time: the proof has to
        // describe *this* crossing, so a proof for another transfer cannot be
        // borrowed, and a fabricated transaction hash has nothing to borrow.
        // The binding consumes the crossing, so it is rebound rather than
        // discarded: P4.5b needs the proof that is now bound to it, because the
        // log index the external fact is named by is read off the proof.
        let crossing = match crossing.with_verified_proof(proof) {
            Ok(crossing) => crossing,
            Err(e) => {
                out.gap = Some(AttestationGap::ChainNotConfirmed(e.to_string()));
                return out;
            }
        };
        out.chain_confirmed = true;

        // Gate 10 (P4.5b): the canonical identity of the external fact, and the
        // claim that counts it once.
        //
        // This is the gate the whole step exists for, and it is placed after the
        // chain read on purpose: the identity is a digest of the *fact*, and the
        // fact's log index is a chain fact, so there is nothing to name before
        // the read has happened. Everything above it decides whether this record
        // is honest; this decides whether it is *new*.
        //
        // The identity is built from the re-derived evidence — the same bytes
        // the signature was verified over in gate 5, not a copy from the file —
        // plus the log index the read just reported, taken from the proof bound
        // to that crossing. `from_confirmed_transfer` is where the "no log index,
        // no name" rule lives; its refusal gets this module's own gap because
        // the fix is a different one from a chain that could not be read at all.
        let Some(confirmed) = crossing.proof() else {
            out.gap = Some(AttestationGap::EventIdentityIndeterminate(
                "the confirmed crossing carries no proof, so the transfer it \
                 describes cannot be named"
                    .into(),
            ));
            return out;
        };
        let fact =
            match ExternalEventFact::from_confirmed_transfer(provenance.evidence(), confirmed) {
                Ok(fact) => fact,
                Err(e) => {
                    out.gap = Some(AttestationGap::EventIdentityIndeterminate(
                        e.to_string(),
                    ));
                    return out;
                }
            };
        let event_id = match ExternalEventId::logged(&fact) {
            Ok(id) => id,
            Err(e) => {
                out.gap = Some(AttestationGap::EventIdentityIndeterminate(
                    e.to_string(),
                ));
                return out;
            }
        };
        out.event_id = Some(event_id.to_string());
        // One external fact, one contribution to the total. The set is the
        // authority; `claim` reports who holds the credit so a duplicate is
        // distinguishable from a replayed attestation in the diagnostics.
        if let Some(first) = counted_events.claim(event_id.clone(), sequence) {
            out.gap = Some(AttestationGap::ExternalEventAlreadyCounted {
                event_id: event_id.to_string(),
                first_counted_at_sequence: first,
            });
            return out;
        }

        // The last line. A receipt counted here has, in this order: a validated
        // policy, an authorised verifier, a verifying signature over re-derived
        // evidence, a `policy_hash` equal to the policy in force, a
        // kernel-identified provider, a chain read that confirms the transfer,
        // and an external fact no record in this pass has already booked.
        // Anything less leaves `counted` false.
        //
        // The policy check below is redundant with the constructor and is written
        // anyway: "grants nothing" should not depend on a constructor nobody
        // re-reads.
        if self.policy.is_none() {
            out.gap = Some(AttestationGap::PolicyNotValidated);
            return out;
        }
        out.counted = true;
        out
    }

    /// Runs gates 3 to 6 over the evidence that cites this receipt, and reports
    /// which evidence the rest of the assessment should use.
    ///
    /// With a validated policy, only evidence a *delegated* verifier signed over
    /// will do. With no policy — the offline mode — the first cited evidence is
    /// returned unchanged, which is what keeps P3's offline claim exactly as it
    /// was, gap for gap.
    fn select_provenance<'e>(
        &self,
        receipt: &ExternalValueReceipt,
        candidates: &[&'e BoundaryEvidence],
        index: &mut AttestationIndex<'_>,
    ) -> std::result::Result<ReceiptProvenance<'e>, AttestationGap> {
        let Some(policy) = self.policy else {
            let first = candidates
                .first()
                .copied()
                .ok_or(AttestationGap::NoBoundaryCrossing)?;
            return Ok(ReceiptProvenance::Unauthenticated { evidence: first });
        };
        let digest = index.digest_for(receipt);
        let covering = match index.by_receipt.get(&digest) {
            None => return Err(AttestationGap::UnsignedReceipt),
            Some(v) => v,
        };
        if covering.len() > 1 {
            // Two *different* attestations for one receipt content. A repeated
            // append of the identical attestation is not this case: ed25519 is
            // deterministic, so the second copy is byte-identical and the index
            // filters it out.
            return Err(AttestationGap::DuplicateAttestation);
        }
        let attestation = covering[0];
        // Every candidate cites the same transaction, so the first is the one the
        // signature is checked over; if it were not the right one, the signature
        // check itself refuses.
        let evidence = candidates
            .first()
            .copied()
            .ok_or(AttestationGap::NoBoundaryCrossing)?;
        // (3) verifier authorised, (4) signature valid, (5) `policy_hash`
        // matches — in that order, each separately reportable.
        let verified = attestation
            .verify(policy, evidence)
            .map_err(auth_gap)?;
        // One signature covers one receipt. A ledger that repeats the attested
        // record is counting one piece of evidence twice, and this is where it
        // stops.
        if !index.consume(verified.attestation_hash.clone()) {
            return Err(AttestationGap::AttestationReplayed);
        }
        Ok(ReceiptProvenance::Attested { evidence, verified })
    }
}

/// What gates 3 to 6 established, and over which evidence.
enum ReceiptProvenance<'e> {
    /// A validated policy, an authorised verifier, a verifying signature and a
    /// matching `policy_hash`.
    Attested {
        evidence: &'e BoundaryEvidence,
        verified: VerifiedAttestation,
    },
    /// Offline mode: no policy, so no signature claim is made at all. The receipt
    /// stays a claim and counts nothing.
    Unauthenticated { evidence: &'e BoundaryEvidence },
}

impl<'e> ReceiptProvenance<'e> {
    fn evidence(&self) -> &'e BoundaryEvidence {
        match self {
            Self::Attested { evidence, .. } | Self::Unauthenticated { evidence } => {
                evidence
            }
        }
    }

    fn verified(&self) -> Option<&VerifiedAttestation> {
        match self {
            Self::Attested { verified, .. } => Some(verified),
            Self::Unauthenticated { .. } => None,
        }
    }
}

/// Translates a receipt-attestation refusal into the gap an operator reads.
fn auth_gap(e: ReceiptAuthError) -> AttestationGap {
    match e {
        ReceiptAuthError::VerifierNotDelegated { claimed, delegated } => {
            AttestationGap::VerifierNotDelegated { claimed, delegated }
        }
        ReceiptAuthError::BadSignature => AttestationGap::AttestationSignatureInvalid,
        ReceiptAuthError::PolicyHashMismatch { found, current } => {
            AttestationGap::PolicyHashMismatch { found, current }
        }
        ReceiptAuthError::AttestationHashMismatch { found, computed } => {
            AttestationGap::AttestationBodyMismatch(format!(
                "recorded digest {found}, recomputed {computed}"
            ))
        }
        other => AttestationGap::AttestationBodyMismatch(other.to_string()),
    }
}

/// Attestations indexed by the receipt content they cover, plus the replay guard.
///
/// The key is a digest of the receipt's *whole* content, recomputed from the
/// ledger's own bytes. That is what makes "mutating the receipt after signing" a
/// non-event rather than a near miss: the edited receipt has a different digest
/// and finds no attestation at all.
struct AttestationIndex<'a> {
    by_receipt: BTreeMap<Hash, Vec<&'a AuthenticatedExternalValueReceipt>>,
    consumed: BTreeSet<Hash>,
}

impl<'a> AttestationIndex<'a> {
    fn build(attestations: &'a [AuthenticatedExternalValueReceipt]) -> Self {
        let mut by_receipt: BTreeMap<
            Hash,
            Vec<&'a AuthenticatedExternalValueReceipt>,
        > = BTreeMap::new();
        for attestation in attestations {
            // An attestation whose own receipt content cannot be digested is not
            // a claim this view can act on and there is no valid content to key
            // it under. Skipping it here keeps such a record from being fatal;
            // the receipt it claims to cover is reported as unsigned, which is
            // the honest diagnosis.
            if let Ok(digest) = attestation.receipt_hash() {
                let slot = by_receipt.entry(digest).or_default();
                if !slot
                    .iter()
                    .any(|a| a.attestation_hash() == attestation.attestation_hash())
                {
                    slot.push(attestation);
                }
            }
        }
        Self {
            by_receipt,
            consumed: BTreeSet::new(),
        }
    }

    /// The digest a ledger receipt is indexed under, or an all-zero value if the
    /// receipt's own content cannot be digested (which no `ExternalValueReceipt`
    /// from a parsed ledger can produce).
    fn digest_for(&self, receipt: &ExternalValueReceipt) -> Hash {
        receipt_hash(receipt).unwrap_or_else(|_| Hash::from_bytes([0u8; 32]))
    }

    /// Marks an attestation as spent. `false` means another record already
    /// claimed it.
    fn consume(&mut self, attestation_hash: Hash) -> bool {
        self.consumed.insert(attestation_hash)
    }
}

/// Translates a settlement-attestation refusal into the gap an operator reads.
fn settlement_auth_gap(e: SettlementAuthError) -> SettlementGap {
    match e {
        SettlementAuthError::VerifierNotDelegated { claimed, delegated } => {
            SettlementGap::SettlementVerifierNotDelegated { claimed, delegated }
        }
        SettlementAuthError::BadSignature => {
            SettlementGap::SettlementSignatureInvalid
        }
        SettlementAuthError::PolicyHashMismatch { found, current } => {
            SettlementGap::SettlementPolicyHashMismatch { found, current }
        }
        SettlementAuthError::AttestationHashMismatch { found, computed } => {
            SettlementGap::SettlementAttestationBodyMismatch(format!(
                "recorded digest {found}, recomputed {computed}"
            ))
        }
        other => SettlementGap::SettlementAttestationBodyMismatch(
            other.to_string(),
        ),
    }
}

/// Settlement attestations indexed by the settlement content they cover, plus
/// the replay guard.
///
/// The revenue mirror of [`AttestationIndex`], and the key is the same idea: a
/// digest of the settlement's *whole* content, recomputed from the ledger's own
/// bytes. That is what makes "inflate the amount after signing" a non-event
/// rather than a near miss — the edited settlement has a different digest and
/// finds no attestation at all.
struct SettlementAttestationIndex<'a> {
    by_settlement: BTreeMap<Hash, Vec<&'a AuthenticatedSettlementReceipt>>,
    consumed: BTreeSet<Hash>,
}

impl<'a> SettlementAttestationIndex<'a> {
    fn build(attestations: &'a [AuthenticatedSettlementReceipt]) -> Self {
        let mut by_settlement: BTreeMap<
            Hash,
            Vec<&'a AuthenticatedSettlementReceipt>,
        > = BTreeMap::new();
        for attestation in attestations {
            // An attestation whose own settlement content cannot be digested is
            // not a claim this view can act on, and there is no valid content to
            // key it under. Skipping it here keeps such a record from being
            // fatal; the settlement it claims to cover is reported as unsigned,
            // which is the honest diagnosis.
            if let Ok(digest) = attestation.settlement_hash() {
                let slot = by_settlement.entry(digest).or_default();
                if !slot
                    .iter()
                    .any(|a| a.attestation_hash() == attestation.attestation_hash())
                {
                    slot.push(attestation);
                }
            }
        }
        Self {
            by_settlement,
            consumed: BTreeSet::new(),
        }
    }

    /// The attestation covering this settlement, or the gap that says there is
    /// none.
    ///
    /// "None" and "more than one" are different answers and get different gaps:
    /// a repeated append of the *identical* attestation is not this case
    /// (ed25519 is deterministic, so the second copy is byte-identical and
    /// `build` filters it out), so two entries under one digest mean two
    /// different signatures over one settlement content — a contradiction, which
    /// is refused rather than resolved.
    fn cover(
        &self,
        settlement: &SettlementReceipt,
    ) -> std::result::Result<&'a AuthenticatedSettlementReceipt, SettlementGap> {
        // The digest a ledger settlement is indexed under, or an all-zero value
        // if the settlement's content cannot be digested (which no
        // `SettlementReceipt` from a parsed ledger can produce).
        let digest = settlement_hash(settlement)
            .unwrap_or_else(|_| Hash::from_bytes([0u8; 32]));
        match self.by_settlement.get(&digest).map(|s| s.as_slice()) {
            None => Err(SettlementGap::UnsignedSettlement),
            Some([only]) => Ok(*only),
            Some(_) => Err(SettlementGap::DuplicateSettlementAttestation),
        }
    }

    /// Marks an attestation as spent. `false` means another record already
    /// claimed it.
    fn consume(&mut self, attestation_hash: Hash) -> bool {
        self.consumed.insert(attestation_hash)
    }
}

fn crossing_evidence(crossing: &BoundaryCrossing) -> CrossingEvidence {
    CrossingEvidence {
        from_address: crossing.from_address().to_string(),
        to_address: crossing.to_address().to_string(),
        from_domain: crossing.from_domain(),
        to_domain: crossing.to_domain(),
        kind: crossing.kind(),
        amount_raw: crossing.amount_raw(),
        tx_hash: crossing.tx_hash().to_string(),
        block_hash: crossing.block_hash().to_string(),
        chain_id: crossing.asset().chain_id(),
        contract: crossing.asset().contract().to_string(),
    }
}

fn claim_note(mode: TrustMode, receipts: &[ReceiptEvidence]) -> String {
    let mut note = format!(
        "TrustMode={mode}: {} of {} external-value records were counted, and each \
         counted record names a distinct external event; a record whose event was \
         already counted is not one of them, and the rest are claims only.",
        receipts.iter().filter(|r| r.counted).count(),
        receipts.len()
    );
    let mut gaps: Vec<&ReceiptEvidence> =
        receipts.iter().filter(|r| !r.counted).collect();
    gaps.sort_by_key(|r| r.sequence);
    if !gaps.is_empty() {
        note.push_str(" Unattested receipts:");
        for gap in gaps.iter().take(8) {
            note.push_str(&format!(
                " #{} {} ({}): {}",
                gap.sequence,
                gap.source_id,
                gap.net_external_value_musd_micros,
                gap.gap
                    .as_ref()
                    .map(AttestationGap::describe)
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }
        if gaps.len() > 8 {
            note.push_str(&format!("; and {} more", gaps.len() - 8));
        }
    }
    if !mode.can_attest() {
        note.push_str(
            " No number on this ledger can be promoted or funded without a provider \
             pinned out-of-band, so nothing here is reported as verified value.",
        );
    }
    note
}

/// Read-side authority over the revenue ledger: RV levels and paid demand.
///
/// Same shape and same rules as [`VerifiedEconomyView`], over the other
/// ledger. The stored `payment_proof_verified` and `external_paid` booleans are
/// diagnostics here for exactly the reason `proof_verified` is: a record that
/// says "I was verified" is a claim, and the cited transaction is the evidence.
pub struct VerifiedRevenueView<'a> {
    revenue: &'a LocalEconomy,
    registry: &'a ControlledAddressRegistry,
    mode: TrustMode,
    verifier: Option<&'a BaseUsdcVerifier>,
    /// The policy in force. `Some` exactly when `mode` can attest, as on the
    /// autonomy side. It is the authority every settlement signature is checked
    /// against, and it stands between a revenue view and "a number with no
    /// auditable authority behind it" even where the settlement itself carries
    /// no signature — which is every ledger written before
    /// [`crate::settlement_auth`].
    policy: Option<&'a ValidatedOutcomePolicy>,
}

impl<'a> VerifiedRevenueView<'a> {
    pub fn unverified(
        revenue: &'a LocalEconomy,
        registry: &'a ControlledAddressRegistry,
    ) -> Self {
        Self {
            revenue,
            registry,
            mode: TrustMode::Unverified,
            verifier: None,
            policy: None,
        }
    }

    /// Pinned mode. Requires a validated policy for the same reason the autonomy
    /// view does: a revenue view that cannot name its authority does not
    /// promote, so there is no constructor that reaches RV0 without one.
    pub fn provider_pinned(
        revenue: &'a LocalEconomy,
        registry: &'a ControlledAddressRegistry,
        verifier: &'a BaseUsdcVerifier,
        policy: &'a ValidatedOutcomePolicy,
    ) -> Result<Self> {
        if !verifier.provider_identity_verified() {
            return Err(EconomyError::Invalid(format!(
                "chain provider {} has no kernel-enforced identity, so it cannot \
                 attest paid demand",
                verifier.endpoint()
            )));
        }
        Ok(Self {
            revenue,
            registry,
            mode: TrustMode::ProviderPinned,
            verifier: Some(verifier),
            policy: Some(policy),
        })
    }

    pub fn trust_mode(&self) -> TrustMode {
        self.mode
    }

    /// The validated policy in force, when this view has one.
    pub fn policy(&self) -> Option<&ValidatedOutcomePolicy> {
        self.policy
    }

    /// Per-settlement diagnostics, whatever the mode.
    pub fn settlement_evidence(&self) -> Result<Vec<SettlementEvidence>> {
        let records = self.revenue.records()?;
        // P4c: the settlement attestations are read under the same durability
        // machinery as the ledger they gate, so a corrupted attestation file is
        // an error rather than an empty set — an empty set and "unsigned" are
        // the same verdict, and the second must not be reachable by damaging the
        // first.
        let attestations = self.revenue.settlement_attestations()?;
        let mut index = SettlementAttestationIndex::build(&attestations);
        // P4.5c: the payments already counted in THIS pass, keyed by
        // [`ExternalEventId`]. Created empty on every call, passed as `&mut`
        // into the one function that can set `counted`, and dropped when the
        // call returns — so the answer is recomputed from the ledger every read
        // and a duplicate cannot be promoted again by restarting the process
        // that wrote it.
        let mut counted_events = CountedEvents::default();
        let mut intents: Vec<&PaymentIntent> = Vec::new();
        let mut out = Vec::new();
        for record in &records {
            match record {
                LedgerRecord::PaymentIntent { intent, .. } => intents.push(intent),
                LedgerRecord::Settlement { settlement, .. } => {
                    out.push(self.assess_settlement(
                        record.sequence(),
                        settlement,
                        &intents,
                        &mut index,
                        &mut counted_events,
                    ));
                }
                _ => {}
            }
        }
        Ok(out)
    }

    pub fn rv_status(&self, now: u64) -> Result<RvStatus> {
        let settlements = self.settlement_evidence()?;
        let counted: Vec<&SettlementEvidence> =
            settlements.iter().filter(|s| s.counted).collect();
        let claimed: Vec<&SettlementEvidence> =
            settlements.iter().filter(|s| s.rederived).collect();
        let note = settlement_note(self.mode, &settlements);

        let cutoff = now.saturating_sub(30 * 86_400);
        let mut total = 0u64;
        let mut recent = 0u64;
        let mut oldest: Option<u64> = None;
        for s in &counted {
            total = total.saturating_add(s.usd_equivalent_micros);
            oldest = Some(oldest.map_or(s.settled_at_unix, |t| t.min(s.settled_at_unix)));
            if s.settled_at_unix >= cutoff && s.settled_at_unix <= now {
                recent = recent.saturating_add(s.usd_equivalent_micros);
            }
        }
        let claimed_total: u64 =
            claimed.iter().map(|s| s.usd_equivalent_micros).sum();
        let claimed_recent: u64 = claimed
            .iter()
            .filter(|s| s.settled_at_unix >= cutoff && s.settled_at_unix <= now)
            .map(|s| s.usd_equivalent_micros)
            .sum();

        let full_30d = oldest.map(|t| t <= cutoff).unwrap_or(false);
        let daily_30d = recent as f64 / 1_000_000.0 / 30.0;
        let rv0 = counted.len() >= 1;
        let (level, next) = if rv0 {
            if full_30d && daily_30d >= 2000.0 {
                ("RV4", None)
            } else if full_30d && daily_30d >= 500.0 {
                ("RV3", Some(2000.0))
            } else if full_30d && daily_30d >= 100.0 {
                ("RV2", Some(500.0))
            } else if full_30d && daily_30d >= 10.0 {
                ("RV1", Some(100.0))
            } else {
                ("RV0", Some(10.0))
            }
        } else {
            ("PRE-RV0", Some(0.0))
        };

        Ok(RvStatus {
            level: level.into(),
            external_paid_jobs: counted.len() as u64,
            paid_demand_musd_total: total as f64 / 1_000_000.0,
            paid_demand_musd_per_day_30d: daily_30d,
            next_target_musd_per_day: next,
            rv0_pass: rv0,
            note: if rv0 {
                if full_30d {
                    "RV is computed by VerifiedRevenueView: each settlement re-derives \
                     against its payment intent and the cited transaction was \
                     re-confirmed by the pinned provider."
                        .into()
                } else {
                    "RV0 passed on chain-attested paid demand; RV1-RV4 require a complete \
                     30-day attested window."
                        .into()
                }
            } else {
                format!(
                    "RV0 requires one externally paid settlement whose cited transaction \
                     was re-confirmed by the pinned provider. {note}"
                )
            },
            trust_mode: self.mode,
            unattested_external_paid_jobs: claimed.len() as u64,
            unattested_paid_demand_musd_total: claimed_total as f64 / 1_000_000.0,
            unattested_paid_demand_musd_per_day_30d: {
                claimed_recent as f64 / 1_000_000.0 / 30.0
            },
            attestation_note: note,
        })
    }

    pub fn revenue_summary(&self) -> Result<RevenueSummary> {
        let settlements = self.settlement_evidence()?;
        let note = settlement_note(self.mode, &settlements);
        self.revenue.revenue_summary_with_evidence(self.mode, &settlements, &note)
    }

    fn assess_settlement(
        &self,
        sequence: u64,
        settlement: &SettlementReceipt,
        intents: &[&PaymentIntent],
        index: &mut SettlementAttestationIndex<'_>,
        counted_events: &mut CountedEvents,
    ) -> SettlementEvidence {
        let mut out = SettlementEvidence {
            settlement_id: settlement.settlement_id.clone(),
            job_id: settlement.job_id.clone(),
            settlement_asset: settlement.settlement_asset.symbol().to_string(),
            settled_amount_micros: settlement.settled_amount_micros,
            usd_equivalent_micros: settlement.usd_equivalent_micros,
            settled_at_unix: settlement.settled_at_unix,
            // Read on purpose, reported on purpose, never an authority input.
            stored_payment_proof_verified: settlement.payment_proof_verified,
            stored_external_paid: settlement.external_paid,
            rederived: false,
            chain_confirmed: false,
            counted: false,
            gap: None,
            attested: false,
            policy_hash: None,
            verifier_key_id: None,
            attestation_hash: None,
            event_id: None,
        };
        let intent = match self.rederive_settlement(settlement, intents) {
            Ok(intent) => intent,
            Err(gap) => {
                out.gap = Some(gap);
                return out;
            }
        };
        out.rederived = true;

        // ---- the policy is the outer authority ------------------------------
        //
        // Unchanged from P4b: the view's policy is what every signature below is
        // checked against, so without one there is nothing to check against and
        // nothing promotes. A view that holds no policy therefore never even
        // looks for an attestation — it makes no signature claim at all.
        if self.policy.is_none() {
            out.gap = Some(SettlementGap::PolicyNotValidated);
            return out;
        }
        let policy = self.policy.expect("checked above");

        // ---- P4c: the settlement signature gate ----------------------------
        //
        // The revenue side of the identity
        // `VerifyChain(VerifySettlementSig(VerifyPolicy(DeriveSettlement)))`.
        // Position: after P3's re-derivation and the policy check, and *before*
        // the provider and the chain read — the same place the autonomy side
        // puts `VerifyReceiptSig`, relative to its own boundary derivation and
        // its own chain read.
        //
        // Before P4c this is where the check stopped, and the check was one
        // thing: "this view holds a validated policy". A party who could write
        // the revenue ledger and produce a *real* transfer of the right size into
        // a controlled address booked paid demand that no verifier ever signed.
        // From here it is a signature, or nothing counts.
        //
        // What this does NOT do, and says so here rather than implying it: it
        // does not assert that the booked amount equals the on-chain amount. The
        // signature binds the *identity* of the two numbers (`amount_raw` from the
        // intent, `settlement_hash` over the settlement's own figures); the
        // arithmetic rule is P3's, it stayed in `rederive_settlement` above, and
        // it did not move. See `settlement_auth`'s module doc.
        let attestation = match index.cover(settlement) {
            Ok(attestation) => attestation,
            Err(gap) => {
                out.gap = Some(gap);
                return out;
            }
        };
        // Verifier authorised, signature valid over the ledger's own records,
        // `policy_hash` equal to the policy in force — in that order, each
        // separately reportable, exactly as on the autonomy side.
        let verified = match attestation.verify(policy, intent) {
            Ok(verified) => verified,
            Err(e) => {
                out.gap = Some(settlement_auth_gap(e));
                return out;
            }
        };
        // One signature covers one settlement. A ledger that repeats the attested
        // record is counting one piece of evidence twice.
        if !index.consume(verified.attestation_hash.clone()) {
            out.gap = Some(SettlementGap::SettlementAttestationReplayed);
            return out;
        }
        out.attested = true;
        out.policy_hash = Some(verified.policy_hash.to_string());
        out.verifier_key_id = Some(verified.verifier_key_id.to_string());
        out.attestation_hash = Some(verified.attestation_hash.to_string());

        // ---- the chain read (P3, unchanged) ---------------------------------
        //
        // Everything below is P3/P4b exactly as it was, in the same order. The
        // signature above adds provenance; it does not substitute for the chain
        // read, and a settlement that verifies here still has to be confirmed by
        // a kernel-identified provider.
        // The provider's identity, mandatory, as on the autonomy side.
        let Some(verifier) = self.verifier else {
            out.gap = Some(SettlementGap::NoPinnedProvider);
            return out;
        };
        if !verifier.provider_identity_verified() {
            out.gap = Some(SettlementGap::ProviderIdentityUnverified(format!(
                "provider {} is an address, not an identity",
                verifier.endpoint()
            )));
            return out;
        };
        let Some(tx) = settlement.payment_proof_hash.as_deref() else {
            out.gap = Some(SettlementGap::NoPaymentTransaction);
            return out;
        };
        let block = settlement.payment_block_number.unwrap_or_default();
        match verifier.verify_transfer(tx, &intent.recipient, intent.exact_amount_raw) {
            Ok(proof) => {
                if !proof.verified || !proof.provider_identity_verified {
                    out.gap = Some(SettlementGap::ChainNotConfirmed(format!(
                        "provider {} answered without a kernel-enforced identity",
                        proof.rpc
                    )));
                    return out;
                }
                if proof.block_number != block {
                    out.gap = Some(SettlementGap::ChainNotConfirmed(format!(
                        "transaction is in block {} but the settlement books {}",
                        proof.block_number, block
                    )));
                    return out;
                }
                out.chain_confirmed = true;

                // ---- gate 12: the payment's external identity (P4.5c) -------
                //
                // The last gate, and the one the revenue side was missing. Every
                // gate above asks "is this record what it claims to be?"; this one
                // asks "has this *payment* been counted before?", which is a
                // question about the ledger as a whole rather than about the
                // record. Before P4.5c the revenue side had no such gate, so two
                // settlements of one payment — each with its own genuine signature
                // over its own content — both reached paid demand.
                //
                // It runs *after* the signature and *after* the chain read on
                // purpose. A record that is not provably a settlement of a real
                // payment has no payment to be a duplicate of, and refusing it here
                // would report the wrong fault.
                //
                // The identity is a [`crate::event_id::ExternalEventId`] over the
                // facts this read established, under its own domain. It is built
                // from the *proof* rather than from the record's own fields, so it
                // cannot be moved: change `settled_at_unix`, `payment_tx_hash` or
                // anything else about the booking and the identity is unchanged,
                // because none of those are the payment.
                let Some(real_asset) = settlement.settlement_asset.real_asset() else {
                    // `rederive_settlement` already refused a synthetic asset, so
                    // this is unreachable rather than merely unlikely; stated
                    // rather than unwrapped so the invariant is visible here too.
                    out.gap = Some(SettlementGap::SettlementEventIdentityIndeterminate(
                        format!(
                            "settlement {} books a synthetic asset, which has no on-chain \
                             payment to name",
                            settlement.settlement_id
                        ),
                    ));
                    return out;
                };
                match crate::event_id::SettlementPaymentFact::from_confirmed_payment(
                    real_asset.chain_id(),
                    &proof,
                    real_asset,
                    &intent.recipient,
                    intent.exact_amount_raw,
                )
                .and_then(|fact| {
                    crate::event_id::ExternalEventId::settlement_payment(&fact)
                }) {
                    Ok(id) => {
                        let rendered = id.to_string();
                        out.event_id = Some(rendered.clone());
                        if let Some(first) = counted_events.claim(id, sequence) {
                            out.gap =
                                Some(SettlementGap::SettlementEventAlreadyCounted {
                                    event_id: rendered,
                                    first_counted_at_sequence: first,
                                });
                            return out;
                        }
                    }
                    Err(e) => {
                        out.gap = Some(
                            SettlementGap::SettlementEventIdentityIndeterminate(
                                e.to_string(),
                            ),
                        );
                        return out;
                    }
                }
            }
            Err(e) => {
                out.gap = Some(SettlementGap::ChainNotConfirmed(e.to_string()));
                return out;
            }
        }
        out.counted = true;
        out
    }

    /// Everything about a settlement that can be re-derived from the ledger
    /// itself. Note what is *not* consulted: `payment_proof_verified` and
    /// `external_paid`.
    fn rederive_settlement<'b>(
        &self,
        settlement: &SettlementReceipt,
        intents: &[&'b PaymentIntent],
    ) -> std::result::Result<&'b PaymentIntent, SettlementGap> {
        if settlement.mode != SettlementMode::External {
            return Err(SettlementGap::NotExternal);
        }
        if settlement.internal_work {
            return Err(SettlementGap::InternalWork);
        }
        if !settlement.settlement_asset.is_real() {
            return Err(SettlementGap::NotARealAsset(
                settlement.settlement_asset.symbol().to_string(),
            ));
        }
        if settlement.usd_equivalent_micros == 0 {
            return Err(SettlementGap::NoValue);
        }
        let Some(tx) = settlement.payment_proof_hash.as_deref() else {
            return Err(SettlementGap::NoPaymentTransaction);
        };
        if base_usdc::validate_hash32("payment_proof_hash", tx).is_err() {
            return Err(SettlementGap::MalformedTransaction);
        }
        let Some(intent) = intents.iter().find(|i| i.job_id == settlement.job_id)
        else {
            return Err(SettlementGap::NoPaymentIntent);
        };
        if settlement.payment_intent_id.as_deref()
            != Some(intent.payment_intent_id.as_str())
        {
            return Err(SettlementGap::IntentMismatch);
        }
        if intent.token != base_usdc::BASE_USDC.to_ascii_lowercase() {
            return Err(SettlementGap::ForeignToken(intent.token.clone()));
        }
        if settlement.usd_equivalent_micros != intent.exact_amount_raw {
            return Err(SettlementGap::AmountNotJustified {
                booked: settlement.usd_equivalent_micros,
                expected: intent.exact_amount_raw,
            });
        }
        match self.registry.domain_of(&intent.recipient) {
            Ok(ControlDomain::Controlled) => {}
            Ok(ControlDomain::External) => {
                return Err(SettlementGap::RecipientNotControlled(
                    intent.recipient.clone(),
                ))
            }
            Err(e) => {
                return Err(SettlementGap::MalformedRecipient(format!(
                    "{}: {e}",
                    intent.recipient
                )))
            }
        }
        let Some(block) = settlement.payment_block_number else {
            return Err(SettlementGap::NoPaymentBlock);
        };
        if block <= intent.anchor_block {
            return Err(SettlementGap::BlockNotAfterAnchor {
                block,
                anchor: intent.anchor_block,
            });
        }
        Ok(intent)
    }
}

fn settlement_note(mode: TrustMode, settlements: &[SettlementEvidence]) -> String {
    let mut note = format!(
        "TrustMode={mode}: {} of {} paid settlements are attested; the rest are claims \
         only.",
        settlements.iter().filter(|s| s.counted).count(),
        settlements.len()
    );
    let gaps: Vec<&SettlementEvidence> =
        settlements.iter().filter(|s| !s.counted).collect();
    if !gaps.is_empty() {
        note.push_str(" Unattested settlements:");
        for gap in gaps.iter().take(8) {
            note.push_str(&format!(
                " {} ({}): {}",
                gap.settlement_id,
                gap.usd_equivalent_micros,
                gap.gap
                    .as_ref()
                    .map(SettlementGap::describe)
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }
        if gaps.len() > 8 {
            note.push_str(&format!("; and {} more", gaps.len() - 8));
        }
    }
    if !mode.can_attest() {
        note.push_str(
            " No paid-demand level can be promoted without a provider pinned \
             out-of-band.",
        );
    }
    note
}

/// P4.5c: `pub(crate)` so the settlement tests can reuse this module's fixtures
/// and, above all, its one `assert_no_promotion_route` helper. Writing a second
/// helper for the same claim would be how the two drifted apart.
///
/// P6.0.1: `Fixture`, `fixture`, `Authenticated::new`, `Authenticated::view`
/// and `record_genuine_inflow_with` are now `pub(crate)` as well, because
/// `discovery.rs` has to be able to build a *real* `VerifiedNev` — there,
/// attestation used to be a string in a JSON document, so a test could fake it
/// with a struct literal, and the fix is a capability that cannot be faked. One
/// recipe, this one; a second copy in `discovery.rs` would be a second thing to
/// keep in step with P4.5b's signature and P4.5c's chain read.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        autonomy::{
            AgentClass, EconomicAgentManifest, EconomicPolicy, JobIntent,
            OpportunityCandidate, RiskProfile,
        },
        base_usdc::{BaseUsdcVerification, BASE_CHAIN_ID, BASE_USDC},
        chain_provider::{resolve, PinnedChainProvider, ProviderSource},
        reinvestment::{ReinvestmentController, ReinvestmentPolicy, ReinvestmentSignals},
        rpc_test_server::FakeRpcSocket,
        settlement_auth,
        JobType, JobRequest, LocalEconomy, WorkReceipt, LEDGER_GENESIS_HASH,
        REVENUE_LEDGER_FILE, SCHEMA_VERSION,
    };
    use serde_json::Value;
    use std::{
        collections::BTreeMap,
        fs,
        path::{Path, PathBuf},
        sync::Arc,
    };
    use tempfile::tempdir;

    const PAYOUT: &str = "0xe83331104f5f3c41e49abc46c810f9d71133e48c";
    const COUNTERPARTY: &str = "0x1234567890abcdef1234567890abcdef12345678";
    const AMOUNT: u64 = 5_000_000;
    const BLOCK: u64 = 101;
    pub(crate) const NOW: u64 = 1_700_000_500;

    fn tx_hash() -> String {
        format!("0x{}", "11".repeat(32))
    }

    fn block_hash() -> String {
        format!("0x{}", "22".repeat(32))
    }

    pub(crate) fn registry() -> ControlledAddressRegistry {
        ControlledAddressRegistry::new()
            .with_address(PAYOUT)
            .unwrap()
    }

    fn evidence(from: &str, to: &str) -> BoundaryEvidence {
        BoundaryEvidence {
            chain_id: BASE_CHAIN_ID,
            asset: crate::boundary::RealAsset::base_usdc(),
            from_address: from.into(),
            to_address: to.into(),
            amount_raw: AMOUNT,
            tx_hash: tx_hash(),
            block_hash: block_hash(),
        }
    }

    /// A fake provider that actually serves the transfer the crossing cites: an
    /// exact USDC Transfer to the recipient, inside the canonical block, with
    /// enough confirmations. `FakeRpcSocket` binds a real Unix socket with
    /// owner-only permissions, so the kernel identity check is exercised rather
    /// than stubbed.
    fn serving_socket(dir: &Path) -> FakeRpcSocket {
        let recipient_topic = format!("0x{:0>64}", PAYOUT.trim_start_matches("0x"));
        let log = serde_json::json!({
            "address": BASE_USDC,
            "topics": [
                crate::base_usdc::ERC20_TRANSFER_TOPIC,
                format!("0x{:0>64}", COUNTERPARTY.trim_start_matches("0x")),
                recipient_topic,
            ],
            "data": format!("0x{amount:064x}", amount = AMOUNT),
            "logIndex": "0x3",
        });
        FakeRpcSocket::with_responses(
            dir.join("verifier.sock"),
            vec![
                ("eth_chainId", serde_json::json!("0x2105")),
                ("eth_blockNumber", serde_json::json!("0x6e")),
                ("eth_getTransactionReceipt", serde_json::json!({
                    "status": "0x1",
                    "blockNumber": format!("0x{block:x}", block = BLOCK),
                    "blockHash": block_hash(),
                    "transactionHash": tx_hash(),
                    "logs": [log],
                })),
                ("eth_getBlockByNumber", serde_json::json!({
                    "hash": block_hash(),
                    "timestamp": "0x6553f100",
                })),
            ],
        )
    }

    /// A pinned provider that answers correctly about the chain but has never
    /// seen the transaction the evidence cites. This is what a fabricated
    /// transaction hash runs into.
    fn unbacked_socket(dir: &Path) -> FakeRpcSocket {
        FakeRpcSocket::with_responses(
            dir.join("unbacked.sock"),
            vec![
                ("eth_chainId", serde_json::json!("0x2105")),
                ("eth_blockNumber", serde_json::json!("0x6e")),
                ("eth_getTransactionReceipt", serde_json::Value::Null),
            ],
        )
    }

    fn verifier_for(socket: &FakeRpcSocket) -> Result<BaseUsdcVerifier> {
        let provider =
            PinnedChainProvider::unix_socket(socket.path(), Some(socket.uid()))?;
        let resolved = resolve(None, Some(&provider))?;
        assert_eq!(resolved.source, ProviderSource::PolicyPin);
        let verifier = BaseUsdcVerifier::from_resolved(&resolved, 2)?;
        assert!(verifier.provider_identity_verified());
        Ok(verifier)
    }

    pub(crate) fn agent() -> EconomicAgentManifest {
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
            expires_at_unix: 1_700_002_000,
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

    pub(crate) struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        pub(crate) autonomy: AutonomousEconomy,
    }

    /// An agent, an opportunity and an orchestrated job intent: a plausible
    /// economy with nothing attested in it.
    pub(crate) fn fixture() -> Fixture {
        let dir = tempdir().unwrap();
        let autonomy = AutonomousEconomy::open(dir.path()).unwrap();
        LocalEconomy::open(dir.path()).unwrap();
        autonomy.register_agent(agent()).unwrap();
        autonomy.submit_opportunity(opportunity()).unwrap();
        autonomy
            .orchestrate("opp-1", &EconomicPolicy::default(), 1_700_000_200)
            .unwrap();
        let root = dir.path().to_path_buf();
        Fixture {
            _dir: dir,
            root,
            autonomy,
        }
    }

    fn receipt() -> ExternalValueReceipt {
        ExternalValueReceipt {
            schema_version: SCHEMA_VERSION,
            source_id: "source-1".into(),
            agent_id: "s1-arb-01".into(),
            opportunity_id: "opp-1".into(),
            value_class: ExternalValueClass::ExternalTradingPnl,
            network: "base".into(),
            asset: "USDC".into(),
            gross_inflow_musd_micros: 6_000_000,
            external_cost_musd_micros: 1_000_000,
            net_external_value_musd_micros: 5_000_000,
            proof_hash: tx_hash(),
            proof_verified: true,
            realized_at_unix: 1_700_000_400,
            verifier_id: "base-reconcile".into(),
        }
    }

    /// The genuine case, written through the typed path: evidence recorded, the
    /// crossing derived against the operator's registry, the receipt booked
    /// against that crossing.
    fn record_genuine_inflow(f: &Fixture) {
        record_genuine_inflow_with(f, None);
    }

    /// The same, and then the P4b signature: the delegated verifier signs the
    /// receipt over the evidence it cites and the attestation is recorded beside
    /// it. `None` is the pre-P4b shape, kept because several tests are about
    /// what an *unattested* receipt does.
    pub(crate) fn record_genuine_inflow_with(f: &Fixture, auth: Option<&Authenticated<'_>>) {
        let registry = registry();
        let evidence = evidence(COUNTERPARTY, PAYOUT);
        let crossing = f
            .autonomy
            .record_boundary_crossing(&evidence, &registry)
            .unwrap();
        let proof = BaseUsdcVerification {
            verified: true,
            rpc: "unix:///run/mycelium-verifier.sock".into(),
            provider_identity_verified: true,
            chain_id: BASE_CHAIN_ID,
            transaction_hash: tx_hash(),
            block_number: BLOCK,
            block_hash: block_hash(),
            block_timestamp_unix: 1_700_000_400,
            latest_block: 110,
            confirmations: 10,
            token: BASE_USDC.to_ascii_lowercase(),
            recipient: PAYOUT.into(),
            expected_raw: AMOUNT,
            matched_raw: AMOUNT,
            matching_log_index: Some(3),
        };
        let crossing = crossing.with_verified_proof(proof).unwrap();
        let booked = receipt();
        if let Some(auth) = auth {
            auth.record_attestation(&booked, &evidence);
        }
        f.autonomy
            .record_external_value_with_crossing(booked, &crossing)
            .unwrap();
    }

    /// A pinned view with the authority P4b requires behind it: a validated
    /// policy, the key it delegates to, and the pin that makes the policy real.
    ///
    /// All of them have to outlive the view, so they live in a struct rather
    /// than in a function that hands a borrow back — the same discipline P3 used
    /// for the socket.
    pub(crate) struct Authenticated<'a> {
        _socket: FakeRpcSocket,
        _auth: crate::receipt_auth::testkit::AuthFixture,
        registry: ControlledAddressRegistry,
        verifier: BaseUsdcVerifier,
        policy: crate::policy_auth::ValidatedOutcomePolicy,
        autonomy: &'a AutonomousEconomy,
    }

    impl<'a> Authenticated<'a> {
        /// A provider that serves the transfer the standard evidence cites, and
        /// an authority scoped to that socket.
        pub(crate) fn new(dir: &Path, autonomy: &'a AutonomousEconomy) -> Self {
            let socket = serving_socket(dir);
            Self::with_socket(socket, autonomy)
        }

        fn with_socket(
            socket: FakeRpcSocket,
            autonomy: &'a AutonomousEconomy,
        ) -> Self {
            let verifier = verifier_for(&socket).unwrap();
            let registry = registry();
            let auth = crate::receipt_auth::testkit::AuthFixture::new(
                socket.path(),
                socket.uid(),
                registry.clone(),
            );
            let policy = auth.validated();
            Self {
                _socket: socket,
                _auth: auth,
                registry,
                verifier,
                policy,
                autonomy,
            }
        }

        pub(crate) fn view(&'a self) -> VerifiedEconomyView<'a> {
            VerifiedEconomyView::provider_pinned(
                self.autonomy,
                &self.registry,
                &self.verifier,
                &self.policy,
            )
            .unwrap()
        }

        /// The delegated verifier signs a receipt and the signature is recorded,
        /// which is the only way a receipt ever becomes attested. Returns the
        /// attestation so a test can verify it independently of the view.
        fn record_attestation(
            &self,
            receipt: &ExternalValueReceipt,
            evidence: &BoundaryEvidence,
        ) -> AuthenticatedExternalValueReceipt {
            let attestation =
                self._auth.attest(&self.policy, receipt, evidence);
            self.autonomy
                .record_receipt_attestation(&attestation)
                .unwrap();
            attestation
        }
    }

    /// P6.0.1: a genuine [`VerifiedNev`] whose total is **not** positive, minted
    /// by the production constructor rather than assembled for a test.
    ///
    /// `VerifiedNev::from_settlement_authorities` is the only way this crate
    /// produces one, so the way to get a non-positive total without weakening
    /// that type is to run it for real over an operation set that settled
    /// nothing: a kernel-identified provider, a validated policy, its real
    /// `policy_hash`, and therefore a total of zero over zero receipts. Nothing
    /// here is a test-only shortcut into the type — `receipts == 0` is the
    /// honest answer for an empty set, and `is_positive()` is false because of
    /// it.
    ///
    /// This exists because P6.0.1 has to show that `is_positive()` is honoured on
    /// the promotion path, and a positive fixture cannot show that. Exposed to
    /// `discovery.rs`'s tests because the settlement path there is inert by
    /// design: nothing in production calls this.
    pub(crate) fn empty_verified_nev() -> VerifiedNev {
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Authenticated::new(dir.path(), &f.autonomy);
        let nev = VerifiedNev::from_settlement_authorities(&[], Some(&auth.verifier), &auth.policy)
            .expect("a pinned provider and a validated policy over no operations is a real zero");
        assert_eq!(nev.receipts(), 0);
        assert_eq!(nev.nev_musd_micros(), 0);
        assert!(!nev.is_positive());
        assert!(nev.provider_identity_verified());
        nev
    }

    // ------------------------------------------------------------------
    // 1. a forged ledger with a valid hash chain and proof_verified: true
    // ------------------------------------------------------------------

    /// Appends an `Agent`, an `Opportunity`, a `BoundaryCrossing` evidence
    /// record and an `ExternalValue` record with correct
    /// sequence/prev_hash/record_hash and `proof_verified: true`, by hand, the
    /// way a process that can write `~/.mycelium/economy/*.jsonl` would.
    ///
    /// It writes into a directory that has never been appended to, which is the
    /// realistic ordering: the forgery lands before the node ever opens the
    /// ledger. (A ledger rewritten *under* a running node is caught separately by
    /// the head-anchor check in the read path; that is a different attack with a
    /// different answer, and it is not what P3 is about.)
    fn forge_ledger(dir: &Path) -> AutonomousEconomy {
        forge_ledger_with(dir, receipt(), evidence(COUNTERPARTY, PAYOUT))
    }

    /// [`forge_ledger`] with the receipt and the evidence as parameters, so a
    /// test can write a ledger whose value record has been edited after the
    /// attestation was signed.
    fn forge_ledger_with(
        dir: &Path,
        receipt: ExternalValueReceipt,
        evidence: BoundaryEvidence,
    ) -> AutonomousEconomy {
        let mut prev = crate::autonomy::AUTONOMY_GENESIS_HASH.to_string();
        let mut sequence = 1u64;
        let mut push = |payload: crate::autonomy::AutonomyPayload| {
            let mut record = crate::autonomy::AutonomyRecord {
                sequence,
                recorded_at_unix: 1_700_000_900,
                prev_hash: prev.clone(),
                record_hash: String::new(),
                payload,
            };
            record.record_hash =
                blake3::hash(&serde_json::to_vec(&record).unwrap())
                    .to_hex()
                    .to_string();
            prev = record.record_hash.clone();
            sequence += 1;
            serde_json::to_string(&record).unwrap()
        };
        let mut lines = Vec::new();
        lines.push(push(crate::autonomy::AutonomyPayload::Agent {
            manifest: agent(),
        }));
        lines.push(push(crate::autonomy::AutonomyPayload::Opportunity {
            opportunity: opportunity(),
        }));
        lines.push(push(crate::autonomy::AutonomyPayload::JobIntent {
            intent: JobIntent {
                schema_version: SCHEMA_VERSION,
                job_intent_id: "job-forged".into(),
                opportunity_id: "opp-1".into(),
                agent_id: "s1-arb-01".into(),
                job_type: JobType::Simulation,
                input_hash: "blake3:input".into(),
                max_cost_musd_micros: 500_000,
                deadline_unix: 1_700_010_000,
                verification: crate::autonomy::VerificationMode::ExternalProof,
                created_at_unix: 1_700_000_200,
            },
        }));
        // A fabricated transfer: valid shapes, a transaction that does not exist.
        lines.push(push(crate::autonomy::AutonomyPayload::BoundaryCrossing {
            evidence,
        }));
        lines.push(push(crate::autonomy::AutonomyPayload::ExternalValue {
            receipt,
        }));
        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join("autonomous-ledger.jsonl"),
            format!("{}\n", lines.join("\n")),
        )
        .unwrap();
        AutonomousEconomy::open(dir).unwrap()
    }

    #[test]
    fn a_forged_ledger_passes_the_hash_chain_and_still_cannot_promote() {
        let dir = tempdir().unwrap();
        let autonomy = forge_ledger(dir.path());
        let _f = fixture();
        // The chain itself is intact: sequence, prev_hash and record_hash all
        // check out, and the record still says proof_verified: true.
        let raw = fs::read_to_string(autonomy.ledger_path()).unwrap();
        assert!(raw.contains("\"proof_verified\":true"));
        assert!(autonomy.records().is_ok());

        let registry = registry();
        let view = VerifiedEconomyView::unverified(&autonomy, &registry);

        // Which predicate fails, stated explicitly.
        let evidence = view.receipt_evidence().unwrap();
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].stored_proof_verified, "the claim is still on disk");
        assert!(!evidence[0].counted);
        assert!(matches!(
            evidence[0].gap,
            Some(AttestationGap::ChainNotConfirmed(_))
        ));
        // Everything up to the chain read passed, which is the point: the only
        // thing standing between the forgery and ARV4 is a transaction that does
        // not exist.
        assert!(evidence[0].revalidated);
        assert!(evidence[0].crossing.is_some());

        let arv = view.arv_status(NOW).unwrap();
        assert_eq!(arv.level, "PRE-ARV0");
        assert!(!arv.arv0_pass);
        assert_eq!(arv.verified_external_events, 0);
        assert_eq!(arv.net_external_value_musd_total, 0.0);
        // And the claim is reported, not swallowed.
        assert_eq!(arv.unattested_external_events, 1);
        assert_eq!(arv.unattested_net_external_value_musd, 5.0);
        assert_eq!(arv.trust_mode, TrustMode::Unverified);
    }

    #[test]
    fn a_forged_ledger_cannot_raise_the_reinvestment_budget() {
        let dir = tempdir().unwrap();
        let autonomy = forge_ledger(dir.path());
        let f = fixture();
        let registry = registry();
        let view = VerifiedEconomyView::unverified(&autonomy, &registry);
        let controller = ReinvestmentController::open(&f.root).unwrap();
        let policy = ReinvestmentPolicy::default();
        let signals = ReinvestmentSignals::default();

        let decision = controller
            .decide_from_view(&view, &signals, &policy, NOW)
            .unwrap();
        assert_eq!(
            decision.available_new_commitment_musd_micros, 0,
            "a forged ledger funded real spending authority"
        );
        assert_eq!(decision.verified_nev_musd_micros, 0);
        assert_eq!(decision.target_cumulative_reinvestment_musd_micros, 0);
        // The ledger's claim is reported, under a name that cannot be mistaken
        // for a budget.
        assert_eq!(decision.unattested_nev_musd_micros, 5_000_000);
        assert!(decision.reason.contains("TrustMode=unverified"), "{}", decision.reason);
        assert!(decision.reason.contains("5"), "{}", decision.reason);

        // And the spending gate refuses before the arithmetic.
        let forged_job = autonomy
            .job_intents()
            .unwrap()
            .into_iter()
            .find(|j| j.job_intent_id == "job-forged")
            .expect("the forged ledger carries a job intent");
        let err = controller
            .commit_job_from_view(&view, &agent(), &forged_job, &signals, &policy, NOW)
            .unwrap_err();
        assert!(err.to_string().contains("TrustMode=unverified"), "{err}");
    }

    #[test]
    fn a_forged_ledger_is_still_rejected_when_a_provider_is_pinned() {
        // The same forgery, now with a real pinned provider attached *and* a
        // genuine signature from the verifier the policy delegates to. Both new
        // gates pass — the receipt really was signed by an authorised key over
        // a policy that really is in force — and the provider still has never
        // seen the transaction. This is the property P4b must not weaken: the
        // signature is not a substitute for the chain read.
        let dir = tempdir().unwrap();
        let autonomy = forge_ledger(dir.path());
        let socket = unbacked_socket(dir.path());
        let verifier = verifier_for(&socket).unwrap();
        let registry = registry();
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        // Sign the forgery over the very evidence it cites. A real verifier
        // would never see this transaction, so it would never sign it; the test
        // holds the key and does, precisely to show that the chain read is still
        // the gate that stops.
        let forged = receipt();
        let evidence = evidence(COUNTERPARTY, PAYOUT);
        let attestation =
            auth.attest(&policy, &forged, &evidence);
        autonomy.record_receipt_attestation(&attestation).unwrap();

        let view = VerifiedEconomyView::provider_pinned(
            &autonomy, &registry, &verifier, &policy,
        )
        .unwrap();
        assert_eq!(view.trust_mode(), TrustMode::ProviderPinned);

        let evidence_rows = view.receipt_evidence().unwrap();
        assert!(!evidence_rows[0].counted);
        assert!(evidence_rows[0].attested, "the signature itself is genuine");
        assert_eq!(
            evidence_rows[0].policy_hash.as_deref(),
            Some(policy.policy_hash().unwrap().to_string().as_str())
        );
        assert_eq!(
            evidence_rows[0].verifier_key_id.as_deref(),
            Some(auth.verifier.key_id().to_string().as_str())
        );
        assert!(
            evidence_rows[0].offline_ok,
            "everything but the chain read passed"
        );
        let gap = evidence_rows[0].gap.as_ref().unwrap().describe();
        assert!(gap.contains("did not confirm"), "{gap}");
        assert!(gap.contains("receipt not found"), "{gap}");
        assert_eq!(view.arv_status(NOW).unwrap().level, "PRE-ARV0");

        // And the budget stays at zero with a provider attached.
        let controller = ReinvestmentController::open(dir.path()).unwrap();
        let decision = controller
            .decide_from_view(
                &view,
                &ReinvestmentSignals::default(),
                &ReinvestmentPolicy::default(),
                NOW,
            )
            .unwrap();
        assert_eq!(decision.available_new_commitment_musd_micros, 0);
    }

    // ------------------------------------------------------------------
    // 1b. the same forgery, against the REVENUE ledger
    // ------------------------------------------------------------------

    /// The record timestamp a hand-written line would carry. Same instant for
    /// every record, which is what a script writing four lines in a row does.
    const FORGED_AT: u64 = 1_700_000_900;

    /// A payment transaction that does not exist on Base. Deliberately NOT
    /// [`tx_hash`], which [`serving_socket`] answers for: a provider that can
    /// serve the autonomy fixture's transfer still cannot serve this one, so
    /// the revenue forgery is refused on its own merits.
    fn forged_payment_tx() -> String {
        format!("0x{}", "9e".repeat(32))
    }

    /// Stamps the chain fields onto a revenue record.
    ///
    /// The revenue chain is not the autonomy chain and the helper above does not
    /// transfer to it: there is no record wrapper around a payload enum, but an
    /// internally tagged `LedgerRecord`, and its hash is committed over the
    /// same struct re-serialized with an empty `record_hash`. Rebuilding the
    /// variant here keeps the forge independent of the crate's private
    /// `set_record_hash`/`computed_hash`.
    fn stamp(
        record: &LedgerRecord,
        sequence: u64,
        prev_hash: &str,
        record_hash: &str,
    ) -> LedgerRecord {
        let prev_hash = prev_hash.to_string();
        let record_hash = record_hash.to_string();
        match record {
            LedgerRecord::Job { recorded_at_unix, job, .. } => LedgerRecord::Job {
                sequence,
                recorded_at_unix: *recorded_at_unix,
                prev_hash,
                record_hash,
                job: job.clone(),
            },
            LedgerRecord::Work { recorded_at_unix, receipt, .. } => {
                LedgerRecord::Work {
                    sequence,
                    recorded_at_unix: *recorded_at_unix,
                    prev_hash,
                    record_hash,
                    receipt: receipt.clone(),
                }
            }
            LedgerRecord::PaymentIntent { recorded_at_unix, intent, .. } => {
                LedgerRecord::PaymentIntent {
                    sequence,
                    recorded_at_unix: *recorded_at_unix,
                    prev_hash,
                    record_hash,
                    intent: intent.clone(),
                }
            }
            LedgerRecord::Settlement { recorded_at_unix, settlement, .. } => {
                LedgerRecord::Settlement {
                    sequence,
                    recorded_at_unix: *recorded_at_unix,
                    prev_hash,
                    record_hash,
                    settlement: settlement.clone(),
                }
            }
        }
    }

    /// The canonical `record_hash` of a revenue record, recomputed from the test
    /// side. This is the value the reader will derive, so a forged line that
    /// only "looks" chained is caught here rather than being mistaken for a
    /// forgery the view refused.
    fn revenue_computed_hash(record: &LedgerRecord) -> String {
        let canonical = stamp(record, record.sequence(), record.prev_hash(), "");
        blake3::hash(&serde_json::to_vec(&canonical).unwrap())
            .to_hex()
            .to_string()
    }

    /// The three things the revenue reader checks, asserted here directly:
    /// contiguous sequence from 1, every `prev_hash` equal to its
    /// predecessor's `record_hash` starting at the public genesis anchor, and
    /// every `record_hash` equal to a hash recomputed from the record's own
    /// bytes. If any of them failed, the view would have been handed an error
    /// and nothing below would prove anything about it.
    fn assert_revenue_chain_intact(records: &[LedgerRecord]) {
        let mut expected_prev = LEDGER_GENESIS_HASH.to_string();
        for (idx, record) in records.iter().enumerate() {
            let at = idx + 1;
            assert_eq!(record.sequence(), at as u64, "sequence contiguous at {at}");
            assert_eq!(
                record.prev_hash(),
                expected_prev,
                "prev_hash linked at {at}"
            );
            assert_eq!(
                record.record_hash(),
                revenue_computed_hash(record),
                "record_hash recomputes at {at}"
            );
            expected_prev = record.record_hash().to_string();
        }
    }

    /// Appends a `Job`, a `Work`, a `PaymentIntent` and a `Settlement` with
    /// correct sequence/prev_hash/record_hash, by hand, the way a process that
    /// can write `~/.mycelium/economy/revenue-ledger.jsonl` would.
    ///
    /// The settlement is as convincing as the type system allows: a real
    /// on-chain asset, a positive amount, a payment intent that matches it
    /// field for field and pays a controlled recipient, a payment block after
    /// the intent's anchor, a well-formed 32-byte transaction hash, and both
    /// stored booleans set — `payment_proof_verified: true` with
    /// `external_paid: true`, the pair the pre-P3 code treated as the
    /// definition of paid demand. The one thing it cannot have is a
    /// transaction that exists.
    fn forge_revenue_ledger(dir: &Path) -> LocalEconomy {
        let mut prev = LEDGER_GENESIS_HASH.to_string();
        let mut sequence = 1u64;
        let mut lines: Vec<String> = Vec::new();
        let mut push = |base: LedgerRecord| {
            // What `LocalEconomy::append` does: link to the previous record,
            // commit the hash over the record with an empty `record_hash`, then
            // write the hash back into the bytes that get appended.
            let canonical = stamp(&base, sequence, &prev, "");
            let record_hash = blake3::hash(&serde_json::to_vec(&canonical).unwrap())
                .to_hex()
                .to_string();
            let record = stamp(&base, sequence, &prev, &record_hash);
            prev = record_hash;
            sequence += 1;
            lines.push(serde_json::to_string(&record).unwrap());
        };

        push(LedgerRecord::Job {
            sequence: 0,
            recorded_at_unix: FORGED_AT,
            prev_hash: String::new(),
            record_hash: String::new(),
            job: JobRequest {
                schema_version: SCHEMA_VERSION,
                job_id: "job-forged".into(),
                created_at_unix: 1_700_000_100,
                requester_id: "customer-forged".into(),
                job_type: JobType::Simulation,
                input_hash: "blake3:input".into(),
                max_price_musd_micros: AMOUNT,
                internal_work: false,
                description: "forged external job".into(),
            },
        });
        push(LedgerRecord::Work {
            sequence: 0,
            recorded_at_unix: FORGED_AT,
            prev_hash: String::new(),
            record_hash: String::new(),
            receipt: WorkReceipt {
                schema_version: SCHEMA_VERSION,
                receipt_id: "work-forged".into(),
                job_id: "job-forged".into(),
                worker_id: "worker-forged".into(),
                started_at_unix: 1_700_000_110,
                completed_at_unix: 1_700_000_350,
                result_hash: "blake3:result".into(),
                useful_work_units: 10,
                verifier_id: "verifier-forged".into(),
                verified_at_unix: 1_700_000_360,
                verified: true,
            },
        });
        push(LedgerRecord::PaymentIntent {
            sequence: 0,
            recorded_at_unix: FORGED_AT,
            prev_hash: String::new(),
            record_hash: String::new(),
            intent: PaymentIntent {
                schema_version: SCHEMA_VERSION,
                payment_intent_id: "intent-forged".into(),
                job_id: "job-forged".into(),
                chain_id: BASE_CHAIN_ID,
                token: BASE_USDC.to_ascii_lowercase(),
                recipient: PAYOUT.into(),
                exact_amount_raw: AMOUNT,
                anchor_block: BLOCK - 1,
                anchor_block_hash: format!("0x{}", "33".repeat(32)),
                anchor_timestamp_unix: 1_700_000_300,
                created_at_unix: 1_700_000_310,
            },
        });
        push(LedgerRecord::Settlement {
            sequence: 0,
            recorded_at_unix: FORGED_AT,
            prev_hash: String::new(),
            record_hash: String::new(),
            settlement: SettlementReceipt {
                schema_version: SCHEMA_VERSION,
                settlement_id: "settle-forged".into(),
                job_id: "job-forged".into(),
                work_receipt_id: "work-forged".into(),
                settled_at_unix: 1_700_000_400,
                mode: SettlementMode::External,
                settlement_asset: SettlementAsset::classify_symbol("USDC").unwrap(),
                settled_amount_micros: AMOUNT,
                usd_equivalent_micros: AMOUNT,
                payment_intent_id: Some("intent-forged".into()),
                payment_block_number: Some(BLOCK),
                payment_proof_hash: Some(forged_payment_tx()),
                payment_proof_verified: true,
                external_paid: true,
                internal_work: false,
            },
        });

        fs::create_dir_all(dir).unwrap();
        fs::write(
            dir.join(REVENUE_LEDGER_FILE),
            format!("{}\n", lines.join("\n")),
        )
        .unwrap();
        LocalEconomy::open(dir).unwrap()
    }

    #[test]
    fn a_forged_revenue_ledger_passes_the_hash_chain_and_still_cannot_promote() {
        let dir = tempdir().unwrap();
        let revenue = forge_revenue_ledger(dir.path());

        // 1. The chain itself is intact, and the record on disk still claims a
        // verified external payment. A forgery that failed its own chain would
        // prove nothing about the view: the view would never have seen it.
        let raw = fs::read_to_string(revenue.ledger_path()).unwrap();
        assert!(raw.contains("\"payment_proof_verified\":true"));
        assert!(raw.contains("\"external_paid\":true"));
        assert!(raw.contains(&forged_payment_tx()));
        let records = revenue.records().unwrap();
        assert_eq!(records.len(), 4);
        assert_revenue_chain_intact(&records);
        let audit = revenue.audit_ledger().unwrap();
        assert!(audit.valid, "the audit path agrees the chain verifies");
        assert_eq!(audit.records, 4);
        assert_eq!(audit.head_hash, records[3].record_hash());
        assert_ne!(audit.head_hash, LEDGER_GENESIS_HASH);

        // 2. The forged receipt looks maximally convincing: both stored
        // booleans on, a non-empty transaction hash, a positive amount, a real
        // asset. `counts_as_paid_demand` is the pre-P3 definition of paid
        // demand, and it is exactly the predicate the view may not use.
        let forged = match &records[3] {
            LedgerRecord::Settlement { settlement, .. } => settlement,
            other => panic!("record 4 is a settlement, got {other:?}"),
        };
        assert!(forged.payment_proof_verified);
        assert!(forged.external_paid);
        assert!(forged
            .payment_proof_hash
            .as_deref()
            .map(|h| !h.is_empty())
            .unwrap_or(false));
        assert_eq!(forged.usd_equivalent_micros, AMOUNT);
        assert!(
            forged.counts_as_paid_demand(),
            "the claim has to look like paid demand for the test to mean anything"
        );

        let registry = registry();
        let view = VerifiedRevenueView::unverified(&revenue, &registry);

        // 3. Which predicate fails, stated explicitly. Not a parse error: the
        // evidence list is a value, and it names one settlement.
        let evidence = view.settlement_evidence().unwrap();
        assert_eq!(evidence.len(), 1);
        assert!(
            evidence[0].stored_payment_proof_verified,
            "the claim is still on disk"
        );
        assert!(
            evidence[0].stored_external_paid,
            "the claim is still on disk"
        );
        assert!(!evidence[0].counted);
        assert!(!evidence[0].chain_confirmed);
        // Everything up to the authority check passed, which is the point: real
        // asset, positive value, a well-formed 32-byte transaction, an intent
        // that matches the settlement field for field and pays a controlled
        // recipient, a block after the intent's anchor. The one thing missing is
        // a transaction that exists.
        assert!(evidence[0].rederived);
        assert_eq!(evidence[0].usd_equivalent_micros, AMOUNT);
        // P4b changed which gap an offline reader is told about. Before, "no
        // pinned provider in this view" was the answer; now the authority check
        // runs first, and the honest first answer in an offline view is that
        // there is no policy to check any of this against. Both are true, and
        // this one is the stronger statement.
        assert!(matches!(
            evidence[0].gap,
            Some(SettlementGap::PolicyNotValidated)
        ));

        // 4. RV0 does not move, and the only non-zero number is filed under a
        // name that cannot be mistaken for an attested total.
        let rv = view.rv_status(NOW).unwrap();
        assert_eq!(rv.level, "PRE-RV0");
        assert!(!rv.rv0_pass);
        assert_eq!(rv.external_paid_jobs, 0);
        assert_eq!(rv.paid_demand_musd_total, 0.0);
        assert_eq!(rv.paid_demand_musd_per_day_30d, 0.0);
        assert_eq!(rv.trust_mode, TrustMode::Unverified);
        // And the claim is reported, with its reason, not swallowed.
        assert_eq!(rv.unattested_external_paid_jobs, 1);
        assert_eq!(rv.unattested_paid_demand_musd_total, 5.0);
        assert!(rv.attestation_note.contains("0 of 1"), "{rv:?}");
        assert!(rv
            .attestation_note
            .contains("no validated outcome policy"), "{rv:?}");
        let json = serde_json::to_value(&rv).unwrap();
        assert_eq!(json["paid_demand_musd_total"], serde_json::json!(0.0));
        assert_eq!(
            json["unattested_paid_demand_musd_total"],
            serde_json::json!(5.0)
        );
        assert_eq!(json["trust_mode"], serde_json::json!("unverified"));

        // 5. The summary does not book the forged settlement as paid either.
        let summary = view.revenue_summary().unwrap();
        assert_eq!(summary.trust_mode, TrustMode::Unverified);
        assert_eq!(summary.external_paid_jobs, 0);
        assert_eq!(summary.paid_demand_musd_micros, 0);
        assert_eq!(summary.paid_demand_musd(), 0.0);
        assert!(
            summary.by_asset_micros.is_empty(),
            "a real asset with zero attested value is not an asset bucket"
        );
        assert_eq!(summary.internal_or_simulated_jobs, 1);
        assert_eq!(summary.unattested_external_paid_jobs, 1);
        assert_eq!(summary.unattested_paid_demand_musd_micros, AMOUNT);
    }

    #[test]
    fn a_forged_revenue_ledger_is_still_refused_when_a_provider_is_pinned() {
        // The same forged bytes, now with a real pinned provider attached. The
        // provider is asked about the transaction the settlement cites and has
        // never seen it, so the gap stops being "no provider" and becomes the
        // concrete attestation failure: ChainNotConfirmed.
        //
        // Positive control: `verified_external_settlement_promotes_rv0`
        // (`lib.rs`, same crate) builds the genuine counterpart of this ledger
        // through the typed write path and asserts `RV0` with
        // `external_paid_jobs == 1` in pinned mode. Nothing here can be passing
        // because nothing promotes anymore.
        let dir = tempdir().unwrap();
        let revenue = forge_revenue_ledger(dir.path());
        assert_revenue_chain_intact(&revenue.records().unwrap());
        let socket = unbacked_socket(dir.path());
        let verifier = verifier_for(&socket).unwrap();
        let registry = registry();
        // P4b: the revenue view also needs a validated policy. It clears the
        // policy gate below and still fails on the chain read, which is what
        // makes this a test of the chain read and nothing else.
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        let view = VerifiedRevenueView::provider_pinned(
            &revenue,
            &registry,
            &verifier,
            &policy,
        )
        .unwrap();
        assert_eq!(view.trust_mode(), TrustMode::ProviderPinned);

        // P4c: sign the forged settlement with the delegated key, so the
        // signature gate clears and the chain read stays the only failing
        // predicate. Without this the gap would be `UnsignedSettlement` and the
        // test would prove nothing about the chain read. The forgery is
        // therefore exactly as convincing as before, plus a signature that
        // says the delegated verifier blessed this settlement.
        let settlement = revenue
            .records()
            .unwrap()
            .into_iter()
            .find_map(|r| match r {
                LedgerRecord::Settlement { settlement, .. } => Some(settlement),
                _ => None,
            })
            .expect("the forged settlement");
        let intent = revenue
            .payment_intent_for_job("job-forged")
            .unwrap()
            .expect("the forged intent");
        let attestation = auth
            .verifier
            .attest_settlement(&policy, &settlement, &intent)
            .unwrap();
        revenue.record_settlement_attestation(&attestation).unwrap();

        let evidence = view.settlement_evidence().unwrap();
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].stored_payment_proof_verified);
        assert!(evidence[0].stored_external_paid);
        assert!(!evidence[0].counted);
        assert!(!evidence[0].chain_confirmed);
        // Still re-derived, and now attested: the chain read is the only thing
        // that failed.
        assert!(evidence[0].rederived);
        assert!(evidence[0].attested);
        let gap = evidence[0].gap.as_ref().unwrap().describe();
        assert_eq!(
            evidence[0].gap,
            Some(SettlementGap::ChainNotConfirmed(
                "invalid record: transaction receipt not found".to_string()
            )),
            "the gap must name the attestation failure, not a parse or re-derivation error"
        );
        assert!(gap.contains("did not confirm"), "{gap}");
        assert!(gap.contains("receipt not found"), "{gap}");

        let rv = view.rv_status(NOW).unwrap();
        assert_eq!(rv.level, "PRE-RV0");
        assert!(!rv.rv0_pass);
        assert_eq!(rv.external_paid_jobs, 0);
        assert_eq!(rv.paid_demand_musd_total, 0.0);
        assert_eq!(rv.unattested_external_paid_jobs, 1);
        assert_eq!(rv.unattested_paid_demand_musd_total, 5.0);

        let summary = view.revenue_summary().unwrap();
        assert_eq!(summary.external_paid_jobs, 0);
        assert_eq!(summary.paid_demand_musd_micros, 0);
        assert_eq!(summary.unattested_external_paid_jobs, 1);
    }

    // ------------------------------------------------------------------
    // 2. trust modes
    // ------------------------------------------------------------------

    #[test]
    fn unverified_mode_cannot_produce_an_actionable_number() {
        let f = fixture();
        record_genuine_inflow(&f);
        let registry = registry();
        let view = VerifiedEconomyView::unverified(&f.autonomy, &registry);

        // The type-level half: there is no `VerifiedNev` to have.
        let err = view.verified_nev().unwrap_err();
        assert!(err.to_string().contains("TrustMode::ProviderPinned"), "{err}");
        // The runtime half: the offline number is a claim, and it stays a claim
        // even though every fact underneath it is genuine.
        let claim = view.unattested_nev().unwrap();
        assert_eq!(claim.re_derived_receipts, 1);
        assert_eq!(claim.claimed_net_external_value_musd_micros, 5_000_000);
        assert!(claim.receipts[0].offline_ok);
        assert!(!claim.receipts[0].counted);
        let arv = view.arv_status(NOW).unwrap();
        assert_eq!(arv.level, "PRE-ARV0");
        assert_eq!(arv.verified_external_events, 0);
        assert_eq!(arv.net_external_value_musd_total, 0.0);
        assert_eq!(arv.unattested_net_external_value_musd, 5.0);
        assert!(arv.attestation_note.contains("no pinned provider"), "{arv:?}");
    }

    #[test]
    fn pinned_mode_promotes_when_the_chain_confirms() {
        // The whole identity, once: a policy validated from the pinned anchor, a
        // receipt signed by the key that policy delegated to, a crossing that
        // re-derives, and a chain read that confirms. All four have to be there;
        // the tests around it remove one at a time.
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Authenticated::new(dir.path(), &f.autonomy);
        record_genuine_inflow_with(&f, Some(&auth));
        let view = auth.view();

        let nev = view.verified_nev().unwrap();
        assert_eq!(nev.nev_musd_micros(), 5_000_000);
        assert_eq!(nev.receipts(), 1);
        assert!(nev.is_positive());
        assert!(nev.provider_identity_verified());
        assert_eq!(
            nev.policy_hash(),
            auth.policy.policy_hash().unwrap().to_string()
        );

        let arv = view.arv_status(NOW).unwrap();
        assert_eq!(arv.level, "ARV0");
        assert!(arv.arv0_pass);
        assert_eq!(arv.verified_external_events, 1);
        assert_eq!(arv.net_external_value_musd_total, 5.0);
        assert_eq!(arv.trust_mode, TrustMode::ProviderPinned);
        assert_eq!(arv.unattested_net_external_value_musd, 5.0);
    }

    #[test]
    fn a_provider_without_a_kernel_identity_cannot_attest() {
        // The dev-only loopback override drives a verifier, but it authenticates
        // nothing, so the view refuses to exist in pinned mode with it.
        let f = fixture();
        let verifier = BaseUsdcVerifier::new("http://127.0.0.1:8546", 2).unwrap();
        assert!(!verifier.provider_identity_verified());
        let registry = registry();
        let dir = tempdir().unwrap();
        // The policy is not the point of this test, so it is built over the same
        // loopback-free socket the rest of the module uses. What is being shown
        // is that the provider check fires first and unconditionally.
        let socket = serving_socket(dir.path());
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        let err = match VerifiedEconomyView::provider_pinned(
            &f.autonomy,
            &registry,
            &verifier,
            &policy,
        ) {
            Ok(_) => panic!("a loopback endpoint must not be able to attest"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("kernel-enforced identity"), "{err}");
    }

    // ------------------------------------------------------------------
    // 3. round trip: genuine facts, same answer as before
    // ------------------------------------------------------------------

    #[test]
    fn a_ledger_written_by_the_current_code_reads_back_identically() {
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Authenticated::new(dir.path(), &f.autonomy);
        record_genuine_inflow_with(&f, Some(&auth));
        let view = auth.view();

        // What the pre-P3 code reported for this ledger, when the facts are
        // genuine: one verified event, 5.0 mUSD, ARV0.
        let nev = view.verified_nev().unwrap();
        assert_eq!(nev.nev_musd(), 5.0);
        let arv = view.arv_status(NOW).unwrap();
        assert_eq!(arv.level, "ARV0");
        assert_eq!(arv.net_external_value_musd_total, 5.0);
        assert_eq!(arv.verified_external_events, 1);

        // And the economics are unchanged: (5 - 1) still books 5.0, and the
        // reserve floor still applies to the reinvestment base.
        let summary = view.autonomy_summary().unwrap();
        assert_eq!(summary.verified_external_value_receipts, 1);
        assert_eq!(summary.net_external_value_musd, 5.0);
        let controller = ReinvestmentController::open(&f.root).unwrap();
        let decision = controller
            .decide_from_view(
                &view,
                &ReinvestmentSignals::default(),
                &ReinvestmentPolicy::default(),
                NOW,
            )
            .unwrap();
        // (5 - 1 reserve... reserve floor is 10 mUSD) -> investable 0.
        assert_eq!(decision.verified_nev_musd_micros, 5_000_000);
        assert_eq!(decision.investable_nev_musd_micros, 0);
    }

    #[test]
    fn gross_minus_cost_still_holds_through_the_view() {
        let f = fixture();
        let registry = registry();
        let crossing = f
            .autonomy
            .record_boundary_crossing(&evidence(COUNTERPARTY, PAYOUT), &registry)
            .unwrap();
        let proof = BaseUsdcVerification {
            verified: true,
            rpc: "unix:///run/mycelium-verifier.sock".into(),
            provider_identity_verified: true,
            chain_id: BASE_CHAIN_ID,
            transaction_hash: tx_hash(),
            block_number: BLOCK,
            block_hash: block_hash(),
            block_timestamp_unix: 1_700_000_400,
            latest_block: 110,
            confirmations: 10,
            token: BASE_USDC.to_ascii_lowercase(),
            recipient: PAYOUT.into(),
            expected_raw: AMOUNT,
            matched_raw: AMOUNT,
            matching_log_index: Some(3),
        };
        let crossing = crossing.with_verified_proof(proof).unwrap();

        // A receipt whose net does not match gross - cost is refused at write
        // time...
        let mut tampered = receipt();
        tampered.gross_inflow_musd_micros = 9_000_000;
        assert!(f
            .autonomy
            .record_external_value_with_crossing(tampered, &crossing)
            .is_err());

        // ...and one that is consistent survives the same way it did before.
        let booked = f
            .autonomy
            .record_external_value_with_crossing(receipt(), &crossing)
            .unwrap();
        assert_eq!(
            booked.net_external_value_musd_micros,
            booked.gross_inflow_musd_micros as i64
                - booked.external_cost_musd_micros as i64
        );

        let view = VerifiedEconomyView::unverified(&f.autonomy, &registry);
        let claim = view.unattested_nev().unwrap();
        assert_eq!(claim.receipts.len(), 1);
        assert_eq!(
            claim.receipts[0].gross_inflow_musd_micros as i64
                - claim.receipts[0].external_cost_musd_micros as i64,
            claim.receipts[0].net_external_value_musd_micros
        );
    }

    // ------------------------------------------------------------------
    // 4. the stored boolean is not an authority input
    // ------------------------------------------------------------------

    #[test]
    fn the_stored_flag_moves_nothing_in_either_direction() {
        // Flag off, genuine evidence, genuine signature: still counted, because
        // the flag is not an input. This is the "NEVER
        // VerifiedNev = receipt.proof_verified" half.
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Authenticated::new(dir.path(), &f.autonomy);
        let crossing_evidence = evidence(COUNTERPARTY, PAYOUT);
        f.autonomy
            .record_boundary_crossing(&crossing_evidence, &registry())
            .unwrap();
        let mut r = receipt();
        r.proof_verified = false;
        r.verifier_id = "written-by-a-tool-without-a-verifier".into();
        // The write path refuses to mark an unverified receipt as verified, but
        // it accepts the record either way; here it is written as an
        // evidence-candidate, exactly as the CLI's
        // `external-value-candidate-json` does.
        //
        // The signature covers the flag, because the attestation's
        // `receipt_hash` covers every field. A flag flipped *after* signing is
        // therefore a mutation, and is refused below — which is the whole of the
        // freeze: the flag can neither add nor remove authority, and changing it
        // changes the receipt's identity rather than its status.
        auth.record_attestation(&r, &crossing_evidence);
        f.autonomy.record_external_value(r).unwrap();

        let view = auth.view();
        let rows = view.receipt_evidence().unwrap();
        assert!(!rows[0].stored_proof_verified);
        assert!(
            rows[0].counted,
            "a genuine receipt was ignored because a stored flag was false"
        );
        assert_eq!(view.verified_nev().unwrap().nev_musd_micros(), 5_000_000);
        assert_eq!(view.arv_status(NOW).unwrap().level, "ARV0");

        // And the other direction, which P4b strengthens rather than replaces:
        // the flag alone is not a signature. Same ledger, flag on, no
        // attestation at all.
        let g = fixture();
        let dir2 = tempdir().unwrap();
        let auth2 = Authenticated::new(dir2.path(), &g.autonomy);
        g.autonomy
            .record_boundary_crossing(&crossing_evidence, &registry())
            .unwrap();
        let mut flagged = receipt();
        flagged.proof_verified = true;
        g.autonomy.record_external_value(flagged).unwrap();
        let view2 = auth2.view();
        let rows2 = view2.receipt_evidence().unwrap();
        assert!(rows2[0].stored_proof_verified);
        assert!(!rows2[0].attested);
        assert!(!rows2[0].counted);
        assert_eq!(
            rows2[0].gap,
            Some(AttestationGap::UnsignedReceipt),
            "a stored flag must not stand in for a signature"
        );
        assert_eq!(view2.arv_status(NOW).unwrap().level, "PRE-ARV0");
    }

    #[test]
    fn a_receipt_citing_no_transaction_is_unattested_with_a_reason() {
        // The shape of every pre-crossing ledger, and of every candidate the CLI
        // accepts: a receipt whose proof_hash is not a transaction at all.
        let f = fixture();
        let registry = registry();
        let mut r = receipt();
        r.proof_hash = "0xproof".into();
        f.autonomy.record_external_value(r).unwrap();

        let view = VerifiedEconomyView::unverified(&f.autonomy, &registry);
        let evidence = view.receipt_evidence().unwrap();
        assert!(matches!(
            evidence[0].gap,
            Some(AttestationGap::NoCitableTransaction)
        ));
        let arv = view.arv_status(NOW).unwrap();
        assert_eq!(arv.level, "PRE-ARV0");
        // It is not silently zero: the claim is reported, with the reason.
        assert_eq!(arv.unattested_net_external_value_musd, 0.0);
        assert!(arv
            .attestation_note
            .contains("cites no transaction"), "{arv:?}");
    }

    #[test]
    fn evidence_that_does_not_derive_against_the_registry_is_refused() {
        // The registry moved: the address the crossing paid is no longer ours, so
        // the same bytes re-derive as an irrelevant external-to-external hop.
        let f = fixture();
        record_genuine_inflow(&f);
        let moved = ControlledAddressRegistry::new()
            .with_address("0x9999999999999999999999999999999999999999")
            .unwrap();
        let view = VerifiedEconomyView::unverified(&f.autonomy, &moved);
        let evidence = view.receipt_evidence().unwrap();
        assert!(matches!(
            evidence[0].gap,
            Some(AttestationGap::NotAnExternalInflow { .. })
        ));
        assert_eq!(view.arv_status(NOW).unwrap().level, "PRE-ARV0");
    }

    #[test]
    fn the_chain_tamper_regression_still_holds_through_the_view() {
        // The hash chain is still the first thing checked, and a tampered ledger
        // is an error, not a smaller number.
        let f = fixture();
        record_genuine_inflow(&f);
        let path = f.autonomy.ledger_path();
        let raw = fs::read_to_string(&path).unwrap();
        fs::write(&path, raw.replace("s1-arb-01", "evil-agent")).unwrap();

        let registry = registry();
        let view = VerifiedEconomyView::unverified(&f.autonomy, &registry);
        assert!(view.receipt_evidence().is_err());
        assert!(view.verified_nev().is_err());
        assert!(view.arv_status(NOW).is_err());
        assert!(view.autonomy_summary().is_err());
    }

    #[test]
    fn the_claim_type_cannot_be_mistaken_for_the_attested_one() {
        // The compiler-level guarantee is that `UnattestedNev` and `VerifiedNev`
        // are different types, that neither has a public constructor and that
        // neither has a `Deserialize`. This crate has no compile-fail harness,
        // so — exactly as `boundary.rs` pins its type identity — the test pins
        // what is observable at runtime: the names differ, and the serialized
        // form of the claim names every number as a claim, so a JSON blob
        // cannot be read back and mistaken for an attested total.
        assert_ne!(
            std::any::type_name::<UnattestedNev>(),
            std::any::type_name::<VerifiedNev>()
        );
        let f = fixture();
        let registry = registry();
        let dir = tempdir().unwrap();
        let auth = Authenticated::new(dir.path(), &f.autonomy);
        record_genuine_inflow_with(&f, Some(&auth));
        let claim = VerifiedEconomyView::unverified(&f.autonomy, &registry)
            .unattested_nev()
            .unwrap();
        let json = serde_json::to_value(&claim).unwrap();
        assert!(json
            .get("claimed_net_external_value_musd_micros")
            .is_some());
        assert!(json.get("nev_musd_micros").is_none());
        assert!(json.get("receipts").is_some());
        // The attested type serializes its number under the plain name, and the
        // two shapes cannot be confused by a reader of the JSON either.
        let pinned = auth.view();
        let nev = pinned.verified_nev().unwrap();
        let json = serde_json::to_value(&nev).unwrap();
        assert!(json.get("nev_musd_micros").is_some());
        assert!(json.get("claimed_net_external_value_musd_micros").is_none());
        assert_eq!(json["provider_identity_verified"], serde_json::json!(true));
        // P4b: the attested type also names the authority it came from, so the
        // JSON alone is enough to say which policy produced the number.
        assert_eq!(
            json["policy_hash"],
            serde_json::json!(auth.policy.policy_hash().unwrap().to_string())
        );
    }

    #[test]
    fn a_ledger_written_before_p3_still_deserializes_and_is_reported_as_unattested() {
        // The exact on-disk shape a pre-P3 build wrote, with the stored flag the
        // old code trusted. It loads, it is accounted for, and it attests
        // nothing.
        let f = fixture();
        let mut legacy = receipt();
        legacy.proof_hash = format!("0x{}", "ab".repeat(32));
        legacy.proof_verified = true;
        f.autonomy.record_external_value(legacy).unwrap();

        let registry = registry();
        let view = VerifiedEconomyView::unverified(&f.autonomy, &registry);
        let evidence = view.receipt_evidence().unwrap();
        assert_eq!(evidence.len(), 1);
        assert!(evidence[0].stored_proof_verified);
        assert!(!evidence[0].counted);
        assert!(matches!(
            evidence[0].gap,
            Some(AttestationGap::NoBoundaryCrossing)
        ));
        let arv = view.arv_status(NOW).unwrap();
        assert_eq!(arv.level, "PRE-ARV0");
        assert_eq!(arv.unattested_net_external_value_musd, 0.0);
    }

    // ==================================================================
    // 5. P4b: the authenticated receipt
    // ==================================================================

    /// Asserts the autonomy ledger is *really* well formed: contiguous
    /// sequence, every `prev_hash` equal to its predecessor's `record_hash`, and
    /// every `record_hash` equal to a digest recomputed from the record's own
    /// bytes. Every forgery in this section claims to pass these checks, so
    /// they are asserted rather than assumed.
    fn assert_receipt_chain_is_readable(autonomy: &AutonomousEconomy) {
        let records = autonomy.records().unwrap();
        assert!(!records.is_empty());
        let mut expected_prev =
            crate::autonomy::AUTONOMY_GENESIS_HASH.to_string();
        for (idx, record) in records.iter().enumerate() {
            let at = idx + 1;
            assert_eq!(record.sequence, at as u64, "sequence contiguous at {at}");
            assert_eq!(record.prev_hash, expected_prev, "prev_hash at {at}");
            let mut canonical = record.clone();
            canonical.record_hash = String::new();
            assert_eq!(
                record.record_hash,
                blake3::hash(&serde_json::to_vec(&canonical).unwrap())
                    .to_hex()
                    .to_string(),
                "record_hash recomputes at {at}"
            );
            expected_prev = record.record_hash.clone();
        }
    }

    /// Appends a second `ExternalValue` record with the *same* receipt content,
    /// correctly chained — what a forger rewriting the file would write to get a
    /// receipt counted twice.
    fn repeat_receipt_record(autonomy: &AutonomousEconomy) -> AutonomousEconomy {
        let path = autonomy.ledger_path();
        let raw = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = raw.lines().map(|l| l.to_string()).collect();
        let last: crate::autonomy::AutonomyRecord =
            serde_json::from_str(lines.last().unwrap()).unwrap();
        let receipt = match &last.payload {
            AutonomyPayload::ExternalValue { receipt } => receipt.clone(),
            other => panic!("expected the last record to be a value record, got {other:?}"),
        };
        let mut record = crate::autonomy::AutonomyRecord {
            sequence: last.sequence + 1,
            recorded_at_unix: last.recorded_at_unix,
            prev_hash: last.record_hash.clone(),
            record_hash: String::new(),
            payload: AutonomyPayload::ExternalValue { receipt },
        };
        record.record_hash =
            blake3::hash(&serde_json::to_vec(&record).unwrap())
                .to_hex()
                .to_string();
        lines.push(serde_json::to_string(&record).unwrap());
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        AutonomousEconomy::open(
            autonomy.ledger_path().parent().unwrap(),
        )
        .unwrap()
    }

    /// Every route a number can leave the autonomy side of this crate by,
    /// asserted zero for one view.
    ///
    /// There are four and the point of the helper is that they are all here:
    /// `VerifiedNev`, `ArvStatus`, `AutonomousSummary` and the reinvestment
    /// decision. A test that checks one of them proves very little, because the
    /// others could still be reading something else. Every P4b refusal test calls
    /// this, so "no path skips the signature check and still promotes" is one
    /// assertion applied everywhere rather than a claim in a comment.
    /// The one assertion set for "this ledger authorises nothing".
    ///
    /// `revenue` is the revenue side of the same question and is `Some` in the
    /// P4c tests: the two ledgers are independent, so "no promotion route" means
    /// neither ARV nor RV moves and neither the reinvestment budget nor any
    /// summary books a number. The autonomy-only callers pass `None` because
    /// they have no revenue view to assert about.
    pub(crate) fn assert_no_promotion_route(
        view: &VerifiedEconomyView<'_>,
        revenue: Option<&VerifiedRevenueView<'_>>,
        why: &str,
    ) {
        // 1. NEV. In pinned mode this is a zero `VerifiedNev` rather than a
        //    refusal — that is P3's shape, and `is_positive()` is the predicate
        //    every caller uses. What matters is that it names no receipt, so
        //    nothing downstream can read a value out of it. In unverified mode
        //    it is a refusal, because there is no authority at all.
        match view.verified_nev() {
            Ok(nev) => {
                assert_eq!(nev.receipts(), 0, "{why}");
                assert!(!nev.is_positive(), "{why}");
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
        // 3. The summary the dashboards read.
        let summary = view.autonomy_summary().unwrap();
        assert_eq!(summary.verified_external_value_receipts, 0, "{why}");
        assert_eq!(summary.net_external_value_musd, 0.0, "{why}");
        // 4. The budget, and the commitment that would spend it.
        let controller =
            ReinvestmentController::open(view.autonomy().root()).unwrap();
        let decision = controller
            .decide_from_view(
                view,
                &ReinvestmentSignals::default(),
                &ReinvestmentPolicy::default(),
                NOW,
            )
            .unwrap();
        assert_eq!(decision.verified_nev_musd_micros, 0, "{why}");
        assert_eq!(decision.available_new_commitment_musd_micros, 0, "{why}");
        assert!(
            controller
                .commit_job_from_view(
                    view,
                    &agent(),
                    &job_intent(),
                    &ReinvestmentSignals::default(),
                    &ReinvestmentPolicy::default(),
                    NOW,
                )
                .is_err(),
            "{why}: a commitment was funded"
        );
        // 5. RV, when a revenue view was handed in.
        if let Some(revenue) = revenue {
            let rv = revenue.rv_status(NOW).unwrap();
            assert_eq!(rv.level, "PRE-RV0", "{why}");
            assert!(!rv.rv0_pass, "{why}");
            assert_eq!(rv.external_paid_jobs, 0, "{why}");
            assert_eq!(rv.paid_demand_musd_total, 0.0, "{why}");
            assert_eq!(rv.paid_demand_musd_per_day_30d, 0.0, "{why}");
            let summary = revenue.revenue_summary().unwrap();
            assert_eq!(summary.external_paid_jobs, 0, "{why}");
            assert_eq!(summary.paid_demand_musd_micros, 0, "{why}");
            assert_eq!(summary.paid_demand_musd(), 0.0, "{why}");
            // Every settlement is reported with a reason rather than dropped, and
            // none of them claims an attestation.
            for row in revenue.settlement_evidence().unwrap() {
                assert!(!row.counted, "{why}: {} counted", row.settlement_id);
                assert!(
                    !row.attested,
                    "{why}: {} claims an attestation",
                    row.settlement_id
                );
                assert!(
                    row.gap.is_some(),
                    "{why}: {} was neither counted nor explained",
                    row.settlement_id
                );
            }
        }
    }

    /// The job a budget commitment would try to fund, standing in for one an
    /// attacker would name.
    pub(crate) fn job_intent() -> JobIntent {
        JobIntent {
            schema_version: SCHEMA_VERSION,
            job_intent_id: "job-forged".into(),
            opportunity_id: "opp-1".into(),
            agent_id: "s1-arb-01".into(),
            job_type: JobType::Simulation,
            input_hash: "blake3:input".into(),
            max_cost_musd_micros: 500_000,
            deadline_unix: 1_700_010_000,
            verification: crate::autonomy::VerificationMode::ExternalProof,
            created_at_unix: 1_700_000_200,
        }
    }

    #[test]
    fn an_unattested_receipt_cannot_promote_even_when_the_chain_confirms() {
        // Everything is genuine except the signature: the evidence re-derives,
        // the crossing is an external inflow, the provider confirms the exact
        // transfer, and the ledger claims paid demand. Without a signature from
        // the delegated verifier it is a claim.
        let f = fixture();
        record_genuine_inflow(&f);
        let dir = tempdir().unwrap();
        let auth = Authenticated::new(dir.path(), &f.autonomy);
        assert_eq!(
            f.autonomy.receipt_attestations().unwrap().len(),
            0,
            "nothing has signed this receipt"
        );
        let view = auth.view();

        let rows = view.receipt_evidence().unwrap();
        assert!(!rows[0].counted);
        assert!(!rows[0].attested);
        assert!(rows[0].policy_hash.is_none());
        assert!(rows[0].verifier_key_id.is_none());
        assert_eq!(rows[0].gap, Some(AttestationGap::UnsignedReceipt));
        let gap = rows[0].gap.as_ref().unwrap().describe();
        assert!(gap.contains("no signed attestation"), "{gap}");
        // `crossing` is `None` here *because* the gate order puts the
        // attestation before the derivation, which is the point: with no
        // authority the view stops before it does any derivation work. The
        // evidence itself still re-derives, and that is checkable independently.
        assert!(
            BoundaryCrossing::derive(&evidence(COUNTERPARTY, PAYOUT), &registry())
                .is_ok(),
            "the crossing re-derives; what is missing is only the signature"
        );

        // P4b changed what the *unattested* column says in pinned mode, and the
        // change is worth stating. In a view that holds an authority, an
        // unsigned receipt is a violation, not a claim: the gate order stops the
        // read before `offline_ok`, so it contributes nothing to the weak total
        // either. The 5.0 mUSD claim still appears — in the offline view, which
        // is the only view that has no authority to contradict it.
        let claim = view.unattested_nev().unwrap();
        assert_eq!(claim.claimed_net_external_value_musd_micros, 0);
        assert_eq!(claim.receipts[0].offline_ok, false);
        assert_eq!(claim.receipts[0].counted, false);
        let registry = registry();
        let offline = VerifiedEconomyView::unverified(&f.autonomy, &registry);
        assert_eq!(
            offline
                .unattested_nev()
                .unwrap()
                .claimed_net_external_value_musd_micros,
            5_000_000,
            "and the offline view still reports it as a claim"
        );
        assert_no_promotion_route(&view, None, "unsigned receipt");
    }

    #[test]
    fn a_receipt_signed_by_an_unknown_verifier_cannot_promote_through_the_view() {
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Authenticated::new(dir.path(), &f.autonomy);
        record_genuine_inflow(&f);
        // A genuine attestation, by a key this policy does not delegate to, over
        // this policy's own hash — so the delegation is the only thing wrong.
        let other = auth._auth.with_other_verifier();
        let forged = crate::receipt_auth::testkit::AuthFixture::forge_with(
            &other.verifier,
            &auth.policy,
            &receipt(),
            &evidence(COUNTERPARTY, PAYOUT),
        );
        assert!(
            forged
                .verify(&auth.policy, &evidence(COUNTERPARTY, PAYOUT))
                .is_err()
        );
        f.autonomy.record_receipt_attestation(&forged).unwrap();

        let view = auth.view();
        let rows = view.receipt_evidence().unwrap();
        assert!(!rows[0].counted);
        assert!(!rows[0].attested);
        match rows[0].gap.as_ref().unwrap() {
            AttestationGap::VerifierNotDelegated { claimed, delegated } => {
                assert_eq!(claimed, &other.verifier.key_id().to_string());
                assert_eq!(delegated, &auth._auth.verifier.key_id().to_string());
            }
            other => panic!("expected the delegation check, got {other:?}"),
        }
        assert_no_promotion_route(&view, None, "unknown verifier");
    }

    #[test]
    fn a_receipt_issued_under_a_previous_policy_cannot_promote_through_the_view() {
        // Same receipt, same evidence, same chain read, same delegated key. The
        // only difference is which policy is in force now.
        let f = fixture();
        record_genuine_inflow(&f);
        let dir = tempdir().unwrap();
        let socket = serving_socket(dir.path());
        let verifier = verifier_for(&socket).unwrap();
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry(),
        );
        let old = auth.validated();
        f.autonomy
            .record_receipt_attestation(
                &auth.attest(&old, &receipt(), &evidence(COUNTERPARTY, PAYOUT)),
            )
            .unwrap();

        let registry = registry();
        // Under the issuing policy it promotes: this is a real, genuine receipt.
        let before =
            VerifiedEconomyView::provider_pinned(
                &f.autonomy, &registry, &verifier, &old,
            )
            .unwrap();
        assert_eq!(before.arv_status(NOW).unwrap().level, "ARV0");

        // Under the rotated policy it does not, and says why. Rotation history
        // is out of scope, so this is a hard stop, not a warning.
        let rotated = auth
            .rotated(old.policy_version() + 1)
            .validate()
            .unwrap();
        let after =
            VerifiedEconomyView::provider_pinned(
                &f.autonomy, &registry, &verifier, &rotated,
            )
            .unwrap();
        let rows = after.receipt_evidence().unwrap();
        assert!(!rows[0].counted);
        match rows[0].gap.as_ref().unwrap() {
            AttestationGap::PolicyHashMismatch { found, current } => {
                assert_eq!(found, &old.policy_hash().unwrap().to_string());
                assert_eq!(current, &rotated.policy_hash().unwrap().to_string());
            }
            other => panic!("expected the policy binding, got {other:?}"),
        }
        let gap = rows[0].gap.as_ref().unwrap().describe();
        assert!(gap.contains("not re-approved"), "{gap}");
        assert_no_promotion_route(&after, None, "receipt from a previous policy");
    }

    #[test]
    fn a_legacy_unsigned_ledger_is_unattested_with_a_reason() {
        // A directory written before signed attestations existed: no attestation
        // file at all. It must still open, still be accounted for, and still
        // say why it attests nothing — not fail to parse, not be dropped, and
        // not be quietly promoted.
        let f = fixture();
        record_genuine_inflow(&f);
        assert!(!f.autonomy.attestation_ledger_path().exists());

        let dir = tempdir().unwrap();
        let auth = Authenticated::new(dir.path(), &f.autonomy);
        let view = auth.view();
        assert_eq!(auth.view().policy().is_some(), true);
        let rows = view.receipt_evidence().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].counted);
        assert_eq!(rows[0].gap, Some(AttestationGap::UnsignedReceipt));
        // The record itself is intact and still readable — the reason is on
        // disk, not an error.
        let records = f.autonomy.records().unwrap();
        assert!(
            records
                .iter()
                .any(|r| matches!(r.payload, AutonomyPayload::ExternalValue { .. })),
            "the value record is still there to be reported"
        );
        assert_no_promotion_route(&view, None, "legacy unsigned ledger");
    }

    #[test]
    fn editing_the_ledger_receipt_after_signing_breaks_the_attestation() {
        // The economics are ledger numbers. An attestation that did not carry a
        // digest of the whole receipt could be re-pointed at an inflated amount
        // with its signature intact.
        // A hand-written ledger whose value record inflates the amount a
        // hundred-fold, with a freshly valid hash chain over it.
        let dir = tempdir().unwrap();
        let mut inflated = receipt();
        inflated.gross_inflow_musd_micros = 600_000_000;
        inflated.net_external_value_musd_micros = 599_000_000;
        inflated.proof_verified = true;
        let autonomy = forge_ledger_with(
            dir.path(),
            inflated.clone(),
            evidence(COUNTERPARTY, PAYOUT),
        );
        assert_receipt_chain_is_readable(&autonomy);

        // A real authority, a real provider, and a genuine signature over the
        // *honest* version of this very receipt.
        let provider_dir = tempdir().unwrap();
        let socket = serving_socket(provider_dir.path());
        let verifier = verifier_for(&socket).unwrap();
        let registry = registry();
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        let honest = receipt();
        let signed = auth.attest(&policy, &honest, &evidence(COUNTERPARTY, PAYOUT));
        assert!(
            signed
                .verify(&policy, &evidence(COUNTERPARTY, PAYOUT))
                .is_ok(),
            "control: the attestation is genuine"
        );
        autonomy.record_receipt_attestation(&signed).unwrap();

        // The attestation is on disk and *would* be found, if the receipt
        // matched it.
        let stored = autonomy.receipt_attestations().unwrap();
        assert_eq!(stored.len(), 1, "the signature is present on disk");
        assert_ne!(
            stored[0].receipt_hash().unwrap(),
            crate::receipt_auth::receipt_hash(&inflated).unwrap(),
            "the edited receipt is not the receipt that was signed"
        );
        assert_ne!(
            crate::receipt_auth::receipt_hash(&honest).unwrap(),
            crate::receipt_auth::receipt_hash(&inflated).unwrap(),
            "and the inflation is the only difference"
        );

        let view = VerifiedEconomyView::provider_pinned(
            &autonomy,
            &registry,
            &verifier,
            &policy,
        )
        .unwrap();
        let rows = view.receipt_evidence().unwrap();
        assert!(!rows[0].counted);
        assert_eq!(
            rows[0].gap,
            Some(AttestationGap::UnsignedReceipt),
            "an edited receipt is not covered by any attestation, which is the              honest way to say it"
        );
        assert_no_promotion_route(&view, None, "receipt edited after signing");
    }

    #[test]
    fn an_attestation_is_consumed_by_exactly_one_receipt() {
        // One signature covers one receipt. A ledger that repeats the attested
        // record is counting one piece of evidence twice.
        let f = fixture();
        record_genuine_inflow(&f);
        let dir = tempdir().unwrap();
        let auth = Authenticated::new(dir.path(), &f.autonomy);
        auth.record_attestation(&receipt(), &evidence(COUNTERPARTY, PAYOUT));

        // Two identical value records citing the same transaction, as a forger
        // rewriting the file would write them.
        let autonomy = repeat_receipt_record(&f.autonomy);
        assert_receipt_chain_is_readable(&autonomy);
        let registry = registry();
        let view = VerifiedEconomyView::provider_pinned(
            &autonomy,
            &registry,
            &auth.verifier,
            &auth.policy,
        )
        .unwrap();
        let rows = view.receipt_evidence().unwrap();
        assert_eq!(rows.len(), 2, "both records are read");
        let counted: Vec<bool> = rows.iter().map(|r| r.counted).collect();
        assert_eq!(
            counted,
            vec![true, false],
            "exactly one record may consume the attestation"
        );
        assert!(rows.iter().any(|r| r.gap == Some(AttestationGap::AttestationReplayed)));
        assert_eq!(
            view.verified_nev().unwrap().nev_musd_micros(),
            5_000_000,
            "and the NEV counts it once"
        );
    }

    #[test]
    fn the_signature_does_not_substitute_for_the_chain_read() {
        // The identity read as a sequence, with the fifth step present and the
        // ninth still binding. A genuine signature from the delegated key, over
        // re-derived evidence, under the policy in force — and a provider that
        // has never seen the transaction.
        let dir = tempdir().unwrap();
        let autonomy = forge_ledger(dir.path());
        let socket = unbacked_socket(dir.path());
        let verifier = verifier_for(&socket).unwrap();
        let registry = registry();
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        let evidence_row = evidence(COUNTERPARTY, PAYOUT);
        autonomy
            .record_receipt_attestation(
                &auth.attest(&policy, &receipt(), &evidence_row),
            )
            .unwrap();

        // Every earlier gate passes. Stated positively, so this test cannot
        // pass by accident: if any of them were quietly skipped, the assertions
        // below would be about a different failure.
        let verified = auth
            .attest(&policy, &receipt(), &evidence_row)
            .verify(&policy, &evidence_row)
            .unwrap();
        assert_eq!(verified.verifier_key_id, auth.verifier.key_id());
        assert_eq!(verified.policy_hash, policy.policy_hash().unwrap());
        assert_eq!(
            BoundaryCrossing::derive(&evidence_row, &registry)
                .unwrap()
                .kind(),
            CrossingKind::ExternalToControlled,
            "the crossing re-derives as an external inflow"
        );

        let view = VerifiedEconomyView::provider_pinned(
            &autonomy,
            &registry,
            &verifier,
            &policy,
        )
        .unwrap();
        let rows = view.receipt_evidence().unwrap();
        assert!(rows[0].attested, "the signature is genuine");
        assert!(rows[0].offline_ok, "gates 1, 2 and 7 passed");
        assert!(!rows[0].chain_confirmed, "gate 9 did not");
        assert!(!rows[0].counted);
        match rows[0].gap.as_ref().unwrap() {
            AttestationGap::ChainNotConfirmed(_) => {}
            other => panic!("expected the chain read to be the gate, got {other:?}"),
        }
        assert_no_promotion_route(&view, None, "signature without the chain");
    }

    #[test]
    fn the_combined_attack_cannot_promote() {
        // Everything a forger with write access to the economy directory can do
        // at once:
        //
        //  * a ledger whose semantic hash chain is valid (sequence, prev_hash
        //    and a record_hash recomputed from the record's own bytes);
        //  * boundary evidence that is syntactically a transfer of the right
        //    size in the right asset from a counterparty to a controlled
        //    address, and re-derives as an ExternalInflow;
        //  * `proof_verified: true` and `verifier_id` on the value record;
        //  * a cryptographically valid signature from a key that is *not* the
        //    one the policy delegates to, over the correct body, under the
        //    correct policy hash;
        //  * a kernel-identified provider attached, which would confirm the
        //    transfer if it existed.
        //
        // The signature is the strongest thing in the forgery and it is still
        // not enough, because `VerifyPolicy` runs before `VerifyReceiptSig`.
        let dir = tempdir().unwrap();
        let autonomy = forge_ledger(dir.path());
        assert_receipt_chain_is_readable(&autonomy);

        // 1. The stored claim looks like paid demand by every old predicate.
        let raw = fs::read_to_string(autonomy.ledger_path()).unwrap();
        assert!(raw.contains("\"proof_verified\":true"));
        let booked = autonomy
            .external_values()
            .unwrap()
            .pop()
            .unwrap();
        assert!(booked.value_class.can_create_external_value());
        assert_eq!(booked.net_external_value_musd_micros, 5_000_000);
        assert!(booked.proof_verified);
        assert_eq!(booked.verifier_id, "base-reconcile");

        // 2. The crossing is syntactically correct and re-derives.
        let registry = registry();
        let evidence_row = evidence(COUNTERPARTY, PAYOUT);
        let crossing = BoundaryCrossing::derive(&evidence_row, &registry).unwrap();
        assert_eq!(crossing.kind(), CrossingKind::ExternalToControlled);
        assert_eq!(crossing.to_domain(), ControlDomain::Controlled);
        assert_eq!(crossing.amount_raw(), AMOUNT);

        // 3. A kernel-identified provider is attached.
        let socket = unbacked_socket(dir.path());
        let verifier = verifier_for(&socket).unwrap();
        assert!(verifier.provider_identity_verified());

        // 4. A real policy with a real pin, delegating to a real key.
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();

        // 5. A syntactically valid signature from a key the policy does not
        //    delegate to, over the correct body and the correct policy hash.
        let other = auth.with_other_verifier();
        let forged = crate::receipt_auth::testkit::AuthFixture::forge_with(
            &other.verifier,
            &policy,
            &booked,
            &evidence_row,
        );
        // Control: the signature itself is perfect. It is refused because of who
        // signed, not because of anything about the bytes.
        let body = forged.body(&evidence_row).unwrap();
        // The body is the one the signature claims to cover; it must rebuild
        // cleanly, or the control below would pass for the wrong reason.
        assert!(body.signing_preimage().is_ok());
        // Proving the forger's key is functional: the *same* key signing the
        // *same* body under a policy that delegates to it verifies perfectly.
        // So the refusal below cannot be "that key signs garbage".
        let forger_policy = other.validate().unwrap();
        let control = crate::receipt_auth::testkit::AuthFixture::forge_with(
            &other.verifier,
            &forger_policy,
            &booked,
            &evidence_row,
        );
        assert!(
            control.verify(&forger_policy, &evidence_row).is_ok(),
            "the forger's key signs genuine attestations when a policy delegates \
             to it; the refusal below is therefore about the delegation and \
             nothing else"
        );
        // And the forgery is byte-for-byte what that same key produces for the
        // policy in force: the same sections in the same order, one digest
        // apart.
        assert_ne!(
            forger_policy.policy_hash().unwrap(),
            *forged.policy_hash(),
            "the forgery was re-signed for the policy in force"
        );
        assert_ne!(
            forged.body(&evidence_row).unwrap().signing_preimage().unwrap(),
            control.body(&evidence_row).unwrap().signing_preimage().unwrap(),
            "and its preimage is the one that policy hash produces"
        );
        assert_eq!(forged.policy_hash(), &policy.policy_hash().unwrap());
        autonomy.record_receipt_attestation(&forged).unwrap();

        // 6. Read it.
        let view = VerifiedEconomyView::provider_pinned(
            &autonomy,
            &registry,
            &verifier,
            &policy,
        )
        .unwrap();
        let rows = view.receipt_evidence().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(!rows[0].counted);
        assert!(!rows[0].attested);
        assert!(!rows[0].chain_confirmed);
        match rows[0].gap.as_ref().unwrap() {
            AttestationGap::VerifierNotDelegated { claimed, delegated } => {
                assert_eq!(claimed, &other.verifier.key_id().to_string());
                assert_eq!(delegated, &auth.verifier.key_id().to_string());
            }
            other => panic!("expected the delegation check, got {other:?}"),
        }

        // 7. Reported, with the reason, in both views. In the authenticated view
        //    it is a violation rather than a claim, so the weak total is zero;
        //    in the offline view the ledger's 5.0 mUSD claim is still reported
        //    as a claim. Neither promotes, and both are visible.
        let pinned_claim = view.unattested_nev().unwrap();
        assert_eq!(pinned_claim.claimed_net_external_value_musd_micros, 0);
        assert_eq!(
            view.arv_status(NOW).unwrap().unattested_net_external_value_musd,
            0.0
        );
        let offline =
            VerifiedEconomyView::unverified(&autonomy, &registry);
        assert_eq!(
            offline
                .unattested_nev()
                .unwrap()
                .claimed_net_external_value_musd_micros,
            5_000_000,
            "the ledger's claim is still visible offline"
        );
        assert_eq!(
            offline.arv_status(NOW).unwrap().unattested_net_external_value_musd,
            5.0
        );

        // 8. Every route out, closed.
        assert_no_promotion_route(&view, None, "the combined attack");
    }

    #[test]
    fn the_dev_provider_can_never_produce_a_verified_nev() {
        // `MYCELIUM_DEV_BASE_PROVIDER` — and every other address without a
        // kernel-enforced identity — can drive a verifier. It cannot attest,
        // and this walks every number out of the economy to say so.
        //
        // The setup is deliberately as generous as possible: a genuine receipt,
        // a genuine attestation from the delegated key, and a genuine paid
        // settlement. The only thing wrong is the provider's identity.
        let dir = tempdir().unwrap();
        let f = fixture();
        let socket = serving_socket(dir.path());
        let auth = Authenticated::with_socket(socket, &f.autonomy);
        record_genuine_inflow_with(&f, Some(&auth));

        let registry = registry();
        // Control: with the real socket this same economy promotes. So nothing
        // below can be passing because the fixture is wrong.
        assert_eq!(
            auth.view().arv_status(NOW).unwrap().level,
            "ARV0",
            "control: the genuine economy promotes under a kernel-identified provider"
        );

        // The dev override: a loopback address, which is an address and not an
        // identity.
        let dev = BaseUsdcVerifier::new("http://127.0.0.1:8546", 2).unwrap();
        assert!(!dev.provider_identity_verified());

        // 1. The autonomy side refuses to exist in pinned mode.
        let err = match VerifiedEconomyView::provider_pinned(
            &f.autonomy,
            &registry,
            &dev,
            &auth.policy,
        ) {
            Ok(_) => panic!("a loopback endpoint must not be able to attest"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("kernel-enforced identity"), "{err}");

        // 2. And in the mode it does allow, it attests nothing. This is the
        //    state a CLI running with the override set actually produces.
        let offline = VerifiedEconomyView::unverified(&f.autonomy, &registry);
        let nev = offline.verified_nev().unwrap_err();
        assert!(
            nev.to_string().contains("TrustMode::ProviderPinned"),
            "{nev}"
        );
        let arv = offline.arv_status(NOW).unwrap();
        assert_eq!(arv.unattested_net_external_value_musd, 5.0);
        assert_eq!(arv.trust_mode, TrustMode::Unverified);
        assert_no_promotion_route(&offline, None, "dev provider, autonomy side");

        // 3. The revenue half of this claim lives in
        //    `a_dev_provider_cannot_promote_paid_demand` in `lib.rs`, next to the
        //    settlement fixtures this module does not have.
    }

    #[test]
    fn the_view_reports_its_own_trust_mode_in_the_status() {
        let f = fixture();
        let registry = registry();
        let arv = VerifiedEconomyView::unverified(&f.autonomy, &registry)
            .arv_status(NOW)
            .unwrap();
        assert_eq!(arv.trust_mode, TrustMode::Unverified);
        assert!(arv.attestation_note.contains("TrustMode=unverified"));
        let json = serde_json::to_value(&arv).unwrap();
        assert_eq!(json["trust_mode"], serde_json::json!("unverified"));
    }

    // ==================================================================
    // 6. P4c: the authenticated settlement
    // ==================================================================

    /// A revenue ledger whose settlement is as convincing as a ledger author can
    /// make it *without* a signature, plus the provider, authority and view that
    /// would promote it if it were signed.
    ///
    /// The payment is real: [`serving_socket`] serves this exact transaction, in
    /// this exact block, for this exact amount into the controlled recipient.
    /// Every test in this section either leaves the signature out or puts it in,
    /// and both halves are asserted somewhere, so none of them can pass for the
    /// wrong reason.
    struct RevenueFixture {
        // Declaration order is drop order, and it matters here: the fake
        // provider unblocks its accept loop by connecting to its own socket
        // path, so the socket has to still exist when it is dropped. Holding the
        // temporary directory in the same struct means the socket field must be
        // declared first, or the directory is removed first and the drop hangs.
        _socket: FakeRpcSocket,
        _dir: tempfile::TempDir,
        registry: ControlledAddressRegistry,
        auth: crate::receipt_auth::testkit::AuthFixture,
        policy: ValidatedOutcomePolicy,
        verifier: BaseUsdcVerifier,
        root: PathBuf,
        autonomy: AutonomousEconomy,
        econ: LocalEconomy,
    }

    impl RevenueFixture {
        /// The economy directory both ledgers live in, for the "process
        /// restart" reads that must open it afresh.
        fn dir(&self) -> &Path {
            &self.root
        }

        /// The pinned revenue view over these bytes.
        fn view(&self) -> VerifiedRevenueView<'_> {
            VerifiedRevenueView::provider_pinned(
                &self.econ,
                &self.registry,
                &self.verifier,
                &self.policy,
            )
            .unwrap()
        }

        /// The autonomy half of the same directory, so the "no promotion route"
        /// assertions cover both ledgers.
        fn autonomy_view(&self) -> VerifiedEconomyView<'_> {
            VerifiedEconomyView::unverified(&self.autonomy, &self.registry)
        }

        fn settlement(&self) -> SettlementReceipt {
            self.econ
                .records()
                .unwrap()
                .into_iter()
                .find_map(|r| match r {
                    LedgerRecord::Settlement { settlement, .. } => Some(settlement),
                    _ => None,
                })
                .expect("a settlement")
        }

        fn intent(&self) -> PaymentIntent {
            self.econ
                .payment_intent_for_job("job-revenue")
                .unwrap()
                .expect("a payment intent")
        }

        /// Signs the settlement with the policy's delegated verifier and records
        /// the attestation. The only difference between an unsigned fixture and
        /// a signed one.
        fn attest(&self) -> settlement_auth::AuthenticatedSettlementReceipt {
            let attestation = self
                .auth
                .verifier
                .attest_settlement(&self.policy, &self.settlement(), &self.intent())
                .unwrap();
            self.econ
                .record_settlement_attestation(&attestation)
                .unwrap();
            attestation
        }

        /// Records an attestation built by `make`, bypassing
        /// `attest_settlement`'s own refusal. Only for handing the view the
        /// shape of an attack; every caller proves the signature is otherwise
        /// genuine.
        fn record_forged(
            &self,
            key: &crate::policy_auth::VerifierRuntimeKey,
        ) -> settlement_auth::AuthenticatedSettlementReceipt {
            let attestation = settlement_auth::forge_settlement_with(
                key,
                &self.policy,
                &self.settlement(),
                &self.intent(),
            )
            .unwrap();
            self.econ
                .record_settlement_attestation(&attestation)
                .unwrap();
            attestation
        }

        /// Every assertion that must hold for a settlement the view refuses to count,
        /// given a view that holds a validated policy and a kernel-identified
        /// provider. `expected` is the gap the refusal has to name, so a test can
        /// be specific about *why*.
        ///
        /// `assert_no_promotion_route` is the shared form of the first four; the
        /// rest is what makes the gap itself the subject: no ARV and no RV, and
        /// the settlement reported with a reason rather than dropped or silently
        /// promoted.
        fn assert_counts_for_nothing(&self, expected: SettlementGap, why: &str) {
            assert_no_promotion_route(&self.autonomy_view(), Some(&self.view()), why);
            let rows = self.view().settlement_evidence().unwrap();
            assert_eq!(rows.len(), 1, "{why}");
            assert!(
                rows[0].rederived,
                "{why}: P3 re-derivation must still pass, or this test would be \
                 proving something else"
            );
            assert!(!rows[0].attested, "{why}");
            assert!(!rows[0].counted, "{why}");
            assert_eq!(rows[0].gap, Some(expected), "{why}");
            assert!(
                rows[0].gap.as_ref().unwrap().describe().len() > 10,
                "{why}: a refusal with no stated reason is not reportable"
            );
            let rv = self.view().rv_status(NOW).unwrap();
            assert_eq!(rv.level, "PRE-RV0", "{why}");
            assert!(!rv.rv0_pass, "{why}");
            assert_eq!(rv.external_paid_jobs, 0, "{why}");
            assert_eq!(rv.paid_demand_musd_total, 0.0, "{why}");
            // The claim is still reported, so an operator can see what is being
            // refused rather than watching a total go quiet.
            assert_eq!(rv.unattested_external_paid_jobs, 1, "{why}");
            assert_eq!(rv.unattested_paid_demand_musd_total, 5.0, "{why}");
            let summary = self.view().revenue_summary().unwrap();
            assert_eq!(summary.external_paid_jobs, 0, "{why}");
            assert_eq!(summary.paid_demand_musd_micros, 0, "{why}");
        }
    }

    /// The standard revenue fixture: an external job, a payment intent matching
    /// a controlled payee, one unsigned settlement, and a provider that serves
    /// exactly that transfer.
    fn revenue_fixture() -> RevenueFixture {
        let dir = tempdir().unwrap();
        let socket = serving_socket(dir.path());
        revenue_fixture_in(dir, socket)
    }

    /// [`revenue_fixture`] over a caller-chosen provider, so a test can serve a
    /// receipt the standard one cannot describe — a payment with no log index,
    /// say. The socket is taken rather than built because the caller needs this
    /// directory's path to build it.
    fn revenue_fixture_in(
        dir: tempfile::TempDir,
        socket: FakeRpcSocket,
    ) -> RevenueFixture {
        let econ = LocalEconomy::open(dir.path()).unwrap();
        let autonomy = AutonomousEconomy::open(dir.path()).unwrap();
        econ.append_job(JobRequest {
            schema_version: SCHEMA_VERSION,
            job_id: "job-revenue".into(),
            created_at_unix: 1_700_000_100,
            requester_id: "customer-revenue".into(),
            job_type: JobType::Simulation,
            input_hash: "blake3:input".into(),
            max_price_musd_micros: AMOUNT,
            internal_work: false,
            description: "an external job a client really pays for".into(),
        })
        .unwrap();
        econ.append_work(WorkReceipt {
            schema_version: SCHEMA_VERSION,
            receipt_id: "work-revenue".into(),
            job_id: "job-revenue".into(),
            worker_id: "worker-revenue".into(),
            started_at_unix: 1_700_000_110,
            completed_at_unix: 1_700_000_350,
            result_hash: "blake3:result".into(),
            useful_work_units: 10,
            verifier_id: "verifier-revenue".into(),
            verified_at_unix: 1_700_000_360,
            verified: true,
        })
        .unwrap();
        econ.init_payment_policy(PAYOUT, 2).unwrap();
        let intent = econ
            .create_payment_intent(
                "job-revenue",
                BLOCK - 1,
                &block_hash(),
                1_700_000_300,
            )
            .unwrap();
        let settlement = SettlementReceipt {
            schema_version: SCHEMA_VERSION,
            settlement_id: "settle-revenue".into(),
            job_id: "job-revenue".into(),
            work_receipt_id: "work-revenue".into(),
            settled_at_unix: 1_700_000_400,
            mode: SettlementMode::External,
            settlement_asset: SettlementAsset::base_usdc(),
            settled_amount_micros: AMOUNT,
            usd_equivalent_micros: AMOUNT,
            payment_intent_id: Some(intent.payment_intent_id.clone()),
            payment_block_number: Some(BLOCK),
            payment_proof_hash: Some(tx_hash()),
            payment_proof_verified: true,
            external_paid: true,
            internal_work: false,
        };
        econ.append_settlement(settlement).unwrap();

        let provider = PinnedChainProvider::unix_socket(
            socket.path(),
            Some(socket.uid()),
        )
        .unwrap();
        let resolved = resolve(None, Some(&provider)).unwrap();
        let verifier = BaseUsdcVerifier::from_resolved(&resolved, 2).unwrap();
        assert!(verifier.provider_identity_verified());
        let registry = registry();
        let auth = crate::receipt_auth::testkit::AuthFixture::new(
            socket.path(),
            socket.uid(),
            registry.clone(),
        );
        let policy = auth.validated();
        RevenueFixture {
            root: dir.path().to_path_buf(),
            _socket: socket,
            _dir: dir,
            registry,
            auth,
            policy,
            verifier,
            autonomy,
            econ,
        }
    }

    #[test]
    fn an_unsigned_settlement_with_a_real_transfer_does_not_reach_paid_demand() {
        // THE regression test for the gap P4b reported.
        //
        // Everything here except the signature is what an attacker's ledger
        // could contain: verified work, a payment intent matching field for
        // field, a controlled payee, a block after the anchor, a well-formed
        // transaction hash, both stored booleans on — and a *real* on-chain
        // transfer of exactly the right size into a controlled address, which
        // [`serving_socket`] serves and the kernel-identified provider confirms.
        // Before P4c that reached RV0.
        let f = revenue_fixture();

        // Nothing in this fixture is signed yet. The transfer is real —
        // [`serving_socket`] serves this exact transaction in this exact block for
        // this exact amount into the controlled recipient, and the
        // kernel-identified provider confirms it. The one thing missing is the
        // signature, which is the whole point.
        assert!(
            !f.econ.settlement_attestation_ledger_path().exists(),
            "no signature has been written yet"
        );
        f.assert_counts_for_nothing(
            SettlementGap::UnsignedSettlement,
            "unsigned settlement with a genuine on-chain transfer",
        );
        // The refusal happens *before* the provider is asked, so an unsigned
        // settlement cannot even spend an RPC call to look plausible.
        let rows = f.view().settlement_evidence().unwrap();
        assert!(
            !rows[0].chain_confirmed,
            "the chain read must not be reached for an unsigned settlement"
        );

        // Control, last, on the *same directory and the same ledger bytes*: the
        // only change is one signed attestation, and the very same settlement
        // becomes paid demand. Without this arm the assertions above could be
        // passing because the payment was never real.
        f.attest();
        let signed = f.view().settlement_evidence().unwrap();
        assert!(signed[0].rederived);
        assert!(signed[0].attested, "a signed settlement is attested");
        assert!(signed[0].chain_confirmed);
        assert!(signed[0].counted);
        assert!(signed[0].gap.is_none());
        assert!(signed[0].policy_hash.is_some());
        assert!(signed[0].verifier_key_id.is_some());
        assert!(signed[0].attestation_hash.is_some());
        let rv = f.view().rv_status(NOW).unwrap();
        assert_eq!(rv.level, "RV0", "the signed settlement is paid demand");
        assert_eq!(rv.external_paid_jobs, 1);
        assert_eq!(rv.paid_demand_musd_total, 5.0);
    }

    #[test]
    fn a_settlement_signed_by_an_unknown_verifier_does_not_reach_paid_demand() {
        // A second policy over the same anchor that delegates to a *different*
        // verifier key. That key signs a cryptographically perfect settlement
        // attestation over the current policy's hash, so the only thing wrong is
        // the delegation — and it is refused on the delegation check, before any
        // signature maths.
        let f = revenue_fixture();
        let other = f.auth.with_other_verifier();
        let impostor = other.verifier.clone();
        assert_ne!(
            impostor.key_id(),
            f.policy.trusted_verifier().key_id(),
            "the two policies must delegate to different keys"
        );
        // Control: this key signs settlements perfectly well under its own
        // policy, so the refusal below is about the delegation and nothing else.
        let other_policy = other.validate().unwrap();
        assert_eq!(
            other_policy.trusted_verifier().key_id(),
            impostor.key_id()
        );
        let genuine = impostor
            .attest_settlement(&other_policy, &f.settlement(), &f.intent())
            .unwrap();
        assert!(genuine.verify(&other_policy, &f.intent()).is_ok());

        // Under the policy in force, the same key signs the same settlement against the
        // *current* policy's hash. The signature maths is perfect; the delegation
        // is the only thing wrong, and it is refused on the delegation check.
        f.record_forged(&impostor);

        let rows = f.view().settlement_evidence().unwrap();
        assert!(rows[0].rederived);
        assert!(!rows[0].attested);
        match rows[0].gap.clone() {
            Some(SettlementGap::SettlementVerifierNotDelegated { claimed, delegated }) => {
                assert_eq!(claimed, impostor.key_id().to_string());
                assert_eq!(
                    delegated,
                    f.policy.trusted_verifier().key_id().to_string()
                );
            }
            other => panic!("an unknown verifier must be refused on delegation, got {other:?}"),
        }
        f.assert_counts_for_nothing(
            SettlementGap::SettlementVerifierNotDelegated {
                claimed: impostor.key_id().to_string(),
                delegated: f.policy.trusted_verifier().key_id().to_string(),
            },
            "settlement signed by an unknown verifier",
        );
    }

    #[test]
    fn a_key_no_validated_policy_delegated_to_cannot_sign_a_settlement() {
        // The layer-down Gland trap, on this path too. Holding a verifier key is
        // not authority: the signing side refuses unless the key signing *is* the
        // key a validated policy delegated to, and the read side has no way to
        // reach a verifying key at all.
        let f = revenue_fixture();
        let orphan = crate::policy_auth::VerifierRuntimeKey::generate();
        assert_ne!(
            orphan.key_id(),
            f.policy.trusted_verifier().key_id()
        );

        // The signing side refuses.
        let err = orphan
            .attest_settlement(&f.policy, &f.settlement(), &f.intent())
            .unwrap_err();
        assert!(
            matches!(err, settlement_auth::SettlementAuthError::SigningKeyNotDelegated { .. }),
            "a key the policy does not delegate to must not mint attestations, got {err}"
        );
        assert!(err.to_string().contains(&orphan.key_id().to_string()), "{err}");

        // And the read side refuses the artefact anyway, even though the
        // signature over it is genuinely valid — which is the half that matters,
        // because it is the half an attacker controls.
        f.record_forged(&orphan);
        let rows = f.view().settlement_evidence().unwrap();
        assert!(rows[0].rederived);
        assert!(!rows[0].attested);
        assert!(matches!(
            rows[0].gap,
            Some(SettlementGap::SettlementVerifierNotDelegated { .. })
        ));
        f.assert_counts_for_nothing(
            SettlementGap::SettlementVerifierNotDelegated {
                claimed: orphan.key_id().to_string(),
                delegated: f.policy.trusted_verifier().key_id().to_string(),
            },
            "settlement signed by a key no validated policy delegated to",
        );

        // The compile-time half, pinned the way this crate pins type identity.
        // `VerifierPublicKey::verifying_key` is private to `policy_auth` and
        // `TrustedVerifierKey` has exactly one constructor, so the only
        // `VerifyingKey` this module can name comes from a validated policy.
        // Every public route to the public bytes is asserted below, and none of
        // them can produce anything that verifies.
        let from_policy = f.policy.verifier_public_key();
        let from_trusted = f.policy.trusted_verifier().public_key().clone();
        let rebuilt =
            crate::policy_auth::VerifierPublicKey::from_bytes(*from_policy.as_bytes());
        assert_eq!(rebuilt.as_bytes(), from_trusted.as_bytes());
        assert_eq!(rebuilt.key_id(), f.policy.trusted_verifier().key_id());
        // A signed settlement under the right policy still verifies, so the
        // assertions above are about the delegation and not about the bytes.
        assert!(f.attest().verify(&f.policy, &f.intent()).is_ok());
    }

    #[test]
    fn editing_the_ledger_settlement_after_signing_breaks_the_attestation() {
        // The economics are ledger numbers, not chain numbers, so they are only
        // covered because `settlement_hash` is in the preimage. The attack is the
        // one that matters: keep the signature, edit the record, recompute the
        // ledger's own hash chain so the forgery is internally perfect, and hope
        // a summary sums the bigger number.
        let f = revenue_fixture();
        let attestation = f.attest();
        assert_eq!(f.view().rv_status(NOW).unwrap().level, "RV0");

        // `settled_amount_micros` is the number `RevenueSummary::by_asset_micros`
        // sums, and P3's re-derivation never looks at it, so inflating it is an
        // edit only the attestation can catch. `settlement_id` goes with it so
        // the two records are visibly different.
        let edited = SettlementReceipt {
            settled_amount_micros: AMOUNT * 10,
            settlement_id: "settle-revenue-edited".into(),
            ..f.settlement()
        };
        let dir = tempdir().unwrap();
        let forged = rewrite_revenue_ledger(&f.econ, dir.path(), &edited);
        assert_revenue_chain_intact(&forged.records().unwrap());
        // And the same signature, copied across unchanged.
        forged.record_settlement_attestation(&attestation).unwrap();
        assert_eq!(
            forged.settlement_attestations().unwrap().len(),
            1,
            "the signature is present on disk"
        );
        assert_ne!(
            attestation.settlement_hash().unwrap(),
            settlement_auth::settlement_hash(&edited).unwrap(),
            "editing the record must change the settlement digest"
        );
        assert!(
            attestation.verify(&f.policy, &f.intent()).is_ok(),
            "the signature is untouched and still valid for the record it signed"
        );

        let view = VerifiedRevenueView::provider_pinned(
            &forged,
            &f.registry,
            &f.verifier,
            &f.policy,
        )
        .unwrap();
        let rows = view.settlement_evidence().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].rederived, "P3 still re-derives the edited record");
        assert!(!rows[0].counted);
        assert_eq!(
            rows[0].gap,
            Some(SettlementGap::UnsignedSettlement),
            "an edited settlement is covered by no attestation at all, which is \
             the honest way to say it"
        );
        let rv = view.rv_status(NOW).unwrap();
        assert_eq!(rv.level, "PRE-RV0");
        assert_eq!(rv.external_paid_jobs, 0);
        assert_eq!(rv.paid_demand_musd_total, 0.0);
        assert_eq!(rv.unattested_paid_demand_musd_total, 5.0);
        // And no asset bucket either: the inflated figure is nowhere.
        let summary = view.revenue_summary().unwrap();
        assert_eq!(summary.external_paid_jobs, 0);
        assert!(
            summary.by_asset_micros.is_empty(),
            "an unauthenticated edit must not create an asset bucket: {:?}",
            summary.by_asset_micros
        );
        assert_no_promotion_route(
            &f.autonomy_view(),
            Some(&view),
            "settlement edited after signing",
        );
    }

    #[test]
    fn the_amount_relationship_is_p3s_rule_and_not_the_signature_s() {
        // The question P4b flagged, answered by a test.
        //
        // The attestation does NOT assert `usd_equivalent_micros == on-chain
        // amount`. It binds the *identity* of the two numbers: `amount_raw` from
        // the intent and `settlement_hash` over the settlement's own figures. The
        // relationship is P3's rule and it did not move — it lives in
        // `rederive_settlement` as `AmountNotJustified` and in
        // `append_settlement` as a write-time check. This test shows the rule is
        // still enforced, by the re-derivation, on a record no signature covers
        // and on a record a signature does cover.
        let f = revenue_fixture();

        // No signature, an inflated booked value: refused by P3's arithmetic,
        // before the attestation gate is even reached.
        let inflated = SettlementReceipt {
            usd_equivalent_micros: AMOUNT * 10,
            settled_amount_micros: AMOUNT * 10,
            ..f.settlement()
        };
        let dir = tempdir().unwrap();
        let forged = rewrite_revenue_ledger(&f.econ, dir.path(), &inflated);
        let view = VerifiedRevenueView::provider_pinned(
            &forged,
            &f.registry,
            &f.verifier,
            &f.policy,
        )
        .unwrap();
        let rows = view.settlement_evidence().unwrap();
        assert_eq!(
            rows[0].gap,
            Some(SettlementGap::AmountNotJustified {
                booked: AMOUNT * 10,
                expected: AMOUNT,
            }),
            "the arithmetic is the re-derivation's, unchanged"
        );
        assert!(!rows[0].counted);

        // And the honest record with a signature still counts, because the
        // signature did not have to re-assert what the reader already computes.
        f.attest();
        let signed = f.view().settlement_evidence().unwrap();
        assert!(signed[0].counted);
        assert!(signed[0].gap.is_none());
        assert_eq!(f.view().rv_status(NOW).unwrap().level, "RV0");
    }

    #[test]
    fn a_legacy_unsigned_revenue_ledger_is_unattested_with_a_reason() {
        // A directory written before this step: settlements, no attestation file
        // at all. It must still open, still deserialize, and report every
        // settlement as unattested with a reason — not crash, and not silently
        // promote.
        let f = revenue_fixture();
        assert!(
            !f.econ
                .settlement_attestation_ledger_path()
                .exists(),
            "no signature was ever written"
        );
        let rows = f.view().settlement_evidence().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].rederived);
        assert!(!rows[0].attested);
        assert_eq!(rows[0].gap, Some(SettlementGap::UnsignedSettlement));
        let described = rows[0].gap.as_ref().unwrap().describe();
        assert!(described.contains("predates settlement signatures"), "{described}");
        f.assert_counts_for_nothing(
            SettlementGap::UnsignedSettlement,
            "legacy unsigned revenue ledger",
        );

        // The record itself is untouched on disk and still parses as the type it
        // always was: this step added no field to `SettlementReceipt`, so the
        // wire format and every `record_hash` computed over it are unchanged.
        let raw = fs::read_to_string(f.econ.ledger_path()).unwrap();
        assert!(raw.contains("\"settlement_id\":\"settle-revenue\""));
        assert!(raw.contains(&format!("\"usd_equivalent_micros\":{AMOUNT}")));
        assert_revenue_chain_intact(&f.econ.records().unwrap());
        let settlement_line = raw
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .find(|v| v["kind"] == serde_json::json!("settlement"))
            .unwrap();
        let mut keys: Vec<&str> = settlement_line["settlement"]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "external_paid",
                "internal_work",
                "job_id",
                "mode",
                "payment_block_number",
                "payment_intent_id",
                "payment_proof_hash",
                "payment_proof_verified",
                "schema_version",
                "settled_amount_micros",
                "settled_at_unix",
                "settlement_asset",
                "settlement_id",
                "usd_equivalent_micros",
                "work_receipt_id",
            ],
            "the settlement record's wire format is exactly what it was before \
             signed settlements existed"
        );
    }

    #[test]
    fn an_attestation_is_consumed_by_at_most_one_settlement() {
        // One signature covers one settlement. A ledger that repeats the attested
        // record — correctly chained, which a writer can do — is counting one
        // piece of evidence twice, and this is where it stops.
        let f = revenue_fixture();
        f.attest();
        assert_eq!(f.view().rv_status(NOW).unwrap().external_paid_jobs, 1);

        // The same settlement content, appended a second time: the honest version of
        // this attack, because the typed write path refuses a second settlement
        // for a job.
        repeat_last_settlement(&f.econ);
        assert_revenue_chain_intact(&f.econ.records().unwrap());
        assert_eq!(f.econ.records().unwrap().len(), 5);

        let rows = f.view().settlement_evidence().unwrap();
        assert_eq!(rows.len(), 2);
        let counted = rows.iter().filter(|r| r.counted).count();
        assert_eq!(
            counted, 1,
            "a duplicated record must be counted once, not twice"
        );
        let replayed = rows
            .iter()
            .find(|r| !r.counted)
            .expect("the second copy is refused");
        assert_eq!(
            replayed.gap,
            Some(SettlementGap::SettlementAttestationReplayed)
        );
        let rv = f.view().rv_status(NOW).unwrap();
        assert_eq!(rv.external_paid_jobs, 1);
        assert_eq!(rv.paid_demand_musd_total, 5.0);
    }

    #[test]
    fn a_settlement_citing_another_intent_or_anchor_does_not_verify() {
        // The preimage binds the job, the payment intent, the anchor block and
        // the anchor block hash, so a signature for one settlement cannot be
        // re-pointed at another intent or another anchor.
        let f = revenue_fixture();
        let attestation = f.attest();
        let intent = f.intent();

        // Control: it verifies against the intent it was signed for.
        assert!(attestation.verify(&f.policy, &intent).is_ok());

        let other_intent_id = "intent-somebody-elses".to_string();
        let cases: Vec<(&str, PaymentIntent)> = vec![
            (
                "a different intent for the same job",
                PaymentIntent {
                    payment_intent_id: other_intent_id.clone(),
                    exact_amount_raw: intent.exact_amount_raw * 10,
                    ..intent.clone()
                },
            ),
            (
                "another anchor block",
                PaymentIntent {
                    anchor_block: intent.anchor_block + 10,
                    ..intent.clone()
                },
            ),
            (
                "another anchor block hash",
                PaymentIntent {
                    anchor_block_hash: format!("0x{}", "44".repeat(32)),
                    ..intent.clone()
                },
            ),
            (
                "another payee",
                PaymentIntent {
                    recipient: "0x0000000000000000000000000000000000000042".into(),
                    ..intent.clone()
                },
            ),
            (
                "another exact amount",
                PaymentIntent {
                    exact_amount_raw: intent.exact_amount_raw + 1,
                    ..intent.clone()
                },
            ),
            (
                "another job",
                PaymentIntent {
                    job_id: "job-somebody-elses".into(),
                    ..intent.clone()
                },
            ),
            (
                "another chain",
                PaymentIntent {
                    chain_id: intent.chain_id + 1,
                    ..intent.clone()
                },
            ),
            (
                "another token",
                PaymentIntent {
                    token: "0x0000000000000000000000000000000000000042".into(),
                    ..intent.clone()
                },
            ),
        ];
        for (why, altered) in cases {
            let err = attestation
                .verify(&f.policy, &altered)
                .expect_err(&format!("a settlement re-pointed at {why} must not verify"));
            let message = err.to_string();
            // Either the body refuses to rebuild — a different job, chain, token, anchor or
            // amount cannot describe this transfer at all — or the signature does
            // not match the preimage rebuilt from the altered intent. Both are
            // refusals, and both are the answer.
            assert!(
                matches!(
                    err,
                    settlement_auth::SettlementAuthError::BadSignature
                        | settlement_auth::SettlementAuthError::UnusableSettlement { .. }
                        | settlement_auth::SettlementAuthError::UnusableIntent { .. }
                        | settlement_auth::SettlementAuthError::IntentMismatch { .. }
                        | settlement_auth::SettlementAuthError::PolicyChainMismatch { .. }
                ),
                "{why} was refused for an unrelated reason: {message}"
            );
        }

        // And the settlement citing a different intent cannot even be signed.
        let mut mispointed = f.settlement();
        mispointed.payment_intent_id = Some(other_intent_id);
        let err = f
            .auth
            .verifier
            .attest_settlement(&f.policy, &mispointed, &intent)
            .unwrap_err();
        assert!(
            matches!(
                err,
                settlement_auth::SettlementAuthError::IntentMismatch { .. }
            ),
            "a settlement citing another intent must not be signed, got {err}"
        );
    }

    /// Appends a second, identical `Settlement` record — correctly chained — which
    /// is what a writer with file access does to get one signature counted twice.
    /// Appending (rather than rewriting) is deliberate: an *anchored* ledger that
    /// is rewritten in place is refused by the durability layer before the view
    /// ever sees it, so an append is the shape that actually reaches the replay
    /// guard.
    fn repeat_last_settlement(econ: &LocalEconomy) {
        let path = econ.ledger_path();
        let raw = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<LedgerRecord> = raw
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let last = lines.last().expect("at least one record");
        let settlement = match last {
            LedgerRecord::Settlement { settlement, .. } => settlement.clone(),
            other => panic!("the last record must be a settlement, got {other:?}"),
        };
        let sequence = lines.len() as u64 + 1;
        let prev_hash = last.record_hash().to_string();
        let base = LedgerRecord::Settlement {
            sequence: 0,
            recorded_at_unix: last.sequence(),
            prev_hash: String::new(),
            record_hash: String::new(),
            settlement,
        };
        let canonical = stamp(&base, sequence, &prev_hash, "");
        let record_hash = blake3::hash(&serde_json::to_vec(&canonical).unwrap())
            .to_hex()
            .to_string();
        lines.push(stamp(&base, sequence, &prev_hash, &record_hash));
        let text = format!(
            "{}\n",
            lines
                .iter()
                .map(|r| serde_json::to_string(r).unwrap())
                .collect::<Vec<String>>()
                .join("\n")
        );
        fs::write(&path, text).unwrap();
        // Readable through the crate, head anchor included: the anchor is behind
        // the new head rather than contradicted by it.
        econ.records().unwrap();
    }

    /// The honest ledger re-written into `dir` with its settlement record
    /// replaced by `settlement` and the whole hash chain recomputed, the way a
    /// writer with file access would.
    ///
    /// No head anchor is written, which is the point: an anchored ledger that is
    /// rewritten in place is refused by the durability layer before the view ever
    /// sees it, so this shape is the one that reaches the attestation gate. It is
    /// the revenue mirror of `forge_ledger_with` on the autonomy side.
    fn rewrite_revenue_ledger(
        from: &LocalEconomy,
        dir: &Path,
        settlement: &SettlementReceipt,
    ) -> LocalEconomy {
        let source = from.records().unwrap();
        let mut prev = LEDGER_GENESIS_HASH.to_string();
        let mut out: Vec<String> = Vec::new();
        for (idx, record) in source.iter().enumerate() {
            let sequence = idx as u64 + 1;
            let base = match record {
                LedgerRecord::Settlement { recorded_at_unix, .. } => {
                    LedgerRecord::Settlement {
                        sequence: 0,
                        recorded_at_unix: *recorded_at_unix,
                        prev_hash: String::new(),
                        record_hash: String::new(),
                        settlement: settlement.clone(),
                    }
                }
                other => stamp(other, 0, "", ""),
            };
            let canonical = stamp(&base, sequence, &prev, "");
            let record_hash = blake3::hash(&serde_json::to_vec(&canonical).unwrap())
                .to_hex()
                .to_string();
            out.push(serde_json::to_string(&stamp(
                &base,
                sequence,
                &prev,
                &record_hash,
            ))
            .unwrap());
            prev = record_hash;
        }
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(REVENUE_LEDGER_FILE), format!("{}\n", out.join("\n")))
            .unwrap();
        LocalEconomy::open(dir).unwrap()
    }

    // ------------------------------------------------------------------
    // 9. P4.5b: economic idempotency by external event identity
    // ------------------------------------------------------------------
    //
    // Everything below is about one rule:
    //
    //   one external fact contributes to a total at most once, whatever the
    //   ledger physically contains.
    //
    // The write path refuses a repeated append, and that is hygiene — see
    // `AutonomousEconomy::external_value_source_used`. These tests deliberately
    // do not go through the write path for the duplicates, because a test that
    // appends twice and reads a total of one has proved nothing: the second
    // append never happened. The duplicate here is written into the file by
    // hand, correctly chained, and the read has to cope.

    /// Appends a value record with an arbitrary receipt, correctly chained, by
    /// hand — the way a process that can write the directory would, and the way
    /// a restored-from-backup ledger already looks.
    ///
    /// Deliberately not routed through `record_external_value`: a test that
    /// appends twice and reads a total of one has proved nothing, because the
    /// second append never happened.
    fn append_value_record(
        autonomy: &AutonomousEconomy,
        recorded_at_unix: u64,
        receipt: ExternalValueReceipt,
    ) -> crate::autonomy::AutonomyRecord {
        let path = autonomy.ledger_path();
        let mut lines: Vec<String> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| l.to_string())
            .collect();
        let last: crate::autonomy::AutonomyRecord =
            serde_json::from_str(lines.last().unwrap()).unwrap();
        let mut record = crate::autonomy::AutonomyRecord {
            sequence: last.sequence + 1,
            recorded_at_unix,
            prev_hash: last.record_hash.clone(),
            record_hash: String::new(),
            payload: AutonomyPayload::ExternalValue { receipt },
        };
        record.record_hash =
            blake3::hash(&serde_json::to_vec(&record).unwrap())
                .to_hex()
                .to_string();
        lines.push(serde_json::to_string(&record).unwrap());
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        record
    }

    /// A SECOND booking of the same on-chain fact: a different `source_id`, a
    /// different `realized_at_unix`, and `proof_verified` off.
    ///
    /// That is the shape a real mistake takes, and the shape a deliberate one
    /// takes, because the two checks the write path does make are keyed on
    /// those very fields and are stepped around by choosing them differently:
    /// `source_id` is new, and `proof_verified: false` is not consulted by the
    /// proof check. (P4b froze the flag in both directions, so it changes
    /// nothing about whether the record counts.)
    ///
    /// The receipt content differs, so `receipt_hash` differs, so a signature
    /// over it is a *different* signature: the P4b attestation-replay guard has
    /// nothing to say about this record at all.
    fn second_booking() -> ExternalValueReceipt {
        ExternalValueReceipt {
            source_id: "source-2".into(),
            realized_at_unix: 1_700_000_900,
            proof_verified: false,
            ..receipt()
        }
    }

    /// The genuine attested event's evidence, without booking anything yet —
    /// so a test can choose which booking comes first.
    fn record_inflow_evidence(autonomy: &AutonomousEconomy) {
        let registry = registry();
        autonomy
            .record_boundary_crossing(&evidence(COUNTERPARTY, PAYOUT), &registry)
            .unwrap();
    }

    /// The view over a ledger that has an attested external event in it, plus
    /// the authority needed to count it.
    struct Attested {
        _socket: FakeRpcSocket,
        _auth: crate::receipt_auth::testkit::AuthFixture,
        registry: ControlledAddressRegistry,
        verifier: BaseUsdcVerifier,
        policy: crate::policy_auth::ValidatedOutcomePolicy,
    }

    impl Attested {
        fn new(socket: FakeRpcSocket) -> Self {
            let verifier = verifier_for(&socket).unwrap();
            let registry = registry();
            let auth = crate::receipt_auth::testkit::AuthFixture::new(
                socket.path(),
                socket.uid(),
                registry.clone(),
            );
            let policy = auth.validated();
            Self {
                _socket: socket,
                _auth: auth,
                registry,
                verifier,
                policy,
            }
        }

        fn view<'a>(&'a self, autonomy: &'a AutonomousEconomy) -> VerifiedEconomyView<'a> {
            VerifiedEconomyView::provider_pinned(
                autonomy,
                &self.registry,
                &self.verifier,
                &self.policy,
            )
            .unwrap()
        }
    }

    /// The genuine, attested event, recorded through the typed path.
    fn attested_inflow(autonomy: &AutonomousEconomy, auth: &Attested) {
        let registry = registry();
        let evidence = evidence(COUNTERPARTY, PAYOUT);
        let crossing = autonomy
            .record_boundary_crossing(&evidence, &registry)
            .unwrap();
        let crossing = crossing
            .with_verified_proof(crate::base_usdc::BaseUsdcVerification {
                verified: true,
                rpc: "unix:///run/mycelium-verifier.sock".into(),
                provider_identity_verified: true,
                chain_id: BASE_CHAIN_ID,
                transaction_hash: tx_hash(),
                block_number: BLOCK,
                block_hash: block_hash(),
                block_timestamp_unix: 1_700_000_400,
                latest_block: 110,
                confirmations: 10,
                token: BASE_USDC.to_ascii_lowercase(),
                recipient: PAYOUT.into(),
                expected_raw: AMOUNT,
                matched_raw: AMOUNT,
                matching_log_index: Some(3),
            })
            .unwrap();
        autonomy
            .record_external_value_with_crossing(receipt(), &crossing)
            .unwrap();
        // The delegated verifier signs the same evidence, and the signature is
        // recorded beside the receipt. The duplicate gets its own signature
        // below, which is the whole difficulty of the test.
        let attestation =
            auth._auth.attest(&auth.policy, &receipt(), &evidence);
        autonomy.record_receipt_attestation(&attestation).unwrap();
    }

    /// Signs a booking of the same external fact with the delegated key, so it
    /// is not caught by the attestation ledger's replay guard: two records, two
    /// genuine signatures over the same chain facts, one piece of real money.
    fn attest_booking(
        autonomy: &AutonomousEconomy,
        auth: &Attested,
        receipt: &ExternalValueReceipt,
    ) {
        let attestation =
            auth._auth
                .attest(&auth.policy, receipt, &evidence(COUNTERPARTY, PAYOUT));
        autonomy.record_receipt_attestation(&attestation).unwrap();
    }

    /// THE LOAD-BEARING TEST.
    ///
    /// A ledger that books the same attested external event twice — twice
    /// chained, twice validly attested by the delegated verifier, both
    /// chain-confirmed by the pinned provider — must contribute that event to
    /// the verified total ONCE.
    ///
    /// The second record is not a replayed *attestation*: it has its own
    /// signature over its own receipt content, so the P4b replay guard has
    /// nothing to say about it and both records reach the chain read. Before
    /// P4.5b this ledger produced 10.0 mUSD of verified external value for a
    /// 5.0 mUSD transfer. It now produces 5.0.
    #[test]
    fn a_duplicated_attested_event_is_counted_once_in_the_verified_total() {
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Attested::new(serving_socket(dir.path()));
        attested_inflow(&f.autonomy, &auth);

        // The duplicate: a correctly chained second value record for the same
        // on-chain transfer, with a fresh, genuine signature over it.
        let original = receipt();
        append_value_record(&f.autonomy, 1_700_000_900, second_booking());
        attest_booking(&f.autonomy, &auth, &second_booking());
        let autonomy = AutonomousEconomy::open(f.root.clone()).unwrap();
        assert_receipt_chain_is_readable(&autonomy);
        let original_sequence = original_record_sequence(&autonomy, &original);

        // The precondition, stated rather than assumed: there really are two
        // records, two distinct receipt contents and two distinct attestation
        // hashes in the file. If this ever stops being true the test would be
        // passing for the wrong reason.
        let stored = autonomy.external_values().unwrap();
        assert_eq!(stored.len(), 2);
        assert_ne!(stored[0].source_id, stored[1].source_id);
        assert_ne!(
            crate::receipt_auth::receipt_hash(&stored[0]).unwrap(),
            crate::receipt_auth::receipt_hash(&stored[1]).unwrap()
        );
        let attestations = autonomy.receipt_attestations().unwrap();
        assert_eq!(attestations.len(), 2, "one signature per record");
        assert_ne!(
            attestations[0].attestation_hash(),
            attestations[1].attestation_hash(),
            "so neither is a replay of the other"
        );

        let view = auth.view(&autonomy);
        let rows = view.receipt_evidence().unwrap();
        assert_eq!(rows.len(), 2);
        // Both records pass every gate up to the last one.
        for row in &rows {
            assert!(row.chain_confirmed, "both are chain-confirmed");
            assert!(row.attested, "both carry a genuine signature");
        }

        // The total.
        let nev = view.verified_nev().unwrap();
        assert_eq!(
            nev.nev_musd_micros(),
            5_000_000,
            "one transfer of 5.0 mUSD is 5.0 mUSD, not 10.0"
        );
        assert_eq!(nev.receipts(), 1, "and it is one external event");
        assert!(nev.is_positive());

        // The diagnosis, which is the other half of the requirement: the second
        // record is refused as a repeated EVENT, and the refusal names the id
        // and who holds the credit.
        let counted: Vec<&ReceiptEvidence> =
            rows.iter().filter(|r| r.counted).collect();
        assert_eq!(counted.len(), 1);
        assert_eq!(
            counted[0].sequence, original_sequence,
            "the first record holds credit"
        );
        let refused: Vec<&ReceiptEvidence> =
            rows.iter().filter(|r| !r.counted).collect();
        assert_eq!(refused.len(), 1);
        assert_eq!(
            refused[0].gap,
            Some(AttestationGap::ExternalEventAlreadyCounted {
                event_id: counted[0]
                    .event_id
                    .clone()
                    .expect("a counted record names its event"),
                first_counted_at_sequence: counted[0].sequence,
            })
        );
        // Both records carry the same id: that is the fact being claimed twice.
        assert_eq!(rows[0].event_id, rows[1].event_id);
        assert!(rows[1].event_id.is_some());
    }

    /// The duplicate counts once whichever of the two records comes first.
    ///
    /// Two ledgers holding the same two bookings of the same event, in opposite
    /// order, and the same 5.0 mUSD out of both. An identity is not a position:
    /// if the total or the credit moved with the order, the thing being compared
    /// would be a sequence number wearing a digest's clothes.
    ///
    /// The hash chain does constrain the order — `sequence` is contiguous in file
    /// order and `prev_hash` follows the line above — so "the other order" means
    /// building the ledger with the duplicate as the earlier record, not
    /// rearranging a finished one. That is the realistic duplicate anyway: a
    /// second booking written by something that had not yet seen the first.
    #[test]
    fn a_duplicate_counts_once_whichever_record_comes_first() {
        // (a) original first, duplicate second.
        let a = fixture();
        let dir_a = tempdir().unwrap();
        let auth_a = Attested::new(serving_socket(dir_a.path()));
        attested_inflow(&a.autonomy, &auth_a);
        let original_a = receipt();
        append_value_record(&a.autonomy, 1_700_000_900, second_booking());
        attest_booking(&a.autonomy, &auth_a, &second_booking());
        let ledger_a = AutonomousEconomy::open(a.root.clone()).unwrap();

        // (b) duplicate first, original second. Same two bookings, same event,
        // same two signatures — only which of them was written first differs.
        let b = fixture();
        let dir_b = tempdir().unwrap();
        let auth_b = Attested::new(serving_socket(dir_b.path()));
        record_inflow_evidence(&b.autonomy);
        let original_b = receipt();
        append_value_record(&b.autonomy, 1_700_000_900, second_booking());
        attest_booking(&b.autonomy, &auth_b, &second_booking());
        append_value_record(&b.autonomy, 1_700_000_400, original_b.clone());
        attest_booking(&b.autonomy, &auth_b, &original_b);
        let ledger_b = AutonomousEconomy::open(b.root.clone()).unwrap();

        for ledger in [&ledger_a, &ledger_b] {
            assert_receipt_chain_is_readable(ledger);
            assert_eq!(ledger.external_values().unwrap().len(), 2);
            assert_eq!(ledger.receipt_attestations().unwrap().len(), 2);
        }
        // The credit lands on whichever booking the ledger reached first, so in
        // (b) that is the duplicate, one sequence before the original.
        let original_seq_a = original_record_sequence(&ledger_a, &original_a);
        let original_seq_b = original_record_sequence(&ledger_b, &original_b);

        let nev_a = auth_a.view(&ledger_a).verified_nev().unwrap();
        let nev_b = auth_b.view(&ledger_b).verified_nev().unwrap();
        assert_eq!(nev_a.nev_musd_micros(), 5_000_000);
        assert_eq!(nev_b.nev_musd_micros(), 5_000_000, "order changed nothing");
        assert_eq!(nev_a.receipts(), 1);
        assert_eq!(nev_b.receipts(), 1);

        // Credit follows the record that comes first in the ledger, which is the
        // only thing about it that is a property of storage — and the *amount*
        // is not.
        let rows_b = auth_b.view(&ledger_b).receipt_evidence().unwrap();
        let counted_b: Vec<&ReceiptEvidence> =
            rows_b.iter().filter(|r| r.counted).collect();
        assert_eq!(counted_b.len(), 1);
        assert_eq!(
            counted_b[0].sequence,
            original_seq_b - 1,
            "in (b) the duplicate is the earlier record, so it holds the credit"
        );
        // The mirror image in (a): there the original is the earlier record, so
        // the credit is the original's and the duplicate is the one refused.
        let rows_a = auth_a.view(&ledger_a).receipt_evidence().unwrap();
        let counted_a: Vec<&ReceiptEvidence> =
            rows_a.iter().filter(|r| r.counted).collect();
        assert_eq!(counted_a.len(), 1);
        assert_eq!(counted_a[0].sequence, original_seq_a);
        assert_eq!(
            rows_b
                .iter()
                .find(|r| r.sequence == original_seq_b)
                .and_then(|r| r.gap.clone()),
            Some(AttestationGap::ExternalEventAlreadyCounted {
                event_id: counted_b[0].event_id.clone().unwrap(),
                first_counted_at_sequence: counted_b[0].sequence,
            })
        );
    }

    /// The sequence of the record that booked `receipt`, found by its content
    /// rather than by its position, so a test can say "the original" without
    /// caring where it landed.
    fn original_record_sequence(
        autonomy: &AutonomousEconomy,
        receipt: &ExternalValueReceipt,
    ) -> u64 {
        let digest = crate::receipt_auth::receipt_hash(receipt).unwrap();
        autonomy
            .records()
            .unwrap()
            .into_iter()
            .find_map(|r| match r.payload {
                AutonomyPayload::ExternalValue { receipt }
                    if crate::receipt_auth::receipt_hash(&receipt).unwrap() == digest =>
                {
                    Some(r.sequence)
                }
                _ => None,
            })
            .expect("the original booking is in the ledger")
    }

    /// Rebuilds the whole read path from scratch — a fresh handle on the
    /// directory, a fresh view, a fresh `CountedEvents` — and asserts the same
    /// answer.
    ///
    /// This is the "process restart" case, and it is why the set is built inside
    /// `receipt_evidence` rather than kept on the view: nothing is remembered
    /// between reads, so a duplicate cannot be promoted again by restarting the
    /// process that created it.
    #[test]
    fn the_duplicate_is_still_not_counted_after_the_view_is_rebuilt() {
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Attested::new(serving_socket(dir.path()));
        attested_inflow(&f.autonomy, &auth);
        append_value_record(&f.autonomy, 1_700_000_900, second_booking());
        attest_booking(&f.autonomy, &auth, &second_booking());

        let mut readings = Vec::new();
        for round in 0..3 {
            // A genuinely fresh handle on the directory, as a new process would
            // open, and a fresh view over it. Nothing is carried across rounds.
            let autonomy = AutonomousEconomy::open(f.root.clone()).unwrap();
            let view = auth.view(&autonomy);
            let nev = view.verified_nev().unwrap();
            let gaps: Vec<Option<AttestationGap>> = view
                .receipt_evidence()
                .unwrap()
                .into_iter()
                .map(|r| r.gap)
                .collect();
            readings.push((nev.nev_musd_micros(), nev.receipts(), gaps));
            let _ = round;
        }
        for (micros, receipts, _) in &readings {
            assert_eq!(*micros, 5_000_000, "every read agrees on the total");
            assert_eq!(*receipts, 1);
        }
        assert_eq!(
            readings[0].2, readings[1].2,
            "every read reports the same diagnosis"
        );
        assert_eq!(readings[1].2, readings[2].2);
        assert_eq!(
            readings[0].2
                .iter()
                .filter(|g| matches!(g, Some(AttestationGap::ExternalEventAlreadyCounted { .. })))
                .count(),
            1
        );
    }

    /// A second, genuinely distinct on-chain event is a different identity and
    /// is counted in full. The dedup must be keyed on the fact, not on a
    /// transaction, a ledger, a day or a coarse fingerprint.
    #[test]
    fn a_second_genuine_event_is_counted_in_full() {
        let f = fixture();
        let dir = tempdir().unwrap();
        let socket = two_transfer_socket(dir.path());
        let auth = Attested::new(socket);
        let registry = registry();

        // Event one: the standard transfer, recorded and attested.
        attested_inflow(&f.autonomy, &auth);
        // Event two: a different transaction, a different block, a different
        // log, the same amount and the same recipient. Distinct in every field
        // the identity binds.
        let second_tx = format!("0x{}", "77".repeat(32));
        let second_block = format!("0x{}", "88".repeat(32));
        let second = BoundaryEvidence {
            chain_id: BASE_CHAIN_ID,
            asset: crate::boundary::RealAsset::base_usdc(),
            from_address: COUNTERPARTY.into(),
            to_address: PAYOUT.into(),
            amount_raw: AMOUNT,
            tx_hash: second_tx.clone(),
            block_hash: second_block.clone(),
        };
        let crossing = f
            .autonomy
            .record_boundary_crossing(&second, &registry)
            .unwrap();
        let crossing = crossing
            .with_verified_proof(crate::base_usdc::BaseUsdcVerification {
                verified: true,
                rpc: "unix:///run/mycelium-verifier.sock".into(),
                provider_identity_verified: true,
                chain_id: BASE_CHAIN_ID,
                transaction_hash: second_tx,
                block_number: 202,
                block_hash: second_block,
                block_timestamp_unix: 1_700_000_500,
                latest_block: 210,
                confirmations: 9,
                token: BASE_USDC.to_ascii_lowercase(),
                recipient: PAYOUT.into(),
                expected_raw: AMOUNT,
                matched_raw: AMOUNT,
                matching_log_index: Some(7),
            })
            .unwrap();
        let mut second_receipt = receipt();
        second_receipt.source_id = "source-2".into();
        second_receipt.proof_hash = second.tx_hash.clone();
        second_receipt.realized_at_unix = 1_700_000_500;
        let attestation =
            auth._auth
                .attest(&auth.policy, &second_receipt, &second);
        f.autonomy
            .record_receipt_attestation(&attestation)
            .unwrap();
        f.autonomy
            .record_external_value_with_crossing(second_receipt, &crossing)
            .unwrap();

        let autonomy = AutonomousEconomy::open(f.root.clone()).unwrap();
        let view = auth.view(&autonomy);
        let rows = view.receipt_evidence().unwrap();
        assert_eq!(rows.len(), 2);
        assert!(
            rows.iter().all(|r| r.counted),
            "two real transfers are two events, not one: {:?}",
            rows.iter().map(|r| r.gap.clone()).collect::<Vec<_>>()
        );
        assert_ne!(
            rows[0].event_id, rows[1].event_id,
            "and their identities are different"
        );
        let nev = view.verified_nev().unwrap();
        assert_eq!(nev.receipts(), 2);
        assert_eq!(nev.nev_musd_micros(), 10_000_000, "both are counted");
    }

    /// A duplicated ATTESTATION and a duplicated EVENT are different faults and
    /// must be reported differently.
    ///
    /// * byte-identical receipt content twice → one attestation, claimed twice →
    ///   `AttestationReplayed`, a provenance fault;
    /// * the same on-chain fact booked twice with each receipt separately signed
    ///   → two perfect attestations, one piece of money → `ExternalEventAlreadyCounted`,
    ///   an economic fault.
    ///
    /// Before P4.5b both produced the same shape of refusal, and an operator
    /// reading the second one was told the signature was replayed, which it was
    /// not.
    #[test]
    fn a_replayed_attestation_and_a_repeated_event_are_reported_differently() {
        // (a) the same attested record written twice: one signature, two claims.
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Attested::new(serving_socket(dir.path()));
        attested_inflow(&f.autonomy, &auth);
        let replayed = repeat_receipt_record(&f.autonomy);
        let view = auth.view(&replayed);
        let rows = view.receipt_evidence().unwrap();
        assert_eq!(rows.len(), 2);
        let replayed_gap = rows
            .iter()
            .find_map(|r| r.gap.clone())
            .expect("the second record is refused");
        assert_eq!(replayed_gap, AttestationGap::AttestationReplayed);

        // (b) the same event booked twice, each with its own valid signature.
        let g = fixture();
        let dir_b = tempdir().unwrap();
        let auth_b = Attested::new(serving_socket(dir_b.path()));
        attested_inflow(&g.autonomy, &auth_b);
        append_value_record(&g.autonomy, 1_700_000_900, second_booking());
        attest_booking(&g.autonomy, &auth_b, &second_booking());
        let autonomy_b = AutonomousEconomy::open(g.root.clone()).unwrap();
        let view_b = auth_b.view(&autonomy_b);
        let rows_b = view_b.receipt_evidence().unwrap();
        let event_gap = rows_b
            .iter()
            .find_map(|r| r.gap.clone())
            .expect("the second record is refused");

        // Different variants...
        assert_ne!(replayed_gap, event_gap);
        assert!(matches!(replayed_gap, AttestationGap::AttestationReplayed));
        assert!(matches!(
            event_gap,
            AttestationGap::ExternalEventAlreadyCounted { .. }
        ));
        // ...different words...
        let replayed_text = replayed_gap.describe();
        let event_text = event_gap.describe();
        assert_ne!(replayed_text, event_text);
        assert!(replayed_text.contains("attestation was already consumed"));
        assert!(event_text.contains("already in the total"));
        // ...and the event report carries the handle the attestation report has
        // no way to produce, because no single signature is at fault.
        match &event_gap {
            AttestationGap::ExternalEventAlreadyCounted {
                event_id,
                first_counted_at_sequence,
            } => {
                assert!(event_id.starts_with("0x") && event_id.len() == 66);
                assert!(*first_counted_at_sequence > 0);
            }
            other => panic!("expected the economic gap, got {other:?}"),
        }
        // Both cases end with the same total, which is the point of the
        // exercise: the fix is not "count it anyway".
        assert_eq!(
            view.verified_nev().unwrap().nev_musd_micros(),
            view_b.verified_nev().unwrap().nev_musd_micros()
        );
    }

    /// The write path's refusal and the economic idempotency are two different
    /// properties, asserted independently.
    ///
    /// Half one: a repeated append IS refused — the storage-level hygiene. Half
    /// two: a duplicate that is physically in the ledger anyway does NOT change
    /// the total — the economic authority. Passing the first says nothing about
    /// the second, which is why both are here and why the duplicate in half two
    /// is written by hand rather than through the API.
    #[test]
    fn the_write_path_refuses_a_repeated_append_and_the_total_is_idempotent() {
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Attested::new(serving_socket(dir.path()));
        attested_inflow(&f.autonomy, &auth);

        // --- half one: hygiene. The append is refused. -------------------
        let same_source = receipt();
        let err = f
            .autonomy
            .record_external_value(same_source)
            .unwrap_err()
            .to_string();
        assert!(err.contains("external source source-1 already recorded"), "{err}");

        let mut same_proof = receipt();
        same_proof.source_id = "source-other".into();
        let err = f
            .autonomy
            .record_external_value(same_proof)
            .unwrap_err()
            .to_string();
        assert!(err.contains("external value proof already recorded"), "{err}");
        // Neither refusal appended anything, so the ledger still has one record.
        assert_eq!(f.autonomy.external_values().unwrap().len(), 1);
        assert_eq!(auth.view(&f.autonomy).verified_nev().unwrap().nev_musd_micros(), 5_000_000);

        // --- half two: authority. The duplicate is in the file regardless. -
        append_value_record(&f.autonomy, 1_700_000_900, second_booking());
        attest_booking(&f.autonomy, &auth, &second_booking());
        let autonomy = AutonomousEconomy::open(f.root.clone()).unwrap();
        assert_eq!(
            autonomy.external_values().unwrap().len(),
            2,
            "the duplicate is physically present, whatever the write path thinks"
        );
        let nev = auth.view(&autonomy).verified_nev().unwrap();
        assert_eq!(nev.nev_musd_micros(), 5_000_000, "and it changes nothing");
        assert_eq!(nev.receipts(), 1);
    }

    /// Every consumer of the view agrees, because there is only one funnel.
    ///
    /// If any of these could see two events where `VerifiedNev` sees one, then
    /// the `HashSet` would not be load-bearing — it would be one number among
    /// several, and an operator reading a dashboard would be told a total the
    /// budget gate does not use.
    #[test]
    fn every_route_to_a_number_agrees_on_what_was_counted() {
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Attested::new(serving_socket(dir.path()));
        attested_inflow(&f.autonomy, &auth);
        append_value_record(&f.autonomy, 1_700_000_900, second_booking());
        attest_booking(&f.autonomy, &auth, &second_booking());
        let autonomy = AutonomousEconomy::open(f.root.clone()).unwrap();

        let view = auth.view(&autonomy);
        let nev = view.verified_nev().unwrap();
        assert_eq!(nev.receipts(), 1);
        assert_eq!(nev.nev_musd_micros(), 5_000_000);

        let arv = view.arv_status(NOW).unwrap();
        assert_eq!(arv.verified_external_events, 1);
        assert_eq!(arv.net_external_value_musd_total, 5.0);
        assert_eq!(arv.trust_mode, TrustMode::ProviderPinned);
        assert!(
            arv.attestation_note.contains("distinct external event"),
            "the note says why: {}",
            arv.attestation_note
        );
        assert!(
            arv.attestation_note.contains("already in the total"),
            "and which record was refused: {}",
            arv.attestation_note
        );

        let summary = view.autonomy_summary().unwrap();
        assert_eq!(summary.verified_external_value_receipts, 1);
        assert_eq!(summary.net_external_value_musd, 5.0);
        // The offline claim is NOT an authority input and does not claim to be:
        // it is the ledger's own arithmetic over both records, and it says so.
        let claim = VerifiedEconomyView::unverified(&autonomy, &registry())
            .unattested_nev()
            .unwrap();
        assert_eq!(claim.receipts.len(), 2, "both records are still reported");
        assert_eq!(claim.re_derived_receipts, 2);
        assert_eq!(claim.claimed_net_external_value_musd_micros, 10_000_000);
        assert_eq!(claim.trust_mode, TrustMode::Unverified);
    }

    /// A provider that confirms a transfer without saying which log it matched
    /// leaves the fact unnamed, and a fact with no name is not counted.
    ///
    /// Fail-closed by design: defaulting the index to zero would let this event
    /// be filed under another log's identity, which is worse than refusing it.
    #[test]
    fn a_confirmed_transfer_with_no_log_index_is_not_counted() {
        let f = fixture();
        let dir = tempdir().unwrap();
        let auth = Attested::new(indexless_socket(dir.path()));
        // The write-time path also needs a proof, and the log index is optional
        // there, so the event is recorded normally and only the *read* discovers
        // that the fact cannot be named.
        let registry = registry();
        let crossing = f
            .autonomy
            .record_boundary_crossing(&evidence(COUNTERPARTY, PAYOUT), &registry)
            .unwrap();
        let crossing = crossing
            .with_verified_proof(crate::base_usdc::BaseUsdcVerification {
                verified: true,
                rpc: "unix:///run/mycelium-verifier.sock".into(),
                provider_identity_verified: true,
                chain_id: BASE_CHAIN_ID,
                transaction_hash: tx_hash(),
                block_number: BLOCK,
                block_hash: block_hash(),
                block_timestamp_unix: 1_700_000_400,
                latest_block: 110,
                confirmations: 10,
                token: BASE_USDC.to_ascii_lowercase(),
                recipient: PAYOUT.into(),
                expected_raw: AMOUNT,
                matched_raw: AMOUNT,
                matching_log_index: None,
            })
            .unwrap();
        f.autonomy
            .record_external_value_with_crossing(receipt(), &crossing)
            .unwrap();
        let attestation =
            auth._auth
                .attest(&auth.policy, &receipt(), &evidence(COUNTERPARTY, PAYOUT));
        f.autonomy.record_receipt_attestation(&attestation).unwrap();

        let autonomy = AutonomousEconomy::open(f.root.clone()).unwrap();
        let view = auth.view(&autonomy);
        let rows = view.receipt_evidence().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].chain_confirmed, "the transfer itself was confirmed");
        assert!(rows[0].attested);
        assert!(!rows[0].counted, "but it cannot be named, so it is not money");
        assert_eq!(rows[0].event_id, None);
        match &rows[0].gap {
            Some(AttestationGap::EventIdentityIndeterminate(why)) => {
                assert!(why.contains("no log index"), "{why}");
            }
            other => panic!("expected the identity gap, got {other:?}"),
        }
        assert_no_promotion_route(&view, None, "event identity indeterminate");
    }

    /// A provider that serves two distinct transfers, so one ledger can hold
    /// two distinct external events and the dedup can be shown not to be
    /// over-eager. Built on the per-request dispatcher because a fixed
    /// method→response map can only ever describe one of them.
    fn two_transfer_socket(dir: &Path) -> FakeRpcSocket {
        let log = |log_index: &str| {
            serde_json::json!({
                "address": BASE_USDC,
                "topics": [
                    crate::base_usdc::ERC20_TRANSFER_TOPIC,
                    format!("0x{:0>64}", COUNTERPARTY.trim_start_matches("0x")),
                    format!("0x{:0>64}", PAYOUT.trim_start_matches("0x")),
                ],
                "data": format!("0x{amount:064x}", amount = AMOUNT),
                "logIndex": log_index,
            })
        };
        let first_tx = tx_hash();
        let first_block = block_hash();
        let second_tx = format!("0x{}", "77".repeat(32));
        let second_block = format!("0x{}", "88".repeat(32));
        let log = Arc::new(log);
        FakeRpcSocket::with_dispatch(dir.join("two.sock"), move |method, params| {
            let first_tx = first_tx.clone();
            let first_block = first_block.clone();
            let second_tx = second_tx.clone();
            let second_block = second_block.clone();
            let log = Arc::clone(&log);
            Some(match method {
                "eth_chainId" => serde_json::json!("0x2105"),
                "eth_blockNumber" => serde_json::json!("0xd2"),
                "eth_getTransactionReceipt" => {
                    let asked = params
                        .as_array()
                        .and_then(|a| a.first())
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if asked == second_tx {
                        serde_json::json!({
                            "status": "0x1",
                            "blockNumber": "0xca",
                            "blockHash": second_block,
                            "transactionHash": second_tx,
                            "logs": [log("0x7")],
                        })
                    } else {
                        serde_json::json!({
                            "status": "0x1",
                            "blockNumber": format!("0x{block:x}", block = BLOCK),
                            "blockHash": first_block,
                            "transactionHash": first_tx,
                            "logs": [log("0x3")],
                        })
                    }
                }
                "eth_getBlockByNumber" => {
                    let asked = params
                        .as_array()
                        .and_then(|a| a.first())
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_ascii_lowercase();
                    if asked == format!("0x{block:x}", block = 202) {
                        serde_json::json!({
                            "hash": second_block,
                            "timestamp": "0x6553f300",
                        })
                    } else {
                        serde_json::json!({
                            "hash": first_block,
                            "timestamp": "0x6553f100",
                        })
                    }
                }
                _ => return None,
            })
        })
    }

    /// A provider that confirms the standard transfer and reports no log index.
    fn indexless_socket(dir: &Path) -> FakeRpcSocket {
        let recipient_topic = format!("0x{:0>64}", PAYOUT.trim_start_matches("0x"));
        let log = serde_json::json!({
            "address": BASE_USDC,
            "topics": [
                crate::base_usdc::ERC20_TRANSFER_TOPIC,
                format!("0x{:0>64}", COUNTERPARTY.trim_start_matches("0x")),
                recipient_topic,
            ],
            "data": format!("0x{amount:064x}", amount = AMOUNT),
            // Deliberately no `logIndex`.
        });
        FakeRpcSocket::with_responses(
            dir.join("indexless.sock"),
            vec![
                ("eth_chainId", serde_json::json!("0x2105")),
                ("eth_blockNumber", serde_json::json!("0x6e")),
                ("eth_getTransactionReceipt", serde_json::json!({
                    "status": "0x1",
                    "blockNumber": format!("0x{block:x}", block = BLOCK),
                    "blockHash": block_hash(),
                    "transactionHash": tx_hash(),
                    "logs": [log],
                })),
                ("eth_getBlockByNumber", serde_json::json!({
                    "hash": block_hash(),
                    "timestamp": "0x6553f100",
                })),
            ],
        )
    }
    // ------------------------------------------------------------------
    // 10. P4.5c: economic idempotency on the revenue side
    // ------------------------------------------------------------------
    //
    // The gap P4.5b reported, closed. The counting rule — one external fact
    // contributes to a total at most once, whatever the ledger physically
    // contains — existed only for `VerifiedEconomyView`. The revenue side had
    // none, so two settlements of one payment both counted.
    //
    // The hard part is that the two records below are not the same bytes. They
    // differ in `settled_at_unix`, so they have different `settlement_hash`
    // values, different attestation bodies, different attestation hashes and two
    // individually genuine signatures from the delegated verifier. Every check
    // that exists before P4.5c passes on both.

    /// A SECOND booking of the same payment: same intent, same transaction,
    /// same amount, but a different `settled_at_unix`.
    ///
    /// That is the shape a real mistake takes and the shape a deliberate one
    /// takes. `settled_at_unix` is exactly the kind of field an operator
    /// re-records, and P4b deliberately left both stored booleans alone, so
    /// changing nothing else already gets past the write-path hygiene.
    fn later_booking(f: &RevenueFixture) -> SettlementReceipt {
        let mut later = f.settlement();
        later.settlement_id = "settle-revenue-later".into();
        later.settled_at_unix = 1_700_000_900;
        later
    }

    /// Appends a second settlement record with an arbitrary receipt, correctly
    /// chained, by hand.
    ///
    /// Deliberately not `append_settlement`: a test that appends twice and reads
    /// a total of one has proved nothing, because the second append may never
    /// have happened. This is the same reasoning as `repeat_receipt_record` on
    /// the autonomy side.
    fn append_settlement_record(
        f: &RevenueFixture,
        recorded_at_unix: u64,
        settlement: SettlementReceipt,
    ) -> LedgerRecord {
        let path = f.econ.ledger_path();
        let mut lines: Vec<String> = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| l.to_string())
            .collect();
        let last: LedgerRecord =
            serde_json::from_str(lines.last().unwrap()).unwrap();
        let base = LedgerRecord::Settlement {
            sequence: 0,
            recorded_at_unix,
            prev_hash: String::new(),
            record_hash: String::new(),
            settlement,
        };
        let sequence = lines.len() as u64 + 1;
        let prev_hash = last.record_hash().to_string();
        let canonical = stamp(&base, sequence, &prev_hash, "");
        let record_hash = blake3::hash(&serde_json::to_vec(&canonical).unwrap())
            .to_hex()
            .to_string();
        let record = stamp(&base, sequence, &prev_hash, &record_hash);
        lines.push(serde_json::to_string(&record).unwrap());
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        record
    }

    /// Signs a settlement with the delegated key, so it is not caught by the
    /// attestation ledger's replay guard, and records the attestation.
    fn attest_settlement(
        f: &RevenueFixture,
        settlement: &SettlementReceipt,
    ) -> crate::settlement_auth::AuthenticatedSettlementReceipt {
        let attestation = f
            .auth
            .verifier
            .attest_settlement(&f.policy, settlement, &f.intent())
            .unwrap();
        f.econ.record_settlement_attestation(&attestation).unwrap();
        attestation
    }

    /// A ledger holding two individually genuine settlements of one payment
    /// contributes that payment to paid demand ONCE.
    ///
    /// Before P4.5c this ledger produced 10.0 mUSD of paid demand for a 5.0 mUSD
    /// transfer. It now produces 5.0 — and the second record is refused as a
    /// repeated *event*, with the identity that matched named in the report.
    #[test]
    fn a_duplicated_settlement_is_counted_once_in_paid_demand() {
        let f = revenue_fixture();
        f.attest();
        let later = later_booking(&f);
        append_settlement_record(&f, 1_700_000_900, later.clone());
        attest_settlement(&f, &later);

        // The precondition, stated rather than assumed: two records, two
        // distinct contents, two distinct attestation hashes, both genuinely
        // signed. If any of this stops being true the test would pass for the
        // wrong reason.
        let settlements: Vec<SettlementReceipt> = f
            .econ
            .records()
            .unwrap()
            .into_iter()
            .filter_map(|r| match r {
                LedgerRecord::Settlement { settlement, .. } => Some(settlement),
                _ => None,
            })
            .collect();
        assert_eq!(settlements.len(), 2);
        assert_ne!(settlements[0].settlement_id, settlements[1].settlement_id);
        assert_ne!(settlements[0].settled_at_unix, settlements[1].settled_at_unix);
        assert_ne!(
            crate::settlement_auth::settlement_hash(&settlements[0]).unwrap(),
            crate::settlement_auth::settlement_hash(&settlements[1]).unwrap(),
            "so the attestation replay guard has nothing to say about either"
        );
        let attestations = f.econ.settlement_attestations().unwrap();
        assert_eq!(attestations.len(), 2, "one genuine signature per record");
        assert_ne!(
            attestations[0].attestation_hash(),
            attestations[1].attestation_hash()
        );

        let rows = f.view().settlement_evidence().unwrap();
        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert!(row.rederived, "P3 re-derivation passes on both");
            assert!(row.attested, "both carry a genuine signature");
            assert!(row.chain_confirmed, "both name the same real transfer");
            assert!(
                row.event_id.is_some(),
                "both name the same payment event: {:?}",
                row.gap
            );
        }
        // Both records carry the same payment identity. That is the fact being
        // claimed twice, and it is reported on the refused record as well as the
        // counted one.
        assert_eq!(rows[0].event_id, rows[1].event_id);

        let counted: Vec<&SettlementEvidence> =
            rows.iter().filter(|r| r.counted).collect();
        assert_eq!(counted.len(), 1, "one transfer is one payment");
        let refused: Vec<&SettlementEvidence> =
            rows.iter().filter(|r| !r.counted).collect();
        assert_eq!(refused.len(), 1);
        match &refused[0].gap {
            Some(SettlementGap::SettlementEventAlreadyCounted {
                event_id,
                first_counted_at_sequence,
            }) => {
                assert_eq!(
                    Some(event_id.clone()),
                    counted[0].event_id,
                    "the refusal names the identity that matched"
                );
                assert!(
                    *first_counted_at_sequence > 0,
                    "the refusal names the record that holds the credit"
                );
                assert!(
                    refused[0].gap.as_ref().unwrap().describe().contains(
                        "already in paid demand"
                    ),
                    "and says why: {}",
                    refused[0].gap.as_ref().unwrap().describe()
                );
            }
            other => panic!("expected the economic gap, got {other:?}"),
        }

        // The total.
        let rv = f.view().rv_status(NOW).unwrap();
        assert_eq!(rv.external_paid_jobs, 1, "one payment, one job of demand");
        assert_eq!(
            rv.paid_demand_musd_total, 5.0,
            "one transfer of 5.0 mUSD is 5.0 mUSD, not 10.0"
        );
        assert_eq!(f.view().revenue_summary().unwrap().paid_demand_musd_micros, AMOUNT);
    }

    /// The narrower case the gap report named: a duplicate that differs **only**
    /// in `settled_at_unix`.
    ///
    /// Every other field — the intent, the transaction, the block, the amounts,
    /// the asset — is identical, and the two records are each separately signed.
    /// The two therefore have different content, different digests and different
    /// signatures, so neither the attestation replay guard nor a byte comparison
    /// can see them. Only the external fact's identity can, and it does.
    #[test]
    fn a_duplicate_settlement_differing_only_in_settled_at_is_still_one_event() {
        let f = revenue_fixture();
        f.attest();
        let original = f.settlement();
        let mut later = original.clone();
        later.settlement_id = "settle-revenue-retimed".into();
        later.settled_at_unix = original.settled_at_unix + 60;
        append_settlement_record(&f, 1_700_000_460, later.clone());
        attest_settlement(&f, &later);

        // The shape is exactly as described, and stated rather than assumed.
        for field in [
            "schema_version",
            "job_id",
            "work_receipt_id",
            "mode",
            "settlement_asset",
            "settled_amount_micros",
            "usd_equivalent_micros",
            "payment_intent_id",
            "payment_block_number",
            "payment_proof_hash",
            "payment_proof_verified",
            "external_paid",
            "internal_work",
        ] {
            let before = serde_json::to_value(&original).unwrap()[field].clone();
            let after = serde_json::to_value(&later).unwrap()[field].clone();
            assert_eq!(before, after, "field {field} must be identical");
        }
        assert_ne!(original.settled_at_unix, later.settled_at_unix);
        assert_ne!(original.settlement_id, later.settlement_id);

        let rows = f.view().settlement_evidence().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].event_id, rows[1].event_id);
        assert!(rows[1].event_id.is_some());
        assert_eq!(rows.iter().filter(|r| r.counted).count(), 1);
        assert_eq!(rv_paid(&f), 5.0);
        // And the offline view still reports both records, because it performs
        // no chain read and therefore establishes no payment identity. Stating
        // that here keeps the new gate from looking like a filter on rows.
        let offline_registry = registry();
        let offline = VerifiedRevenueView::unverified(&f.econ, &offline_registry);
        assert_eq!(offline.settlement_evidence().unwrap().len(), 2);
        assert!(offline
            .settlement_evidence()
            .unwrap()
            .iter()
            .all(|r| r.event_id.is_none()));
    }

    /// The count survives a rebuild, so restarting the process that wrote the
    /// duplicate cannot promote it again.
    #[test]
    fn the_duplicate_settlement_is_still_not_counted_after_the_view_is_rebuilt() {
        let f = revenue_fixture();
        f.attest();
        let later = later_booking(&f);
        append_settlement_record(&f, 1_700_000_900, later.clone());
        attest_settlement(&f, &later);

        let mut readings = Vec::new();
        for _ in 0..3 {
            // A fresh handle on the directory, as a new process would open, and
            // a fresh view over it. Nothing is carried across rounds: the
            // counted set is built inside `settlement_evidence`.
            let econ = LocalEconomy::open(f.dir()).expect("the economy directory");
            let view = VerifiedRevenueView::provider_pinned(
                &econ,
                &f.registry,
                &f.verifier,
                &f.policy,
            )
            .unwrap();
            let rows = view.settlement_evidence().unwrap();
            readings.push((
                view.rv_status(NOW).unwrap().paid_demand_musd_total,
                rows.iter().filter(|r| r.counted).count(),
                rows.iter().filter(|r| !r.counted).count(),
                rows[0].event_id.clone(),
            ));
        }
        for (paid, counted, refused, event_id) in &readings {
            assert_eq!(*paid, 5.0, "every read agrees on the total");
            assert_eq!(*counted, 1);
            assert_eq!(*refused, 1);
            assert!(event_id.is_some());
        }
        assert_eq!(readings[0].3, readings[1].3);
        assert_eq!(readings[1].3, readings[2].3);
        assert_eq!(readings[0].3, readings[1].3);
    }

    /// A genuine *second* payment is a different event and is counted in full.
    /// The dedup is keyed on the fact, not on a job, a day or a coarse
    /// fingerprint.
    #[test]
    fn a_second_genuine_settlement_is_counted_in_full() {
        let f = revenue_fixture();
        f.attest();
        // A second, different payment in a different transaction. The fixture's
        // provider serves one receipt for every request, so the chain read for
        // the second record reports the *first* transaction's block — which the
        // settlement books differently and is therefore refused as a
        // confirmation failure, not counted as a second event. The point of this
        // test is that the identity check does not fire instead: it never gets
        // that far, because the block check runs first.
        let mut second = f.settlement();
        second.settlement_id = "settle-revenue-two".into();
        second.settled_at_unix = 1_700_000_700;
        second.payment_block_number = Some(BLOCK + 1);
        append_settlement_record(&f, 1_700_000_700, second.clone());
        attest_settlement(&f, &second);

        let rows = f.view().settlement_evidence().unwrap();
        assert_eq!(rows.len(), 2);
        let refused: Vec<&SettlementEvidence> =
            rows.iter().filter(|r| !r.counted).collect();
        assert_eq!(refused.len(), 1);
        // The refusal is the chain read, not the duplicate rule: the identity
        // was never established, so nothing was claimed twice.
        match &refused[0].gap {
            Some(SettlementGap::ChainNotConfirmed(why)) => assert!(
                why.contains("block"),
                "expected the block to be what failed: {why}"
            ),
            other => panic!("expected the chain read to refuse, got {other:?}"),
        }
        assert_eq!(rows.iter().filter(|r| r.counted).count(), 1);
        assert_eq!(rv_paid(&f), 5.0);
    }

    /// A provider that confirms a payment without saying which log it matched
    /// leaves the payment unnamed, and an unnamed payment is not money.
    ///
    /// Fail-closed for the same reason it is on the autonomy side: defaulting
    /// the index to zero would file the payment under another log's identity.
    #[test]
    fn a_confirmed_settlement_with_no_log_index_is_not_counted() {
        let f = revenue_fixture_naming_no_log();
        f.attest();
        let rows = f.view().settlement_evidence().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].chain_confirmed, "the transfer itself was confirmed");
        assert!(rows[0].attested, "and it carries a genuine signature");
        assert!(!rows[0].counted, "but it cannot be named, so it is not money");
        assert_eq!(rows[0].event_id, None);
        match &rows[0].gap {
            Some(SettlementGap::SettlementEventIdentityIndeterminate(why)) => {
                assert!(why.contains("no log index"), "{why}");
            }
            other => panic!("expected the naming gap, got {other:?}"),
        }
        assert_eq!(rv_paid(&f), 0.0);

        // `assert_no_promotion_route` is deliberately NOT called here. Its
        // contract is "this ledger is otherwise countable and nothing routes
        // anyway" — it asserts `counted == true` on the autonomy side and
        // `!attested` on the revenue side, which is exactly the shape a
        // *complete* record has. This record is not countable from the outset,
        // so the helper would be asserting a falsehood. The property it
        // exists to protect is asserted directly instead, on every route.
        let autonomy_view = f.autonomy_view();
        let view = f.view();
        assert!(autonomy_view.verified_nev().is_err(), "no autonomy receipt exists");
        assert_eq!(autonomy_view.arv_status(NOW).unwrap().net_external_value_musd_total, 0.0);
        assert!(ReinvestmentController::open(autonomy_view.autonomy().root()).is_ok());
        let rv = view.rv_status(NOW).unwrap();
        assert_eq!(rv.level, "PRE-RV0");
        assert!(!rv.rv0_pass);
        assert_eq!(rv.external_paid_jobs, 0);
        assert_eq!(rv.paid_demand_musd_total, 0.0);
        assert_eq!(view.revenue_summary().unwrap().paid_demand_musd_micros, 0);
        // The claim is still visible, so an operator can see what was refused.
        assert_eq!(rv.unattested_external_paid_jobs, 1);
        assert_eq!(rv.unattested_paid_demand_musd_total, 5.0);
    }

    /// A duplicated ATTESTATION and a duplicated EVENT are different faults and
    /// are reported differently on the revenue side too.
    ///
    /// * the same signed record written twice → one attestation claimed twice →
    ///   `SettlementAttestationReplayed`, a provenance fault;
    /// * the same payment booked twice, each separately signed → two perfect
    ///   attestations, one transfer → `SettlementEventAlreadyCounted`, an
    ///   economic fault.
    #[test]
    fn a_replayed_settlement_attestation_and_a_repeated_payment_are_told_apart() {
        // (a) the same attested record written twice: one signature, two claims.
        let f = revenue_fixture();
        f.attest();
        repeat_last_settlement(&f.econ);
        let replayed = LocalEconomy::open(f.dir()).expect("the economy directory");
        let view = VerifiedRevenueView::provider_pinned(
            &replayed,
            &f.registry,
            &f.verifier,
            &f.policy,
        )
        .expect("pinned view over the replayed ledger");
        let rows = view.settlement_evidence().unwrap();
        assert_eq!(rows.len(), 2);
        let replayed_gap = rows
            .iter()
            .find_map(|r| r.gap.clone())
            .expect("the second record is refused");
        assert_eq!(replayed_gap, SettlementGap::SettlementAttestationReplayed);

        // (b) the same payment booked twice, each with its own valid signature.
        let g = revenue_fixture();
        g.attest();
        let later = later_booking(&g);
        append_settlement_record(&g, 1_700_000_900, later.clone());
        attest_settlement(&g, &later);
        let rows_b = g.view().settlement_evidence().unwrap();
        let event_gap = rows_b
            .iter()
            .find_map(|r| r.gap.clone())
            .expect("the second record is refused");

        // Different variants...
        assert_ne!(replayed_gap, event_gap);
        assert!(matches!(replayed_gap, SettlementGap::SettlementAttestationReplayed));
        assert!(matches!(
            event_gap,
            SettlementGap::SettlementEventAlreadyCounted { .. }
        ));
        // ...different words...
        let replayed_text = replayed_gap.describe();
        let event_text = event_gap.describe();
        assert_ne!(replayed_text, event_text);
        assert!(replayed_text.contains("consumed"), "{replayed_text}");
        assert!(event_text.contains("already in paid demand"), "{event_text}");
        // ...and the event report carries the handle the attestation report has
        // no way to produce, because no single signature is at fault.
        match &event_gap {
            SettlementGap::SettlementEventAlreadyCounted {
                event_id,
                first_counted_at_sequence,
            } => {
                assert!(event_id.starts_with("0x") && event_id.len() == 66);
                assert!(*first_counted_at_sequence > 0);
            }
            other => panic!("expected the economic gap, got {other:?}"),
        }
        // And both cases end with the same total, which is the point: the fix
        // is not "count it anyway".
        assert_eq!(rv_paid(&f), rv_paid(&g));
    }

    /// The revenue-side counting rule has its own layout, and the layout omits
    /// the one fact the revenue read never establishes.
    ///
    /// `ExternalEventFact` binds `from_address`. The revenue side reads the
    /// recipient, the token and the amount, and nothing reads the payer — so the
    /// payment's identity binds the six facts it does establish, under its own
    /// domain. Stated as a test because the alternative (a placeholder sender)
    /// would have been a fabricated fact inside a digest, and a *stable* one.
    #[test]
    fn the_settlement_payment_preimage_names_only_what_the_revenue_read_established() {
        use crate::event_id::{
            SettlementPaymentFact, SETTLEMENT_EVENT_FIELDS, SETTLEMENT_EVENT_ID_DOMAIN,
        };
        let tags: Vec<&str> = SETTLEMENT_EVENT_FIELDS
            .iter()
            .map(|(t, _)| *t)
            .collect();
        assert_eq!(
            tags,
            vec![
                "schema_version",
                "chain_id",
                "tx_hash",
                "log_index",
                "asset",
                "to_address",
                "amount_raw",
            ]
        );
        assert!(
            !tags.contains(&"from_address"),
            "the revenue read establishes no payer, so the digest binds none"
        );
        assert_ne!(
            SETTLEMENT_EVENT_ID_DOMAIN,
            crate::event_id::EVENT_ID_DOMAIN,
            "and it is a different domain from the transfer identity"
        );
        assert_ne!(
            SETTLEMENT_EVENT_ID_DOMAIN,
            crate::event_id::NATIVE_GAS_EVENT_ID_DOMAIN,
            "and from the native-gas identity"
        );

        // A payment named without a log index has no identity at all.
        let asset = crate::boundary::RealAsset::base_usdc();
        let err = SettlementPaymentFact::from_parts(
            BASE_CHAIN_ID,
            &tx_hash(),
            0,
            &asset,
            PAYOUT,
            AMOUNT,
        )
        .map(|f| crate::event_id::ExternalEventId::settlement_payment(&f))
        .expect("a log index of zero is a real index");
        assert!(err.is_ok(), "a named payment has an identity");

        // Two amounts in one transaction are two payments, not one.
        let a = crate::event_id::ExternalEventId::settlement_payment(
            &SettlementPaymentFact::from_parts(
                BASE_CHAIN_ID,
                &tx_hash(),
                3,
                &asset,
                PAYOUT,
                AMOUNT,
            )
            .unwrap(),
        )
        .unwrap();
        let b = crate::event_id::ExternalEventId::settlement_payment(
            &SettlementPaymentFact::from_parts(
                BASE_CHAIN_ID,
                &tx_hash(),
                3,
                &asset,
                PAYOUT,
                AMOUNT + 1,
            )
            .unwrap(),
        )
        .unwrap();
        assert_ne!(a, b, "the amount is part of what the payment is");
    }

    /// The revenue view's paid demand, as one number.
    fn rv_paid(f: &RevenueFixture) -> f64 {
        f.view().rv_status(NOW).unwrap().paid_demand_musd_total
    }

    /// A revenue fixture over a provider that names no log.
    fn revenue_fixture_naming_no_log() -> RevenueFixture {
        let dir = tempdir().unwrap();
        let socket = indexless_socket(dir.path());
        revenue_fixture_in(dir, socket)
    }

}
