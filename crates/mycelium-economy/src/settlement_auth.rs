//! P4c: the authenticated settlement receipt, and its integration into the
//! verified revenue read side.
//!
//! # The gap this module exists to close
//!
//! P4b built [`crate::receipt_auth`], a signed wrapper for external-value
//! receipts, and then said plainly what it had left open:
//!
//! ```text
//! "SettlementReceipt is not signed. RV's 'authenticated' half is exactly one
//!  thing: the view holds a policy validated against the pinned anchor."
//! ```
//!
//! Concretely: a party who can write `revenue-ledger.jsonl` **and** can produce
//! a *real* on-chain transfer of the right size into a controlled address could
//! book a settlement that no verifier ever signed, and the view would count it
//! as paid demand. Before this module that attack needs nothing but a ledger
//! write and a transfer anyone can make.
//!
//! This module is the revenue-side mirror of `receipt_auth`: a settlement plus
//! a signature from the one verifier key the validated policy delegated to.
//!
//! # The rule the read side now enforces
//!
//! ```text
//! VerifiedRsv = VerifyChain(VerifySettlementSig(VerifyPolicy(DeriveSettlement)))
//! ```
//!
//! Read innermost last. `DeriveSettlement(...)` — P3's re-derivation, untouched:
//! every structural fact about the settlement is recomputed from the ledger and
//! its payment intent. `VerifyPolicy(...)` — the outcome policy was validated
//! against the pinned trust anchor (P4a) and is scoped to this chain, registry
//! and provider. `VerifySettlementSig(...)` — **this module**: the settlement
//! carries a signature from the delegated verifier, over facts re-derived from
//! the ledger, never over a copy stored beside the signature. `VerifyChain(...)`
//! — the pinned, kernel-identified provider re-reads the cited transaction.
//!
//! The signature **does not substitute for the chain read**, exactly as on the
//! autonomy side. A signature says "the delegated verifier signed this
//! settlement against this transfer"; only the chain read says the transfer
//! happened. `assert_no_promotion_route` in [`crate::verified_view`] asserts
//! that no combination of the two short-circuits the other.
//!
//! # Where the key comes from — the same trap, the same close
//!
//! [`AuthenticatedSettlementReceipt::verify`] takes **no key parameter**, for
//! the same reason the receipt check does not: the only `VerifyingKey` a
//! settlement check can obtain comes out of
//! [`ValidatedOutcomePolicy::trusted_verifier`], whose only constructor is on a
//! policy that resolved its authority from the pinned anchor. `verify` needs a
//! [`ValidatedOutcomePolicy`] to exist at all.
//!
//! The signing side is mirror-image too:
//! [`VerifierRuntimeKey::attest_settlement`] refuses unless the key signing
//! *is* the key the validated policy delegated to, so holding a key that no
//! validated policy delegated to is not authority.
//!
//! # What the signature covers
//!
//! Not JSON, and never a serialised struct. The preimage is built with the same
//! tagged, length-prefixed, domain-first encoder P4a established
//! ([`crate::policy_auth::push_tagged`]), under its **own** domain,
//! [`SETTLEMENT_ATTESTATION_DOMAIN`], which is a different byte string from the
//! receipt attestation's [`crate::receipt_auth::EXTERNAL_VALUE_ATTESTATION_DOMAIN`].
//! Because the domain is the first tagged section of both preimages, a settlement
//! signature cannot verify as a receipt signature and a receipt signature cannot
//! verify as a settlement signature even when every other section is made to
//! match. `a_settlement_signature_cannot_be_replayed_as_a_receipt_signature`
//! proves it in both directions.
//!
//! Two things are worth calling out, because they are the parts a naive version
//! gets wrong:
//!
//! * **The signed facts are re-derived, never read back.** `verify` takes the
//!   ledger's own `PaymentIntent` and rebuilds the body from it. A wrapper that
//!   carried the payee, the amount or the intent id and verified against its own
//!   copy would be attesting to itself — the [`mycelium_pheromones::Gland`]
//!   shape, one type over.
//! * **`settlement_hash` is in the preimage.** The chain facts do not bind the
//!   *economics*: `usd_equivalent_micros` and `settled_amount_micros` are ledger
//!   numbers, and RV sums the first. A ledger author holding one genuine
//!   signature could otherwise inflate either. The preimage therefore also
//!   covers a canonical digest of every field of the settlement, so one signature
//!   is valid for exactly one settlement content.
//!
//! # The amount relationship — a deliberate non-assertion
//!
//! P4b flagged the question: a genuine signature attests "this receipt against
//! this transfer", but does not assert `net == on-chain amount`. Same here, and
//! the decision is deliberate.
//!
//! **The settlement attestation does not assert the amount relationship.** It
//! binds the *identity* of the two amounts — `amount_raw` is the exact on-chain
//! amount the intent authorised, `settlement_hash` covers the ledger's own
//! figures — so the signature says "these two numbers belong to this one
//! settlement". It does **not** say `usd_equivalent_micros == amount_raw`.
//!
//! That rule stays where P3 put it, and it did not move:
//! [`crate::verified_view::SettlementGap::AmountNotJustified`] in
//! `rederive_settlement`, and the write-time check in
//! `LocalEconomy::append_settlement`. It belongs there for three reasons:
//!
//! 1. It is a predicate over two ledger records the *reader* can see
//!    (`SettlementReceipt.usd_equivalent_micros` and
//!    `PaymentIntent.exact_amount_raw`). A verifier is handed both in the same
//!    call, so it could enforce it — but then the rule would live in two places
//!    and the two could drift apart silently.
//! 2. Arithmetic in a signature is arithmetic a *signer* can get wrong, and a
//!    signer bug would then become a promotion rule. Re-derivation has no signer
//!    in the loop.
//! 3. P3's arithmetic is the crate's economic contract; folding a copy of it
//!    into a signature would not strengthen it, it would fork it.
//!
//! So the signature establishes provenance and the re-derivation establishes the
//! arithmetic, and neither stands in for the other.
//!
//! # What is NOT here
//!
//! * **Policy rotation history.** Identical to the receipt side, on purpose: a
//!   settlement carries the `policy_hash` it was issued under and the view
//!   compares it to the policy in force now. A settlement from policy A is never
//!   silently re-approved under policy B.
//! * **The confirmed block hash.** A settlement record claims a block *height*,
//!   not a block hash, and the only block hash it is anchored to is the payment
//!   intent's. That is what the preimage binds (`anchor_block`,
//!   `anchor_block_hash`). Binding the *confirmed* block hash would require
//!   moving the signature gate after the chain read, which breaks parity with the
//!   autonomy sequence (`VerifySettlementSig` sits inside `VerifyChain`); the
//!   height is re-checked against the provider's answer at read time instead,
//!   which is the part that has to hold for promotion.
//! * **Any protection against a party who can rewrite the whole economy
//!   directory**, which P4a documented as outside its threat model, and which
//!   applies unchanged here.

use crate::{
    policy_auth::{
        push_tagged, signature_serde, Address, Hash, KeyId, KeyRole, PolicyError,
        PreimageFieldKind, TrustedVerifierKey, ValidatedOutcomePolicy,
        VerifierRuntimeKey,
    },
    EconomyError, PaymentIntent, SettlementMode, SettlementReceipt,
};
use ed25519_dalek::{Signature, Verifier as _};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader},
    path::Path,
};

/// Domain string of the settlement attestation preimage. First bytes of every
/// settlement preimage, and a different string from the receipt attestation's
/// domain, so the two signatures are never interchangeable.
pub const SETTLEMENT_ATTESTATION_DOMAIN: &str = "MYCELIUM-ECONOMY/SETTLEMENT/V1";

/// Domain of the canonical settlement digest that the preimage carries.
pub const SETTLEMENT_HASH_DOMAIN: &str =
    "MYCELIUM-ECONOMY/SETTLEMENT-RECEIPT/V1";

/// Schema version this build issues and accepts for settlement attestations.
///
/// A different constant from [`crate::receipt_auth::ATTESTATION_SCHEMA_VERSION`]
/// on purpose: the two artefacts have different layouts and must never be
/// confused for one another at the version level either.
pub const SETTLEMENT_ATTESTATION_SCHEMA_VERSION: u32 = 1;

/// Settlement attestation ledger file name in the economy root; also the append
/// lock name and the head anchor's ledger identifier.
pub const SETTLEMENT_ATTESTATION_LEDGER_FILE: &str =
    "settlement-attestations.jsonl";

/// First `prev_hash` of a settlement attestation ledger. The public genesis
/// anchor, identical to the autonomy ledgers': it is a fixed string, not a
/// secret, and the head anchor file is what actually pins the tail.
pub const SETTLEMENT_ATTESTATION_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum SettlementAuthError {
    /// Wraps P4a's vocabulary rather than inventing a parallel one: a policy
    /// that does not validate is a policy error, and the caller reports it as
    /// such.
    #[error(transparent)]
    Policy(#[from] PolicyError),

    #[error(transparent)]
    Economy(#[from] EconomyError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("settlement preimage is malformed: {0}")]
    Preimage(String),

    /// The settlement and the intent it is measured against describe different
    /// transfers: different job, different intent, different anchor.
    #[error(
        "settlement {settlement} cites intent {cited}, but intent {other} is \
         the one recorded for job {job}"
    )]
    IntentMismatch {
        settlement: String,
        cited: String,
        other: String,
        job: String,
    },

    #[error("payment intent {field} is not usable in a signed attestation: {reason}")]
    UnusableIntent { field: &'static str, reason: String },

    #[error("settlement {field} is not usable in a signed attestation: {reason}")]
    UnusableSettlement { field: &'static str, reason: String },

    /// The signing key is not the key the validated policy delegated to.
    #[error(
        "verifier key {key_id} signed this settlement, but the policy delegates \
         to {delegated}; a key no validated policy delegated to cannot attest"
    )]
    SigningKeyNotDelegated { key_id: String, delegated: String },

    /// The settlement claims to be signed by a key the current policy does not
    /// delegate to. This is what an unknown verifier's signature gets.
    #[error("settlement names verifier {claimed}, but the policy delegates to {delegated}")]
    VerifierNotDelegated { claimed: String, delegated: String },

    #[error("settlement attestation signature does not verify against the policy's delegated verifier key")]
    BadSignature,

    #[error("settlement attestation was issued under policy {found}, but the current policy is {current}")]
    PolicyHashMismatch { found: String, current: String },

    #[error("settlement attestation_hash {found} is not the digest of its signed body ({computed})")]
    AttestationHashMismatch { found: String, computed: String },

    #[error("settlement attestation was issued on chain {found}, but the current policy settles on {expected}")]
    PolicyChainMismatch { found: u64, expected: u64 },
}

// ---------------------------------------------------------------------------
// The canonical settlement digest
// ---------------------------------------------------------------------------

/// Every field of [`SettlementReceipt`], in canonical order.
///
/// The chain facts in the preimage do not mention the economics, and the
/// economics are what RV sums. A digest over every field means one signature is
/// valid for exactly one settlement content, so a valid attestation cannot be
/// re-pointed at an inflated amount — the shape P4b gave the receipt digest.
///
/// `mode`, `settlement_asset` and the three optional payment fields take their
/// canonical form from serde: they are closed enums or nullable values whose
/// wire spelling is already inside the ledger's own `record_hash`, so renaming a
/// variant or re-spelling a `null` breaks existing ledgers loudly rather than
/// silently re-hashing them.
const SETTLEMENT_HASH_FIELDS: &[(&str, PreimageFieldKind)] = &[
    ("schema_version", PreimageFieldKind::U32),
    ("settlement_id", PreimageFieldKind::Text),
    ("job_id", PreimageFieldKind::Text),
    ("work_receipt_id", PreimageFieldKind::Text),
    ("settled_at_unix", PreimageFieldKind::U64),
    ("mode", PreimageFieldKind::Bytes),
    ("settlement_asset", PreimageFieldKind::Bytes),
    ("settled_amount_micros", PreimageFieldKind::U64),
    ("usd_equivalent_micros", PreimageFieldKind::U64),
    ("payment_intent_id", PreimageFieldKind::Bytes),
    ("payment_block_number", PreimageFieldKind::Bytes),
    ("payment_proof_hash", PreimageFieldKind::Bytes),
    ("payment_proof_verified", PreimageFieldKind::Bool),
    ("external_paid", PreimageFieldKind::Bool),
    ("internal_work", PreimageFieldKind::Bool),
];

/// Canonical digest of a settlement's whole content, under
/// [`SETTLEMENT_HASH_DOMAIN`].
///
/// Used twice, for two jobs that must not be confused:
/// * it is a field of the signed preimage, so a signature cannot be re-pointed;
/// * it is the key the view indexes attestations under, so a mutated ledger
///   settlement simply does not find the attestation signed for the original.
pub fn settlement_hash(
    settlement: &SettlementReceipt,
) -> Result<Hash, SettlementAuthError> {
    let mode = serde_json::to_vec(&settlement.mode)?;
    let asset = serde_json::to_vec(&settlement.settlement_asset)?;
    let intent_id = serde_json::to_vec(&settlement.payment_intent_id)?;
    let block = serde_json::to_vec(&settlement.payment_block_number)?;
    let proof = serde_json::to_vec(&settlement.payment_proof_hash)?;
    let values: Vec<(&str, Vec<u8>)> = vec![
        (
            "schema_version",
            settlement.schema_version.to_be_bytes().to_vec(),
        ),
        ("settlement_id", settlement.settlement_id.as_bytes().to_vec()),
        ("job_id", settlement.job_id.as_bytes().to_vec()),
        (
            "work_receipt_id",
            settlement.work_receipt_id.as_bytes().to_vec(),
        ),
        (
            "settled_at_unix",
            settlement.settled_at_unix.to_be_bytes().to_vec(),
        ),
        ("mode", mode),
        ("settlement_asset", asset),
        (
            "settled_amount_micros",
            settlement.settled_amount_micros.to_be_bytes().to_vec(),
        ),
        (
            "usd_equivalent_micros",
            settlement.usd_equivalent_micros.to_be_bytes().to_vec(),
        ),
        ("payment_intent_id", intent_id),
        ("payment_block_number", block),
        ("payment_proof_hash", proof),
        (
            "payment_proof_verified",
            vec![u8::from(settlement.payment_proof_verified)],
        ),
        ("external_paid", vec![u8::from(settlement.external_paid)]),
        ("internal_work", vec![u8::from(settlement.internal_work)]),
    ];
    check_layout(&values, SETTLEMENT_HASH_FIELDS, "settlement digest")?;

    let mut buf = Vec::new();
    push_tagged(&mut buf, b"domain", SETTLEMENT_HASH_DOMAIN.as_bytes());
    push_tagged(
        &mut buf,
        b"sections",
        &u32::try_from(values.len())
            .map_err(|_| {
                SettlementAuthError::Preimage(
                    "too many settlement digest sections".into(),
                )
            })?
            .to_be_bytes(),
    );
    for (tag, value) in &values {
        push_tagged(&mut buf, tag.as_bytes(), value);
    }
    Ok(Hash::from_bytes(*blake3::hash(&buf).as_bytes()))
}

/// The encoder and the layout table can disagree in exactly one way that
/// matters — a field renamed on one side and not the other — so it is checked
/// at run time rather than trusted. Same discipline as
/// [`crate::policy_auth::OutcomePolicyPayload::signing_preimage`] and
/// `receipt_auth::check_layout`, kept local so the two modules' layout tables
/// stay independent.
fn check_layout(
    values: &[(&str, Vec<u8>)],
    layout: &[(&str, PreimageFieldKind)],
    what: &str,
) -> Result<(), SettlementAuthError> {
    if values.len() != layout.len() {
        return Err(SettlementAuthError::Preimage(format!(
            "{what}: encoder emitted {} sections for a layout of {}",
            values.len(),
            layout.len()
        )));
    }
    for ((tag, _), (expected_tag, _)) in values.iter().zip(layout.iter()) {
        if *tag != *expected_tag {
            return Err(SettlementAuthError::Preimage(format!(
                "{what}: encoder emitted section {tag:?} where the layout expects \
                 {expected_tag:?}"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The signed body
// ---------------------------------------------------------------------------

/// The settlement attestation preimage layout, in canonical order.
///
/// Fourteen sections. The ten the design calls for — `policy_hash`, `chain_id`,
/// `tx_hash`, `anchor_block_hash`, `asset`, `payee`, `amount_raw`, `job_id`,
/// `payment_intent_id`, `payment_block` — plus four that make the signature mean
/// something: `anchor_block` (so a settlement cannot claim a block at or before
/// the intent's anchor), `schema_version` (so a future layout cannot be mistaken
/// for this one), `verifier_key_id` (so a settlement cannot be re-signed under
/// another delegated key) and `settlement_hash` (so it cannot be re-pointed at
/// another settlement's economics).
///
/// Note what is **not** here: the economics themselves. `usd_equivalent_micros`
/// and `settled_amount_micros` are covered by `settlement_hash`, which is a
/// statement about identity, not arithmetic. See the module doc for why the
/// amount *relationship* is P3's rule and stays there.
pub const SETTLEMENT_ATTESTATION_PREIMAGE_FIELDS: &[(
    &str,
    PreimageFieldKind,
)] = &[
    ("schema_version", PreimageFieldKind::U32),
    ("policy_hash", PreimageFieldKind::Hash32),
    ("chain_id", PreimageFieldKind::U64),
    ("tx_hash", PreimageFieldKind::Hash32),
    ("payment_block", PreimageFieldKind::U64),
    ("anchor_block", PreimageFieldKind::U64),
    ("anchor_block_hash", PreimageFieldKind::Hash32),
    ("asset", PreimageFieldKind::Text),
    ("payee", PreimageFieldKind::AddressText),
    ("amount_raw", PreimageFieldKind::U64),
    ("job_id", PreimageFieldKind::Text),
    ("payment_intent_id", PreimageFieldKind::Text),
    ("verifier_key_id", PreimageFieldKind::KeyId32),
    ("settlement_hash", PreimageFieldKind::Hash32),
];

/// The exact bytes a verifier key signs over a settlement.
///
/// Built with the same construction as the policy preimage:
///
/// ```text
/// tagged   := TAG_LEN:u32be || TAG || VALUE_LEN:u32be || VALUE
/// preimage := tagged("domain", SETTLEMENT_ATTESTATION_DOMAIN)
///          || tagged("sections", SECTION_COUNT:u32be)
///          || section*
/// section  := tagged(TAG_i, VALUE_i)   for TAG_i in SETTLEMENT_ATTESTATION_PREIMAGE_FIELDS
/// ```
///
/// Never a serialised struct: signing a self-describing encoding would promote
/// field order, whitespace, number formatting and unknown fields into
/// cryptographic semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementAttestationBody {
    pub schema_version: u32,
    pub policy_hash: Hash,
    pub chain_id: u64,
    /// The transaction the settlement cites, canonicalised from
    /// `SettlementReceipt::payment_proof_hash`.
    pub tx_hash: Hash,
    /// `SettlementReceipt::payment_block_number`: the block the settlement books.
    pub payment_block: u64,
    pub anchor_block: u64,
    /// The payment intent's anchor block hash — the block hash this settlement is
    /// anchored to. See the module doc on why this is a section rather than the
    /// confirmed block's hash.
    pub anchor_block_hash: Hash,
    /// Canonical contract of the identified real asset, from the settlement's
    /// `settlement_asset` classified through
    /// [`crate::boundary::SettlementAsset::classify_symbol`]. The chain travels in its own
    /// section and the pair is the asset identity this crate uses everywhere
    /// else, so `usdc` and `USDC` cannot be two different signed messages.
    pub asset: String,
    /// The controlled address the payment must have reached: the intent's
    /// `recipient`.
    pub payee: Address,
    /// The intent's `exact_amount_raw`. The on-chain amount, from the payment
    /// record, not from the settlement's own arithmetic.
    pub amount_raw: u64,
    pub job_id: String,
    pub payment_intent_id: String,
    pub verifier_key_id: KeyId,
    pub settlement_hash: Hash,
}

impl SettlementAttestationBody {
    /// Rebuilds the body from a settlement, the payment intent it settles and
    /// the policy being asked about it.
    ///
    /// `policy_hash` and `verifier_key_id` are *arguments*, not values read off
    /// the current policy, and that is deliberate for the same reason as on the
    /// receipt side: the preimage must be reconstructible from the artefact
    /// alone plus the ledger's own records, so the signature check answers "is
    /// this attestation internally authentic?" and the separate `policy_hash`
    /// comparison answers "is it current?". Reading both from the policy here
    /// would collapse two independent gates into one and make the second
    /// unobservable.
    ///
    /// Everything else comes from the two ledger records, and the checks below
    /// are the same shape as P3's `rederive_settlement`: signing is never more
    /// permissive than re-derivation. A settlement that P3 would refuse — not
    /// external, synthetic asset, no transaction, a different intent, a block at
    /// or before the anchor — cannot be signed at all.
    pub fn from_parts(
        settlement: &SettlementReceipt,
        intent: &PaymentIntent,
        policy_hash: &Hash,
        verifier_key_id: KeyId,
    ) -> Result<Self, SettlementAuthError> {
        if settlement.mode != SettlementMode::External {
            return Err(SettlementAuthError::UnusableSettlement {
                field: "mode",
                reason: "only an external settlement can be attested".into(),
            });
        }
        if settlement.internal_work {
            return Err(SettlementAuthError::UnusableSettlement {
                field: "internal_work",
                reason: "internal work is never paid demand".into(),
            });
        }
        if settlement.job_id.trim().is_empty() {
            return Err(SettlementAuthError::UnusableSettlement {
                field: "job_id",
                reason: "a settlement must name its job".into(),
            });
        }
        // The asset goes through the same classifier the reader uses, so a
        // synthetic ledger unit cannot be signed at all and the signed asset is
        // the *identified* contract rather than whatever spelling the ledger
        // used. `SettlementAsset::symbol()` keeps the exact stored string
        // ("usdc" and "USDC" are two different symbols), so it is not canonical
        // and would make the same asset two different signed messages; the
        // normalised contract is canonical by construction.
        let asset = match settlement.settlement_asset.real_asset() {
            Some(real) => real.clone(),
            None => {
                return Err(SettlementAuthError::UnusableSettlement {
                    field: "settlement_asset",
                    reason: format!(
                        "{} is a synthetic ledger unit and can never be attested",
                        settlement.settlement_asset.symbol()
                    ),
                })
            }
        };
        if asset.chain_id() != intent.chain_id {
            return Err(SettlementAuthError::UnusableIntent {
                field: "chain_id",
                reason: format!(
                    "intent is on chain {} while its asset is on chain {}",
                    intent.chain_id,
                    asset.chain_id()
                ),
            });
        }
        // The token the intent pays in must be the asset the settlement claims
        // to have been paid in. `PaymentIntent.token` is stored lowercased by
        // `init_payment_policy`, and the real asset's contract is lowercase, so
        // this is a case-insensitive comparison on purpose.
        if !intent.token.eq_ignore_ascii_case(asset.contract()) {
            return Err(SettlementAuthError::UnusableIntent {
                field: "token",
                reason: format!(
                    "intent pays in {} while the settlement claims {}",
                    intent.token,
                    asset.contract()
                ),
            });
        }
        if intent.exact_amount_raw == 0 {
            return Err(SettlementAuthError::UnusableIntent {
                field: "exact_amount_raw",
                reason: "a payment intent must authorise a non-zero amount".into(),
            });
        }
        if intent.payment_intent_id.trim().is_empty() {
            return Err(SettlementAuthError::UnusableIntent {
                field: "payment_intent_id",
                reason: "a payment intent must name itself".into(),
            });
        }
        // The settlement has to settle *this* intent for *this* job. Without
        // this a signature for one intent could be re-pointed at another.
        if settlement.job_id != intent.job_id {
            return Err(SettlementAuthError::IntentMismatch {
                settlement: settlement.settlement_id.clone(),
                cited: settlement
                    .payment_intent_id
                    .clone()
                    .unwrap_or_else(|| "<none>".into()),
                other: intent.payment_intent_id.clone(),
                job: intent.job_id.clone(),
            });
        }
        if settlement.payment_intent_id.as_deref()
            != Some(intent.payment_intent_id.as_str())
        {
            return Err(SettlementAuthError::IntentMismatch {
                settlement: settlement.settlement_id.clone(),
                cited: settlement
                    .payment_intent_id
                    .clone()
                    .unwrap_or_else(|| "<none>".into()),
                other: intent.payment_intent_id.clone(),
                job: intent.job_id.clone(),
            });
        }
        let Some(tx) = settlement.payment_proof_hash.as_deref() else {
            return Err(SettlementAuthError::UnusableSettlement {
                field: "payment_proof_hash",
                reason: "an external settlement must cite a transaction".into(),
            });
        };
        let Some(payment_block) = settlement.payment_block_number else {
            return Err(SettlementAuthError::UnusableSettlement {
                field: "payment_block_number",
                reason: "an external settlement must book a block".into(),
            });
        };
        if payment_block <= intent.anchor_block {
            return Err(SettlementAuthError::UnusableSettlement {
                field: "payment_block_number",
                reason: format!(
                    "payment block {payment_block} is not after the intent anchor {}",
                    intent.anchor_block
                ),
            });
        }
        // Both hashes are validated before they are taken, so a signed body can
        // never cover a malformed citation.
        let tx_hash = Hash::parse("payment_proof_hash", tx)?;
        let anchor_block_hash =
            Hash::parse("anchor_block_hash", &intent.anchor_block_hash)?;
        let payee = Address::parse(&intent.recipient).map_err(|e| {
            SettlementAuthError::UnusableIntent {
                field: "recipient",
                reason: e.to_string(),
            }
        })?;
        Ok(Self {
            schema_version: SETTLEMENT_ATTESTATION_SCHEMA_VERSION,
            policy_hash: policy_hash.clone(),
            chain_id: intent.chain_id,
            tx_hash,
            payment_block,
            anchor_block: intent.anchor_block,
            anchor_block_hash,
            asset: asset.contract().to_string(),
            payee,
            amount_raw: intent.exact_amount_raw,
            job_id: intent.job_id.clone(),
            payment_intent_id: intent.payment_intent_id.clone(),
            verifier_key_id,
            settlement_hash: settlement_hash(settlement)?,
        })
    }

    pub fn signing_preimage(&self) -> Result<Vec<u8>, SettlementAuthError> {
        let policy_hash = self.policy_hash.to_bytes()?;
        let tx_hash = self.tx_hash.to_bytes()?;
        let anchor_block_hash = self.anchor_block_hash.to_bytes()?;
        let verifier_key_id = *self.verifier_key_id.as_bytes();
        let settlement_hash = self.settlement_hash.to_bytes()?;
        let values: Vec<(&str, Vec<u8>)> = vec![
            ("schema_version", self.schema_version.to_be_bytes().to_vec()),
            ("policy_hash", policy_hash.to_vec()),
            ("chain_id", self.chain_id.to_be_bytes().to_vec()),
            ("tx_hash", tx_hash.to_vec()),
            ("payment_block", self.payment_block.to_be_bytes().to_vec()),
            ("anchor_block", self.anchor_block.to_be_bytes().to_vec()),
            ("anchor_block_hash", anchor_block_hash.to_vec()),
            ("asset", self.asset.as_bytes().to_vec()),
            ("payee", self.payee.as_str().as_bytes().to_vec()),
            ("amount_raw", self.amount_raw.to_be_bytes().to_vec()),
            ("job_id", self.job_id.as_bytes().to_vec()),
            ("payment_intent_id", self.payment_intent_id.as_bytes().to_vec()),
            ("verifier_key_id", verifier_key_id.to_vec()),
            ("settlement_hash", settlement_hash.to_vec()),
        ];
        check_layout(
            &values,
            SETTLEMENT_ATTESTATION_PREIMAGE_FIELDS,
            "settlement attestation preimage",
        )?;

        let mut buf = Vec::new();
        push_tagged(
            &mut buf,
            b"domain",
            SETTLEMENT_ATTESTATION_DOMAIN.as_bytes(),
        );
        push_tagged(
            &mut buf,
            b"sections",
            &u32::try_from(values.len())
                .map_err(|_| {
                    SettlementAuthError::Preimage(
                        "too many settlement attestation sections".into(),
                    )
                })?
                .to_be_bytes(),
        );
        for (tag, value) in &values {
            push_tagged(&mut buf, tag.as_bytes(), value);
        }
        Ok(buf)
    }

    /// Digest of the preimage. This is what `attestation_hash` carries, and it is
    /// an audit handle over the signed body — never an authority input on its
    /// own, and recomputed and compared at verification time.
    pub fn attestation_hash(&self) -> Result<Hash, SettlementAuthError> {
        let preimage = self.signing_preimage()?;
        Ok(Hash::from_bytes(*blake3::hash(&preimage).as_bytes()))
    }
}

// ---------------------------------------------------------------------------
// The wrapper
// ---------------------------------------------------------------------------

/// A settlement receipt plus the verifier's signature over it.
///
/// Private fields and exactly one constructor,
/// [`VerifierRuntimeKey::attest_settlement`], which requires a
/// [`ValidatedOutcomePolicy`]. `Deserialize` exists so the wrapper survives a
/// round trip through the settlement attestation ledger, and it is not a trust
/// input: a decoded wrapper is a claim until `verify` says otherwise, and
/// `verify` needs a validated policy to exist at all.
///
/// Field-for-field the same shape as
/// [`crate::receipt_auth::AuthenticatedExternalValueReceipt`], so the two ledgers
/// read alike and the two threats are described in the same words.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedSettlementReceipt {
    settlement: SettlementReceipt,
    policy_hash: Hash,
    verifier_key_id: KeyId,
    attestation_hash: Hash,
    #[serde(with = "signature_serde")]
    signature: Signature,
}

impl AuthenticatedSettlementReceipt {
    pub fn settlement(&self) -> &SettlementReceipt {
        &self.settlement
    }

    /// The policy this settlement was issued under. Compared against
    /// [`ValidatedOutcomePolicy::policy_hash`] for the policy in force now.
    pub fn policy_hash(&self) -> &Hash {
        &self.policy_hash
    }

    pub fn verifier_key_id(&self) -> KeyId {
        self.verifier_key_id
    }

    pub fn attestation_hash(&self) -> &Hash {
        &self.attestation_hash
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    /// The digest this attestation is indexed under. Recomputed from the
    /// embedded settlement, never read out of the record.
    pub fn settlement_hash(&self) -> Result<Hash, SettlementAuthError> {
        settlement_hash(&self.settlement)
    }

    /// Reconstructs the body this attestation *would* be over, for diagnostics
    /// and for the view's reporting. Never returns a key and never authorises
    /// anything.
    pub fn body(
        &self,
        intent: &PaymentIntent,
    ) -> Result<SettlementAttestationBody, SettlementAuthError> {
        SettlementAttestationBody::from_parts(
            &self.settlement,
            intent,
            &self.policy_hash,
            self.verifier_key_id,
        )
    }

    /// The authoritative check. Requires a validated policy, and takes no key:
    /// the verifier key comes out of `policy`, which is the only place in the
    /// crate a `VerifyingKey` for a delegated verifier can be reached.
    ///
    /// Gate order, which is the identity in the module doc:
    ///
    /// 1. **verifier authorized** — the claimed `verifier_key_id` is the one the
    ///    current policy delegates to. A settlement signed by an unknown
    ///    verifier stops here, before any signature maths.
    /// 2. **signature valid** — over the preimage rebuilt from the ledger's own
    ///    settlement and payment intent, never from a copy stored beside the
    ///    signature.
    /// 3. **policy_hash matches** — the settlement was issued under the policy in
    ///    force now. One from policy A is refused under policy B.
    /// 4. three consistency assertions: the attestation's own digest handle, the
    ///    chain the intent settles on, and the policy's chain.
    ///
    /// Note that steps 1 to 3 say nothing about whether the transfer happened.
    /// Only the view's chain read, which runs after this, can say that.
    pub fn verify(
        &self,
        policy: &ValidatedOutcomePolicy,
        intent: &PaymentIntent,
    ) -> Result<VerifiedSettlementAttestation, SettlementAuthError> {
        // (1) The verifier has to be one this policy delegated to.
        let trusted: TrustedVerifierKey = policy.trusted_verifier();
        if self.verifier_key_id != trusted.key_id() {
            return Err(SettlementAuthError::VerifierNotDelegated {
                claimed: self.verifier_key_id.to_string(),
                delegated: trusted.key_id().to_string(),
            });
        }
        // Gate 1 is also an internal consistency check: the id has to be the
        // identity of the key it names, in the verifier-runtime role. P4a makes
        // the same check on a policy; a hand-built wrapper skips both.
        if self.verifier_key_id.role() != KeyRole::VerifierRuntime {
            return Err(SettlementAuthError::VerifierNotDelegated {
                claimed: self.verifier_key_id.to_string(),
                delegated: trusted.key_id().to_string(),
            });
        }
        let body = self.body(intent)?;
        if body.schema_version != SETTLEMENT_ATTESTATION_SCHEMA_VERSION {
            return Err(SettlementAuthError::Preimage(format!(
                "settlement attestation schema_version {} is not supported \
                 (expected {})",
                body.schema_version, SETTLEMENT_ATTESTATION_SCHEMA_VERSION
            )));
        }
        let preimage = body.signing_preimage()?;

        // (2) The signature, against the key the validated policy delegated to.
        trusted.verifying_key()?.verify(&preimage, &self.signature).map_err(
            |_| SettlementAuthError::BadSignature,
        )?;

        // (3) The policy binding. The signature already covers `policy_hash`, so
        // this cannot be skipped by editing the field — but it is a *different*
        // question: not "is this attestation authentic?" but "is it current?",
        // and collapsing the two is how a rotated policy silently re-approves
        // old settlements. Policy-rotation history is out of scope: nothing here
        // accepts a settlement issued under a previous policy.
        let current = policy.policy_hash()?;
        if self.policy_hash != current {
            return Err(SettlementAuthError::PolicyHashMismatch {
                found: self.policy_hash.to_string(),
                current: current.to_string(),
            });
        }

        // Consistency assertions, after the authority gates.
        let computed = body.attestation_hash()?;
        if self.attestation_hash != computed {
            return Err(SettlementAuthError::AttestationHashMismatch {
                found: self.attestation_hash.to_string(),
                computed: computed.to_string(),
            });
        }
        if intent.chain_id != policy.chain_id() {
            return Err(SettlementAuthError::PolicyChainMismatch {
                found: intent.chain_id,
                expected: policy.chain_id(),
            });
        }
        Ok(VerifiedSettlementAttestation {
            attestation_hash: self.attestation_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            verifier_key_id: self.verifier_key_id,
            settlement_hash: self.settlement_hash()?,
            payment_intent_id: body.payment_intent_id,
            payee: body.payee,
            amount_raw: body.amount_raw,
        })
    }
}

/// What a successful [`AuthenticatedSettlementReceipt::verify`] establishes.
///
/// A settlement of provenance, not of money: it says the delegated verifier
/// signed this settlement against this intent under this policy. The view still
/// has to re-derive P3's arithmetic and re-read the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSettlementAttestation {
    pub attestation_hash: Hash,
    pub policy_hash: Hash,
    pub verifier_key_id: KeyId,
    pub settlement_hash: Hash,
    pub payment_intent_id: String,
    /// The controlled address the payment must have reached, as signed.
    pub payee: Address,
    /// The exact on-chain amount the intent authorised, as signed. Note this is
    /// the *identity* of the amount, not a statement that
    /// `usd_equivalent_micros == amount_raw`: that stays P3's rule in
    /// `rederive_settlement`.
    pub amount_raw: u64,
}

impl VerifierRuntimeKey {
    /// Signs a settlement against the payment intent it settles.
    ///
    /// The only constructor of an [`AuthenticatedSettlementReceipt`], and it
    /// requires a validated policy for a reason that has nothing to do with
    /// signatures: a key that no validated policy delegated to must not be able
    /// to mint attestations, or "signed by a key some policy delegated to" would
    /// be a statement with no referent.
    ///
    /// The settlement and the intent are the verifier's own view of the ledger.
    /// Both are validated here, not merely carried, so an operator holding this
    /// key cannot sign a body P3's re-derivation would refuse.
    pub fn attest_settlement(
        &self,
        policy: &ValidatedOutcomePolicy,
        settlement: &SettlementReceipt,
        intent: &PaymentIntent,
    ) -> Result<AuthenticatedSettlementReceipt, SettlementAuthError> {
        let trusted = policy.trusted_verifier();
        if self.key_id() != trusted.key_id() {
            return Err(SettlementAuthError::SigningKeyNotDelegated {
                key_id: self.key_id().to_string(),
                delegated: trusted.key_id().to_string(),
            });
        }
        let policy_hash = policy.policy_hash()?;
        let body = SettlementAttestationBody::from_parts(
            settlement,
            intent,
            &policy_hash,
            self.key_id(),
        )?;
        let preimage = body.signing_preimage()?;
        let attestation_hash = body.attestation_hash()?;
        Ok(AuthenticatedSettlementReceipt {
            settlement: settlement.clone(),
            policy_hash,
            verifier_key_id: self.key_id(),
            attestation_hash,
            signature: self.sign_preimage(&preimage),
        })
    }
}

// ---------------------------------------------------------------------------
// The settlement attestation ledger file
// ---------------------------------------------------------------------------

/// One line of the settlement attestation ledger.
///
/// Same shape and same hashing rule as
/// [`crate::autonomy::AttestationRecord`]: the hash is committed over the record
/// with an empty `record_hash`, so it is a chain, not a checksum of the final
/// bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementAttestationRecord {
    pub sequence: u64,
    pub recorded_at_unix: u64,
    pub prev_hash: String,
    pub record_hash: String,
    pub attestation: AuthenticatedSettlementReceipt,
}

impl SettlementAttestationRecord {
    /// `pub(crate)` because the append lives on `LocalEconomy`, next to the
    /// revenue ledger it gates, and mirrors `autonomy::AttestationRecord`.
    pub(crate) fn computed_hash(&self) -> Result<String, EconomyError> {
        let mut copy = self.clone();
        copy.record_hash.clear();
        Ok(blake3::hash(&serde_json::to_vec(&copy)?)
            .to_hex()
            .to_string())
    }
}

/// Chain-verifies the settlement attestation ledger file.
///
/// A missing file is an empty ledger, which is the legacy shape — every economy
/// directory written before this step has settlements and no attestations, and
/// those settlements must keep deserializing and be reported as unattested. A
/// present but broken file is an error, so a corrupted attestation ledger can
/// never degrade into "no attestations", which would be indistinguishable from
/// "unsigned".
pub fn read_settlement_attestation_file(
    path: &Path,
) -> crate::Result<Vec<SettlementAttestationRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(path)?;
    let mut out = Vec::new();
    let mut expected_seq = 1u64;
    let mut expected_prev = SETTLEMENT_ATTESTATION_GENESIS_HASH.to_string();
    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: SettlementAttestationRecord = serde_json::from_str(&line)
            .map_err(|e| {
                EconomyError::Invalid(format!(
                    "settlement attestation ledger line {} cannot be parsed: {}",
                    idx + 1,
                    e
                ))
            })?;
        if record.sequence != expected_seq {
            return Err(EconomyError::Invalid(format!(
                "settlement attestation ledger sequence mismatch: expected {}, got {}",
                expected_seq, record.sequence
            )));
        }
        if record.prev_hash != expected_prev {
            return Err(EconomyError::Invalid(format!(
                "settlement attestation ledger hash-chain break at sequence {}",
                record.sequence
            )));
        }
        let computed = record.computed_hash()?;
        if record.record_hash != computed {
            return Err(EconomyError::Invalid(format!(
                "settlement attestation ledger hash mismatch at sequence {}",
                record.sequence
            )));
        }
        expected_prev = record.record_hash.clone();
        expected_seq += 1;
        out.push(record);
    }
    Ok(out)
}

/// Builds the shape of an attack: a cryptographically valid settlement
/// attestation signed by a key the caller names, bypassing
/// [`VerifierRuntimeKey::attest_settlement`]'s own refusal.
///
/// The test-only counterpart to the signing guard, and it exists so the read
/// side can be handed the artefact instead of having to assert that such an
/// artefact is impossible to build — which is exactly the assertion the Gland
/// trap is about. Every caller must also prove the signature is otherwise
/// genuine (see `a_key_no_validated_policy_delegated_to_cannot_sign_a_settlement`
/// in `verified_view.rs`), or the resulting test would pass for the wrong reason.
#[cfg(test)]
pub(crate) fn forge_settlement_with(
    key: &VerifierRuntimeKey,
    policy: &ValidatedOutcomePolicy,
    settlement: &SettlementReceipt,
    intent: &PaymentIntent,
) -> Result<AuthenticatedSettlementReceipt, SettlementAuthError> {
    let policy_hash = policy.policy_hash()?;
    let body = SettlementAttestationBody::from_parts(
        settlement,
        intent,
        &policy_hash,
        key.key_id(),
    )?;
    let preimage = body.signing_preimage()?;
    Ok(AuthenticatedSettlementReceipt {
        settlement: settlement.clone(),
        policy_hash,
        verifier_key_id: key.key_id(),
        attestation_hash: body.attestation_hash()?,
        signature: key.sign_preimage(&preimage),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        base_usdc::BASE_CHAIN_ID,
        boundary::SettlementAsset,
        policy_auth::{VerifierPublicKey, VerifierRuntimeKey},
        receipt_auth::testkit::{evidence, AuthFixture},
        SCHEMA_VERSION,
    };
    use std::fs;

    const PAYOUT: &str = "0xe83331104f5f3c41e49abc46c810f9d71133e48c";
    const COUNTERPARTY: &str = "0x1234567890abcdef1234567890abcdef12345678";
    const AMOUNT: u64 = 5_000_000;
    const ANCHOR_BLOCK: u64 = 100;
    const PAYMENT_BLOCK: u64 = 101;

    fn socket(dir: &std::path::Path) -> crate::rpc_test_server::FakeRpcSocket {
        crate::rpc_test_server::FakeRpcSocket::with_responses(
            dir.join("verifier.sock"),
            Vec::<(&str, serde_json::Value)>::new(),
        )
    }

    fn fixture(dir: &std::path::Path) -> AuthFixture {
        let socket = socket(dir);
        let registry = crate::boundary::ControlledAddressRegistry::new()
            .with_address(PAYOUT)
            .unwrap();
        AuthFixture::new(socket.path(), socket.uid(), registry)
    }

    fn intent() -> PaymentIntent {
        PaymentIntent {
            schema_version: SCHEMA_VERSION,
            payment_intent_id: "payintent-1".into(),
            job_id: "job-1".into(),
            chain_id: BASE_CHAIN_ID,
            token: crate::base_usdc::BASE_USDC.to_ascii_lowercase(),
            recipient: PAYOUT.into(),
            exact_amount_raw: AMOUNT,
            anchor_block: ANCHOR_BLOCK,
            anchor_block_hash: format!("0x{}", "22".repeat(32)),
            anchor_timestamp_unix: 1_700_000_300,
            created_at_unix: 1_700_000_310,
        }
    }

    fn settlement() -> SettlementReceipt {
        SettlementReceipt {
            schema_version: SCHEMA_VERSION,
            settlement_id: "settle-1".into(),
            job_id: "job-1".into(),
            work_receipt_id: "work-1".into(),
            settled_at_unix: 1_700_000_400,
            mode: SettlementMode::External,
            settlement_asset: SettlementAsset::base_usdc(),
            settled_amount_micros: AMOUNT,
            usd_equivalent_micros: AMOUNT,
            payment_intent_id: Some("payintent-1".into()),
            payment_block_number: Some(PAYMENT_BLOCK),
            payment_proof_hash: Some(format!("0x{}", "11".repeat(32))),
            payment_proof_verified: true,
            external_paid: true,
            internal_work: false,
        }
    }

    fn body_of(
        policy: &ValidatedOutcomePolicy,
        settlement: &SettlementReceipt,
        intent: &PaymentIntent,
    ) -> SettlementAttestationBody {
        SettlementAttestationBody::from_parts(
            settlement,
            intent,
            &policy.policy_hash().unwrap(),
            policy.trusted_verifier().key_id(),
        )
        .unwrap()
    }

    // ------------------------------------------------------------------
    // 1. the happy path, end to end through the type
    // ------------------------------------------------------------------

    #[test]
    fn a_valid_settlement_attestation_verifies_under_the_policy_that_issued_it() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let attestation = auth
            .verifier
            .attest_settlement(&policy, &settlement(), &intent())
            .unwrap();

        assert_eq!(attestation.verifier_key_id(), auth.verifier.key_id());
        assert_eq!(
            attestation.policy_hash(),
            &policy.policy_hash().unwrap(),
            "the settlement carries the policy it was issued under"
        );
        assert_eq!(
            attestation.attestation_hash(),
            &body_of(&policy, &settlement(), &intent())
                .attestation_hash()
                .unwrap()
        );
        let verified = attestation.verify(&policy, &intent()).unwrap();
        assert_eq!(verified.policy_hash, *attestation.policy_hash());
        assert_eq!(verified.verifier_key_id, auth.verifier.key_id());
        assert_eq!(
            verified.settlement_hash,
            attestation.settlement_hash().unwrap()
        );
        assert_eq!(verified.payment_intent_id, "payintent-1");
        assert_eq!(verified.payee.as_str(), PAYOUT);
        assert_eq!(verified.amount_raw, AMOUNT);

        // And it survives a round trip through the wire, which is how it is
        // stored. A decoded attestation is a claim; `verify` is what makes it
        // anything, and it works identically on the decoded copy.
        let bytes = serde_json::to_vec(&attestation).unwrap();
        let decoded: AuthenticatedSettlementReceipt =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            decoded.verify(&policy, &intent()).unwrap().attestation_hash,
            verified.attestation_hash
        );
    }

    // ------------------------------------------------------------------
    // 2. the verifier has to be one a policy delegated to
    // ------------------------------------------------------------------

    #[test]
    fn a_settlement_signed_by_an_unknown_verifier_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let other = auth.with_other_verifier();
        let impostor = other.verifier.clone();
        assert_ne!(
            impostor.key_id(),
            policy.trusted_verifier().key_id()
        );
        // Control: the key signs perfectly well under the policy that delegates
        // to it, so the refusal below is about the delegation and not the bytes.
        let other_policy = other.validate().unwrap();
        assert_eq!(other_policy.trusted_verifier().key_id(), impostor.key_id());
        assert!(impostor
            .attest_settlement(&other_policy, &settlement(), &intent())
            .unwrap()
            .verify(&other_policy, &intent())
            .is_ok());

        // Under the policy in force, the same key signs the same settlement
        // against the current policy's hash. The signature maths is perfect and
        // the only thing wrong is the delegation.
        let forged = forge_settlement_with(
            &impostor,
            &policy,
            &settlement(),
            &intent(),
        )
        .unwrap();
        assert_eq!(forged.verifier_key_id(), impostor.key_id());
        let err = forged.verify(&policy, &intent()).unwrap_err();
        assert!(
            matches!(err, SettlementAuthError::VerifierNotDelegated { .. }),
            "an unknown verifier must be refused on the delegation check, got {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains(&impostor.key_id().to_string()), "{msg}");
        assert!(msg.contains(&auth.verifier.key_id().to_string()), "{msg}");
    }

    #[test]
    fn a_key_no_validated_policy_delegated_to_cannot_sign_a_settlement() {
        // The signing-side half of the layer-down trap: holding a verifier key
        // is not authority.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let orphan = VerifierRuntimeKey::generate();
        let err = orphan
            .attest_settlement(&policy, &settlement(), &intent())
            .unwrap_err();
        assert!(
            matches!(err, SettlementAuthError::SigningKeyNotDelegated { .. }),
            "a key the policy does not delegate to must not mint attestations, got {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains(&orphan.key_id().to_string()), "{msg}");
        assert!(msg.contains(&auth.verifier.key_id().to_string()), "{msg}");
    }

    // ------------------------------------------------------------------
    // 3. the policy binding
    // ------------------------------------------------------------------

    #[test]
    fn a_settlement_issued_under_a_previous_policy_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let old = auth.validated();
        let attestation = auth
            .verifier
            .attest_settlement(&old, &settlement(), &intent())
            .unwrap();
        assert!(attestation.verify(&old, &intent()).is_ok());

        let rotated = auth.rotated(old.policy_version() + 1).validate().unwrap();
        assert_ne!(rotated.policy_hash().unwrap(), old.policy_hash().unwrap());
        let err = attestation.verify(&rotated, &intent()).unwrap_err();
        assert!(
            matches!(err, SettlementAuthError::PolicyHashMismatch { .. }),
            "a settlement from policy A must not be re-approved under policy B, got {err}"
        );
        // And it still verifies under its own policy: nothing was invalidated, it
        // simply is not current.
        assert!(attestation.verify(&old, &intent()).is_ok());
    }

    // ------------------------------------------------------------------
    // 4. the preimage
    // ------------------------------------------------------------------

    #[test]
    fn the_preimage_is_bytes_not_json_and_is_domain_separated() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let settlement = settlement();
        let intent = intent();
        let body = body_of(&policy, &settlement, &intent);
        let preimage = body.signing_preimage().unwrap();

        // Not a serialised struct: the transaction hash appears as raw bytes and
        // its hex spelling appears nowhere.
        let tx_bytes = body.tx_hash.to_bytes().unwrap();
        assert!(preimage.windows(32).any(|w| w == tx_bytes));
        let hex = format!("0x{}", "11".repeat(32));
        assert!(
            !preimage.windows(hex.len()).any(|w| w == hex.as_bytes()),
            "the preimage must not carry the hex spelling"
        );
        assert_ne!(serde_json::to_vec(&body).unwrap(), preimage);

        // The domain is the first tagged section, and it is this module's own.
        let mut expected = Vec::new();
        push_tagged(
            &mut expected,
            b"domain",
            SETTLEMENT_ATTESTATION_DOMAIN.as_bytes(),
        );
        assert!(preimage.starts_with(&expected));

        // Domain-separated: the same sections under any other domain are
        // different bytes.
        for other_domain in [
            crate::receipt_auth::EXTERNAL_VALUE_ATTESTATION_DOMAIN,
            crate::policy_auth::POLICY_SIGNING_DOMAIN,
            crate::policy_auth::CONTROLLED_REGISTRY_DOMAIN,
            "MYCELIUM-ECONOMY/SOMETHING-ELSE/V1",
        ] {
            let mut other = Vec::new();
            push_tagged(&mut other, b"domain", other_domain.as_bytes());
            push_tagged(
                &mut other,
                b"sections",
                &(SETTLEMENT_ATTESTATION_PREIMAGE_FIELDS.len() as u32)
                    .to_be_bytes(),
            );
            for (tag, _) in SETTLEMENT_ATTESTATION_PREIMAGE_FIELDS {
                push_tagged(
                    &mut other,
                    tag.as_bytes(),
                    &section_bytes(&body, tag),
                );
            }
            assert_ne!(
                other, preimage,
                "the preimage must differ under domain {other_domain}"
            );
        }

        // Stable: the same inputs produce the same bytes, byte for byte.
        assert_eq!(body.signing_preimage().unwrap(), preimage);
        assert_eq!(
            body_of(&policy, &settlement, &intent)
                .signing_preimage()
                .unwrap(),
            preimage
        );

        // Length-prefixed, so a value cannot be shifted between two sections.
        // `asset` and `job_id` are both text.
        let mut shifted = Vec::new();
        push_tagged(&mut shifted, b"domain", SETTLEMENT_ATTESTATION_DOMAIN.as_bytes());
        push_tagged(&mut shifted, b"sections", &2u32.to_be_bytes());
        push_tagged(
            &mut shifted,
            b"asset",
            format!("{}{}", body.asset, body.job_id).as_bytes(),
        );
        assert!(!preimage
            .windows(shifted.len())
            .any(|w| w == shifted.as_slice()));
    }

    #[test]
    fn a_settlement_signature_cannot_be_replayed_as_a_receipt_signature() {
        // The domain separation, proved in both directions and against a
        // deliberate re-labelling.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let verifying = policy.trusted_verifier().verifying_key().unwrap();

        let settlement = settlement();
        let intent = intent();
        let attestation = auth
            .verifier
            .attest_settlement(&policy, &settlement, &intent)
            .unwrap();
        let settlement_preimage = attestation.body(&intent).unwrap().signing_preimage()
            .unwrap();

        // The receipt side of the same chain facts: same transaction, same
        // block, same asset, same amount, same controlled payee, same key. Every
        // field the two preimages have in common carries the same bytes, so the
        // ONLY thing separating the two signed messages is the domain and the
        // section list.
        let receipt = crate::autonomy::ExternalValueReceipt {
            schema_version: SCHEMA_VERSION,
            source_id: "source-1".into(),
            agent_id: "s1-arb-01".into(),
            opportunity_id: "opp-1".into(),
            value_class: crate::autonomy::ExternalValueClass::ExternalTradingPnl,
            network: "base".into(),
            asset: "USDC".into(),
            gross_inflow_musd_micros: AMOUNT,
            external_cost_musd_micros: 0,
            net_external_value_musd_micros: AMOUNT as i64,
            proof_hash: settlement.payment_proof_hash.clone().unwrap(),
            proof_verified: true,
            realized_at_unix: 1_700_000_400,
            verifier_id: "base-reconcile".into(),
        };
        let chain_evidence = evidence(COUNTERPARTY, PAYOUT, AMOUNT);
        let receipt_attestation =
            auth.verifier.attest(&policy, &receipt, &chain_evidence).unwrap();
        let receipt_preimage = receipt_attestation
            .body(&chain_evidence)
            .unwrap()
            .signing_preimage()
            .unwrap();

        // 1. The two preimages are different messages...
        assert_ne!(settlement_preimage, receipt_preimage);
        assert_ne!(
            SETTLEMENT_ATTESTATION_DOMAIN,
            crate::receipt_auth::EXTERNAL_VALUE_ATTESTATION_DOMAIN
        );
        // ...each carrying its own domain and not the other's...
        assert!(settlement_preimage
            .windows(SETTLEMENT_ATTESTATION_DOMAIN.len())
            .any(|w| w == SETTLEMENT_ATTESTATION_DOMAIN.as_bytes()));
        assert!(!settlement_preimage
            .windows(crate::receipt_auth::EXTERNAL_VALUE_ATTESTATION_DOMAIN.len())
            .any(|w| w == crate::receipt_auth::EXTERNAL_VALUE_ATTESTATION_DOMAIN.as_bytes()));
        assert!(receipt_preimage
            .windows(crate::receipt_auth::EXTERNAL_VALUE_ATTESTATION_DOMAIN.len())
            .any(|w| w == crate::receipt_auth::EXTERNAL_VALUE_ATTESTATION_DOMAIN.as_bytes()));

        // 2. ...so neither signature verifies over the other's message.
        assert!(verifying
            .verify(&settlement_preimage, attestation.signature())
            .is_ok());
        assert!(
            verifying
                .verify(&receipt_preimage, attestation.signature())
                .is_err(),
            "a settlement signature verified as a receipt signature"
        );
        assert!(
            verifying
                .verify(&settlement_preimage, receipt_attestation.signature())
                .is_err(),
            "a receipt signature verified as a settlement signature"
        );

        // 3. And the wrappers cannot even be read as one another: five fields
        // each, of different types. A JSON blob carrying a settlement
        // attestation is not a receipt attestation.
        let settlement_json = serde_json::to_value(&attestation).unwrap();
        assert!(serde_json::from_value::<
            crate::receipt_auth::AuthenticatedExternalValueReceipt,
        >(settlement_json.clone())
        .is_err());
        let receipt_json = serde_json::to_value(&receipt_attestation).unwrap();
        assert!(serde_json::from_value::<AuthenticatedSettlementReceipt>(
            receipt_json.clone()
        )
        .is_err());
        assert!(serde_json::from_value::<AuthenticatedSettlementReceipt>(
            settlement_json
        )
        .is_ok());

        // 4. The strongest form of the attack: re-label the settlement's own
        // sections under the receipt domain. The bytes are the settlement's, the
        // layout is the settlement's, and only the domain string is the
        // impostor's. The signature still refuses, because it was made over the
        // settlement domain.
        let mut relabelled = Vec::new();
        push_tagged(
            &mut relabelled,
            b"domain",
            crate::receipt_auth::EXTERNAL_VALUE_ATTESTATION_DOMAIN.as_bytes(),
        );
        push_tagged(
            &mut relabelled,
            b"sections",
            &(SETTLEMENT_ATTESTATION_PREIMAGE_FIELDS.len() as u32).to_be_bytes(),
        );
        for (tag, _) in SETTLEMENT_ATTESTATION_PREIMAGE_FIELDS {
            push_tagged(
                &mut relabelled,
                tag.as_bytes(),
                &section_bytes(&body_of(&policy, &settlement, &intent), tag),
            );
        }
        assert!(relabelled != settlement_preimage);
        assert!(
            verifying
                .verify(&relabelled, attestation.signature())
                .is_err(),
            "a re-domained settlement preimage verified: the domain separation \
             does not bite"
        );
    }

    #[test]
    fn mutating_any_signed_section_invalidates_the_signature() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let attestation = auth
            .verifier
            .attest_settlement(&policy, &settlement(), &intent())
            .unwrap();
        let body = body_of(&policy, &settlement(), &intent());
        let preimage = body.signing_preimage().unwrap();
        let verifying = policy.trusted_verifier().verifying_key().unwrap();
        assert!(verifying
            .verify(&preimage, attestation.signature())
            .is_ok());

        let mut mutated_any = false;
        for (tag, _) in SETTLEMENT_ATTESTATION_PREIMAGE_FIELDS {
            let mut mutated = body.clone();
            let changed = mutate_field(&mut mutated, tag);
            assert!(changed, "no mutation defined for section {tag:?}");
            mutated_any = true;
            let mutated_preimage = mutated.signing_preimage().unwrap();
            assert_ne!(
                mutated_preimage, preimage,
                "section {tag:?} is not in the preimage at all"
            );
            assert!(
                verifying
                    .verify(&mutated_preimage, attestation.signature())
                    .is_err(),
                "a signature survived a change to {tag:?}"
            );
        }
        assert!(
            mutated_any,
            "the layout table was empty, so this test proved nothing"
        );
    }

    #[test]
    fn swapping_two_sections_changes_the_preimage() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let body = body_of(&policy, &settlement(), &intent());

        let ordered = |order: &[&str]| -> Vec<u8> {
            let mut buf = Vec::new();
            push_tagged(
                &mut buf,
                b"domain",
                SETTLEMENT_ATTESTATION_DOMAIN.as_bytes(),
            );
            push_tagged(
                &mut buf,
                b"sections",
                &(order.len() as u32).to_be_bytes(),
            );
            for tag in order {
                push_tagged(&mut buf, tag.as_bytes(), &section_bytes(&body, tag));
            }
            buf
        };
        let tags: Vec<&str> = SETTLEMENT_ATTESTATION_PREIMAGE_FIELDS
            .iter()
            .map(|(tag, _)| *tag)
            .collect();
        assert_eq!(ordered(&tags), body.signing_preimage().unwrap());
        let mut swapped = tags.clone();
        swapped.swap(3, 4);
        assert_ne!(ordered(&swapped), body.signing_preimage().unwrap());
        let mut rotated = tags.clone();
        rotated.rotate_left(1);
        assert_ne!(ordered(&rotated), body.signing_preimage().unwrap());
    }

    #[test]
    fn mutating_the_settlement_after_signing_invalidates_it() {
        // Every field of the settlement is covered by `settlement_hash`, so one
        // signature is valid for exactly one settlement content. Each edit below
        // is asserted to move the digest *and* to leave the wrapper unverifiable.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let intent = intent();
        let original = settlement();
        let attestation = auth
            .verifier
            .attest_settlement(&policy, &original, &intent)
            .unwrap();
        assert!(attestation.verify(&policy, &intent).is_ok());

        let edits: Vec<(&str, Box<dyn Fn(&mut SettlementReceipt)>)> = vec![
            ("settlement id", Box::new(|s: &mut SettlementReceipt| {
                s.settlement_id = "settle-2".into();
            })),
            ("job id", Box::new(|s: &mut SettlementReceipt| {
                s.job_id = "job-2".into();
            })),
            ("work receipt id", Box::new(|s: &mut SettlementReceipt| {
                s.work_receipt_id = "work-2".into();
            })),
            ("settled at", Box::new(|s: &mut SettlementReceipt| {
                s.settled_at_unix += 1;
            })),
            ("mode", Box::new(|s: &mut SettlementReceipt| {
                s.mode = SettlementMode::Simulated;
            })),
            ("asset", Box::new(|s: &mut SettlementReceipt| {
                s.settlement_asset = SettlementAsset::synthetic(
                    crate::boundary::SyntheticAsset::SmUsd,
                );
            })),
            ("settled amount", Box::new(|s: &mut SettlementReceipt| {
                s.settled_amount_micros += 100_000_000;
            })),
            ("usd equivalent", Box::new(|s: &mut SettlementReceipt| {
                s.usd_equivalent_micros += 100_000_000;
            })),
            ("intent id", Box::new(|s: &mut SettlementReceipt| {
                s.payment_intent_id = Some("payintent-2".into());
            })),
            ("payment block", Box::new(|s: &mut SettlementReceipt| {
                s.payment_block_number = Some(PAYMENT_BLOCK + 1);
            })),
            ("cited transaction", Box::new(|s: &mut SettlementReceipt| {
                s.payment_proof_hash = Some(format!("0x{}", "cc".repeat(32)));
            })),
            ("stored proof flag", Box::new(|s: &mut SettlementReceipt| {
                s.payment_proof_verified = false;
            })),
            ("external paid flag", Box::new(|s: &mut SettlementReceipt| {
                s.external_paid = false;
            })),
            ("internal work flag", Box::new(|s: &mut SettlementReceipt| {
                s.internal_work = true;
            })),
            ("absent payment block", Box::new(|s: &mut SettlementReceipt| {
                s.payment_block_number = None;
            })),
        ];
        assert_eq!(
            edits.len(),
            SETTLEMENT_HASH_FIELDS.len(),
            "every field of the settlement must have an edit"
        );
        for (label, edit) in edits {
            let mut edited = original.clone();
            edit(&mut edited);
            assert_ne!(
                settlement_hash(&edited).unwrap(),
                settlement_hash(&original).unwrap(),
                "the {label} edit did not change the settlement"
            );
            let tampered = AuthenticatedSettlementReceipt {
                settlement: edited.clone(),
                policy_hash: attestation.policy_hash.clone(),
                verifier_key_id: attestation.verifier_key_id,
                attestation_hash: attestation.attestation_hash.clone(),
                signature: attestation.signature.clone(),
            };
            assert!(
                tampered.verify(&policy, &intent).is_err(),
                "a signature survived an edit to {label}"
            );
        }
    }

    // ------------------------------------------------------------------
    // 5. what the wrapper does not let you do
    // ------------------------------------------------------------------

    #[test]
    fn the_attestation_carries_no_field_a_reader_could_verify_against() {
        // The signed facts — chain, payee, amount, anchor — are not stored in the
        // wrapper. A wrapper that carried them would be verified against its own
        // copy, which is the `Gland` shape one type over. `verify` takes the
        // payment intent instead.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let attestation = auth
            .verifier
            .attest_settlement(&policy, &settlement(), &intent())
            .unwrap();
        let json = serde_json::to_value(&attestation).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "attestation_hash",
                "policy_hash",
                "settlement",
                "signature",
                "verifier_key_id",
            ],
            "the wrapper is exactly the five fields the design names"
        );
        for absent in [
            "payee",
            "amount_raw",
            "asset",
            "tx_hash",
            "block_hash",
            "anchor_block",
            "payment_intent_id",
        ] {
            assert!(
                json.get(absent).is_none(),
                "{absent} must not be a field a reader could trust"
            );
        }
    }

    #[test]
    fn the_attestation_hash_is_checked_so_the_record_cannot_be_edited() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let mut attestation = auth
            .verifier
            .attest_settlement(&policy, &settlement(), &intent())
            .unwrap();
        attestation.attestation_hash = Hash::from_bytes([0x5au8; 32]);
        let err = attestation.verify(&policy, &intent()).unwrap_err();
        assert!(
            matches!(err, SettlementAuthError::AttestationHashMismatch { .. }),
            "an edited digest handle must be caught, got {err}"
        );
    }

    #[test]
    fn a_re_signed_body_is_still_refused_when_the_digest_handle_is_stale() {
        // Somebody holding the delegated key (the operator does) can produce a
        // valid signature over a different body. The digest handle is what stops
        // the *record* being relabelled underneath it.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let attestation = auth
            .verifier
            .attest_settlement(&policy, &settlement(), &intent())
            .unwrap();
        let mut resigned = body_of(&policy, &settlement(), &intent());
        resigned.amount_raw = AMOUNT * 2;
        let preimage = resigned.signing_preimage().unwrap();
        let mut swapped = attestation.clone();
        swapped.signature = auth.verifier.sign_preimage(&preimage);
        assert!(
            swapped.verify(&policy, &intent()).is_err(),
            "a valid signature over a different body must not verify as this attestation"
        );
    }

    #[test]
    fn the_verifying_key_is_not_reachable_outside_a_validated_policy() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        // Every public route to the bytes...
        let from_policy = policy.verifier_public_key();
        let from_trusted = policy.trusted_verifier().public_key().clone();
        let from_signer = auth.verifier.public_key();
        let rebuilt = VerifierPublicKey::from_bytes(*from_policy.as_bytes());
        assert_eq!(rebuilt.as_bytes(), from_trusted.as_bytes());
        assert_eq!(rebuilt.as_bytes(), from_signer.as_bytes());
        assert_eq!(rebuilt.key_id(), policy.trusted_verifier().key_id());
        // ...and a settlement is still only verifiable through a validated
        // policy. A wrapper claiming a different key id for the same bytes is
        // refused, because the id is derived from the key *in the
        // verifier-runtime role*.
        let attestation = auth
            .verifier
            .attest_settlement(&policy, &settlement(), &intent())
            .unwrap();
        assert!(attestation.verify(&policy, &intent()).is_ok());
        let mut relabelled = attestation.clone();
        relabelled.verifier_key_id =
            KeyId::derive(KeyRole::PolicyAuthority, from_policy.as_bytes());
        let err = relabelled.verify(&policy, &intent()).unwrap_err();
        assert!(
            matches!(err, SettlementAuthError::VerifierNotDelegated { .. }),
            "a key id in the authority role must not satisfy a verifier delegation, got {err}"
        );
    }

    #[test]
    fn signing_is_never_more_permissive_than_re_derivation() {
        // Every settlement P3's re-derivation refuses is also unsigned, so a
        // verifier cannot bless something no reader would ever count.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let intent = intent();

        let cases: Vec<(&str, SettlementReceipt)> = vec![
            ("a simulated settlement", SettlementReceipt {
                mode: SettlementMode::Simulated,
                ..settlement()
            }),
            ("internal work", SettlementReceipt {
                internal_work: true,
                ..settlement()
            }),
            (
                "a synthetic ledger unit",
                SettlementReceipt {
                    settlement_asset: SettlementAsset::synthetic(
                        crate::boundary::SyntheticAsset::SmUsd,
                    ),
                    ..settlement()
                },
            ),
            ("no cited transaction", SettlementReceipt {
                payment_proof_hash: None,
                ..settlement()
            }),
            ("no payment block", SettlementReceipt {
                payment_block_number: None,
                ..settlement()
            }),
            (
                "a block at or before the anchor",
                SettlementReceipt {
                    payment_block_number: Some(ANCHOR_BLOCK),
                    ..settlement()
                },
            ),
            ("another intent", SettlementReceipt {
                payment_intent_id: Some("payintent-2".into()),
                ..settlement()
            }),
            ("no intent at all", SettlementReceipt {
                payment_intent_id: None,
                ..settlement()
            }),
            ("another job", SettlementReceipt {
                job_id: "job-2".into(),
                ..settlement()
            }),
            ("a malformed transaction", SettlementReceipt {
                payment_proof_hash: Some("0xnothex".into()),
                ..settlement()
            }),
            ("an empty job id", SettlementReceipt {
                job_id: String::new(),
                ..settlement()
            }),
        ];
        for (why, settlement) in cases {
            assert!(
                auth.verifier
                    .attest_settlement(&policy, &settlement, &intent)
                    .is_err(),
                "{why} must not be signable"
            );
        }

        // And the intent side: an intent that cannot describe a real transfer is
        // refused too.
        let bad_intents: Vec<(&str, PaymentIntent)> = vec![
            ("a foreign chain", PaymentIntent {
                chain_id: BASE_CHAIN_ID + 1,
                ..intent.clone()
            }),
            ("a foreign token", PaymentIntent {
                token: "0x0000000000000000000000000000000000000042".into(),
                ..intent.clone()
            }),
            ("a zero amount", PaymentIntent {
                exact_amount_raw: 0,
                ..intent.clone()
            }),
            ("a malformed recipient", PaymentIntent {
                recipient: "0xnope".into(),
                ..intent.clone()
            }),
            ("a malformed anchor hash", PaymentIntent {
                anchor_block_hash: "0xzz".into(),
                ..intent.clone()
            }),
            ("an unnamed intent", PaymentIntent {
                payment_intent_id: "  ".into(),
                ..intent.clone()
            }),
        ];
        for (why, bad) in bad_intents {
            assert!(
                auth.verifier
                    .attest_settlement(&policy, &settlement(), &bad)
                    .is_err(),
                "an intent with {why} must not be signable"
            );
        }
    }

    // ------------------------------------------------------------------
    // 6. the store
    // ------------------------------------------------------------------

    #[test]
    fn the_settlement_attestation_ledger_chain_verifies_and_refuses_a_broken_one() {
        let dir = tempfile::tempdir().unwrap();
        let econ = crate::LocalEconomy::open(dir.path()).unwrap();
        // No file yet: the legacy shape. An absent ledger is an empty ledger, not
        // an error, or every directory written before this step would be
        // unreadable.
        assert_eq!(econ.settlement_attestations().unwrap().len(), 0);
        assert!(!econ.settlement_attestation_ledger_path().exists());

        let auth = fixture(dir.path());
        let policy = auth.validated();
        for i in 0..3u64 {
            let settlement = SettlementReceipt {
                settlement_id: format!("settle-{i}"),
                ..settlement()
            };
            econ.record_settlement_attestation(
                &auth.verifier
                    .attest_settlement(&policy, &settlement, &intent())
                    .unwrap(),
            )
            .unwrap();
        }
        assert_eq!(econ.settlement_attestations().unwrap().len(), 3);
        for stored in econ.settlement_attestations().unwrap() {
            assert!(stored.verify(&policy, &intent()).is_ok());
        }

        // Corrupt the middle of the chain.
        let path = econ.settlement_attestation_ledger_path();
        let raw = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = raw.lines().map(|l| l.to_string()).collect();
        lines[1] = lines[1].replace("\"settle-1\"", "\"settle-tampered\"");
        assert_ne!(lines[1], raw.lines().nth(1).unwrap());
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let err = econ.settlement_attestations().unwrap_err();
        assert!(
            err.to_string().contains("hash"),
            "a rewritten settlement attestation ledger must be refused, got {err}"
        );
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    fn section_bytes(body: &SettlementAttestationBody, tag: &str) -> Vec<u8> {
        match tag {
            "schema_version" => body.schema_version.to_be_bytes().to_vec(),
            "policy_hash" => body.policy_hash.to_bytes().unwrap().to_vec(),
            "chain_id" => body.chain_id.to_be_bytes().to_vec(),
            "tx_hash" => body.tx_hash.to_bytes().unwrap().to_vec(),
            "payment_block" => body.payment_block.to_be_bytes().to_vec(),
            "anchor_block" => body.anchor_block.to_be_bytes().to_vec(),
            "anchor_block_hash" => {
                body.anchor_block_hash.to_bytes().unwrap().to_vec()
            }
            "asset" => body.asset.as_bytes().to_vec(),
            "payee" => body.payee.as_str().as_bytes().to_vec(),
            "amount_raw" => body.amount_raw.to_be_bytes().to_vec(),
            "job_id" => body.job_id.as_bytes().to_vec(),
            "payment_intent_id" => body.payment_intent_id.as_bytes().to_vec(),
            "verifier_key_id" => body.verifier_key_id.as_bytes().to_vec(),
            "settlement_hash" => body.settlement_hash.to_bytes().unwrap().to_vec(),
            other => panic!("unknown section {other:?}"),
        }
    }

    fn mutate_field(body: &mut SettlementAttestationBody, tag: &str) -> bool {
        match tag {
            "schema_version" => body.schema_version += 1,
            "policy_hash" => body.policy_hash = Hash::from_bytes([0xa1u8; 32]),
            "chain_id" => body.chain_id = body.chain_id.wrapping_add(1),
            "tx_hash" => body.tx_hash = Hash::from_bytes([0xa2u8; 32]),
            "payment_block" => body.payment_block = body.payment_block.wrapping_add(1),
            "anchor_block" => body.anchor_block = body.anchor_block.wrapping_add(1),
            "anchor_block_hash" => {
                body.anchor_block_hash = Hash::from_bytes([0xa3u8; 32])
            }
            "asset" => body.asset = format!("0x{}", "cd".repeat(20)),
            "payee" => {
                body.payee =
                    Address::parse("0x0000000000000000000000000000000000000001")
                        .unwrap()
            }
            "amount_raw" => body.amount_raw = body.amount_raw.wrapping_add(1),
            "job_id" => body.job_id.push_str("-other"),
            "payment_intent_id" => body.payment_intent_id.push_str("-other"),
            "verifier_key_id" => {
                body.verifier_key_id =
                    KeyId::derive(KeyRole::VerifierRuntime, &[0xa4u8; 32])
            }
            "settlement_hash" => {
                body.settlement_hash = Hash::from_bytes([0xa5u8; 32])
            }
            _ => return false,
        }
        true
    }
}
