//! P4b: the authenticated external-value receipt, and its integration into the
//! verified read side.
//!
//! # The rule this module exists to enforce
//!
//! ```text
//! VerifiedNev = VerifyChain(DeriveBoundary(VerifyReceiptSig(VerifyPolicy(Evidence))))
//! ```
//!
//! Read outermost last: `VerifyPolicy(Evidence)` — the outcome policy is checked
//! against a pinned trust anchor that lives outside the mutable economy
//! directory (P4a, [`crate::policy_auth`]). `VerifyReceiptSig(...)` — the receipt
//! carries a signature from the one verifier key that policy delegated to.
//! `DeriveBoundary(...)` — the control side of the settlement is re-derived from
//! stored evidence against the operator's registry. `VerifyChain(...)` — the
//! transaction, block and ERC-20 log the evidence cites are re-read from a
//! kernel-identified provider.
//!
//! The signature **adds provenance and a policy binding. It does not substitute
//! for chain confirmation.** A signature says "the delegated verifier said this
//! receipt describes this transfer"; only the chain read says the transfer
//! exists. Collapsing the identity to `signature valid → NEV valid` would be a
//! regression of P3 and is not done anywhere below.
//!
//! # Where the key comes from — the Gland trap one layer down
//!
//! P4a reported the hazard and P4b closes it: `VerifierPublicKey::verifying_key()`
//! used to be `pub`, so a caller could take the key a policy *claims* and verify
//! with it — which is [`mycelium_pheromones::Gland`]'s mistake, one layer down.
//! It is now private to [`crate::policy_auth`], and the only `VerifyingKey` a
//! receipt check can obtain is [`crate::policy_auth::TrustedVerifierKey`], which
//! has exactly one constructor:
//! [`ValidatedOutcomePolicy::trusted_verifier`].
//!
//! Note what [`AuthenticatedExternalValueReceipt::verify`] therefore does *not*
//! have: a parameter for a key. A caller cannot supply the verifier key, cannot
//! offer a [`VerifierPublicKey`] read off an unvalidated policy, and cannot reach
//! the dalek type at all. Holding a [`ValidatedOutcomePolicy`] is the only way in,
//! and holding one is P4a's proof that the policy's authority resolved from the
//! pin.
//!
//! The signing side has the mirror-image check. [`VerifierRuntimeKey::attest`]
//! refuses to sign unless the key signing *is* the key the validated policy
//! delegated to, so a key nobody delegated to cannot mint receipts even if the
//! operator holds it.
//!
//! # What the signature covers
//!
//! Not JSON, and never a serialised struct: [`AttestationBody::signing_preimage`]
//! builds the bytes with the same tagged, length-prefixed, domain-first encoder
//! P4a established ([`crate::policy_auth::push_tagged`]), with its own domain
//! [`EXTERNAL_VALUE_ATTESTATION_DOMAIN`].
//!
//! Two things are worth calling out because they are the parts a naive version
//! gets wrong:
//!
//! * **The signed facts are re-derived, never read back.** The signature covers
//!   the transaction, block, asset, from, to and amount *as they appear in
//!   re-derived boundary evidence*, not as a copy stored next to the signature.
//!   If the wrapper carried those fields and verified against its own copy, the
//!   artefact would be attesting to itself — the `Gland` shape again, one type
//!   over. So `verify` takes the evidence and rebuilds the body from it.
//! * **`receipt_hash` is in the preimage.** The chain facts alone do not bind the
//!   *economics*: a ledger author who holds one genuine signature for a 5 mUSD
//!   receipt could otherwise edit `gross_inflow_musd_micros` and
//!   `net_external_value_musd_micros`, which are ledger numbers, not chain
//!   numbers. The preimage therefore also covers a canonical digest of every
//!   field of the receipt, so a signature is valid for exactly one receipt
//!   content. (The digest deliberately includes the diagnostic
//!   `proof_verified` flag: a record that changed after signing has unknown
//!   provenance.)
//!
//! # What is NOT here
//!
//! * **Policy rotation history.** A receipt carries the `policy_hash` it was
//!   issued under and the view compares it to the hash of the policy running
//!   *now*; a receipt from policy A is therefore never silently re-approved under
//!   policy B, it simply stops matching and is reported unattested. There is no
//!   revocation list, no `policy_version` high-water mark, and no way to accept
//!   a receipt issued under a previous policy. Out of scope, deliberately.
//! * **A signature on `SettlementReceipt`.** This step built the signed wrapper
//!   for external-value receipts only, so RV promotion was bound to a validated
//!   policy plus a kernel-identified chain read and not to a per-settlement
//!   signature — which meant a party who could write the revenue ledger and
//!   produce a *real* transfer of the right size into a controlled address could
//!   book paid demand nobody signed. That is closed by
//!   [`crate::settlement_auth`], the revenue-side mirror of this module, and
//!   nothing in it changes the rules here.
//! * **Any protection against a party who can rewrite the whole economy
//!   directory**, which P4a already documented as out of its threat model.

use crate::{
    autonomy::ExternalValueReceipt,
    boundary::{BoundaryEvidence, SettlementAsset},
    policy_auth::{
        push_tagged, signature_serde, Address, Hash, KeyId, KeyRole, PolicyError,
        PreimageFieldKind, TrustedVerifierKey, ValidatedOutcomePolicy,
        VerifierRuntimeKey,
    },
    EconomyError,
};
use ed25519_dalek::{Signature, Verifier as _};
use serde::{Deserialize, Serialize};

/// Domain string of the receipt attestation preimage. First bytes of every
/// attestation preimage, so a receipt signature can never be replayed as a
/// signature over a policy, a controlled-registry digest, a provider-identity
/// digest or a policy hash.
pub const EXTERNAL_VALUE_ATTESTATION_DOMAIN: &str =
    "MYCELIUM-ECONOMY/EXTERNAL-VALUE/V1";

/// Domain of the canonical receipt digest that the preimage carries.
pub const RECEIPT_HASH_DOMAIN: &str = "MYCELIUM-ECONOMY/EXTERNAL-VALUE-RECEIPT/V1";

/// Schema version this build issues and accepts for attestations.
pub const ATTESTATION_SCHEMA_VERSION: u32 = 1;

/// Attestation ledger file name in the economy root; also the append lock name
/// and the head anchor's ledger identifier.
pub const ATTESTATION_LEDGER_FILE: &str = "receipt-attestations.jsonl";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ReceiptAuthError {
    /// Wraps P4a's vocabulary rather than inventing a parallel one: a policy
    /// that does not validate is a policy error, and the caller reports it as
    /// such.
    #[error(transparent)]
    Policy(#[from] PolicyError),

    #[error(transparent)]
    Economy(#[from] EconomyError),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("attestation preimage is malformed: {0}")]
    Preimage(String),

    #[error("receipt cites transaction {cited}, but the offered evidence describes {described}")]
    ReceiptCitesAnotherTransaction { cited: String, described: String },

    #[error("evidence {field} is not usable in a signed attestation: {reason}")]
    UnusableEvidence { field: &'static str, reason: String },

    #[error("receipt {field} is not usable in a signed attestation: {reason}")]
    UnusableReceipt { field: &'static str, reason: String },

    /// The signing key is not the key the validated policy delegated to.
    #[error(
        "verifier key {key_id} signed this receipt, but the policy delegates to \
         {delegated}; a key no validated policy delegated to cannot attest"
    )]
    SigningKeyNotDelegated { key_id: String, delegated: String },

    /// The receipt claims to be signed by a key the current policy does not
    /// delegate to. This is what an unknown verifier's signature gets.
    #[error("receipt names verifier {claimed}, but the policy delegates to {delegated}")]
    VerifierNotDelegated { claimed: String, delegated: String },

    #[error("attestation signature does not verify against the policy's delegated verifier key")]
    BadSignature,

    #[error("attestation was issued under policy {found}, but the current policy is {current}")]
    PolicyHashMismatch { found: String, current: String },

    #[error("attestation_hash {found} is not the digest of this attestation's signed body ({computed})")]
    AttestationHashMismatch { found: String, computed: String },

    #[error("attestation was issued on chain {found}, but the current policy settles on {expected}")]
    PolicyChainMismatch { found: u64, expected: u64 },
}

// ---------------------------------------------------------------------------
// The canonical receipt digest
// ---------------------------------------------------------------------------

/// Every field of [`ExternalValueReceipt`], in canonical order.
///
/// This is the whole point of the digest: the chain facts in the preimage do not
/// mention the economics, and the economics are what an ARV predicate sums. A
/// digest over every field means one signature is valid for exactly one receipt
/// content, so a valid attestation cannot be re-pointed at an edited amount.
///
/// `value_class` is the one field whose canonical form comes from serde, because
/// it is a closed enum whose wire spelling is already inside the ledger's own
/// record hash: renaming a variant breaks existing ledgers loudly rather than
/// silently re-hashing them.
const RECEIPT_HASH_FIELDS: &[(&str, PreimageFieldKind)] = &[
    ("schema_version", PreimageFieldKind::U32),
    ("source_id", PreimageFieldKind::Text),
    ("agent_id", PreimageFieldKind::Text),
    ("opportunity_id", PreimageFieldKind::Text),
    ("value_class", PreimageFieldKind::Bytes),
    ("network", PreimageFieldKind::Text),
    ("asset", PreimageFieldKind::Text),
    ("gross_inflow_musd_micros", PreimageFieldKind::U64),
    ("external_cost_musd_micros", PreimageFieldKind::U64),
    ("net_external_value_musd_micros", PreimageFieldKind::I64),
    ("proof_hash", PreimageFieldKind::Text),
    ("proof_verified", PreimageFieldKind::Bool),
    ("realized_at_unix", PreimageFieldKind::U64),
    ("verifier_id", PreimageFieldKind::Text),
];

/// Canonical digest of a receipt's whole content, under [`RECEIPT_HASH_DOMAIN`].
///
/// Used twice, for two different jobs that must not be confused:
/// * it is a field of the signed preimage, so a signature cannot be re-pointed;
/// * it is the key the view indexes attestations under, so a mutated ledger
///   receipt simply does not find the attestation that was signed for the
///   original.
pub fn receipt_hash(receipt: &ExternalValueReceipt) -> Result<Hash, ReceiptAuthError> {
    let class = serde_json::to_vec(&receipt.value_class)?;
    let values: Vec<(&str, Vec<u8>)> = vec![
        ("schema_version", receipt.schema_version.to_be_bytes().to_vec()),
        ("source_id", receipt.source_id.as_bytes().to_vec()),
        ("agent_id", receipt.agent_id.as_bytes().to_vec()),
        ("opportunity_id", receipt.opportunity_id.as_bytes().to_vec()),
        ("value_class", class),
        ("network", receipt.network.as_bytes().to_vec()),
        ("asset", receipt.asset.as_bytes().to_vec()),
        ("gross_inflow_musd_micros", receipt.gross_inflow_musd_micros.to_be_bytes().to_vec()),
        ("external_cost_musd_micros", receipt.external_cost_musd_micros.to_be_bytes().to_vec()),
        ("net_external_value_musd_micros", receipt.net_external_value_musd_micros.to_be_bytes().to_vec()),
        ("proof_hash", receipt.proof_hash.as_bytes().to_vec()),
        ("proof_verified", vec![u8::from(receipt.proof_verified)]),
        ("realized_at_unix", receipt.realized_at_unix.to_be_bytes().to_vec()),
        ("verifier_id", receipt.verifier_id.as_bytes().to_vec()),
    ];
    check_layout(&values, RECEIPT_HASH_FIELDS, "receipt digest")?;

    let mut buf = Vec::new();
    push_tagged(&mut buf, b"domain", RECEIPT_HASH_DOMAIN.as_bytes());
    push_tagged(
        &mut buf,
        b"sections",
        &u32::try_from(values.len())
            .map_err(|_| ReceiptAuthError::Preimage("too many receipt fields".into()))?
            .to_be_bytes(),
    );
    for (tag, value) in &values {
        push_tagged(&mut buf, tag.as_bytes(), value);
    }
    Ok(Hash::from_bytes(*blake3::hash(&buf).as_bytes()))
}

/// The encoder and the layout table can disagree in exactly one way that matters
/// — a field renamed on one side and not the other — so it is checked at run
/// time rather than trusted. Same discipline as
/// [`crate::policy_auth::OutcomePolicyPayload::signing_preimage`].
fn check_layout(
    values: &[(&str, Vec<u8>)],
    layout: &[(&str, PreimageFieldKind)],
    what: &str,
) -> Result<(), ReceiptAuthError> {
    if values.len() != layout.len() {
        return Err(ReceiptAuthError::Preimage(format!(
            "{what}: encoder emitted {} sections for a layout of {}",
            values.len(),
            layout.len()
        )));
    }
    for ((tag, _), (expected_tag, _)) in values.iter().zip(layout.iter()) {
        if *tag != *expected_tag {
            return Err(ReceiptAuthError::Preimage(format!(
                "{what}: encoder emitted section {tag:?} where the layout expects {expected_tag:?}"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The signed body
// ---------------------------------------------------------------------------

/// The attestation preimage layout, in canonical order.
///
/// The ten fields the design calls for — `policy_hash`, `chain_id`, `tx_hash`,
/// `block_hash`, `asset`, `from`, `to`, `amount`, `opportunity_id`, `source_id` —
/// are all here, plus three that make the signature mean something:
/// `verifier_key_id` (so a receipt cannot be re-signed under another delegated
/// key), `receipt_hash` (so it cannot be re-pointed at another receipt's
/// economics) and `schema_version` (so a future layout cannot be mistaken for
/// this one).
pub const ATTESTATION_PREIMAGE_FIELDS: &[(&str, PreimageFieldKind)] = &[
    ("schema_version", PreimageFieldKind::U32),
    ("policy_hash", PreimageFieldKind::Hash32),
    ("chain_id", PreimageFieldKind::U64),
    ("tx_hash", PreimageFieldKind::Hash32),
    ("block_hash", PreimageFieldKind::Hash32),
    ("asset", PreimageFieldKind::Text),
    ("from_address", PreimageFieldKind::AddressText),
    ("to_address", PreimageFieldKind::AddressText),
    ("amount_raw", PreimageFieldKind::U64),
    ("opportunity_id", PreimageFieldKind::Text),
    ("source_id", PreimageFieldKind::Text),
    ("verifier_key_id", PreimageFieldKind::KeyId32),
    ("receipt_hash", PreimageFieldKind::Hash32),
];

/// The exact bytes a verifier key signs.
///
/// Built with the same construction as the policy preimage:
///
/// ```text
/// tagged   := TAG_LEN:u32be || TAG || VALUE_LEN:u32be || VALUE
/// preimage := tagged("domain", EXTERNAL_VALUE_ATTESTATION_DOMAIN)
///          || tagged("sections", SECTION_COUNT:u32be)
///          || section*
/// section  := tagged(TAG_i, VALUE_i)   for TAG_i in ATTESTATION_PREIMAGE_FIELDS
/// ```
///
/// Never a serialised struct: signing a self-describing encoding would promote
/// field order, whitespace, number formatting and unknown fields into
/// cryptographic semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationBody {
    pub schema_version: u32,
    pub policy_hash: Hash,
    pub chain_id: u64,
    pub tx_hash: Hash,
    pub block_hash: Hash,
    /// Canonical contract of the identified real asset this receipt moves, from
    /// [`SettlementAsset::classify_symbol`]. The chain travels in its own
    /// section, and the pair is the asset identity this crate uses everywhere
    /// else, so `usdc` and `USDC` cannot be two different signed messages.
    pub asset: String,
    pub from_address: Address,
    pub to_address: Address,
    pub amount_raw: u64,
    pub opportunity_id: String,
    pub source_id: String,
    pub verifier_key_id: KeyId,
    pub receipt_hash: Hash,
}

impl AttestationBody {
    /// Rebuilds the body from a receipt, the evidence it cites and the policy
    /// that is being asked about it.
    ///
    /// `policy_hash` and `verifier_key_id` are *arguments*, not values read off
    /// the current policy, and that is deliberate: the preimage must be
    /// reconstructible from the artefact alone plus re-derived evidence, so that
    /// the signature check answers "is this attestation internally authentic?"
    /// and the separate `policy_hash` comparison answers "is it current?".
    /// Reading both from the policy here would collapse two independent gates
    /// into one and make the second unobservable.
    ///
    /// `chain_id` comes from the evidence, so a receipt issued on another chain
    /// keeps failing the *same* way under any policy.
    pub fn from_parts(
        receipt: &ExternalValueReceipt,
        evidence: &BoundaryEvidence,
        policy_hash: &Hash,
        verifier_key_id: KeyId,
    ) -> Result<Self, ReceiptAuthError> {
        // The evidence is validated with P1's own rules before anything is taken
        // out of it, so a signed attestation can never cover evidence the
        // crossing derivation would have refused (chain/asset disagreement, a
        // zero amount, equal addresses, malformed hashes).
        evidence.validate()?;
        let cited = receipt.proof_hash.to_ascii_lowercase();
        let described = evidence.tx_hash.to_ascii_lowercase();
        if cited != described {
            return Err(ReceiptAuthError::ReceiptCitesAnotherTransaction {
                cited: receipt.proof_hash.clone(),
                described: evidence.tx_hash.clone(),
            });
        }
        if receipt.source_id.trim().is_empty() {
            return Err(ReceiptAuthError::UnusableReceipt {
                field: "source_id",
                reason: "an external-value receipt must name its source".into(),
            });
        }
        if receipt.opportunity_id.trim().is_empty() {
            return Err(ReceiptAuthError::UnusableReceipt {
                field: "opportunity_id",
                reason: "an external-value receipt must name its opportunity".into(),
            });
        }
        // The asset goes through the same classifier P3 uses to justify a
        // receipt's denomination, so a synthetic ledger unit cannot be signed at
        // all, and the signed asset is the *identified* asset rather than
        // whatever spelling the ledger used. `SettlementAsset::symbol()` keeps
        // the exact stored string ("usdc" and "USDC" are two different symbols),
        // so it is not canonical and would make the same asset two different
        // signed messages; the normalised contract is canonical by construction.
        let classified = SettlementAsset::classify_symbol(&receipt.asset).map_err(|e| {
            ReceiptAuthError::UnusableReceipt {
                field: "asset",
                reason: e.to_string(),
            }
        })?;
        let asset = match classified.real_asset() {
            Some(real) => real.clone(),
            None => {
                return Err(ReceiptAuthError::UnusableReceipt {
                    field: "asset",
                    reason: format!(
                        "{} is a synthetic ledger unit and can never be attested",
                        classified.symbol()
                    ),
                })
            }
        };
        if asset != evidence.asset {
            return Err(ReceiptAuthError::UnusableReceipt {
                field: "asset",
                reason: format!(
                    "receipt is denominated in {}/{} while the evidence moved {}/{}",
                    asset.chain_id(),
                    asset.contract(),
                    evidence.asset.chain_id(),
                    evidence.asset.contract()
                ),
            });
        }
        if asset.chain_id() != evidence.chain_id {
            return Err(ReceiptAuthError::UnusableEvidence {
                field: "chain_id",
                reason: format!(
                    "evidence chain {} does not match its asset's chain {}",
                    evidence.chain_id,
                    asset.chain_id()
                ),
            });
        }
        Ok(Self {
            schema_version: ATTESTATION_SCHEMA_VERSION,
            policy_hash: policy_hash.clone(),
            chain_id: evidence.chain_id,
            tx_hash: Hash::parse("tx_hash", &evidence.tx_hash)?,
            block_hash: Hash::parse("block_hash", &evidence.block_hash)?,
            asset: asset.contract().to_string(),
            from_address: Address::parse(&evidence.from_address)?,
            to_address: Address::parse(&evidence.to_address)?,
            amount_raw: evidence.amount_raw,
            opportunity_id: receipt.opportunity_id.clone(),
            source_id: receipt.source_id.clone(),
            verifier_key_id,
            receipt_hash: receipt_hash(receipt)?,
        })
    }

    pub fn signing_preimage(&self) -> Result<Vec<u8>, ReceiptAuthError> {
        let policy_hash = self.policy_hash.to_bytes()?;
        let tx_hash = self.tx_hash.to_bytes()?;
        let block_hash = self.block_hash.to_bytes()?;
        let verifier_key_id = *self.verifier_key_id.as_bytes();
        let receipt_hash = self.receipt_hash.to_bytes()?;
        let values: Vec<(&str, Vec<u8>)> = vec![
            ("schema_version", self.schema_version.to_be_bytes().to_vec()),
            ("policy_hash", policy_hash.to_vec()),
            ("chain_id", self.chain_id.to_be_bytes().to_vec()),
            ("tx_hash", tx_hash.to_vec()),
            ("block_hash", block_hash.to_vec()),
            ("asset", self.asset.as_bytes().to_vec()),
            ("from_address", self.from_address.as_str().as_bytes().to_vec()),
            ("to_address", self.to_address.as_str().as_bytes().to_vec()),
            ("amount_raw", self.amount_raw.to_be_bytes().to_vec()),
            ("opportunity_id", self.opportunity_id.as_bytes().to_vec()),
            ("source_id", self.source_id.as_bytes().to_vec()),
            ("verifier_key_id", verifier_key_id.to_vec()),
            ("receipt_hash", receipt_hash.to_vec()),
        ];
        check_layout(&values, ATTESTATION_PREIMAGE_FIELDS, "attestation preimage")?;

        let mut buf = Vec::new();
        push_tagged(
            &mut buf,
            b"domain",
            EXTERNAL_VALUE_ATTESTATION_DOMAIN.as_bytes(),
        );
        push_tagged(
            &mut buf,
            b"sections",
            &u32::try_from(values.len())
                .map_err(|_| {
                    ReceiptAuthError::Preimage("too many attestation sections".into())
                })?
                .to_be_bytes(),
        );
        for (tag, value) in &values {
            push_tagged(&mut buf, tag.as_bytes(), value);
        }
        Ok(buf)
    }

    /// Digest of the preimage. This is what `attestation_hash` carries, and it
    /// is an audit handle over the signed body — never an authority input on its
    /// own, and recomputed and compared at verification time.
    pub fn attestation_hash(&self) -> Result<Hash, ReceiptAuthError> {
        let preimage = self.signing_preimage()?;
        Ok(Hash::from_bytes(*blake3::hash(&preimage).as_bytes()))
    }
}

// ---------------------------------------------------------------------------
// The wrapper
// ---------------------------------------------------------------------------

/// An external-value receipt plus the verifier's signature over it.
///
/// Private fields and exactly one constructor, [`VerifierRuntimeKey::attest`],
/// which requires a [`ValidatedOutcomePolicy`]. `Deserialize` exists so the
/// wrapper survives a round trip through the attestation ledger, and it is not a
/// trust input: a decoded wrapper is a claim until `verify` says otherwise, and
/// `verify` needs a validated policy to exist at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedExternalValueReceipt {
    receipt: ExternalValueReceipt,
    policy_hash: Hash,
    verifier_key_id: KeyId,
    attestation_hash: Hash,
    #[serde(with = "signature_serde")]
    signature: Signature,
}

impl AuthenticatedExternalValueReceipt {
    pub fn receipt(&self) -> &ExternalValueReceipt {
        &self.receipt
    }

    /// The policy this receipt was issued under. Compared against
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
    /// embedded receipt, never read out of the record.
    pub fn receipt_hash(&self) -> Result<Hash, ReceiptAuthError> {
        receipt_hash(&self.receipt)
    }

    /// Reconstructs the body this attestation *would* be over, for diagnostics
    /// and for the view's reporting. Never returns a key and never authorises
    /// anything.
    pub fn body(
        &self,
        evidence: &BoundaryEvidence,
    ) -> Result<AttestationBody, ReceiptAuthError> {
        AttestationBody::from_parts(
            &self.receipt,
            evidence,
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
    ///    current policy delegates to. A receipt signed by an unknown verifier
    ///    stops here, before any signature maths.
    /// 2. **signature valid** — over the preimage rebuilt from *re-derived
    ///    evidence*, never from a copy stored beside the signature.
    /// 3. **policy_hash matches** — the receipt was issued under the policy in
    ///    force now. A receipt from policy A is refused under policy B.
    /// 4. two consistency assertions: the attestation's own digest handle, and
    ///    the chain the policy settles on.
    ///
    /// Note that steps 1-3 say nothing about whether the transfer happened.
    /// Only the view's chain read, which runs after `DeriveBoundary`, can say
    /// that.
    pub fn verify(
        &self,
        policy: &ValidatedOutcomePolicy,
        evidence: &BoundaryEvidence,
    ) -> Result<VerifiedAttestation, ReceiptAuthError> {
        // (1) The verifier has to be one this policy delegated to.
        let trusted: TrustedVerifierKey = policy.trusted_verifier();
        if self.verifier_key_id != trusted.key_id() {
            return Err(ReceiptAuthError::VerifierNotDelegated {
                claimed: self.verifier_key_id.to_string(),
                delegated: trusted.key_id().to_string(),
            });
        }
        // Gate 1 is also an internal consistency check: the id has to be the
        // identity of the key it names, in the verifier-runtime role. P4a makes
        // the same check on a policy; a hand-built wrapper skips both.
        if self.verifier_key_id.role() != KeyRole::VerifierRuntime {
            return Err(ReceiptAuthError::VerifierNotDelegated {
                claimed: self.verifier_key_id.to_string(),
                delegated: trusted.key_id().to_string(),
            });
        }
        let body = self.body(evidence)?;
        if body.schema_version != ATTESTATION_SCHEMA_VERSION {
            return Err(ReceiptAuthError::Preimage(format!(
                "attestation schema_version {} is not supported (expected {})",
                body.schema_version, ATTESTATION_SCHEMA_VERSION
            )));
        }
        let preimage = body.signing_preimage()?;

        // (2) The signature, against the key the validated policy delegated to.
        trusted.verifying_key()?.verify(&preimage, &self.signature).map_err(
            |_| ReceiptAuthError::BadSignature,
        )?;

        // (3) The policy binding. The signature already covers `policy_hash`, so
        // this cannot be skipped by editing the field — but it is a *different*
        // question: not "is this attestation authentic?" but "is it current?",
        // and collapsing the two is how a rotated policy silently re-approves
        // old receipts. Policy-rotation history is out of scope: nothing here
        // accepts a receipt issued under a previous policy.
        let current = policy.policy_hash()?;
        if self.policy_hash != current {
            return Err(ReceiptAuthError::PolicyHashMismatch {
                found: self.policy_hash.to_string(),
                current: current.to_string(),
            });
        }

        // Consistency assertions, after the authority gates.
        let computed = body.attestation_hash()?;
        if self.attestation_hash != computed {
            return Err(ReceiptAuthError::AttestationHashMismatch {
                found: self.attestation_hash.to_string(),
                computed: computed.to_string(),
            });
        }
        if evidence.chain_id != policy.chain_id() {
            return Err(ReceiptAuthError::PolicyChainMismatch {
                found: evidence.chain_id,
                expected: policy.chain_id(),
            });
        }
        Ok(VerifiedAttestation {
            attestation_hash: self.attestation_hash.clone(),
            policy_hash: self.policy_hash.clone(),
            verifier_key_id: self.verifier_key_id,
            receipt_hash: self.receipt_hash()?,
        })
    }
}

/// What a successful [`AuthenticatedExternalValueReceipt::verify`] establishes.
///
/// A receipt of provenance, not of money: it says the delegated verifier signed
/// this receipt against this evidence under this policy. The view still has to
/// re-read the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub attestation_hash: Hash,
    pub policy_hash: Hash,
    pub verifier_key_id: KeyId,
    pub receipt_hash: Hash,
}

impl VerifierRuntimeKey {
    /// Signs a receipt against the evidence it cites.
    ///
    /// The only constructor of an [`AuthenticatedExternalValueReceipt`], and it
    /// requires a validated policy for a reason that has nothing to do with
    /// signatures: a key that no validated policy delegated to must not be able
    /// to mint attestations, or "signed by a key some policy delegated to"
    /// would be a statement with no referent.
    ///
    /// The evidence is the verifier's own chain read. It is validated here, not
    /// merely carried, so an operator holding this key cannot sign a body over
    /// evidence the boundary derivation would refuse.
    pub fn attest(
        &self,
        policy: &ValidatedOutcomePolicy,
        receipt: &ExternalValueReceipt,
        evidence: &BoundaryEvidence,
    ) -> Result<AuthenticatedExternalValueReceipt, ReceiptAuthError> {
        let trusted = policy.trusted_verifier();
        if self.key_id() != trusted.key_id() {
            return Err(ReceiptAuthError::SigningKeyNotDelegated {
                key_id: self.key_id().to_string(),
                delegated: trusted.key_id().to_string(),
            });
        }
        let policy_hash = policy.policy_hash()?;
        let body =
            AttestationBody::from_parts(receipt, evidence, &policy_hash, self.key_id())?;
        let preimage = body.signing_preimage()?;
        let attestation_hash = body.attestation_hash()?;
        Ok(AuthenticatedExternalValueReceipt {
            receipt: receipt.clone(),
            policy_hash,
            verifier_key_id: self.key_id(),
            attestation_hash,
            signature: self.sign_preimage(&preimage),
        })
    }
}

/// A whole authority, assembled in one place, for the tests across this crate.
///
/// Three test modules need the same thing — a pinned trust anchor, an authority
/// key, a delegated verifier key, a registry and a provider identity — and a
/// copy of it per module would be three places to keep the same invariants in
/// step. Lives here because this is the module that defines what "a validated
pub mod testkit {
    use super::*;
    use crate::{
        base_usdc::BASE_CHAIN_ID,
        boundary::{ControlledAddressRegistry, RealAsset},
        chain_provider::PinnedChainProvider,
        policy_auth::{
            controlled_registry_hash, OutcomePolicyPayload,
            PolicyAuthorityKey, PolicyExpectations, PinnedTrustStore,
            ProviderIdentityConstraints, SignedOutcomePolicy, TrustStoreConfig,
            OUTCOME_POLICY_SCHEMA_VERSION,
        },
    };
    use std::{os::unix::fs::MetadataExt as _, path::Path};

    pub const EXECUTOR_HEX: &str = "0x1111111111111111111111111111111111111111";

    pub struct AuthFixture {
        /// Keeps the pin's temporary directory alive for as long as the fixture.
        _dir: tempfile::TempDir,
        pub config: TrustStoreConfig,
        pub authority: PolicyAuthorityKey,
        pub verifier: VerifierRuntimeKey,
        pub registry: ControlledAddressRegistry,
        pub provider: ProviderIdentityConstraints,
        policy: SignedOutcomePolicy,
    }

    fn current_uid() -> u32 {
        std::fs::metadata("/proc/self").unwrap().uid()
    }

    impl AuthFixture {
        /// Builds an authority scoped to a *real* socket: the provider identity
        /// digest is part of the signed payload, so a fixture whose constraints
        /// do not describe the socket the test will pin could never validate.
        pub fn new(
            socket: &Path,
            socket_uid: u32,
            registry: ControlledAddressRegistry,
        ) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let config = TrustStoreConfig::with_pin_path(
                dir.path().join("trust").join("authority.pub"),
            )
            .with_expected_owner_uid(current_uid());
            let authority = PolicyAuthorityKey::generate();
            PinnedTrustStore::install(&config, &authority).unwrap();
            let pin = PinnedChainProvider::unix_socket(socket, Some(socket_uid))
                .expect("unix socket pin");
            let provider = ProviderIdentityConstraints::from_pinned_provider(&pin);
            let verifier = VerifierRuntimeKey::generate();
            let payload = OutcomePolicyPayload {
                schema_version: OUTCOME_POLICY_SCHEMA_VERSION,
                policy_version: 3,
                chain_id: BASE_CHAIN_ID,
                executor: Address::parse(EXECUTOR_HEX).unwrap(),
                min_confirmations: 12,
                controlled_registry_hash: controlled_registry_hash(&registry)
                    .unwrap(),
                provider_identity_hash: provider.identity_hash(),
                // P4.6. The receipt side has no opinion about prices, but the
                // *policy* it is signed under must authorise one: a policy with
                // no permitted price source is refused at validation, so this
                // fixture — which is the crate's canonical policy — carries the
                // shared canonical binding. `the_receipt_side_and_the_price_side
                // _share_one_authority` is what proves the two halves are bound
                // to the same key and the same policy.
                price_source_hash: crate::trusted_valuation::testkit::canonical_hash(
                    BASE_CHAIN_ID,
                ),
                verifier_key_id: verifier.key_id(),
                verifier_public_key: verifier.public_key(),
                created_at_unix: 1_700_000_000,
            };
            let policy = authority.sign(payload, &verifier).unwrap();
            Self {
                _dir: dir,
                config,
                authority,
                verifier,
                registry,
                provider,
                policy,
            }
        }

        /// Re-reads the pin and re-validates, the way a process that has just
        /// started would. Cheap enough to call per test and it keeps every
        /// assertion honest about going through the anchor.
        pub fn validated(&self) -> ValidatedOutcomePolicy {
            let trust = PinnedTrustStore::load(self.config.clone()).unwrap();
            validate_policy(&self.policy, &trust, &self.registry, &self.provider)
        }

        /// The signed document, for tests that need to check what an unvalidated
        /// policy looks like on the wire.
        pub fn signed(&self) -> SignedOutcomePolicy {
            self.policy.clone()
        }

        /// Re-signs a different payload version over the *same* anchor, registry
        /// and provider: a rotated policy.
        ///
        /// Returned separately rather than as a second `AuthFixture` because the
        /// pin's temporary directory cannot be shared by two owners, and a test
        /// needs both policies alive at once — one that issued the receipt and
        /// one it is read back under.
        pub fn rotated(&self, policy_version: u64) -> AlternatePolicy {
            let mut payload = self.policy.payload.clone();
            payload.policy_version = policy_version;
            self.alternate(payload, self.verifier.clone())
        }

        /// The same anchor, registry and provider, delegating to a *different*
        /// verifier key. The shape of "an unknown verifier signed this".
        pub fn with_other_verifier(&self) -> AlternatePolicy {
            let verifier = VerifierRuntimeKey::generate();
            let mut payload = self.policy.payload.clone();
            payload.verifier_key_id = verifier.key_id();
            payload.verifier_public_key = verifier.public_key();
            self.alternate(payload, verifier)
        }

        /// Signs `payload` with `verifier`, which must be the key the payload
        /// names — P4a's `PolicyAuthorityKey::sign` refuses otherwise, and that
        /// refusal is itself part of what is being relied on here.
        fn alternate(
            &self,
            payload: OutcomePolicyPayload,
            verifier: VerifierRuntimeKey,
        ) -> AlternatePolicy {
            AlternatePolicy {
                signed: self.authority.sign(payload, &verifier).unwrap(),
                verifier,
                config: self.config.clone(),
                registry: self.registry.clone(),
                provider: self.provider.clone(),
            }
        }

        /// Signs with a key the policy does **not** delegate to.
        ///
        /// The test-only counterpart to [`VerifierRuntimeKey::attest`], which
        /// refuses exactly this. It exists so the read side can be handed the
        /// shape of an attack — a cryptographically perfect signature from an
        /// unauthorised key — instead of having to assert that such an artefact
        /// is impossible to build. Every caller must also prove the signature is
        /// genuinely valid, or the resulting test would pass for the wrong
        /// reason; see
        /// `the_combined_attack_cannot_promote` in `verified_view.rs`.
        pub fn forge_with(
            key: &VerifierRuntimeKey,
            policy: &ValidatedOutcomePolicy,
            receipt: &ExternalValueReceipt,
            evidence: &BoundaryEvidence,
        ) -> AuthenticatedExternalValueReceipt {
            let policy_hash = policy.policy_hash().unwrap();
            let body = AttestationBody::from_parts(
                receipt,
                evidence,
                &policy_hash,
                key.key_id(),
            )
            .unwrap();
            let preimage = body.signing_preimage().unwrap();
            AuthenticatedExternalValueReceipt {
                receipt: receipt.clone(),
                policy_hash,
                verifier_key_id: key.key_id(),
                attestation_hash: body.attestation_hash().unwrap(),
                signature: key.sign_preimage(&preimage),
            }
        }

        /// Signs `receipt` over `evidence` with the delegated key.
        pub fn attest(
            &self,
            policy: &ValidatedOutcomePolicy,
            receipt: &ExternalValueReceipt,
            evidence: &BoundaryEvidence,
        ) -> AuthenticatedExternalValueReceipt {
            self.verifier.attest(policy, receipt, evidence).unwrap()
        }
    }

    /// A second policy over the same pin. See [`AuthFixture::rotated`].
    pub struct AlternatePolicy {
        pub signed: SignedOutcomePolicy,
        pub verifier: VerifierRuntimeKey,
        config: TrustStoreConfig,
        registry: ControlledAddressRegistry,
        provider: ProviderIdentityConstraints,
    }

    impl AlternatePolicy {
        /// Goes through the pin again, exactly as a running process would.
        pub fn validate(&self) -> Result<ValidatedOutcomePolicy, PolicyError> {
            let trust = PinnedTrustStore::load(self.config.clone())?;
            crate::policy_auth::validate_outcome_policy(
                &self.signed,
                &trust,
                PolicyExpectations {
                    chain_id: BASE_CHAIN_ID,
                    registry: &self.registry,
                    provider: &self.provider,
                },
            )
        }

    }

    fn validate_policy(
        signed: &SignedOutcomePolicy,
        trust: &PinnedTrustStore,
        registry: &ControlledAddressRegistry,
        provider: &ProviderIdentityConstraints,
    ) -> ValidatedOutcomePolicy {
        crate::policy_auth::validate_outcome_policy(
            signed,
            trust,
            PolicyExpectations {
                chain_id: BASE_CHAIN_ID,
                registry,
                provider,
            },
        )
        .unwrap()
    }

    /// The standard transfer every fixture in this crate moves: an external
    /// counterparty paying a controlled address.
    pub fn evidence(from: &str, to: &str, amount_raw: u64) -> BoundaryEvidence {
        BoundaryEvidence {
            chain_id: BASE_CHAIN_ID,
            asset: RealAsset::base_usdc(),
            from_address: from.into(),
            to_address: to.into(),
            amount_raw,
            tx_hash: format!("0x{}", "11".repeat(32)),
            block_hash: format!("0x{}", "22".repeat(32)),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::testkit::{evidence, AuthFixture};
    use super::*;
    use crate::{
        autonomy::{ExternalValueClass, ExternalValueReceipt},
        base_usdc::BASE_CHAIN_ID,
        boundary::RealAsset,
        policy_auth::{KeyRole, VerifierPublicKey},
    };
    use std::fs;

    const COUNTERPARTY: &str = "0x1234567890abcdef1234567890abcdef12345678";
    const PAYOUT: &str = "0xe83331104f5f3c41e49abc46c810f9d71133e48c";
    const AMOUNT: u64 = 5_000_000;

    /// A socket that is never actually talked to. The fixture needs a real path
    /// with a real owner uid because the provider identity digest is inside the
    /// signed policy, and this module is about the signature rather than the
    /// chain read — but the socket has to be a genuine one so the policy it
    /// validates is a genuine policy.
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

    fn receipt() -> ExternalValueReceipt {
        ExternalValueReceipt {
            schema_version: crate::SCHEMA_VERSION,
            source_id: "source-1".into(),
            agent_id: "s1-arb-01".into(),
            opportunity_id: "opp-1".into(),
            value_class: ExternalValueClass::ExternalTradingPnl,
            network: "base".into(),
            asset: "USDC".into(),
            gross_inflow_musd_micros: 6_000_000,
            external_cost_musd_micros: 1_000_000,
            net_external_value_musd_micros: 5_000_000,
            proof_hash: format!("0x{}", "11".repeat(32)),
            proof_verified: true,
            realized_at_unix: 1_700_000_400,
            verifier_id: "base-reconcile".into(),
        }
    }

    fn tx() -> BoundaryEvidence {
        evidence(COUNTERPARTY, PAYOUT, AMOUNT)
    }

    // ------------------------------------------------------------------
    // 1. the happy path, end to end through the type
    // ------------------------------------------------------------------

    #[test]
    fn a_valid_attestation_verifies_under_the_policy_that_issued_it() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let attestation = auth.attest(&policy, &receipt(), &tx());

        assert_eq!(attestation.verifier_key_id(), auth.verifier.key_id());
        assert_eq!(
            attestation.policy_hash(),
            &policy.policy_hash().unwrap(),
            "the receipt carries the policy it was issued under"
        );
        assert_eq!(
            attestation.attestation_hash(),
            &attestation.body(&tx()).unwrap().attestation_hash().unwrap()
        );
        let verified = attestation.verify(&policy, &tx()).unwrap();
        assert_eq!(verified.policy_hash, *attestation.policy_hash());
        assert_eq!(verified.verifier_key_id, auth.verifier.key_id());
        assert_eq!(
            verified.receipt_hash,
            attestation.receipt_hash().unwrap()
        );

        // And it survives a round trip through the wire, which is how it is
        // stored. A decoded attestation is a claim; `verify` is what makes it
        // anything, and it works identically on the decoded copy.
        let bytes = serde_json::to_vec(&attestation).unwrap();
        let decoded: AuthenticatedExternalValueReceipt =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            decoded.verify(&policy, &tx()).unwrap().attestation_hash,
            verified.attestation_hash
        );
    }

    // ------------------------------------------------------------------
    // 2. the verifier has to be one a policy delegated to
    // ------------------------------------------------------------------

    #[test]
    fn a_receipt_signed_by_an_unknown_verifier_is_refused() {
        // `other` is a second policy over the same anchor that delegates to a
        // different verifier key. That key produces a genuine attestation over
        // the current policy's hash, so the signature maths is perfect and the
        // only thing wrong is the delegation.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let other = auth.with_other_verifier();
        let impostor = other.verifier.clone();
        assert_ne!(
            impostor.key_id(),
            policy.trusted_verifier().key_id(),
            "the two policies must delegate to different keys"
        );

        let forged = AuthenticatedExternalValueReceipt {
            receipt: receipt(),
            policy_hash: policy.policy_hash().unwrap(),
            verifier_key_id: impostor.key_id(),
            attestation_hash: Hash::from_bytes([0u8; 32]),
            signature: [0u8; 64].into(),
        };
        let mut forged = forged;
        // Sign it properly: over a body built for this key and this policy hash.
        let body = AttestationBody::from_parts(
            &forged.receipt,
            &tx(),
            &forged.policy_hash,
            impostor.key_id(),
        )
        .unwrap();
        let preimage = body.signing_preimage().unwrap();
        forged.attestation_hash = body.attestation_hash().unwrap();
        forged.signature = impostor.sign_preimage(&preimage);

        // Control, first: this key signs perfectly good attestations when a
        // policy delegates to it. So the refusal below is about the delegation,
        // not about the bytes or the signature.
        let other_policy = other.validate().unwrap();
        assert_eq!(
            other_policy.trusted_verifier().key_id(),
            impostor.key_id()
        );
        let genuine = impostor
            .attest(&other_policy, &receipt(), &tx())
            .unwrap();
        assert!(
            genuine.verify(&other_policy, &tx()).is_ok(),
            "control: this key's signatures are genuine under its own policy"
        );

        // Under the policy in force, it is refused — and refused on the
        // distribution check, before any signature maths.
        let err = forged.verify(&policy, &tx()).unwrap_err();
        assert!(
            matches!(err, ReceiptAuthError::VerifierNotDelegated { .. }),
            "an unknown verifier must be refused on the distribution check, got {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains(&impostor.key_id().to_string()), "{msg}");
        assert!(msg.contains(&auth.verifier.key_id().to_string()), "{msg}");
    }

    #[test]
    fn a_key_no_validated_policy_delegated_to_cannot_sign() {
        // The signing-side half of the layer-down trap: holding a verifier key
        // is not authority. `attest` refuses unless the key signing *is* the key
        // the policy delegated to.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let impostor = VerifierRuntimeKey::generate();
        let err = impostor
            .attest(&policy, &receipt(), &tx())
            .unwrap_err();
        assert!(
            matches!(err, ReceiptAuthError::SigningKeyNotDelegated { .. }),
            "a key the policy does not delegate to must not mint attestations, got {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains(&impostor.key_id().to_string()), "{msg}");
        assert!(msg.contains(&auth.verifier.key_id().to_string()), "{msg}");
    }

    #[test]
    fn the_verifying_key_is_not_reachable_outside_a_validated_policy() {
        // The compile-time half of the Gland trap, pinned the way this crate
        // pins type identity: by asserting the property that is observable.
        //
        // `VerifierPublicKey::verifying_key` is private to `policy_auth`, so the
        // only `VerifyingKey` reachable from here is the one on
        // `TrustedVerifierKey`, and a `TrustedVerifierKey` has exactly one
        // constructor: `ValidatedOutcomePolicy::trusted_verifier`. What is
        // asserted is that this really is the only route *behaviourally* — the
        // public key bytes can be extracted from a policy in a dozen ways and
        // none of them can produce anything that verifies a receipt.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();

        // Every public route to the bytes.
        let from_policy = policy.verifier_public_key();
        let from_trusted = policy.trusted_verifier().public_key().clone();
        let from_signer = auth.verifier.public_key();
        let rebuilt = VerifierPublicKey::from_bytes(*from_policy.as_bytes());
        assert_eq!(rebuilt.as_bytes(), from_trusted.as_bytes());
        assert_eq!(rebuilt.as_bytes(), from_signer.as_bytes());
        assert_eq!(rebuilt.key_id(), policy.trusted_verifier().key_id());

        // And a receipt is still only verifiable through a validated policy.
        let attestation = auth.attest(&policy, &receipt(), &tx());
        assert!(attestation.verify(&policy, &tx()).is_ok());
        // The attestation names a key id; a hand-built wrapper claiming a
        // different key id for the same bytes is refused, because the id is
        // derived from the key *in the verifier-runtime role* and compared
        // against the policy's own claim.
        let mut relabelled = attestation.clone();
        relabelled.verifier_key_id =
            KeyId::derive(KeyRole::PolicyAuthority, from_policy.as_bytes());
        let err = relabelled.verify(&policy, &tx()).unwrap_err();
        assert!(
            matches!(err, ReceiptAuthError::VerifierNotDelegated { .. }),
            "a key id in the authority role must not satisfy a verifier delegation, got {err}"
        );
    }

    // ------------------------------------------------------------------
    // 3. the policy binding
    // ------------------------------------------------------------------

    #[test]
    fn a_receipt_issued_under_a_previous_policy_is_refused() {
        // Rotation history is out of scope, so this is the whole of it: the
        // receipt keeps the `policy_hash` it was issued under, the view compares
        // it against the policy in force, and a mismatch fails closed.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let old = auth.validated();
        let attestation = auth.attest(&old, &receipt(), &tx());
        assert!(attestation.verify(&old, &tx()).is_ok());

        // A new policy, same anchor, same registry, same provider, one version
        // later.
        let rotated = auth.rotated(old.policy_version() + 1).validate().unwrap();
        assert_eq!(rotated.policy_version(), old.policy_version() + 1);
        assert_ne!(
            rotated.policy_hash().unwrap(),
            old.policy_hash().unwrap(),
            "two policies must not share a hash, or the binding means nothing"
        );
        let err = attestation.verify(&rotated, &tx()).unwrap_err();
        assert!(
            matches!(err, ReceiptAuthError::PolicyHashMismatch { .. }),
            "a receipt from policy A must not be re-approved under policy B, got {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains(&attestation.policy_hash().to_string()), "{msg}");
        assert!(
            msg.contains(&rotated.policy_hash().unwrap().to_string()),
            "{msg}"
        );
        assert!(
            msg.contains(&old.policy_hash().unwrap().to_string()),
            "{msg}"
        );

        // And the receipt itself still verifies under its own policy: nothing
        // was invalidated, it simply is not current.
        assert!(attestation.verify(&old, &tx()).is_ok());
    }

    #[test]
    fn the_policy_hash_is_a_digest_of_the_bytes_the_authority_signed() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        // Reproduced from scratch, the way a second implementation would.
        let mut buf = Vec::new();
        push_tagged(
            &mut buf,
            b"domain",
            crate::policy_auth::POLICY_HASH_DOMAIN.as_bytes(),
        );
        push_tagged(
            &mut buf,
            b"policy",
            &auth.signed().payload.signing_preimage().unwrap(),
        );
        assert_eq!(
            policy.policy_hash().unwrap(),
            Hash::from_bytes(*blake3::hash(&buf).as_bytes())
        );
        // Same anchor, same payload, same hash: it is a function of the signed
        // bytes and nothing else.
        assert_eq!(
            auth.validated().policy_hash().unwrap(),
            policy.policy_hash().unwrap()
        );
    }

    // ------------------------------------------------------------------
    // 4. the preimage
    // ------------------------------------------------------------------

    #[test]
    fn the_preimage_is_bytes_not_json_and_is_domain_separated() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let receipt = receipt();
        let evidence = tx();
        let body = attestation_body(&policy, &receipt, &evidence);
        let preimage = body.signing_preimage().unwrap();

        // Not a serialised struct. The transaction hash appears as raw bytes,
        // and its hex spelling appears nowhere.
        let tx_bytes = body.tx_hash.to_bytes().unwrap();
        assert!(
            preimage.windows(32).any(|w| w == tx_bytes),
            "the preimage must carry the raw digest bytes"
        );
        let hex = format!("0x{}", "11".repeat(32));
        assert!(
            !preimage.windows(hex.len()).any(|w| w == hex.as_bytes()),
            "the preimage must not carry the hex spelling, or the encoding is a display format"
        );
        assert_ne!(
            serde_json::to_vec(&body).unwrap(),
            preimage,
            "a signed struct encoding would make field order and whitespace \
             cryptographic semantics"
        );

        // Domain-separated: the same sections under a different domain are
        // different bytes, so the signature cannot be replayed as a signature
        // over anything else this crate signs.
        let mut other = Vec::new();
        push_tagged(&mut other, b"domain", b"MYCELIUM-ECONOMY/SOMETHING-ELSE/V1");
        for (tag, _) in ATTESTATION_PREIMAGE_FIELDS {
            push_tagged(&mut other, tag.as_bytes(), &section_bytes(&body, tag));
        }
        assert_ne!(other, preimage);

        // Stable: the same inputs produce the same bytes, byte for byte.
        assert_eq!(
            body.signing_preimage().unwrap(),
            preimage,
            "the preimage must be deterministic"
        );
        assert_eq!(
            AttestationBody::from_parts(
                &receipt,
                &evidence,
                &policy.policy_hash().unwrap(),
                auth.verifier.key_id()
            )
            .unwrap()
            .signing_preimage()
            .unwrap(),
            preimage
        );

        // Length-prefixed, so a value cannot be shifted between two sections.
        // `asset` and `from_address` are both text; concatenating them is a
        // different byte string from tagging them.
        let mut shifted = Vec::new();
        push_tagged(&mut shifted, b"domain", EXTERNAL_VALUE_ATTESTATION_DOMAIN.as_bytes());
        push_tagged(&mut shifted, b"sections", &2u32.to_be_bytes());
        push_tagged(
            &mut shifted,
            b"asset",
            format!(
                "{}{}",
                body.asset,
                body.from_address.as_str().trim_start_matches("0x")
            )
            .as_bytes(),
        );
        assert!(!preimage
            .windows(shifted.len())
            .any(|w| w == shifted.as_slice()));
    }

    #[test]
    fn swapping_two_sections_changes_the_preimage() {
        // Field order is part of what was signed. If it were not, two different
        // field assignments could share one signature.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let body = attestation_body(&policy, &receipt(), &tx());

        let ordered = |order: &[&str]| -> Vec<u8> {
            let mut buf = Vec::new();
            push_tagged(
                &mut buf,
                b"domain",
                EXTERNAL_VALUE_ATTESTATION_DOMAIN.as_bytes(),
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
        let tags: Vec<&str> = ATTESTATION_PREIMAGE_FIELDS
            .iter()
            .map(|(tag, _)| *tag)
            .collect();
        assert_eq!(ordered(&tags), body.signing_preimage().unwrap());

        let mut swapped = tags.clone();
        swapped.swap(2, 3);
        assert_ne!(
            ordered(&swapped),
            body.signing_preimage().unwrap(),
            "a different section order must be a different message"
        );
        let mut rotated = tags.clone();
        rotated.rotate_left(1);
        assert_ne!(ordered(&rotated), body.signing_preimage().unwrap());
    }

    #[test]
    fn mutating_any_signed_field_invalidates_the_signature() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let attestation = auth.attest(&policy, &receipt(), &tx());
        let body = attestation.body(&tx()).unwrap();
        let preimage = body.signing_preimage().unwrap();
        let verifying = policy.trusted_verifier().verifying_key().unwrap();
        assert!(verifying
            .verify(&preimage, attestation.signature())
            .is_ok());

        let mut mutated_any = false;
        for (tag, _) in ATTESTATION_PREIMAGE_FIELDS {
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
    fn mutating_the_receipt_after_signing_invalidates_it() {
        // The economics are ledger numbers, not chain numbers, so they are only
        // covered because `receipt_hash` is in the preimage. This is the test
        // that says so.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let original = receipt();
        let attestation = auth.attest(&policy, &original, &tx());
        assert!(attestation.verify(&policy, &tx()).is_ok());

        // Edit the receipt on disk, keep the signature.
        for (label, edit) in [
            ("gross inflow", Box::new(|r: &mut ExternalValueReceipt| {
                r.gross_inflow_musd_micros += 100_000_000;
                r.net_external_value_musd_micros += 100_000_000;
            }) as Box<dyn Fn(&mut ExternalValueReceipt)>),
            ("net value", Box::new(|r: &mut ExternalValueReceipt| {
                r.net_external_value_musd_micros = 500_000_000;
            })),
            ("external cost", Box::new(|r: &mut ExternalValueReceipt| {
                r.external_cost_musd_micros = 0;
                r.net_external_value_musd_micros = 6_000_000;
            })),
            ("value class", Box::new(|r: &mut ExternalValueReceipt| {
                r.value_class = ExternalValueClass::ExternalProtocolFee;
            })),
            ("asset", Box::new(|r: &mut ExternalValueReceipt| {
                r.asset = "usdc".into();
            })),
            ("network", Box::new(|r: &mut ExternalValueReceipt| {
                r.network = "ethereum".into();
            })),
            ("agent", Box::new(|r: &mut ExternalValueReceipt| {
                r.agent_id = "s1-arb-02".into();
            })),
            ("source", Box::new(|r: &mut ExternalValueReceipt| {
                r.source_id = "source-2".into();
            })),
            ("opportunity", Box::new(|r: &mut ExternalValueReceipt| {
                r.opportunity_id = "opp-2".into();
            })),
            ("stored flag", Box::new(|r: &mut ExternalValueReceipt| {
                r.proof_verified = false;
            })),
            ("cited transaction", Box::new(|r: &mut ExternalValueReceipt| {
                r.proof_hash = format!("0x{}", "cc".repeat(32));
            })),
            ("verifier label", Box::new(|r: &mut ExternalValueReceipt| {
                r.verifier_id = "someone-else".into();
            })),
            ("realised at", Box::new(|r: &mut ExternalValueReceipt| {
                r.realized_at_unix = 1_700_000_401;
            })),
        ] {
            let mut edited = original.clone();
            edit(&mut edited);
            assert_ne!(
                receipt_hash(&edited).unwrap(),
                receipt_hash(&original).unwrap(),
                "the {label} edit did not change the receipt"
            );
            // The digest moves, so the attestation is not even *about* this
            // receipt any more...
            assert_ne!(
                attestation.receipt_hash().unwrap(),
                receipt_hash(&edited).unwrap(),
                "editing {label} left the receipt digest unchanged"
            );
            // ...and an attestation carrying the edited receipt does not verify.
            let tampered = AuthenticatedExternalValueReceipt {
                receipt: edited,
                policy_hash: attestation.policy_hash.clone(),
                verifier_key_id: attestation.verifier_key_id,
                attestation_hash: attestation.attestation_hash.clone(),
                signature: attestation.signature.clone(),
            };
            assert!(
                tampered.verify(&policy, &tx()).is_err(),
                "a signature survived an edit to {label}"
            );
        }
    }

    // ------------------------------------------------------------------
    // 5. an attestation is about one transfer
    // ------------------------------------------------------------------

    #[test]
    fn an_attestation_cannot_be_re_pointed_at_another_transfer() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let attestation = auth.attest(&policy, &receipt(), &tx());

        // Same receipt, a different transfer: the body is rebuilt from the
        // evidence, so the preimage changes and the signature does not survive.
        let mut other = tx();
        other.tx_hash = format!("0x{}", "dd".repeat(32));
        assert!(attestation.verify(&policy, &other).is_err());

        let mut bigger = tx();
        bigger.amount_raw = AMOUNT * 10;
        assert!(attestation.verify(&policy, &bigger).is_err());

        let mut other_payee = tx();
        other_payee.to_address = "0x0000000000000000000000000000000000000042".into();
        assert!(attestation.verify(&policy, &other_payee).is_err());

        let mut other_block = tx();
        other_block.block_hash = format!("0x{}", "ee".repeat(32));
        assert!(attestation.verify(&policy, &other_block).is_err());

        // The mirror: a receipt that cites a different transaction than the
        // evidence cannot be signed at all.
        let err = auth
            .verifier
            .attest(
                &policy,
                &ExternalValueReceipt {
                    proof_hash: format!("0x{}", "cc".repeat(32)),
                    ..receipt()
                },
                &tx(),
            )
            .unwrap_err();
        assert!(
            matches!(err, ReceiptAuthError::ReceiptCitesAnotherTransaction { .. }),
            "a receipt citing another transaction must not be signed, got {err}"
        );
    }

    #[test]
    fn a_synthetic_unit_cannot_be_attested() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let err = auth
            .verifier
            .attest(
                &policy,
                &ExternalValueReceipt {
                    asset: "smUSD".into(),
                    ..receipt()
                },
                &tx(),
            )
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("synthetic ledger unit"), "{msg}");
        assert!(matches!(err, ReceiptAuthError::UnusableReceipt { .. }));
    }

    #[test]
    fn an_unidentified_asset_cannot_be_attested() {
        // `BoundaryEvidence` can carry an unidentified triple: it is well formed
        // but not on the allowlist. The boundary derivation would refuse it, and
        // so does signing.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let bogus = RealAsset::new(
            BASE_CHAIN_ID,
            "0x0000000000000000000000000000000000000042",
            6,
        )
        .unwrap();
        assert!(!bogus.is_known());
        let err = auth
            .verifier
            .attest(
                &policy,
                &receipt(),
                &BoundaryEvidence {
                    asset: bogus,
                    ..tx()
                },
            )
            .unwrap_err();
        // P1's own rules refuse it before anything is taken out of the evidence,
        // which is the point: signing never gets to be more permissive than
        // derivation.
        assert!(
            matches!(err, ReceiptAuthError::Economy(_)),
            "expected an evidence-validation refusal, got {err}"
        );
        assert!(
            err.to_string().contains("not an identified real asset"),
            "{err}"
        );
    }

    // ------------------------------------------------------------------
    // 6. what the wrapper does not let you do
    // ------------------------------------------------------------------

    #[test]
    fn the_attestation_carries_no_field_a_reader_could_verify_against() {
        // The signed facts — chain, addresses, amount, block — are not stored in
        // the wrapper. That is deliberate: a wrapper that carried them would be
        // verified against its own copy, which is the `Gland` shape one type
        // over. `verify` takes the evidence instead.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let attestation = auth.attest(&policy, &receipt(), &tx());
        let json = serde_json::to_value(&attestation).unwrap();
        let object = json.as_object().unwrap();
        let mut keys: Vec<&str> = object.keys().map(|k| k.as_str()).collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "attestation_hash",
                "policy_hash",
                "receipt",
                "signature",
                "verifier_key_id",
            ],
            "the wrapper is exactly the five fields the design names"
        );
        // The transaction and the block live inside the receipt, as a citation —
        // never as a value this wrapper asks anyone to trust.
        assert_eq!(json["receipt"]["proof_hash"], serde_json::json!(tx().tx_hash));
        assert!(json.get("tx_hash").is_none());
        assert!(json.get("block_hash").is_none());
        assert!(json.get("amount_raw").is_none());
        assert!(json.get("from_address").is_none());
        assert!(json.get("to_address").is_none());
    }

    #[test]
    fn the_attestation_hash_is_checked_so_the_record_cannot_be_edited() {
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let mut attestation = auth.attest(&policy, &receipt(), &tx());
        attestation.attestation_hash = Hash::from_bytes([0x5au8; 32]);
        let err = attestation.verify(&policy, &tx()).unwrap_err();
        assert!(
            matches!(err, ReceiptAuthError::AttestationHashMismatch { .. }),
            "an edited digest handle must be caught, got {err}"
        );
    }

    #[test]
    fn a_re_signed_body_is_still_refused_when_the_digest_handle_is_stale() {
        // Somebody who holds a delegated key (the operator does) can produce a
        // perfectly valid signature over a different body. The digest handle is
        // what stops the *record* being relabelled underneath it.
        let dir = tempfile::tempdir().unwrap();
        let auth = fixture(dir.path());
        let policy = auth.validated();
        let attestation = auth.attest(&policy, &receipt(), &tx());
        let mut resigned = attestation.body(&tx()).unwrap();
        resigned.amount_raw = AMOUNT * 2;
        let preimage = resigned.signing_preimage().unwrap();
        let mut swapped = attestation.clone();
        swapped.signature = auth.verifier.sign_preimage(&preimage);
        assert!(
            swapped.verify(&policy, &tx()).is_err(),
            "a valid signature over a different body must not verify as this attestation"
        );
    }

    // ------------------------------------------------------------------
    // 7. the store
    // ------------------------------------------------------------------

    #[test]
    fn the_attestation_ledger_chain_verifies_and_refuses_a_broken_one() {
        let dir = tempfile::tempdir().unwrap();
        let autonomy = crate::autonomy::AutonomousEconomy::open(dir.path()).unwrap();
        // No file yet: the legacy shape. An absent ledger is an empty ledger,
        // not an error, or every directory written before P4b would be
        // unreadable.
        assert_eq!(autonomy.receipt_attestations().unwrap().len(), 0);
        assert!(!autonomy.attestation_ledger_path().exists());

        let auth = fixture(dir.path());
        let policy = auth.validated();
        for i in 0..3u64 {
            let mut r = receipt();
            r.source_id = format!("source-{i}");
            let evidence = tx();
            autonomy
                .record_receipt_attestation(&auth.attest(&policy, &r, &evidence))
                .unwrap();
        }
        let stored = autonomy.receipt_attestations().unwrap();
        assert_eq!(stored.len(), 3);

        // Corrupt the middle of the chain.
        let path = autonomy.attestation_ledger_path();
        let raw = fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = raw.lines().map(|l| l.to_string()).collect();
        lines[1] = lines[1].replace("\"source_id\":\"source-1\"", "\"source_id\":\"tampered\"");
        assert_ne!(lines[1], raw.lines().nth(1).unwrap());
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let err = autonomy.receipt_attestations().unwrap_err();
        assert!(
            err.to_string().contains("hash"),
            "a rewritten attestation ledger must be refused, got {err}"
        );
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    fn attestation_body(
        policy: &ValidatedOutcomePolicy,
        receipt: &ExternalValueReceipt,
        evidence: &BoundaryEvidence,
    ) -> AttestationBody {
        AttestationBody::from_parts(
            receipt,
            evidence,
            &policy.policy_hash().unwrap(),
            policy.trusted_verifier().key_id(),
        )
        .unwrap()
    }

    fn section_bytes(body: &AttestationBody, tag: &str) -> Vec<u8> {
        match tag {
            "schema_version" => body.schema_version.to_be_bytes().to_vec(),
            "policy_hash" => body.policy_hash.to_bytes().unwrap().to_vec(),
            "chain_id" => body.chain_id.to_be_bytes().to_vec(),
            "tx_hash" => body.tx_hash.to_bytes().unwrap().to_vec(),
            "block_hash" => body.block_hash.to_bytes().unwrap().to_vec(),
            "asset" => body.asset.as_bytes().to_vec(),
            "from_address" => body.from_address.as_str().as_bytes().to_vec(),
            "to_address" => body.to_address.as_str().as_bytes().to_vec(),
            "amount_raw" => body.amount_raw.to_be_bytes().to_vec(),
            "opportunity_id" => body.opportunity_id.as_bytes().to_vec(),
            "source_id" => body.source_id.as_bytes().to_vec(),
            "verifier_key_id" => body.verifier_key_id.as_bytes().to_vec(),
            "receipt_hash" => body.receipt_hash.to_bytes().unwrap().to_vec(),
            other => panic!("unknown section {other:?}"),
        }
    }

    fn mutate_field(body: &mut AttestationBody, tag: &str) -> bool {
        match tag {
            "schema_version" => body.schema_version += 1,
            "policy_hash" => body.policy_hash = Hash::from_bytes([0xa1u8; 32]),
            "chain_id" => body.chain_id = body.chain_id.wrapping_add(1),
            "tx_hash" => body.tx_hash = Hash::from_bytes([0xa2u8; 32]),
            "block_hash" => body.block_hash = Hash::from_bytes([0xa3u8; 32]),
            "asset" => body.asset = format!("0x{}", "cd".repeat(20)),
            "from_address" => {
                body.from_address =
                    Address::parse("0x0000000000000000000000000000000000000001")
                        .unwrap()
            }
            "to_address" => {
                body.to_address =
                    Address::parse("0x0000000000000000000000000000000000000002")
                        .unwrap()
            }
            "amount_raw" => body.amount_raw = body.amount_raw.wrapping_add(1),
            "opportunity_id" => body.opportunity_id.push_str("-other"),
            "source_id" => body.source_id.push_str("-other"),
            "verifier_key_id" => {
                body.verifier_key_id =
                    KeyId::derive(KeyRole::VerifierRuntime, &[0xa4u8; 32])
            }
            "receipt_hash" => body.receipt_hash = Hash::from_bytes([0xa5u8; 32]),
            _ => return false,
        }
        true
    }
}
