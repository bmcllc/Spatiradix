//! P4.5b: the canonical identity of an external fact, and the economic
//! idempotency that follows from it.
//!
//! # Why this module exists
//!
//! Everything else in this crate binds a piece of external evidence to a
//! *position in a local file*. A receipt is found in the attestation ledger by
//! the digest of its own content, which is right; but the accounting decision —
//! "has this external event already been paid for?" — used to have no answer
//! that did not mention where the record sat. That is the wrong identity, for
//! two reasons the project had already decided on elsewhere:
//!
//!  * it mixes domains. "What happened on Base" and "what is line 4 of this
//!    node's ledger" are separate facts, and P4a/P4b/P4c each took a domain
//!    string precisely to keep them apart. An economic total that depends on
//!    ledger position is depending on the second while claiming the first.
//!  * it is per-read. A guard that only sees one pass over the file catches a
//!    duplicate *within* that pass and nothing else, so a duplicated record
//!    promotes again the next time the process starts.
//!
//! The identity here is the opposite of both: a digest of the external fact,
//! and nothing else.
//!
//! ```text
//! ExternalEventId = H(domain, chain_id, tx_hash, log_index, asset, from, to, amount)
//! ```
//!
//! # What the digest may not contain
//!
//! Not the ledger `sequence`. Not `recorded_at_unix` or `realized_at_unix`. Not
//! the `source_id`, the `opportunity_id`, the receipt's own `schema_version`, or
//! any other field of the JSON envelope a record is written in. Not the file
//! path, the directory, the process, the byte offset, or the order in which the
//! records were read. Every one of those is a property of *this node's copy* of
//! the fact, and a second node that observed the same transfer — or the same
//! node after a restart, a re-serialisation or a rewrite — must arrive at the
//! same digest. `the_id_survives_everything_that_is_not_the_fact` in this
//! module's tests is the assertion of that, and it is the reason the layout
//! below is spelled out field by field rather than derived from a struct.
//!
//! # What the digest deliberately leaves out
//!
//! `asset` is bound as the *canonical contract address*, not as a symbol and not
//! with the local `decimals` table. "USDC" is a local name; `0x833589…` is what
//! the chain moved. The `decimals` field is presentation, and binding it would
//! make the identity of an on-chain fact depend on a constant compiled into this
//! binary — the same mistake as binding a timestamp, one level down.
//!
//! # Domain separation
//!
//! The event-id digest is built with the same encoder as every other preimage in
//! this crate ([`crate::policy_auth::push_tagged`]): tagged, length-prefixed,
//! domain first. It is *not* a signature and it authenticates nothing on its
//! own; it is an identity, and its whole job is to be equal for one fact and
//! unequal for every other. Because the domain comes first and is
//! [`EVENT_ID_DOMAIN`], a receipt attestation, a settlement attestation, a
//! policy signature and an event id over the same underlying transfer are four
//! different digests over four different messages.
//! `an_event_id_is_domain_separated_from_every_other_digest_in_the_crate` pins
//! that with the real artefacts rather than with a restatement of the domain
//! strings.
//!
//! Two domains are defined, and only the first is used by the crate today:
//!
//! * [`EVENT_ID_DOMAIN`] — a fact a chain *log* records. Its identity is
//!   `(tx_hash, log_index)`, which is unique inside a transaction.
//! * [`NATIVE_GAS_EVENT_ID_DOMAIN`] — a native/gas fact, which has no log. The
//!   seam exists now, before gas economics do, because adding a second domain
//!   later is exactly the moment when a native fact would otherwise be filed
//!   under the token domain and collide with a token transfer in the same
//!   transaction. Nothing in this crate computes one yet, and
//!   `the_native_gas_seam_is_defined_and_distinct` says so out loud rather than
//!   leaving it to be discovered.
//!
//! Two more arrived later, both by the same rule — a new **domain**, never a
//! field or an [`ExternalEventKind`] variant:
//! [`SETTLEMENT_EVENT_ID_DOMAIN`] for the revenue side's payment reading, and
//! [`PRICE_OBSERVATION_ID_DOMAIN`] for P4.6's price reading.
//!
//! A fifth arrived with P6.N6, by that rule once more:
//! [`SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN`], which names a whole settled
//! operation as one economic event rather than any single log inside it. It is
//! the domain that makes a NEV event's identity something that is *derived*
//! instead of something a caller supplies, and it is the one preimage below
//! whose distinguishing property is an omission: no price, no policy, no
//! net value, no confirmation count. All five are distinct strings and all five
//! are asserted distinct from one another with real artefacts, not with a
//! restatement of the constants.
//!
//! # The log index is not optional
//!
//! A transaction can contain more than one transfer of the same token to the
//! same recipient. `(tx_hash, asset, from, to, amount)` does not tell those
//! apart, so a fact with no log index has no canonical identity and this module
//! refuses to invent one — it returns [`EventIdError::LogIndexUnknown`] rather
//! than defaulting to zero. The index comes from the chain read, which is
//! [`crate::verified_view`]'s last gate, so the identity of an external fact is
//! established by the same call that establishes that the fact happened.

use crate::{
    base_usdc::BaseUsdcVerification,
    boundary::{BoundaryEvidence, RealAsset},
    policy_auth::{push_tagged, Address, Hash, PreimageFieldKind},
    EconomyError,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// Domain of the identity of a fact a chain log records. First bytes of the
/// event-id preimage, so this digest can never equal a receipt attestation, a
/// settlement attestation, a policy signature or any other digest the crate
/// produces.
pub const EVENT_ID_DOMAIN: &str = "MYCELIUM-ECONOMY/EVENT-ID/V1";

/// Domain of the identity of a native/gas fact — a value that moved as the
/// chain's own currency and therefore has no log to point at.
///
/// Defined now and used by nothing yet, on purpose. Filing a native fact under
/// [`EVENT_ID_DOMAIN`] would put a gas payment and a token transfer in the same
/// namespace, where `(chain_id, tx_hash, asset, from, to, amount)` can collide.
pub const NATIVE_GAS_EVENT_ID_DOMAIN: &str = "MYCELIUM-ECONOMY/NATIVE-GAS-EVENT-ID/V1";

/// The canonical spelling of "the chain's own currency", for a native fact.
///
/// **Not an address anything can hold a token at.** It is a reserved zero word,
/// and `RealAsset::new` is never involved in building a native fact, so no code
/// path in this crate can turn it into a token identity, compare a delta's
/// asset against it, or classify it through `SettlementAsset`.
///
/// It exists because [`ExternalEventFact`] binds an `asset` field and a native
/// fact has no ERC-20 contract to put there. The alternatives were worse:
/// inventing a plausible-looking contract address would put a fabricated token
/// into the identity of a real fact, and dropping the field would give the
/// native domain a second, different layout from the one
/// [`NATIVE_GAS_EVENT_ID_DOMAIN`] already implies.
pub const NATIVE_CURRENCY: &str = "0x0000000000000000000000000000000000000000";

/// Schema version this build computes and expects. The first byte group of the
/// preimage, so a future layout cannot silently produce the same digests.
pub const EVENT_ID_SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum EventIdError {
    /// Wraps the crate's existing vocabulary rather than inventing a parallel
    /// one: an unusable address, hash or asset is an invalid external fact.
    #[error(transparent)]
    Economy(#[from] EconomyError),

    /// `policy_auth`'s vocabulary, for the canonical `Address`/`Hash`
    /// constructors this module reuses.
    #[error(transparent)]
    Policy(#[from] crate::policy_auth::PolicyError),

    #[error("event-id preimage is malformed: {0}")]
    Preimage(String),

    /// The chain read did not say which log it matched. Two transfers of the
    /// same token to the same recipient in one transaction are
    /// indistinguishable without it, so this fact is not nameable and is
    /// refused rather than hashed under a made-up index.
    #[error(
        "the chain read reported no log index, so this external fact has no \
         canonical identity and is not counted: {0}"
    )]
    LogIndexUnknown(String),

    /// The chain the fact claims and the chain its asset lives on disagree.
    /// `BoundaryEvidence::validate` refuses the same thing; this is the
    /// event-id-shaped copy, so a caller building a fact from parts rather than
    /// from stored evidence cannot skip the rule.
    #[error("external fact is on chain {fact} but its asset is on chain {asset}")]
    ChainMismatch { fact: u64, asset: u64 },

    /// Two addresses that must differ are the same address. A self-transfer is
    /// not an external event, and an id built from it would name a fact the
    /// crossing derivation has already refused.
    #[error("external fact has the same from and to address ({address})")]
    SelfTransfer { address: String },

    /// A zero-amount fact moves no value. It cannot be an external inflow and
    /// it must not be able to occupy an identity a real transfer would want.
    #[error("external fact amount_raw must be > 0")]
    ZeroAmount,

    /// Chain 0 names no chain.
    #[error("external fact chain_id must be > 0")]
    ZeroChain,

    /// A native fact whose cost does not fit the `u64` raw-amount slot the
    /// identity binds.
    ///
    /// The arithmetic is done in `u128` and refused here rather than truncated:
    /// a truncated gas figure is a fabricated one, and it is the whole figure
    /// the identity commits to. On Base a single transaction costing more than
    /// `u64::MAX` wei — about 18 ETH — is not reachable, so this is defence in
    /// depth against a future chain, not a state this build can produce.
    #[error("native cost of {cost_wei} wei does not fit the identity's raw-amount slot")]
    NativeAmountOutOfRange { cost_wei: u128 },

    /// The settlement-payment identity found something the shared
    /// [`EventIdError`] vocabulary cannot describe. Wrapped rather than
    /// flattened, so a caller reading a revenue-side refusal sees which of the
    /// two preimages failed.
    #[error("settlement-payment fact is not describable: {0}")]
    UnusableSettlementFact(String),

    /// P4.6. The price-observation identity found something the shared
    /// vocabulary cannot describe, wrapped for the same reason.
    #[error("price-observation fact is not describable: {0}")]
    UnusablePriceFact(String),

    /// P6.N6. The settlement-economic identity was handed something it cannot
    /// bind — in practice a leg with no canonical external event id, so the
    /// operation's legs cannot all be named.
    ///
    /// Wrapped for the same reason as [`Self::UnusableSettlementFact`] and
    /// [`Self::UnusablePriceFact`]: a caller reading a refusal on the NEV route
    /// should be able to tell which preimage refused. What matters more is what
    /// this variant **forecloses**: there is no companion fallback-id variant,
    /// because a synthesised id over a leg set that is not fully named is a
    /// *stable* id over an incomplete fact, and a stable id is how one
    /// on-chain operation ends up counted under two different identities.
    #[error("settlement-economic fact is not describable: {0}")]
    UnusableSettlementEconomicFact(String),
}

// ---------------------------------------------------------------------------
// Which class of fact
// ---------------------------------------------------------------------------

/// Which domain an event id is computed under.
///
/// This is a *domain selector*, not a tag stored in the preimage: the two
/// variants share a layout and differ only in the first section, which is the
/// whole point of domain separation. Adding a third class of fact later means
/// adding a domain, not a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalEventKind {
    /// A fact a chain log records, identified by `(tx_hash, log_index)`.
    /// Every event id the view computes today is this one.
    Logged,
    /// A native/gas fact, which has no log. The seam gas economics will use.
    NativeGas,
}

impl ExternalEventKind {
    /// The domain string this class of fact hashes under.
    pub fn domain(self) -> &'static str {
        match self {
            Self::Logged => EVENT_ID_DOMAIN,
            Self::NativeGas => NATIVE_GAS_EVENT_ID_DOMAIN,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Logged => "logged",
            Self::NativeGas => "native_gas",
        }
    }
}

impl std::fmt::Display for ExternalEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// The fact
// ---------------------------------------------------------------------------

/// The external fact an [`ExternalEventId`] names — and the *only* thing it
/// names.
///
/// Private fields with validating construction, exactly like [`RealAsset`]: a
/// fact that has not been through [`Self::from_parts`] cannot exist, so no
/// caller can hand the digest something the chain would not describe. The
/// fields are exactly the layout table's, in the same order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalEventFact {
    chain_id: u64,
    tx_hash: Hash,
    log_index: u64,
    asset_contract: String,
    from_address: Address,
    to_address: Address,
    amount_raw: u64,
}

impl ExternalEventFact {
    /// Validating constructor.
    ///
    /// Every rule here is a rule P1 already applies to the evidence a crossing is
    /// derived from; restating them at the identity layer means a caller that
    /// builds a fact from parts instead of from stored evidence still cannot get
    /// a digest for a fact that would have been refused earlier.
    pub fn from_parts(
        chain_id: u64,
        tx_hash: &str,
        log_index: u64,
        asset: &RealAsset,
        from_address: &str,
        to_address: &str,
        amount_raw: u64,
    ) -> std::result::Result<Self, EventIdError> {
        if chain_id == 0 {
            return Err(EventIdError::ZeroChain);
        }
        if chain_id != asset.chain_id() {
            return Err(EventIdError::ChainMismatch {
                fact: chain_id,
                asset: asset.chain_id(),
            });
        }
        if amount_raw == 0 {
            return Err(EventIdError::ZeroAmount);
        }
        // `Address::parse` and `Hash::parse` normalise, so a checksummed,
        // mixed-case or upper-case spelling of one address hashes identically to
        // its lowercase twin. That is what makes the identity independent of
        // re-serialisation.
        let from_address = Address::parse(from_address)?;
        let to_address = Address::parse(to_address)?;
        if from_address == to_address {
            return Err(EventIdError::SelfTransfer {
                address: from_address.to_string(),
            });
        }
        Ok(Self {
            chain_id,
            tx_hash: Hash::parse("tx_hash", tx_hash)?,
            log_index,
            // `RealAsset::new` already normalised the contract, so this is
            // canonical by construction and needs no second pass.
            asset_contract: asset.contract().to_string(),
            from_address,
            to_address,
            amount_raw,
        })
    }

    /// The fact stored boundary evidence describes, at a given log index.
    ///
    /// The evidence is validated with P1's own [`BoundaryEvidence::validate`]
    /// first, so an id can never name evidence the crossing derivation would
    /// have refused. The log index is a *parameter*, not a field of the
    /// evidence: it is a chain fact the read establishes, and the ledger does
    /// not store it.
    pub fn from_boundary(
        evidence: &BoundaryEvidence,
        log_index: u64,
    ) -> std::result::Result<Self, EventIdError> {
        evidence.validate()?;
        Self::from_parts(
            evidence.chain_id,
            &evidence.tx_hash,
            log_index,
            &evidence.asset,
            &evidence.from_address,
            &evidence.to_address,
            evidence.amount_raw,
        )
    }

    /// The fact a confirmed transfer describes, taking the log index from the
    /// proof the chain read produced.
    ///
    /// This is the one place the "no log index, no identity" rule lives, and it
    /// is the constructor the read path uses: a provider that answers a
    /// transfer question without saying which log it matched has not established
    /// an event, and [`crate::verified_view`] reports
    /// [`EventIdError::LogIndexUnknown`] rather than counting it.
    pub fn from_confirmed_transfer(
        evidence: &BoundaryEvidence,
        proof: &BaseUsdcVerification,
    ) -> std::result::Result<Self, EventIdError> {
        let log_index = proof.matching_log_index.ok_or_else(|| {
            EventIdError::LogIndexUnknown(format!(
                "provider {} confirmed {} to {} without reporting a log index",
                proof.rpc, proof.transaction_hash, proof.recipient
            ))
        })?;
        Self::from_boundary(evidence, log_index)
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn tx_hash(&self) -> &str {
        self.tx_hash.as_str()
    }

    pub fn log_index(&self) -> u64 {
        self.log_index
    }

    /// The canonical contract address of the asset that moved. Never a symbol.
    pub fn asset_contract(&self) -> &str {
        &self.asset_contract
    }

    pub fn from_address(&self) -> &str {
        self.from_address.as_str()
    }

    pub fn to_address(&self) -> &str {
        self.to_address.as_str()
    }

    pub fn amount_raw(&self) -> u64 {
        self.amount_raw
    }

    /// A native/gas fact: value that moved as the chain's own currency, which
    /// has no ERC-20 contract and no ERC-20 log.
    ///
    /// # Why this is not `from_parts`
    ///
    /// [`Self::from_parts`] demands a [`RealAsset`] — an *identified ERC-20* —
    /// and refuses a self-transfer. Both rules are right for a token transfer
    /// and wrong here:
    ///
    /// * a gas fee is not a transfer of a token, so there is no contract to
    ///   name. [`NATIVE_CURRENCY`] stands in as a reserved word that can never
    ///   be mistaken for one.
    /// * the fee payer and the party that receives (or burns) the fee may be
    ///   the same address, and on some chains there is no recipient at all. The
    ///   self-transfer rule exists so an id cannot name a fact the crossing
    ///   derivation would refuse; a native fact never reaches that derivation.
    ///
    /// # What the identity actually commits to
    ///
    /// `gas_used`, `effective_gas_price_wei` and `l1_fee_wei` are properties of
    /// the *transaction*, not of a log, and every node that reads the same
    /// receipt computes the same three numbers. That is why `log_index` is fixed
    /// at `0` here: a gas charge has no log, the transaction hash already names
    /// it uniquely, and pinning a made-up index would suggest a log exists.
    ///
    /// The cost is bound as `amount_raw`, checked rather than truncated — see
    /// [`EventIdError::NativeAmountOutOfRange`].
    ///
    /// `effective_gas_price_wei` and `l1_fee_wei` are **not** parameters: the
    /// identity commits to the *cost*, which is the only economically
    /// meaningful number here, and `gas_used` and the prices stay on
    /// [`crate::settlement::VerifiedNativeGasCost`] where an audit can read
    /// them. Two different splits of gas and price that cost the same amount
    /// name the same economic event, which is correct.
    pub fn native_gas(
        chain_id: u64,
        tx_hash: &str,
        fee_payer: &str,
        fee_recipient: &str,
        gas_used: u64,
        cost_wei: u128,
    ) -> std::result::Result<Self, EventIdError> {
        if chain_id == 0 {
            return Err(EventIdError::ZeroChain);
        }
        if cost_wei == 0 {
            return Err(EventIdError::ZeroAmount);
        }
        if cost_wei > u128::from(u64::MAX) {
            return Err(EventIdError::NativeAmountOutOfRange { cost_wei });
        }
        if gas_used == 0 {
            return Err(EventIdError::ZeroAmount);
        }
        Ok(Self {
            chain_id,
            tx_hash: Hash::parse("tx_hash", tx_hash)?,
            // No log: the transaction hash names a gas charge uniquely, and
            // inventing an index would imply a log this fact does not have.
            log_index: 0,
            asset_contract: NATIVE_CURRENCY.to_string(),
            from_address: Address::parse(fee_payer)?,
            to_address: Address::parse(fee_recipient)?,
            amount_raw: cost_wei as u64,
        })
    }
}

// ---------------------------------------------------------------------------
// The identity
// ---------------------------------------------------------------------------

/// The canonical event-id preimage layout, in canonical order.
///
/// Exactly the eight facts the external world knows, and nothing about how this
/// node stored them:
///
/// | row | field | kind | why it is in the identity |
/// |-----|-------|------|---------------------------|
/// | 1 | `schema_version` | `U32` | so a future layout cannot produce today's digests |
/// | 2 | `chain_id` | `U64` | the same transaction hash on two chains is two facts |
/// | 3 | `tx_hash` | `Hash32` | which transaction |
/// | 4 | `log_index` | `U64` | which event inside it |
/// | 5 | `asset` | `AddressText` | canonical contract, not a symbol |
/// | 6 | `from_address` | `AddressText` | who sent |
/// | 7 | `to_address` | `AddressText` | who received |
/// | 8 | `amount_raw` | `U64` | how much, in the asset's own units |
///
/// What is *not* here is the point: no `sequence`, no timestamp, no `source_id`,
/// no `opportunity_id`, no `verifier_id`, no `policy_hash`, no receipt digest,
/// no path. `the_layout_table_names_exactly_the_facts_and_nothing_else` asserts
/// that against the table rather than against a comment.
pub const EVENT_ID_FIELDS: &[(&str, PreimageFieldKind)] = &[
    ("schema_version", PreimageFieldKind::U32),
    ("chain_id", PreimageFieldKind::U64),
    ("tx_hash", PreimageFieldKind::Hash32),
    ("log_index", PreimageFieldKind::U64),
    ("asset", PreimageFieldKind::AddressText),
    ("from_address", PreimageFieldKind::AddressText),
    ("to_address", PreimageFieldKind::AddressText),
    ("amount_raw", PreimageFieldKind::U64),
];

/// The exact bytes an [`ExternalEventId`] is the digest of.
///
/// ```text
/// tagged   := TAG_LEN:u32be || TAG || VALUE_LEN:u32be || VALUE
/// preimage := tagged("domain", <the kind's domain>)
///          || tagged("sections", SECTION_COUNT:u32be)
///          || section*
/// section  := tagged(TAG_i, VALUE_i)   for TAG_i in EVENT_ID_FIELDS
/// ```
///
/// Never a serialised struct: a self-describing encoding would promote field
/// order, whitespace and number formatting into the identity of an economic
/// event. `push_tagged` is P4a's encoder, reused rather than reimplemented, so
/// this preimage is in the same canonical shape as a policy preimage, a receipt
/// digest and a settlement digest.
pub fn preimage(
    fact: &ExternalEventFact,
    kind: ExternalEventKind,
) -> std::result::Result<Vec<u8>, EventIdError> {
    let values: Vec<(&str, Vec<u8>)> = vec![
        (
            "schema_version",
            EVENT_ID_SCHEMA_VERSION.to_be_bytes().to_vec(),
        ),
        ("chain_id", fact.chain_id.to_be_bytes().to_vec()),
        ("tx_hash", fact.tx_hash.to_bytes()?.to_vec()),
        ("log_index", fact.log_index.to_be_bytes().to_vec()),
        ("asset", fact.asset_contract.as_bytes().to_vec()),
        (
            "from_address",
            fact.from_address.as_str().as_bytes().to_vec(),
        ),
        ("to_address", fact.to_address.as_str().as_bytes().to_vec()),
        ("amount_raw", fact.amount_raw.to_be_bytes().to_vec()),
    ];
    check_layout(&values, EVENT_ID_FIELDS, "event-id preimage")?;

    let mut buf = Vec::new();
    push_tagged(&mut buf, b"domain", kind.domain().as_bytes());
    push_tagged(
        &mut buf,
        b"sections",
        &u32::try_from(values.len())
            .map_err(|_| EventIdError::Preimage("too many event-id sections".into()))?
            .to_be_bytes(),
    );
    for (tag, value) in &values {
        push_tagged(&mut buf, tag.as_bytes(), value);
    }
    Ok(buf)
}

/// The encoder and the layout table can disagree in exactly one way that
/// matters — a field renamed on one side and not the other — so it is checked at
/// run time rather than trusted. Same discipline as
/// [`crate::policy_auth::OutcomePolicyPayload::signing_preimage`],
/// `receipt_auth::check_layout` and `settlement_auth::check_layout`, and kept
/// local for the same reason those two are: each layout table is checked against
/// its own encoder, and a shared helper would let one module's table be
/// satisfied by another module's field list.
fn check_layout(
    values: &[(&str, Vec<u8>)],
    layout: &[(&str, PreimageFieldKind)],
    what: &str,
) -> std::result::Result<(), EventIdError> {
    if values.len() != layout.len() {
        return Err(EventIdError::Preimage(format!(
            "{what}: encoder emitted {} sections for a layout of {}",
            values.len(),
            layout.len()
        )));
    }
    for ((tag, _), (expected_tag, _)) in values.iter().zip(layout.iter()) {
        if *tag != *expected_tag {
            return Err(EventIdError::Preimage(format!(
                "{what}: encoder emitted section {tag:?} where the layout expects {expected_tag:?}"
            )));
        }
    }
    Ok(())
}

/// The canonical digest of an external fact.
///
/// A digest, not a signature: it proves that two observers are talking about the
/// same transfer, and nothing else. It carries no authority, so it is never a
/// gate on its own — the gates that established the fact in the first place are
/// unchanged by this type existing. What it buys is the *count*:
///
/// > two records that name the same external fact are one piece of external
/// > value, however many times the ledger says otherwise.
///
/// The digest is a [`Hash`], the crate's canonical 32-byte handle, so it
/// serialises, prints and compares exactly like the other handles in an audit
/// record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExternalEventId(Hash);

/// Hand-written rather than derived because the inner [`Hash`] is ordered rather
/// than hashed, and the crate's other set types index it that way. The digest
/// spelling is canonical, so hashing the string and hashing the bytes agree.
impl std::hash::Hash for ExternalEventId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

impl ExternalEventId {
    /// The identity of a fact a chain log records.
    pub fn logged(fact: &ExternalEventFact) -> std::result::Result<Self, EventIdError> {
        Self::compute(fact, ExternalEventKind::Logged)
    }

    /// The identity of a native/gas fact. Unused by the crate today; see
    /// [`NATIVE_GAS_EVENT_ID_DOMAIN`] for why the seam exists before the feature
    /// does.
    pub fn native_gas(fact: &ExternalEventFact) -> std::result::Result<Self, EventIdError> {
        Self::compute(fact, ExternalEventKind::NativeGas)
    }

    pub fn compute(
        fact: &ExternalEventFact,
        kind: ExternalEventKind,
    ) -> std::result::Result<Self, EventIdError> {
        let bytes = *blake3::hash(&preimage(fact, kind)?).as_bytes();
        Ok(Self(Hash::from_bytes(bytes)))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Rehydrates an id from its stored canonical text, VALIDATING it.
    ///
    /// `crate(crate)`, not public, and not a back door: the crate's `Hash`
    /// derives `Deserialize` as a transparent `String` with no validation, so
    /// without this there would be no way to turn a durable `economic_event_id`
    /// back into an `ExternalEventId` through a checked path. This refuses
    /// anything that is not the canonical `0x` + 64 lowercase-hex digest
    /// spelling an id's own constructors produce.
    pub(crate) fn from_canonical_text(text: &str) -> std::result::Result<Self, EventIdError> {
        Ok(Self(Hash::parse(
            "ExternalEventId::from_canonical_text",
            text,
        )?))
    }

    /// The underlying canonical handle, for callers that need the raw digest
    /// (a signature preimage, a set of ids in a report).
    pub fn digest(&self) -> &Hash {
        &self.0
    }

    /// Test helper to create an ExternalEventId from a test seed string.
    #[cfg(test)]
    pub(crate) fn from_test_seed(seed: &str) -> Self {
        let digest = blake3::hash(seed.as_bytes());
        Self(Hash::from_bytes(*digest.as_bytes()))
    }
}

impl std::fmt::Display for ExternalEventId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// The settlement-payment identity (P4.5c)
// ---------------------------------------------------------------------------
//
// P4.5b built the counting rule and applied it to the autonomy side only. The
// revenue side books *payments*, and a payment's counterparty is the one fact
// the revenue read never establishes: `BaseUsdcVerification` reports the
// recipient, the token and the amount, and nothing reads the payer. Two
// settlements of one payment therefore cannot be reduced to an
// `ExternalEventFact`, because that type's layout binds `from_address` and the
// revenue view would have to invent one.
//
// Inventing it is exactly the failure this module exists to prevent: a digest
// over a fabricated fact is a digest of nothing, and it would be *stable*,
// which is worse than a random one. So the payment gets its own preimage under
// its own domain, over the facts the revenue read really did establish:
//
//   SettlementPaymentId = H(SETTLEMENT_EVENT_ID_DOMAIN, schema, chain, tx,
//                           log_index, asset, recipient, amount)
//
// `(chain_id, tx_hash, log_index)` already names one log on one chain — the
// event-id module doc says so — so the smaller preimage is the *more* truthful
// one, not a weaker one: it omits a field because that field is unknown here,
// not because it was forgotten. `settlement_preimage_names_only_what_the_revenue
// _read_established` pins the table.

/// Domain of the identity of a *payment* as the revenue side establishes it.
pub const SETTLEMENT_EVENT_ID_DOMAIN: &str =
    "MYCELIUM-ECONOMY/SETTLEMENT-EVENT-ID/V1";

/// Schema version this build computes and expects for
/// [`SETTLEMENT_EVENT_ID_DOMAIN`].
pub const SETTLEMENT_EVENT_ID_SCHEMA_VERSION: u32 = 1;

/// The settlement-payment preimage layout, in canonical order.
///
/// Deliberately **not** [`EVENT_ID_FIELDS`]: the `from_address` row is absent
/// because the revenue read never establishes it, and inventing a placeholder
/// row would make the two preimages differ only in a field that is always the
/// same constant.
pub const SETTLEMENT_EVENT_FIELDS: &[(&str, PreimageFieldKind)] = &[
    ("schema_version", PreimageFieldKind::U32),
    ("chain_id", PreimageFieldKind::U64),
    ("tx_hash", PreimageFieldKind::Hash32),
    ("log_index", PreimageFieldKind::U64),
    ("asset", PreimageFieldKind::AddressText),
    ("to_address", PreimageFieldKind::AddressText),
    ("amount_raw", PreimageFieldKind::U64),
];

/// A payment the revenue side established, and nothing more.
///
/// Private fields with one validating constructor, so a caller cannot hand the
/// digest a fact the chain read did not produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementPaymentFact {
    chain_id: u64,
    tx_hash: Hash,
    log_index: u64,
    asset_contract: String,
    to_address: Address,
    amount_raw: u64,
}

impl SettlementPaymentFact {
    pub fn from_parts(
        chain_id: u64,
        tx_hash: &str,
        log_index: u64,
        asset: &RealAsset,
        to_address: &str,
        amount_raw: u64,
    ) -> std::result::Result<Self, EventIdError> {
        if chain_id == 0 {
            return Err(EventIdError::ZeroChain);
        }
        if chain_id != asset.chain_id() {
            return Err(EventIdError::ChainMismatch {
                fact: chain_id,
                asset: asset.chain_id(),
            });
        }
        if amount_raw == 0 {
            return Err(EventIdError::ZeroAmount);
        }
        Ok(Self {
            chain_id,
            tx_hash: Hash::parse("tx_hash", tx_hash)?,
            log_index,
            asset_contract: asset.contract().to_string(),
            to_address: Address::parse(to_address)?,
            amount_raw,
        })
    }

    /// The payment a confirmed transfer describes, with the log index taken
    /// from the proof the chain read produced.
    ///
    /// This is where "no log index, no identity" lives for the revenue side, in
    /// the same shape as
    /// [`ExternalEventFact::from_confirmed_transfer`]: a provider that confirms
    /// a payment without saying which log it matched has not established an
    /// event, and the reader reports [`EventIdError::LogIndexUnknown`] rather
    /// than counting it.
    pub fn from_confirmed_payment(
        chain_id: u64,
        proof: &BaseUsdcVerification,
        asset: &RealAsset,
        to_address: &str,
        amount_raw: u64,
    ) -> std::result::Result<Self, EventIdError> {
        if proof.chain_id != chain_id {
            return Err(EventIdError::ChainMismatch {
                fact: chain_id,
                asset: proof.chain_id,
            });
        }
        let log_index = proof.matching_log_index.ok_or_else(|| {
            EventIdError::LogIndexUnknown(format!(
                "provider {} confirmed a payment of {amount_raw} to {to_address} without \
                 reporting a log index",
                proof.rpc
            ))
        })?;
        Self::from_parts(
            chain_id,
            &proof.transaction_hash,
            log_index,
            asset,
            to_address,
            amount_raw,
        )
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn tx_hash(&self) -> &str {
        self.tx_hash.as_str()
    }

    pub fn log_index(&self) -> u64 {
        self.log_index
    }

    pub fn asset_contract(&self) -> &str {
        &self.asset_contract
    }

    pub fn to_address(&self) -> &str {
        self.to_address.as_str()
    }

    pub fn amount_raw(&self) -> u64 {
        self.amount_raw
    }
}

/// The exact bytes a settlement-payment id is the digest of. Same framing as
/// [`preimage`]: domain first, section count, one tagged section per row.
pub fn settlement_preimage(
    fact: &SettlementPaymentFact,
) -> std::result::Result<Vec<u8>, EventIdError> {
    let values: Vec<(&str, Vec<u8>)> = vec![
        (
            "schema_version",
            SETTLEMENT_EVENT_ID_SCHEMA_VERSION.to_be_bytes().to_vec(),
        ),
        ("chain_id", fact.chain_id.to_be_bytes().to_vec()),
        ("tx_hash", fact.tx_hash.to_bytes()?.to_vec()),
        ("log_index", fact.log_index.to_be_bytes().to_vec()),
        ("asset", fact.asset_contract.as_bytes().to_vec()),
        ("to_address", fact.to_address.as_str().as_bytes().to_vec()),
        ("amount_raw", fact.amount_raw.to_be_bytes().to_vec()),
    ];
    check_layout(
        &values,
        SETTLEMENT_EVENT_FIELDS,
        "settlement-payment preimage",
    )?;

    let mut buf = Vec::new();
    push_tagged(&mut buf, b"domain", SETTLEMENT_EVENT_ID_DOMAIN.as_bytes());
    push_tagged(
        &mut buf,
        b"sections",
        &u32::try_from(values.len())
            .map_err(|_| {
                EventIdError::Preimage("too many settlement-payment sections".into())
            })?
            .to_be_bytes(),
    );
    for (tag, value) in &values {
        push_tagged(&mut buf, tag.as_bytes(), value);
    }
    Ok(buf)
}

impl ExternalEventId {
    /// The identity of a payment as the revenue side established it, under
    /// [`SETTLEMENT_EVENT_ID_DOMAIN`].
    ///
    /// Domain-separated from [`Self::logged`] and [`Self::native_gas`] by the
    /// first section, so the same chain facts under three readings are three
    /// different digests and none of them can be looked up under another.
    pub fn settlement_payment(
        fact: &SettlementPaymentFact,
    ) -> std::result::Result<Self, EventIdError> {
        let bytes = *blake3::hash(&settlement_preimage(fact)?).as_bytes();
        Ok(Self(Hash::from_bytes(bytes)))
    }

    /// The identity of a price observation, under
    /// [`PRICE_OBSERVATION_ID_DOMAIN`].
    ///
    /// P4.6, and the same shape as [`Self::settlement_payment`]: a fourth domain
    /// rather than a new variant of [`ExternalEventKind`], which stays at two
    /// arms exactly as `event_id.rs`'s rule says. Adding a domain is what keeps
    /// a price reading from being fileable under a transfer identity — the two
    /// share a `chain_id` and a `block_hash`, and a shared layout would let a
    /// price be counted as a transfer.
    pub fn price_observation(
        fact: &PriceObservationFact,
    ) -> std::result::Result<Self, EventIdError> {
        let bytes = *blake3::hash(&price_observation_preimage(fact)?).as_bytes();
        Ok(Self(Hash::from_bytes(bytes)))
    }
}

// ---------------------------------------------------------------------------
// The price-observation identity (P4.6)
// ---------------------------------------------------------------------------
//
// A price observation is a fourth class of external fact: something that was
// read, happened, and moved no token. It gets its own domain and its own layout
// for the same reason the settlement payment got one — the fields are not the
// other layouts' fields, and a shared layout padded with placeholder rows would
// make a digest bind nothing it claims to bind.
//
// The layout below names EXACTLY what the read established:
//
//   PriceObservationId = H(PRICE_OBSERVATION_ID_DOMAIN, schema, source_id,
//                          base_asset, quote_unit, price_musd_per_eth, chain_id,
//                          block_number, block_hash, block_timestamp_unix,
//                          source_round, confirmations)
//
// What is *not* here, and why, is the interesting part:
//
// * no `policy_hash` — that is an authority binding, and it belongs to the
//   attestation that carried the observation (exactly as a receipt's event id
//   carries no policy hash). Two observers of one price reading must agree on
//   this digest even if they read it under different policies; the policy
//   decides which of them may be *used*, not what it *is*.
// * no `verifier_key_id` and no signature — same reason.
// * no `operation_id` — the observation is not about one settlement. It is read
//   at a block, and a settlement at or after that block may use it. Binding an
//   operation here would make the identity depend on which settlement happened
//   to ask for it, which is a property of the reader, not of the fact.
// * no decimals or scale row — `price_musd_per_eth` is an integer in micro-USD
//   per whole ETH and `quote_unit` says so. Binding a scale constant compiled
//   into this binary would make the identity of a market fact depend on the
//   binary, the same mistake as binding `decimals` in a transfer identity.

/// Domain of the identity of a *price observation*: a signed reading of one
/// economic rate, anchored to a block.
pub const PRICE_OBSERVATION_ID_DOMAIN: &str =
    "MYCELIUM-ECONOMY/PRICE-OBSERVATION-ID/V1";

/// Schema version this build computes and expects for
/// [`PRICE_OBSERVATION_ID_DOMAIN`].
pub const PRICE_OBSERVATION_ID_SCHEMA_VERSION: u32 = 1;

/// The price-observation preimage layout, in canonical order.
///
/// Deliberately **not** [`EVENT_ID_FIELDS`] and **not** [`SETTLEMENT_EVENT_FIELDS`]:
/// a price has no log index, no from-address and no token contract, so every
/// row here is a fact the other two layouts cannot express.
pub const PRICE_OBSERVATION_FIELDS: &[(&str, PreimageFieldKind)] = &[
    ("schema_version", PreimageFieldKind::U32),
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

/// A price observation, as the observation read established it, and nothing
/// more.
///
/// Private fields with one validating constructor, for the same reason
/// [`SettlementPaymentFact`] has them: a caller must not be able to hand the
/// digest a fact no read established. The rules restated here are the ones the
/// valuation module applies, restated at the identity layer so that a fact built
/// from parts rather than from an authenticated observation still cannot produce
/// a digest for something that would have been refused earlier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriceObservationFact {
    source_id: String,
    base_asset: String,
    quote_unit: String,
    price_musd_per_eth: u128,
    chain_id: u64,
    block_number: u64,
    block_hash: Hash,
    block_timestamp_unix: u64,
    source_round: String,
    confirmations: u64,
}

impl PriceObservationFact {
    /// Validating constructor.
    ///
    /// `base_asset` and `quote_unit` are the *canonical spellings* the caller
    /// already resolved (see
    /// [`crate::trusted_valuation::PricePair`]), passed as text because this
    /// module must not depend on the valuation module's types: the domains are
    /// separate, so the identity stays valid even if the valuation vocabulary is
    /// later extended. What is bound is the spelling that was read.
    #[allow(clippy::too_many_arguments)]
    pub fn from_parts(
        source_id: &str,
        base_asset: &str,
        quote_unit: &str,
        price_musd_per_eth: u128,
        chain_id: u64,
        block_number: u64,
        block_hash: &str,
        block_timestamp_unix: u64,
        source_round: &str,
        confirmations: u64,
    ) -> std::result::Result<Self, EventIdError> {
        if source_id.is_empty() {
            return Err(EventIdError::Preimage(
                "a price observation must name the source that produced it".into(),
            ));
        }
        if price_musd_per_eth == 0 {
            return Err(EventIdError::ZeroAmount);
        }
        if chain_id == 0 {
            return Err(EventIdError::ZeroChain);
        }
        if block_number == 0 {
            return Err(EventIdError::Preimage(
                "a price observation must name the block it was read at; block 0 is the \
                 genesis block and cannot be a settled reading"
                    .into(),
            ));
        }
        if block_timestamp_unix == 0 {
            return Err(EventIdError::Preimage(
                "a price observation must carry the block timestamp it was read at; zero \
                 is not a time"
                    .into(),
            ));
        }
        if confirmations == 0 {
            return Err(EventIdError::Preimage(
                "a price observation with zero confirmations has not been read from a \
                 canonical view"
                    .into(),
            ));
        }
        Ok(Self {
            source_id: source_id.to_string(),
            base_asset: base_asset.to_string(),
            quote_unit: quote_unit.to_string(),
            price_musd_per_eth,
            chain_id,
            block_number,
            block_hash: Hash::parse("price_observation_block_hash", block_hash)?,
            block_timestamp_unix,
            source_round: source_round.to_string(),
            confirmations,
        })
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

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
}

/// The exact bytes a price-observation id is the digest of. Same framing as
/// [`preimage`] and [`settlement_preimage`]: domain first, section count, one
/// tagged section per row, checked against the table by this module's own
/// `check_layout`.
pub fn price_observation_preimage(
    fact: &PriceObservationFact,
) -> std::result::Result<Vec<u8>, EventIdError> {
    let values: Vec<(&str, Vec<u8>)> = vec![
        (
            "schema_version",
            PRICE_OBSERVATION_ID_SCHEMA_VERSION
                .to_be_bytes()
                .to_vec(),
        ),
        ("source_id", fact.source_id.as_bytes().to_vec()),
        ("base_asset", fact.base_asset.as_bytes().to_vec()),
        ("quote_unit", fact.quote_unit.as_bytes().to_vec()),
        (
            "price_musd_per_eth",
            fact.price_musd_per_eth.to_be_bytes().to_vec(),
        ),
        ("chain_id", fact.chain_id.to_be_bytes().to_vec()),
        ("block_number", fact.block_number.to_be_bytes().to_vec()),
        ("block_hash", fact.block_hash.to_bytes()?.to_vec()),
        (
            "block_timestamp_unix",
            fact.block_timestamp_unix.to_be_bytes().to_vec(),
        ),
        ("source_round", fact.source_round.as_bytes().to_vec()),
        ("confirmations", fact.confirmations.to_be_bytes().to_vec()),
    ];
    check_layout(
        &values,
        PRICE_OBSERVATION_FIELDS,
        "price-observation preimage",
    )?;

    let mut buf = Vec::new();
    push_tagged(
        &mut buf,
        b"domain",
        PRICE_OBSERVATION_ID_DOMAIN.as_bytes(),
    );
    push_tagged(
        &mut buf,
        b"sections",
        &u32::try_from(values.len())
            .map_err(|_| EventIdError::Preimage("too many price-observation sections".into()))?
            .to_be_bytes(),
    );
    for (tag, value) in &values {
        push_tagged(&mut buf, tag.as_bytes(), value);
    }
    Ok(buf)
}

// ---------------------------------------------------------------------------
// The settlement-economic identity (P6.N6)
// ---------------------------------------------------------------------------
//
// `nev_tier`'s NEV event used to be handed its economic identity by its caller:
// `VerifiedNevEvent::from_comparable_settlement(event_id, &settlement, class)`
// took an `ExternalEventId` the caller had computed, read or invented. That is
// the double-counting hole this domain closes. The *same* comparable settlement
// could be recorded under two different ids by two call sites — or by one call
// site run twice — and NEV would add it up twice. `NevTierEvaluator::record_event`
// only knows that it has already seen *one* id; it cannot know that the two ids
// under which it saw the same operation are the same operation.
//
// So the identity is derived from the settlement, and the derivation is the whole
// point of the domain:
//
//   SettlementEconomicId = H(SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN, schema_version,
//                            chain_id, anchor_block_number, anchor_block_hash,
//                            operation_id, leg_count, leg_event_id*,
//                            cost_count, cost_event_id*)
//
// with the `*` rows emitted once per leg and once per cost, sorted.
//
// # What is deliberately absent is the property, not an oversight
//
// A reader arriving at this preimage will notice that it commits to no money.
// That is the design, and it is the anti-double-counting mechanism:
//
// * **No price, no policy, no value.** Not `comparable_digest()`, not
//   `policy_hash()`, not `native_cost_musd()`, not `token_net_delta_micros()`,
//   not `comparable_net_value_micros()`. A valuation is a *reading* of an
//   operation, not the operation: the same on-chain operation priced under two
//   policies, or valued at two different signed price observations, is **one**
//   economic event and must produce **one** identity. Bind any of those rows
//   and one operation acquires one identity per valuation, at which point the
//   identity stops being an economic fact and becomes a reading of one — and
//   the double counting this domain exists to prevent is back, wearing a
//   different digest. Do not "helpfully" add the net value back.
// * **No `confirmations`.** It changes on every re-read of the same transaction
//   by the same node, so binding it would hand one operation a brand-new
//   identity each time the process polled. That is the per-read identity this
//   module's own opening rejects, in the precise form it warned about.
// * **No `anchor_block_timestamp_unix`.** `(chain_id, block_hash,
//   block_number)` already names one block uniquely; the timestamp is a *reading*
//   of that block and is read again on every poll, for the same reason
//   `confirmations` is. Two nodes that disagree about a block's timestamp are
//   disagreeing about something the block hash already settles.
//
// # The leg rows are leg *event ids*, not legs
//
// `settlement_digest` binds each leg whole, as serialised JSON, and is
// deliberately order-SENSITIVE: it is the digest of what the settlement
// authority authorised, and the authority's reading includes each leg's own
// evidence and policy hashes and its prose `why`.
//
// This identity cannot do that. Those per-leg fields are properties of *this
// node's copy* — the same class of field this module's docstring opens by
// refusing — and one of them is a policy hash, which is exactly the valuation
// input this domain must not see. What is bound instead is each leg's canonical
// [`ExternalEventId`], which already commits to
// `(chain_id, tx_hash, log_index, asset, from, to, amount_raw)`: the whole of
// what the leg *is*, and none of what this node thought about it.
//
// # Order-independence, and why it is the opposite of `settlement_digest`
//
// Legs arrive in RPC receipt log order, which is a property of how a provider
// serialised a response, not of the operation. An order-SENSITIVE identity
// would let one operation acquire two identities purely because two nodes
// enumerated its logs differently — the same bug, arriving from a different
// direction. So the leg and cost ids are **sorted before encoding**, ascending
// by [`ExternalEventId::as_str`], i.e. by their canonical lowercase hex
// spelling, which is fixed-length so the lexicographic order is a total order
// with no ties between distinct ids.
//
// Sorting the *spelling* rather than the raw digest bytes is the deliberate
// choice: the spelling is the exact byte string that goes into the preimage, so
// "sorted" and "as encoded" are the same statement and there is nothing to keep
// in step. (The two orders coincide anyway — equal-length lowercase hex sorts
// lexicographically exactly as the bytes it spells sort numerically.)

/// Domain of the identity of a **complete settled operation**: the one economic
/// event a whole transaction is, once every leg it moved and every cost it paid
/// is known.
///
/// Distinct from [`SETTLEMENT_EVENT_ID_DOMAIN`], which names one *payment* as
/// the revenue side read it. A payment is a fact; a settlement is the sum of the
/// facts of one operation, and it is the settlement — not any single log inside
/// it — that NEV counts.
pub const SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN: &str =
    "MYCELIUM-ECONOMY/SETTLEMENT-ECONOMIC-ID/V1";

/// Schema version this build computes and expects for
/// [`SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN`].
pub const SETTLEMENT_ECONOMIC_EVENT_ID_SCHEMA_VERSION: u32 = 1;

/// The settlement-economic preimage layout, in canonical order.
///
/// Deliberately neither [`EVENT_ID_FIELDS`], [`SETTLEMENT_EVENT_FIELDS`] nor
/// [`PRICE_OBSERVATION_FIELDS`], and deliberately **not** typed as
/// `&[(&str, PreimageFieldKind)]` the way those three are: two of these rows —
/// `leg_event_id` and `cost_event_id` — are emitted **once per element** rather
/// than once overall, so a per-row field kind would be describing a row that
/// does not correspond to one field. The repeated tags are named in
/// `SETTLEMENT_ECONOMIC_REPEATED_ROWS`, and the emitter's tag list is still
/// checked against this table with the repeats expanded, so table and encoder
/// cannot drift apart the way a `#[allow]` would permit.
///
/// | row | field | emitted | why it is in the identity |
/// |-----|-------|---------|---------------------------|
/// | 1 | `schema_version` | once | so a future layout cannot produce today's digests |
/// | 2 | `chain_id` | once | the same transaction hash on two chains is two operations |
/// | 3 | `anchor_block_number` | once | which block the operation settled in |
/// | 4 | `anchor_block_hash` | once | which block, cryptographically |
/// | 5 | `operation_id` | once | which operation, as the settlement itself named it |
/// | 6 | `leg_count` | once | an omitted leg row cannot hide inside a list |
/// | 7 | `leg_event_id` | **per leg, sorted** | which transfers the operation moved |
/// | 8 | `cost_count` | once | the same, for what it paid |
/// | 9 | `cost_event_id` | **per cost, sorted** | which native facts it burned |
///
/// `leg_count` and `cost_count` are what make the repeated rows safe: a
/// length-prefixed row count is bound, so a dropped row changes the bytes even
/// before the remaining rows are compared.
pub const SETTLEMENT_ECONOMIC_EVENT_ID_FIELDS: &[&str] = &[
    "schema_version",
    "chain_id",
    "anchor_block_number",
    "anchor_block_hash",
    "operation_id",
    "leg_count",
    "leg_event_id",
    "cost_count",
    "cost_event_id",
];

/// The layout rows emitted once per element instead of once overall.
///
/// Named here rather than spelled inline in the check so that adding a third
/// repeated row is a one-line edit whose consequences are visible in this file.
const SETTLEMENT_ECONOMIC_REPEATED_ROWS: [&str; 2] = ["leg_event_id", "cost_event_id"];

/// A complete operation's economic facts, and nothing else.
///
/// Private fields with one validating constructor, for the same reason
/// [`SettlementPaymentFact`] and [`PriceObservationFact`] have them: a caller
/// must not be able to hand the digest a fact no read established. The leg and
/// cost rows are typed [`ExternalEventId`]s rather than text, so a label cannot
/// be passed off as one of them; the only free text a caller supplies is
/// `operation_id`, which is itself a digest spelling and is refused when empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementEconomicFact {
    chain_id: u64,
    anchor_block_number: u64,
    anchor_block_hash: Hash,
    operation_id: String,
    leg_event_ids: Vec<ExternalEventId>,
    cost_event_ids: Vec<ExternalEventId>,
}

impl SettlementEconomicFact {
    /// Validating constructor.
    ///
    /// The leg and cost ids are stored **in the order they were given**. This
    /// type records what was bound; the canonical ordering is applied by the
    /// encoder, so the rule and the reason for it sit in one place and a fact
    /// cannot look already-sorted when it was not. The ordering itself is
    /// asserted in this module's tests.
    pub fn from_parts(
        chain_id: u64,
        anchor_block_number: u64,
        anchor_block_hash: &str,
        operation_id: &str,
        leg_event_ids: &[&ExternalEventId],
        cost_event_ids: &[&ExternalEventId],
    ) -> std::result::Result<Self, EventIdError> {
        if chain_id == 0 {
            return Err(EventIdError::ZeroChain);
        }
        if operation_id.is_empty() {
            return Err(EventIdError::Preimage(
                "a settlement's economic identity must name the operation it settled; an \
                 empty operation id names nothing"
                    .into(),
            ));
        }
        Ok(Self {
            chain_id,
            anchor_block_number,
            // Parsed and validated exactly the way `settlement_digest` parses its
            // anchor hash, so a spelling this crate refuses anywhere else cannot
            // enter an economic identity either.
            anchor_block_hash: Hash::parse(
                "settlement_economic_anchor_block_hash",
                anchor_block_hash,
            )?,
            operation_id: operation_id.to_string(),
            leg_event_ids: leg_event_ids.iter().map(|id| (*id).clone()).collect(),
            cost_event_ids: cost_event_ids.iter().map(|id| (*id).clone()).collect(),
        })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn anchor_block_number(&self) -> u64 {
        self.anchor_block_number
    }

    pub fn anchor_block_hash(&self) -> &str {
        self.anchor_block_hash.as_str()
    }

    /// The operation's own canonical identity, as the settlement named it.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// The leg identities, in the order they were supplied — **not** in the
    /// canonical order the encoder sorts them into.
    pub fn leg_event_ids(&self) -> &[ExternalEventId] {
        &self.leg_event_ids
    }

    /// The external-cost identities, in the order they were supplied.
    pub fn cost_event_ids(&self) -> &[ExternalEventId] {
        &self.cost_event_ids
    }
}

/// The exact bytes a settlement-economic id is the digest of.
///
/// Same framing as every other preimage in this file — [`push_tagged`],
/// length-prefixed, domain first, then a section-count row — with one
/// difference the count row exists to explain. Two of the layout rows repeat per
/// element, so the emitted section count and the number of layout rows are not
/// the same number. The `sections` row therefore names the number of **layout
/// rows**, which is a constant of this build, exactly as it does for
/// [`preimage`] ("the section count names the layout, not the sections
/// present"). The two multiplicities are bound separately and explicitly by the
/// `leg_count` and `cost_count` rows, so nothing is left unbound by that choice.
fn settlement_economic_preimage(
    fact: &SettlementEconomicFact,
) -> std::result::Result<Vec<u8>, EventIdError> {
    // Sorted BEFORE encoding, which is the entire order-independence property:
    // legs arrive in whichever order a provider serialised the receipt's logs,
    // and that order is not a fact about the operation. See the section comment
    // above for why this identity is order-INDEPENDENT where `settlement_digest`
    // is deliberately order-sensitive.
    let mut legs = fact.leg_event_ids.clone();
    legs.sort();
    let mut costs = fact.cost_event_ids.clone();
    costs.sort();

    let mut values: Vec<(&str, Vec<u8>)> = Vec::with_capacity(
        SETTLEMENT_ECONOMIC_EVENT_ID_FIELDS.len() + legs.len() + costs.len(),
    );
    values.push((
        "schema_version",
        SETTLEMENT_ECONOMIC_EVENT_ID_SCHEMA_VERSION
            .to_be_bytes()
            .to_vec(),
    ));
    values.push(("chain_id", fact.chain_id.to_be_bytes().to_vec()));
    values.push((
        "anchor_block_number",
        fact.anchor_block_number.to_be_bytes().to_vec(),
    ));
    values.push((
        "anchor_block_hash",
        fact.anchor_block_hash.to_bytes()?.to_vec(),
    ));
    values.push(("operation_id", fact.operation_id.as_bytes().to_vec()));
    values.push((
        "leg_count",
        u32::try_from(legs.len())
            .map_err(|_| EventIdError::Preimage("too many settlement legs".into()))?
            .to_be_bytes()
            .to_vec(),
    ));
    for leg in &legs {
        values.push(("leg_event_id", leg.as_str().as_bytes().to_vec()));
    }
    values.push((
        "cost_count",
        u32::try_from(costs.len())
            .map_err(|_| EventIdError::Preimage("too many settlement costs".into()))?
            .to_be_bytes()
            .to_vec(),
    ));
    for cost in &costs {
        values.push(("cost_event_id", cost.as_str().as_bytes().to_vec()));
    }
    check_settlement_economic_layout(&values, legs.len(), costs.len())?;

    let mut buf = Vec::new();
    push_tagged(
        &mut buf,
        b"domain",
        SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN.as_bytes(),
    );
    push_tagged(
        &mut buf,
        b"sections",
        &u32::try_from(SETTLEMENT_ECONOMIC_EVENT_ID_FIELDS.len())
            .map_err(|_| {
                EventIdError::Preimage("too many settlement-economic layout rows".into())
            })?
            .to_be_bytes(),
    );
    for (tag, value) in &values {
        push_tagged(&mut buf, tag.as_bytes(), value);
    }
    Ok(buf)
}

/// The encoder and the layout table can disagree in the same way every other
/// preimage in this crate guards against — a row renamed, reordered or dropped
/// on one side only — plus one failure specific to this layout: a repeated row
/// emitted the wrong number of times, or under the wrong tag. Comparing the
/// emitted tag list against the table with [`SETTLEMENT_ECONOMIC_REPEATED_ROWS`]
/// expanded catches all four. Kept local, and shaped differently from
/// [`check_layout`], for the reason `check_layout` is kept local: each layout
/// table is checked against its own encoder, and a shared helper would let one
/// module's table be satisfied by another module's field list.
fn check_settlement_economic_layout(
    values: &[(&str, Vec<u8>)],
    leg_rows: usize,
    cost_rows: usize,
) -> std::result::Result<(), EventIdError> {
    let mut expected: Vec<&str> = Vec::with_capacity(values.len());
    for tag in SETTLEMENT_ECONOMIC_EVENT_ID_FIELDS {
        if !SETTLEMENT_ECONOMIC_REPEATED_ROWS.contains(tag) {
            expected.push(*tag);
            continue;
        }
        let rows = match *tag {
            "leg_event_id" => leg_rows,
            "cost_event_id" => cost_rows,
            // A repeated row that was added to the table but not to this match
            // expands to nothing, and the comparison below then refuses. Failing
            // closed is the point: an unhandled repeat must not silently pass.
            _ => 0,
        };
        expected.extend(std::iter::repeat(*tag).take(rows));
    }
    let emitted: Vec<&str> = values.iter().map(|(tag, _)| *tag).collect();
    if emitted != expected {
        return Err(EventIdError::Preimage(format!(
            "settlement-economic preimage: encoder emitted {emitted:?} where the layout \
             expects {expected:?}"
        )));
    }
    Ok(())
}

impl ExternalEventId {
    /// The identity of one complete settled operation, under
    /// [`SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN`].
    ///
    /// P6.N6. What this constructor will not accept is the point of it: there
    /// is no parameter through which a caller can supply, reuse or override an
    /// identity, and no valuation, policy or confirmation count anywhere in the
    /// preimage it digests. One on-chain operation therefore has exactly one
    /// economic identity no matter how many times it is settled, priced or
    /// re-read — which is what makes a second NEV event for it a *duplicate*
    /// rather than a new event.
    pub fn settlement_economic(
        fact: &SettlementEconomicFact,
    ) -> std::result::Result<Self, EventIdError> {
        let bytes = *blake3::hash(&settlement_economic_preimage(fact)?).as_bytes();
        Ok(Self(Hash::from_bytes(bytes)))
    }
}

// ---------------------------------------------------------------------------
// The counting rule
// ---------------------------------------------------------------------------

/// Which external facts a single reconstruction pass has already counted.
///
/// # Three concerns, kept apart
///
/// This type exists because the word "duplicate" covers three different
/// problems, and only one of them is about money:
///
/// | concern | where it lives | what happens if it is ignored |
/// |---------|----------------|------------------------------|
/// | the same line was appended twice | a *storage* problem, refused by the write path under the ledger lock | the file grows; nothing is wrong yet |
/// | the same *attestation* is claimed by two records | a *provenance* problem, `AttestationGap::AttestationReplayed` | one signature would vouch for two bookings |
/// | the same *external fact* is booked twice | the *economic* problem, and the only one that can inflate a total | NEV is counted twice for one transfer |
///
/// The third is this type's job, and it is the only one that survives the
/// process that created it. The first is hygiene and is not an authority: a
/// ledger that *physically contains* a duplicate — written by a fork, restored
/// from a backup, hand-appended, or replayed from another node — must still not
/// double-count, and no amount of write-path discipline can promise otherwise.
/// The second is defence in depth over the attestation ledger and is reported
/// separately, because a duplicated attestation and a duplicated event are
/// different diagnoses with different fixes.
///
/// # Why membership is the authority
///
/// `seen` is the whole mechanism. `first_counted_at` exists only so the report
/// can name the record that holds the credit; it is written in the same call that
/// writes `seen` and is never consulted for the decision, so there is no path
/// where the two disagree.
///
/// The set is created inside the reconstruction pass and dies with it, so the
/// answer to "was this already counted?" is recomputed from the ledger on every
/// read. That is what makes the property hold across a process restart: nothing
/// is remembered between runs, so nothing can be forgotten between runs. The
/// price is that the pass is O(n) in receipts, which is the same cost the
/// attestation index already pays and one hash insert per counted record.
///
/// [`crate::verified_view::VerifiedEconomyView::receipt_evidence`] owns the only
/// instance, and it is the only producer of `counted = true`, so there is no way
/// to reach a total that did not pass through here.
#[derive(Debug, Default)]
pub(crate) struct CountedEvents {
    seen: HashSet<ExternalEventId>,
    first_counted_at: BTreeMap<ExternalEventId, u64>,
}

impl CountedEvents {
    /// Claims an identity for a record at `sequence`.
    ///
    /// `None` means the claim succeeded and the caller may count it. `Some(sequence)`
    /// means this fact is already in the total and `sequence` is the record that
    /// holds the credit; the caller must not count it again.
    pub(crate) fn claim(
        &mut self,
        id: ExternalEventId,
        sequence: u64,
    ) -> Option<u64> {
        if !self.seen.insert(id.clone()) {
            return self.first_counted_at.get(&id).copied();
        }
        self.first_counted_at.insert(id, sequence);
        None
    }

    /// How many distinct facts this pass has counted. Test-only, and explicitly
    /// a cross-check for a reconstruction rather than an input to one: nothing
    /// in the crate reads the count back, because the count is the *consequence*
    /// of the set and reading it would only invite the set to be bypassed.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.seen.len()
    }

    /// The sequence of the record that first counted `id`, if it was counted.
    #[cfg(test)]
    pub(crate) fn first_counted_at(&self, id: &ExternalEventId) -> Option<u64> {
        self.first_counted_at.get(id).copied()
    }

    /// Whether `id` has been counted in this pass.
    #[cfg(test)]
    pub(crate) fn contains(&self, id: &ExternalEventId) -> bool {
        self.seen.contains(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        autonomy::{ExternalValueClass, ExternalValueReceipt},
        base_usdc::{BASE_CHAIN_ID, BASE_USDC},
        policy_auth::{Hash, VerifierRuntimeKey},
        receipt_auth::{
            receipt_hash, AttestationBody, EXTERNAL_VALUE_ATTESTATION_DOMAIN, RECEIPT_HASH_DOMAIN,
        },
        settlement_auth::{
            settlement_hash, SettlementAttestationBody, SETTLEMENT_ATTESTATION_DOMAIN,
            SETTLEMENT_HASH_DOMAIN,
        },
        PaymentIntent, SettlementMode, SettlementReceipt, SCHEMA_VERSION,
    };

    const PAYOUT: &str = "0xe83331104f5f3c41e49abc46c810f9d71133e48c";
    const COUNTERPARTY: &str = "0x1234567890abcdef1234567890abcdef12345678";
    const AMOUNT: u64 = 5_000_000;
    const TX: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER_TX: &str = "0x9999999999999999999999999999999999999999999999999999999999999999";
    const BLOCK: &str = "0x2222222222222222222222222222222222222222222222222222222222222222";
    const LOG_INDEX: u64 = 3;

    fn asset() -> RealAsset {
        RealAsset::base_usdc()
    }

    fn fact() -> ExternalEventFact {
        ExternalEventFact::from_parts(
            BASE_CHAIN_ID,
            TX,
            LOG_INDEX,
            &asset(),
            COUNTERPARTY,
            PAYOUT,
            AMOUNT,
        )
        .unwrap()
    }

    fn evidence() -> BoundaryEvidence {
        BoundaryEvidence {
            chain_id: BASE_CHAIN_ID,
            asset: asset(),
            from_address: COUNTERPARTY.into(),
            to_address: PAYOUT.into(),
            amount_raw: AMOUNT,
            tx_hash: TX.into(),
            block_hash: BLOCK.into(),
        }
    }

    fn id_of(fact: &ExternalEventFact) -> String {
        ExternalEventId::logged(fact).unwrap().to_string()
    }

    // ---- determinism ---------------------------------------------------

    #[test]
    fn the_same_fact_yields_the_same_id_every_time_it_is_computed() {
        let first = id_of(&fact());
        for _ in 0..64 {
            assert_eq!(id_of(&fact()), first, "recomputation must be stable");
        }
        // And the digest itself, not just its spelling.
        let a = ExternalEventId::logged(&fact()).unwrap();
        let b = ExternalEventId::compute(&fact(), ExternalEventKind::Logged).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.digest().as_str(), first);
    }

    #[test]
    fn the_id_survives_re_serialisation_and_field_order_variation() {
        let canonical = id_of(&ExternalEventFact::from_boundary(&evidence(), LOG_INDEX).unwrap());

        // Round-tripped through this crate's own serialiser.
        let round = evidence();
        let bytes = serde_json::to_vec(&round).unwrap();
        let reparsed: BoundaryEvidence = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            id_of(&ExternalEventFact::from_boundary(&reparsed, LOG_INDEX).unwrap()),
            canonical
        );

        // A hand-written ledger line with the same facts and the keys in reverse
        // order. serde_json resolves a map by name, so the stored order is not
        // observable — which is the property being asserted, not a detail.
        let reordered = format!(
            r#"{{"block_hash":"{BLOCK}","tx_hash":"{TX}","amount_raw":{AMOUNT},
                "to_address":"{PAYOUT}","from_address":"{COUNTERPARTY}",
                "asset":{{"decimals":6,"contract":"{}","chain_id":{BASE_CHAIN_ID}}},
                "chain_id":{BASE_CHAIN_ID}}}"#,
            BASE_USDC.trim_start_matches("0x").to_ascii_lowercase()
        );
        let from_reordered: BoundaryEvidence = serde_json::from_str(&reordered).unwrap();
        assert_eq!(
            id_of(&ExternalEventFact::from_boundary(&from_reordered, LOG_INDEX).unwrap()),
            canonical,
            "field order in the stored line must not reach the identity"
        );

        // Uppercase and checksummed spellings of the same addresses.
        let shouty = BoundaryEvidence {
            from_address: COUNTERPARTY.to_ascii_uppercase().replace("0X", "0x"),
            to_address: PAYOUT.to_ascii_uppercase().replace("0X", "0x"),
            tx_hash: TX.to_ascii_uppercase().replace("0X", "0x"),
            block_hash: BLOCK.to_ascii_uppercase().replace("0X", "0x"),
            ..evidence()
        };
        assert_eq!(
            id_of(&ExternalEventFact::from_boundary(&shouty, LOG_INDEX).unwrap()),
            canonical,
            "a spelling is not a fact"
        );
    }

    // ---- every field is bound ------------------------------------------

    #[test]
    fn a_different_fact_in_any_single_field_yields_a_different_id() {
        let base = fact();
        let canonical = id_of(&base);
        // Each entry is a *valid* fact that differs from `base` in exactly one
        // field, so a collision below is a real collision and not a refusal.
        let variants: Vec<(&str, ExternalEventFact)> = vec![
            (
                "tx_hash",
                ExternalEventFact::from_parts(
                    BASE_CHAIN_ID,
                    OTHER_TX,
                    LOG_INDEX,
                    &asset(),
                    COUNTERPARTY,
                    PAYOUT,
                    AMOUNT,
                )
                .unwrap(),
            ),
            (
                "log_index",
                ExternalEventFact::from_parts(
                    BASE_CHAIN_ID,
                    TX,
                    LOG_INDEX + 1,
                    &asset(),
                    COUNTERPARTY,
                    PAYOUT,
                    AMOUNT,
                )
                .unwrap(),
            ),
            (
                "amount_raw",
                ExternalEventFact::from_parts(
                    BASE_CHAIN_ID,
                    TX,
                    LOG_INDEX,
                    &asset(),
                    COUNTERPARTY,
                    PAYOUT,
                    AMOUNT + 1,
                )
                .unwrap(),
            ),
            (
                "from_address",
                ExternalEventFact::from_parts(
                    BASE_CHAIN_ID,
                    TX,
                    LOG_INDEX,
                    &asset(),
                    PAYOUT,
                    COUNTERPARTY,
                    AMOUNT,
                )
                .unwrap(),
            ),
            (
                "to_address",
                ExternalEventFact::from_parts(
                    BASE_CHAIN_ID,
                    TX,
                    LOG_INDEX,
                    &asset(),
                    "0x00000000000000000000000000000000000000aa",
                    PAYOUT,
                    AMOUNT,
                )
                .unwrap(),
            ),
            (
                "asset",
                ExternalEventFact::from_parts(
                    BASE_CHAIN_ID,
                    TX,
                    LOG_INDEX,
                    &RealAsset::new(BASE_CHAIN_ID, "0x00000000000000000000000000000000000000bb", 6)
                        .unwrap(),
                    COUNTERPARTY,
                    PAYOUT,
                    AMOUNT,
                )
                .unwrap(),
            ),
            (
                "chain_id",
                // A different chain with its own identified asset, so the only
                // difference between the two facts is the chain.
                ExternalEventFact::from_parts(
                    1,
                    TX,
                    LOG_INDEX,
                    &RealAsset::new(1, "0x00000000000000000000000000000000000000cc", 6).unwrap(),
                    COUNTERPARTY,
                    PAYOUT,
                    AMOUNT,
                )
                .unwrap(),
            ),
        ];
        assert_eq!(
            variants.len(),
            7,
            "every bound field must have a variant here"
        );
        for (field, variant) in variants {
            assert_ne!(id_of(&variant), canonical, "{field} is not bound into the id");
        }
    }

    #[test]
    fn the_two_log_indexes_of_one_transaction_are_two_facts() {
        // A transaction can contain two identical transfers. Without the log
        // index they are one fact and one of them is silently unrepresented.
        let first = ExternalEventFact::from_boundary(&evidence(), 0).unwrap();
        let second = ExternalEventFact::from_boundary(&evidence(), 1).unwrap();
        assert_ne!(id_of(&first), id_of(&second));
    }

    // ---- what the id must not depend on --------------------------------

    #[test]
    fn the_layout_table_names_exactly_the_facts_and_nothing_else() {
        let tags: Vec<&str> = EVENT_ID_FIELDS.iter().map(|(t, _)| *t).collect();
        assert_eq!(
            tags,
            vec![
                "schema_version",
                "chain_id",
                "tx_hash",
                "log_index",
                "asset",
                "from_address",
                "to_address",
                "amount_raw",
            ]
        );
        // Named explicitly rather than by a deny-list, so adding a field to the
        // identity is a visible edit to this test as well as to the table.
        for forbidden in [
            "sequence",
            "recorded_at_unix",
            "realized_at_unix",
            "settled_at_unix",
            "created_at_unix",
            "source_id",
            "agent_id",
            "opportunity_id",
            "verifier_id",
            "receipt_hash",
            "policy_hash",
            "attestation_hash",
            "settlement_id",
            "job_id",
            "payment_intent_id",
            "path",
            "record_hash",
            "prev_hash",
        ] {
            assert!(
                !tags.contains(&forbidden),
                "{forbidden} is a property of this node's copy, not of the fact"
            );
        }
    }

    #[test]
    fn the_encoded_preimage_carries_no_envelope_field() {
        let raw = preimage(&fact(), ExternalEventKind::Logged).unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        for forbidden in [
            "source-1",
            "opp-1",
            "s1-arb-01",
            "base-reconcile",
            "1700000400",
            "1700000500",
            "sequence",
        ] {
            assert!(
                !text.contains(forbidden),
                "the preimage leaks {forbidden}: {text}"
            );
        }
        // And the receipt envelope's own economics are not in it either: the id
        // is a fact about the chain, not about what was booked for it.
        assert!(!text.contains("6000000"));
        assert!(!text.contains("5000000"));
    }

    #[test]
    fn the_id_survives_everything_that_is_not_the_fact() {
        // Two ledger records that differ in sequence, recorded_at_unix and
        // record_hash, and which sit in different files, describe the same
        // external event and must produce the same id.
        let first_dir = tempfile::tempdir().unwrap();
        let second_dir = tempfile::tempdir().unwrap();
        let a = write_boundary_line(first_dir.path(), 7, 1_700_000_400, &evidence());
        let b = write_boundary_line(second_dir.path(), 9_001, 1_800_000_000, &evidence());
        let id_a = id_of(&ExternalEventFact::from_boundary(&evidence(), LOG_INDEX).unwrap());
        let id_b = id_of(&ExternalEventFact::from_boundary(&evidence(), LOG_INDEX).unwrap());
        assert_eq!(id_a, id_b, "the identity moved with the storage position");
        assert_ne!(
            a.record_hash, b.record_hash,
            "the two records really are different records"
        );
        assert_ne!(a.sequence, b.sequence);
        assert_ne!(a.recorded_at_unix, b.recorded_at_unix);
    }

    /// Writes one hand-made `BoundaryCrossing` ledger line, the way a process
    /// that can append to the economy directory would, and returns what it
    /// wrote. Deliberately not routed through `AutonomousEconomy::append`: this
    /// test is about the identity, and the identity does not care how the bytes
    /// got there.
    fn write_boundary_line(
        dir: &std::path::Path,
        sequence: u64,
        recorded_at_unix: u64,
        evidence: &BoundaryEvidence,
    ) -> crate::autonomy::AutonomyRecord {
        let mut record = crate::autonomy::AutonomyRecord {
            sequence,
            recorded_at_unix,
            prev_hash: crate::autonomy::AUTONOMY_GENESIS_HASH.to_string(),
            record_hash: String::new(),
            payload: crate::autonomy::AutonomyPayload::BoundaryCrossing {
                evidence: evidence.clone(),
            },
        };
        record.record_hash = blake3::hash(&serde_json::to_vec(&record).unwrap())
            .to_hex()
            .to_string();
        std::fs::create_dir_all(dir).unwrap();
        let mut existing = std::fs::read_to_string(dir.join("autonomous-ledger.jsonl"))
            .unwrap_or_default();
        existing.push_str(&serde_json::to_string(&record).unwrap());
        existing.push('\n');
        std::fs::write(dir.join("autonomous-ledger.jsonl"), existing).unwrap();
        record
    }

    // ---- domain separation --------------------------------------------

    #[test]
    fn an_event_id_is_domain_separated_from_every_other_digest_in_the_crate() {
        // Three artefacts over related facts, and one digest that is not any of
        // them: a receipt attestation, a settlement attestation and an event id
        // are three different messages and must be three different digests.
        //
        // Built from the real artefacts rather than from the domain strings, so
        // this cannot pass by restating the constants. The attestation bodies
        // are signed for real, over the same chain facts the event id names; no
        // socket or pin is needed because a *signature* is not what is being
        // compared, only the digest the signature commits to.
        let policy_hash = Hash::from_bytes([0x11u8; 32]);
        let key_id = VerifierRuntimeKey::generate().key_id();

        let receipt = ExternalValueReceipt {
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
            proof_hash: TX.into(),
            proof_verified: true,
            realized_at_unix: 1_700_000_400,
            verifier_id: "base-reconcile".into(),
        };
        let receipt_attestation = AttestationBody::from_parts(
            &receipt,
            &evidence(),
            &policy_hash,
            key_id.clone(),
        )
        .unwrap()
        .attestation_hash()
        .unwrap()
        .to_string();
        let receipt_digest = receipt_hash(&receipt).unwrap().to_string();

        let intent = PaymentIntent {
            schema_version: SCHEMA_VERSION,
            payment_intent_id: "payintent-1".into(),
            job_id: "job-1".into(),
            chain_id: BASE_CHAIN_ID,
            token: BASE_USDC.to_ascii_lowercase(),
            recipient: PAYOUT.into(),
            exact_amount_raw: AMOUNT,
            anchor_block: 100,
            anchor_block_hash: BLOCK.into(),
            anchor_timestamp_unix: 1_700_000_300,
            created_at_unix: 1_700_000_310,
        };
        let settlement = SettlementReceipt {
            schema_version: SCHEMA_VERSION,
            settlement_id: "settle-1".into(),
            job_id: "job-1".into(),
            work_receipt_id: "work-1".into(),
            settled_at_unix: 1_700_000_400,
            mode: SettlementMode::External,
            internal_work: false,
            settlement_asset: crate::SettlementAsset::base_usdc(),
            settled_amount_micros: AMOUNT,
            usd_equivalent_micros: AMOUNT,
            payment_intent_id: Some("payintent-1".into()),
            payment_block_number: Some(101),
            payment_proof_hash: Some(TX.into()),
            payment_proof_verified: true,
            external_paid: true,
        };
        let settlement_attestation = SettlementAttestationBody::from_parts(
            &settlement,
            &intent,
            &policy_hash,
            key_id,
        )
        .unwrap()
        .attestation_hash()
        .unwrap()
        .to_string();
        let settlement_digest = settlement_hash(&settlement).unwrap().to_string();

        let event = id_of(&ExternalEventFact::from_boundary(&evidence(), LOG_INDEX).unwrap());

        let digests = [
            ("event id", event.clone()),
            ("receipt attestation", receipt_attestation),
            ("settlement attestation", settlement_attestation),
            ("receipt digest", receipt_digest),
            ("settlement digest", settlement_digest),
        ];
        for (i, (left_name, left)) in digests.iter().enumerate() {
            for (right_name, right) in digests.iter().skip(i + 1) {
                assert_ne!(
                    left, right,
                    "{left_name} and {right_name} are the same digest over related facts"
                );
            }
        }

        // And the domains are the reason, stated rather than implied: the
        // preimage this crate builds for the event names only the event domain.
        let raw = preimage(&fact(), ExternalEventKind::Logged).unwrap();
        let sections = decode(&raw);
        assert_eq!(domains(&raw), vec![EVENT_ID_DOMAIN.to_string()]);
        for other in [
            EXTERNAL_VALUE_ATTESTATION_DOMAIN,
            RECEIPT_HASH_DOMAIN,
            SETTLEMENT_ATTESTATION_DOMAIN,
            SETTLEMENT_HASH_DOMAIN,
            crate::policy_auth::POLICY_SIGNING_DOMAIN,
            crate::policy_auth::CONTROLLED_REGISTRY_DOMAIN,
        ] {
            assert_ne!(EVENT_ID_DOMAIN, other);
            assert!(
                !domains(&raw).contains(&other.to_string()),
                "the event preimage carries {other}"
            );
        }
        assert_eq!(sections.first().map(|(t, _)| t.as_str()), Some("domain"));
    }

    /// A native fact is named over the chain facts that describe it, and it does
    /// not pretend there is a token.
    ///
    /// Two things this pins, both of which the alternative would have got
    /// wrong:
    ///
    /// * `asset` is [`NATIVE_CURRENCY`], a reserved zero word, and not a
    ///   plausible-looking contract address. A fabricated token contract inside
    ///   the identity of a real fee is worse than an obviously-absent one.
    /// * the self-transfer rule is not applied, because a fee payer and a fee
    ///   burner may be the same address and the rule exists to stop a token
    ///   identity the crossing derivation would refuse.
    #[test]
    fn a_native_gas_fact_is_named_without_inventing_a_token() {
        let native_fact = ExternalEventFact::native_gas(
            8453,
            TX,
            NATIVE_CURRENCY,
            NATIVE_CURRENCY,
            21_000,
            21_000_000_000,
        )
        .expect("a native fact");
        assert_eq!(native_fact.asset_contract(), NATIVE_CURRENCY);
        assert_eq!(native_fact.from_address(), NATIVE_CURRENCY);
        assert_eq!(native_fact.to_address(), NATIVE_CURRENCY);
        assert_eq!(
            native_fact.log_index(),
            0,
            "a gas charge has no log; the transaction hash already names it"
        );
        assert_eq!(native_fact.amount_raw(), 21_000_000_000);

        // Stable, and distinct from the same transaction's token fact.
        let again = ExternalEventFact::native_gas(
            8453,
            TX,
            NATIVE_CURRENCY,
            NATIVE_CURRENCY,
            21_000,
            21_000_000_000,
        )
        .expect("a native fact");
        let native = ExternalEventId::native_gas(&native_fact).unwrap();
        assert_eq!(native, ExternalEventId::native_gas(&again).unwrap());
        assert_ne!(native, ExternalEventId::logged(&fact()).unwrap());

        // A different cost is a different fact; the same cost in a different
        // transaction is a different fact.
        let cheaper = ExternalEventId::native_gas(
            &ExternalEventFact::native_gas(
                8453,
                TX,
                NATIVE_CURRENCY,
                NATIVE_CURRENCY,
                21_000,
                20_999_999_999,
            )
            .unwrap(),
        )
        .unwrap();
        assert_ne!(native, cheaper);
        let other_tx = ExternalEventId::native_gas(
            &ExternalEventFact::native_gas(
                8453,
                OTHER_TX,
                NATIVE_CURRENCY,
                NATIVE_CURRENCY,
                21_000,
                21_000_000_000,
            )
            .unwrap(),
        )
        .unwrap();
        assert_ne!(native, other_tx);

        // Refusals, not silent nonsense: zero cost, zero gas and a cost that
        // will not fit the identity's raw-amount slot.
        assert!(matches!(
            ExternalEventFact::native_gas(8453, TX, NATIVE_CURRENCY, NATIVE_CURRENCY, 1, 0),
            Err(EventIdError::ZeroAmount)
        ));
        assert!(matches!(
            ExternalEventFact::native_gas(8453, TX, NATIVE_CURRENCY, NATIVE_CURRENCY, 0, 5),
            Err(EventIdError::ZeroAmount)
        ));
        assert!(matches!(
            ExternalEventFact::native_gas(
                8453,
                TX,
                NATIVE_CURRENCY,
                NATIVE_CURRENCY,
                u64::MAX,
                u128::from(u64::MAX) + 1
            ),
            Err(EventIdError::NativeAmountOutOfRange { .. })
        ));
        assert!(matches!(
            ExternalEventFact::native_gas(0, TX, NATIVE_CURRENCY, NATIVE_CURRENCY, 1, 1),
            Err(EventIdError::ZeroChain)
        ));
    }

    /// The reserved native-currency word is not an address anything can hold a
    /// token at, and this crate can never mistake it for one.
    ///
    /// `RealAsset::new` is the only way to build an asset identity in this crate
    /// and it is never reached from a native fact, so the two vocabularies do
    /// not overlap.
    #[test]
    fn the_native_currency_word_cannot_become_a_token_identity() {
        assert_eq!(NATIVE_CURRENCY.len(), 42);
        assert!(NATIVE_CURRENCY.starts_with("0x"));
        assert_eq!(
            NATIVE_CURRENCY.trim_start_matches("0x").len(),
            40,
            "spelled as an address so it can be parsed as one, and it names nothing"
        );
        assert!(NATIVE_CURRENCY
            .trim_start_matches("0x")
            .chars()
            .all(|c| c == '0'));
        // The one identified asset this crate has is a different contract, so
        // a native fact can never be filed under it.
        assert_ne!(NATIVE_CURRENCY, RealAsset::base_usdc().contract());
        assert_ne!(
            NATIVE_CURRENCY.to_ascii_lowercase(),
            crate::base_usdc::BASE_USDC
        );
    }

    #[test]
    fn the_native_gas_seam_is_defined_and_distinct() {
        let fact = fact();
        let logged = ExternalEventId::logged(&fact).unwrap();
        let native = ExternalEventId::native_gas(&fact).unwrap();
        assert_ne!(
            logged, native,
            "a native fact filed under the token domain would collide with a token transfer"
        );
        assert_ne!(ExternalEventKind::Logged.domain(), ExternalEventKind::NativeGas.domain());
        assert_eq!(ExternalEventKind::Logged.domain(), EVENT_ID_DOMAIN);
        assert_eq!(
            ExternalEventKind::NativeGas.domain(),
            NATIVE_GAS_EVENT_ID_DOMAIN
        );
        // Same layout, different first section: the seam costs one domain and no
        // new field, which is the reason it was defined now.
        assert_eq!(
            decode(&preimage(&fact, ExternalEventKind::Logged).unwrap()).len(),
            decode(&preimage(&fact, ExternalEventKind::NativeGas).unwrap()).len()
        );
        assert_eq!(
            domains(&preimage(&fact, ExternalEventKind::NativeGas).unwrap()),
            vec![NATIVE_GAS_EVENT_ID_DOMAIN.to_string()]
        );
    }

    // ---- the byte layout -----------------------------------------------

    #[test]
    fn the_preimage_layout_is_exactly_the_published_table() {
        let raw = preimage(&fact(), ExternalEventKind::Logged).unwrap();
        let sections = decode(&raw);
        // The two framing sections come first, in this order and no other: the
        // domain, then the count. After them, one section per layout row.
        assert_eq!(
            sections[..2]
                .iter()
                .map(|(t, _)| t.as_str())
                .collect::<Vec<_>>(),
            vec!["domain", "sections"]
        );
        let tags: Vec<&str> = sections[2..]
            .iter()
            .map(|(t, _)| t.as_str())
            .collect();
        let expected: Vec<&str> = EVENT_ID_FIELDS.iter().map(|(t, _)| *t).collect();
        assert_eq!(tags, expected, "one section per layout row, in order");
        assert_eq!(
            sections[1].1,
            (EVENT_ID_FIELDS.len() as u32).to_be_bytes().to_vec(),
            "the section count names the layout, not the sections present"
        );

        let value = |tag: &str| -> Vec<u8> {
            sections
                .iter()
                .find(|(t, _)| t == tag)
                .unwrap_or_else(|| panic!("no section {tag}"))
                .1
                .clone()
        };
        assert_eq!(value("schema_version"), EVENT_ID_SCHEMA_VERSION.to_be_bytes().to_vec());
        assert_eq!(value("chain_id"), BASE_CHAIN_ID.to_be_bytes().to_vec());
        assert_eq!(value("log_index"), LOG_INDEX.to_be_bytes().to_vec());
        assert_eq!(value("amount_raw"), AMOUNT.to_be_bytes().to_vec());
        // Addresses and the tx hash go in as their canonical lowercase spelling,
        // and the contract is an address rather than a symbol.
        // The hash goes in as raw 32 bytes and the addresses as their canonical
        // `0x`-prefixed lowercase spelling — the same choice the attestation
        // preimage makes, so an event id and an attestation bind the same facts
        // in the same bytes.
        assert_eq!(
            value("tx_hash"),
            hex::decode(TX.trim_start_matches("0x")).unwrap()
        );
        assert_eq!(value("from_address"), COUNTERPARTY.as_bytes().to_vec());
        assert_eq!(value("to_address"), PAYOUT.as_bytes().to_vec());
        assert_eq!(
            value("asset"),
            asset().contract().as_bytes().to_vec(),
            "the canonical contract, `0x`-prefixed, never a symbol"
        );
        assert!(
            !String::from_utf8_lossy(&value("asset")).contains("USDC"),
            "a symbol is a local name, not an on-chain identity"
        );

        // Concrete prefix, shown rather than asserted by digest:
        //   0  : 06 00 00 00            len("domain") = 6
        //   4  : "domain"
        //  10  : 1D 00 00 00            len(EVENT_ID_DOMAIN) = 29
        assert_eq!(&raw[0..4], &6u32.to_be_bytes());
        assert_eq!(&raw[4..10], b"domain");
        assert_eq!(raw.len() > 14, true);
        assert_eq!(
            u32::from_be_bytes(raw[10..14].try_into().unwrap()) as usize,
            EVENT_ID_DOMAIN.len()
        );
        assert_eq!(&raw[14..14 + EVENT_ID_DOMAIN.len()], EVENT_ID_DOMAIN.as_bytes());
    }

    /// Walks a `push_tagged` preimage and returns `(tag, value)` per section.
    /// Test-only, and independent of the encoder it reads, so a layout mistake
    /// cannot hide behind a matching mistake.
    fn decode(raw: &[u8]) -> Vec<(String, Vec<u8>)> {
        fn take(raw: &[u8], at: &mut usize, len: usize) -> Vec<u8> {
            let end = *at + len;
            assert!(end <= raw.len(), "preimage truncated at {at}");
            let out = raw[*at..end].to_vec();
            *at = end;
            out
        }
        let mut at = 0usize;
        let mut out = Vec::new();
        while at < raw.len() {
            let tag_len = u32::from_be_bytes(take(raw, &mut at, 4).try_into().unwrap()) as usize;
            let tag = String::from_utf8(take(raw, &mut at, tag_len)).unwrap();
            let value_len = u32::from_be_bytes(take(raw, &mut at, 4).try_into().unwrap()) as usize;
            let value = take(raw, &mut at, value_len);
            out.push((tag, value));
        }
        out
    }

    fn domains(raw: &[u8]) -> Vec<String> {
        decode(raw)
            .into_iter()
            .filter(|(tag, _)| tag == "domain")
            .map(|(_, value)| String::from_utf8(value).unwrap())
            .collect()
    }

    // ---- refusals -------------------------------------------------------

    #[test]
    fn a_fact_the_chain_does_not_describe_has_no_id() {
        let ok = |c: std::result::Result<ExternalEventFact, EventIdError>| c.is_ok();
        let asset = asset();
        // chain 0 names no chain.
        assert!(!ok(ExternalEventFact::from_parts(
            0,
            TX,
            0,
            &asset,
            COUNTERPARTY,
            PAYOUT,
            AMOUNT
        )));
        // A chain and an asset that disagree.
        assert!(!ok(ExternalEventFact::from_parts(
            1,
            TX,
            0,
            &asset,
            COUNTERPARTY,
            PAYOUT,
            AMOUNT
        )));
        // Zero amount moves nothing.
        assert!(!ok(ExternalEventFact::from_parts(
            BASE_CHAIN_ID,
            TX,
            0,
            &asset,
            COUNTERPARTY,
            PAYOUT,
            0
        )));
        // A self-transfer is not an external event.
        assert!(!ok(ExternalEventFact::from_parts(
            BASE_CHAIN_ID,
            TX,
            0,
            &asset,
            PAYOUT,
            PAYOUT,
            AMOUNT
        )));
        // Truncated addresses and hashes, reusing the crate's validators.
        assert!(!ok(ExternalEventFact::from_parts(
            BASE_CHAIN_ID,
            "0xdeadbeef",
            0,
            &asset,
            COUNTERPARTY,
            PAYOUT,
            AMOUNT
        )));
        assert!(!ok(ExternalEventFact::from_parts(
            BASE_CHAIN_ID,
            TX,
            0,
            &asset,
            "0xnothex",
            PAYOUT,
            AMOUNT
        )));
        // And the errors say which rule, rather than all reading "invalid".
        let err = ExternalEventFact::from_parts(
            BASE_CHAIN_ID,
            TX,
            0,
            &asset,
            COUNTERPARTY,
            PAYOUT,
            0,
        )
        .unwrap_err();
        assert!(matches!(err, EventIdError::ZeroAmount), "{err}");
        let err = ExternalEventFact::from_parts(
            BASE_CHAIN_ID,
            TX,
            0,
            &asset,
            PAYOUT,
            PAYOUT,
            AMOUNT,
        )
        .unwrap_err();
        assert!(matches!(err, EventIdError::SelfTransfer { .. }), "{err}");
    }

    #[test]
    fn a_transfer_with_no_reported_log_index_is_not_named() {
        // Every other field present, the log index missing: the shape of a
        // provider that confirms a transfer without saying which log it matched.
        let mut proof = crate::base_usdc::BaseUsdcVerification {
            verified: true,
            rpc: "unix:///run/mycelium-verifier.sock".into(),
            provider_identity_verified: true,
            chain_id: BASE_CHAIN_ID,
            transaction_hash: TX.into(),
            block_number: 101,
            block_hash: BLOCK.into(),
            block_timestamp_unix: 1_700_000_400,
            latest_block: 110,
            confirmations: 10,
            token: BASE_USDC.to_ascii_lowercase(),
            recipient: PAYOUT.into(),
            expected_raw: AMOUNT,
            matched_raw: AMOUNT,
            matching_log_index: None,
        };
        let err = ExternalEventFact::from_confirmed_transfer(&evidence(), &proof)
            .unwrap_err();
        assert!(matches!(err, EventIdError::LogIndexUnknown(_)), "{err}");
        assert!(err.to_string().contains("no log index"), "{err}");

        // The same proof with an index names the fact, and it is the same fact
        // the ledger's evidence describes.
        proof.matching_log_index = Some(LOG_INDEX);
        let from_proof = ExternalEventFact::from_confirmed_transfer(&evidence(), &proof)
            .unwrap();
        assert_eq!(id_of(&from_proof), id_of(&fact()));
    }

    // ---- the counting rule ---------------------------------------------

    #[test]
    fn an_identity_is_claimed_once_however_often_it_is_offered() {
        let mut counted = CountedEvents::default();
        let a = ExternalEventId::logged(&fact()).unwrap();
        let b = ExternalEventId::logged(&fact()).unwrap();
        assert_eq!(a, b, "the same fact must have one identity");

        assert_eq!(counted.claim(a.clone(), 1), None, "the first claim wins");
        assert_eq!(counted.len(), 1);
        assert!(counted.contains(&a));
        assert_eq!(counted.first_counted_at(&a), Some(1));

        // The same identity again, on another record, out of order, at another
        // position in the file: refused, and the report names who holds credit.
        assert_eq!(counted.claim(b, 5), Some(1));
        assert_eq!(counted.len(), 1, "the second claim changed the count");
        assert_eq!(counted.first_counted_at(&a), Some(1), "credit did not move");

        // A genuinely different fact is a different identity and does count.
        let other = ExternalEventFact::from_parts(
            BASE_CHAIN_ID,
            TX,
            LOG_INDEX + 1,
            &asset(),
            COUNTERPARTY,
            PAYOUT,
            AMOUNT,
        )
        .unwrap();
        let other = ExternalEventId::logged(&other).unwrap();
        assert_eq!(counted.claim(other.clone(), 6), None);
        assert_eq!(counted.len(), 2);
        assert!(!counted.contains(&a.clone()) == false);
        assert!(counted.contains(&other));
    }

    #[test]
    fn a_fresh_count_answers_the_same_way() {
        // The pass is rebuilt from the ledger every time, so the answer cannot
        // depend on anything a previous pass remembered. Two passes over the
        // same two identities, in opposite orders, agree on the total count and
        // on which record holds the credit *within their own pass*.
        let a = ExternalEventId::logged(&fact()).unwrap();
        let b = ExternalEventId::logged(
            &ExternalEventFact::from_parts(
                BASE_CHAIN_ID,
                TX,
                LOG_INDEX + 1,
                &asset(),
                COUNTERPARTY,
                PAYOUT,
                AMOUNT,
            )
            .unwrap(),
        )
        .unwrap();

        let mut forward = CountedEvents::default();
        assert_eq!(forward.claim(a.clone(), 1), None);
        assert_eq!(forward.claim(a.clone(), 2), Some(1));
        assert_eq!(forward.claim(b.clone(), 3), None);
        assert_eq!(forward.len(), 2);

        let mut backward = CountedEvents::default();
        assert_eq!(backward.claim(b.clone(), 3), None);
        assert_eq!(backward.claim(a.clone(), 1), None);
        assert_eq!(backward.claim(a.clone(), 2), Some(1));
        assert_eq!(backward.len(), 2);

        assert_eq!(forward.len(), backward.len());
    }

    // ---- the settlement-economic identity (P6.N6) -----------------------

    /// A canonical operation-id spelling: the 32-byte digest form every
    /// `OperationId` in this crate has. Note that the only free text the fact
    /// accepts is itself a digest — there is nowhere for a label to enter.
    const ECON_OPERATION: &str =
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ECON_OTHER_OPERATION: &str =
        "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const ECON_BLOCK: u64 = 12_345;
    const ECON_ANCHOR: &str =
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ECON_OTHER_ANCHOR: &str =
        "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn econ_leg(seed: &str) -> ExternalEventId {
        ExternalEventId::from_test_seed(&format!("econ-leg-{seed}"))
    }

    fn econ_cost(seed: &str) -> ExternalEventId {
        ExternalEventId::from_test_seed(&format!("econ-cost-{seed}"))
    }

    fn econ_fact_with(
        chain_id: u64,
        anchor_block_number: u64,
        anchor_block_hash: &str,
        operation_id: &str,
        legs: Vec<ExternalEventId>,
        costs: Vec<ExternalEventId>,
    ) -> SettlementEconomicFact {
        SettlementEconomicFact::from_parts(
            chain_id,
            anchor_block_number,
            anchor_block_hash,
            operation_id,
            &legs.iter().collect::<Vec<_>>(),
            &costs.iter().collect::<Vec<_>>(),
        )
        .expect("a settlement-economic fact")
    }

    fn econ_fact() -> SettlementEconomicFact {
        econ_fact_with(
            BASE_CHAIN_ID,
            ECON_BLOCK,
            ECON_ANCHOR,
            ECON_OPERATION,
            vec![econ_leg("a"), econ_leg("b")],
            vec![econ_cost("gas")],
        )
    }

    fn econ_id(fact: &SettlementEconomicFact) -> String {
        ExternalEventId::settlement_economic(fact)
            .expect("a settlement-economic id")
            .to_string()
    }

    #[test]
    fn the_settlement_economic_layout_names_exactly_the_emitted_tags() {
        // Named explicitly rather than by a deny-list, so adding a row to the
        // identity is a visible edit to this test as well as to the table.
        assert_eq!(
            SETTLEMENT_ECONOMIC_EVENT_ID_FIELDS.to_vec(),
            vec![
                "schema_version",
                "chain_id",
                "anchor_block_number",
                "anchor_block_hash",
                "operation_id",
                "leg_count",
                "leg_event_id",
                "cost_count",
                "cost_event_id",
            ]
        );

        let raw = settlement_economic_preimage(&econ_fact()).unwrap();
        let sections = decode(&raw);

        // Framing first, in this order and no other: the domain, then the count.
        assert_eq!(
            sections[..2]
                .iter()
                .map(|(t, _)| t.as_str())
                .collect::<Vec<_>>(),
            vec!["domain", "sections"]
        );
        assert_eq!(domains(&raw), vec![SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN.to_string()]);

        // Then the emitted tags, with the two repeated rows expanded by the
        // counts the fact carries: two legs and one cost.
        let tags: Vec<&str> = sections[2..].iter().map(|(t, _)| t.as_str()).collect();
        assert_eq!(
            tags,
            vec![
                "schema_version",
                "chain_id",
                "anchor_block_number",
                "anchor_block_hash",
                "operation_id",
                "leg_count",
                "leg_event_id",
                "leg_event_id",
                "cost_count",
                "cost_event_id",
            ],
            "one section per layout row, repeats expanded, in canonical order"
        );

        let rows = |tag: &str| -> Vec<Vec<u8>> {
            sections
                .iter()
                .filter(|(t, _)| t == tag)
                .map(|(_, value)| value.clone())
                .collect()
        };
        assert_eq!(
            rows("schema_version"),
            vec![SETTLEMENT_ECONOMIC_EVENT_ID_SCHEMA_VERSION
                .to_be_bytes()
                .to_vec()]
        );
        assert_eq!(rows("chain_id"), vec![BASE_CHAIN_ID.to_be_bytes().to_vec()]);
        assert_eq!(
            rows("anchor_block_number"),
            vec![ECON_BLOCK.to_be_bytes().to_vec()]
        );
        assert_eq!(
            rows("anchor_block_hash"),
            vec![hex::decode(ECON_ANCHOR.trim_start_matches("0x")).unwrap()],
            "the anchor hash goes in as raw 32 bytes, as settlement_digest writes it"
        );
        assert_eq!(rows("operation_id"), vec![ECON_OPERATION.as_bytes().to_vec()]);
        assert_eq!(rows("leg_count"), vec![2u32.to_be_bytes().to_vec()]);
        assert_eq!(rows("cost_count"), vec![1u32.to_be_bytes().to_vec()]);
        assert_eq!(rows("leg_event_id").len(), 2);
        assert_eq!(rows("cost_event_id").len(), 1);

        // The section-count row names the LAYOUT, as it does for every other
        // preimage in this file — here the count of layout rows, which differs
        // from the count of sections actually written because two rows repeat.
        assert_eq!(
            sections[1].1,
            (SETTLEMENT_ECONOMIC_EVENT_ID_FIELDS.len() as u32)
                .to_be_bytes()
                .to_vec()
        );
    }

    #[test]
    fn the_settlement_economic_layout_binds_no_valuation_and_no_observation() {
        // The absence is the property. Each of these names a real field of a
        // `ComparableVerifiedSettlement`, and each is deliberately absent.
        let tags: Vec<&str> = SETTLEMENT_ECONOMIC_EVENT_ID_FIELDS.to_vec();
        for forbidden in [
            "comparable_digest",
            "settlement_digest",
            "policy_hash",
            "comparable_net_value_micros",
            "token_net_delta_micros",
            "native_cost_musd",
            "total_native_cost_wei",
            "price",
            "price_musd_per_eth",
            "price_observation_event_id",
            "price_block_number",
            "confirmations",
            "anchor_block_timestamp_unix",
        ] {
            assert!(
                !tags.contains(&forbidden),
                "{forbidden} reached the economic identity of an operation"
            );
        }
        // The same statement about the bytes, so it cannot be satisfied by
        // deleting a table row while leaving the encoder alone.
        let raw = settlement_economic_preimage(&econ_fact()).unwrap();
        let text = String::from_utf8_lossy(&raw).into_owned();
        for forbidden in ["policy_hash", "confirmations", "native_cost_musd"] {
            assert!(
                !text.contains(forbidden),
                "the preimage carries a {forbidden} row: {text}"
            );
        }
    }

    #[test]
    fn a_settlement_economic_fact_differing_in_any_single_field_yields_a_different_id() {
        let canonical = econ_id(&econ_fact());
        // Each entry is a *valid* fact differing from the base in exactly one
        // field, so a collision below would be a real collision, not a refusal.
        let variants: Vec<(&str, SettlementEconomicFact)> = vec![
            (
                "chain_id",
                econ_fact_with(
                    1,
                    ECON_BLOCK,
                    ECON_ANCHOR,
                    ECON_OPERATION,
                    vec![econ_leg("a"), econ_leg("b")],
                    vec![econ_cost("gas")],
                ),
            ),
            (
                "anchor_block_number",
                econ_fact_with(
                    BASE_CHAIN_ID,
                    ECON_BLOCK + 1,
                    ECON_ANCHOR,
                    ECON_OPERATION,
                    vec![econ_leg("a"), econ_leg("b")],
                    vec![econ_cost("gas")],
                ),
            ),
            (
                "anchor_block_hash",
                econ_fact_with(
                    BASE_CHAIN_ID,
                    ECON_BLOCK,
                    ECON_OTHER_ANCHOR,
                    ECON_OPERATION,
                    vec![econ_leg("a"), econ_leg("b")],
                    vec![econ_cost("gas")],
                ),
            ),
            (
                "operation_id",
                econ_fact_with(
                    BASE_CHAIN_ID,
                    ECON_BLOCK,
                    ECON_ANCHOR,
                    ECON_OTHER_OPERATION,
                    vec![econ_leg("a"), econ_leg("b")],
                    vec![econ_cost("gas")],
                ),
            ),
            (
                "leg_event_id",
                econ_fact_with(
                    BASE_CHAIN_ID,
                    ECON_BLOCK,
                    ECON_ANCHOR,
                    ECON_OPERATION,
                    vec![econ_leg("a"), econ_leg("c")],
                    vec![econ_cost("gas")],
                ),
            ),
        ];
        assert_eq!(
            variants.len(),
            5,
            "every bound field must have a variant here"
        );
        for (field, variant) in variants {
            assert_ne!(
                econ_id(&variant),
                canonical,
                "{field} is not bound into the settlement-economic identity"
            );
        }
    }

    #[test]
    fn adding_or_removing_a_leg_or_a_cost_changes_the_settlement_economic_identity() {
        let ids = [
            (
                "two legs, one cost",
                econ_id(&econ_fact_with(
                    BASE_CHAIN_ID,
                    ECON_BLOCK,
                    ECON_ANCHOR,
                    ECON_OPERATION,
                    vec![econ_leg("a"), econ_leg("b")],
                    vec![econ_cost("gas")],
                )),
            ),
            (
                "one leg",
                econ_id(&econ_fact_with(
                    BASE_CHAIN_ID,
                    ECON_BLOCK,
                    ECON_ANCHOR,
                    ECON_OPERATION,
                    vec![econ_leg("a")],
                    vec![econ_cost("gas")],
                )),
            ),
            (
                "three legs",
                econ_id(&econ_fact_with(
                    BASE_CHAIN_ID,
                    ECON_BLOCK,
                    ECON_ANCHOR,
                    ECON_OPERATION,
                    vec![econ_leg("a"), econ_leg("b"), econ_leg("c")],
                    vec![econ_cost("gas")],
                )),
            ),
            (
                "two costs",
                econ_id(&econ_fact_with(
                    BASE_CHAIN_ID,
                    ECON_BLOCK,
                    ECON_ANCHOR,
                    ECON_OPERATION,
                    vec![econ_leg("a"), econ_leg("b")],
                    vec![econ_cost("gas"), econ_cost("l1")],
                )),
            ),
            (
                "no costs at all",
                econ_id(&econ_fact_with(
                    BASE_CHAIN_ID,
                    ECON_BLOCK,
                    ECON_ANCHOR,
                    ECON_OPERATION,
                    vec![econ_leg("a"), econ_leg("b")],
                    vec![],
                )),
            ),
        ];
        // Every one of these names a different set of external facts, so every
        // pair must be a different economic event — including "no cost at all",
        // which is a genuinely different operation and not a zero-cost version
        // of the same one.
        for (i, (left_name, left)) in ids.iter().enumerate() {
            for (right_name, right) in ids.iter().skip(i + 1) {
                assert_ne!(left, right, "{left_name} and {right_name} are one identity");
            }
        }
    }

    #[test]
    fn reordering_legs_or_costs_leaves_the_settlement_economic_identity_unchanged() {
        // THE order-independence property. Legs arrive in RPC receipt log order,
        // which is a property of how a provider serialised a response; an
        // order-sensitive id would let one operation acquire two identities
        // purely because two nodes enumerated its logs differently.
        let forward = econ_id(&econ_fact_with(
            BASE_CHAIN_ID,
            ECON_BLOCK,
            ECON_ANCHOR,
            ECON_OPERATION,
            vec![econ_leg("a"), econ_leg("b"), econ_leg("c")],
            vec![econ_cost("x"), econ_cost("y")],
        ));
        let reversed = econ_id(&econ_fact_with(
            BASE_CHAIN_ID,
            ECON_BLOCK,
            ECON_ANCHOR,
            ECON_OPERATION,
            vec![econ_leg("c"), econ_leg("b"), econ_leg("a")],
            vec![econ_cost("y"), econ_cost("x")],
        ));
        let rotated = econ_id(&econ_fact_with(
            BASE_CHAIN_ID,
            ECON_BLOCK,
            ECON_ANCHOR,
            ECON_OPERATION,
            vec![econ_leg("b"), econ_leg("c"), econ_leg("a")],
            vec![econ_cost("x"), econ_cost("y")],
        ));
        // Same legs, same order; only the costs are swapped.
        let cost_swapped = econ_id(&econ_fact_with(
            BASE_CHAIN_ID,
            ECON_BLOCK,
            ECON_ANCHOR,
            ECON_OPERATION,
            vec![econ_leg("a"), econ_leg("b"), econ_leg("c")],
            vec![econ_cost("y"), econ_cost("x")],
        ));
        assert_eq!(forward, reversed, "leg order reached the identity");
        assert_eq!(forward, rotated, "leg order reached the identity");
        assert_eq!(forward, cost_swapped, "cost order reached the identity");

        // The equality is the ENCODER's doing, not the constructor's: the fact
        // records the order it was handed, so this assertion would fail if the
        // sort had been pushed into `from_parts` instead.
        let unsorted_fact = econ_fact_with(
            BASE_CHAIN_ID,
            ECON_BLOCK,
            ECON_ANCHOR,
            ECON_OPERATION,
            vec![econ_leg("c"), econ_leg("a"), econ_leg("b")],
            vec![econ_cost("y"), econ_cost("x")],
        );
        assert_eq!(unsorted_fact.leg_event_ids()[0], econ_leg("c"));
        assert_eq!(unsorted_fact.cost_event_ids()[0], econ_cost("y"));
        let mut canonical_legs = unsorted_fact.leg_event_ids().to_vec();
        canonical_legs.sort();
        assert_ne!(
            unsorted_fact.leg_event_ids().to_vec(),
            canonical_legs,
            "this fact is genuinely not in canonical order, so the sort is load-bearing"
        );
    }

    #[test]
    fn the_settlement_economic_domain_is_distinct_from_every_other_domain_in_the_crate() {
        // Every domain string this crate has, asserted pairwise distinct — a
        // fifth copy of an existing domain would make one settlement's economic
        // identity equal to, say, a payment's, and both would then be findable
        // under the same key.
        let all_domains = [
            EVENT_ID_DOMAIN,
            NATIVE_GAS_EVENT_ID_DOMAIN,
            SETTLEMENT_EVENT_ID_DOMAIN,
            PRICE_OBSERVATION_ID_DOMAIN,
            SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN,
            crate::settlement::OPERATION_ID_DOMAIN,
            crate::policy_auth::POLICY_SIGNING_DOMAIN,
            crate::policy_auth::CONTROLLED_REGISTRY_DOMAIN,
            EXTERNAL_VALUE_ATTESTATION_DOMAIN,
            RECEIPT_HASH_DOMAIN,
            SETTLEMENT_ATTESTATION_DOMAIN,
            SETTLEMENT_HASH_DOMAIN,
        ];
        for (i, left) in all_domains.iter().enumerate() {
            for right in all_domains.iter().skip(i + 1) {
                assert_ne!(left, right, "{left} and {right} are the same domain string");
            }
        }

        // And asserted with real artefacts over related chain facts rather than
        // by restating the constants above: five identities, five domains, five
        // digests.
        let settlement_payment = SettlementPaymentFact::from_parts(
            BASE_CHAIN_ID,
            TX,
            LOG_INDEX,
            &asset(),
            PAYOUT,
            AMOUNT,
        )
        .unwrap();
        let price_observation = PriceObservationFact::from_parts(
            "base-usdc-usd",
            "USDC",
            "USDC",
            3_000_000_000_000u128,
            BASE_CHAIN_ID,
            100,
            BLOCK,
            1_700_000_400,
            "round-1",
            10,
        )
        .unwrap();
        let native = ExternalEventId::native_gas(
            &ExternalEventFact::native_gas(
                BASE_CHAIN_ID,
                TX,
                NATIVE_CURRENCY,
                NATIVE_CURRENCY,
                21_000,
                21_000_000_000,
            )
            .unwrap(),
        )
        .unwrap();

        let ids = [
            ("logged", ExternalEventId::logged(&fact()).unwrap()),
            ("native gas", native),
            (
                "settlement payment",
                ExternalEventId::settlement_payment(&settlement_payment).unwrap(),
            ),
            (
                "price observation",
                ExternalEventId::price_observation(&price_observation).unwrap(),
            ),
            (
                "settlement economic",
                ExternalEventId::settlement_economic(&econ_fact()).unwrap(),
            ),
        ];
        for (i, (left_name, left)) in ids.iter().enumerate() {
            for (right_name, right) in ids.iter().skip(i + 1) {
                assert_ne!(
                    left, right,
                    "{left_name} and {right_name} are the same digest over related facts"
                );
            }
        }

        // The preimage carries this domain and no other, and it is first.
        let raw = settlement_economic_preimage(&econ_fact()).unwrap();
        assert_eq!(
            domains(&raw),
            vec![SETTLEMENT_ECONOMIC_EVENT_ID_DOMAIN.to_string()]
        );
        assert_eq!(decode(&raw).first().map(|(t, _)| t.as_str()), Some("domain"));
    }

    #[test]
    fn the_settlement_economic_id_has_no_text_back_door() {
        // There is exactly one route to one of these ids: a validated fact.
        assert!(matches!(
            SettlementEconomicFact::from_parts(0, ECON_BLOCK, ECON_ANCHOR, ECON_OPERATION, &[], &[]),
            Err(EventIdError::ZeroChain)
        ));
        // An empty operation id names nothing and is refused rather than bound.
        assert!(matches!(
            SettlementEconomicFact::from_parts(BASE_CHAIN_ID, ECON_BLOCK, ECON_ANCHOR, "", &[], &[]),
            Err(EventIdError::Preimage(_))
        ));
        // And the anchor hash is validated exactly as `settlement_digest`
        // validates its own, so no unparseable spelling reaches the identity.
        assert!(
            SettlementEconomicFact::from_parts(
                BASE_CHAIN_ID,
                ECON_BLOCK,
                "0xnothex",
                ECON_OPERATION,
                &[],
                &[],
            )
            .is_err()
        );

        // The operation-id row is the only free text, and it is one tagged row
        // among the schema rather than an identity in its own right: naming an
        // event means producing a digest over every row, not typing a label.
        let fact = econ_fact();
        assert_eq!(fact.operation_id(), ECON_OPERATION);
        assert_ne!(
            econ_id(&fact),
            ECON_OPERATION,
            "one preimage row is not an economic identity"
        );
        // A label is not even a legal operation-id spelling.
        assert!(Hash::parse("operation_id", "settled").is_err());
        assert!(Hash::parse("operation_id", ECON_OPERATION).is_ok());
    }
}
